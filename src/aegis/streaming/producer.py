"""KafkaSink - writes events to Kafka, and satisfies the same Sink contract.

THE PAYOFF FOR PHASE 1's DESIGN
-------------------------------
This class has `write`, `flush` and `close`, exactly like JsonlFileSink. So
every collector can now publish to Kafka with **zero changes to collector
code**. That is what the sink abstraction bought us, and it is worth noticing:
the effort spent on an interface in Phase 1 is being repaid right now.

THREE THINGS THAT SURPRISE PEOPLE ABOUT KAFKA PRODUCERS
-------------------------------------------------------
1. `produce()` does not send anything. It appends to an in-memory buffer and
   returns immediately. Data goes out when the batch fills, when linger.ms
   elapses, or when you call flush(). A program that produces and then exits
   without flushing loses everything it "sent". This is the number one Kafka
   bug for newcomers.

2. Errors arrive later, on a different thread. Because produce() is
   asynchronous, a failure cannot be raised from it - the call already
   returned. You must supply a delivery callback, and you must actually check
   it. Ignoring the callback is how "the producer never errors" becomes "we
   lost 4% of yesterday's data".

3. The message KEY decides the partition. Same key, same partition, therefore
   guaranteed ordering between records that share a key. Choosing this key is
   the most consequential decision in the whole file - see key_for() below.
"""

from __future__ import annotations

import json
from typing import Any

from confluent_kafka import Producer
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer
from confluent_kafka.serialization import MessageField, SerializationContext, StringSerializer

from aegis.config import settings
from aegis.logging import get_logger
from aegis.sources.models import Event, Source, utc_now, uuid7
from aegis.streaming.schemas import (
    DEAD_LETTER_SCHEMA,
    EVENT_ENVELOPE_SCHEMA,
    event_to_avro_dict,
)
from aegis.streaming.topics import DLQ_TOPIC, topic_for

log = get_logger(__name__)


def safe_repr(event: Event, limit: int = 50_000) -> str:
    """Render an event as text for the dead-letter topic, never raising.

    WHY THIS EXISTS - a real bug this project hit
    ---------------------------------------------
    The first version of the dead-letter path called `event.to_json_line()` to
    capture the failed record. That is JSON serialisation... which is exactly
    what had just failed. So a record with an unserialisable payload raised a
    second exception *inside the error handler*, which escaped `write()` and
    crashed the whole collector.

    The dead-letter queue existed precisely to prevent a crash, and it caused
    one. The lesson generalises: **error-handling code must not use the
    machinery that failed.** Anything running in a `except` block has to assume
    the normal path is broken, and degrade rather than raise.

    So this function tries progressively weaker representations, and its last
    resort cannot fail.
    """
    try:
        return event.to_json_line()[:limit]
    except Exception:  # noqa: S110 - falling through is the entire design here
        pass
    try:
        # repr() handles cycles that json.dumps cannot, printing {...} instead
        # of recursing forever.
        return repr(event.payload)[:limit]
    except Exception:  # noqa: S110 - fall through to the guaranteed-safe branch
        pass
    # Last resort: the metadata we know is plain strings. Something is always
    # better than losing the record entirely.
    return (
        f"<unrepresentable payload> event_id={event.event_id} "
        f"source={event.source.value} type={event.event_type.value}"
    )


def key_for(event: Event) -> str:
    """Choose the partition key for an event.

    THE DECISION, AND WHY IT IS NOT OBVIOUS
    ---------------------------------------
    Kafka hashes this key to pick a partition. Records sharing a key always
    land in the same partition, and therefore stay in order relative to each
    other. Three candidate keys, and why we rejected two:

    * Key by SOURCE ("urlhaus"). Simple, and gives per-source ordering. But
      every URLhaus record would hash to one partition, so the other two sit
      idle and we cannot scale consumers at all. This is partition skew, and
      it silently removes the parallelism the partitions were for.

    * Key by nothing (null). Kafka would round-robin, giving perfect balance -
      and no ordering guarantee whatsoever. Two observations about the same IP
      could then be processed out of order by different consumers, so "last
      seen status" becomes a race.

    * Key by the ENTITY the event is about - this URL, this IP, this CVE.
      Balance is excellent because there are thousands of distinct entities,
      AND every observation about one entity is ordered. That is exactly the
      ordering we need: when the same malicious URL is reported twice, we must
      process them in the right sequence to know its current status.

    So: entity key. We fall back to the event_id when no natural entity exists,
    which behaves like round-robin - correct, since an event with no entity has
    nothing to be ordered against.
    """
    payload = event.payload
    for field in ("url", "ip_address", "cve_id", "session_id", "src_ip"):
        value = payload.get(field)
        if value:
            return str(value)
    return event.event_id


class KafkaSink:
    """A Sink that publishes events to Kafka with Avro + Schema Registry."""

    def __init__(
        self,
        *,
        client_id: str = "aegis-collector",
        topic: str | None = None,
        register_schema: bool = True,
    ) -> None:
        self.client_id = client_id
        self.override_topic = topic

        self.produced = 0
        self.delivered = 0
        self.failed = 0
        self.dead_lettered = 0
        self.dlq_write_failures = 0
        self._errors: list[str] = []

        self._producer = Producer(settings.kafka.producer_config(client_id))
        self._key_serializer = StringSerializer("utf_8")

        self._registry = SchemaRegistryClient({"url": settings.kafka.schema_registry_url})
        self._value_serializer = AvroSerializer(
            self._registry,
            json.dumps(EVENT_ENVELOPE_SCHEMA),
            conf={
                # If the subject does not exist yet, register this schema.
                # In production you would set this False and register schemas
                # in a deliberate CI step, so a rogue producer cannot silently
                # evolve the contract everyone else depends on.
                "auto.register.schemas": register_schema,
                # Do not normalise: we want the schema stored exactly as
                # written, docs and all, so the registry serves our
                # documentation to whoever inspects it.
                "normalize.schemas": False,
            },
        )
        self._dlq_serializer = AvroSerializer(
            self._registry, json.dumps(DEAD_LETTER_SCHEMA), conf={"auto.register.schemas": True}
        )

        log.debug("kafka_sink_ready", client_id=client_id, broker=settings.kafka.kafka_bootstrap)

    # ------------------------------------------------------------- callbacks

    def _on_delivery(self, err: Any, msg: Any) -> None:
        """Called by librdkafka once the broker acknowledges (or refuses) a message.

        This runs on the producer's background thread, which is why it must be
        cheap and must never raise. Its only job is to record the outcome so
        close() can report the truth.
        """
        if err is not None:
            self.failed += 1
            message = str(err)
            if len(self._errors) < 10:  # keep a sample, not a million copies
                self._errors.append(message)
            log.error("delivery_failed", error=message[:200], topic=msg.topic() if msg else None)
        else:
            self.delivered += 1

    # ------------------------------------------------------------ Sink API

    def write(self, event: Event) -> None:
        """Queue one event for delivery.

        Returns as soon as the record is buffered. Delivery is confirmed later,
        via _on_delivery. If the buffer is full, librdkafka raises
        BufferError - we then serve the delivery callbacks to drain it, and
        retry. That is back-pressure working correctly: the producer slows down
        instead of using unbounded memory.
        """
        topic = self.override_topic or topic_for(event.source)

        try:
            value = self._value_serializer(
                event_to_avro_dict(event), SerializationContext(topic, MessageField.VALUE)
            )
        except Exception as exc:
            # Serialisation failed: the record does not fit the schema. This is
            # a contract violation, so it goes to the dead-letter topic with the
            # reason attached rather than being dropped.
            self.send_to_dlq(
                stage="serialize",
                error=exc,
                raw_payload=safe_repr(event),
                source=event.source,
                topic=topic,
            )
            return

        key = self._key_serializer(key_for(event), SerializationContext(topic, MessageField.KEY))

        for attempt in range(3):
            try:
                self._producer.produce(
                    topic=topic,
                    key=key,
                    value=value,
                    # INGESTION time, not event time. This line used to read
                    # `int(event.occurred_at.timestamp() * 1000)`, and that was
                    # a real bug that destroyed 45,233 records.
                    #
                    # Kafka's message timestamp is not just metadata: with the
                    # default `message.timestamp.type=CreateTime`, the broker
                    # uses it to decide when a log segment has aged out. Feeding
                    # it event time therefore means retention counts from when
                    # the malware was first seen, not from when we collected it.
                    #
                    # URLhaus publishes a rolling 30-day window, so on a topic
                    # with 7-day retention most records were already expired at
                    # the instant they were written. They were accepted, they
                    # appeared in the delivery reports, and they were deleted
                    # before anything could read them. Nothing errored.
                    #
                    # Event time is not lost - it rides in `occurred_at` inside
                    # the payload, which is where a consumer should read it from
                    # anyway. Kafka's own clock should only ever describe Kafka.
                    timestamp=int(event.ingested_at.timestamp() * 1000),
                    headers={
                        # Headers travel with the message and can be read
                        # without deserialising the body - useful for routing
                        # and for debugging in the Console UI.
                        "source": event.source.value,
                        "event_type": event.event_type.value,
                        "schema_version": str(event.schema_version),
                    },
                    on_delivery=self._on_delivery,
                )
                self.produced += 1
                return
            except BufferError:
                # The local queue is full. Serve callbacks to make room, then
                # try again. poll(1) also gives delivery reports a chance to run.
                self._producer.poll(1.0)
                if attempt == 2:
                    self.failed += 1
                    log.error("produce_buffer_full", topic=topic)
            except Exception as exc:
                self.failed += 1
                log.error("produce_failed", error=str(exc)[:200], topic=topic)
                return

    def send_to_dlq(
        self,
        *,
        stage: str,
        error: Exception,
        raw_payload: str,
        source: Source | str | None = None,
        topic: str | None = None,
        retry_count: int = 0,
    ) -> None:
        """Publish a failure to the dead-letter topic, with the original bytes."""
        source_value = source.value if isinstance(source, Source) else source
        record = {
            "dlq_id": uuid7(),
            "failed_at": utc_now(),
            "stage": stage,
            "source": source_value,
            "original_topic": topic,
            "error_type": type(error).__name__,
            "error_message": str(error)[:2000],
            "raw_payload": raw_payload[:100_000],  # cap: never blow up on a huge blob
            "retry_count": retry_count,
        }
        try:
            value = self._dlq_serializer(
                record, SerializationContext(DLQ_TOPIC.name, MessageField.VALUE)
            )
            self._producer.produce(topic=DLQ_TOPIC.name, value=value, on_delivery=self._on_delivery)
            self.dead_lettered += 1
            log.warning(
                "sent_to_dlq", stage=stage, error_type=type(error).__name__, source=source_value
            )
        except Exception as exc:
            # If even the DLQ write fails, log loudly. There is nowhere left to
            # put this record, and pretending otherwise would be dishonest.
            # Crucially this still does NOT raise: one unrecordable failure must
            # not stop the other 15,000 records from being delivered.
            self.dlq_write_failures += 1
            log.error("dlq_write_failed", error=str(exc)[:200], original_stage=stage)

    def flush(self, timeout: float = 30.0) -> None:
        """Block until every buffered message has been acknowledged or has failed.

        The return value is how many messages are STILL outstanding after the
        timeout. Anything above zero means we could not confirm delivery, and
        the caller must not report success.
        """
        remaining = self._producer.flush(timeout)
        if remaining > 0:
            log.error("flush_incomplete", undelivered=remaining, timeout_seconds=timeout)

    def close(self) -> None:
        """Flush and report. Safe to call more than once."""
        self.flush()
        if self.produced:
            log.info(
                "kafka_sink_closed",
                produced=self.produced,
                delivered=self.delivered,
                failed=self.failed,
                dead_lettered=self.dead_lettered,
                dlq_write_failures=self.dlq_write_failures,
                sample_errors=self._errors[:3],
            )

    @property
    def all_delivered(self) -> bool:
        """True when every produced message was acknowledged by the broker."""
        return self.failed == 0 and self.delivered == self.produced
