"""Reading from Kafka safely.

THE ONE THING THAT MATTERS: WHEN YOU COMMIT THE OFFSET
------------------------------------------------------
A consumer's "offset" is a bookmark: the position it will resume from after a
restart. Committing that bookmark at the wrong moment is the source of almost
every data-loss and data-duplication bug in streaming systems.

    Commit BEFORE processing  ->  crash loses the batch.  AT-MOST-ONCE.
    Commit AFTER processing   ->  crash re-reads the batch. AT-LEAST-ONCE.

Kafka's default, `enable.auto.commit=true`, commits on a timer, in the
background, regardless of whether your code finished. That is effectively the
first option, and it fails silently: nothing errors, some records are simply
never processed. AEGIS disables it globally in `aegis.config` so the mistake
cannot be made here.

We therefore choose AT-LEAST-ONCE, and handle the duplicates it implies by
deduplicating on `event_id` in the Silver layer. That combination -
at-least-once transport plus idempotent storage - is how production systems
achieve effectively-exactly-once without distributed transactions. Chasing true
exactly-once delivery is usually a much larger cost for a much smaller benefit.

POISON MESSAGES
---------------
A message that always fails to process will, under at-least-once, be re-read
forever: the consumer never commits, restarts, reads the same record, fails
again. This is a poison-pill loop, and it takes a pipeline down completely.
The cure is the dead-letter topic: after a bounded number of attempts, move on
and preserve the record for later analysis.
"""

from __future__ import annotations

import json
import signal
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from types import FrameType
from typing import Any

from confluent_kafka import Consumer, KafkaError, KafkaException, Message
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroDeserializer
from confluent_kafka.serialization import MessageField, SerializationContext

from aegis.config import settings
from aegis.logging import get_logger
from aegis.streaming.schemas import EVENT_ENVELOPE_SCHEMA

log = get_logger(__name__)


@dataclass
class ConsumedEvent:
    """One decoded message, plus the Kafka metadata that came with it."""

    envelope: dict[str, Any]  # the decoded Avro envelope
    payload: dict[str, Any]  # payload, JSON-decoded from the envelope string
    topic: str
    partition: int
    offset: int
    key: str | None
    timestamp_ms: int

    @property
    def source(self) -> str:
        return str(self.envelope.get("source", "unknown"))

    @property
    def event_id(self) -> str:
        return str(self.envelope.get("event_id", ""))


@dataclass
class ConsumerStats:
    """What happened during a consume loop."""

    consumed: int = 0
    processed: int = 0
    failed: int = 0
    committed_batches: int = 0
    errors: list[str] = field(default_factory=list)


class EventConsumer:
    """Reads AEGIS events from one or more topics, with manual offset commits."""

    def __init__(
        self,
        *,
        topics: list[str],
        group_id: str,
        from_beginning: bool = False,
        commit_every: int = 100,
        max_attempts: int = 3,
    ) -> None:
        """
        Args:
            topics: topics to subscribe to.
            group_id: the consumer group. Two processes sharing a group SPLIT
                the partitions between them (scaling out). Two processes with
                DIFFERENT groups each receive every record (fan-out). Choosing
                the wrong one is a common and confusing mistake.
            from_beginning: read the whole retained history rather than only
                new records. This is how replay works.
            commit_every: commit the offset after this many processed records.
                A trade-off: commit rarely and a crash re-reads more; commit on
                every record and you pay a broker round-trip per message.
            max_attempts: how many times to retry one record before sending it
                to the dead-letter topic and moving on.
        """
        self.topics = topics
        self.group_id = group_id
        self.commit_every = commit_every
        self.max_attempts = max_attempts
        self.stats = ConsumerStats()
        self._running = False

        self._consumer = Consumer(
            settings.kafka.consumer_config(group_id, from_beginning=from_beginning)
        )
        registry = SchemaRegistryClient({"url": settings.kafka.schema_registry_url})
        # The deserialiser reads the 4-byte schema ID from each message and
        # fetches THAT schema from the registry - so a message written last
        # year, under an older schema, still decodes correctly. Passing our
        # schema as the reader schema is what applies Avro's resolution rules
        # (defaults filled in for fields the writer did not have).
        self._deserializer = AvroDeserializer(registry, json.dumps(EVENT_ENVELOPE_SCHEMA))

    # ------------------------------------------------------------- lifecycle

    def _install_signal_handlers(self) -> None:
        """Stop cleanly on Ctrl+C instead of dying mid-batch.

        Without this, Ctrl+C raises KeyboardInterrupt wherever the code happens
        to be - possibly after processing a record but before committing its
        offset. Setting a flag and finishing the current batch means shutdown
        is predictable, and the consumer leaves the group politely so Kafka
        does not have to wait for a session timeout to rebalance.
        """

        def handle(signum: int, frame: FrameType | None) -> None:
            log.info("shutdown_requested", signal=signum)
            self._running = False

        signal.signal(signal.SIGINT, handle)
        if sys.platform != "win32":
            signal.signal(signal.SIGTERM, handle)

    def _decode(self, msg: Message) -> ConsumedEvent:
        """Turn raw Kafka bytes into a usable object.

        Every accessor below (topic, partition, offset, key) is typed Optional
        by confluent-kafka, because a Message can also represent an error or an
        end-of-partition marker rather than a real record. We have already
        filtered those out before calling this, but we check anyway instead of
        casting the problem away.

        Note especially `partition is None` rather than `partition or 0`:
        partition 0 is a perfectly valid partition and is falsy, so the short
        form would silently rewrite partition 0 as partition 0 - correct by
        accident here, and wrong the moment the same idiom is used on offsets,
        where offset 0 is the first record in the log.
        """
        topic = msg.topic()
        partition = msg.partition()
        offset = msg.offset()
        if topic is None or partition is None or offset is None:
            raise ValueError("message has no topic/partition/offset; not a data record")

        envelope = self._deserializer(msg.value(), SerializationContext(topic, MessageField.VALUE))
        if envelope is None:
            # A null value in Kafka is a "tombstone", meaningful only on
            # compacted topics. Ours use delete retention, so this should never
            # happen - and if it does, it is worth an error rather than a
            # silently skipped record.
            raise ValueError("message deserialised to None (tombstone?)")

        raw_key = msg.key()
        raw_payload = envelope.get("payload") or "{}"
        return ConsumedEvent(
            envelope=envelope,
            payload=json.loads(raw_payload),
            topic=topic,
            partition=partition,
            offset=offset,
            key=raw_key.decode("utf-8", errors="replace") if raw_key else None,
            timestamp_ms=msg.timestamp()[1],
        )

    # ------------------------------------------------------------------ read

    def consume(
        self,
        handler: Callable[[ConsumedEvent], None],
        *,
        max_records: int | None = None,
        idle_timeout: float | None = None,
        dlq_sink: Any = None,
    ) -> ConsumerStats:
        """Read messages and pass each to `handler`, committing after success.

        Args:
            handler: called once per decoded event. Raising from it counts as a
                processing failure and triggers retry / dead-letter handling.
            max_records: stop after this many records. Useful for demos, tests
                and one-shot batch reads.
            idle_timeout: stop after this many seconds with no new messages.
                Turns an endless consumer into a "drain what exists" job -
                which is exactly what a scheduled batch run wants.
            dlq_sink: a KafkaSink used to publish records that keep failing.
        """
        self._install_signal_handlers()
        self._consumer.subscribe(self.topics)
        self._running = True
        since_commit = 0
        idle_seconds = 0.0

        log.info("consumer_start", topics=self.topics, group=self.group_id, max_records=max_records)

        try:
            while self._running:
                msg = self._consumer.poll(timeout=1.0)

                if msg is None:
                    idle_seconds += 1.0
                    if idle_timeout is not None and idle_seconds >= idle_timeout:
                        log.info("idle_timeout_reached", seconds=idle_seconds)
                        break
                    continue
                idle_seconds = 0.0

                error = msg.error()
                if error is not None:
                    # PARTITION_EOF is informational, not a failure: it just
                    # means we reached the end of a partition. Everything else
                    # is a real error worth recording.
                    if error.code() == KafkaError._PARTITION_EOF:
                        continue
                    self.stats.failed += 1
                    self.stats.errors.append(str(error))
                    log.error("consume_error", error=str(error)[:200])
                    continue

                self.stats.consumed += 1

                try:
                    event = self._decode(msg)
                except Exception as exc:
                    # Undecodable bytes. Retrying cannot help - the message will
                    # never decode - so go straight to the dead-letter topic.
                    self.stats.failed += 1
                    log.error("decode_failed", error=str(exc)[:200], offset=msg.offset())
                    if dlq_sink is not None:
                        dlq_sink.send_to_dlq(
                            stage="consume-decode",
                            error=exc,
                            raw_payload=repr(msg.value())[:10_000],
                            topic=msg.topic(),
                        )
                    since_commit += 1
                    continue

                # Bounded retries. A record that fails every attempt is a poison
                # pill: preserve it, then move past it so the consumer is not
                # stuck re-reading it forever.
                for attempt in range(1, self.max_attempts + 1):
                    try:
                        handler(event)
                        self.stats.processed += 1
                        break
                    except Exception as exc:
                        if attempt == self.max_attempts:
                            self.stats.failed += 1
                            log.error(
                                "handler_failed_permanently",
                                error=str(exc)[:200],
                                attempts=attempt,
                                offset=event.offset,
                            )
                            if dlq_sink is not None:
                                dlq_sink.send_to_dlq(
                                    stage="consume-handle",
                                    error=exc,
                                    raw_payload=json.dumps(event.envelope, default=str),
                                    source=event.source,
                                    topic=event.topic,
                                    retry_count=attempt,
                                )
                        else:
                            log.warning("handler_retry", attempt=attempt, error=str(exc)[:120])

                since_commit += 1

                # THE COMMIT. Only ever reached after the handler has been given
                # every chance to process the record, or the record has been
                # safely preserved in the dead-letter topic.
                if since_commit >= self.commit_every:
                    self._consumer.commit(asynchronous=False)
                    self.stats.committed_batches += 1
                    since_commit = 0

                if max_records is not None and self.stats.consumed >= max_records:
                    break

        except KafkaException as exc:
            log.error("consumer_fatal", error=str(exc)[:300])
            raise
        finally:
            # Commit whatever is outstanding, then leave the group. Without the
            # close(), Kafka waits out the session timeout (45s) before
            # reassigning our partitions - so every restart would stall.
            if since_commit > 0:
                try:
                    self._consumer.commit(asynchronous=False)
                    self.stats.committed_batches += 1
                except Exception as exc:
                    log.warning("final_commit_failed", error=str(exc)[:200])
            self._consumer.close()
            log.info(
                "consumer_stopped",
                consumed=self.stats.consumed,
                processed=self.stats.processed,
                failed=self.stats.failed,
                commits=self.stats.committed_batches,
            )

        return self.stats

    def read_batch(self, *, limit: int, idle_timeout: float = 5.0) -> Iterator[ConsumedEvent]:
        """Read up to `limit` records and yield them. Convenience for inspection.

        Note: this does NOT commit offsets, because a caller who is only
        looking at data should not move anyone's bookmark.
        """
        collected: list[ConsumedEvent] = []
        self.consume(collected.append, max_records=limit, idle_timeout=idle_timeout)
        yield from collected


def lag_report(group_id: str, topics: list[str]) -> list[dict[str, Any]]:
    """How far behind a consumer group is, per partition.

    CONSUMER LAG is the single most important streaming metric: the number of
    records produced but not yet processed. Steady lag means the consumer keeps
    up. Growing lag means it does not, and every dashboard downstream is
    showing stale data. It is the first thing to put on a monitor, and the
    first thing anyone asks about in an incident.
    """
    from confluent_kafka import TopicPartition

    consumer = Consumer(settings.kafka.consumer_config(group_id))
    rows: list[dict[str, Any]] = []
    try:
        for topic in topics:
            metadata = consumer.list_topics(topic, timeout=10)
            topic_meta = metadata.topics.get(topic)
            if topic_meta is None or topic_meta.error is not None:
                continue

            partitions = [TopicPartition(topic, p) for p in topic_meta.partitions]
            # committed() asks the broker where this group's bookmark is.
            committed = consumer.committed(partitions, timeout=10)

            for tp in committed:
                low, high = consumer.get_watermark_offsets(tp, timeout=10, cached=False)
                # A group that has never committed reports offset -1001
                # (OFFSET_INVALID). Treat that as "starting from the beginning".
                position = tp.offset if tp.offset >= 0 else low
                rows.append(
                    {
                        "topic": topic,
                        "partition": tp.partition,
                        "committed_offset": tp.offset if tp.offset >= 0 else None,
                        "high_watermark": high,
                        "lag": max(high - position, 0),
                    }
                )
    finally:
        consumer.close()
    return rows
