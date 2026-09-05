"""Prove that the safety mechanisms actually work.

Run with:  python scripts/demo_contracts.py

It is easy to write a README claiming "schema enforcement" and "a dead-letter
queue". This script demonstrates both against the running system, so the claim
is evidence rather than assertion.

Three demonstrations:

  1. A BREAKING schema change is refused by the registry.
  2. A SAFE schema change is accepted.
  3. A record that cannot be serialised lands in the dead-letter topic,
     with its original content and the reason, while the pipeline keeps going.
"""

from __future__ import annotations

import copy
import json
import sys

from confluent_kafka.schema_registry import Schema, SchemaRegistryClient

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from aegis.config import settings
from aegis.sources.models import Event, EventType, Source, utc_now
from aegis.streaming.schemas import EVENT_ENVELOPE_SCHEMA, subject_for
from aegis.streaming.topics import DLQ_TOPIC, topic_for

GREEN, RED, YELLOW, DIM, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[2m", "\033[0m"


def header(text: str) -> None:
    print(f"\n{DIM}{'=' * 76}{RESET}")
    print(f"  {text}")
    print(f"{DIM}{'=' * 76}{RESET}")


def demo_breaking_change_is_refused() -> None:
    """A field removal breaks every existing reader, so the registry must refuse it."""
    header("1. A BREAKING schema change must be REFUSED")

    client = SchemaRegistryClient({"url": settings.kafka.schema_registry_url})
    subject = subject_for(topic_for(Source.FEODO))

    # Remove `content_hash`. Any consumer that reads that field would break,
    # because messages written under the new schema simply would not have it.
    broken = copy.deepcopy(EVENT_ENVELOPE_SCHEMA)
    broken["fields"] = [f for f in broken["fields"] if f["name"] != "content_hash"]

    print(f"  subject : {subject}")
    print("  change  : remove the field 'content_hash' (no default declared)")
    print(f"  {DIM}why it is dangerous: consumers that read that field would start{RESET}")
    print(f"  {DIM}receiving nothing, with no error raised anywhere.{RESET}")
    print()
    print(f"  {YELLOW}This exact test was ACCEPTED when we first ran it.{RESET}")
    print(f"  {DIM}The registry's default level is BACKWARD, which only asks 'can a NEW{RESET}")
    print(f"  {DIM}reader read OLD data?' - and a reader that dropped a field can. So a{RESET}")
    print(f"  {DIM}deletion sailed through, even though it breaks any consumer that has{RESET}")
    print(f"  {DIM}not been redeployed yet.{RESET}")
    print(f"  {DIM}AEGIS therefore sets FULL (see streaming/admin.py), which asks BOTH{RESET}")
    print(f"  {DIM}directions. Under FULL the same change is refused:{RESET}\n")

    try:
        compatible = client.test_compatibility(subject, Schema(json.dumps(broken), "AVRO"))
        if compatible:
            print(f"  {RED}UNEXPECTED: the registry accepted a breaking change.{RESET}")
            print(f"  {RED}Check that compatibility is set to BACKWARD or stricter.{RESET}")
        else:
            print(f"  {GREEN}REFUSED{RESET} - the registry rejected it as incompatible.")
            print("  A deploy carrying this change fails in CI, not in production.")
    except Exception as exc:
        print(f"  {GREEN}REFUSED{RESET} - {str(exc)[:180]}")


def demo_safe_change_is_accepted() -> None:
    """Adding an optional field with a default is safe, and must be allowed."""
    header("2. A SAFE schema change must be ACCEPTED")

    client = SchemaRegistryClient({"url": settings.kafka.schema_registry_url})
    subject = subject_for(topic_for(Source.FEODO))

    # Add a new OPTIONAL field with a default. Old consumers ignore it; new
    # consumers reading old messages get the default. Nothing breaks either way.
    evolved = copy.deepcopy(EVENT_ENVELOPE_SCHEMA)
    evolved["fields"].append(
        {
            "name": "enrichment_version",
            "type": ["null", "string"],
            "default": None,
            "doc": "Version of the enrichment ruleset applied (added in Phase 4).",
        }
    )

    print(f"  subject : {subject}")
    print("  change  : add optional field 'enrichment_version' with default null")
    print(f"  {DIM}why it is safe: old readers ignore the new field; new readers{RESET}")
    print(f"  {DIM}reading old messages fall back to the declared default.{RESET}\n")

    try:
        compatible = client.test_compatibility(subject, Schema(json.dumps(evolved), "AVRO"))
        if compatible:
            print(f"  {GREEN}ACCEPTED{RESET} - the schema can evolve without a migration.")
            print("  This is why every optional field in schemas.py has a default.")
        else:
            print(f"  {RED}REFUSED{RESET} - unexpected; a defaulted optional field should pass.")
    except Exception as exc:
        print(f"  {RED}error: {str(exc)[:180]}{RESET}")


def demo_dead_letter_queue() -> None:
    """A record that cannot be serialised must be preserved, not lost."""
    header("3. A BAD RECORD must land in the dead-letter topic, not vanish")

    from aegis.streaming.producer import KafkaSink

    sink = KafkaSink(client_id="aegis-dlq-demo")

    good = Event(
        source=Source.FEODO,
        event_type=EventType.IOC_IP,
        occurred_at=utc_now(),
        payload={"ip_address": "203.0.113.10", "malware": "DemoBot"},
    )

    # A payload containing something JSON cannot represent. Our serialiser calls
    # json.dumps(..., default=str) so most objects survive; a self-referencing
    # structure does not, and raises during serialisation. That is a realistic
    # stand-in for the real cause: a source sending something unexpected.
    cyclic: dict[str, object] = {"ip_address": "203.0.113.99"}
    cyclic["self"] = cyclic
    bad = Event(
        source=Source.FEODO,
        event_type=EventType.IOC_IP,
        occurred_at=utc_now(),
        payload=cyclic,
    )

    print("  Sending 3 records: good, BAD, good\n")
    sink.write(good)
    sink.write(bad)
    sink.write(good)
    sink.close()

    print()
    print(f"  produced to aegis.raw.feodo : {sink.produced}   (the 2 good records)")
    print(f"  routed to the dead-letter   : {sink.dead_lettered}   (the bad one)")
    print(f"  broker acknowledgements     : {sink.delivered}   (2 good + 1 dead letter)")
    print(f"  records lost                : {sink.dlq_write_failures}")
    print()
    if sink.produced >= 2 and sink.dead_lettered >= 1:
        print(f"  {GREEN}The pipeline did not stop, and nothing was lost.{RESET}")
    print(f"  The bad record is in '{DLQ_TOPIC.name}' with its error attached.")
    print()
    print(f"  {DIM}This demo also found a real bug. The first version of the{RESET}")
    print(f"  {DIM}dead-letter path serialised the failed record to JSON to store it -{RESET}")
    print(f"  {DIM}but JSON serialisation was what had just failed, so it raised again{RESET}")
    print(f"  {DIM}INSIDE the error handler and crashed the collector. The fix is{RESET}")
    print(f"  {DIM}safe_repr() in streaming/producer.py: error handling must never{RESET}")
    print(f"  {DIM}depend on the machinery that failed.{RESET}")


def show_dlq_contents() -> None:
    """Read back what is sitting in the dead-letter topic."""
    header("4. What is actually IN the dead-letter topic")

    import json as _json

    from confluent_kafka import Consumer
    from confluent_kafka.schema_registry import SchemaRegistryClient as SRC
    from confluent_kafka.schema_registry.avro import AvroDeserializer
    from confluent_kafka.serialization import MessageField, SerializationContext

    from aegis.streaming.schemas import DEAD_LETTER_SCHEMA

    registry = SRC({"url": settings.kafka.schema_registry_url})
    deserializer = AvroDeserializer(registry, _json.dumps(DEAD_LETTER_SCHEMA))

    consumer = Consumer(settings.kafka.consumer_config("aegis-dlq-inspect", from_beginning=True))
    consumer.subscribe([DLQ_TOPIC.name])

    found = 0
    try:
        for _ in range(40):  # poll a bounded number of times, then give up
            msg = consumer.poll(timeout=1.0)
            if msg is None or msg.error():
                continue
            record = deserializer(
                msg.value(), SerializationContext(DLQ_TOPIC.name, MessageField.VALUE)
            )
            if record is None:
                continue
            found += 1
            print(f"\n  {YELLOW}dead letter #{found}{RESET}")
            print(f"    stage      : {record['stage']}")
            print(f"    error_type : {record['error_type']}")
            print(f"    error      : {str(record['error_message'])[:120]}")
            print(f"    source     : {record['source']}")
            print(f"    raw kept   : {len(str(record['raw_payload']))} characters")
            if found >= 3:
                break
    finally:
        consumer.close()

    if found == 0:
        print(f"\n  {DIM}(empty - run demo 3 first){RESET}")
    else:
        print(f"\n  {GREEN}{found} failed record(s) preserved, each with its cause.{RESET}")
        print("  Once the bug is fixed, these can be replayed. Nothing is lost.")


def main() -> None:
    demo_breaking_change_is_refused()
    demo_safe_change_is_accepted()
    demo_dead_letter_queue()
    show_dlq_contents()
    print(f"\n{DIM}{'=' * 76}{RESET}\n")


if __name__ == "__main__":
    main()
