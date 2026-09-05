"""Tests for the streaming layer.

Split deliberately into two kinds:

  * Unit tests (the majority) - pure logic, no broker, run in milliseconds.
  * Integration tests, marked `@pytest.mark.integration` - these need Docker
    running, and CI runs them in a separate later stage.

Keeping them apart matters. If every test needed a broker, the suite would take
minutes and people would stop running it before committing. The fast tests are
the ones that actually catch mistakes, because they are the ones that get run.
"""

from __future__ import annotations

import json

import pytest

from aegis.sources.models import Event, EventType, Source, utc_now
from aegis.streaming.producer import key_for, safe_repr
from aegis.streaming.schemas import (
    DEAD_LETTER_SCHEMA,
    EVENT_ENVELOPE_SCHEMA,
    event_to_avro_dict,
    subject_for,
)
from aegis.streaming.topics import DLQ_TOPIC, TOPICS, all_specs, topic_for


def make_event(payload: dict[str, object], source: Source = Source.FEODO) -> Event:
    return Event(
        source=source,
        event_type=EventType.IOC_IP,
        occurred_at=utc_now(),
        payload=payload,
    )


# ============================================================================
# Topic design
# ============================================================================
class TestTopics:
    def test_every_source_has_a_topic(self) -> None:
        """A source with no topic fails at produce time, in production.

        Cheap to check here, expensive to discover there.
        """
        for source in (Source.URLHAUS, Source.CISA_KEV, Source.FEODO, Source.TOR_EXIT):
            assert topic_for(source).startswith("aegis.raw.")

    def test_unknown_source_fails_loudly(self) -> None:
        with pytest.raises(KeyError, match="No topic declared"):
            topic_for("not_a_real_source")

    def test_topic_names_are_unique(self) -> None:
        names = [spec.name for spec in all_specs()]
        assert len(names) == len(set(names))

    def test_high_volume_source_has_room_to_scale(self) -> None:
        """URLhaus is the only feed big enough to need parallel consumers.

        Partitions can be ADDED later but never removed, and adding them
        reshuffles which partition a key maps to. So the count has to be a
        deliberate decision, not a default - this test records that it was.
        """
        assert TOPICS[Source.URLHAUS.value].partitions >= 3
        assert TOPICS[Source.FEODO.value].partitions == 1

    def test_reference_data_is_kept_longer_than_high_volume_data(self) -> None:
        """Retention should reflect value and size, not one global default."""
        kev = TOPICS[Source.CISA_KEV.value].retention_hours
        urlhaus = TOPICS[Source.URLHAUS.value].retention_hours
        assert kev > urlhaus

    def test_dlq_retention_outlives_source_retention(self) -> None:
        """You need time to notice a failure, fix the code, and replay.

        That clock starts when a human looks at a dashboard - not when the
        record failed. A DLQ that expires before anyone investigates is
        theatre.
        """
        assert DLQ_TOPIC.retention_hours >= TOPICS[Source.URLHAUS.value].retention_hours

    def test_raw_topics_delete_rather_than_compact(self) -> None:
        """Compaction keeps only the newest record per key - wrong for raw events.

        We care about every observation, including the four earlier times we
        saw the same IP. Compaction would silently discard them.
        """
        for spec in all_specs():
            assert spec.broker_config()["cleanup.policy"] == "delete"

    def test_retention_is_expressed_in_milliseconds(self) -> None:
        """Kafka wants retention.ms. A units mistake here silently deletes data."""
        spec = TOPICS[Source.TOR_EXIT.value]
        assert spec.broker_config()["retention.ms"] == str(30 * 24 * 3_600_000)


# ============================================================================
# Partition key - the most consequential decision in the layer
# ============================================================================
class TestPartitionKey:
    def test_keys_on_the_entity_not_the_source(self) -> None:
        """Keying by source would put every URLhaus record in one partition."""
        event = make_event({"ip_address": "1.2.3.4", "malware": "QakBot"})
        assert key_for(event) == "1.2.3.4"

    def test_url_events_key_on_the_url(self) -> None:
        event = make_event({"url": "http://evil.test/x", "threat": "malware_download"})
        assert key_for(event) == "http://evil.test/x"

    def test_cve_events_key_on_the_cve_id(self) -> None:
        event = make_event({"cve_id": "CVE-2026-1234", "vendor": "Microsoft"})
        assert key_for(event) == "CVE-2026-1234"

    def test_same_entity_always_produces_the_same_key(self) -> None:
        """This is the ordering guarantee. Two observations of one IP must
        land in the same partition, or 'current status' becomes a race."""
        a = make_event({"ip_address": "5.5.5.5", "status": "online"})
        b = make_event({"ip_address": "5.5.5.5", "status": "offline"})
        assert key_for(a) == key_for(b)

    def test_falls_back_to_event_id_when_no_entity_exists(self) -> None:
        """No entity means nothing to order against, so round-robin is correct."""
        event = make_event({"note": "no identifiable entity here"})
        assert key_for(event) == event.event_id

    def test_keys_spread_across_partitions(self) -> None:
        """Sanity-check the balance claim with the same hash Kafka uses.

        Not a proof, but it would catch a key choice that collapses everything
        onto one partition - which is the failure this decision exists to avoid.
        """
        import hashlib

        counts = [0, 0, 0]
        for i in range(3000):
            key = key_for(make_event({"url": f"http://test.local/{i}"}))
            digest = hashlib.md5(key.encode()).digest()  # noqa: S324 - not security
            counts[int.from_bytes(digest[:4], "big") % 3] += 1

        # Every partition should get roughly a third. Allow generous slack;
        # we are detecting collapse, not measuring hash quality.
        assert all(700 < c < 1300 for c in counts), f"badly skewed: {counts}"


# ============================================================================
# Schemas
# ============================================================================
class TestSchemas:
    def test_every_optional_field_declares_a_default(self) -> None:
        """Under FULL compatibility, a field without a default cannot be
        added OR removed later. Defaults are what make the schema evolvable."""
        for schema in (EVENT_ENVELOPE_SCHEMA, DEAD_LETTER_SCHEMA):
            for field in schema["fields"]:
                type_ = field["type"]
                if isinstance(type_, list) and "null" in type_:
                    assert "default" in field, f"{field['name']} is optional but has no default"
                    assert field["default"] is None
                    # Avro requires the default's type FIRST in the union.
                    assert type_[0] == "null", f"{field['name']}: put 'null' first in the union"

    def test_timestamps_use_a_logical_type(self) -> None:
        """Without logicalType these are anonymous longs, and every reader has
        to be told separately that they are microsecond timestamps."""
        fields = {f["name"]: f for f in EVENT_ENVELOPE_SCHEMA["fields"]}
        for name in ("occurred_at", "ingested_at"):
            assert fields[name]["type"]["logicalType"] == "timestamp-micros"

    def test_every_field_is_documented(self) -> None:
        """The registry serves these docs to anyone inspecting the schema.
        They are the documentation your future consumers actually read."""
        for schema in (EVENT_ENVELOPE_SCHEMA, DEAD_LETTER_SCHEMA):
            for field in schema["fields"]:
                assert field.get("doc"), f"{schema['name']}.{field['name']} has no doc"

    def test_dlq_preserves_the_original_bytes(self) -> None:
        """If parsing is what failed, a parsed copy is the one thing we cannot
        trust. Replay needs the original."""
        names = {f["name"] for f in DEAD_LETTER_SCHEMA["fields"]}
        assert {"raw_payload", "error_type", "error_message", "stage"} <= names

    def test_subject_follows_the_registry_convention(self) -> None:
        """'<topic>-value' is what Console, Connect and ksqlDB all expect."""
        assert subject_for("aegis.raw.feodo") == "aegis.raw.feodo-value"


class TestAvroConversion:
    def test_payload_becomes_a_canonical_json_string(self) -> None:
        """Key order must not change the bytes, or content_hash stops working."""
        a = event_to_avro_dict(make_event({"b": 2, "a": 1}))
        b = event_to_avro_dict(make_event({"a": 1, "b": 2}))
        assert a["payload"] == b["payload"] == '{"a":1,"b":2}'

    def test_datetimes_are_left_as_objects_for_the_serialiser(self) -> None:
        """Converting them ourselves would encode them twice."""
        from datetime import datetime

        record = event_to_avro_dict(make_event({"ip_address": "1.1.1.1"}))
        assert isinstance(record["occurred_at"], datetime)
        assert isinstance(record["ingested_at"], datetime)

    def test_output_matches_the_schema_field_set_exactly(self) -> None:
        """A field in one and not the other fails at serialise time, in prod."""
        record = event_to_avro_dict(make_event({"ip_address": "1.1.1.1"}))
        assert set(record) == {f["name"] for f in EVENT_ENVELOPE_SCHEMA["fields"]}

    def test_non_json_values_are_stringified_rather_than_crashing(self) -> None:
        from datetime import date

        record = event_to_avro_dict(make_event({"seen": date(2026, 1, 1)}))
        assert json.loads(record["payload"])["seen"] == "2026-01-01"


# ============================================================================
# The dead-letter safety net - regression tests for a bug this project hit
# ============================================================================
class TestSafeRepr:
    def test_normal_event_serialises_as_json(self) -> None:
        text = safe_repr(make_event({"ip_address": "1.1.1.1"}))
        assert '"ip_address":"1.1.1.1"' in text.replace(" ", "")

    def test_circular_payload_does_not_raise(self) -> None:
        """THE REGRESSION TEST.

        The original dead-letter path called to_json_line() to capture a failed
        record - but JSON serialisation was exactly what had failed, so it
        raised a second time inside the error handler and crashed the whole
        collector. The queue built to prevent a crash caused one.

        This test locks in the rule: error handling must never depend on the
        machinery that failed.
        """
        cyclic: dict[str, object] = {"ip_address": "9.9.9.9"}
        cyclic["self"] = cyclic

        text = safe_repr(make_event(cyclic))  # must not raise

        assert isinstance(text, str)
        assert "9.9.9.9" in text

    def test_result_is_bounded(self) -> None:
        """A huge payload must not blow up the DLQ message."""
        text = safe_repr(make_event({"blob": "x" * 200_000}), limit=1000)
        assert len(text) <= 1000


# ============================================================================
# Integration - these need Docker running
# ============================================================================
@pytest.mark.integration
class TestAgainstRealBroker:
    def test_topics_can_be_created_idempotently(self) -> None:
        from aegis.streaming.admin import create_topics

        first = create_topics()
        second = create_topics()
        assert all(v in ("created", "exists") for v in first.values())
        # The second run must change nothing at all.
        assert all(v == "exists" for v in second.values())

    def test_round_trip_through_kafka(self) -> None:
        """Produce an event, read it back, and confirm it survived unchanged."""
        from aegis.streaming.consumer import EventConsumer
        from aegis.streaming.producer import KafkaSink

        marker = f"test-{utc_now().timestamp()}"
        event = make_event({"ip_address": "198.51.100.7", "marker": marker})

        sink = KafkaSink(client_id="aegis-pytest")
        sink.write(event)
        sink.close()
        assert sink.all_delivered

        consumer = EventConsumer(
            topics=[topic_for(Source.FEODO)],
            group_id=f"aegis-pytest-{marker}",
            from_beginning=True,
            commit_every=10_000,
        )
        found = []
        consumer.consume(
            lambda e: found.append(e) if e.payload.get("marker") == marker else None,
            max_records=5000,
            idle_timeout=5.0,
        )
        assert found, "the produced event was not read back"
        assert found[0].payload["ip_address"] == "198.51.100.7"
        assert found[0].event_id == event.event_id

    def test_compatibility_is_set_to_full(self) -> None:
        """BACKWARD (the default) permits field deletion, which breaks a
        consumer that has not been redeployed yet. See ADR 0004."""
        from aegis.streaming.admin import ensure_compatibility

        assert ensure_compatibility() == "FULL"
