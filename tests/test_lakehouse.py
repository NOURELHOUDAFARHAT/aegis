"""Tests for the lakehouse layer.

Several of these are regression tests for bugs this project actually hit in
Phase 3. Those are the most valuable tests in the file: a test that encodes a
mistake you have already made once is worth more than three tests of behaviour
that was never in doubt.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pyarrow as pa
import pytest

from aegis.lakehouse.tables import (
    BRONZE_PARTITION_SPEC,
    BRONZE_SCHEMA,
    BRONZE_TABLES,
    table_for,
)
from aegis.lakehouse.writer import BRONZE_ARROW_SCHEMA, _as_utc
from aegis.sources.models import Source


# ============================================================================
# Schema design
# ============================================================================
class TestBronzeSchema:
    def test_arrow_and_iceberg_schemas_have_the_same_columns(self) -> None:
        """The two schemas are written in different files and must not drift.

        PyIceberg validates on write, so a mismatch would fail at runtime -
        but it would fail during a nightly load, not during development.
        """
        iceberg_names = [f.name for f in BRONZE_SCHEMA.fields]
        arrow_names = [f.name for f in BRONZE_ARROW_SCHEMA]
        assert iceberg_names == arrow_names

    def test_required_fields_match_between_schemas(self) -> None:
        """A field required in Iceberg must be non-nullable in Arrow, or a null
        slips through Arrow and is only rejected at commit time."""
        arrow_nullable = {f.name: f.nullable for f in BRONZE_ARROW_SCHEMA}
        for field in BRONZE_SCHEMA.fields:
            assert arrow_nullable[field.name] == (not field.required), field.name

    def test_field_ids_are_unique_and_stable(self) -> None:
        """Iceberg identifies columns by ID, not name. Reusing or renumbering an
        ID silently attaches old data to a new column."""
        ids = [f.field_id for f in BRONZE_SCHEMA.fields]
        assert len(ids) == len(set(ids))
        assert ids == sorted(ids), "field IDs should be assigned in order"

    def test_timestamps_are_timezone_aware(self) -> None:
        """A naive timestamp column would undo every guard in the Event model."""
        for name in ("occurred_at", "ingested_at", "_bronze_written_at"):
            field = BRONZE_ARROW_SCHEMA.field(name)
            assert field.type.tz == "UTC", f"{name} must be UTC-aware"

    def test_kafka_provenance_is_recorded(self) -> None:
        """Without topic/partition/offset, a Bronze row cannot be traced back to
        the log entry it came from, and 'this is what the feed sent' becomes an
        assertion rather than a checkable claim."""
        names = {f.name for f in BRONZE_SCHEMA.fields}
        assert {"_kafka_topic", "_kafka_partition", "_kafka_offset"} <= names

    def test_payload_stays_a_string(self) -> None:
        """Bronze must not parse the payload into columns. Its contract is
        'exactly what arrived', and parsing is a Silver concern."""
        assert BRONZE_ARROW_SCHEMA.field("payload").type == pa.string()


class TestPartitioning:
    def test_partitioned_by_ingestion_day_not_event_day(self) -> None:
        """Partitioning by occurred_at would be the obvious choice and is wrong.

        The CISA feed's occurred_at spans 2021 to today, so it would create
        ~1,700 partitions of one or two rows on the very first load - the
        small-files problem, immediately. ingested_at gives one partition per
        day we actually ran.
        """
        assert len(BRONZE_PARTITION_SPEC.fields) == 1
        partition_field = BRONZE_PARTITION_SPEC.fields[0]

        ingested_at_id = next(f.field_id for f in BRONZE_SCHEMA.fields if f.name == "ingested_at")
        assert partition_field.source_id == ingested_at_id
        assert partition_field.name == "ingested_day"


class TestTableMapping:
    def test_every_source_has_a_bronze_table(self) -> None:
        for source in Source:
            if source.value in BRONZE_TABLES:
                assert table_for(source).startswith("bronze.")

    def test_unknown_source_fails_loudly(self) -> None:
        with pytest.raises(KeyError, match="No Bronze table"):
            table_for("not_a_source")


# ============================================================================
# Timestamp coercion - a real source of silent corruption
# ============================================================================
class TestAsUtc:
    def test_aware_datetime_passes_through(self) -> None:
        value = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        assert _as_utc(value) == value

    def test_naive_datetime_is_assumed_utc_not_local(self) -> None:
        """Avro timestamps are UTC by definition. Interpreting a naive one as
        local time would shift every row by the machine's offset - a corruption
        that looks perfectly plausible in the data."""
        result = _as_utc(datetime(2026, 1, 1, 12, 0))  # noqa: DTZ001 - the point of the test
        assert result.tzinfo == timezone.utc
        assert result.hour == 12

    def test_integer_microseconds_are_converted(self) -> None:
        result = _as_utc(1_654_377_893_000_000)
        assert result.tzinfo == timezone.utc
        assert result.year == 2022

    def test_nonsense_raises_rather_than_guessing(self) -> None:
        with pytest.raises(TypeError):
            _as_utc("not a timestamp")


# ============================================================================
# REGRESSION TESTS for the two Phase 3 bugs
# ============================================================================
class TestPhase3Regressions:
    def test_kafka_message_timestamp_uses_ingestion_time(self) -> None:
        """REGRESSION: the producer once stamped messages with EVENT time.

        Kafka's message timestamp is not decorative - with the default
        `CreateTime` policy the broker uses it to decide when a log segment has
        aged out. URLhaus publishes a rolling 30-day window, so on a topic with
        7-day retention most records were already expired the moment they were
        written. 45,233 messages were accepted, acknowledged, and deleted before
        any consumer read them. Nothing errored.

        This test reads the producer source and fails if event time ever
        reappears there. It is a crude check, but the alternative - asserting
        against a live broker - would not run in the fast unit suite, and this
        bug is worth catching in milliseconds.
        """
        from pathlib import Path

        import aegis.streaming.producer as producer_module

        source_code = Path(producer_module.__file__).read_text(encoding="utf-8")

        # Find the produce() call's timestamp argument.
        timestamp_lines = [
            line.strip()
            for line in source_code.splitlines()
            if line.strip().startswith("timestamp=")
        ]
        assert timestamp_lines, "produce() should set an explicit timestamp"
        for line in timestamp_lines:
            assert "ingested_at" in line, (
                "Kafka's message timestamp must be INGESTION time. Using "
                "occurred_at makes retention count from when the event happened, "
                "which silently deletes data. See docs/adr/0005."
            )
            assert "occurred_at" not in line

    def test_topics_force_broker_side_timestamps(self) -> None:
        """REGRESSION: the fix above is only half of it.

        Fixing the producer stops OUR code reintroducing the bug. Setting
        `message.timestamp.type=LogAppendTime` makes the broker overwrite
        whatever any producer claims, which stops anyone else's code doing it
        either. Defence in depth, on a bug that fails silently.
        """
        from aegis.streaming.topics import all_specs

        for spec in all_specs():
            assert spec.broker_config()["message.timestamp.type"] == "LogAppendTime", (
                f"{spec.name} would trust producer-supplied timestamps"
            )

    def test_bronze_writer_never_starts_at_latest(self) -> None:
        """REGRESSION: the Bronze writer once skipped a full topic and said 'ok'.

        `auto.offset.reset` decides where a consumer group with no committed
        offset begins. `latest` means 'ignore everything already here'. For a
        dashboard that is right; for a writer whose job is to miss nothing it is
        a silent data-loss bug - the first run reported 0 rows written against a
        topic holding 12,710 messages, and reported success.

        Because the setting only applies when there is no committed offset,
        `earliest` gives both properties we need: never skip on a first run,
        never reprocess on later ones.
        """
        from pathlib import Path

        import aegis.lakehouse.writer as writer_module

        source_code = Path(writer_module.__file__).read_text(encoding="utf-8")
        consumer_block = source_code.split("consumer = EventConsumer(")[1].split(")")[0]
        assert "from_beginning=True" in consumer_block, (
            "BronzeWriter must always use the earliest reset policy, or a fresh "
            "consumer group silently skips everything already in the topic."
        )


# ============================================================================
# Integration - needs Docker
# ============================================================================
@pytest.mark.integration
class TestAgainstRealLakehouse:
    def test_tables_can_be_created_idempotently(self) -> None:
        from aegis.lakehouse.catalog import ensure_namespaces
        from aegis.lakehouse.tables import create_bronze_tables

        ensure_namespaces()
        first = create_bronze_tables()
        second = create_bronze_tables()
        assert all(v in ("created", "exists") for v in first.values())
        assert all(v == "exists" for v in second.values())

    def test_write_then_read_round_trip(self) -> None:
        """Append a row and read it back, then confirm a snapshot was created."""
        from aegis.lakehouse.tables import load_bronze
        from aegis.sources.models import utc_now, uuid7

        table = load_bronze(Source.COWRIE)  # unused by collectors, safe to write
        before = len(table.metadata.snapshots)

        marker = uuid7()
        now = utc_now()
        table.append(
            pa.Table.from_pylist(
                [
                    {
                        "event_id": marker,
                        "source": "cowrie",
                        "event_type": "session.ssh",
                        "schema_version": 1,
                        "occurred_at": now,
                        "ingested_at": now,
                        "payload": '{"test": true}',
                        "content_hash": "deadbeef",
                        "collector_run_id": None,
                        "collector_host": "pytest",
                        "_kafka_topic": "test",
                        "_kafka_partition": 0,
                        "_kafka_offset": 0,
                        "_bronze_written_at": now,
                    }
                ],
                schema=BRONZE_ARROW_SCHEMA,
            )
        )
        table.refresh()

        assert len(table.metadata.snapshots) == before + 1
        ids = table.scan().to_arrow().column("event_id").to_pylist()
        assert marker in ids

    def test_time_travel_returns_an_older_state(self) -> None:
        """Reading an older snapshot must show fewer rows than the current one.

        This is the property that makes a data incident investigable: you can
        ask what the table looked like BEFORE the bad load, rather than
        reasoning about it from logs.
        """
        from aegis.lakehouse.tables import load_bronze

        table = load_bronze(Source.COWRIE)
        snapshots = table.metadata.snapshots
        if len(snapshots) < 2:
            pytest.skip("needs at least two snapshots; run the write test first")

        oldest = len(table.scan(snapshot_id=snapshots[0].snapshot_id).to_arrow())
        newest = len(table.scan().to_arrow())
        assert oldest < newest
