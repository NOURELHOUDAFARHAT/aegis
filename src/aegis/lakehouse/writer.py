"""The Bronze writer: reads Kafka, writes Iceberg.

This is the first component that joins two halves of the system, and it is the
one place where getting the ordering wrong loses data. Two rules govern it.

RULE 1 - BATCH THE WRITES
-------------------------
Every Iceberg commit writes at least one Parquet file plus a new metadata file,
and creates a snapshot. Committing per row would produce 15,077 files and
15,077 snapshots for one URLhaus run. That is the "small files problem", and it
is the most common way a working lakehouse becomes an unusably slow one:
queries spend all their time opening files instead of reading rows.

So we buffer in memory and commit in batches. The batch size is a trade-off
between file size (bigger is better for queries) and how much work a crash
repeats (smaller is better).

RULE 2 - FLUSH BEFORE YOU COMMIT OFFSETS
----------------------------------------
Buffering creates a window where rows exist only in memory. If Kafka offsets
were committed while rows sat in that buffer, a crash would lose them while
Kafka recorded them as done - silent data loss, the worst kind.

The order must always be:

    write the batch to Iceberg  ->  then commit the Kafka offsets

We enforce this structurally by flushing inside the consumer's `before_commit`
hook, so the unsafe order is not expressible rather than merely discouraged.

WHY DUPLICATES ARE FINE
-----------------------
Crash after the Iceberg write but before the offset commit, and those rows are
written twice. We accept that. Bronze is append-only and keeps `event_id`, so
Silver deduplicates on it. At-least-once delivery plus idempotent downstream
processing is how real systems get effectively-exactly-once without paying for
distributed transactions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pyarrow as pa

from aegis.lakehouse.tables import load_bronze
from aegis.logging import get_logger
from aegis.sources.models import Source, utc_now
from aegis.streaming.consumer import ConsumedEvent, EventConsumer
from aegis.streaming.topics import topic_for

log = get_logger(__name__)


# The PyArrow schema must line up with BRONZE_SCHEMA in tables.py, field for
# field. PyIceberg validates on write, so a mismatch fails loudly rather than
# writing a subtly wrong file - but keeping them adjacent in the codebase is
# what stops the mismatch happening in the first place.
#
# `timestamp("us", tz="UTC")` is deliberate: microseconds, explicitly UTC.
# A naive timestamp column here would defeat every guard we put in the Event
# model back in Phase 1.
_TS = pa.timestamp("us", tz="UTC")

BRONZE_ARROW_SCHEMA = pa.schema(
    [
        pa.field("event_id", pa.string(), nullable=False),
        pa.field("source", pa.string(), nullable=False),
        pa.field("event_type", pa.string(), nullable=False),
        pa.field("schema_version", pa.int32(), nullable=False),
        pa.field("occurred_at", _TS, nullable=False),
        pa.field("ingested_at", _TS, nullable=False),
        pa.field("payload", pa.string(), nullable=False),
        pa.field("content_hash", pa.string(), nullable=False),
        pa.field("collector_run_id", pa.string(), nullable=True),
        pa.field("collector_host", pa.string(), nullable=True),
        pa.field("_kafka_topic", pa.string(), nullable=True),
        pa.field("_kafka_partition", pa.int32(), nullable=True),
        pa.field("_kafka_offset", pa.int64(), nullable=True),
        pa.field("_bronze_written_at", _TS, nullable=True),
    ]
)


@dataclass
class TableStats:
    """One Bronze table's health, as reported by its current snapshot.

    A dataclass rather than a dict on purpose: the CLI reads six fields off
    this, and with a dict every one of them is typed `object`, so mypy cannot
    tell `int` from `datetime` and every use needs a cast. Typing the shape
    once here removes all of that - and documents what a caller can rely on.
    """

    table: str
    rows: int = 0
    files: int = 0
    size_bytes: int = 0
    snapshots: int = 0
    last_updated: datetime | None = None
    error: str | None = None

    @property
    def size_mb(self) -> float:
        return self.size_bytes / 1_048_576

    @property
    def avg_rows_per_file(self) -> float:
        """Low values signal the small-files problem before it hurts.

        A table with 40,000 rows across 400 files reads far slower than the
        same rows in 4 files, and it degrades a little more with every write.
        """
        return self.rows / self.files if self.files else 0.0


@dataclass
class WriteResult:
    """What one Bronze sync actually did."""

    source: str
    table: str
    rows_read: int = 0
    rows_written: int = 0
    batches: int = 0
    snapshots_created: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def snapshot_summary(snapshot: object) -> tuple[str, dict[str, str]]:
    """Extract (operation, properties) from an Iceberg snapshot summary.

    PyIceberg models the summary as a typed object rather than a plain dict:
    `operation` is an enum, and the running totals live in
    `additional_properties`. Reading it as if it were a dict type-checks
    badly and breaks between versions.

    Every caller wants the same two things, so we normalise once here instead
    of scattering defensive `getattr` calls through the CLI.
    """
    summary = getattr(snapshot, "summary", None)
    if summary is None:
        return "unknown", {}

    operation = getattr(summary, "operation", None)
    operation_name = getattr(operation, "value", None) or str(operation or "unknown")

    properties = getattr(summary, "additional_properties", None)
    if not isinstance(properties, dict):
        # Older PyIceberg exposed the whole thing as a mapping.
        try:
            properties = dict(summary)  # type: ignore[call-overload]
        except Exception:
            properties = {}

    return operation_name, {str(k): str(v) for k, v in properties.items()}


def _as_utc(value: object) -> datetime:
    """Coerce whatever Avro handed back into a timezone-aware UTC datetime.

    The Avro deserialiser returns timestamp-micros fields as datetimes, but
    whether they carry tzinfo depends on the library version. Rather than
    trusting that, we normalise here - because a naive datetime reaching
    PyArrow becomes a silently wrong value, not an error.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # Avro timestamp-micros as a raw integer.
        return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
    raise TypeError(f"cannot interpret {value!r} as a timestamp")


class BronzeWriter:
    """Consumes one source's Kafka topic and appends it to that source's Bronze table."""

    def __init__(
        self,
        source: Source | str,
        *,
        batch_size: int = 2000,
        group_suffix: str = "",
    ) -> None:
        self.source = source.value if isinstance(source, Source) else source
        self.batch_size = batch_size
        self.topic = topic_for(self.source)
        self.table = load_bronze(self.source)
        self.identifier = ".".join(self.table.name())

        # The consumer GROUP ID is what remembers our position between runs.
        # It must be stable across restarts - a random group id would re-read
        # the whole topic every time - and distinct per source, so a slow feed
        # cannot hold up a fast one.
        self.group_id = f"aegis-bronze-{self.source}{group_suffix}"

        self._buffer: list[dict[str, object]] = []
        self.result = WriteResult(source=self.source, table=self.identifier)
        self._snapshots_before = len(self.table.metadata.snapshots)

    # ---------------------------------------------------------------- rows

    def _to_row(self, event: ConsumedEvent) -> dict[str, object]:
        """Flatten one consumed message into a Bronze row.

        Note what does NOT happen: the payload stays a JSON string. We do not
        parse it into columns, fix its types, or drop fields we do not
        recognise. Bronze's contract is 'exactly what arrived', and honouring
        it here is what makes a Silver rebuild trustworthy later.
        """
        envelope = event.envelope
        return {
            "event_id": envelope["event_id"],
            "source": envelope["source"],
            "event_type": envelope["event_type"],
            "schema_version": int(envelope.get("schema_version", 1)),
            "occurred_at": _as_utc(envelope["occurred_at"]),
            "ingested_at": _as_utc(envelope["ingested_at"]),
            "payload": envelope["payload"],
            "content_hash": envelope["content_hash"],
            "collector_run_id": envelope.get("collector_run_id"),
            "collector_host": envelope.get("collector_host"),
            "_kafka_topic": event.topic,
            "_kafka_partition": event.partition,
            "_kafka_offset": event.offset,
            "_bronze_written_at": utc_now(),
        }

    def _handle(self, event: ConsumedEvent) -> None:
        """Buffer one event. Flush when the batch is full."""
        self._buffer.append(self._to_row(event))
        self.result.rows_read += 1
        if len(self._buffer) >= self.batch_size:
            self.flush()

    # --------------------------------------------------------------- flush

    def flush(self) -> None:
        """Write the buffered rows to Iceberg as one atomic commit.

        Everything about this method is designed so that it either fully
        succeeds or changes nothing:

        * `pa.Table.from_pylist` with an explicit schema fails on a type
          mismatch instead of guessing, so bad data cannot reach the file.
        * `table.append` is a single Iceberg transaction. It writes the Parquet
          files first, then swaps the catalog pointer. A reader querying during
          the write sees the previous snapshot, never a partial one.
        * The buffer is only cleared AFTER the append returns. If the append
          raises, the rows stay buffered, offsets are not committed, and the
          run fails loudly with the data still recoverable.
        """
        if not self._buffer:
            return

        rows = len(self._buffer)
        arrow_table = pa.Table.from_pylist(self._buffer, schema=BRONZE_ARROW_SCHEMA)

        self.table.append(arrow_table)

        self._buffer.clear()
        self.result.rows_written += rows
        self.result.batches += 1
        log.info(
            "bronze_batch_committed",
            table=self.identifier,
            rows=rows,
            total=self.result.rows_written,
        )

    # ----------------------------------------------------------------- run

    def replay(self) -> bool:
        """Forget where we were, so the next run re-reads the whole topic.

        Deleting the consumer group discards its committed offsets. The next
        run then finds no bookmark and falls back to the reset policy, which
        for this writer is always `earliest`.

        This is what a real replay is. It is deliberately a separate, explicit
        action rather than a flag on the read path, because it means "process
        everything again" - which, with an append-only Bronze layer, duplicates
        rows until Silver deduplicates them.
        """
        from aegis.streaming.admin import get_admin

        try:
            admin = get_admin()
            futures = admin.delete_consumer_groups([self.group_id], request_timeout=20)
            futures[self.group_id].result(timeout=20)
            log.warning("consumer_group_reset", group=self.group_id)
            return True
        except Exception as exc:
            # A group that never committed anything does not exist yet, and
            # deleting it fails. That is not an error: there is nothing to
            # forget, and the next run starts from earliest regardless.
            log.debug("consumer_group_reset_skipped", group=self.group_id, reason=str(exc)[:120])
            return False

    def run(
        self,
        *,
        max_records: int | None = None,
        idle_timeout: float = 8.0,
        from_beginning: bool = False,
    ) -> WriteResult:
        """Drain the topic into Bronze and return what happened.

        `idle_timeout` turns an endless streaming consumer into a batch job:
        read whatever is waiting, and stop once the topic goes quiet. That is
        what a scheduled run wants, and it is the shape Dagster will call in
        Phase 5. The same class runs continuously by passing idle_timeout=None.

        `from_beginning=True` performs a genuine replay: it deletes the
        consumer group's committed offsets first.
        """
        if from_beginning:
            self.replay()

        consumer = EventConsumer(
            topics=[self.topic],
            group_id=self.group_id,
            # ALWAYS earliest, for this writer specifically.
            #
            # `auto.offset.reset` only applies when a group has no committed
            # offset - so it decides one thing only: where a brand-new consumer
            # starts. The two answers mean very different things:
            #
            #   latest   -> skip everything already in the topic, wait for new
            #   earliest -> read the topic from the oldest retained record
            #
            # `latest` is right for a live dashboard, which only cares about
            # now. It is badly wrong for a Bronze writer, whose whole purpose is
            # to miss nothing: a first run would silently skip every record
            # already published and report success having written zero rows.
            #
            # This project did exactly that. The urlhaus writer reported "0 read,
            # ok" against a topic holding 12,710 messages, twice, before the
            # cause was found. Nothing errored, because nothing was wrong from
            # Kafka's point of view - we had asked to start at the end.
            #
            # Once the group has committed offsets, this setting is ignored and
            # the writer resumes exactly where it stopped. So `earliest` gives
            # us both properties we want: never skip on the first run, never
            # reprocess on later ones.
            from_beginning=True,
            # Align the offset-commit cadence with our flush cadence, so each
            # commit corresponds to exactly one Iceberg batch. Mismatched
            # cadences are legal but make failures much harder to reason about.
            commit_every=self.batch_size,
        )

        log.info(
            "bronze_sync_start",
            source=self.source,
            topic=self.topic,
            table=self.identifier,
            group=self.group_id,
            from_beginning=from_beginning,
        )

        try:
            stats = consumer.consume(
                self._handle,
                max_records=max_records,
                idle_timeout=idle_timeout,
                # THE ORDERING GUARANTEE: flush to Iceberg, then commit offsets.
                before_commit=self.flush,
            )
            self.result.errors.extend(stats.errors[:5])
        except Exception as exc:
            self.result.errors.append(f"{type(exc).__name__}: {exc}")
            log.error("bronze_sync_failed", error=str(exc)[:300])

        # Anything still buffered when the loop ended (for example because
        # max_records was hit mid-batch) must still be written.
        try:
            self.flush()
        except Exception as exc:
            self.result.errors.append(f"final flush failed: {exc}")
            log.error("bronze_final_flush_failed", error=str(exc)[:300])

        self.table.refresh()
        self.result.snapshots_created = len(self.table.metadata.snapshots) - self._snapshots_before

        log.info(
            "bronze_sync_done",
            source=self.source,
            rows_read=self.result.rows_read,
            rows_written=self.result.rows_written,
            batches=self.result.batches,
            snapshots=self.result.snapshots_created,
            errors=len(self.result.errors),
        )
        return self.result


def sync_all(
    sources: list[str] | None = None,
    *,
    from_beginning: bool = False,
    batch_size: int = 2000,
    idle_timeout: float = 8.0,
) -> list[WriteResult]:
    """Run the Bronze writer for several sources, one after another.

    Sequential rather than parallel, deliberately: on this machine, four
    concurrent writers would contend for the same 4 GB of Docker memory and the
    same catalog connection pool, and the whole run would be slower than doing
    them in turn. Parallelism is a cloud-phase concern.
    """
    from aegis.lakehouse.tables import BRONZE_TABLES

    names = sources or [s for s in BRONZE_TABLES if s != Source.COWRIE.value]
    results = []
    for name in names:
        writer = BronzeWriter(name, batch_size=batch_size)
        results.append(writer.run(from_beginning=from_beginning, idle_timeout=idle_timeout))
    return results


def bronze_stats() -> list[TableStats]:
    """Summarise every Bronze table: rows, files, snapshots, time range.

    This is the "is my lakehouse healthy?" query. `files` matters as much as
    `rows`: a table with 40,000 rows in 400 files has a small-files problem and
    will get slower every day until it is compacted.

    Every number here comes from the current snapshot's summary, which Iceberg
    maintains as running totals. So this is a metadata read - it never opens a
    single Parquet file, and it costs the same whether the table holds a
    thousand rows or a billion.
    """
    from aegis.lakehouse.catalog import NAMESPACE_BRONZE, get_catalog

    catalog = get_catalog()
    out: list[TableStats] = []

    for namespace, name in sorted(catalog.list_tables(NAMESPACE_BRONZE)):
        identifier = f"{namespace}.{name}"
        try:
            table = catalog.load_table(identifier)
            snapshot = table.current_snapshot()
            if snapshot is None:
                out.append(TableStats(table=identifier))
                continue

            _operation, summary = snapshot_summary(snapshot)
            out.append(
                TableStats(
                    table=identifier,
                    rows=int(summary.get("total-records", 0) or 0),
                    files=int(summary.get("total-data-files", 0) or 0),
                    size_bytes=int(summary.get("total-files-size", 0) or 0),
                    snapshots=len(table.metadata.snapshots),
                    last_updated=datetime.fromtimestamp(
                        snapshot.timestamp_ms / 1000, tz=timezone.utc
                    ),
                )
            )
        except Exception as exc:
            out.append(TableStats(table=identifier, error=str(exc)[:120]))

    return out


def read_payloads(source: Source | str, limit: int = 5) -> list[dict[str, object]]:
    """Read a few rows back and parse their payloads. For inspection."""
    table = load_bronze(source)
    arrow = table.scan(limit=limit).to_arrow()
    rows: list[dict[str, object]] = arrow.to_pylist()
    for row in rows:
        raw = row.get("payload")
        if not isinstance(raw, str):
            continue
        try:
            row["payload"] = json.loads(raw)
        except json.JSONDecodeError:
            # A payload that will not parse stays as the original string. That
            # is the honest outcome: Bronze stores what arrived, and if what
            # arrived is not valid JSON, showing it verbatim is more useful
            # than hiding it behind an error.
            pass
    return rows
