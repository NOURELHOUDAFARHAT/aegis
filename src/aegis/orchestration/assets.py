"""Ingestion assets: collecting each feed, and landing it in Bronze.

ASSETS, NOT TASKS
-----------------
Airflow describes a pipeline as tasks: "run the collector, then run the
writer". Dagster describes it as assets - the things that exist afterwards:
"raw/feodo exists, and bronze/feodo is built from it". The order is derived
from those dependencies rather than written down separately.

That difference is practical, not philosophical. Because Dagster knows
`gold/c2_infrastructure` depends on `bronze/feodo`, it can answer "what is
stale?" and "what breaks if Feodo fails?" by itself, and a single asset can be
rebuilt without re-running the whole chain.

TWO ASSETS PER SOURCE
---------------------
    raw/<source>     the feed collected and published to Kafka
    bronze/<source>  that topic appended to its Iceberg Bronze table

Keeping them separate means a Bronze failure can be retried without
re-downloading the feed - which matters, because the feeds are rolling windows
and a second download is not guaranteed to contain the same records.

The asset functions are built by factories, one per source, rather than written
out four times. Adding a fifth feed to `COLLECTORS` adds its assets here
automatically.
"""

# NOTE: no `from __future__ import annotations` in this module, unlike the rest
# of AEGIS. That import makes Python store every type hint as a STRING. Dagster
# validates the `context` parameter by comparing its annotation against the real
# AssetExecutionContext class - and the string "AssetExecutionContext" is not
# the class. Definition loading then fails with the self-contradictory
#   "Cannot annotate `context` with type AssetExecutionContext. `context` must
#    be annotated with AssetExecutionContext..."
# because both halves of the message print the same name. Python 3.10+ supports
# `X | None` natively, so nothing here needs the future import anyway.
from typing import Any

from dagster import (
    AssetExecutionContext,
    AssetKey,
    AssetsDefinition,
    Backoff,
    Failure,
    MaterializeResult,
    MetadataValue,
    RetryPolicy,
    asset,
)

from aegis.lakehouse.tables import BRONZE_TABLES
from aegis.sources.feeds import COLLECTORS
from aegis.streaming.topics import topic_for

# Every feed with a collector. The honeypot (cowrie) has a Bronze table but no
# collector yet, so it is deliberately absent here.
SOURCES: list[str] = sorted(COLLECTORS)

# ---------------------------------------------------------------------------
# Retries: 3 attempts, waiting 30s, then 60s, then 120s.
#
# Exponential backoff matters for public feeds. abuse.ch and CISA are free
# services; hammering one that is struggling makes its outage worse and gets
# us rate-limited. Waiting longer each time gives a transient problem room to
# clear.
#
# A retried collection re-publishes the whole feed, so a retry can put
# duplicate events into Bronze. That is acceptable by design: Bronze is
# at-least-once, and Silver deduplicates on each table's natural key.
# ---------------------------------------------------------------------------
INGESTION_RETRY = RetryPolicy(max_retries=3, delay=30, backoff=Backoff.EXPONENTIAL)


def raw_key(source: str) -> AssetKey:
    return AssetKey(["raw", source])


def bronze_key(source: str) -> AssetKey:
    # Must match the key the dbt translator gives each dbt source
    # (see orchestration/dbt.py). That match is what connects the Python
    # half of the graph to the dbt half.
    return AssetKey(["bronze", source])


def build_raw_asset(source: str) -> AssetsDefinition:
    """The feed, downloaded and published to its Kafka topic."""
    collector_cls = COLLECTORS[source]

    @asset(
        name=source,
        key_prefix=["raw"],
        group_name="ingestion",
        kinds={"python", "kafka"},
        retry_policy=INGESTION_RETRY,
        description=(
            f"The {source} feed, downloaded and published to Kafka. Nothing is "
            "stored as a table at this step; the durable copy is bronze/"
            f"{source}."
        ),
        metadata={
            "source_url": MetadataValue.url(collector_cls.url),
            "kafka_topic": topic_for(source),
        },
    )
    def _raw(context: AssetExecutionContext) -> MaterializeResult:
        # Imported inside the function so loading the Dagster definitions does
        # not open Schema Registry or Kafka connections. The web UI loads this
        # module constantly; it should not touch the network to draw a graph.
        from aegis.sources.base import record_run
        from aegis.streaming.producer import KafkaSink

        collector = collector_cls()
        sink = KafkaSink(client_id=f"aegis-dagster-{source}")
        result = collector.run(sink)
        record_run(result)

        if result.status != "success":
            raise Failure(
                description=f"{source} collection failed: {result.error_message}",
                metadata={"records_fetched": result.records_fetched},
            )

        # "The collector finished" is not the same as "Kafka has the data".
        # produce() is asynchronous: only the broker's acknowledgements prove
        # delivery. Treating unacknowledged messages as success is how data
        # disappears without an error.
        if not sink.all_delivered:
            raise Failure(
                description=(
                    f"{source}: {sink.failed} of {sink.produced} messages were not "
                    "acknowledged by the broker."
                ),
            )

        context.log.info(f"{source}: {result.records_emitted:,} events published")
        return MaterializeResult(
            metadata={
                "records_emitted": result.records_emitted,
                "records_rejected": result.records_rejected,
                "dead_lettered": sink.dead_lettered,
                "bytes_downloaded": result.bytes_downloaded,
                "duration_seconds": round(result.duration_seconds, 2),
            }
        )

    return _raw


def build_bronze_asset(source: str) -> AssetsDefinition:
    """The Kafka topic appended to its Iceberg Bronze table."""
    table_name = BRONZE_TABLES[source]

    @asset(
        name=source,
        key_prefix=["bronze"],
        deps=[raw_key(source)],
        group_name="bronze",
        kinds={"iceberg"},
        retry_policy=INGESTION_RETRY,
        description=(
            f"Raw {source} events exactly as received, appended to the Iceberg "
            f"table {table_name}. Append-only: every collection run adds rows."
        ),
        metadata={"iceberg_table": table_name, "kafka_topic": topic_for(source)},
    )
    def _bronze(context: AssetExecutionContext) -> MaterializeResult:
        from aegis.lakehouse.writer import BronzeWriter, bronze_stats

        result = BronzeWriter(source).run(idle_timeout=8.0)
        if not result.ok:
            raise Failure(
                description=f"Bronze sync for {source} failed.",
                metadata={"errors": MetadataValue.text("\n".join(result.errors[:5]))},
            )

        metadata: dict[str, Any] = {
            "rows_read": result.rows_read,
            "rows_written": result.rows_written,
            "iceberg_commits": result.batches,
            "snapshots_created": result.snapshots_created,
        }
        stats = next((s for s in bronze_stats() if s.table == table_name), None)
        if stats is not None:
            # `dagster/row_count` is a reserved key: the UI charts it over time,
            # so a feed that suddenly delivers far fewer rows is visible at a
            # glance rather than discovered in a dashboard later.
            metadata["dagster/row_count"] = stats.rows
            metadata["data_files"] = stats.files
            metadata["avg_rows_per_file"] = round(stats.avg_rows_per_file, 1)

        context.log.info(f"{source}: {result.rows_written:,} rows appended to {table_name}")
        return MaterializeResult(metadata=metadata)

    return _bronze


RAW_ASSETS: list[AssetsDefinition] = [build_raw_asset(s) for s in SOURCES]
BRONZE_ASSETS: list[AssetsDefinition] = [build_bronze_asset(s) for s in SOURCES]
