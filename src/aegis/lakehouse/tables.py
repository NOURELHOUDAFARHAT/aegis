"""Bronze table definitions.

BRONZE IN ONE SENTENCE
----------------------
Bronze stores exactly what arrived, plus enough metadata to prove where it came
from, and is never edited.

Everything below follows from that. There is no cleaning, no type conversion of
the payload, no deduplication. Those all happen in Silver, which can be deleted
and rebuilt. Bronze cannot be rebuilt - the feeds delete their own history -
so Bronze is the one layer that must be right by construction rather than by
correction.
"""

from __future__ import annotations

from pyiceberg.partitioning import PartitionField, PartitionSpec
from pyiceberg.schema import Schema
from pyiceberg.table import Table
from pyiceberg.transforms import DayTransform
from pyiceberg.types import (
    IntegerType,
    LongType,
    NestedField,
    StringType,
    TimestamptzType,
)

from aegis.lakehouse.catalog import NAMESPACE_BRONZE, get_catalog
from aegis.logging import get_logger
from aegis.sources.models import Source

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# THE SCHEMA
#
# Note that every field carries an explicit, hand-assigned `field_id`.
#
# This is the single most important idea in the Iceberg format: **columns are
# identified by ID, not by name.** The Parquet files on disk store column 5,
# not column "content_hash". So renaming a column is a metadata-only change
# that costs nothing and breaks nothing, and re-adding a previously dropped
# column does NOT silently resurrect its old data, because the new column gets
# a new ID.
#
# The consequence for us: these numbers are permanent. Never renumber a field,
# never reuse the ID of a dropped one. New fields get the next unused number.
# ---------------------------------------------------------------------------
BRONZE_SCHEMA = Schema(
    # --- the envelope, exactly as it travelled through Kafka -----------------
    NestedField(
        1, "event_id", StringType(), required=True, doc="UUIDv7. The key Silver deduplicates on."
    ),
    NestedField(
        2,
        "source",
        StringType(),
        required=True,
        doc="urlhaus | cisa_kev | feodo | tor_exit | cowrie",
    ),
    NestedField(
        3,
        "event_type",
        StringType(),
        required=True,
        doc="ioc.url | ioc.ip | vuln.cve | network.tor_exit | session.ssh",
    ),
    NestedField(
        4,
        "schema_version",
        IntegerType(),
        required=True,
        doc="Version of the payload shape for this source.",
    ),
    NestedField(
        5,
        "occurred_at",
        TimestamptzType(),
        required=True,
        doc="When it happened in the real world (UTC).",
    ),
    NestedField(
        6,
        "ingested_at",
        TimestamptzType(),
        required=True,
        doc="When AEGIS first saw it (UTC). This is the partition key.",
    ),
    NestedField(
        7,
        "payload",
        StringType(),
        required=True,
        doc="The source's own record as JSON, byte-for-byte as received.",
    ),
    NestedField(
        8,
        "content_hash",
        StringType(),
        required=True,
        doc="SHA-256 of the canonical payload. Distinguishes 'seen again' from 'changed'.",
    ),
    NestedField(
        9,
        "collector_run_id",
        StringType(),
        required=False,
        doc="Which collector run produced this.",
    ),
    NestedField(
        10, "collector_host", StringType(), required=False, doc="Which machine collected it."
    ),
    # --- provenance: exactly where in the log this row came from -------------
    # These four fields are what make a claim like "this row is genuinely what
    # the feed sent" checkable rather than asserted. Given a topic, partition
    # and offset you can go back to Kafka (within retention) and compare.
    # Without them, Bronze is just a copy you have to trust.
    NestedField(11, "_kafka_topic", StringType(), required=False),
    NestedField(12, "_kafka_partition", IntegerType(), required=False),
    NestedField(13, "_kafka_offset", LongType(), required=False),
    NestedField(
        14,
        "_bronze_written_at",
        TimestamptzType(),
        required=False,
        doc="When this row was committed to Bronze. Differs from "
        "ingested_at by however long the row sat in Kafka.",
    ),
)


# ---------------------------------------------------------------------------
# THE PARTITION SPEC
#
# Partitioning splits a table's files into folders so a filtered query can skip
# whole folders instead of reading and discarding their contents.
#
# We partition by DAY OF ingested_at. That choice needs defending, because the
# obvious alternative - occurred_at - is wrong here:
#
#   * occurred_at on the CISA feed spans 2021 to today. Partitioning by it would
#     produce ~1,700 partitions of one or two rows each on the very first load.
#     Thousands of tiny files is the classic lakehouse performance disaster:
#     every query pays to open every file.
#
#   * ingested_at produces exactly one partition per day we actually ran. It
#     matches how Bronze is queried in practice ("what arrived yesterday?",
#     "reprocess last Tuesday's load") and how it is expired ("drop data older
#     than N days" becomes a folder delete).
#
# Silver re-partitions by event time, because Silver IS queried by when things
# happened. Different layer, different question, different partitioning.
#
# A last Iceberg-specific point: this is HIDDEN partitioning. A query says
# `WHERE ingested_at > '2026-09-01'` and Iceberg works out which folders that
# implies. In Hive you had to know the partition column existed and filter on
# it by hand, and forgetting meant a silent full scan.
# ---------------------------------------------------------------------------
BRONZE_PARTITION_SPEC = PartitionSpec(
    PartitionField(
        source_id=6,  # ingested_at
        field_id=1000,  # partition field IDs conventionally start at 1000
        transform=DayTransform(),
        name="ingested_day",
    )
)


# Table properties are stored with the table and read by every engine that
# opens it - so these settings survive whichever tool queries the data next.
BRONZE_PROPERTIES: dict[str, str] = {
    "write.format.default": "parquet",
    # zstd beats snappy on both ratio and speed for this kind of repetitive
    # text. Storage is billed per byte in the cloud, so this is money.
    "write.parquet.compression-codec": "zstd",
    # Target file size. Too small and queries drown in file-open overhead; too
    # large and readers cannot parallelise. 128 MB is the usual sweet spot.
    "write.target-file-size-bytes": str(128 * 1024 * 1024),
    # Keep a snapshot's metadata for 7 days. This is the time-travel window:
    # how far back you can query the table "as it was".
    "history.expire.max-snapshot-age-ms": str(7 * 24 * 60 * 60 * 1000),
    "history.expire.min-snapshots-to-keep": "10",
    "comment": "Bronze: raw events exactly as received. Append-only, never edited.",
}


# One Bronze table per source, mirroring one Kafka topic per source. Same
# reasoning: different volumes, different retention, and a broken parser on one
# feed leaves the others untouched.
BRONZE_TABLES: dict[str, str] = {
    Source.URLHAUS.value: f"{NAMESPACE_BRONZE}.urlhaus",
    Source.CISA_KEV.value: f"{NAMESPACE_BRONZE}.cisa_kev",
    Source.FEODO.value: f"{NAMESPACE_BRONZE}.feodo",
    Source.TOR_EXIT.value: f"{NAMESPACE_BRONZE}.tor_exit",
    Source.COWRIE.value: f"{NAMESPACE_BRONZE}.cowrie",
}


def table_for(source: Source | str) -> str:
    """Map a source to its Bronze table identifier."""
    key = source.value if isinstance(source, Source) else source
    if key not in BRONZE_TABLES:
        raise KeyError(f"No Bronze table declared for source '{key}'. Add one in tables.py.")
    return BRONZE_TABLES[key]


def create_bronze_tables(*, dry_run: bool = False) -> dict[str, str]:
    """Create every Bronze table that does not exist. Idempotent.

    Returns table identifier -> 'created' | 'exists' | 'would create' | error.
    """
    catalog = get_catalog()
    existing = {f"{ns}.{name}" for ns, name in catalog.list_tables(NAMESPACE_BRONZE)}
    results: dict[str, str] = {}

    for identifier in BRONZE_TABLES.values():
        if identifier in existing:
            results[identifier] = "exists"
            continue
        if dry_run:
            results[identifier] = "would create"
            continue
        try:
            catalog.create_table(
                identifier=identifier,
                schema=BRONZE_SCHEMA,
                partition_spec=BRONZE_PARTITION_SPEC,
                properties=BRONZE_PROPERTIES,
            )
            results[identifier] = "created"
            log.info("bronze_table_created", table=identifier)
        except Exception as exc:
            message = str(exc)
            if "already exists" in message.lower():
                results[identifier] = "exists"
            else:
                results[identifier] = f"error: {message[:120]}"
                log.error("bronze_table_failed", table=identifier, error=message[:200])

    return results


def load_bronze(source: Source | str) -> Table:
    """Load one Bronze table, creating it if it does not exist yet."""
    catalog = get_catalog()
    identifier = table_for(source)
    try:
        return catalog.load_table(identifier)
    except Exception:
        log.info("bronze_table_autocreate", table=identifier)
        return catalog.create_table(
            identifier=identifier,
            schema=BRONZE_SCHEMA,
            partition_spec=BRONZE_PARTITION_SPEC,
            properties=BRONZE_PROPERTIES,
        )
