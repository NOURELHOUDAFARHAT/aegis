"""Asset checks and freshness: what Dagster asserts about the data it produced.

dbt's 37 data tests already become checks on the dbt assets automatically.
These add the guarantees dbt cannot express, because they are about the
pipeline's machinery rather than the rows:

    bronze/<source>  has_rows            check, BLOCKING  an empty table must not feed dbt
    bronze/<source>  consumer_caught_up  check, warn      every Kafka message was read
    bronze + gold    freshness policy    warn 8h / fail 14h  nothing has silently gone stale

BLOCKING CHECKS
---------------
A blocking check that fails stops everything downstream of its asset. Without
that, an empty Bronze table would flow into dbt, Silver would rebuild as empty,
and Gold would publish zeros - confidently, with every dbt test passing,
because an empty table is perfectly unique and has no nulls.
"""

# No `from __future__ import annotations`: Dagster validates the check context
# annotation against the real class, and that import turns it into a string.
# See the note at the top of orchestration/assets.py.
from datetime import timedelta

from dagster import (
    AssetCheckExecutionContext,
    AssetCheckResult,
    AssetChecksDefinition,
    AssetCheckSeverity,
    AssetKey,
    FreshnessPolicy,
    asset_check,
)

from aegis.lakehouse.tables import BRONZE_TABLES
from aegis.orchestration.assets import SOURCES, bronze_key
from aegis.streaming.topics import topic_for


def bronze_group_id(source: str, suffix: str = "") -> str:
    """The Kafka consumer group the Bronze writer uses for a source.

    Kept as a function (and tested against BronzeWriter) because the lag check
    must inspect exactly the group the writer commits to. If the two strings
    drifted apart, the check would report a different, idle group as
    permanently caught up - a check that always passes is worse than none.
    """
    return f"aegis-bronze-{source}{suffix}"


def build_has_rows_check(source: str) -> AssetChecksDefinition:
    table_name = BRONZE_TABLES[source]

    @asset_check(
        asset=bronze_key(source),
        name=f"{source}_has_rows",
        blocking=True,
        description=f"{table_name} must not be empty. Blocks dbt from building on an empty table.",
    )
    def _check(context: AssetCheckExecutionContext) -> AssetCheckResult:
        from aegis.lakehouse.writer import bronze_stats

        stats = next((s for s in bronze_stats() if s.table == table_name), None)
        rows = stats.rows if stats else 0
        return AssetCheckResult(
            passed=rows > 0,
            severity=AssetCheckSeverity.ERROR,
            metadata={
                "rows": rows,
                "data_files": stats.files if stats else 0,
                "avg_rows_per_file": round(stats.avg_rows_per_file, 1) if stats else 0.0,
            },
        )

    return _check


def build_lag_check(source: str) -> AssetChecksDefinition:
    topic = topic_for(source)

    @asset_check(
        asset=bronze_key(source),
        name=f"{source}_consumer_caught_up",
        description=(
            f"After a sync, the Bronze writer should have read every message in {topic}. "
            "Remaining lag means records are waiting that Bronze does not yet hold."
        ),
    )
    def _check(context: AssetCheckExecutionContext) -> AssetCheckResult:
        from aegis.streaming.consumer import lag_report

        rows = lag_report(bronze_group_id(source), [topic])
        total = sum(int(r["lag"]) for r in rows)
        return AssetCheckResult(
            passed=total == 0,
            # A warning, not a failure: messages can legitimately arrive during
            # the few seconds between the sync finishing and this check running.
            severity=AssetCheckSeverity.WARN,
            metadata={
                "lag": total,
                "partitions": len(rows),
                "consumer_group": bronze_group_id(source),
            },
        )

    return _check


# ---------------------------------------------------------------------------
# FRESHNESS
#
# Freshness catches the one failure no other check can: the one where nothing
# runs at all. A job that never starts produces no failed test, no error and
# no alert - only data that quietly gets older.
#
# The pipeline is scheduled every 6 hours, so:
#   WARN after 8 hours   one run was missed (plus margin for a slow run)
#   FAIL after 14 hours  two runs were missed; the pipeline has stopped
#
# Two levels rather than one, so a single slow night is a yellow badge, not a
# red one - an alert that fires for every hiccup trains people to ignore it.
#
# HOW THIS IS ATTACHED
# An earlier version built freshness *checks* with
# build_last_update_freshness_checks() and evaluated them with a sensor.
# Dagster 1.13 supersedes both: a FreshnessPolicy is declared on the asset
# itself and evaluated by Dagster, with no sensor to run or forget to start.
# The policy is attached to Bronze and Gold in definitions.py, in one place,
# via Definitions.map_asset_specs - which also reaches the dbt-generated Gold
# assets that have no decorator of ours to put it on.
#
# Only Bronze and Gold are governed. Bronze is where data enters, Gold is what
# people read; staging and Silver are intermediate, and a stale Gold table
# already implies they are stale too.
# ---------------------------------------------------------------------------
FRESHNESS_POLICY = FreshnessPolicy.time_window(
    fail_window=timedelta(hours=14),
    warn_window=timedelta(hours=8),
)

GOLD_ASSETS: list[AssetKey] = [
    AssetKey(["gold", "vendor_exploitation"]),
    AssetKey(["gold", "malware_url_tags"]),
    AssetKey(["gold", "c2_infrastructure"]),
]

FRESHNESS_GOVERNED: list[AssetKey] = [*(bronze_key(s) for s in SOURCES), *GOLD_ASSETS]

ALL_CHECKS: list[AssetChecksDefinition] = [
    *(build_has_rows_check(s) for s in SOURCES),
    *(build_lag_check(s) for s in SOURCES),
]
