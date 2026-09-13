"""Jobs and schedules.

A job is a selection of assets to materialise together. A schedule runs a job
on a timer.
"""

from __future__ import annotations

from dagster import (
    AssetSelection,
    DefaultScheduleStatus,
    ScheduleDefinition,
    define_asset_job,
)

# Everything: collect every feed, land it in Bronze, rebuild Silver and Gold.
PIPELINE_JOB = define_asset_job(
    name="aegis_pipeline",
    selection=AssetSelection.all(),
    description="Collect every feed, land it in Bronze, then rebuild Silver and Gold with dbt.",
)

# Only the dbt models. For when the SQL changed but the data did not: rebuilding
# Silver and Gold from the Bronze already held, without touching the internet.
MODELS_JOB = define_asset_job(
    name="rebuild_models",
    selection=AssetSelection.key_prefixes(["staging"], ["silver"], ["gold"]),
    description="Rebuild staging, Silver and Gold from existing Bronze. No collection.",
)

# ---------------------------------------------------------------------------
# Every 6 hours, at 00:00, 06:00, 12:00 and 18:00 UTC.
#
# Why 6 hours: CISA updates KEV a few times a week, and URLhaus publishes a
# rolling 30-day window, so collecting more often mostly re-downloads records
# already held. Four runs a day is enough to notice a new actively-exploited
# vulnerability the same day, without leaning on free public services.
#
# Why UTC: a schedule in local time runs twice, or not at all, on the nights
# the clocks change. Every timestamp in AEGIS is UTC; the scheduler is no
# exception.
#
# Why STOPPED by default: starting Dagster should never, on its own, begin
# downloading from third-party servers every six hours. Turning the schedule on
# is a deliberate act, done once in the UI.
# ---------------------------------------------------------------------------
PIPELINE_SCHEDULE = ScheduleDefinition(
    name="aegis_pipeline_every_6h",
    job=PIPELINE_JOB,
    cron_schedule="0 */6 * * *",
    execution_timezone="UTC",
    default_status=DefaultScheduleStatus.STOPPED,
)
