"""Run sensors: record every pipeline run's outcome in Postgres.

Dagster already stores its own run history. These sensors copy each outcome
into `ops.pipeline_run` - the same audit table the collectors write to - so
"did the pipeline succeed last night?" is a SQL query answerable without the
Dagster UI, by a dashboard, or by the Phase 7 API.

Real alerting (email, Slack, a pager) belongs in the cloud phase. Locally the
honest scope is: every failure is recorded with its error, durably, somewhere
queryable.
"""

# No `from __future__ import annotations`: Dagster inspects sensor context
# annotations too. See the note at the top of orchestration/assets.py.
import json

from dagster import (
    DagsterRun,
    DagsterRunStatus,
    DefaultSensorStatus,
    RunFailureSensorContext,
    RunStatusSensorContext,
    run_failure_sensor,
    run_status_sensor,
)

from aegis.orchestration.jobs import MODELS_JOB, PIPELINE_JOB

MONITORED_JOBS = [PIPELINE_JOB, MODELS_JOB]


def record_outcome(
    context: RunStatusSensorContext,
    run: DagsterRun,
    status: str,
    error: str | None = None,
) -> None:
    """Upsert one run into ops.pipeline_run. Never raises.

    A sensor that crashes while reporting a failure would bury the original
    failure under its own - the same lesson as the dead-letter queue: code that
    handles an error must not become a second error.
    """
    import psycopg

    from aegis.config import settings

    record = context.instance.get_run_record_by_id(run.run_id)
    started = record.start_time if record else None
    finished = record.end_time if record else None

    try:
        with psycopg.connect(settings.database.psycopg_dsn, connect_timeout=5) as conn:
            conn.execute(
                """
                INSERT INTO ops.pipeline_run
                    (run_id, pipeline_name, started_at, finished_at, status, metadata)
                VALUES (
                    %s,
                    %s,
                    COALESCE(to_timestamp(%s), now()),
                    to_timestamp(%s),
                    %s,
                    %s::jsonb
                )
                ON CONFLICT (run_id) DO UPDATE SET
                    finished_at = EXCLUDED.finished_at,
                    status      = EXCLUDED.status,
                    metadata    = EXCLUDED.metadata
                """,
                (
                    run.run_id,
                    f"dagster.{run.job_name}",
                    started,
                    finished,
                    status,
                    json.dumps({"orchestrator": "dagster", "error": error}),
                ),
            )
        context.log.info(f"recorded {run.job_name} run {run.run_id[:8]} as {status}")
    except Exception as exc:
        context.log.error(f"could not record run outcome in ops.pipeline_run: {exc}")


@run_status_sensor(
    run_status=DagsterRunStatus.SUCCESS,
    monitored_jobs=MONITORED_JOBS,
    default_status=DefaultSensorStatus.RUNNING,
    name="record_run_success",
)
def record_run_success(context: RunStatusSensorContext) -> None:
    record_outcome(context, context.dagster_run, "success")


@run_failure_sensor(
    monitored_jobs=MONITORED_JOBS,
    default_status=DefaultSensorStatus.RUNNING,
    name="record_run_failure",
)
def record_run_failure(context: RunFailureSensorContext) -> None:
    message = context.failure_event.message if context.failure_event else None
    record_outcome(context, context.dagster_run, "failed", message)
