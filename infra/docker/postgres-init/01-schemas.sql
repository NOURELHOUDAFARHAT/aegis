-- ============================================================================
-- AEGIS - Postgres bootstrap. Runs ONCE, on first container start only.
-- If you change this file later you must destroy the volume to re-run it:
--   ./aegis.ps1 nuke
--
-- We separate concerns into schemas rather than databases so a single
-- connection pool can serve all of them, while privileges stay separable.
-- ============================================================================

-- Iceberg catalog: pyiceberg's SqlCatalog creates its own tables in here.
CREATE SCHEMA IF NOT EXISTS iceberg_catalog;

-- Dagster's run/event log (Phase 5).
CREATE SCHEMA IF NOT EXISTS orchestration;

-- Hot serving tables read by the FastAPI layer (Phase 7).
CREATE SCHEMA IF NOT EXISTS serving;

-- Operational metadata we own: ingestion watermarks, feed run history,
-- data-quality results. This is the pipeline's own memory.
CREATE SCHEMA IF NOT EXISTS ops;

-- ---------------------------------------------------------------------------
-- Ingestion watermarks: how a batch source knows where it stopped last time.
-- This tiny table is what makes re-running a feed collector idempotent
-- instead of re-downloading and re-inserting everything.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.ingestion_watermark (
    source_name     TEXT        PRIMARY KEY,
    last_run_at     TIMESTAMPTZ NOT NULL,
    last_cursor     TEXT,                    -- e.g. an ETag, or max(modified_at)
    last_status     TEXT        NOT NULL,    -- success | failed | partial
    records_emitted BIGINT      NOT NULL DEFAULT 0,
    error_message   TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE ops.ingestion_watermark IS
  'One row per data source. Enables incremental, idempotent re-runs.';

-- ---------------------------------------------------------------------------
-- Audit log for every pipeline run. Phase 8 turns this into a tamper-evident
-- audit trail; for now it is honest observability.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ops.pipeline_run (
    run_id        UUID        PRIMARY KEY,
    pipeline_name TEXT        NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ,
    status        TEXT        NOT NULL DEFAULT 'running',
    rows_in       BIGINT,
    rows_out      BIGINT,
    rows_rejected BIGINT,
    metadata      JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_pipeline_run_name_time
    ON ops.pipeline_run (pipeline_name, started_at DESC);
