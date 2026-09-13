# ADR 0007 — Orchestration as a Dagster asset graph

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

After Phase 4 the platform worked, but only when a person ran four commands in
the right order: `aegis collect all --to kafka`, `aegis lake sync all`,
`aegis model build`, and a manual look at whether anything had failed. Nothing
ran unattended, nothing retried a flaky feed, and nothing would ever notice that
the whole pipeline had silently stopped.

The machine constraint still applies: 7.7 GB of RAM, of which **0.14–0.2 GB was
free** throughout this phase, with Chrome alone holding 1.8 GB.

## Decision

Model the pipeline as a **Dagster asset graph** in `aegis.orchestration`.

### Assets, not tasks

Every node is a thing that exists afterwards, not a step that runs:

```
raw/<source> → bronze/<source> → staging/* → silver/* → gold/*
```

- `raw/<source>` and `bronze/<source>` are Python assets built by factories,
  one pair per collector, so a fifth feed adds its assets automatically.
- Staging, Silver and Gold come from the dbt manifest through `dagster-dbt`.
- `AegisDbtTranslator` maps every dbt source `bronze.<table>` onto the exact key
  of the Bronze writer's asset. That single mapping is what makes one connected
  graph instead of two halves; a unit test guards it.

### Guarantees

| Guarantee | Mechanism |
|---|---|
| Transient feed failures are retried | `RetryPolicy`: 3 retries, 30 s exponential backoff |
| An empty Bronze table cannot feed dbt | `<source>_has_rows`, a **blocking** asset check |
| Bronze read everything Kafka held | `<source>_consumer_caught_up`, lag check on the writer's own consumer group |
| Nothing goes stale silently | `FreshnessPolicy.time_window` on Bronze and Gold: **warn 8 h, fail 14 h** |
| Runs never overlap | `QueuedRunCoordinator`, `max_concurrent_runs: 1` |
| No unattended downloads without consent | 6-hour UTC schedule, `DefaultScheduleStatus.STOPPED` |
| Outcomes are queryable without the UI | run sensors upsert into `ops.pipeline_run` |

The freshness windows follow from the schedule: warning after one missed run,
failure after two. Two levels, so one slow night is not a red alert.

### Where state lives

- Run, event and schedule storage: **Postgres**, in the `orchestration` schema
  created in Phase 0 (22 tables, none in `public`).
- `DAGSTER_HOME`: under `AEGIS_DATA_DIR`, outside OneDrive.
- Instance config: committed at `infra/dagster/dagster.yaml` and copied into
  `DAGSTER_HOME` on every start, so git stays the source of truth. It contains
  no password; the storage URL comes from the environment.

## Verification

One end-to-end run of `aegis_pipeline`, with Bronze, Kafka and Silver measured
immediately before and after:

| Feed | Bronze added | Kafka waiting after | Silver before → after |
|---|---:|---:|---|
| `cisa_kev` | 1,709 | 0 | 1,695 → 1,709 |
| `urlhaus` | 12,681 | 0 | 12,710 → 13,101 |
| `tor_exit` | 1,325 | 0 | 1,339 → 1,373 |
| `feodo` | 7 | 0 | 5 → 5 |

- **Run succeeded** in about 90 seconds, with no step failures and no retries.
- **19 assets** materialised.
- **42 check evaluations**: 8 custom (all 4 blocking `has_rows` and all 4 lag
  checks passed) and 34 dbt tests. 41 passed; the one warning is the known
  duplicate-`event_id` from the Phase 2 demo script.
- dbt's `run_results.json` for the run shows **49 nodes and all 37 tests
  executed**, including the three singular reconciliation tests, all `pass`.
- Every Silver table's row count equals the distinct natural keys now in
  Bronze, recounted independently of dbt. Bronze KEV gained 1,709 rows; Silver
  gained 14 — the genuinely new CVEs CISA published that day.

## Consequences

### Positive

- The platform can run unattended: one schedule, one run at a time, retried,
  checked and recorded.
- A failure is now contained at the right boundary. A blocking check on an
  empty Bronze table stops Silver and Gold from being rebuilt as empty tables
  that would still pass every dbt test.
- Freshness covers the failure no other check can see: a pipeline that stops
  running produces no error, only older data.
- The collectors, Bronze writer and dbt project are unchanged and still run on
  their own. Dagster decides when; it does not own the logic.

### Negative

- `Definitions.map_resolved_asset_specs` is a **preview** API that "may have
  breaking changes in patch version releases". The Dagster packages are
  therefore pinned to exact versions (`dagster==1.13.22`), unlike every other
  dependency. Upgrading is a deliberate step, gated by
  `tests/test_orchestration.py`.
- dbt's three reconciliation tests run and are enforced — a failure fails the
  step — but they do not appear as Dagster checks, because each spans several
  tables and maps to no single asset. They are visible only in dbt's own
  artifacts.
- Two more long-running processes (web UI and daemon) are needed for
  schedules, sensors and freshness evaluation. On this machine that is not
  currently affordable.

## Not yet verified

Stated plainly, because a green test suite does not cover these:

- **The schedule, both run sensors and freshness evaluation have not been
  observed running.** All three need the Dagster daemon (`aegis orchestrate
  dev`), which was not started with under 0.2 GB of RAM free. They are defined
  and load-validated, and the in-process run does not fire sensors by design.
- **Partial runs.** The full job issues `dbt build --select fqn:*`, so every
  test runs. When only a subset is materialised — for example one Gold table
  from the UI — dagster-dbt narrows the selection, and multi-table singular
  tests referencing models outside that subset may not be selected. Not tested.

## Four things the first build found

**1. `from __future__ import annotations` breaks Dagster's context validation.**
That import stores every annotation as a string. Dagster compares the `context`
annotation against the real class, so loading failed with the
self-contradictory *"Cannot annotate `context` with type AssetExecutionContext.
`context` must be annotated with AssetExecutionContext"*. The import was removed
from the four modules that define decorated functions, with a note explaining
why they differ from the rest of the codebase.

**2. The first freshness implementation used superseded APIs.**
`build_last_update_freshness_checks` plus a sensor loaded and even evaluated,
but Dagster 1.13 supersedes both in favour of a `FreshnessPolicy` on the asset.
Migrating also improved the design: two levels (warn and fail) instead of one,
and no sensor to forget to start.

**3. A function signature was the wrong thing to trust.**
`Definitions.map_asset_specs` still lists a `selection` parameter, and passing
one fails at runtime: *"The selection parameter is no longer supported for
map_asset_specs"*. Reading the source, not the signature, showed the invariant
and the replacement, `map_resolved_asset_specs`.

**4. A missing summary line was nearly misread as a crash.**
Two test runs printed passing dots but no final summary, and the first
explanation reached for was memory pressure. The exit codes were 0 and every
test had passed. The diagnosis came from rerunning with raw output and exit
codes, not from the more dramatic theory.

## Alternatives considered

- **Apache Airflow.** The most widely used orchestrator, and its task-centric
  model would have worked. Rejected here for two reasons: its scheduler,
  webserver and metadata database cost roughly 1.5 GB more than this machine
  has, and a task graph cannot answer "which Gold tables are stale because
  Feodo failed?" without that lineage being rebuilt by hand. Dagster reads it
  from the dbt manifest.
- **cron or Windows Task Scheduler running `aegis` commands.** The lightest
  option. Rejected: no retries, no dependency ordering, no checks between
  steps, and no way to see what is stale — every guarantee in the table above
  would have to be reinvented.
- **Prefect.** Comparable, with a lighter local footprint. Rejected mainly for
  its weaker dbt integration: dagster-dbt's manifest-driven assets are what
  make one graph from Python and SQL.
