# ADR 0006 — Silver and Gold built by dbt, stored in a DuckDB warehouse

- **Status:** Accepted
- **Date:** 2026-09-13

## Context

Bronze holds every observation exactly as it arrived: 21,841 rows across four
Iceberg tables, with JSON payloads and one copy per collection run. That is
correct for Bronze and useless for analysis. The CISA catalogue alone appears
three times, so a naive count reported **1,158** actively-exploited Microsoft
vulnerabilities when the true figure is **386**.

Phase 4 needs three things:

1. A place where transformation logic lives as reviewable, versioned SQL.
2. Deduplication that is deterministic, so Silver can be deleted and rebuilt
   and give the same answer every time.
3. Tests that stop the build when the data is wrong, not just when the code is.

## Decision

**Transformations are dbt models; Silver and Gold are tables in a local DuckDB
file.**

| Layer | Materialisation | Grain | Built by |
|---|---|---|---|
| Staging | view | one row per Bronze row | JSON unpacked, types cast, nothing filtered |
| Silver | table | one row per real-world entity | deduplicated on natural key |
| Gold | table | one row per answer | aggregates and cross-source joins |

dbt reads Bronze **directly from the Iceberg catalog** through dbt-duckdb's
`iceberg` plugin, using the same catalog URI the Bronze writer uses. There is no
export step between the lakehouse and the models.

### Deduplication rule

For each natural key (`cve_id`, `url`, `ip_address`) Silver keeps the **most
recently ingested** copy, tie-broken by Kafka offset. The latest collection
carries any correction the source published, and the tie-break makes the choice
deterministic. Nothing is discarded silently: `first_observed_at`,
`last_observed_at` and `times_observed` preserve how the entity was seen.

### Where each guarantee is enforced

| Guarantee | Enforced in | Severity |
|---|---|---|
| Every row has an `event_id` | staging, `not_null` | error |
| `event_id` is unique | staging, `unique` | **warn** |
| One row per real entity | Silver, `unique` on natural key | error |
| Silver lost nothing | singular test: Silver count = distinct keys in Bronze | error |
| Gold adds up | singular test: sum of Gold = Silver total | error |
| No test data in Silver | singular test on RFC 5737 addresses | error |

## Consequences

### Positive

- `1,158` became `386`, and a reconciliation test proves Silver holds exactly
  the 1,695 distinct CVEs in Bronze — catching *loss*, which `unique` alone
  cannot.
- The first cross-source table exists. `gold.c2_infrastructure` joins Feodo
  against the Tor exit list and shows that none of the 5 botnet C2 servers is a
  Tor exit, and 4 of 5 run on DigitalOcean or Amazon.
- Every Gold number is reproducible with one command, `aegis model build`,
  which rebuilds everything in about 6 seconds.

### Negative

- **Silver and Gold are not Iceberg tables.** They live in a single DuckDB file,
  so they have no time travel, no snapshot history, and cannot be read by Spark
  or Athena the way Bronze can. This is acceptable because both layers are
  disposable by design — they are always rebuildable from Bronze — but it means
  the "table format is the interface" claim currently holds only for Bronze.
  Publishing Gold back to Iceberg is deferred to the orchestration phase.
- A DuckDB file permits one writer at a time. Fine for a scheduled build;
  wrong for concurrent writers.

## Three things the first build found

These are recorded because each changed the design, not just the code.

**1. A concurrency race in dbt's source loading.** With two threads, two
Iceberg sources loaded at the same instant and each issued `CREATE SCHEMA
bronze`. DuckDB aborted the loser with *"Catalog write-write conflict"*. Which
model failed depended on timing. Fixed with an `on-run-start` hook that creates
the schema once, keeping both threads rather than removing the concurrency.

**2. Tests and demos had written fake records into production tables.**
Profiling Bronze before writing any SQL found 9 Feodo rows with no `status`.
They were two addresses: `203.0.113.10` ("DemoBot", from
`scripts/demo_contracts.py`) and `198.51.100.7` (from an integration test),
both published through the live pipeline. Bronze keeps them — it records what
arrived. Silver excludes them using the RFC 5737 documentation ranges, which no
real attacker can ever use, so the rule catches whatever the next test leaks
rather than just these two.

**3. A uniqueness test asserted the wrong invariant.** `unique` on
`event_id` in staging failed on three IDs, all DemoBot. Each duplicate had two
distinct Kafka offsets: the demo script wrote the same event object twice per
run. The pipeline had stored exactly what arrived. The test was wrong — Bronze
is at-least-once, and redelivered events legitimately repeat an `event_id`.
The staging test became a warning; uniqueness is enforced in Silver on each
table's natural key. The demo script now sends two distinct events.

## Follow-up

The root cause of finding 2 is that tests and demos publish to the same topics
the collectors use. The Silver filter makes that harmless for analysis, but the
correct fix is at the source: a separate topic and table namespace for tests.
Not done in this phase.

## Alternatives considered

- **Write Silver and Gold back to Iceberg now.** Rejected for this phase. The
  PyIceberg write path would need a merge/upsert strategy for Silver that dbt
  does not provide against Iceberg without a JVM engine, and the benefit —
  time travel on rebuildable tables — is small.
- **Deduplicate in the Bronze writer.** Rejected. It would make Bronze no
  longer "exactly what arrived", and a bug in the deduplication would destroy
  data that could never be recovered.
- **Hand-written SQL scripts run in order.** Rejected. dbt provides the
  dependency ordering, tests, documentation and lineage graph; reimplementing
  them is how teams end up with an undocumented pipeline no one can change.
- **`threads: 1` to avoid the race.** Works, but fixes the conflict by removing
  the concurrency instead of removing the shared write.
