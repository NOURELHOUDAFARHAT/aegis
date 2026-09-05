# ADR 0002 — A JVM-free, single-node lakehouse

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

AEGIS must run end to end on the development machine, which has:

- 7.7 GB total RAM, of which Docker Desktop is allocated **3.95 GB**
- an Intel i3-1215U (6 cores)
- ~39 GB free disk

The conventional data-engineering stack for this workload would be Apache Spark
for processing, Apache Airflow for orchestration and Trino for querying. Their
realistic minimum footprints are roughly:

| Component | Minimum practical memory |
|---|---|
| Spark driver + one executor | ~2.5 GB |
| Airflow (scheduler + webserver + triggerer) | ~1.5 GB |
| Trino coordinator + worker | ~2.0 GB |
| Kafka + ZooKeeper/KRaft | ~2.0 GB |

That is roughly 8 GB before a single row of data is processed — more than twice
the entire Docker allocation, and more than the machine has.

The second, more important observation: **the data does not need a cluster.**
Projected steady-state volume is on the order of 10⁵–10⁷ events per day of
small JSON records — single-digit gigabytes of Parquet per month. Distributed
compute exists to solve a problem this workload does not have, while imposing
its full operational cost regardless.

## Decision

Build the entire platform on **single-node, embedded, JVM-free engines**:

| Layer | Technology | Role |
|---|---|---|
| Table format | **Apache Iceberg** via `pyiceberg` | ACID transactions, snapshot isolation, time travel, schema and partition evolution — implemented in pure Python |
| Storage | **MinIO** (S3 API) → AWS S3 in Phase 9 | Object storage, identical API in both environments |
| Query engine | **DuckDB** | Vectorised OLAP execution, reads Iceberg and Parquet directly from S3 |
| DataFrame engine | **Polars** | Multi-threaded, Arrow-native, lazy-evaluated transformations |
| Transformations | **dbt-duckdb** | Version-controlled, tested, documented SQL |
| Broker | **Redpanda** | Kafka wire protocol without ZooKeeper or a JVM |
| Orchestration | **Dagster** | Asset-based scheduling and lineage |

The binding constraint the architecture respects is: **the table format is the
interface, not the engine.** Because Bronze/Silver/Gold are Iceberg tables in
object storage, Spark, Trino, Athena, Snowflake, BigQuery and Databricks can
all read them without migration. Choosing a small engine today does not
foreclose a large one tomorrow.

## Consequences

**Positive**

- Total infrastructure footprint measured at **~379 MB resident** across four
  containers, leaving ample headroom for the ML phase.
- The edit → run loop is seconds, not a cluster restart. This materially
  changes how much can be learned per hour.
- DuckDB is genuinely faster than Spark for datasets that fit in memory, since
  it pays no serialisation, shuffle or scheduling overhead.
- The stack is honest about the data's real size — a judgement recruiters value
  more highly than reflexive Spark usage.

**Negative**

- No horizontal scale-out. Beyond roughly 100 GB of hot data this must change.
  The migration path is documented in Phase 9 rather than pretended away.
- `pyiceberg` is a younger implementation than Iceberg's Java library; some
  maintenance procedures (compaction, expiring snapshots) require more manual
  work.
- "No Spark" is a claim that must be defended in interviews rather than assumed.
  Phase 9 therefore adds a deliberately small Spark/EMR path so the comparison
  is demonstrated, not merely argued.

**Neutral**

- Application code runs on the host in a venv rather than in containers, saving
  ~1.5 GB of duplicated Python runtimes. Phase 9 containerises it for
  deployment, where that overhead is no longer a constraint.

## Alternatives considered

- **Spark in local mode (`local[*]`)** — rejected: still ~2.5 GB and a JVM
  startup penalty per run, for a dataset that fits in a laptop's RAM.
- **Delta Lake instead of Iceberg** — rejected: `delta-rs` is capable, but
  Iceberg has broader multi-engine catalogue support (Glue, Nessie, Polaris,
  REST) which matters more for the cloud phase.
- **Plain Parquet with no table format** — rejected: no ACID guarantees, no
  time travel, no safe concurrent writes, and no schema evolution. The whole
  point of the Bronze layer is that it can be replayed correctly.
- **A managed warehouse (BigQuery / Snowflake free tier)** — rejected: it hides
  exactly the mechanics this project exists to teach, and adds vendor lock-in
  to a portfolio piece.
