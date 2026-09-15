"""Concurrency pools for the Dagster asset graph.

WAREHOUSE_POOL
--------------
dbt and the three ML assets all write to the same DuckDB warehouse file, and
DuckDB allows one writing process per database file at a time. Dagster's
default multiprocess executor would otherwise start every one of them in
parallel the moment Silver exists - and all but the first would fail to take
the file lock.

Every step that opens the warehouse joins this pool. `infra/dagster/dagster.yaml`
sets `concurrency.pools.default_limit: 1`, so the pool admits one step at a time
across all runs. Collection and the Bronze sync are not in the pool and keep
running in parallel.

(`aegis orchestrate run` executes in-process, one step at a time, so it never
hit this. The web UI and schedules use the multiprocess executor, where it would.)
"""

WAREHOUSE_POOL = "duckdb_warehouse"
