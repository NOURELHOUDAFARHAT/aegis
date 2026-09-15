"""The dbt project as Dagster assets.

dagster-dbt reads dbt's manifest and turns every model into a Dagster asset and
every data test into an asset check - the same 11 models and 37 tests that
`aegis model build` runs, now inside the one graph.

THE ONE LINE THAT JOINS THE TWO HALVES
--------------------------------------
dbt knows its Bronze inputs as sources named `bronze.<table>`. Dagster's
Bronze writer produces assets keyed `bronze/<source>`. If those two names did
not line up, the graph would split in two: Dagster would not know that
rebuilding Silver needs Bronze first, and "what is stale?" would stop at the
dbt boundary.

`AegisDbtTranslator.get_asset_key` maps every dbt source onto exactly the key
the Bronze asset uses, so `bronze/feodo` is one node with the writer upstream
and `staging/stg_feodo` downstream.
"""

# No `from __future__ import annotations`: @dbt_assets validates the `context`
# annotation against the real class, and that import turns it into a string.
# See the note at the top of orchestration/assets.py.
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from dagster import AssetExecutionContext, AssetKey
from dagster_dbt import DagsterDbtTranslator, DbtCliResource, DbtProject, dbt_assets

from aegis.modeling.dbt_runner import DBT_DIR, run_dbt
from aegis.orchestration.pools import WAREHOUSE_POOL


class AegisDbtTranslator(DagsterDbtTranslator):
    """Names dbt nodes so they connect to the rest of the AEGIS graph."""

    def get_asset_key(self, dbt_resource_props: Mapping[str, Any]) -> AssetKey:
        if dbt_resource_props["resource_type"] == "source":
            # source.aegis.bronze.feodo -> bronze/feodo, the Bronze writer's key.
            return AssetKey(["bronze", dbt_resource_props["name"]])
        # Models keep their layer: staging/stg_feodo, silver/..., gold/...
        # `schema` is the generated schema name, so it honours the project's
        # generate_schema_name macro rather than dbt's prefixed default.
        return AssetKey([dbt_resource_props["schema"], dbt_resource_props["name"]])


def dbt_executable() -> str:
    """Path to the dbt binary in THIS interpreter's environment.

    dagster-dbt runs dbt as a subprocess, and by default looks for `dbt` on
    PATH. The venv lives outside the repo and is often not activated when
    Dagster starts, so PATH may hold a different dbt or none at all. Pointing at
    the executable beside the running interpreter guarantees the same dbt
    version the models were developed against.
    """
    name = "dbt.exe" if sys.platform == "win32" else "dbt"
    candidate = Path(sys.executable).with_name(name)
    return str(candidate) if candidate.exists() else "dbt"


DBT_PROJECT = DbtProject(project_dir=DBT_DIR, profiles_dir=DBT_DIR)


def ensure_manifest() -> None:
    """Generate dbt's manifest if it does not exist yet.

    The manifest is build output (dbt/target is gitignored), so a fresh clone or
    CI runner has none - and @dbt_assets needs it at import time to know which
    assets exist. Parsing needs no database connection, so this is safe anywhere.
    """
    if not DBT_PROJECT.manifest_path.exists():
        run_dbt(["parse"])


ensure_manifest()


@dbt_assets(
    manifest=DBT_PROJECT.manifest_path,
    project=DBT_PROJECT,
    dagster_dbt_translator=AegisDbtTranslator(),
    # dbt writes the DuckDB warehouse; so do the ML assets. One writer at a
    # time - see orchestration/pools.py.
    pool=WAREHOUSE_POOL,
)
def aegis_dbt_models(context: AssetExecutionContext, dbt: DbtCliResource) -> Iterator[Any]:
    """Every staging, Silver and Gold model, built and tested by `dbt build`.

    Dagster passes the selected subset to dbt, so materialising only
    gold/c2_infrastructure runs only that model and its tests.
    """
    yield from dbt.cli(["build"], context=context).stream()


def dbt_resource() -> DbtCliResource:
    return DbtCliResource(
        project_dir=DBT_PROJECT,
        profiles_dir=str(DBT_DIR),
        dbt_executable=dbt_executable(),
    )
