"""The AEGIS pipeline, as one Dagster code location.

This is the module Dagster loads:

    dagster dev -m aegis.orchestration.definitions

Everything the orchestrator knows about is registered here, and nothing else
in the codebase needs to know Dagster exists. The collectors, the Bronze
writer, the dbt project and the ML modules all still run from the `aegis` CLI;
Dagster only decides when, and in what order.
"""

from __future__ import annotations

import os

from dagster import AssetSpec, Definitions

from aegis.modeling.dbt_runner import dbt_env
from aegis.orchestration.assets import BRONZE_ASSETS, RAW_ASSETS
from aegis.orchestration.checks import ALL_CHECKS, FRESHNESS_GOVERNED, FRESHNESS_POLICY
from aegis.orchestration.dbt import aegis_dbt_models, dbt_resource
from aegis.orchestration.jobs import ML_JOB, MODELS_JOB, PIPELINE_JOB, PIPELINE_SCHEDULE
from aegis.orchestration.ml_assets import ML_ASSETS, ML_CHECKS
from aegis.orchestration.sensors import record_run_failure, record_run_success

# dbt runs as a subprocess and reads its credentials from the environment
# (see dbt/profiles.yml). Setting them when the code location loads means every
# process Dagster starts to run dbt inherits them.
os.environ.update(dbt_env())


def _with_freshness(spec: AssetSpec) -> AssetSpec:
    return spec.replace_attributes(freshness_policy=FRESHNESS_POLICY)


defs = Definitions(
    assets=[*RAW_ASSETS, *BRONZE_ASSETS, aegis_dbt_models, *ML_ASSETS],
    asset_checks=[*ALL_CHECKS, *ML_CHECKS],
    jobs=[PIPELINE_JOB, MODELS_JOB, ML_JOB],
    schedules=[PIPELINE_SCHEDULE],
    sensors=[record_run_success, record_run_failure],
    resources={"dbt": dbt_resource()},
).map_resolved_asset_specs(
    # One place attaches freshness to every governed asset - including the Gold
    # tables dagster-dbt generates, which have no decorator of ours to put a
    # policy on. See the FRESHNESS note in orchestration/checks.py.
    #
    # map_RESOLVED_asset_specs, not map_asset_specs. Dagster 1.13 still lists
    # `selection` in map_asset_specs' signature, but rejects it at runtime with
    # "The selection parameter is no longer supported for map_asset_specs";
    # only the resolved variant accepts a selection. The signature was the
    # wrong thing to trust - the invariant in the source is what runs.
    func=_with_freshness,
    selection=FRESHNESS_GOVERNED,
)
