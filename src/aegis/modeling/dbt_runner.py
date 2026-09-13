"""Run dbt with AEGIS's configuration.

WHY A WRAPPER INSTEAD OF CALLING `dbt` DIRECTLY
-----------------------------------------------
dbt reads credentials through `env_var()` in profiles.yml. Something has to put
them in the environment, and the choices are:

  * a second .env loader just for dbt   -> two places to change a password
  * typing them into the shell          -> they end up in shell history
  * this module                         -> derived from the one Settings object

So `aegis model build` sets the variables from `aegis.config`, then calls dbt
in-process through its Python API. The catalog URI in particular is built by
`aegis.lakehouse.catalog.catalog_uri()`, which URL-quotes the password - the
dbt profile gets exactly the connection string the Bronze writer uses.
"""

from __future__ import annotations

import os
from pathlib import Path

from aegis.config import settings
from aegis.lakehouse.catalog import catalog_uri
from aegis.logging import get_logger

log = get_logger(__name__)

# aegis/src/aegis/modeling/dbt_runner.py -> aegis/dbt
DBT_DIR = Path(__file__).resolve().parents[3] / "dbt"


def warehouse_path() -> Path:
    """Where the DuckDB file holding Silver and Gold lives."""
    return Path(settings.data_dir) / "warehouse" / "aegis.duckdb"


def dbt_env() -> dict[str, str]:
    """Every variable profiles.yml reads, derived from Settings."""
    storage = settings.storage
    return {
        "AEGIS_WAREHOUSE_PATH": str(warehouse_path()),
        "AEGIS_CATALOG_URI": catalog_uri(),
        "AEGIS_LAKE_BUCKET": storage.lake_bucket,
        "AEGIS_S3_ENDPOINT": storage.s3_endpoint,
        "AEGIS_S3_ACCESS_KEY": storage.s3_access_key,
        "AEGIS_S3_SECRET_KEY": storage.s3_secret_key,
        "AEGIS_S3_REGION": storage.s3_region,
        # dbt phones home with anonymous usage statistics by default. A
        # security-telemetry platform should not make network calls it does
        # not need, and it keeps offline runs quiet.
        "DBT_SEND_ANONYMOUS_USAGE_STATS": "false",
    }


def run_dbt(args: list[str]) -> bool:
    """Invoke dbt in-process. Returns True if every node succeeded."""
    from dbt.cli.main import dbtRunner

    warehouse_path().parent.mkdir(parents=True, exist_ok=True)
    os.environ.update(dbt_env())

    full_args = [*args, "--project-dir", str(DBT_DIR), "--profiles-dir", str(DBT_DIR)]
    log.info("dbt_invoke", args=args, warehouse=str(warehouse_path()))

    result = dbtRunner().invoke(full_args)
    if result.exception is not None:
        log.error("dbt_crashed", error=str(result.exception)[:300])
    return bool(result.success)
