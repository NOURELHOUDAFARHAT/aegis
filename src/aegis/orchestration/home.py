"""Dagster's home directory and connection settings.

DAGSTER_HOME holds Dagster's runtime state: compute logs, schedule ticks, the
instance config. It is regenerable output, so - like the venv, the collected
data and the dbt warehouse - it lives outside OneDrive.

The instance CONFIG, though, is design, and belongs in git. So the committed
file is `infra/dagster/dagster.yaml`, and `prepare_dagster_home()` copies it
into DAGSTER_HOME every time. The repo stays the single source of truth: an
edit made directly in DAGSTER_HOME is overwritten on the next start rather than
quietly drifting from what is reviewed.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from urllib.parse import quote

from aegis.config import settings
from aegis.modeling.dbt_runner import dbt_env

REPO_DAGSTER_YAML = Path(__file__).resolve().parents[3] / "infra" / "dagster" / "dagster.yaml"


def dagster_home() -> Path:
    return Path(settings.data_dir) / "dagster"


def dagster_pg_url() -> str:
    """Postgres URL for Dagster's run and event storage.

    `search_path=orchestration` puts Dagster's tables in the schema created for
    them in Phase 0, instead of scattering them through `public` beside the
    platform's own tables. The password is URL-quoted for the same reason as
    the Iceberg catalog URI: a `@` or `/` in it would silently corrupt the URL.
    """
    db = settings.database
    return (
        f"postgresql://{quote(db.pg_user)}:{quote(db.pg_password)}"
        f"@{db.pg_host}:{db.pg_port}/{db.pg_database}"
        f"?options=-csearch_path%3Dorchestration"
    )


def prepare_dagster_home() -> dict[str, str]:
    """Create DAGSTER_HOME, sync the committed config into it, set the env.

    Returns the environment variables it set, so a caller launching a
    subprocess can pass them on explicitly.
    """
    home = dagster_home()
    home.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO_DAGSTER_YAML, home / "dagster.yaml")

    env = {
        "DAGSTER_HOME": str(home),
        "AEGIS_DAGSTER_PG_URL": dagster_pg_url(),
        **dbt_env(),
    }
    os.environ.update(env)
    return env
