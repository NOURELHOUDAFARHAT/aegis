"""Tests for the modelling layer: the dbt wrapper and the CLI's query guard.

None of these run dbt. They check the seams where the Python side and the dbt
project can drift apart silently - an env var the profile reads but the wrapper
never sets, or a table-name pattern that lets SQL through.
"""

from __future__ import annotations

import re

import pytest

from aegis.modeling.dbt_runner import DBT_DIR, dbt_env, warehouse_path


class TestDbtWrapper:
    def test_every_env_var_the_profile_reads_is_provided(self) -> None:
        """profiles.yml reads credentials with env_var(); the wrapper sets them.

        If someone adds `env_var('AEGIS_NEW_THING')` to the profile and forgets
        the wrapper, dbt fails at run time with a message about a missing
        variable - far from the change that caused it. This catches the drift
        at test time, next to the cause.
        """
        profile = (DBT_DIR / "profiles.yml").read_text(encoding="utf-8")
        referenced = set(re.findall(r"env_var\('([A-Z0-9_]+)'", profile))

        assert referenced, "profiles.yml should read its settings via env_var()"
        missing = referenced - set(dbt_env())
        assert not missing, f"profiles.yml reads variables the wrapper never sets: {missing}"

    def test_dbt_dir_is_the_project(self) -> None:
        assert (DBT_DIR / "dbt_project.yml").is_file()

    def test_anonymous_usage_stats_are_disabled(self) -> None:
        """A security-telemetry platform should not make network calls it does
        not need. dbt reports usage statistics by default."""
        assert dbt_env()["DBT_SEND_ANONYMOUS_USAGE_STATS"] == "false"

    def test_warehouse_lives_under_the_data_dir_not_the_repo(self) -> None:
        """The DuckDB file is regenerable output. It must not land in the repo
        (or in OneDrive, which syncs the repo)."""
        from aegis.config import settings

        assert warehouse_path().name == "aegis.duckdb"
        assert warehouse_path().is_relative_to(settings.data_dir)

    def test_catalog_uri_matches_the_bronze_writer(self) -> None:
        """dbt must read Bronze through the exact same catalog connection the
        writer uses - including the URL-quoted password and search_path."""
        from aegis.lakehouse.catalog import catalog_uri

        assert dbt_env()["AEGIS_CATALOG_URI"] == catalog_uri()


class TestTableNameGuard:
    """`aegis model show <table>` interpolates the table name into SQL.

    Identifiers cannot be bound as query parameters, so the defence is strict
    validation. These tests are the evidence behind the S608 suppression.
    """

    @pytest.fixture
    def pattern(self) -> re.Pattern[str]:
        from aegis.cli import _TABLE_NAME

        return re.compile(_TABLE_NAME)

    @pytest.mark.parametrize(
        "name",
        ["gold.vendor_exploitation", "silver.kev_vulnerabilities", "staging.stg_feodo"],
    )
    def test_accepts_real_tables(self, pattern: re.Pattern[str], name: str) -> None:
        assert pattern.match(name)

    @pytest.mark.parametrize(
        "attempt",
        [
            "gold.x; DROP TABLE silver.kev_vulnerabilities",  # statement stacking
            "gold.x --",  # comment out the rest of the query
            "gold.x UNION SELECT * FROM bronze.urlhaus",  # read outside allowed layers
            "bronze.urlhaus",  # a layer that is not exposed
            "main.secrets",  # an arbitrary schema
            "gold.Vendor",  # uppercase: not a generated dbt name
            "gold.",  # empty table name
            "vendor_exploitation",  # no layer at all
            "gold.x' OR '1'='1",  # quote injection
        ],
    )
    def test_rejects_injection_attempts(self, pattern: re.Pattern[str], attempt: str) -> None:
        assert not pattern.match(attempt), f"pattern accepted unsafe input: {attempt!r}"
