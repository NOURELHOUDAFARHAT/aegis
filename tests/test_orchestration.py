"""Tests for the orchestration layer.

None of these run the pipeline. They check the properties that, if broken,
would make Dagster quietly do the wrong thing: a graph split in two, a lag check
watching the wrong consumer group, a schedule that starts downloading on its
own, or a password written into a config file.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("dagster")

from dagster import AssetKey, DefaultScheduleStatus, Definitions


@pytest.fixture(scope="module")
def defs() -> Definitions:
    from aegis.orchestration.definitions import defs as loaded

    return loaded


def _parents(defs: Definitions, key: AssetKey) -> set[AssetKey]:
    resolve = getattr(defs, "resolve_asset_graph", None) or defs.get_asset_graph
    return set(resolve().get(key).parent_keys)


class TestDefinitions:
    def test_definitions_are_loadable(self, defs: Definitions) -> None:
        """The same validation `dagster dev` performs on startup."""
        Definitions.validate_loadable(defs)

    def test_every_collector_has_a_raw_and_bronze_asset(self, defs: Definitions) -> None:
        from aegis.sources.feeds import COLLECTORS

        resolve = getattr(defs, "resolve_asset_graph", None) or defs.get_asset_graph
        keys = set(resolve().get_all_asset_keys())
        for source in COLLECTORS:
            assert AssetKey(["raw", source]) in keys
            assert AssetKey(["bronze", source]) in keys


class TestLineage:
    """The graph must be ONE connected chain from feed to Gold."""

    def test_bronze_is_built_from_raw(self, defs: Definitions) -> None:
        assert AssetKey(["raw", "feodo"]) in _parents(defs, AssetKey(["bronze", "feodo"]))

    def test_dbt_staging_reads_the_bronze_asset(self, defs: Definitions) -> None:
        """The join between the Python and dbt halves of the graph.

        If the dbt translator named sources differently from the Bronze assets,
        staging would depend on an orphan `bronze/feodo` source with nothing
        upstream, and Dagster could no longer tell that rebuilding Silver needs
        a Bronze sync first.
        """
        assert AssetKey(["bronze", "feodo"]) in _parents(defs, AssetKey(["staging", "stg_feodo"]))

    def test_cross_source_gold_depends_on_both_feeds(self, defs: Definitions) -> None:
        parents = _parents(defs, AssetKey(["gold", "c2_infrastructure"]))
        assert AssetKey(["silver", "feodo_c2_servers"]) in parents
        assert AssetKey(["silver", "tor_exit_nodes"]) in parents


class TestDbtTranslator:
    def test_sources_map_onto_bronze_asset_keys(self) -> None:
        from aegis.orchestration.dbt import AegisDbtTranslator

        props = {"resource_type": "source", "source_name": "bronze", "name": "urlhaus"}
        assert AegisDbtTranslator().get_asset_key(props) == AssetKey(["bronze", "urlhaus"])

    def test_models_keep_their_layer(self) -> None:
        from aegis.orchestration.dbt import AegisDbtTranslator

        props = {"resource_type": "model", "schema": "gold", "name": "vendor_exploitation"}
        assert AegisDbtTranslator().get_asset_key(props) == AssetKey(
            ["gold", "vendor_exploitation"]
        )


class TestSchedule:
    def test_pipeline_schedule_is_stopped_by_default(self, defs: Definitions) -> None:
        """Starting Dagster must never begin downloading from third-party
        servers on its own. Turning the schedule on is a deliberate act."""
        resolve = getattr(defs, "resolve_schedule_def", None) or defs.get_schedule_def
        schedule = resolve("aegis_pipeline_every_6h")
        assert schedule.default_status == DefaultScheduleStatus.STOPPED

    def test_pipeline_schedule_runs_every_six_hours_in_utc(self, defs: Definitions) -> None:
        resolve = getattr(defs, "resolve_schedule_def", None) or defs.get_schedule_def
        schedule = resolve("aegis_pipeline_every_6h")
        assert schedule.cron_schedule == "0 */6 * * *"
        assert schedule.execution_timezone == "UTC"


class TestLagCheckWatchesTheRightGroup:
    def test_group_id_matches_the_bronze_writer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The lag check must inspect the exact consumer group the writer commits to.

        If these drifted, the check would watch an idle group that has never
        consumed anything and report "caught up" forever. BronzeWriter is built
        here against a fake table so the test needs no infrastructure.
        """
        import aegis.lakehouse.writer as writer_module
        from aegis.orchestration.checks import bronze_group_id

        fake_table: Any = SimpleNamespace(
            name=lambda: ("bronze", "feodo"),
            metadata=SimpleNamespace(snapshots=[]),
        )
        monkeypatch.setattr(writer_module, "load_bronze", lambda source: fake_table)

        writer = writer_module.BronzeWriter("feodo")
        assert writer.group_id == bronze_group_id("feodo")


class TestInstanceConfig:
    @pytest.fixture
    def config(self) -> dict[str, Any]:
        import yaml

        from aegis.orchestration.home import REPO_DAGSTER_YAML

        loaded: dict[str, Any] = yaml.safe_load(REPO_DAGSTER_YAML.read_text(encoding="utf-8"))
        return loaded

    def test_no_password_in_the_committed_config(self, config: dict[str, Any]) -> None:
        """The storage URL must come from the environment, not the file."""
        url = config["storage"]["postgres"]["postgres_url"]
        assert url == {"env": "AEGIS_DAGSTER_PG_URL"}

    def test_one_run_at_a_time(self, config: dict[str, Any]) -> None:
        """Two overlapping runs would fight over the DuckDB write lock."""
        assert config["run_coordinator"]["class"] == "QueuedRunCoordinator"
        assert config["run_coordinator"]["config"]["max_concurrent_runs"] == 1

    def test_telemetry_is_disabled(self, config: dict[str, Any]) -> None:
        assert config["telemetry"]["enabled"] is False

    def test_pg_url_targets_the_orchestration_schema(self) -> None:
        from aegis.orchestration.home import dagster_pg_url

        url = dagster_pg_url()
        assert url.startswith("postgresql://")
        assert "search_path%3Dorchestration" in url


class TestFreshness:
    """Freshness is the only guarantee that fires when NOTHING runs.

    Every other check needs the pipeline to execute before it can fail. A
    schedule someone forgot to turn back on produces no failed test and no
    error - only stale data - so this policy must actually be attached.
    """

    @staticmethod
    def _policies(defs: Definitions) -> dict[AssetKey, Any]:
        return {spec.key: spec.freshness_policy for spec in defs.resolve_all_asset_specs()}

    @staticmethod
    def _as_timedelta(value: Any) -> Any:
        # Dagster may store windows in its own serialisable wrapper.
        return value.to_timedelta() if hasattr(value, "to_timedelta") else value

    def test_bronze_and_gold_carry_the_policy(self, defs: Definitions) -> None:
        from aegis.orchestration.checks import FRESHNESS_GOVERNED, FRESHNESS_POLICY

        policies = self._policies(defs)
        for key in FRESHNESS_GOVERNED:
            assert policies[key] == FRESHNESS_POLICY, (
                f"{key.to_user_string()} has no freshness policy"
            )

    def test_dbt_generated_gold_assets_are_governed(self, defs: Definitions) -> None:
        """Gold tables come from dagster-dbt, not from a decorator of ours.

        This is the case map_asset_specs exists to cover: if the policy were set
        only in @asset calls, every dbt asset would silently have none.
        """
        policies = self._policies(defs)
        assert policies[AssetKey(["gold", "c2_infrastructure"])] is not None

    def test_intermediate_layers_are_not_governed(self, defs: Definitions) -> None:
        """Staging and Silver are intermediate; a stale Gold already implies them."""
        policies = self._policies(defs)
        assert policies[AssetKey(["staging", "stg_feodo"])] is None
        assert policies[AssetKey(["silver", "feodo_c2_servers"])] is None

    def test_windows_match_the_six_hour_schedule(self) -> None:
        """Warn after one missed run, fail after two."""
        from datetime import timedelta

        from aegis.orchestration.checks import FRESHNESS_POLICY

        assert self._as_timedelta(FRESHNESS_POLICY.warn_window) == timedelta(hours=8)
        assert self._as_timedelta(FRESHNESS_POLICY.fail_window) == timedelta(hours=14)
