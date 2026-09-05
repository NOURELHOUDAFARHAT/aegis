"""Tests for the configuration layer.

These are deliberately the first tests in the project. Configuration is the
component every other component depends on, and a config bug is the cheapest
possible thing to catch and the most expensive to debug in production.
"""

from __future__ import annotations

import pytest

from aegis.config import DatabaseSettings, KafkaSettings, Settings, StorageSettings


class TestKafkaSettings:
    def test_producer_config_is_durable_by_default(self) -> None:
        """Every producer must be durable and idempotent unless explicitly told otherwise.

        This test exists to prevent a future 'quick fix' from setting acks=0 to
        make a throughput number look better at the cost of silent data loss.
        """
        cfg = KafkaSettings().producer_config(client_id="test")

        assert cfg["acks"] == "all", "security telemetry cannot be re-fetched if lost"
        assert cfg["enable.idempotence"] is True, "retries must not duplicate events"
        assert cfg["client.id"] == "test"
        assert int(cfg["retries"]) >= 5  # type: ignore[arg-type]

    def test_consumer_never_auto_commits(self) -> None:
        """Offsets must be committed after downstream write, never before."""
        cfg = KafkaSettings().consumer_config(group_id="g1")

        assert cfg["enable.auto.commit"] is False
        assert cfg["group.id"] == "g1"
        assert cfg["auto.offset.reset"] == "latest"

    def test_from_beginning_replays_the_whole_topic(self) -> None:
        cfg = KafkaSettings().consumer_config(group_id="g1", from_beginning=True)
        assert cfg["auto.offset.reset"] == "earliest"


class TestStorageSettings:
    def test_s3_properties_use_path_style_for_minio(self) -> None:
        """MinIO cannot serve virtual-host-style URLs without per-bucket DNS."""
        props = StorageSettings().s3_properties

        assert props["s3.path-style-access"] == "true"
        assert props["s3.endpoint"].startswith("http")
        assert "s3.access-key-id" in props
        assert "s3.secret-access-key" in props

    def test_dev_secret_rejected_outside_local_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The development credential must never silently work in staging or prod."""
        monkeypatch.setenv("AEGIS_ENV", "prod")

        with pytest.raises(ValueError, match="development S3 secret"):
            StorageSettings(s3_secret_key="aegis_dev_secret_change_me")

    def test_real_secret_accepted_outside_local_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_ENV", "prod")
        assert StorageSettings(s3_secret_key="a-real-secret").s3_secret_key == "a-real-secret"


class TestDatabaseSettings:
    def test_dsn_is_a_valid_sqlalchemy_url(self) -> None:
        dsn = DatabaseSettings(
            pg_host="db", pg_port=5432, pg_user="u", pg_password="p", pg_database="d"
        ).dsn
        assert dsn == "postgresql+psycopg://u:p@db:5432/d"

    def test_psycopg_dsn_is_libpq_keyword_form(self) -> None:
        dsn = DatabaseSettings(
            pg_host="db", pg_port=5432, pg_user="u", pg_password="p", pg_database="d"
        ).psycopg_dsn
        assert "host=db" in dsn and "dbname=d" in dsn


class TestSettings:
    def test_env_prefix_is_honoured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_LOG_LEVEL", "DEBUG")
        assert Settings().log_level == "DEBUG"

    def test_invalid_env_is_rejected_at_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Fail fast: a typo in .env must not become a runtime surprise."""
        monkeypatch.setenv("AEGIS_ENV", "producton")  # deliberate typo

        with pytest.raises(ValueError):
            Settings()

    def test_is_local_flag(self) -> None:
        assert Settings(env="local").is_local is True
        assert Settings(env="prod").is_local is False
