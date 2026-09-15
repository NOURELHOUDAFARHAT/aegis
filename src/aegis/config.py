"""Typed, validated, environment-driven configuration for AEGIS.

WHY THIS FILE EXISTS
--------------------
The single most common way a data pipeline breaks in production is a config
mistake: a wrong bucket, a stale broker address, a secret that silently fell
back to an empty string. Scattering ``os.getenv("SOMETHING")`` through the
codebase makes those failures happen *late* - deep inside a running job, at
3 a.m., after an hour of processing.

So AEGIS follows the 12-factor rule (config lives in the environment) with one
addition: **config is parsed and validated exactly once, at import time, into
immutable typed objects**. A typo in ``.env`` fails on startup with a precise
message, not halfway through a batch.

Every setting is read from an ``AEGIS_``-prefixed environment variable, so this
module is the complete, authoritative list of every knob the system has.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class KafkaSettings(BaseSettings):
    """Connection details for the Kafka-compatible broker (Redpanda locally)."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    kafka_bootstrap: str = Field(
        default="localhost:19092",
        description="Broker list. Port 19092 is the 'external' listener that "
        "the host venv uses; containers would use redpanda:9092.",
    )
    schema_registry_url: str = Field(default="http://localhost:18081")

    # Producer tuning. These four values are the difference between "it works
    # on my laptop" and "it does not lose messages under load".
    producer_acks: Literal["0", "1", "all"] = Field(
        default="all",
        description="'all' = the broker confirms the write is durable before "
        "we consider it sent. Slower, and the only correct choice for "
        "security telemetry we cannot re-fetch.",
    )
    producer_linger_ms: int = Field(
        default=50,
        description="Wait up to 50ms to batch messages together. Trades a "
        "little latency for a large throughput and compression win.",
    )
    producer_compression: Literal["none", "gzip", "snappy", "lz4", "zstd"] = Field(
        default="zstd",
        description="zstd gives the best ratio for JSON-ish telemetry, which "
        "compresses ~8x. Directly reduces storage cost and network time.",
    )
    producer_enable_idempotence: bool = Field(
        default=True,
        description="Broker de-duplicates retries, so a network blip cannot "
        "produce the same event twice. This is exactly-once *producing*.",
    )

    def producer_config(self, client_id: str) -> dict[str, object]:
        """Build a confluent-kafka producer config dict.

        Centralising this means every producer in the project gets the same
        durability guarantees - nobody can accidentally ship acks=0 code.
        """
        return {
            "bootstrap.servers": self.kafka_bootstrap,
            "client.id": client_id,
            "acks": self.producer_acks,
            "linger.ms": self.producer_linger_ms,
            "compression.type": self.producer_compression,
            "enable.idempotence": self.producer_enable_idempotence,
            # Retry hard: transient broker unavailability must not lose data.
            "retries": 10,
            "retry.backoff.ms": 200,
            "delivery.timeout.ms": 120_000,
        }

    def consumer_config(self, group_id: str, *, from_beginning: bool = False) -> dict[str, object]:
        """Build a confluent-kafka consumer config dict.

        Note ``enable.auto.commit=False``: we commit offsets *after* the data is
        durably written downstream. Auto-commit would acknowledge messages we
        have not actually processed - the classic silent data-loss bug.
        """
        return {
            "bootstrap.servers": self.kafka_bootstrap,
            "group.id": group_id,
            "auto.offset.reset": "earliest" if from_beginning else "latest",
            "enable.auto.commit": False,
            "max.poll.interval.ms": 300_000,
            "session.timeout.ms": 45_000,
        }


class StorageSettings(BaseSettings):
    """S3-compatible object storage: MinIO locally, AWS S3 in Phase 9."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    s3_endpoint: str = Field(default="http://localhost:9000")
    s3_access_key: str = Field(default="aegis_dev_access")
    s3_secret_key: str = Field(default="aegis_dev_secret_change_me")
    s3_region: str = Field(default="eu-west-3")
    lake_bucket: str = Field(default="aegis-lakehouse")
    raw_bucket: str = Field(default="aegis-raw")
    quarantine_bucket: str = Field(
        default="aegis-quarantine",
        description="Where records that fail validation go. We never drop bad "
        "data silently - a rejected record is itself a signal worth analysing.",
    )

    @field_validator("s3_secret_key")
    @classmethod
    def _warn_on_default_secret(cls, v: str) -> str:
        """Fail loudly if the development secret ever reaches a real environment."""
        import os

        if v == "aegis_dev_secret_change_me" and os.getenv("AEGIS_ENV") not in (None, "local"):
            raise ValueError(
                "The development S3 secret is still set outside AEGIS_ENV=local. "
                "Set AEGIS_S3_SECRET_KEY to a real secret."
            )
        return v

    @computed_field  # type: ignore[prop-decorator]
    @property
    def s3_properties(self) -> dict[str, str]:
        """Storage properties in the shape pyiceberg and pyarrow both expect."""
        return {
            "s3.endpoint": self.s3_endpoint,
            "s3.access-key-id": self.s3_access_key,
            "s3.secret-access-key": self.s3_secret_key,
            "s3.region": self.s3_region,
            # MinIO requires path-style addressing (bucket in the URL path)
            # because virtual-host style would need real DNS per bucket.
            "s3.path-style-access": "true",
        }


class DatabaseSettings(BaseSettings):
    """Postgres: Iceberg catalog + Dagster storage + serving tables."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    pg_host: str = Field(default="localhost")
    pg_port: int = Field(default=15432)
    pg_user: str = Field(default="aegis")
    pg_password: str = Field(default="aegis_dev_password_change_me")
    pg_database: str = Field(default="aegis")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dsn(self) -> str:
        """SQLAlchemy/psycopg connection string."""
        return (
            f"postgresql+psycopg://{self.pg_user}:{self.pg_password}"
            f"@{self.pg_host}:{self.pg_port}/{self.pg_database}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def psycopg_dsn(self) -> str:
        """Plain libpq connection string (psycopg.connect wants this form)."""
        return (
            f"host={self.pg_host} port={self.pg_port} user={self.pg_user} "
            f"password={self.pg_password} dbname={self.pg_database}"
        )


class HoneypotSettings(BaseSettings):
    """The Cowrie sensor (Phase 7).

    Fill these from ``terraform output aegis_env`` once the VM exists. Until then
    ``honeypot_host`` is empty and the honeypot commands say so plainly.
    """

    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    honeypot_host: str = Field(default="", description="The sensor's public IP.")
    honeypot_port: int = Field(
        default=22222, description="The real SSH port. Port 22 is the honeypot itself."
    )
    honeypot_user: str = Field(
        default="aegis",
        description="A read-only account whose key can run aegis-log-reader and nothing else.",
    )
    honeypot_key_path: str = Field(
        default="~/.ssh/aegis_reader",
        description="Private key for that account. Lives in ~/.ssh, never in the repository.",
    )


class Settings(BaseSettings):
    """The root configuration object. Import ``settings`` from here, nothing else."""

    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    env: Literal["local", "ci", "staging", "prod"] = Field(default="local")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    catalog_name: str = Field(default="aegis")

    data_dir: str = Field(
        default="data",
        description="Where collected files are written. Defaults to ./data, which "
        "is correct for CI and for a clone on any machine. On the development "
        "laptop this repository sits inside OneDrive, so AEGIS_DATA_DIR points "
        "somewhere unsynced: collected telemetry is regenerable, and syncing "
        "gigabytes of it to the cloud is pure cost.",
    )

    kafka: KafkaSettings = Field(default_factory=KafkaSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    honeypot: HoneypotSettings = Field(default_factory=HoneypotSettings)

    @property
    def is_local(self) -> bool:
        return self.env == "local"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton settings object.

    ``lru_cache`` means the environment is read and validated exactly once per
    process, and every module sees the identical object. Tests can reset it
    with ``get_settings.cache_clear()``.
    """
    return Settings()


# Convenience import target: ``from aegis.config import settings``
settings = get_settings()
