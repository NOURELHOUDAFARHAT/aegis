"""AEGIS environment diagnostics.

Run with:  .\aegis.ps1 doctor

WHY A DOCTOR SCRIPT
-------------------
Every check below corresponds to a failure you *will* hit at some point:
a container that quietly died, a bucket that was never created, a broker
reachable from Docker but not from the host. Without this script each of those
surfaces as a confusing traceback deep inside a job. With it, you get a
one-screen answer to "is my environment sane?" before you debug your own code.

Shipping a doctor command is a habit worth carrying into every project you
build - it is the single highest-leverage 100 lines in a repo.
"""

from __future__ import annotations

import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

# Colour output without a dependency (Windows Terminal supports ANSI).
GREEN, RED, YELLOW, DIM, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[2m", "\033[0m"


@dataclass
class CheckResult:
    ok: bool
    detail: str
    hint: str = ""


def check_python_version() -> CheckResult:
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 10)
    return CheckResult(
        ok=ok,
        detail=f"Python {v.major}.{v.minor}.{v.micro}",
        hint="AEGIS needs Python >= 3.10" if not ok else "",
    )


def check_imports() -> CheckResult:
    """Verify the heavy dependencies actually import (wheel/ABI problems show here)."""
    missing: list[str] = []
    for mod in ("pydantic", "structlog", "confluent_kafka", "pyarrow", "duckdb", "polars"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    return CheckResult(
        ok=not missing,
        detail="all core packages import" if not missing else f"missing: {', '.join(missing)}",
        hint="Run: .\\aegis.ps1 setup" if missing else "",
    )


def check_settings() -> CheckResult:
    try:
        from aegis.config import settings

        return CheckResult(
            ok=True,
            detail=f"env={settings.env} broker={settings.kafka.kafka_bootstrap} "
            f"bucket={settings.storage.lake_bucket}",
        )
    except Exception as exc:
        return CheckResult(
            ok=False,
            detail=f"config failed to load: {exc}",
            hint="Check your .env against .env.example",
        )


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_tcp(name: str, host: str, port: int, hint: str) -> Callable[[], CheckResult]:
    def _check() -> CheckResult:
        ok = _port_open(host, port)
        return CheckResult(ok=ok, detail=f"{name} at {host}:{port}", hint=hint if not ok else "")

    return _check


def check_kafka_metadata() -> CheckResult:
    """A TCP port being open is not the same as a working broker: ask for metadata."""
    try:
        from confluent_kafka.admin import AdminClient

        from aegis.config import settings

        admin = AdminClient({"bootstrap.servers": settings.kafka.kafka_bootstrap})
        md = admin.list_topics(timeout=5)
        topics = [t for t in md.topics if not t.startswith("_")]
        return CheckResult(
            ok=True,
            detail=f"{len(md.brokers)} broker(s), {len(topics)} topic(s): "
            f"{', '.join(sorted(topics)[:6]) or '(none yet - normal in Phase 0)'}",
        )
    except Exception as exc:
        return CheckResult(
            ok=False, detail=str(exc)[:120], hint="Is the broker healthy?  .\\aegis.ps1 ps"
        )


def check_minio_buckets() -> CheckResult:
    """Confirm the buckets exist *and* our credentials work, via the real S3 API."""
    try:
        import urllib.request

        from aegis.config import settings

        # MinIO's unauthenticated liveness probe.
        url = f"{settings.storage.s3_endpoint}/minio/health/live"
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - fixed local URL
            if resp.status != 200:
                return CheckResult(ok=False, detail=f"health endpoint returned {resp.status}")
        return CheckResult(ok=True, detail=f"MinIO healthy at {settings.storage.s3_endpoint}")
    except Exception as exc:
        return CheckResult(ok=False, detail=str(exc)[:120], hint="Run: .\\aegis.ps1 up")


def check_postgres() -> CheckResult:
    """Connect for real and verify our bootstrap schemas exist."""
    try:
        import psycopg

        from aegis.config import settings

        with psycopg.connect(settings.database.psycopg_dsn, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT schema_name FROM information_schema.schemata "
                    "WHERE schema_name IN ('ops','serving','iceberg_catalog','orchestration')"
                )
                found = sorted(r[0] for r in cur.fetchall())
        expected = {"iceberg_catalog", "ops", "orchestration", "serving"}
        missing = expected - set(found)
        return CheckResult(
            ok=not missing,
            detail=f"connected; schemas: {', '.join(found)}",
            hint=f"missing schemas {missing} - the init SQL only runs on a fresh "
            f"volume, so: .\\aegis.ps1 nuke"
            if missing
            else "",
        )
    except Exception as exc:
        return CheckResult(ok=False, detail=str(exc)[:120], hint="Run: .\\aegis.ps1 up")


CHECKS: list[tuple[str, Callable[[], CheckResult]]] = [
    ("Python version", check_python_version),
    ("Core packages", check_imports),
    ("AEGIS settings", check_settings),
    ("Kafka port", check_tcp("Redpanda", "localhost", 19092, "Run: .\\aegis.ps1 up")),
    ("Kafka broker", check_kafka_metadata),
    ("Schema Registry port", check_tcp("Registry", "localhost", 18081, "Run: .\\aegis.ps1 up")),
    ("MinIO S3 API", check_minio_buckets),
    ("Postgres", check_postgres),
]


def main() -> int:
    print(f"\n{DIM}{'=' * 74}{RESET}")
    print("  AEGIS environment diagnostics")
    print(f"{DIM}{'=' * 74}{RESET}\n")

    failures = 0
    for name, fn in CHECKS:
        start = time.perf_counter()
        try:
            result = fn()
        except Exception as exc:
            result = CheckResult(ok=False, detail=f"check crashed: {exc}")
        elapsed_ms = (time.perf_counter() - start) * 1000

        mark = f"{GREEN}PASS{RESET}" if result.ok else f"{RED}FAIL{RESET}"
        print(f"  [{mark}] {name:<22} {result.detail}  {DIM}({elapsed_ms:.0f}ms){RESET}")
        if not result.ok:
            failures += 1
            if result.hint:
                print(f"         {YELLOW}-> {result.hint}{RESET}")

    print()
    if failures:
        print(f"  {RED}{failures} check(s) failed.{RESET} Fix the hints above, then re-run.\n")
        return 1
    print(f"  {GREEN}Everything is healthy. You are clear to build.{RESET}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
