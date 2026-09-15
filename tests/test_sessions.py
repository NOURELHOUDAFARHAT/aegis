"""Tests for honeypot session anomaly detection.

Every session here is SYNTHETIC: 400 repetitive brute-force bots and five
planted sessions that behave nothing like them. Addresses are from 100.64.0.0/10
(RFC 6598), never a public attacker.

Recovering planted anomalies proves the machinery - features, scoring, ranking,
explanations, the table write. It does not show the flags are useful on real
attacks; that needs the sensor's real sessions.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import duckdb
import numpy as np
import pytest

from aegis.ml import sessions

START = datetime(2026, 9, 14, 0, 0, tzinfo=timezone.utc)
PLANTED = {f"planted-{i}" for i in range(5)}

COLUMNS = (
    "session_id", "src_ip", "started_at", "protocol", "login_attempts", "distinct_usernames",
    "distinct_passwords", "commands_run", "downloads", "duration_seconds", "login_succeeded",
    "hassh", "first_command", "is_closed",
)  # fmt: skip


def bot_session(i: int, rng: np.random.Generator) -> dict[str, Any]:
    attempts = int(rng.poisson(3)) + 1
    return {
        "session_id": f"bot-{i}",
        "src_ip": f"100.64.{i // 250}.{i % 250 + 1}",
        "started_at": START + timedelta(minutes=i),
        "protocol": "telnet" if rng.random() < 0.2 else "ssh",
        "login_attempts": attempts,
        "distinct_usernames": int(rng.integers(1, 3)),
        "distinct_passwords": attempts,
        "commands_run": 0,
        "downloads": 0,
        "duration_seconds": float(rng.uniform(2, 10)),
        "login_succeeded": False,
        "hassh": f"common-client-{int(rng.integers(0, 3))}",
        "first_command": None,
        "is_closed": True,
    }


def planted_session(i: int) -> dict[str, Any]:
    return {
        "session_id": f"planted-{i}",
        "src_ip": f"100.127.0.{i + 1}",
        "started_at": START + timedelta(hours=10, minutes=i),
        "protocol": "ssh",
        "login_attempts": 1,
        "distinct_usernames": 1,
        "distinct_passwords": 1,
        "commands_run": 25 + i,
        "downloads": 3,
        "duration_seconds": 600.0 + i,
        "login_succeeded": True,
        "hassh": f"rare-client-{i}",
        "first_command": f"cat /proc/cpuinfo #{i}",
        "is_closed": True,
    }


def warehouse(rows: list[dict[str, Any]]) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute("CREATE SCHEMA silver")
    con.execute(
        """
        CREATE TABLE silver.honeypot_sessions (
            session_id VARCHAR, src_ip VARCHAR, started_at TIMESTAMPTZ, protocol VARCHAR,
            login_attempts BIGINT, distinct_usernames BIGINT, distinct_passwords BIGINT,
            commands_run BIGINT, downloads BIGINT, duration_seconds DOUBLE,
            login_succeeded BOOLEAN, hassh VARCHAR, first_command VARCHAR, is_closed BOOLEAN
        )
        """
    )
    con.executemany(
        "INSERT INTO silver.honeypot_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [[row[c] for c in COLUMNS] for row in rows],
    )
    return con


@pytest.fixture(scope="module")
def scored() -> tuple[duckdb.DuckDBPyConnection, sessions.SessionRun]:
    rng = np.random.default_rng(7)
    rows = [bot_session(i, rng) for i in range(400)] + [planted_session(i) for i in range(5)]
    # Still open, and extreme: must not be scored until its numbers are final.
    rows.append({**planted_session(99), "session_id": "still-open", "is_closed": False})
    con = warehouse(rows)
    return con, sessions.run(con)


class TestScoring:
    def test_planted_sessions_rank_first(self, scored: Any) -> None:
        con, result = scored
        assert result.status == "scored"
        top = {
            r[0]
            for r in con.execute(
                "SELECT session_id FROM ml.honeypot_session_anomalies WHERE anomaly_rank <= 5"
            ).fetchall()
        }
        assert top == PLANTED

    def test_top_one_percent_is_flagged(self, scored: Any) -> None:
        con, result = scored
        flagged = {
            r[0]
            for r in con.execute(
                "SELECT session_id FROM ml.honeypot_session_anomalies WHERE is_flagged"
            ).fetchall()
        }
        assert PLANTED <= flagged
        assert result.flagged == len(flagged) <= 8  # about 1% of 405, allowing for ties

    def test_flagged_sessions_say_why(self, scored: Any) -> None:
        con, _ = scored
        reasons = con.execute(
            "SELECT reasons FROM ml.honeypot_session_anomalies WHERE session_id = 'planted-0'"
        ).fetchone()
        assert reasons is not None and reasons[0]
        assert "(typical" in reasons[0] or "rare" in reasons[0] or "only" in reasons[0]

    def test_unflagged_sessions_carry_no_reasons(self, scored: Any) -> None:
        con, _ = scored
        assert con.execute(
            "SELECT count(*) FROM ml.honeypot_session_anomalies WHERE NOT is_flagged AND reasons IS NOT NULL"
        ).fetchone() == (0,)

    def test_open_sessions_are_not_scored(self, scored: Any) -> None:
        con, result = scored
        assert result.sessions == 405
        assert con.execute(
            "SELECT count(*) FROM ml.honeypot_session_anomalies WHERE session_id = 'still-open'"
        ).fetchone() == (0,)

    def test_ranking_survives_a_change_of_seed(self, scored: Any) -> None:
        con, _ = scored
        rows = sessions.load_sessions(con)
        matrix = sessions.build_features(rows).matrix
        assert sessions.stability(matrix, k=5) >= 0.9


class TestRefusals:
    def test_too_few_sessions_writes_nothing(self) -> None:
        rng = np.random.default_rng(1)
        con = warehouse([bot_session(i, rng) for i in range(50)])
        result = sessions.run(con)
        assert result.status == "insufficient_data"
        assert result.sessions == 50
        assert con.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'ml'"
        ).fetchone() == (0,)

    def test_no_silver_table_yet_is_insufficient_not_an_error(self) -> None:
        result = sessions.run(duckdb.connect())
        assert (result.status, result.sessions) == ("insufficient_data", 0)


class TestFeatures:
    def test_rarity_is_the_share_of_sessions_with_that_value(self) -> None:
        rows = [{"hassh": "a"}, {"hassh": "a"}, {"hassh": "b"}]
        features = sessions.build_features(rows)
        assert np.allclose(features.raw["hassh"], [2 / 3, 2 / 3, 1 / 3])

    def test_missing_values_form_their_own_category(self) -> None:
        rows = [{"first_command": None}, {"first_command": None}, {"first_command": "ls"}]
        features = sessions.build_features(rows)
        assert np.allclose(features.raw["first_command"], [2 / 3, 2 / 3, 1 / 3])
