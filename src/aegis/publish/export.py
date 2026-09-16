"""Export the warehouse to the JSON files the public dashboard reads.

AN ALLOW LIST, NOT A BLOCK LIST
-------------------------------
Everything written here ends up on a public website. So nothing is exported by
default: each file is built from an explicit SELECT of named columns, and no
other table or column in the warehouse can reach the site. A new column added
to a Silver model stays private until someone deliberately adds it here.

TWO KINDS OF DATA, TWO RULES
----------------------------
  * Threat-feed data (CISA KEV, URLhaus, Feodo, Tor) is published as it is. Its
    sources published it for sharing; that is what indicators are for.
  * Honeypot data is collected first-hand, and attacker IP addresses are
    personal data. It is exported only with a pseudonymisation key: addresses
    become keyed pseudonyms, addresses inside free text (commands, reasons)
    are redacted, and a final scan refuses the whole export if anything shaped
    like an IP address survives.

ALL OR NOTHING
--------------
Every payload is built before any file is written. A failure half-way - a
missing key, a failed scan - leaves the previous files untouched, so the site
never shows new vendor numbers beside stale honeypot numbers.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import duckdb

from aegis.governance.pseudonymise import find_ipv4, pseudonymise_ip, redact_ips
from aegis.logging import get_logger

log = get_logger(__name__)

SCHEMA_VERSION = 1
TOP_N = 25


class PublishError(Exception):
    """The export would publish something it must not, or cannot be built."""


def _exists(con: duckdb.DuckDBPyConnection, schema: str, table: str) -> bool:
    row = con.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = ?",
        [schema, table],
    ).fetchone()
    return bool(row and row[0])


def _rows(con: duckdb.DuckDBPyConnection, sql: str) -> list[dict[str, Any]]:
    cursor = con.execute(sql)
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def _scalar(con: duckdb.DuckDBPyConnection, sql: str) -> Any:
    row = con.execute(sql).fetchone()
    return row[0] if row else None


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    raise TypeError(f"cannot publish a value of type {type(value).__name__}")


# ---------------------------------------------------------------------------
# One builder per file
# ---------------------------------------------------------------------------


def build_counts(con: duckdb.DuckDBPyConnection) -> dict[str, int | None]:
    counts: dict[str, int | None] = dict.fromkeys(
        (
            "exploited_cves", "ransomware_linked_cves", "vendors", "malware_urls",
            "online_malware_urls", "malware_hosts", "c2_servers", "tor_exit_nodes",
            "url_campaigns", "clustered_servers", "honeypot_sessions",
        )
    )  # fmt: skip
    if _exists(con, "silver", "kev_vulnerabilities"):
        row = con.execute(
            "SELECT count(*), count(*) FILTER (WHERE is_ransomware_linked), count(DISTINCT vendor) "
            "FROM silver.kev_vulnerabilities"
        ).fetchone()
        if row:
            counts["exploited_cves"], counts["ransomware_linked_cves"], counts["vendors"] = row
    if _exists(con, "silver", "urlhaus_urls"):
        row = con.execute(
            "SELECT count(*), count(*) FILTER (WHERE is_online), count(DISTINCT host) "
            "FROM silver.urlhaus_urls"
        ).fetchone()
        if row:
            counts["malware_urls"], counts["online_malware_urls"], counts["malware_hosts"] = row
    if _exists(con, "silver", "feodo_c2_servers"):
        counts["c2_servers"] = _scalar(con, "SELECT count(*) FROM silver.feodo_c2_servers")
    if _exists(con, "silver", "tor_exit_nodes"):
        counts["tor_exit_nodes"] = _scalar(
            con, "SELECT count(*) FROM silver.tor_exit_nodes WHERE is_current_exit"
        )
    if _exists(con, "ml", "url_campaigns"):
        counts["url_campaigns"] = _scalar(con, "SELECT count(*) FROM ml.url_campaigns")
    if _exists(con, "ml", "url_campaign_servers"):
        counts["clustered_servers"] = _scalar(con, "SELECT count(*) FROM ml.url_campaign_servers")
    if _exists(con, "silver", "honeypot_sessions"):
        counts["honeypot_sessions"] = _scalar(con, "SELECT count(*) FROM silver.honeypot_sessions")
    return counts


def build_vendors(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    if not _exists(con, "gold", "vendor_exploitation"):
        return []
    return _rows(
        con,
        "SELECT vendor, exploited_cves, ransomware_linked_cves, ransomware_share_pct, "
        "products_affected, most_recently_added "
        "FROM gold.vendor_exploitation ORDER BY exploited_cves DESC, vendor LIMIT 25",
    )


def build_malware_tags(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    if not _exists(con, "gold", "malware_url_tags"):
        return []
    return _rows(
        con,
        "SELECT tag, urls, online_urls, distinct_hosts, urls_per_host "
        "FROM gold.malware_url_tags ORDER BY urls DESC, tag LIMIT 25",
    )


def build_c2(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    if not _exists(con, "gold", "c2_infrastructure"):
        return []
    return _rows(
        con,
        "SELECT ip_address, malware, is_online, port, as_name, country, hosting_type, "
        "was_ever_tor_exit, is_current_tor_exit, first_seen, last_online "
        "FROM gold.c2_infrastructure ORDER BY is_online DESC, malware, ip_address",
    )


def build_campaigns(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    if not _exists(con, "ml", "url_campaigns"):
        return []
    return _rows(
        con,
        "SELECT campaign_id, servers, urls, online_urls, distinct_subnets, top_tags, top_paths "
        "FROM ml.url_campaigns ORDER BY servers DESC, campaign_id LIMIT 20",
    )


def build_watchlist(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    if not _exists(con, "ml", "kev_ransomware_scores"):
        return []
    return _rows(
        con,
        "SELECT watchlist_rank, cve_id, vendor, product, vulnerability_name, date_added, "
        "ransomware_probability FROM ml.kev_ransomware_scores "
        "WHERE on_watchlist ORDER BY watchlist_rank LIMIT 25",
    )


def build_honeypot(con: duckdb.DuckDBPyConnection, key: bytes | None) -> dict[str, Any]:
    """Aggregates and flagged sessions, pseudonymised. Refuses to run without a key."""
    if not _exists(con, "silver", "honeypot_sessions"):
        return {"available": False}
    sessions = int(_scalar(con, "SELECT count(*) FROM silver.honeypot_sessions") or 0)
    if sessions == 0:
        return {"available": False}
    if key is None:
        raise PublishError(
            "the honeypot has sessions but AEGIS_PSEUDONYMISATION_KEY is not set; "
            "attacker addresses cannot be published without it"
        )

    overview = _rows(
        con,
        "SELECT count(*) AS sessions, min(started_at) AS first_session, "
        "max(started_at) AS last_session, "
        "count(*) FILTER (WHERE login_succeeded) AS logged_in, "
        "count(*) FILTER (WHERE commands_run > 0) AS ran_commands, "
        "count(*) FILTER (WHERE downloads > 0) AS downloaded, "
        "count(DISTINCT src_ip) AS distinct_sources "
        "FROM silver.honeypot_sessions",
    )[0]
    daily = _rows(
        con,
        "SELECT CAST(date_trunc('day', started_at) AS DATE) AS day, count(*) AS sessions "
        "FROM silver.honeypot_sessions GROUP BY 1 ORDER BY 1 DESC LIMIT 30",
    )
    protocols = _rows(
        con,
        "SELECT coalesce(protocol, 'unknown') AS protocol, count(*) AS sessions "
        "FROM silver.honeypot_sessions GROUP BY 1 ORDER BY 2 DESC",
    )
    usernames = _rows(
        con,
        "SELECT username AS value, count(*) AS attempts FROM silver.honeypot_events "
        "WHERE eventid IN ('cowrie.login.failed', 'cowrie.login.success') AND username IS NOT NULL "
        "GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 15",
    )
    passwords = _rows(
        con,
        "SELECT password AS value, count(*) AS attempts FROM silver.honeypot_events "
        "WHERE eventid IN ('cowrie.login.failed', 'cowrie.login.success') AND password IS NOT NULL "
        "GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 15",
    )
    commands = _rows(
        con,
        "SELECT first_command AS value, count(*) AS sessions FROM silver.honeypot_sessions "
        "WHERE first_command IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10",
    )
    for row in (*usernames, *passwords, *commands):
        row["value"] = redact_ips(row["value"])

    flagged: list[dict[str, Any]] = []
    if _exists(con, "ml", "honeypot_session_anomalies"):
        for row in _rows(
            con,
            "SELECT anomaly_rank, src_ip, started_at, protocol, reasons, commands_run, downloads "
            "FROM ml.honeypot_session_anomalies WHERE is_flagged ORDER BY anomaly_rank LIMIT 20",
        ):
            row["source"] = pseudonymise_ip(row.pop("src_ip"), key)
            row["reasons"] = redact_ips(row["reasons"])
            flagged.append(row)

    return {
        "available": True,
        "overview": overview,
        "daily": daily,
        "protocols": protocols,
        "top_usernames": usernames,
        "top_passwords": passwords,
        "top_first_commands": commands,
        "flagged_sessions": flagged,
    }


# ---------------------------------------------------------------------------
# Model evaluation numbers, from MLflow
# ---------------------------------------------------------------------------

_MODEL_METRICS = {
    "ransomware": (
        "aegis-kev-ransomware",
        ("pr_auc_time_split", "roc_auc_time_split", "test_prevalence", "lift_over_chance"),
    ),
    "campaigns": ("aegis-url-campaigns", ("subnet_lift", "coverage", "campaigns")),
}


def load_model_metrics() -> dict[str, dict[str, float]]:
    """The latest finished run's metrics per model. Empty if MLflow is not available.

    The dashboard shows each model's honest evaluation beside its output. If the
    numbers cannot be read, the page says so rather than the export failing.
    """
    try:
        from mlflow.tracking import MlflowClient

        from aegis.ml.tracking import tracking_uri
    except ImportError:
        return {}

    client = MlflowClient(tracking_uri=tracking_uri())
    metrics: dict[str, dict[str, float]] = {}
    for model, (experiment_name, keys) in _MODEL_METRICS.items():
        try:
            experiment = client.get_experiment_by_name(experiment_name)
            if experiment is None:
                continue
            runs = client.search_runs(
                [experiment.experiment_id],
                filter_string="attributes.status = 'FINISHED'",
                order_by=["attributes.start_time DESC"],
                max_results=1,
            )
        except Exception as exc:
            log.warning("model_metrics_unavailable", model=model, error=str(exc)[:200])
            continue
        if runs:
            recorded = runs[0].data.metrics
            metrics[model] = {k: float(recorded[k]) for k in keys if k in recorded}
    return metrics


# ---------------------------------------------------------------------------
# The export
# ---------------------------------------------------------------------------


@dataclass
class ExportResult:
    files: dict[str, int]  # file name -> bytes written
    honeypot_available: bool


def export(
    con: duckdb.DuckDBPyConnection,
    out_dir: Path,
    *,
    key: bytes | None = None,
    model_metrics: dict[str, dict[str, float]] | None = None,
    run_url: str | None = None,
    commit: str | None = None,
    now: datetime | None = None,
) -> ExportResult:
    """Build every payload, verify the honeypot one, then write them all."""
    honeypot = build_honeypot(con, key)
    honeypot_text = json.dumps(honeypot, default=_json_default)
    leaked = find_ipv4(honeypot_text)
    if leaked:
        raise PublishError(
            f"the honeypot export still contains {len(leaked)} IP-shaped value(s); refusing to publish"
        )

    payloads: dict[str, Any] = {
        "summary": {
            "schema_version": SCHEMA_VERSION,
            "generated_at": (now or datetime.now(timezone.utc)).isoformat(),
            "run_url": run_url,
            "commit": commit,
            "counts": build_counts(con),
            "models": model_metrics or {},
        },
        "vendors": build_vendors(con),
        "malware_tags": build_malware_tags(con),
        "c2": build_c2(con),
        "campaigns": build_campaigns(con),
        "watchlist": build_watchlist(con),
        "honeypot": honeypot,
    }
    encoded = {
        name: json.dumps(payload, default=_json_default, ensure_ascii=False, separators=(",", ":"))
        for name, payload in payloads.items()
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, int] = {}
    for name, text in encoded.items():
        target = out_dir / f"{name}.json"
        temporary = target.with_suffix(".json.tmp")
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, target)
        written[target.name] = len(text.encode("utf-8"))

    log.info("publish_export_done", files=len(written), honeypot=honeypot["available"])
    return ExportResult(files=written, honeypot_available=bool(honeypot["available"]))
