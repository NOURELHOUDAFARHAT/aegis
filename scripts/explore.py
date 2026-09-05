"""Query the collected data with DuckDB, straight off the compressed files.

Run with:  python scripts/explore.py

WHAT TO NOTICE HERE
-------------------
There is no "load the data into a database" step. DuckDB reads the gzipped
JSON Lines files exactly where they sit, works out the schema by itself, and
runs real SQL over them - including the `source=` and `date=` folder names,
which it exposes as ordinary columns.

That is the lakehouse idea in miniature: **the files ARE the database.** You do
not copy data into a system in order to query it; you point a query engine at
storage. It is why this scales from a laptop to S3 without changing the SQL,
and why the same files can later be read by Spark, Trino or Athena.
"""

from __future__ import annotations

import sys

import duckdb

# Windows terminals default to the legacy cp1252 codepage, which cannot encode
# the box-drawing characters DuckDB uses to draw result tables - printing one
# raises UnicodeEncodeError. Forcing UTF-8 on our own output stream fixes it
# without asking the user to change any system setting. Worth knowing: this is
# the single most common "works on Linux, crashes on Windows" bug in data tools.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from aegis.config import settings

RAW = f"{settings.data_dir}/raw/**/*.jsonl.gz"

QUERIES: list[tuple[str, str]] = [
    (
        "What did we collect, and how fresh is it?",
        # `union_by_name` lets files with different payload shapes sit in one
        # scan. `filename` and `hive_partitioning` turn the folder names into
        # real columns - which is exactly why we named the folders source=/date=.
        f"""
        SELECT source,
               count(*)                                   AS events,
               min(occurred_at)::DATE                     AS oldest_event,
               max(occurred_at)::DATE                     AS newest_event,
               round(avg(epoch(ingested_at - occurred_at) / 86400), 1) AS avg_lag_days
        FROM read_json_auto('{RAW}', union_by_name := true, hive_partitioning := true)
        GROUP BY source
        ORDER BY events DESC
        """,
    ),
    (
        "Which vendors have the most actively-exploited vulnerabilities?",
        f"""
        SELECT payload.vendor          AS vendor,
               count(*)                AS exploited_cves,
               sum(CASE WHEN payload.ransomware_use = 'Known' THEN 1 ELSE 0 END)
                                       AS used_by_ransomware
        FROM read_json_auto('{RAW}', union_by_name := true)
        WHERE source = 'cisa_kev'
        GROUP BY vendor
        ORDER BY exploited_cves DESC
        LIMIT 10
        """,
    ),
    (
        "Are attackers exploiting vulnerabilities faster over time?",
        # A real analytical question. Each KEV entry has a date CISA added it;
        # counting by year shows how the pace of confirmed exploitation moves.
        f"""
        SELECT year(occurred_at)  AS year_added,
               count(*)           AS cves_added,
               sum(CASE WHEN payload.ransomware_use = 'Known' THEN 1 ELSE 0 END)
                                  AS ransomware_linked
        FROM read_json_auto('{RAW}', union_by_name := true)
        WHERE source = 'cisa_kev'
        GROUP BY year_added
        ORDER BY year_added DESC
        LIMIT 8
        """,
    ),
    (
        "Which malware families are hosting payloads, and where?",
        f"""
        WITH expanded AS (
            SELECT unnest(payload.tags) AS tag
            FROM read_json_auto('{RAW}', union_by_name := true)
            WHERE source = 'urlhaus' AND len(payload.tags) > 0
        )
        SELECT tag, count(*) AS malicious_urls
        FROM expanded
        GROUP BY tag
        ORDER BY malicious_urls DESC
        LIMIT 12
        """,
    ),
    (
        "THE JOIN: are any botnet control servers also Tor exit nodes?",
        # This is the whole point of the project - a question NO single feed can
        # answer. It only exists once two sources live in the same place.
        f"""
        WITH c2 AS (
            SELECT DISTINCT payload.ip_address AS ip, payload.malware AS malware
            FROM read_json_auto('{RAW}', union_by_name := true)
            WHERE source = 'feodo'
        ),
        tor AS (
            SELECT DISTINCT payload.ip_address AS ip
            FROM read_json_auto('{RAW}', union_by_name := true)
            WHERE source = 'tor_exit'
        )
        SELECT c2.malware, c2.ip, (tor.ip IS NOT NULL) AS is_tor_exit
        FROM c2 LEFT JOIN tor ON c2.ip = tor.ip
        ORDER BY is_tor_exit DESC, c2.malware
        """,
    ),
]


def main() -> None:
    con = duckdb.connect()

    print(f"\nReading: {RAW}\n")
    for title, sql in QUERIES:
        print("=" * 78)
        print(f"  {title}")
        print("=" * 78)
        try:
            con.sql(sql).show(max_width=110)
        except Exception as exc:
            print(f"  query failed: {str(exc)[:300]}\n")

    print("=" * 78)
    print("  Every answer above came from SQL run directly on .jsonl.gz files.")
    print("  No database was loaded. That is the lakehouse pattern.")
    print("=" * 78)


if __name__ == "__main__":
    main()
