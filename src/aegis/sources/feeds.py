"""The four public threat-intelligence feeds AEGIS collects.

Each class below describes ONE source's quirks. Notice how short they are:
retries, timing, counting, logging and error handling all live in BaseCollector,
so a new feed is genuinely about thirty lines.

The four sources, and why each one is here:

  URLhaus    Web addresses currently distributing malware. High volume, changes
             constantly - this is our "does the pipeline keep up?" feed.
  CISA KEV   Vulnerabilities that attackers are PROVEN to be exploiting right
             now. Small, authoritative, slow-moving - our reference data.
  Feodo      Servers that botnets phone home to. Small but high-value: if a
             honeypot attacker's IP appears here, that is a real finding.
  Tor exits  Every current Tor exit node. Pure enrichment: it tells us whether
             an attacker deliberately anonymised themselves.

Together they let us ask the question the whole project exists for: "is this
thing attacking me already known to the wider world?"
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import ClassVar

import httpx

from aegis.sources.base import BaseCollector
from aegis.sources.models import Event, EventType, Source, utc_now


def _parse_utc(value: str, fmt: str) -> datetime:
    """Parse a timestamp string and attach UTC.

    Every feed publishes times in UTC but writes them without a timezone
    marker. If we parsed them as-is we would get naive datetimes, which our
    Event model rejects on purpose. This helper is where that gets fixed, once.
    """
    return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)


# ============================================================================
# URLhaus - malicious URLs
# ============================================================================
class URLhausCollector(BaseCollector):
    """abuse.ch URLhaus: web addresses currently serving malware.

    Format: a CSV file that starts with about nine comment lines beginning with
    '#'. Those comments include the column header, which means a naive
    csv.DictReader would treat a comment as the header row and mangle every
    record. Handling that is exactly the kind of small, real-world detail that
    separates a working collector from a demo.

    ~3 MB and roughly 40,000 rows per fetch, covering the last 30 days.
    """

    source = Source.URLHAUS
    event_type = EventType.IOC_URL
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    is_full_snapshot = False  # a rolling window, not the complete history

    # ClassVar: shared by every instance and never mutated. Without this
    # annotation, ruff flags it as a mutable class attribute (RUF012).
    COLUMNS: ClassVar[list[str]] = [
        "id",
        "dateadded",
        "url",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "urlhaus_link",
        "reporter",
    ]

    def parse(self, response: httpx.Response) -> Iterator[Event]:
        text = response.text
        # Drop the banner comments. We supply our own column names rather than
        # trusting the file's header, so a change in their banner cannot
        # silently shift every column by one.
        data_lines = (line for line in io.StringIO(text) if line and not line.startswith("#"))

        reader = csv.DictReader(data_lines, fieldnames=self.COLUMNS)
        for row in reader:
            if not row.get("url") or not row.get("dateadded"):
                continue  # a blank or truncated line; skip quietly
            try:
                occurred_at = _parse_utc(row["dateadded"], "%Y-%m-%d %H:%M:%S")
            except (ValueError, AttributeError):
                continue  # unparseable date: skip this row, keep the rest

            payload = {
                "urlhaus_id": row.get("id"),
                "url": row.get("url"),
                "url_status": row.get("url_status"),  # online | offline | unknown
                "last_online": row.get("last_online") or None,
                "threat": row.get("threat"),  # e.g. malware_download
                # Tags arrive as a comma-joined string. We split them into a
                # real list here because this is a lossless format change, not
                # a cleaning step - "raw data is sacred" forbids the latter.
                "tags": [t for t in (row.get("tags") or "").split(",") if t],
                "urlhaus_link": row.get("urlhaus_link"),
                "reporter": row.get("reporter"),
            }
            yield self.make_event(payload, occurred_at)


# ============================================================================
# CISA KEV - vulnerabilities under active exploitation
# ============================================================================
class CisaKevCollector(BaseCollector):
    """The US government's catalogue of vulnerabilities being exploited in the wild.

    This is the most valuable feed in the project. There are ~250,000 known CVEs;
    this list has ~1,700. These are the ones attackers actually use. Any
    security dashboard that treats all CVEs equally is useless noise - this feed
    is what turns a vulnerability list into a priority list.

    A slow endpoint (about 25 seconds), which is precisely why BaseCollector
    sets a generous timeout and retries.
    """

    source = Source.CISA_KEV
    event_type = EventType.VULN_CVE
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    timeout_seconds = 120.0
    is_full_snapshot = True  # the complete catalogue, every time

    def parse(self, response: httpx.Response) -> Iterator[Event]:
        catalogue = response.json()
        version = catalogue.get("catalogVersion")

        for vuln in catalogue.get("vulnerabilities", []):
            try:
                occurred_at = _parse_utc(vuln["dateAdded"], "%Y-%m-%d")
            except (KeyError, ValueError):
                occurred_at = utc_now()  # undated entry: fall back to now

            payload = {
                "cve_id": vuln.get("cveID"),
                "vendor": vuln.get("vendorProject"),
                "product": vuln.get("product"),
                "name": vuln.get("vulnerabilityName"),
                "description": vuln.get("shortDescription"),
                "required_action": vuln.get("requiredAction"),
                "date_added": vuln.get("dateAdded"),
                "due_date": vuln.get("dueDate"),
                # A plain "Known"/"Unknown" string in the source. We keep it as
                # published; Silver will turn it into a boolean.
                "ransomware_use": vuln.get("knownRansomwareCampaignUse"),
                "cwes": vuln.get("cwes", []),
                "notes": vuln.get("notes"),
                # Carrying the catalogue version on every record means we can
                # always tell which snapshot a row came from, even months later.
                "catalog_version": version,
            }
            yield self.make_event(payload, occurred_at)


# ============================================================================
# Feodo Tracker - botnet command-and-control servers
# ============================================================================
class FeodoCollector(BaseCollector):
    """abuse.ch Feodo Tracker: IP addresses used as botnet control servers.

    Small (a few dozen entries) but high-signal. If an IP that attacks our
    honeypot also appears here, that is not a bored teenager - it is
    infrastructure belonging to a known malware family such as Emotet or
    Dridex. This feed is what upgrades an observation into a finding.
    """

    source = Source.FEODO
    event_type = EventType.IOC_IP
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    is_full_snapshot = True

    def parse(self, response: httpx.Response) -> Iterator[Event]:
        try:
            entries = response.json()
        except json.JSONDecodeError as exc:
            self.log.error("feodo_bad_json", error=str(exc)[:200])
            return

        if not isinstance(entries, list):
            self.log.error("feodo_unexpected_shape", got=type(entries).__name__)
            return

        for entry in entries:
            try:
                occurred_at = _parse_utc(entry["first_seen"], "%Y-%m-%d %H:%M:%S")
            except (KeyError, ValueError, TypeError):
                occurred_at = utc_now()

            payload = {
                "ip_address": entry.get("ip_address"),
                "port": entry.get("port"),
                "status": entry.get("status"),  # online | offline
                "hostname": entry.get("hostname"),
                "as_number": entry.get("as_number"),  # the network that owns the IP
                "as_name": entry.get("as_name"),
                "country": entry.get("country"),
                "first_seen": entry.get("first_seen"),
                "last_online": entry.get("last_online"),
                "malware": entry.get("malware"),  # Emotet, Dridex, QakBot...
            }
            yield self.make_event(payload, occurred_at)


# ============================================================================
# Tor exit nodes - anonymity network enrichment
# ============================================================================
class TorExitCollector(BaseCollector):
    """The Tor Project's list of current exit-node IP addresses.

    The simplest possible format: plain text, one IP per line, no metadata.

    Why it matters: an attacker arriving from a Tor exit node has *chosen* to
    hide. That is a meaningful behavioural signal, and it is only knowable by
    joining against this list. This is a good example of enrichment data -
    worthless alone, valuable the moment it meets another dataset.

    Note that this list changes constantly, so an IP seen as a Tor exit today
    may not be one next week. Phase 4 handles that with slowly-changing
    dimensions, which record what was true *at the time*.
    """

    source = Source.TOR_EXIT
    event_type = EventType.NETWORK_TOR_EXIT
    url = "https://check.torproject.org/torbulkexitlist"
    is_full_snapshot = True

    def parse(self, response: httpx.Response) -> Iterator[Event]:
        # This feed has no timestamps at all: it is a snapshot of "right now".
        # So observation time IS the event time. We compute it once, outside the
        # loop, so every IP in one fetch shares an identical snapshot timestamp
        # - which is what makes "the exit list as of 14:00" a coherent query.
        observed_at = utc_now()

        for raw_line in response.text.splitlines():
            ip = raw_line.strip()
            if not ip or ip.startswith("#"):
                continue
            yield self.make_event(
                {"ip_address": ip, "observed_at": observed_at.isoformat()},
                observed_at,
            )


# ---------------------------------------------------------------------------
# The registry: how the CLI finds collectors by name.
# Adding a source means adding one line here. Nothing else in the project
# needs to learn about it.
# ---------------------------------------------------------------------------
COLLECTORS: dict[str, type[BaseCollector]] = {
    Source.URLHAUS.value: URLhausCollector,
    Source.CISA_KEV.value: CisaKevCollector,
    Source.FEODO.value: FeodoCollector,
    Source.TOR_EXIT.value: TorExitCollector,
}
