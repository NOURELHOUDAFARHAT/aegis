"""The event envelope: the one shape every record in AEGIS wears.

WHY AN ENVELOPE?
----------------
Our sources are wildly different. URLhaus sends CSV rows about malware links.
CISA sends JSON about vulnerabilities. The honeypot sends SSH session logs.
If each one flowed through the system in its own shape, every downstream piece
of code would need to know about every source - and adding a fifth source would
mean touching ten files.

Instead, every record is wrapped in an identical envelope. The envelope carries
the *metadata* (where did this come from, when did it happen, when did we see
it), and the source's own data rides untouched inside `payload`.

Think of it as postal mail: the addressing on the outside is standardised so
the postal system can route any letter, while the contents inside can be
anything at all.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Source(str, Enum):
    """Every system AEGIS pulls data from.

    An Enum rather than a free string: a typo like "urlhous" becomes an error
    at startup instead of a mysterious empty partition three weeks later.
    """

    URLHAUS = "urlhaus"  # abuse.ch: URLs currently serving malware
    CISA_KEV = "cisa_kev"  # CISA: vulnerabilities known to be exploited
    NVD = "nvd"  # NIST: the full CVE vulnerability database
    TOR_EXIT = "tor_exit"  # The Tor Project: current exit-node addresses
    FEODO = "feodo"  # abuse.ch: botnet command-and-control servers
    COWRIE = "cowrie"  # our own honeypot: live attack sessions


class EventType(str, Enum):
    """What kind of thing a record describes.

    Deliberately separate from Source, because two sources can produce the same
    kind of event. URLhaus and Feodo both emit indicators of compromise; a query
    for "all IOCs" should not have to list every source that might produce one.
    """

    IOC_URL = "ioc.url"  # a malicious web address
    IOC_IP = "ioc.ip"  # a malicious IP address
    VULN_CVE = "vuln.cve"  # a software vulnerability
    NETWORK_TOR_EXIT = "network.tor_exit"  # an IP known to be a Tor exit
    SESSION_SSH = "session.ssh"  # a honeypot login session
    SESSION_COMMAND = "session.command"  # a command typed by an attacker


_uuid7_lock = threading.Lock()
_uuid7_last_ms = 0
_uuid7_counter = 0


def uuid7() -> str:
    """Generate a time-ordered unique ID.

    WHY NOT PLAIN uuid4?
    A uuid4 is completely random. That is fine for uniqueness, but it means
    records written in time order land in random order on disk, which makes
    database indexes fragment and range scans slow.

    A UUID version 7 puts a millisecond timestamp in the leading 48 bits, so
    sorting by ID sorts by time. Layout (RFC 9562):

        [ 48 bits: milliseconds since 1970 ][ 4 bits: version 7 ]
        [ 12 bits: counter ][ 2 bits: variant ][ 62 bits: random ]

    THE SUB-MILLISECOND PROBLEM
    The plain version fills those 12 bits with randomness. That orders IDs
    correctly *across* milliseconds, but two IDs created inside the same
    millisecond come out in random order relative to each other. This code
    generates thousands of events per second, so that case is not theoretical -
    it happens constantly.

    So we use the "monotonic counter" method that RFC 9562 permits: within one
    millisecond, those 12 bits count upward instead of being random. IDs are
    then strictly ordered even when generated in a tight loop. 12 bits gives
    4,096 IDs per millisecond; past that we simply wait for the clock to move
    on, which is a far better failure mode than emitting an out-of-order ID.

    The lock makes this safe when several threads generate IDs at once - which
    they will, the moment a collector goes concurrent.
    """
    global _uuid7_last_ms, _uuid7_counter

    with _uuid7_lock:
        ms = int(time.time() * 1000)

        if ms == _uuid7_last_ms:
            _uuid7_counter += 1
            if _uuid7_counter > 0xFFF:
                # Counter exhausted for this millisecond. Spin until the clock
                # advances rather than wrapping around and breaking ordering.
                while ms <= _uuid7_last_ms:
                    ms = int(time.time() * 1000)
                _uuid7_last_ms = ms
                _uuid7_counter = 0
        else:
            # Clocks can jump backwards (NTP correction). If that happens, keep
            # counting from the last millisecond we used instead of going back
            # in time - monotonic IDs matter more here than exact wall-clock.
            if ms < _uuid7_last_ms:
                ms = _uuid7_last_ms
                _uuid7_counter += 1
            else:
                _uuid7_last_ms = ms
                _uuid7_counter = 0

        counter = _uuid7_counter

    rand = uuid.uuid4().int  # 122 random bits, for the tail

    value = (ms & 0xFFFFFFFFFFFF) << 80  # 48-bit timestamp, top of the ID
    value |= 0x7 << 76  # version nibble = 7
    value |= (counter & 0xFFF) << 64  # 12-bit monotonic counter
    value |= 0b10 << 62  # RFC 9562 variant bits
    value |= rand & 0x3FFFFFFFFFFFFFFF  # 62 random bits
    return str(uuid.UUID(int=value))


def hostname() -> str:
    """The name of the machine running this code, on Windows or Linux.

    Written as a plain function rather than an inline lambda because the
    Windows/Linux difference is real: os.uname() does not exist on Windows,
    and COMPUTERNAME does not exist on Linux.
    """
    name = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME")
    if name:
        return name
    try:
        import socket

        return socket.gethostname()
    except Exception:
        return "unknown"


def utc_now() -> datetime:
    """The current time, always timezone-aware and always UTC.

    Never use datetime.now() in a pipeline. It returns a *naive* datetime with
    no timezone attached, so the same instant is recorded differently depending
    on which machine ran the job. That silently corrupts any time-based join or
    partition. This helper exists so the mistake is impossible to make.
    """
    return datetime.now(timezone.utc)


class Event(BaseModel):
    """One record travelling through AEGIS, from collection to Bronze."""

    model_config = {"frozen": True}  # immutable: nobody edits an event in flight

    event_id: str = Field(
        default_factory=uuid7,
        description="Unique, time-ordered. This is the key we deduplicate on.",
    )
    source: Source
    event_type: EventType
    schema_version: int = Field(default=1, description="Bumped when payload shape changes")

    occurred_at: datetime = Field(
        description="When the thing happened in the REAL WORLD. Drives correctness: "
        "which day does this attack belong to?"
    )
    ingested_at: datetime = Field(
        default_factory=utc_now,
        description="When AEGIS first saw it. Drives OPERATIONS: is the pipeline "
        "falling behind? Keeping these two apart is the single most important "
        "modelling decision in the system.",
    )

    payload: dict[str, Any] = Field(
        description="The source's own data, completely untouched. We never clean "
        "data before storing it - see docs/ARCHITECTURE.md, 'raw data is sacred'."
    )

    collector_run_id: str | None = Field(
        default=None,
        description="Links this event to the collector run that produced it, so a "
        "bad batch can be traced back and replayed.",
    )
    collector_host: str = Field(
        default_factory=hostname,
        description="Which machine collected it. Matters the moment more than one does.",
    )

    @field_validator("occurred_at", "ingested_at")
    @classmethod
    def _must_be_timezone_aware(cls, v: datetime) -> datetime:
        """Reject naive datetimes loudly rather than guessing a timezone."""
        if v.tzinfo is None:
            raise ValueError(
                "datetime must be timezone-aware. Use aegis.sources.models.utc_now(), "
                "never datetime.now()."
            )
        return v.astimezone(timezone.utc)

    @property
    def content_hash(self) -> str:
        """A fingerprint of the payload, used to detect true duplicates.

        Why we need this AS WELL AS event_id: if we re-run the URLhaus collector
        an hour from now, the same malware URL comes back. It is a genuinely new
        observation (new event_id, new ingested_at), but the *content* is
        identical. Hashing the payload lets Silver tell "we saw this again" apart
        from "something changed".

        sort_keys=True is essential: without it, two identical dictionaries can
        serialise differently and produce different hashes.
        """
        canonical = json.dumps(self.payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def lag_seconds(self) -> float:
        """How stale this event was when we collected it.

        This is our core freshness metric. If the average lag on a feed starts
        climbing, either the source stopped publishing or our collector is
        falling behind - and we want to know which, automatically.
        """
        return (self.ingested_at - self.occurred_at).total_seconds()

    def to_json_line(self) -> str:
        """Serialise to a single JSON line (the format Kafka and JSONL both want)."""
        data = self.model_dump(mode="json")
        data["_content_hash"] = self.content_hash
        return json.dumps(data, separators=(",", ":"), default=str)


class CollectorResult(BaseModel):
    """The report a collector returns after one run.

    A collector that just prints and returns None cannot be scheduled,
    monitored or alerted on. Returning a structured result is what lets Dagster
    (Phase 5) decide whether the run succeeded and whether to alert.
    """

    source: Source
    run_id: str
    started_at: datetime
    finished_at: datetime
    status: str  # success | failed | partial
    records_fetched: int = 0  # how many the source gave us
    records_emitted: int = 0  # how many passed validation and were sent
    records_rejected: int = 0  # how many failed validation (quarantined)
    bytes_downloaded: int = 0
    error_message: str | None = None
    cursor: str | None = None  # where to resume next time (ETag, max date...)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def rejection_rate(self) -> float:
        """Share of records that failed validation.

        Worth alerting on: a sudden jump usually means the source silently
        changed its format - which is the most common way a working pipeline
        quietly starts producing garbage.
        """
        if self.records_fetched == 0:
            return 0.0
        return self.records_rejected / self.records_fetched
