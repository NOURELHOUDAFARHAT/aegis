"""The honeypot collector: Cowrie's JSON log, read incrementally over SSH.

WHY THIS IS NOT A BaseCollector
-------------------------------
Every other source is a file on someone's web server that we download whole.
The honeypot is different in three ways, and each one changes the design:

  1. It is a GROWING file on our own machine, not a published snapshot. We
     must read only what is new since last time, or every run re-sends days
     of events.
  2. It ROTATES. Once a day Cowrie renames `cowrie.json` to
     `cowrie.json.2026-09-14` and starts a fresh `cowrie.json`.
  3. It is reached over SSH, not HTTP.

HOW "ONLY WHAT IS NEW" WORKS
----------------------------
We remember a byte offset per file: "I have read file X up to byte N". Next
run starts at N.

The file is identified by its INODE, not its name. An inode is the number the
filesystem uses for a file; renaming changes the name but keeps the inode. So
when `cowrie.json` becomes `cowrie.json.2026-09-14`, the offset follows it and
nothing is read twice, while the new `cowrie.json` has a new inode and starts
at byte 0. Keying on names would re-read the whole rotated file every day.

Three rules make it safe:

  * Only complete lines are consumed. Cowrie may be halfway through writing
    the last line; that fragment waits for the next run.
  * The offset is saved only AFTER the sink has flushed. Crash in between and
    the same lines are sent again - a duplicate, which Silver removes - but
    never a gap. The same ordering rule as the Bronze writer (ADR 0005).
  * One malformed line is counted and skipped; it never costs the rest.

WHAT RUNS ON THE SENSOR
-----------------------
AEGIS logs in as a user whose SSH key is bound to one forced command,
`aegis-log-reader` (infra/honeypot/aegis-log-reader.sh). It can list the log
files and read bytes from one of them, and nothing else: no shell, no port
forwarding, no writes. A stolen AEGIS key reveals attack logs and cannot touch
the machine.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from aegis.logging import get_logger
from aegis.sources.models import CollectorResult, Event, EventType, Source, utc_now, uuid7
from aegis.sources.sinks import Sink

log = get_logger(__name__)

# The live file and its dated rotations. Anything else in the directory is
# ignored, including anything an attacker might try to get listed.
LOG_FILE_PATTERN = re.compile(r"^cowrie\.json(\.\d{4}-\d{2}-\d{2})?$")

# One read is capped so a large backlog arrives in bounded chunks rather than
# one allocation the size of the file. The reader script enforces the same cap.
MAX_READ_BYTES = 8 * 1024 * 1024


class CowrieSourceError(Exception):
    """The sensor could not be listed or read."""


@dataclass(frozen=True)
class LogFile:
    """One log file on the sensor."""

    file_id: str  # the inode, as text: survives the rename at rotation
    size: int
    name: str


class LogSource(Protocol):
    """Where Cowrie's log files are. Over SSH in production; a folder in tests."""

    def list_files(self) -> list[LogFile]: ...

    def read(self, file_id: str, offset: int) -> bytes: ...


def _chronological(file: LogFile) -> tuple[bool, str]:
    # Dated rotations sort by date; the live file is always newest, so last.
    return (file.name == "cowrie.json", file.name)


def parse_listing(text: str) -> list[LogFile]:
    """Parse `aegis-log-reader list` output: one `<inode> <size> <name>` per line.

    Lines that do not match exactly are dropped rather than trusted.
    """
    files: list[LogFile] = []
    for line in text.splitlines():
        parts = line.strip().split(" ")
        if len(parts) != 3:
            continue
        inode, size, name = parts
        if inode.isdigit() and size.isdigit() and LOG_FILE_PATTERN.match(name):
            files.append(LogFile(file_id=inode, size=int(size), name=name))
    return sorted(files, key=_chronological)


class LocalLogSource:
    """Cowrie logs in a local folder: for tests, or logs copied off a sensor."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    def _files(self) -> Iterator[tuple[LogFile, Path]]:
        for path in self.directory.iterdir():
            if path.is_file() and LOG_FILE_PATTERN.match(path.name):
                stat = path.stat()
                yield LogFile(str(stat.st_ino), stat.st_size, path.name), path

    def list_files(self) -> list[LogFile]:
        return sorted((file for file, _ in self._files()), key=_chronological)

    def read(self, file_id: str, offset: int) -> bytes:
        for file, path in self._files():
            if file.file_id == file_id:
                with path.open("rb") as handle:
                    handle.seek(offset)
                    return handle.read(MAX_READ_BYTES)
        raise CowrieSourceError(f"no log file with id {file_id}")


class SshLogSource:
    """Cowrie logs on the sensor, read through the restricted `aegis` account.

    Uses the system OpenSSH client rather than a Python SSH library: one less
    dependency, and it honours the same keys and known_hosts file you use by
    hand.

    Host keys: the first connection records the sensor's key in AEGIS's own
    known_hosts file (`accept-new`); any later change is refused. Terraform
    cannot know the key before the VM boots, so trust-on-first-use is the
    honest option - and a changed key afterwards is exactly the attack it stops.
    """

    def __init__(
        self,
        host: str,
        *,
        port: int,
        user: str,
        key_path: Path,
        known_hosts: Path,
        timeout_seconds: float = 120.0,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.key_path = Path(key_path)
        self.known_hosts = Path(known_hosts)
        self.timeout_seconds = timeout_seconds

    def _ssh(self, *remote_args: str) -> bytes:
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
        command = [
            "ssh",
            "-i", str(self.key_path),
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "ConnectTimeout=15",
            f"{self.user}@{self.host}",
            *remote_args,
        ]  # fmt: skip
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell; remote args are validated ints/verbs
                command,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CowrieSourceError(f"ssh to {self.host} failed: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()[:300]
            raise CowrieSourceError(f"ssh to {self.host} exited {completed.returncode}: {detail}")
        return completed.stdout

    def list_files(self) -> list[LogFile]:
        return parse_listing(self._ssh("list").decode("utf-8", "replace"))

    def read(self, file_id: str, offset: int) -> bytes:
        if not file_id.isdigit() or offset < 0:
            raise ValueError("file_id must be an inode number and offset non-negative")
        return self._ssh("read", file_id, str(offset))


class CursorStore:
    """The per-file byte offsets, kept in a small JSON file.

    Written atomically - to a temporary file, then renamed over the old one -
    so a crash mid-write leaves the previous cursor intact instead of a
    half-written file that would restart collection from byte 0.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, int]:
        if not self.path.exists():
            return {}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return {str(key): int(value) for key, value in data.items()}

    def save(self, offsets: dict[str, int]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(offsets, sort_keys=True), encoding="utf-8")
        os.replace(temporary, self.path)


def parse_timestamp(value: Any) -> datetime:
    """Cowrie writes ISO 8601 in UTC, ending in Z. Python 3.10 cannot parse the Z."""
    if not isinstance(value, str):
        raise ValueError("timestamp is missing")
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def event_type_for(eventid: str) -> EventType:
    return (
        EventType.SESSION_COMMAND
        if eventid.startswith("cowrie.command.")
        else EventType.SESSION_SSH
    )


def parse_record(line: bytes) -> dict[str, Any] | None:
    """One log line as a Cowrie record, or None if it is not one."""
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(record, dict):
        return None
    eventid = record.get("eventid")
    if not isinstance(eventid, str) or not eventid.startswith("cowrie."):
        return None
    return record


class CowrieNotConfiguredError(Exception):
    """No sensor address is set, so there is nothing to collect from."""


def is_configured() -> bool:
    """True once AEGIS_HONEYPOT_HOST names a sensor."""
    from aegis.config import settings

    return bool(settings.honeypot.honeypot_host)


def from_settings(from_dir: Path | None = None) -> tuple[LogSource, CursorStore]:
    """The configured log source and its cursor. Shared by the CLI and Dagster.

    A local folder gets its own cursor file. Sharing one would let offsets
    recorded for local files be applied to the sensor's files, or the reverse.
    """
    from aegis.config import settings

    state = Path(settings.data_dir) / "state"
    if from_dir is not None:
        return LocalLogSource(from_dir), CursorStore(state / "cowrie_cursor_local.json")

    honeypot = settings.honeypot
    if not honeypot.honeypot_host:
        raise CowrieNotConfiguredError("AEGIS_HONEYPOT_HOST is not set")

    source = SshLogSource(
        honeypot.honeypot_host,
        port=honeypot.honeypot_port,
        user=honeypot.honeypot_user,
        key_path=Path(honeypot.honeypot_key_path).expanduser(),
        known_hosts=state / "honeypot_known_hosts",
    )
    return source, CursorStore(state / "cowrie_cursor.json")


class CowrieCollector:
    """Read new Cowrie events from a sensor and hand them to a sink."""

    source = Source.COWRIE

    def __init__(self, log_source: LogSource, cursor: CursorStore) -> None:
        self.log_source = log_source
        self.cursor = cursor
        self.run_id = uuid7()
        self.log = log.bind(source=self.source.value, run_id=self.run_id[:8])

    def run(self, sink: Sink, *, limit: int | None = None, commit: bool = True) -> CollectorResult:
        """Collect everything new. `commit=False` reads without moving the cursor."""
        started = utc_now()
        fetched = emitted = rejected = consumed_bytes = 0
        status = "success"
        error: str | None = None
        saved: dict[str, int] | None = None

        try:
            previous = self.cursor.load()
            files = self.log_source.list_files()
            offsets = {file.file_id: previous.get(file.file_id, 0) for file in files}

            for file in files:
                if limit is not None and emitted >= limit:
                    break
                position = offsets[file.file_id]
                if file.size < position:
                    # Smaller than where we stopped: not the same file any more
                    # (an inode reused after deletion). Start it from the top.
                    self.log.warning(
                        "cowrie_file_shrank", file=file.name, offset=position, size=file.size
                    )
                    position = 0

                while position < file.size and (limit is None or emitted < limit):
                    chunk = self.log_source.read(file.file_id, position)
                    if not chunk:
                        break
                    end = chunk.rfind(b"\n")
                    if end < 0:
                        if len(chunk) >= MAX_READ_BYTES:
                            # A "line" longer than a whole read can never
                            # complete. Skip it rather than stall forever.
                            rejected += 1
                            position += len(chunk)
                            consumed_bytes += len(chunk)
                            continue
                        break  # the last line is still being written

                    for raw in chunk[: end + 1].splitlines(keepends=True):
                        position += len(raw)
                        consumed_bytes += len(raw)
                        line = raw.strip()
                        if not line:
                            continue
                        fetched += 1
                        record = parse_record(line)
                        if record is None:
                            rejected += 1
                            continue
                        try:
                            event = Event(
                                source=self.source,
                                event_type=event_type_for(record["eventid"]),
                                occurred_at=parse_timestamp(record.get("timestamp")),
                                payload=record,
                                collector_run_id=self.run_id,
                            )
                            sink.write(event)
                            emitted += 1
                        except Exception as exc:
                            rejected += 1
                            self.log.warning("cowrie_event_rejected", error=str(exc)[:200])
                        if limit is not None and emitted >= limit:
                            break

                offsets[file.file_id] = position

            sink.flush()
            # flush() returning is not proof of delivery: a Kafka sink counts
            # messages the broker never acknowledged instead of raising. Moving
            # the cursor past those would lose them for good, so check first.
            if not getattr(sink, "all_delivered", True):
                raise RuntimeError(
                    "the destination did not acknowledge every event; cursor left in place"
                )
            # Only now is it safe to move the cursor: everything up to these
            # offsets has reached the destination.
            if commit:
                self.cursor.save(offsets)
            saved = offsets

        except Exception as exc:
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
            self.log.error("cowrie_collect_failed", error=error)
        finally:
            sink.close()

        result = CollectorResult(
            source=self.source,
            run_id=self.run_id,
            started_at=started,
            finished_at=utc_now(),
            status=status,
            records_fetched=fetched,
            records_emitted=emitted,
            records_rejected=rejected,
            bytes_downloaded=consumed_bytes,
            error_message=error,
            cursor=json.dumps(saved, sort_keys=True) if saved is not None else None,
        )
        self.log.info(
            "cowrie_collect_done",
            status=status,
            emitted=emitted,
            rejected=rejected,
            kb=round(consumed_bytes / 1024, 1),
            committed=commit and saved is not None,
        )
        return result
