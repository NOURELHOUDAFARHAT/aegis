"""Sinks: where a collector's events go.

THE IDEA
--------
A collector's job is to fetch data and produce events. It should have no
opinion about the destination. So we define a small contract - "anything with
a .write() and a .close()" - and collectors only ever talk to that contract.

Today we plug in a sink that writes files. In Phase 2 we plug in one that
writes to Kafka. In tests we plug in one that just counts. The collector code
never changes.

This is dependency inversion, and it is the difference between a pipeline you
can evolve and one you have to rewrite. It is also what makes collectors
testable without any infrastructure running at all.
"""

from __future__ import annotations

import gzip
import json
from datetime import timezone
from pathlib import Path
from typing import IO, Protocol, runtime_checkable

from aegis.logging import get_logger
from aegis.sources.models import Event

log = get_logger(__name__)


@runtime_checkable
class Sink(Protocol):
    """The contract every destination must satisfy.

    A Protocol (rather than a base class to inherit from) means a sink does not
    need to import anything from AEGIS to be a valid sink - it just needs the
    right methods. Python checks the shape, not the family tree.
    """

    def write(self, event: Event) -> None:
        """Accept one event. May buffer; must not lose it."""
        ...

    def flush(self) -> None:
        """Force everything buffered to actually reach the destination."""
        ...

    def close(self) -> None:
        """Flush and release resources. Must be safe to call twice."""
        ...


class CountingSink:
    """Counts events and throws them away. For tests and dry runs.

    Lets you answer "would this collector work?" without writing a single byte
    anywhere - which is exactly what you want when you are still fixing a
    parser at 1 a.m.
    """

    def __init__(self) -> None:
        self.count = 0
        self.events: list[Event] = []
        self.keep_events = False

    def write(self, event: Event) -> None:
        self.count += 1
        if self.keep_events:
            self.events.append(event)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class ConsoleSink:
    """Prints events to the terminal. For learning and debugging.

    Run a collector with this sink to *see* the envelope structure with real
    data in it. Reading a schema teaches you less than seeing one filled in.
    """

    def __init__(self, limit: int | None = 5) -> None:
        self.count = 0
        self.limit = limit

    def write(self, event: Event) -> None:
        self.count += 1
        if self.limit is None or self.count <= self.limit:
            print(json.dumps(json.loads(event.to_json_line()), indent=2)[:1200])
        elif self.count == (self.limit or 0) + 1:
            print(f"... (suppressing further events; {self.count - 1} shown)")

    def flush(self) -> None:
        pass

    def close(self) -> None:
        print(f"\n[ConsoleSink] {self.count} events total")


class JsonlFileSink:
    """Writes events as JSON Lines, one event per line, gzip-compressed.

    WHY JSON LINES?
    A single giant JSON array must be fully parsed before you can read record
    one, and appending to it means rewriting the file. JSON Lines - one
    complete JSON object per line - can be appended to forever, streamed
    without loading it all into memory, and split across machines by simply
    cutting at newlines. It is the standard interchange format for exactly this
    reason, and it is what Kafka topics look like when you dump them.

    WHY GZIP?
    This telemetry is repetitive text and compresses roughly 8-10x. On a laptop
    that is disk space; in the cloud it is directly money, because object
    storage and egress are both billed per byte.

    FILE LAYOUT
        data/raw/source=urlhaus/date=2026-09-05/urlhaus-<run_id>.jsonl.gz

    That `key=value` directory naming is called Hive partitioning. It is not
    decoration: DuckDB, Spark, Athena and Polars all read those directory names
    as columns, so a query filtered to one day physically skips every other
    day's files instead of reading and discarding them. Getting the layout right
    is often a bigger performance win than any query tuning.
    """

    def __init__(self, base_dir: Path, source: str, run_id: str) -> None:
        self.base_dir = Path(base_dir)
        self.source = source
        self.run_id = run_id
        self.count = 0
        # NOTE the type: gzip.open(..., "wt") returns a TEXT wrapper around a
        # GzipFile, not a GzipFile itself. Annotating it as GzipFile compiles
        # and runs fine but is simply untrue - and mypy catches exactly that.
        # This is the kind of quiet inaccuracy that becomes a real bug the day
        # someone writes bytes to it expecting the binary interface.
        self._file: IO[str] | None = None
        self._path: Path | None = None

    def _ensure_open(self, event: Event) -> IO[str]:
        """Open the output file lazily, on the first event.

        Lazily, so that a collector run which fetches nothing does not leave an
        empty file behind. Empty files are noise that every downstream reader
        then has to handle.
        """
        if self._file is not None:
            return self._file

        # Partition by INGESTION date, not event date. Bronze answers "what did
        # we receive and when", so it must be partitioned by when we received
        # it. Silver re-partitions by event time for analysis. Mixing the two up
        # here is a classic and painful mistake.
        day = event.ingested_at.astimezone(timezone.utc).strftime("%Y-%m-%d")
        directory = self.base_dir / f"source={self.source}" / f"date={day}"
        directory.mkdir(parents=True, exist_ok=True)

        self._path = directory / f"{self.source}-{self.run_id}.jsonl.gz"
        self._file = gzip.open(self._path, "wt", encoding="utf-8", compresslevel=6)
        log.debug("sink_opened", path=str(self._path))
        return self._file

    def write(self, event: Event) -> None:
        handle = self._ensure_open(event)
        handle.write(event.to_json_line() + "\n")
        self.count += 1

    def flush(self) -> None:
        if self._file is not None:
            self._file.flush()

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
            size = self._path.stat().st_size if self._path and self._path.exists() else 0
            log.info(
                "sink_closed",
                path=str(self._path),
                events=self.count,
                bytes_on_disk=size,
                bytes_per_event=round(size / self.count, 1) if self.count else 0,
            )

    @property
    def path(self) -> Path | None:
        return self._path
