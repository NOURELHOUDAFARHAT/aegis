"""The shared skeleton every collector is built on.

WHAT A COLLECTOR IS
-------------------
A collector is a small program that does three things, in order:

    1. FETCH  - download data from one source, over the network
    2. PARSE  - turn that data into Event objects
    3. EMIT   - hand each Event to a sink

Everything that is *identical* across sources - retrying a failed download,
timing the run, counting rejected records, remembering where we stopped last
time, writing the audit row - lives in this file. Everything that is *specific*
to one source lives in that source's own small file.

That split is the whole point. Adding a fifth feed should mean writing thirty
lines describing that feed's quirks, not re-implementing retry logic for the
fifth time. Each duplicate implementation is a place where the behaviour can
silently drift apart.
"""

from __future__ import annotations

import abc
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from aegis.logging import get_logger
from aegis.sources.models import (
    CollectorResult,
    Event,
    EventType,
    Source,
    utc_now,
    uuid7,
)
from aegis.sources.sinks import Sink

log = get_logger(__name__)

# We identify ourselves honestly to every service we call. Some feeds block
# unlabelled clients, and more importantly: sending real contact details is
# basic courtesy when consuming a free public service. If our collector ever
# misbehaves, the operator can reach us instead of just banning us.
USER_AGENT = (
    "AEGIS-ThreatLakehouse/0.1 (research project; +https://nourelhouda-farhat.netlify.app/)"
)


class CollectorError(Exception):
    """A collector failed in a way worth reporting rather than crashing on."""


class BaseCollector(abc.ABC):
    """Subclass this to add a new data source.

    A subclass must declare four things:

        source       - which Source enum member it is
        event_type   - what kind of event it produces
        url          - where to download from
        parse()      - how to turn the raw response into Events

    Everything else is inherited.
    """

    source: Source
    event_type: EventType
    url: str

    # How long to wait for the whole request. Feeds are sometimes slow (CISA's
    # catalogue took 25 seconds in testing), so this is generous - but it is
    # always SET. A request with no timeout can hang a scheduled job forever,
    # which is one of the most common ways a pipeline silently stops running.
    timeout_seconds: float = 90.0

    # Some sources publish a full snapshot every time (the whole Tor exit list),
    # others publish only what is new. This flag documents which, because it
    # changes how Silver must deduplicate downstream.
    is_full_snapshot: bool = True

    def __init__(self) -> None:
        self.run_id = uuid7()
        self.log = log.bind(source=self.source.value, run_id=self.run_id[:8])

    # ------------------------------------------------------------------ fetch

    @retry(
        # Retry only on things that might succeed if we try again: network
        # errors, timeouts, and HTTP 5xx. We deliberately do NOT retry a 404 or
        # a 401 - those will fail identically forever, and retrying them just
        # wastes time and hammers someone else's server.
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError, CollectorError)),
        stop=stop_after_attempt(4),
        # Exponential backoff WITH JITTER: waits roughly 1s, 2s, 4s, but with a
        # random offset. The jitter matters. Without it, if ten collectors fail
        # at the same moment they all retry at the same moment, re-creating the
        # overload that caused the failure. This is called a thundering herd.
        wait=wait_exponential_jitter(initial=1, max=20),
        reraise=True,
    )
    def fetch(self) -> httpx.Response:
        """Download the source data, retrying transient failures."""
        self.log.debug("fetch_start", url=self.url)

        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"},
        ) as client:
            response = client.get(self.url)

        if response.status_code >= 500:
            # Server-side problem: worth retrying, so raise the retryable type.
            raise CollectorError(f"{self.source.value}: server returned {response.status_code}")
        if response.status_code >= 400:
            # Our problem (bad URL, missing API key). Retrying cannot help.
            raise RuntimeError(
                f"{self.source.value}: request rejected with {response.status_code}. "
                f"This will not fix itself - check the URL or whether the feed now "
                f"requires an API key."
            )

        self.log.debug(
            "fetch_done",
            status=response.status_code,
            bytes=len(response.content),
            seconds=response.elapsed.total_seconds(),
        )
        return response

    # ------------------------------------------------------------------ parse

    @abc.abstractmethod
    def parse(self, response: httpx.Response) -> Iterator[Event]:
        """Turn the downloaded response into Events, one at a time.

        Implemented as a GENERATOR (using `yield`) rather than returning a
        list, so records are processed one by one instead of all being held in
        memory at once. URLhaus is 3 MB today; the same code must still work
        when a source sends 3 GB. Streaming costs nothing extra to write and
        removes the memory ceiling entirely.

        A parser that hits a malformed record should log it and continue, not
        crash. One bad row must never cost us the other 40,000 good ones.
        """
        raise NotImplementedError

    def make_event(self, payload: dict[str, Any], occurred_at: datetime) -> Event:
        """Wrap one parsed record in the standard envelope."""
        return Event(
            source=self.source,
            event_type=self.event_type,
            occurred_at=occurred_at,
            payload=payload,
            collector_run_id=self.run_id,
        )

    # -------------------------------------------------------------------- run

    def run(self, sink: Sink, *, limit: int | None = None) -> CollectorResult:
        """Execute one full collection: fetch, parse, emit, report.

        Returns a CollectorResult rather than printing, so a scheduler can act
        on the outcome. `limit` caps how many events are emitted, which makes
        trying out a new collector cheap and fast.
        """
        started = utc_now()
        fetched = emitted = rejected = 0
        raw_bytes = 0
        status = "success"
        error: str | None = None

        self.log.info("collector_start", url=self.url, limit=limit)

        try:
            response = self.fetch()
            raw_bytes = len(response.content)

            for event in self.parse(response):
                fetched += 1
                try:
                    sink.write(event)
                    emitted += 1
                except Exception as exc:
                    # A single unwritable event must not abort the run. We count
                    # it, log it, and keep going. Silence here would be far worse
                    # than a noisy log: it would look like success.
                    rejected += 1
                    self.log.warning(
                        "event_rejected", error=str(exc)[:200], event_id=event.event_id
                    )

                if limit is not None and emitted >= limit:
                    self.log.info("limit_reached", limit=limit)
                    break

            sink.flush()

        except Exception as exc:
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
            self.log.error("collector_failed", error=error)

        finally:
            sink.close()

        finished = utc_now()
        result = CollectorResult(
            source=self.source,
            run_id=self.run_id,
            started_at=started,
            finished_at=finished,
            status=status,
            records_fetched=fetched,
            records_emitted=emitted,
            records_rejected=rejected,
            bytes_downloaded=raw_bytes,
            error_message=error,
        )

        self.log.info(
            "collector_done",
            status=status,
            fetched=fetched,
            emitted=emitted,
            rejected=rejected,
            seconds=round(result.duration_seconds, 2),
            kb=round(raw_bytes / 1024, 1),
            events_per_second=round(emitted / max(result.duration_seconds, 0.001), 1),
        )
        return result


def record_run(result: CollectorResult) -> None:
    """Save a collector run to Postgres: watermark + audit row.

    WHY BOTHER
    Without this, "did the URLhaus feed run last night?" can only be answered by
    reading log files. With it, it is a SQL query - and so is "show me every
    feed whose rejection rate went above 1% this week".

    A pipeline you cannot query the health of is a pipeline you are not really
    operating. Written as a separate function rather than a method so that
    collectors stay usable with no database at all (which is what makes them
    easy to unit-test).
    """
    import json

    import psycopg

    from aegis.config import settings

    try:
        with psycopg.connect(settings.database.psycopg_dsn, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                # UPSERT: insert the first time, update every time after. This
                # is what makes the collector safe to re-run - a second run
                # updates the watermark instead of failing on a duplicate key.
                cur.execute(
                    """
                    INSERT INTO ops.ingestion_watermark
                        (source_name, last_run_at, last_cursor, last_status,
                         records_emitted, error_message, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, now())
                    ON CONFLICT (source_name) DO UPDATE SET
                        last_run_at     = EXCLUDED.last_run_at,
                        last_cursor     = EXCLUDED.last_cursor,
                        last_status     = EXCLUDED.last_status,
                        records_emitted = EXCLUDED.records_emitted,
                        error_message   = EXCLUDED.error_message,
                        updated_at      = now()
                    """,
                    (
                        result.source.value,
                        result.finished_at,
                        result.cursor,
                        result.status,
                        result.records_emitted,
                        result.error_message,
                    ),
                )
                # The audit row is append-only: one row per run, forever. The
                # watermark says "where are we now"; the audit log says "how did
                # we get here", which is what you need during an incident.
                cur.execute(
                    """
                    INSERT INTO ops.pipeline_run
                        (run_id, pipeline_name, started_at, finished_at, status,
                         rows_in, rows_out, rows_rejected, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        result.run_id,
                        f"collector.{result.source.value}",
                        result.started_at,
                        result.finished_at,
                        result.status,
                        result.records_fetched,
                        result.records_emitted,
                        result.records_rejected,
                        json.dumps(
                            {
                                "bytes_downloaded": result.bytes_downloaded,
                                "duration_seconds": round(result.duration_seconds, 3),
                                "rejection_rate": round(result.rejection_rate, 5),
                            }
                        ),
                    ),
                )
            conn.commit()
        log.debug("run_recorded", source=result.source.value)
    except Exception as exc:
        # Bookkeeping must never destroy a successful collection. If Postgres is
        # down we still collected the data; we log the problem and move on.
        log.warning("run_record_failed", error=str(exc)[:200])
