"""Tests for the collection layer.

NOTE WHAT IS NOT HERE: not one of these tests touches the network, Docker,
Postgres or the internet. They run in milliseconds, offline, on any machine.

That is only possible because of two design choices made earlier:

  * collectors write to a *sink*, so a test can pass in a fake one
  * parse() takes a Response object, so a test can hand it a fake response

If collectors had written straight to Kafka, every one of these tests would
need infrastructure running - and a test suite that needs infrastructure is a
test suite people stop running.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest

from aegis.sources.feeds import (
    CisaKevCollector,
    FeodoCollector,
    TorExitCollector,
    URLhausCollector,
)
from aegis.sources.models import Event, EventType, Source, utc_now, uuid7
from aegis.sources.sinks import CountingSink, JsonlFileSink


def fake_response(body: str | bytes, status: int = 200) -> httpx.Response:
    """Build a Response object without any network call."""
    content = body.encode("utf-8") if isinstance(body, str) else body
    return httpx.Response(
        status_code=status, content=content, request=httpx.Request("GET", "https://test.local")
    )


# ============================================================================
# The envelope
# ============================================================================
class TestEvent:
    def test_naive_datetime_is_rejected(self) -> None:
        """A datetime with no timezone must fail loudly, not be guessed at.

        This is the guard rail for the most expensive class of bug in data
        engineering: the same instant recorded differently on two machines,
        which silently corrupts every time-based join and partition.
        """
        with pytest.raises(ValueError, match="timezone-aware"):
            Event(
                source=Source.FEODO,
                event_type=EventType.IOC_IP,
                occurred_at=datetime(2026, 1, 1, 12, 0, 0),  # noqa: DTZ001 - the point of the test
                payload={},
            )

    def test_non_utc_timezone_is_converted_not_rejected(self) -> None:
        """A valid non-UTC time is fine - we normalise it rather than refuse it."""
        from datetime import timedelta

        paris = timezone(timedelta(hours=2))
        event = Event(
            source=Source.FEODO,
            event_type=EventType.IOC_IP,
            occurred_at=datetime(2026, 1, 1, 14, 0, 0, tzinfo=paris),
            payload={},
        )
        assert event.occurred_at.tzinfo == timezone.utc
        assert event.occurred_at.hour == 12  # 14:00 in Paris is 12:00 UTC

    def test_content_hash_ignores_key_order(self) -> None:
        """Two dictionaries with the same contents must hash identically.

        Without sort_keys in the hashing, {"a":1,"b":2} and {"b":2,"a":1} would
        produce different fingerprints, and deduplication downstream would
        quietly stop working while appearing to run fine.
        """
        now = utc_now()
        a = Event(
            source=Source.FEODO,
            event_type=EventType.IOC_IP,
            occurred_at=now,
            payload={"ip": "1.2.3.4", "port": 443},
        )
        b = Event(
            source=Source.FEODO,
            event_type=EventType.IOC_IP,
            occurred_at=now,
            payload={"port": 443, "ip": "1.2.3.4"},
        )

        assert a.content_hash == b.content_hash
        assert a.event_id != b.event_id  # same content, still distinct observations

    def test_content_hash_changes_when_content_changes(self) -> None:
        now = utc_now()
        a = Event(
            source=Source.FEODO,
            event_type=EventType.IOC_IP,
            occurred_at=now,
            payload={"ip": "1.2.3.4"},
        )
        b = Event(
            source=Source.FEODO,
            event_type=EventType.IOC_IP,
            occurred_at=now,
            payload={"ip": "1.2.3.5"},
        )
        assert a.content_hash != b.content_hash

    def test_lag_is_measured_from_event_time_to_ingest_time(self) -> None:
        from datetime import timedelta

        occurred = utc_now() - timedelta(hours=3)
        event = Event(
            source=Source.FEODO, event_type=EventType.IOC_IP, occurred_at=occurred, payload={}
        )
        assert 10700 < event.lag_seconds < 10900  # ~3 hours

    def test_events_are_immutable(self) -> None:
        """An event must not be editable after creation.

        Immutability is what guarantees that what we store is what we received.
        If any downstream step could edit an event in place, 'raw data is
        sacred' would be a comment rather than a property of the system.
        """
        event = Event(
            source=Source.FEODO, event_type=EventType.IOC_IP, occurred_at=utc_now(), payload={}
        )
        with pytest.raises(Exception):  # noqa: B017 - pydantic raises ValidationError
            event.payload = {"tampered": True}  # type: ignore[misc]


class TestUuid7:
    def test_ids_sort_in_creation_order(self) -> None:
        """The whole point of UUID7: sorting by ID sorts by time."""
        ids = [uuid7() for _ in range(200)]
        assert ids == sorted(ids)

    def test_ids_are_unique(self) -> None:
        assert len({uuid7() for _ in range(5000)}) == 5000

    def test_version_nibble_is_7(self) -> None:
        import uuid as uuidlib

        assert uuidlib.UUID(uuid7()).version == 7


# ============================================================================
# Parsers - fed hand-written samples of each real format
# ============================================================================
class TestURLhausParser:
    SAMPLE = (
        "# comment banner line\n"
        "# id,dateadded,url,url_status,...\n"
        '"1","2026-09-05 10:00:00","http://evil.test/x.bin","online","","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/1/","reporter1"\n'
        '"2","2026-09-05 11:00:00","http://bad.test/y.exe","offline","","malware_download","","https://urlhaus.abuse.ch/url/2/","reporter2"\n'
    )

    def test_comment_lines_are_skipped(self) -> None:
        """The banner must not be mistaken for data or for the header row."""
        events = list(URLhausCollector().parse(fake_response(self.SAMPLE)))
        assert len(events) == 2
        assert events[0].payload["url"] == "http://evil.test/x.bin"

    def test_tags_become_a_list(self) -> None:
        events = list(URLhausCollector().parse(fake_response(self.SAMPLE)))
        assert events[0].payload["tags"] == ["elf", "mirai"]
        assert events[1].payload["tags"] == []  # empty string, not [""]

    def test_bad_row_is_skipped_without_killing_the_run(self) -> None:
        """One malformed line must not cost us the other good ones."""
        broken = self.SAMPLE + '"3","NOT-A-DATE","http://x.test/z","online","","","","",""\n'
        events = list(URLhausCollector().parse(fake_response(broken)))
        assert len(events) == 2  # the bad row is dropped, the good ones survive

    def test_event_time_comes_from_the_feed_not_from_now(self) -> None:
        events = list(URLhausCollector().parse(fake_response(self.SAMPLE)))
        assert events[0].occurred_at == datetime(2026, 9, 5, 10, 0, tzinfo=timezone.utc)


class TestCisaKevParser:
    SAMPLE = json.dumps(
        {
            "catalogVersion": "2026.09.04",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1",
                    "vendorProject": "Microsoft",
                    "product": "Windows",
                    "vulnerabilityName": "Test flaw",
                    "dateAdded": "2026-09-04",
                    "shortDescription": "d",
                    "requiredAction": "patch",
                    "dueDate": "2026-09-25",
                    "knownRansomwareCampaignUse": "Known",
                    "cwes": ["CWE-1"],
                },
                {
                    "cveID": "CVE-2026-2",
                    "vendorProject": "Cisco",
                    "product": "IOS",
                    "vulnerabilityName": "Other",
                    "dateAdded": "bad-date",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        }
    )

    def test_fields_are_mapped(self) -> None:
        events = list(CisaKevCollector().parse(fake_response(self.SAMPLE)))
        assert len(events) == 2
        assert events[0].payload["cve_id"] == "CVE-2026-1"
        assert events[0].payload["ransomware_use"] == "Known"

    def test_catalog_version_is_stamped_on_every_record(self) -> None:
        """So months later we can still tell which snapshot a row came from."""
        events = list(CisaKevCollector().parse(fake_response(self.SAMPLE)))
        assert all(e.payload["catalog_version"] == "2026.09.04" for e in events)

    def test_unparseable_date_falls_back_to_now_rather_than_dropping(self) -> None:
        """A CVE with a broken date is still a CVE. Keep it, flag the time."""
        events = list(CisaKevCollector().parse(fake_response(self.SAMPLE)))
        assert len(events) == 2
        assert events[1].occurred_at.year >= 2026


class TestFeodoParser:
    def test_parses_c2_entries(self) -> None:
        sample = json.dumps(
            [
                {
                    "ip_address": "1.2.3.4",
                    "port": 443,
                    "status": "online",
                    "as_number": 14618,
                    "as_name": "AMAZON-AES",
                    "country": "US",
                    "first_seen": "2026-01-01 10:00:00",
                    "malware": "QakBot",
                }
            ]
        )
        events = list(FeodoCollector().parse(fake_response(sample)))
        assert events[0].payload["malware"] == "QakBot"
        assert events[0].payload["as_name"] == "AMAZON-AES"

    def test_unexpected_shape_returns_nothing_instead_of_crashing(self) -> None:
        """If the feed starts returning an object instead of a list, degrade gracefully."""
        events = list(FeodoCollector().parse(fake_response('{"error": "rate limited"}')))
        assert events == []

    def test_invalid_json_returns_nothing_instead_of_crashing(self) -> None:
        events = list(FeodoCollector().parse(fake_response("<html>502 Bad Gateway</html>")))
        assert events == []


class TestTorExitParser:
    def test_one_ip_per_line(self) -> None:
        events = list(TorExitCollector().parse(fake_response("1.2.3.4\n5.6.7.8\n\n# note\n")))
        assert [e.payload["ip_address"] for e in events] == ["1.2.3.4", "5.6.7.8"]

    def test_all_ips_share_one_snapshot_timestamp(self) -> None:
        """Every IP in one fetch must carry the same observation time.

        Otherwise 'the Tor exit list as of 14:00' is not a coherent query -
        each row would have drifted by microseconds and no clean cut exists.
        """
        events = list(TorExitCollector().parse(fake_response("1.1.1.1\n2.2.2.2\n3.3.3.3\n")))
        assert len({e.occurred_at for e in events}) == 1


# ============================================================================
# Sinks
# ============================================================================
class TestSinks:
    def test_counting_sink_counts(self) -> None:
        sink = CountingSink()
        for _ in range(7):
            sink.write(
                Event(
                    source=Source.FEODO,
                    event_type=EventType.IOC_IP,
                    occurred_at=utc_now(),
                    payload={},
                )
            )
        assert sink.count == 7

    def test_jsonl_sink_writes_hive_partitioned_gzip(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """Verify the folder layout, because query performance depends on it."""
        import gzip

        sink = JsonlFileSink(base_dir=tmp_path, source="feodo", run_id="testrun")
        event = Event(
            source=Source.FEODO,
            event_type=EventType.IOC_IP,
            occurred_at=utc_now(),
            payload={"ip_address": "9.9.9.9"},
        )
        sink.write(event)
        sink.close()

        assert sink.path is not None
        parts = sink.path.parts
        assert "source=feodo" in parts
        assert any(p.startswith("date=") for p in parts)

        with gzip.open(sink.path, "rt", encoding="utf-8") as fh:
            record = json.loads(fh.readline())
        assert record["payload"]["ip_address"] == "9.9.9.9"
        assert record["_content_hash"] == event.content_hash

    def test_jsonl_sink_creates_no_file_when_nothing_is_written(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """An empty run must leave no empty file for readers to trip over."""
        sink = JsonlFileSink(base_dir=tmp_path, source="feodo", run_id="empty")
        sink.close()
        assert list(tmp_path.rglob("*.jsonl.gz")) == []


# ============================================================================
# The full loop, still with no network
# ============================================================================
class TestCollectorRun:
    def test_run_reports_accurate_counts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        collector = TorExitCollector()
        monkeypatch.setattr(collector, "fetch", lambda: fake_response("1.1.1.1\n2.2.2.2\n"))

        sink = CountingSink()
        result = collector.run(sink)

        assert result.status == "success"
        assert result.records_fetched == 2
        assert result.records_emitted == 2
        assert result.records_rejected == 0
        assert result.duration_seconds >= 0

    def test_limit_stops_early(self, monkeypatch: pytest.MonkeyPatch) -> None:
        collector = TorExitCollector()
        body = "\n".join(f"10.0.0.{i}" for i in range(100))
        monkeypatch.setattr(collector, "fetch", lambda: fake_response(body))

        result = collector.run(CountingSink(), limit=5)
        assert result.records_emitted == 5

    def test_network_failure_is_reported_not_raised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failed collector must return a 'failed' result, not explode.

        A scheduler needs a status it can branch on. An unhandled exception
        gives it a stack trace and no structured information to alert on.
        """
        collector = TorExitCollector()

        def boom() -> httpx.Response:
            raise httpx.ConnectError("network unreachable")

        monkeypatch.setattr(collector, "fetch", boom)
        result = collector.run(CountingSink())

        assert result.status == "failed"
        assert result.error_message is not None
        assert "ConnectError" in result.error_message

    def test_a_broken_sink_does_not_abort_the_whole_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One unwritable event is counted as rejected; the rest still flow."""

        class FlakySink(CountingSink):
            def write(self, event: Event) -> None:
                if event.payload["ip_address"].endswith(".2"):
                    raise OSError("disk full")
                super().write(event)

        collector = TorExitCollector()
        monkeypatch.setattr(
            collector, "fetch", lambda: fake_response("10.0.0.1\n10.0.0.2\n10.0.0.3\n")
        )
        result = collector.run(FlakySink())

        assert result.status == "success"
        assert result.records_fetched == 3
        assert result.records_emitted == 2
        assert result.records_rejected == 1
