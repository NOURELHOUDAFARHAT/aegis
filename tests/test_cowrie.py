"""Tests for the honeypot collector.

Every log line here is SYNTHETIC, written by the test itself in Cowrie's
documented JSON shape. Addresses come from the RFC 5737 documentation ranges,
which can never be real attackers - the same ranges Silver filters out.

Nothing touches SSH or a network: the collector reads a local folder through
the same LogSource interface the SSH version implements.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.sources.cowrie import (
    CowrieCollector,
    CursorStore,
    LocalLogSource,
    event_type_for,
    parse_listing,
    parse_record,
    parse_timestamp,
)
from aegis.sources.models import EventType, Source
from aegis.sources.sinks import CountingSink


def line(eventid: str, second: int = 0, **fields: object) -> str:
    record = {
        "eventid": eventid,
        "timestamp": f"2026-09-14T21:00:{second:02d}.123456Z",
        "session": "a1b2c3d4e5f6",
        "src_ip": "198.51.100.23",
        "sensor": "sensor",
        **fields,
    }
    return json.dumps(record) + "\n"


def collect(logs: Path, cursor: Path, **kwargs: object) -> tuple[CountingSink, object]:
    sink = CountingSink()
    sink.keep_events = True
    collector = CowrieCollector(LocalLogSource(logs), CursorStore(cursor))
    result = collector.run(sink, **kwargs)  # type: ignore[arg-type]
    return sink, result


@pytest.fixture
def logs(tmp_path: Path) -> Path:
    directory = tmp_path / "log"
    directory.mkdir()
    return directory


@pytest.fixture
def cursor(tmp_path: Path) -> Path:
    return tmp_path / "state" / "cowrie_cursor.json"


class TestParsing:
    def test_timestamp_with_z_is_utc(self) -> None:
        parsed = parse_timestamp("2026-09-14T21:03:11.123456Z")
        assert parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0
        assert parsed.hour == 21

    def test_timestamp_without_timezone_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="timezone"):
            parse_timestamp("2026-09-14T21:03:11")

    def test_commands_are_command_events(self) -> None:
        assert event_type_for("cowrie.command.input") is EventType.SESSION_COMMAND
        assert event_type_for("cowrie.login.failed") is EventType.SESSION_SSH

    def test_non_cowrie_json_is_not_a_record(self) -> None:
        assert parse_record(b'{"eventid": "something.else"}') is None
        assert parse_record(b"[1, 2, 3]") is None
        assert parse_record(b"not json") is None

    def test_listing_drops_unexpected_lines_and_puts_live_file_last(self) -> None:
        text = (
            "101 500 cowrie.json\n"
            "102 900 cowrie.json.2026-09-13\n"
            "103 10 ../../etc/shadow\n"  # never trusted, whatever the reader returns
            "104 800 cowrie.json.2026-09-12\n"
            "garbage line\n"
        )
        names = [file.name for file in parse_listing(text)]
        assert names == ["cowrie.json.2026-09-12", "cowrie.json.2026-09-13", "cowrie.json"]


class TestIncrementalCollection:
    def test_second_run_reads_only_new_lines(self, logs: Path, cursor: Path) -> None:
        live = logs / "cowrie.json"
        live.write_text(line("cowrie.session.connect", 1) + line("cowrie.login.failed", 2))

        first, _ = collect(logs, cursor)
        assert first.count == 2

        with live.open("a") as handle:
            handle.write(line("cowrie.command.input", 3, input="uname -a"))

        second, _ = collect(logs, cursor)
        assert second.count == 1
        assert second.events[0].payload["input"] == "uname -a"

    def test_payload_is_the_record_untouched(self, logs: Path, cursor: Path) -> None:
        (logs / "cowrie.json").write_text(
            line("cowrie.login.failed", 5, username="root", password="123456")
        )
        sink, _ = collect(logs, cursor)
        event = sink.events[0]
        assert event.source is Source.COWRIE
        assert event.payload["password"] == "123456"
        assert event.occurred_at.second == 5

    def test_half_written_line_waits_for_the_next_run(self, logs: Path, cursor: Path) -> None:
        live = logs / "cowrie.json"
        complete = line("cowrie.session.connect", 1)
        partial = line("cowrie.login.failed", 2)
        live.write_text(complete + partial[:20])  # Cowrie is mid-write

        first, _ = collect(logs, cursor)
        assert first.count == 1

        live.write_text(complete + partial)  # the write finishes
        second, _ = collect(logs, cursor)
        assert second.count == 1
        assert second.events[0].payload["eventid"] == "cowrie.login.failed"

    def test_daily_rotation_reads_nothing_twice(self, logs: Path, cursor: Path) -> None:
        live = logs / "cowrie.json"
        live.write_text(line("cowrie.session.connect", 1) + line("cowrie.login.failed", 2))
        first, _ = collect(logs, cursor)
        assert first.count == 2

        # Midnight: one more event lands, then Cowrie rotates the file.
        with live.open("a") as handle:
            handle.write(line("cowrie.session.closed", 3))
        live.rename(logs / "cowrie.json.2026-09-14")
        (logs / "cowrie.json").write_text(line("cowrie.session.connect", 4))

        second, _ = collect(logs, cursor)
        seconds = sorted(event.occurred_at.second for event in second.events)
        assert seconds == [3, 4]  # the tail of the rotated file, then the new file

    def test_malformed_line_is_counted_and_skipped(self, logs: Path, cursor: Path) -> None:
        (logs / "cowrie.json").write_text(
            line("cowrie.session.connect", 1) + "{not json\n" + line("cowrie.session.closed", 2)
        )
        sink, result = collect(logs, cursor)
        assert sink.count == 2
        assert result.records_rejected == 1  # type: ignore[attr-defined]

    def test_limit_resumes_at_the_next_line(self, logs: Path, cursor: Path) -> None:
        (logs / "cowrie.json").write_text("".join(line("cowrie.login.failed", s) for s in range(5)))

        first, _ = collect(logs, cursor, limit=2)
        assert [e.occurred_at.second for e in first.events] == [0, 1]

        rest, _ = collect(logs, cursor)
        assert [e.occurred_at.second for e in rest.events] == [2, 3, 4]

    def test_dry_run_does_not_move_the_cursor(self, logs: Path, cursor: Path) -> None:
        (logs / "cowrie.json").write_text(line("cowrie.session.connect", 1))
        collect(logs, cursor, commit=False)
        again, _ = collect(logs, cursor)
        assert again.count == 1


class TestCursorSafety:
    def test_cursor_is_not_saved_when_the_sink_fails(self, logs: Path, cursor: Path) -> None:
        """Flush fails -> the events did not arrive -> the next run must resend them."""

        class FailingSink(CountingSink):
            def flush(self) -> None:
                raise RuntimeError("broker unavailable")

        (logs / "cowrie.json").write_text(line("cowrie.session.connect", 1))
        collector = CowrieCollector(LocalLogSource(logs), CursorStore(cursor))
        result = collector.run(FailingSink())
        assert result.status == "failed"
        assert not cursor.exists()

        retry, _ = collect(logs, cursor)
        assert retry.count == 1

    def test_cursor_is_not_saved_when_delivery_is_unacknowledged(
        self, logs: Path, cursor: Path
    ) -> None:
        """flush() returned, but the broker never acknowledged a message.

        A Kafka sink reports that through `all_delivered` rather than raising.
        Moving the cursor anyway would skip those events forever.
        """

        class UnacknowledgedSink(CountingSink):
            all_delivered = False

        (logs / "cowrie.json").write_text(line("cowrie.session.connect", 1))
        collector = CowrieCollector(LocalLogSource(logs), CursorStore(cursor))
        result = collector.run(UnacknowledgedSink())
        assert result.status == "failed"
        assert "acknowledge" in (result.error_message or "")
        assert not cursor.exists()
