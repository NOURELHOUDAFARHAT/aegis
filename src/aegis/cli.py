"""The ``aegis`` command-line interface.

Every operational capability of the platform is exposed here as a subcommand,
so the system can be driven identically by a human, by Dagster, and by CI.
That single-entry-point discipline is what makes a pipeline automatable later
without rewriting it.

Usage::

    aegis version
    aegis config
    aegis doctor
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from aegis import __version__
from aegis.config import settings

app = typer.Typer(
    name="aegis",
    help="AEGIS - threat intelligence lakehouse.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.command()
def version() -> None:
    """Print the AEGIS version."""
    console.print(f"[bold cyan]AEGIS[/] v{__version__}")


@app.command()
def config() -> None:
    """Show the resolved configuration, with secrets masked.

    Masking is not decoration: this command will end up in shared terminals,
    screen recordings and CI logs. Printing a secret once is enough to leak it.
    """

    def mask(value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"

    table = Table(title="AEGIS resolved configuration", show_lines=False)
    table.add_column("Setting", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    rows = [
        ("env", settings.env),
        ("log_level", settings.log_level),
        ("catalog_name", settings.catalog_name),
        ("kafka.bootstrap", settings.kafka.kafka_bootstrap),
        ("kafka.schema_registry", settings.kafka.schema_registry_url),
        ("kafka.acks", settings.kafka.producer_acks),
        ("kafka.compression", settings.kafka.producer_compression),
        ("storage.endpoint", settings.storage.s3_endpoint),
        ("storage.access_key", mask(settings.storage.s3_access_key)),
        ("storage.secret_key", mask(settings.storage.s3_secret_key)),
        ("storage.lake_bucket", settings.storage.lake_bucket),
        ("storage.quarantine", settings.storage.quarantine_bucket),
        ("database.host", f"{settings.database.pg_host}:{settings.database.pg_port}"),
        ("database.user", settings.database.pg_user),
        ("database.password", mask(settings.database.pg_password)),
        ("database.name", settings.database.pg_database),
    ]
    for key, value in rows:
        table.add_row(key, str(value))

    console.print(table)


@app.command()
def doctor() -> None:
    """Run the environment diagnostics (same as ``.\\aegis.ps1 doctor``)."""
    import subprocess
    import sys
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts" / "doctor.py"
    raise SystemExit(subprocess.call([sys.executable, str(script)]))  # noqa: S603


@app.command()
def sources() -> None:
    """List every data source AEGIS can collect from."""
    from aegis.sources.feeds import COLLECTORS

    table = Table(title="AEGIS data sources")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Event type", style="magenta")
    table.add_column("Snapshot?", style="yellow")
    table.add_column("URL", style="dim")

    for name, cls in sorted(COLLECTORS.items()):
        table.add_row(
            name,
            cls.event_type.value,
            "full" if cls.is_full_snapshot else "incremental",
            cls.url[:58] + ("..." if len(cls.url) > 58 else ""),
        )
    console.print(table)


@app.command()
def collect(
    source: str = typer.Argument(..., help="Source name, or 'all'. See: aegis sources"),
    limit: int | None = typer.Option(
        None, "--limit", "-n", help="Stop after N events. Great for a first try."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Fetch and parse, but write nothing to disk."
    ),
    show: bool = typer.Option(
        False, "--show", help="Print the first few events so you can see the shape."
    ),
    to: str = typer.Option("file", "--to", help="Destination: 'file' (gzipped JSONL) or 'kafka'."),
    out: str | None = typer.Option(
        None, "--out", help="Output directory. Defaults to AEGIS_DATA_DIR/raw."
    ),
) -> None:
    """Run a collector: download a source, parse it, and store the events.

    Examples::

        aegis collect cisa_kev --limit 3 --show    # look at the data first
        aegis collect tor_exit                     # store a full snapshot
        aegis collect all                          # every feed, one after another
    """
    from pathlib import Path

    from aegis.config import settings
    from aegis.sources.base import record_run
    from aegis.sources.feeds import COLLECTORS
    from aegis.sources.sinks import ConsoleSink, CountingSink, JsonlFileSink

    names = sorted(COLLECTORS) if source == "all" else [source]
    unknown = [n for n in names if n not in COLLECTORS]
    if unknown:
        console.print(f"[red]Unknown source(s): {', '.join(unknown)}[/]")
        console.print(f"Available: {', '.join(sorted(COLLECTORS))}")
        raise typer.Exit(code=1)

    results = []
    for name in names:
        collector = COLLECTORS[name]()
        console.print(f"\n[bold cyan]-> {name}[/]  {collector.url}")

        sink: object
        if show:
            sink = ConsoleSink(limit=limit or 3)
        elif dry_run:
            sink = CountingSink()
        elif to == "kafka":
            # Note what does NOT happen here: the collector is not told which
            # kind of sink it received. Swapping files for Kafka is a one-line
            # change at the call site, which is exactly what the Sink protocol
            # in Phase 1 was for.
            from aegis.streaming.producer import KafkaSink

            sink = KafkaSink(client_id=f"aegis-collector-{name}")
        elif to == "file":
            sink = JsonlFileSink(
                base_dir=Path(out) if out else Path(settings.data_dir) / "raw",
                source=name,
                run_id=collector.run_id,
            )
        else:
            console.print(f"[red]Unknown destination '{to}'. Use 'file' or 'kafka'.[/]")
            raise typer.Exit(code=1)

        result = collector.run(sink, limit=limit)  # type: ignore[arg-type]
        results.append(result)

        if not dry_run and not show:
            record_run(result)

    # A compact summary table, because after running six collectors you want
    # one glance to tell you whether anything went wrong.
    table = Table(title="Collection summary")
    table.add_column("Source", style="cyan")
    table.add_column("Status")
    table.add_column("Events", justify="right")
    table.add_column("Rejected", justify="right")
    table.add_column("Downloaded", justify="right")
    table.add_column("Seconds", justify="right")

    for r in results:
        colour = "green" if r.status == "success" else "red"
        table.add_row(
            r.source.value,
            f"[{colour}]{r.status}[/]",
            f"{r.records_emitted:,}",
            f"{r.records_rejected:,}",
            f"{r.bytes_downloaded / 1024:,.0f} KB",
            f"{r.duration_seconds:.1f}",
        )
    console.print()
    console.print(table)

    if any(r.status != "success" for r in results):
        raise typer.Exit(code=1)


# ===========================================================================
# Phase 2 - streaming commands
# ===========================================================================

topics_app = typer.Typer(help="Manage Kafka topics.", no_args_is_help=True)
app.add_typer(topics_app, name="topics")


@topics_app.command("create")
def topics_create(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be created."),
) -> None:
    """Create every declared topic that does not exist yet. Safe to re-run."""
    from aegis.streaming.admin import create_topics, ensure_compatibility

    results = create_topics(dry_run=dry_run)

    if not dry_run:
        # Enforce the schema-evolution rules at the same time as the topics.
        # Both are "the shape of the stream", and both must be reproducible on
        # an empty broker rather than set by hand once and forgotten.
        level = ensure_compatibility()
        console.print(f"  schema compatibility: [bold]{level}[/]")
        console.print()
    table = Table(title="Topic creation")
    table.add_column("Topic", style="cyan")
    table.add_column("Result")
    for name, outcome in sorted(results.items()):
        colour = {"created": "green", "exists": "dim", "would create": "yellow"}.get(outcome, "red")
        table.add_row(name, f"[{colour}]{outcome}[/]")
    console.print(table)


@topics_app.command("list")
def topics_list() -> None:
    """Show what the broker actually has, including message counts."""
    from aegis.streaming.admin import describe_topics
    from aegis.streaming.topics import all_specs

    descriptions = {s.name: s.description for s in all_specs()}

    table = Table(title="AEGIS topics on the broker")
    table.add_column("Topic", style="cyan", no_wrap=True)
    table.add_column("Parts", justify="right")
    table.add_column("RF", justify="right")
    table.add_column("Retention", justify="right")
    table.add_column("Messages", justify="right")
    table.add_column("Purpose", style="dim")

    for status in describe_topics():
        if not status.exists:
            table.add_row(status.name, "-", "-", "-", "-", "[red]MISSING[/]")
            continue
        retention = f"{status.retention_hours / 24:.0f}d" if status.retention_hours else "-"
        table.add_row(
            status.name,
            str(status.partitions),
            str(status.replication_factor),
            retention,
            f"{status.message_count:,}" if status.message_count is not None else "?",
            descriptions.get(status.name, ""),
        )
    console.print(table)


@topics_app.command("reset")
def topics_reset(
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt."),
) -> None:
    """Delete and recreate every topic. DESTRUCTIVE: all retained records are lost."""
    from aegis.streaming.admin import create_topics, delete_topics
    from aegis.streaming.topics import all_specs

    names = [s.name for s in all_specs()]
    if not yes:
        console.print("[yellow]This deletes every record in:[/]")
        for n in names:
            console.print(f"  {n}")
        if not typer.confirm("Continue?"):
            console.print("Cancelled.")
            raise typer.Exit()

    for name, outcome in sorted(delete_topics(names).items()):
        console.print(f"  {outcome:10} {name}")

    # Deletion is asynchronous on the broker: recreating immediately can race
    # with the delete and fail. A short pause is the pragmatic fix.
    import time

    time.sleep(3)
    console.print()
    for name, outcome in sorted(create_topics().items()):
        console.print(f"  {outcome:10} {name}")


@app.command()
def tail(
    topic: str = typer.Argument(..., help="Topic name, e.g. aegis.raw.feodo"),
    limit: int = typer.Option(5, "--limit", "-n", help="How many messages to show."),
    from_beginning: bool = typer.Option(
        True, "--from-beginning/--from-now", help="Read history, or only new messages."
    ),
    group: str = typer.Option(
        "aegis-tail", "--group", help="Consumer group. Use a throwaway name for inspection."
    ),
) -> None:
    """Read messages from a topic and print them.

    Uses a throwaway consumer group so it never disturbs a real consumer's
    position in the stream.
    """
    from aegis.streaming.consumer import EventConsumer

    consumer = EventConsumer(
        topics=[topic], group_id=group, from_beginning=from_beginning, commit_every=10_000
    )

    shown = 0

    def show(event: object) -> None:
        nonlocal shown
        shown += 1
        ev = event  # typed loosely to keep the CLI import-light
        console.print(
            f"\n[bold cyan]#{shown}[/]  partition=[yellow]{ev.partition}[/] "  # type: ignore[attr-defined]
            f"offset=[yellow]{ev.offset}[/] key=[magenta]{ev.key}[/]"  # type: ignore[attr-defined]
        )
        console.print(f"  source     : {ev.source}")  # type: ignore[attr-defined]
        console.print(f"  event_id   : {ev.event_id}")  # type: ignore[attr-defined]
        console.print(f"  occurred_at: {ev.envelope.get('occurred_at')}")  # type: ignore[attr-defined]
        console.print(f"  payload    : {json_preview(ev.payload)}")  # type: ignore[attr-defined]

    stats = consumer.consume(show, max_records=limit, idle_timeout=5.0)  # type: ignore[arg-type]
    console.print(f"\n[dim]read {stats.consumed} message(s); {stats.failed} failed[/]")


def json_preview(data: object, width: int = 300) -> str:
    """Compact one-line JSON, truncated - readable in a terminal."""
    import json as _json

    text = _json.dumps(data, separators=(",", ":"), default=str)
    return text if len(text) <= width else text[:width] + "..."


@app.command()
def lag(
    group: str = typer.Option(..., "--group", help="Consumer group to inspect."),
    topic: list[str] = typer.Option(None, "--topic", help="Topic(s); defaults to all AEGIS."),
) -> None:
    """Show consumer lag: how many records are produced but not yet processed.

    This is the number to watch in production. Flat lag means the consumer is
    keeping up; rising lag means everything downstream is going stale.
    """
    from aegis.streaming.consumer import lag_report
    from aegis.streaming.topics import all_specs

    topics = topic or [s.name for s in all_specs()]
    rows = lag_report(group, topics)

    table = Table(title=f"Consumer lag - group '{group}'")
    table.add_column("Topic", style="cyan")
    table.add_column("Part", justify="right")
    table.add_column("Committed", justify="right")
    table.add_column("Latest", justify="right")
    table.add_column("Lag", justify="right")

    total = 0
    for row in rows:
        total += int(row["lag"])
        colour = "green" if row["lag"] == 0 else ("yellow" if row["lag"] < 1000 else "red")
        table.add_row(
            row["topic"],
            str(row["partition"]),
            str(row["committed_offset"]) if row["committed_offset"] is not None else "never",
            str(row["high_watermark"]),
            f"[{colour}]{row['lag']:,}[/]",
        )
    console.print(table)
    console.print(f"  total lag: [bold]{total:,}[/] records")


if __name__ == "__main__":
    app()
