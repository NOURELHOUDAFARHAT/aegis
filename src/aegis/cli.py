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


@topics_app.command("apply")
def topics_apply(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show the drift, change nothing."),
) -> None:
    """Reconcile existing topics' settings with what topics.py declares.

    `topics create` only configures topics it creates. This command fixes
    topics that already exist but have drifted from the declaration - the
    Kafka equivalent of `terraform apply`.
    """
    from aegis.streaming.admin import apply_configs

    out = Table(title="Topic configuration" + (" (dry run)" if dry_run else ""))
    out.add_column("Topic", style="cyan", no_wrap=True)
    out.add_column("Result")

    changed = 0
    for name, outcome in sorted(apply_configs(dry_run=dry_run).items()):
        if outcome == "in sync":
            colour = "dim"
        elif outcome.startswith("error") or outcome == "missing":
            colour = "red"
        else:
            colour = "yellow"
            changed += 1
        out.add_row(name, f"[{colour}]{outcome}[/]")
    console.print(out)
    if changed and not dry_run:
        console.print(f"  [green]{changed} topic(s) reconciled.[/]")


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


# ===========================================================================
# Phase 3 - lakehouse commands
# ===========================================================================

lake_app = typer.Typer(help="Manage the Iceberg lakehouse.", no_args_is_help=True)
app.add_typer(lake_app, name="lake")


@lake_app.command("init")
def lake_init(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be created."),
) -> None:
    """Create the namespaces and Bronze tables. Safe to re-run."""
    from aegis.lakehouse.catalog import ensure_namespaces
    from aegis.lakehouse.tables import create_bronze_tables

    if not dry_run:
        namespaces = ensure_namespaces()
        console.print(f"  namespaces: [bold]{', '.join(namespaces)}[/]")
        console.print()

    out = Table(title="Bronze tables")
    out.add_column("Table", style="cyan")
    out.add_column("Result")
    for name, outcome in sorted(create_bronze_tables(dry_run=dry_run).items()):
        colour = {"created": "green", "exists": "dim", "would create": "yellow"}.get(outcome, "red")
        out.add_row(name, f"[{colour}]{outcome}[/]")
    console.print(out)


@lake_app.command("sync")
def lake_sync(
    source: str = typer.Argument("all", help="Source name, or 'all'."),
    from_beginning: bool = typer.Option(
        False,
        "--from-beginning",
        help="Re-read the entire topic instead of resuming. This is a replay.",
    ),
    batch_size: int = typer.Option(2000, "--batch-size", help="Rows per Iceberg commit."),
    idle: float = typer.Option(
        8.0, "--idle", help="Stop after this many seconds with no new messages."
    ),
) -> None:
    """Read Kafka and append to Bronze.

    Resumes from wherever it stopped last time, so running it twice does not
    redo work. Use --from-beginning to deliberately reprocess everything.
    """
    from aegis.lakehouse.tables import BRONZE_TABLES
    from aegis.lakehouse.writer import sync_all

    names = None if source == "all" else [source]
    if names and names[0] not in BRONZE_TABLES:
        console.print(f"[red]Unknown source '{source}'.[/]")
        console.print(f"Available: {', '.join(sorted(BRONZE_TABLES))}")
        raise typer.Exit(code=1)

    results = sync_all(
        names, from_beginning=from_beginning, batch_size=batch_size, idle_timeout=idle
    )

    out = Table(title="Bronze sync")
    out.add_column("Source", style="cyan")
    out.add_column("Table", style="dim")
    out.add_column("Read", justify="right")
    out.add_column("Written", justify="right")
    out.add_column("Batches", justify="right")
    out.add_column("Snapshots", justify="right")
    out.add_column("Status")

    for r in results:
        out.add_row(
            r.source,
            r.table,
            f"{r.rows_read:,}",
            f"{r.rows_written:,}",
            str(r.batches),
            f"+{r.snapshots_created}",
            "[green]ok[/]" if r.ok else f"[red]{r.errors[0][:40]}[/]",
        )
    console.print()
    console.print(out)

    if any(not r.ok for r in results):
        raise typer.Exit(code=1)


@lake_app.command("tables")
def lake_tables() -> None:
    """Show every Bronze table: rows, files, snapshots, size."""
    from aegis.lakehouse.writer import bronze_stats

    out = Table(title="Lakehouse - Bronze layer")
    out.add_column("Table", style="cyan")
    out.add_column("Rows", justify="right")
    out.add_column("Files", justify="right")
    out.add_column("Rows/file", justify="right")
    out.add_column("Size", justify="right")
    out.add_column("Snaps", justify="right")
    out.add_column("Last written", style="dim")

    for stats in bronze_stats():
        if stats.error:
            out.add_row(stats.table, "-", "-", "-", "-", "-", f"[red]{stats.error}[/]")
            continue
        # Flag the small-files problem before it becomes a performance issue.
        # Under a few hundred rows per file, a table is spending more time
        # opening files than reading them.
        density = stats.avg_rows_per_file
        colour = "green" if density >= 1000 else ("yellow" if density >= 200 else "red")
        out.add_row(
            stats.table,
            f"{stats.rows:,}",
            str(stats.files),
            f"[{colour}]{density:,.0f}[/]" if stats.files else "-",
            f"{stats.size_mb:.1f} MB",
            str(stats.snapshots),
            stats.last_updated.strftime("%Y-%m-%d %H:%M") if stats.last_updated else "-",
        )
    console.print(out)


@lake_app.command("history")
def lake_history(
    source: str = typer.Argument(..., help="Source name, e.g. feodo"),
) -> None:
    """Show a table's snapshots - every version it has ever had.

    Each row is a point in time you can query the table AS OF. That is time
    travel, and it is what makes a data incident investigable rather than
    guessed at.
    """
    from datetime import datetime, timezone

    from aegis.lakehouse.tables import load_bronze
    from aegis.lakehouse.writer import snapshot_summary

    table = load_bronze(source)
    current = table.current_snapshot()
    current_id = current.snapshot_id if current else None

    out = Table(title=f"Snapshot history - {'.'.join(table.name())}")
    out.add_column("", width=2)
    out.add_column("Snapshot ID", style="cyan")
    out.add_column("When", style="dim")
    out.add_column("Operation")
    out.add_column("Rows added", justify="right")
    out.add_column("Total rows", justify="right")

    for snap in table.metadata.snapshots:
        operation, summary = snapshot_summary(snap)
        when = datetime.fromtimestamp(snap.timestamp_ms / 1000, tz=timezone.utc)
        out.add_row(
            "[green]>[/]" if snap.snapshot_id == current_id else "",
            str(snap.snapshot_id),
            when.strftime("%Y-%m-%d %H:%M:%S"),
            operation,
            f"{int(summary.get('added-records', 0) or 0):,}",
            f"{int(summary.get('total-records', 0) or 0):,}",
        )
    console.print(out)
    console.print("  [dim]> marks the current version. Read an older one with:[/]")
    console.print(f"  [dim]aegis lake sample {source} --snapshot <ID>[/]")


@lake_app.command("sample")
def lake_sample(
    source: str = typer.Argument(..., help="Source name, e.g. feodo"),
    limit: int = typer.Option(3, "--limit", "-n"),
    snapshot: int | None = typer.Option(
        None, "--snapshot", help="Read the table as it was at this snapshot ID."
    ),
) -> None:
    """Print a few rows from a Bronze table, optionally as of an older snapshot."""
    import json as _json

    from aegis.lakehouse.tables import load_bronze

    table = load_bronze(source)
    if snapshot is not None:
        scan = table.scan(limit=limit, snapshot_id=snapshot)
        console.print(f"[yellow]Reading the table as it was at snapshot {snapshot}[/]")
        console.print()
    else:
        scan = table.scan(limit=limit)

    for i, row in enumerate(scan.to_arrow().to_pylist(), start=1):
        console.print(f"[bold cyan]#{i}[/]  {row['source']} / {row['event_type']}")
        console.print(f"  event_id    : {row['event_id']}")
        console.print(f"  occurred_at : {row['occurred_at']}")
        console.print(
            f"  from kafka  : {row['_kafka_topic']} "
            f"p{row['_kafka_partition']} offset {row['_kafka_offset']}"
        )
        try:
            payload = _json.dumps(_json.loads(row["payload"]), separators=(",", ":"))
        except Exception:
            payload = str(row["payload"])
        console.print(f"  payload     : {payload[:260]}")
        console.print()


@lake_app.command("sql")
def lake_sql(
    query: str = typer.Argument(..., help="SQL. Bronze tables are registered by short name."),
) -> None:
    """Run SQL against the Bronze tables with DuckDB.

    Each Bronze table is registered under its short name, so you write ordinary
    SQL:

        aegis lake sql "SELECT event_type, count(*) FROM cisa_kev GROUP BY 1"
    """
    import duckdb

    from aegis.lakehouse.tables import BRONZE_TABLES, load_bronze

    con = duckdb.connect()
    registered = []
    for name in BRONZE_TABLES:
        try:
            arrow = load_bronze(name).scan().to_arrow()
            con.register(name, arrow)
            registered.append(f"{name}({arrow.num_rows:,})")
        except Exception as exc:
            # A table that will not load should not stop the query - the other
            # tables may be exactly what the user asked about. But it must be
            # visible: a silently missing table makes a query return a wrong
            # answer that looks right.
            console.print(f"[yellow]  skipped {name}: {str(exc)[:90]}[/]")

    console.print(f"[dim]registered: {', '.join(registered)}[/]")
    console.print()
    try:
        # DuckDB renders its own result tables, so we do not need pandas just
        # to print. It draws with Unicode box characters, which the legacy
        # Windows codepage cannot encode - hence the stdout reconfigure.
        import sys

        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        con.sql(query).show(max_width=120, max_rows=40)
    except Exception as exc:
        console.print(f"[red]{str(exc)[:400]}[/]")
        raise typer.Exit(code=1) from exc


# ===========================================================================
# Phase 4 - modelling commands (dbt: Silver and Gold)
# ===========================================================================

model_app = typer.Typer(help="Build and query Silver and Gold with dbt.", no_args_is_help=True)
app.add_typer(model_app, name="model")

# Only these layers can be named from the command line. Validating the table
# identifier against a pattern - rather than pasting user input into SQL - is
# the difference between a query tool and an injection vector.
_TABLE_NAME = r"^(staging|silver|gold)\.[a-z][a-z0-9_]*$"


@model_app.command("build")
def model_build(
    select: str | None = typer.Option(
        None, "--select", "-s", help="dbt selector, e.g. 'silver' or 'gold.c2_infrastructure+'."
    ),
) -> None:
    """Build every model and run every data test, in dependency order.

    `dbt build` interleaves them: a model's tests run right after the model is
    built, and a failing test stops everything downstream of it. So a broken
    Silver table can never feed a Gold table.
    """
    from aegis.modeling.dbt_runner import run_dbt

    args = ["build"]
    if select:
        args += ["--select", select]
    if not run_dbt(args):
        console.print("[red]dbt build failed - see the output above.[/]")
        raise typer.Exit(code=1)
    console.print("[green]All models built and all data tests passed.[/]")


@model_app.command("test")
def model_test() -> None:
    """Run the data tests only, against the tables that already exist."""
    from aegis.modeling.dbt_runner import run_dbt

    if not run_dbt(["test"]):
        raise typer.Exit(code=1)


@model_app.command("docs")
def model_docs() -> None:
    """Generate dbt's documentation site, including the lineage graph."""
    from aegis.modeling.dbt_runner import DBT_DIR, run_dbt

    if not run_dbt(["docs", "generate"]):
        raise typer.Exit(code=1)
    console.print(f"Docs written to [cyan]{DBT_DIR / 'target' / 'index.html'}[/]")
    console.print("Serve them with:  [dim]cd dbt; dbt docs serve --port 8089[/]")


@model_app.command("show")
def model_show(
    table: str = typer.Argument(..., help="e.g. gold.vendor_exploitation"),
    limit: int = typer.Option(15, "--limit", "-n"),
) -> None:
    """Print rows from a Silver or Gold table."""
    import re

    if not re.match(_TABLE_NAME, table):
        console.print("[red]Table must look like silver.name or gold.name.[/]")
        raise typer.Exit(code=1)
    # S608 is suppressed on this line only, deliberately. SQL identifiers such
    # as table names cannot be passed as bound parameters, so the defence is
    # validation, not binding: `table` has just been matched against
    # _TABLE_NAME (a fixed layer prefix and [a-z0-9_] only) and `limit` is cast
    # to int. tests/test_modeling.py proves the pattern rejects injection input.
    _warehouse_query(f"SELECT * FROM {table} LIMIT {int(limit)}")  # noqa: S608


@model_app.command("sql")
def model_sql(query: str = typer.Argument(..., help="SQL against the warehouse.")) -> None:
    """Run ad-hoc SQL against Silver and Gold (read-only)."""
    _warehouse_query(query)


def _warehouse_query(query: str) -> None:
    """Run a query against the warehouse file in READ-ONLY mode.

    Read-only matters: a query tool should never be able to modify the tables
    that dbt owns, and it lets inspection run while a build holds the file.
    """
    import sys

    import duckdb

    from aegis.modeling.dbt_runner import warehouse_path

    path = warehouse_path()
    if not path.exists():
        console.print("[yellow]No warehouse yet. Run:  aegis model build[/]")
        raise typer.Exit(code=1)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    con = duckdb.connect(str(path), read_only=True)
    try:
        con.sql(query).show(max_width=140, max_rows=50)
    except Exception as exc:
        console.print(f"[red]{str(exc)[:400]}[/]")
        raise typer.Exit(code=1) from exc
    finally:
        con.close()


if __name__ == "__main__":
    app()
