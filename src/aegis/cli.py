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
        else:
            sink = JsonlFileSink(
                base_dir=Path(out) if out else Path(settings.data_dir) / "raw",
                source=name,
                run_id=collector.run_id,
            )

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


if __name__ == "__main__":
    app()
