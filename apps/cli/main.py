"""Typer CLI with first-run wizard, init, config show, and scan commands."""

import typer
from rich.console import Console
from rich.table import Table

from promptheus.adapters.rest import RestAPITarget
from promptheus.config import get_resolved_config_display, reload_config
from promptheus.config_store import config_exists
from promptheus.core.engine import RedTeamEngine

from apps.cli.wizard import run_wizard

app = typer.Typer(help="PROMPTHEUS Red-Team CLI")
config_app = typer.Typer(help="View or manage saved configuration")
app.add_typer(config_app, name="config")


def _ensure_configured() -> None:
    """If no config file exists, launch the setup wizard automatically."""
    if config_exists():
        return
    run_wizard()
    reload_config()


def _run_scan(target_url: str) -> None:
    _ensure_configured()
    adapter = RestAPITarget(target_url)
    engine = RedTeamEngine(adapter)
    engine.run_scan()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    target_url: str = typer.Option(None, "--target-url", "-u", help="Target API URL to scan"),
):
    """PROMPTHEUS — Red-team security auditing for AI targets."""
    if ctx.invoked_subcommand is not None:
        return
    if target_url is None:
        typer.echo("Use: promptheus scan --target-url <url>", err=True)
        typer.echo("     promptheus init           (setup wizard)", err=True)
        typer.echo("     promptheus config show     (view config)", err=True)
        raise typer.Exit(1)
    _run_scan(target_url)


@app.command("scan")
def scan_cmd(
    target_url: str = typer.Option(..., "--target-url", "-u", help="Target API URL to scan"),
):
    """Run red-team scan against target URL (REST API)."""
    _run_scan(target_url)


@app.command("init")
def init_cmd():
    """Run the setup wizard to choose AI provider and enter credentials."""
    run_wizard()
    reload_config()


@config_app.command("show")
def config_show_cmd():
    """Display the current resolved configuration (API key masked)."""
    info = get_resolved_config_display()
    console = Console()
    table = Table(title="PROMPTHEUS Config", show_header=True)
    table.add_column("Key", style="cyan")
    table.add_column("Value")
    for k, v in info.items():
        table.add_row(k, v)
    console.print(table)


def run_app() -> None:
    app()


if __name__ == "__main__":
    run_app()
