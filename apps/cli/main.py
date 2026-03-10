"""Typer CLI with first-run wizard, config show, and scan commands."""

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from promptheus.adapters.rest import RestAPITarget
from promptheus.config import get_resolved_config_display, reload_config
from promptheus.config_store import config_exists
from promptheus.core.engine import RedTeamEngine
from promptheus.scanner import Scanner
from promptheus.scanner.scanner import _EstimateCostExit

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


def _run_agent_scan(
    target_path: str,
    *,
    model: str,
    debug: bool,
    dast: bool,
    dast_url: str | None,
    confirm_large_scan: bool = False,
    estimate_cost: bool = False,
) -> None:
    scanner = Scanner(
        model=model,
        debug=debug,
        confirm_large_scan=confirm_large_scan,
        estimate_cost_only=estimate_cost,
    )
    if dast:
        if not dast_url:
            raise typer.BadParameter("--dast-url is required when --dast is enabled")
        scanner.configure_dast(dast_url)
    try:
        asyncio.run(scanner.scan(target_path))
    except _EstimateCostExit:
        raise typer.Exit(0)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    target_url: str = typer.Option(None, "--target-url", "-u", help="Target API URL to scan"),
    target_path: str = typer.Option(None, "--target-path", help="Repository path for agent scanning"),
    mode: str = typer.Option("legacy", "--mode", help="Scan mode: legacy or agent"),
    model: str = typer.Option("sonnet", "--model", help="Model for agent scanning"),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose agent scan output"),
    dast: bool = typer.Option(False, "--dast", help="Enable DAST validation in agent mode"),
    dast_url: str = typer.Option(None, "--dast-url", help="Target URL for DAST validation"),
    confirm_large_scan: bool = typer.Option(
        False, "--confirm-large-scan", help="Proceed even when repo exceeds PROMPTHEUS_MAX_SCAN_FILES / MAX_REPO_MB"
    ),
    estimate_cost: bool = typer.Option(
        False, "--estimate-cost", help="Print rough cost estimate for agent scan and exit (no API call)"
    ),
):
    """PROMPTHEUS — Red-team security auditing for AI targets."""
    if ctx.invoked_subcommand is not None:
        return
    if mode == "agent":
        if target_path is None:
            typer.echo("Use: promptheus scan --mode agent --target-path <path>", err=True)
            raise typer.Exit(1)
        _run_agent_scan(
            target_path,
            model=model,
            debug=debug,
            dast=dast,
            dast_url=dast_url,
            confirm_large_scan=ctx.params.get("confirm_large_scan", False),
            estimate_cost=ctx.params.get("estimate_cost", False),
        )
        return
    if target_url is None:
        typer.echo("Use: promptheus scan --target-url <url>", err=True)
        typer.echo("     promptheus scan --mode agent --target-path <path>", err=True)
        typer.echo("     promptheus init           (setup wizard)", err=True)
        typer.echo("     promptheus config show     (view config)", err=True)
        raise typer.Exit(1)
    _run_scan(target_url)


@app.command("scan")
def scan_cmd(
    target_url: str = typer.Option(None, "--target-url", "-u", help="Target API URL for legacy scanning"),
    target_path: str = typer.Option(None, "--target-path", help="Repository path for agent scanning"),
    mode: str = typer.Option("legacy", "--mode", help="Scan mode: legacy or agent"),
    model: str = typer.Option("sonnet", "--model", help="Model for agent scanning"),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose agent scan output"),
    dast: bool = typer.Option(False, "--dast", help="Enable DAST validation in agent mode"),
    dast_url: str = typer.Option(None, "--dast-url", help="Target URL for DAST validation"),
    confirm_large_scan: bool = typer.Option(
        False, "--confirm-large-scan", help="Proceed when repo exceeds file/size limits"
    ),
    estimate_cost: bool = typer.Option(False, "--estimate-cost", help="Print cost estimate and exit (agent mode)"),
):
    """Run a PROMPTHEUS scan in legacy or agent mode."""
    if mode == "agent":
        if target_path is None:
            raise typer.BadParameter("--target-path is required when --mode agent is used")
        _run_agent_scan(
            target_path,
            model=model,
            debug=debug,
            dast=dast,
            dast_url=dast_url,
            confirm_large_scan=confirm_large_scan,
            estimate_cost=estimate_cost,
        )
        return

    if target_url is None:
        raise typer.BadParameter("--target-url is required when --mode legacy is used")
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
