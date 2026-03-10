"""Typer CLI with first-run wizard, config show, scan, and pr-review commands."""

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from promptheus.adapters.rest import RestAPITarget
from promptheus.config import get_resolved_config_display, reload_config
from promptheus.config_store import config_exists
from promptheus.core.engine import RedTeamEngine
from promptheus.diff import get_diff_from_commit_list, get_diff_from_commits, get_last_n_commits, parse_unified_diff
from promptheus.diff.parser import DiffContext
from promptheus.scanner import Scanner
from promptheus.scanner.scanner import _EstimateCostExit

from apps.cli.wizard import run_wizard

app = typer.Typer(help="PROMPTHEUS Red-Team CLI")


def _build_diff_context(repo_path: str, commit_range: str | None, last_n: int | None):
    """Build DiffContext from git. Exactly one of commit_range or last_n must be set."""
    from pathlib import Path

    repo = Path(repo_path).resolve()
    if not repo.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
    if commit_range and last_n is not None:
        raise typer.BadParameter("Use either --range or --last, not both")
    if not commit_range and last_n is None:
        raise typer.BadParameter("Provide either --range <base..head> or --last <N>")

    if last_n is not None:
        commits = get_last_n_commits(repo, last_n)
        diff_content = get_diff_from_commit_list(repo, commits) if commits else ""
    else:
        diff_content = get_diff_from_commits(repo, commit_range)

    return parse_unified_diff(diff_content) if diff_content.strip() else DiffContext(
        files=[], added_lines=0, removed_lines=0, changed_files=[]
    )


config_app = typer.Typer(help="View or manage saved configuration")
app.add_typer(config_app, name="config")


def _ensure_configured() -> None:
    """If no config file exists, launch the setup wizard automatically."""
    if config_exists():
        return
    run_wizard()
    reload_config()


def _run_scan(target_url: str, *, output: str = "text") -> None:
    _ensure_configured()
    adapter = RestAPITarget(target_url)
    engine = RedTeamEngine(adapter)
    report = engine.run_scan(verbose_console=(output != "json"))
    if output == "json":
        typer.echo(report.to_json())


def _run_agent_scan(
    target_path: str,
    *,
    model: str,
    debug: bool,
    dast: bool,
    dast_url: str | None,
    confirm_large_scan: bool = False,
    estimate_cost: bool = False,
    output: str = "text",
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
        result = asyncio.run(scanner.scan(target_path))
        if output == "json":
            typer.echo(result.to_json())
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
    output: str = typer.Option("text", "--output", help="Output format for legacy URL scan: text or json"),
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
            confirm_large_scan=confirm_large_scan,
            estimate_cost=estimate_cost,
            output=output,
        )
        return
    if target_url is None:
        typer.echo("Use: promptheus scan --target-url <url>", err=True)
        typer.echo("     promptheus scan --mode agent --target-path <path>", err=True)
        typer.echo("     promptheus init           (setup wizard)", err=True)
        typer.echo("     promptheus config show     (view config)", err=True)
        raise typer.Exit(1)
    _run_scan(target_url, output=output)


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
    output: str = typer.Option(
        "text", "--output", help="Output format: for legacy URL scan or agent scan use text or json"
    ),
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
            output=output,
        )
        return

    if target_url is None:
        raise typer.BadParameter("--target-url is required when --mode legacy is used")
    _run_scan(target_url, output=output)


@app.command("pr-review")
def pr_review_cmd(
    path: str = typer.Option(..., "--path", "-p", help="Repository path to review"),
    commit_range: str = typer.Option(None, "--range", "-r", help="Commit range (e.g. main..feature)"),
    last_n: int = typer.Option(None, "--last", "-n", help="Review last N commits instead of a range"),
    output: str = typer.Option("text", "--output", "-o", help="Output format: text or json"),
    model: str = typer.Option("sonnet", "--model", help="Model for PR review"),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose output"),
    severity_threshold: str = typer.Option(
        "info", "--severity", "-s", help="Minimum severity to report (info, low, medium, high, critical)"
    ),
):
    """Run PR/code security review on a repository (diff or last N commits).

    Exit codes: 0 = success, 1 = invalid args or scan failure.
    With --output json, prints a single JSON object to stdout with keys:
    repository_path, issues (list of findings), files_scanned, scan_time_seconds,
    total_cost_usd, summary (total/critical/high/medium/low), optional warnings.
    """
    _ensure_configured()
    if not path:
        raise typer.BadParameter("--path is required")
    diff_context = _build_diff_context(path, commit_range, last_n)
    scanner = Scanner(model=model, debug=debug)
    try:
        result = asyncio.run(
            scanner.pr_review(
                path,
                diff_context,
                severity_threshold=severity_threshold,
                update_artifacts=True,
            )
        )
    except (ValueError, RuntimeError) as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    if output == "json":
        typer.echo(result.to_json())
    else:
        console = Console()
        if result.issues:
            table = Table(title="PR review findings", show_header=True)
            table.add_column("Severity", style="cyan")
            table.add_column("Title")
            table.add_column("File")
            table.add_column("Line")
            for i in result.issues:
                table.add_row(
                    i.severity.value,
                    i.title,
                    i.file_path or "-",
                    str(i.line_number),
                )
            console.print(table)
        else:
            console.print("No findings.")
        if result.warnings:
            for w in result.warnings:
                console.print(f"[yellow]{w}[/yellow]")


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
