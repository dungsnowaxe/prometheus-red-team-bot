from __future__ import annotations

import json
import logging
import os
import sys
import types
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import typer
from openai import OpenAI
from rich import print as rprint
from dotenv import load_dotenv, find_dotenv

from promptheus.adapters.rest import RestAdapter
from promptheus.core.engine import RedTeamEngine
from promptheus.core.attack_runner import run_attack
from promptheus.core.attacks import load_payloads
from promptheus.core.judge import Judge
from promptheus.config import (
    get_attacker_api_key,
    get_attacker_base_url,
    get_attacker_model,
    get_judge_api_key,
    get_judge_base_url,
    get_judge_model,
    get_judge_max_tokens,
)

# Auto-load .env from current working directory if present.
load_dotenv(find_dotenv(usecwd=True))

app = typer.Typer(help="PROMPTHEUS CLI (Steps 1-5)")


class PayloadSet(str, Enum):
    standard = "standard"
    extended = "extended"


class DummyAdapter:
    name = "dummy"

    def send_message(self, payload: str) -> str:
        return f"(offline dummy) {payload}"


class OfflineClient:
    """Stub OpenAI client shape to avoid real calls."""

    def __init__(self, content: str):
        self._content = content
        self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self._create))

    def _create(self, *_, **__):
        class Completion:
            def __init__(self, content: str):
                self.choices = [types.SimpleNamespace(message=types.SimpleNamespace(content=content))]

        return Completion(self._content)


def _configure_logging(log_file: Path | None, verbose: bool) -> logging.Logger | None:
    if log_file is None:
        return None
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("promptheus")
    if logger.handlers:
        return logger
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setLevel(level)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def _parse_skills(skills: str | None, skill: str) -> list[str]:
    if skills:
        items = [s.strip() for s in skills.split(",") if s.strip()]
        if items:
            return items
    return [skill]


def _save_report_json(content: str, *, prefix: str) -> Path:
    reports_dir = Path(__file__).resolve().parents[1] / "data" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = reports_dir / f"{prefix}_{ts}.json"
    out_path.write_text(content, encoding="utf-8")
    return out_path


def _load_payloads_for_set(payloads_set: PayloadSet, payloads_file: Path | None) -> list[dict]:
    base_dir = Path(__file__).resolve().parents[1] / "core" / "attacks"
    if payloads_file is not None:
        payloads_path = payloads_file
        if not payloads_path.is_file():
            raise typer.BadParameter(f"Payloads file not found: {payloads_path}")
    elif payloads_set == PayloadSet.extended:
        payloads_path = base_dir / "payloads_extended.json"
    else:
        payloads_path = base_dir / "payloads.json"
    return load_payloads(payloads_path)


def _run_attack(
    target_url: str | None,
    objective: str,
    skill: str,
    skills: str | None,
    attempts: int,
    offline: bool,
    json_output: bool,
    save_report: bool,
    no_save: bool,
    dry_run: bool,
    log_file: Path | None,
    verbose: bool,
) -> None:
    logger = _configure_logging(log_file, verbose)
    attacker_api_key = get_attacker_api_key()
    attacker_base_url = get_attacker_base_url()
    attacker_model = get_attacker_model()
    attacker_ready = bool(attacker_api_key or attacker_base_url)

    skill_list = _parse_skills(skills, skill)
    if verbose and not json_output:
        rprint(f"[cyan]Running {len(skill_list)} skills[/cyan]")
    if dry_run:
        if json_output:
            sys.stdout.write(json.dumps({"objective": objective, "skills": skill_list}) + "\n")
            sys.stdout.flush()
        else:
            rprint("[cyan]Dry run[/cyan]: no network calls will be made.")
            rprint(f"Objective: {objective}")
            rprint(f"Skills: {', '.join(skill_list)}")
        if logger:
            logger.info("dry_run attack objective=%s skills=%s", objective, ",".join(skill_list))
        return

    if offline or not target_url:
        adapter = DummyAdapter()
        attack_client = OfflineClient("offline-payload")
        judge_client = OfflineClient('{"is_vulnerable": false, "reason": "offline", "severity": "low"}')
        if not json_output:
            print("[yellow]Offline mode[/yellow]: using dummy adapter and stubbed LLMs.")
    else:
        adapter = RestAdapter(target_url)
        if attacker_ready:
            kwargs = {}
            if attacker_api_key:
                kwargs["api_key"] = attacker_api_key
            if attacker_base_url:
                kwargs["base_url"] = attacker_base_url
            attack_client = OpenAI(**kwargs)
        else:
            attack_client = OfflineClient("offline-payload")
            if not json_output:
                print("[yellow]No attacker API key/base URL set[/yellow]: using offline payload stub.")
        judge_client = None

    judge = Judge(client=judge_client)
    sessions = []
    for idx, skill_name in enumerate(skill_list, start=1):
        if not json_output and len(skill_list) > 1:
            rprint(f"[cyan]Skill {idx}/{len(skill_list)}:[/cyan] {skill_name}")
        session = run_attack(
            adapter=adapter,
            skill=skill_name,
            objective=objective,
            judge=judge,
            max_attempts=attempts,
            client=attack_client,
            model=attacker_model,
            verbose_console=not json_output,
            save_session=not no_save,
        )
        sessions.append(session)

    if json_output:
        if len(sessions) == 1:
            sys.stdout.write(json.dumps(sessions[0].to_json()) + "\n")
        else:
            sys.stdout.write(json.dumps({"sessions": [s.to_json() for s in sessions]}) + "\n")
        sys.stdout.flush()
    else:
        rprint("[green]Session complete[/green]")

    if save_report:
        content = json.dumps({"sessions": [s.to_json() for s in sessions]}) if len(sessions) > 1 else json.dumps(sessions[0].to_json())
        out_path = _save_report_json(content, prefix="attack_report")
        if not json_output:
            rprint(f"[cyan]Report saved:[/cyan] {out_path}")
        if logger:
            logger.info("attack_report_saved path=%s", out_path)


def _run_scan(
    target_url: str,
    json_output: bool,
    payloads_set: PayloadSet,
    payloads_file: Path | None,
    max_payloads: int | None,
    save_report: bool,
    dry_run: bool,
    log_file: Path | None,
    verbose: bool,
) -> None:
    logger = _configure_logging(log_file, verbose)
    adapter = RestAdapter(target_url)
    engine = RedTeamEngine(adapter)
    payloads = _load_payloads_for_set(payloads_set, payloads_file)
    if max_payloads is not None:
        payloads = payloads[:max_payloads]

    if dry_run:
        if json_output:
            sys.stdout.write(json.dumps({"payloads": payloads}) + "\n")
            sys.stdout.flush()
        else:
            rprint("[cyan]Dry run[/cyan]: no network calls will be made.")
            rprint(f"Payloads: {len(payloads)}")
            for p in payloads:
                rprint(f"- {p.get('id', 'unknown')}: {p.get('name', '')}")
        if logger:
            logger.info("dry_run scan payloads=%d", len(payloads))
        return

    if verbose and not json_output:
        rprint(f"[cyan]Running {len(payloads)} payloads[/cyan]")

    report = engine.run_scan(payloads=payloads, verbose_console=not json_output)
    if json_output:
        sys.stdout.write(report.to_json() + "\n")
        sys.stdout.flush()
    if save_report:
        out_path = _save_report_json(report.to_json(), prefix="scan_report")
        if not json_output:
            rprint(f"[cyan]Report saved:[/cyan] {out_path}")
        if logger:
            logger.info("scan_report_saved path=%s", out_path)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    target_url: str = typer.Option(None, "--target-url", "-u", help="Target REST endpoint"),
    objective: str = typer.Option(
        None, "--objective", "-o", help="Attack objective (required unless using subcommands)"
    ),
    skill: str = typer.Option("grandma", "--skill", "-s", help="Skill name"),
    skills: str = typer.Option(None, "--skills", help="Comma-separated skill list (overrides --skill)"),
    attempts: int = typer.Option(1, "--attempts", "-n", min=1, help="Max attempts"),
    offline: bool = typer.Option(False, "--offline", help="Use dummy adapter and stubbed clients"),
    json_output: bool = typer.Option(False, "--json-output", help="Print session as JSON only"),
    save_report: bool = typer.Option(False, "--save-report", help="Save report JSON to promptheus/data/reports/"),
    no_save: bool = typer.Option(False, "--no-save", help="Do not write attack session files"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print planned actions without running"),
    log_file: Path | None = typer.Option(None, "--log-file", help="Write logs to a file"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logging"),
):
    """Run an attack loop. If no subcommand is provided, this acts as the default."""
    if ctx.invoked_subcommand is None:
        if objective is None:
            typer.echo(ctx.get_help())
            raise typer.Exit(code=0)
        _run_attack(target_url, objective, skill, skills, attempts, offline, json_output, save_report, no_save, dry_run, log_file, verbose)


@app.command(help="Explicit attack command (same as top-level).")
def attack(
    target_url: str = typer.Option(None, "--target-url", "-u", help="Target REST endpoint"),
    objective: str = typer.Option(..., "--objective", "-o", help="Attack objective"),
    skill: str = typer.Option("grandma", "--skill", "-s", help="Skill name"),
    skills: str = typer.Option(None, "--skills", help="Comma-separated skill list (overrides --skill)"),
    attempts: int = typer.Option(1, "--attempts", "-n", min=1, help="Max attempts"),
    offline: bool = typer.Option(False, "--offline", help="Use dummy adapter and stubbed clients"),
    json_output: bool = typer.Option(False, "--json-output", help="Print session as JSON only"),
    save_report: bool = typer.Option(False, "--save-report", help="Save report JSON to promptheus/data/reports/"),
    no_save: bool = typer.Option(False, "--no-save", help="Do not write attack session files"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print planned actions without running"),
    log_file: Path | None = typer.Option(None, "--log-file", help="Write logs to a file"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logging"),
):
    _run_attack(target_url, objective, skill, skills, attempts, offline, json_output, save_report, no_save, dry_run, log_file, verbose)


@app.command(help="Payload-based scan (rubric judge).")
def scan(
    target_url: str = typer.Option(..., "--target-url", "-u", help="Target REST endpoint"),
    json_output: bool = typer.Option(False, "--json-output", help="Print report as JSON only"),
    payloads_set: PayloadSet = typer.Option(PayloadSet.standard, "--payloads-set", help="Payload set: standard|extended"),
    payloads_file: Path | None = typer.Option(None, "--payloads-file", help="Path to payloads JSON file"),
    max_payloads: int | None = typer.Option(None, "--max-payloads", min=1, help="Limit number of payloads"),
    save_report: bool = typer.Option(False, "--save-report", help="Save report JSON to promptheus/data/reports/"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print planned actions without running"),
    log_file: Path | None = typer.Option(None, "--log-file", help="Write logs to a file"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logging"),
):
    _run_scan(target_url, json_output, payloads_set, payloads_file, max_payloads, save_report, dry_run, log_file, verbose)


@app.command(help="Interactive wizard that walks you through required inputs.")
def wizard():
    print("[cyan]PROMPTHEUS attack wizard[/cyan]")
    mode = typer.prompt("Target mode [offline/rest]", default="offline").strip().lower()
    if mode == "rest":
        target_url = typer.prompt("Target REST URL (e.g., https://example.com/llm)").strip()
        offline = False
    else:
        target_url = None
        offline = True

    objective = typer.prompt("Objective (what to obtain)").strip()
    skill = typer.prompt("Skill [grandma/json_leak]", default="grandma").strip() or "grandma"
    attempts = int(typer.prompt("Max attempts", default="1"))

    _run_attack(target_url, objective, skill, None, attempts, offline, False, False, False, False, None, False)


@app.command(help="Show resolved judge configuration (masked).")
def config_show():
    api_key = get_judge_api_key()
    base_url = get_judge_base_url() or ""
    model = get_judge_model()
    max_tokens = get_judge_max_tokens()
    masked = ""
    if api_key:
        masked = api_key[:6] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
    rprint("[cyan]PROMPTHEUS Judge Config[/cyan]")
    rprint(f"JUDGE_BASE_URL={base_url or '-'}")
    rprint(f"JUDGE_MODEL={model}")
    rprint(f"JUDGE_MAX_TOKENS={max_tokens if max_tokens is not None else '-'}")
    rprint(f"JUDGE_API_KEY={masked or '-'}")
    rprint("[cyan]ATTACKER[/cyan]: uses judge config by default")


@app.command(help="Validate config and show missing keys.")
def config_check():
    judge_key = get_judge_api_key()
    judge_base = get_judge_base_url()
    rprint("[cyan]Config Check[/cyan]")
    if judge_key or judge_base:
        rprint("[green]Judge: OK[/green]")
    else:
        rprint("[yellow]Judge: missing API key/base URL[/yellow]")
        rprint("Set PROMPTHEUS_JUDGE_API_KEY and PROMPTHEUS_JUDGE_BASE_URL")
    rprint("[green]Attacker: OK[/green] (uses judge config)")


if __name__ == "__main__":
    app()
