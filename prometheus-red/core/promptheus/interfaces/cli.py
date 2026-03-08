from __future__ import annotations

import json
import os
import sys
import types

import typer
from rich import print as rprint

from promptheus.adapters.rest import RestAdapter
from promptheus.core.engine import run_attack
from promptheus.core.judge import Judge


app = typer.Typer(help="PROMPTHEUS CLI (Steps 1-5)")


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


def _run(
    target_url: str | None,
    objective: str,
    skill: str,
    attempts: int,
    offline: bool,
    json_output: bool,
):
    no_api_key = not os.getenv("OPENAI_API_KEY")

    if offline or not target_url or no_api_key:
        adapter = DummyAdapter()
        attack_client = OfflineClient("offline-payload")
        judge_client = OfflineClient('{"is_vulnerable": false, "reason": "offline", "severity": "low"}')
        if not json_output:
            if no_api_key and not offline:
                print("[yellow]No OPENAI_API_KEY set[/yellow]: falling back to offline stub.")
            else:
                print("[yellow]Offline mode[/yellow]: using dummy adapter and stubbed LLMs.")
    else:
        adapter = RestAdapter(target_url)
        attack_client = None
        judge_client = None

    judge = Judge(client=judge_client)
    session = run_attack(
        adapter=adapter,
        skill=skill,
        objective=objective,
        judge=judge,
        max_attempts=attempts,
        client=attack_client,
    )

    if json_output:
        sys.stdout.write(json.dumps(session.to_json()) + "\n")
        sys.stdout.flush()
    else:
        rprint("[green]Session complete[/green]")
        rprint(session.to_json())


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    target_url: str = typer.Option(None, "--target-url", "-u", help="Target REST endpoint"),
    objective: str = typer.Option(
        None, "--objective", "-o", help="Attack objective (required unless using subcommands)"
    ),
    skill: str = typer.Option("grandma", "--skill", "-s", help="Skill name"),
    attempts: int = typer.Option(1, "--attempts", "-n", min=1, help="Max attempts"),
    offline: bool = typer.Option(False, "--offline", help="Use dummy adapter and stubbed clients"),
    json_output: bool = typer.Option(False, "--json-output", help="Print session as JSON only"),
):
    """Run an attack loop. If no subcommand is provided, this acts as the default."""
    # If no command and no objective, just show help.
    if ctx.invoked_subcommand is None:
        if objective is None:
            typer.echo(ctx.get_help())
            raise typer.Exit(code=0)
        _run(target_url, objective, skill, attempts, offline, json_output)


@app.command(help="Explicit attack command (same as top-level).")
def attack(
    target_url: str = typer.Option(None, "--target-url", "-u", help="Target REST endpoint"),
    objective: str = typer.Option(..., "--objective", "-o", help="Attack objective"),
    skill: str = typer.Option("grandma", "--skill", "-s", help="Skill name"),
    attempts: int = typer.Option(1, "--attempts", "-n", min=1, help="Max attempts"),
    offline: bool = typer.Option(False, "--offline", help="Use dummy adapter and stubbed clients"),
    json_output: bool = typer.Option(False, "--json-output", help="Print session as JSON only"),
):
    _run(target_url, objective, skill, attempts, offline, json_output)


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

    _run(target_url, objective, skill, attempts, offline, False)


if __name__ == "__main__":
    app()
