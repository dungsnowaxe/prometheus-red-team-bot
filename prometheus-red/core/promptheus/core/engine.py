from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from promptheus.adapters.base import TargetAdapter
from promptheus.core.attacks import load_payloads
from promptheus.core.judge import evaluate_response


@dataclass
class ScanResult:
    """Single payload result."""

    payload_id: str
    name: str
    prompt: str
    response: str
    vulnerable: bool
    reasoning: str
    severity: str


@dataclass
class Report:
    """Aggregated scan report."""

    results: list[ScanResult] = field(default_factory=list)

    def add(self, r: ScanResult) -> None:
        self.results.append(r)

    def to_json(self) -> str:
        """Convert to JSON string."""
        data = {
            "results": [
                {
                    "payload_id": r.payload_id,
                    "name": r.name,
                    "vulnerable": r.vulnerable,
                    "severity": r.severity,
                    "reasoning": r.reasoning,
                }
                for r in self.results
            ]
        }
        return json.dumps(data)


class RedTeamEngine:
    """Run payloads via a TargetAdapter and judge responses."""

    def __init__(self, adapter: TargetAdapter):
        self.adapter = adapter

    def run_scan(
        self,
        payloads: list[dict[str, Any]] | None = None,
        *,
        verbose_console: bool = True,
    ) -> Report:
        if payloads is None:
            payloads = load_payloads()
        report = Report()
        console = Console()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(payloads))
            for p in payloads:
                payload_id = p.get("id", "unknown")
                name = p.get("name", payload_id)
                prompt = p.get("prompt", "")
                judge_expectation = p.get("judge_expectation", "")
                progress.update(task, description=f"[{payload_id}] {name[:40]}...")
                try:
                    response = self._send_prompt(prompt)
                except Exception as e:
                    response = f"[Adapter error: {e}]"
                result_judge = evaluate_response(prompt, response, judge_expectation)
                scan_result = ScanResult(
                    payload_id=payload_id,
                    name=name,
                    prompt=prompt,
                    response=response[:500] + ("..." if len(response) > 500 else ""),
                    vulnerable=result_judge.vulnerable,
                    reasoning=result_judge.reasoning,
                    severity=result_judge.severity,
                )
                report.add(scan_result)
                if verbose_console:
                    status = "[red]Vulnerable[/red]" if result_judge.vulnerable else "[green]Safe[/green]"
                    console.print(f"  {status} {name} ({result_judge.severity})")
                progress.advance(task)

        if verbose_console:
            self._print_summary(console, report)
        return report

    def _send_prompt(self, prompt: str) -> str:
        # Backward compatible with older adapters using send_message.
        if hasattr(self.adapter, "send_prompt"):
            return self.adapter.send_prompt(prompt)
        return self.adapter.send_message(prompt)

    def _print_summary(self, console: Console, report: Report) -> None:
        table = Table(title="Scan Report")
        table.add_column("Payload", style="cyan")
        table.add_column("Verdict", style="bold")
        table.add_column("Severity")
        table.add_column("Reasoning", overflow="fold")
        for r in report.results:
            verdict = "[red]Vulnerable[/red]" if r.vulnerable else "[green]Safe[/green]"
            table.add_row(r.name, verdict, r.severity, r.reasoning[:500] or "-")
        console.print(table)
