"""Tests for PROMPTHEUS scanner imports and CLI dispatch."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from typer.testing import CliRunner

from apps.cli.main import app


runner = CliRunner()


def test_promptheus_scanner_import_and_instantiation() -> None:
    from promptheus.scanner import Scanner

    scanner = Scanner(model="haiku", debug=True)

    assert scanner.model == "haiku"
    assert scanner.debug is True


def test_cli_agent_mode_dispatches_to_promptheus_scanner(
    monkeypatch,
    minimal_repo: Path,
) -> None:
    calls: dict[str, object] = {}

    @dataclass
    class FakeScanResult:
        repository_path: str
        issues: list
        files_scanned: int
        scan_time_seconds: float
        total_cost_usd: float

    class FakeScanner:
        def __init__(
            self,
            model: str = "sonnet",
            debug: bool = False,
            confirm_large_scan: bool = False,
            estimate_cost_only: bool = False,
            **kwargs: object,
        ):
            calls["model"] = model
            calls["debug"] = debug

        async def scan(self, repo_path: str):
            calls["repo_path"] = repo_path
            return FakeScanResult(
                repository_path=repo_path,
                issues=[],
                files_scanned=1,
                scan_time_seconds=0.01,
                total_cost_usd=0.0,
            )

    monkeypatch.setattr("apps.cli.main.Scanner", FakeScanner)
    monkeypatch.setattr("apps.cli.main.config_exists", lambda: True)

    result = runner.invoke(
        app,
        [
            "scan",
            "--mode",
            "agent",
            "--target-path",
            str(minimal_repo),
            "--model",
            "haiku",
            "--debug",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls["model"] == "haiku"
    assert calls["debug"] is True
    assert calls["repo_path"] == str(minimal_repo)
