"""Integration tests for PROMPTHEUS CLI (apps/cli/main.py)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apps.cli.main import app


runner = CliRunner()


class TestCLIScanLegacyMode:
    def test_legacy_mode_requires_target_url(self, monkeypatch):
        monkeypatch.setattr("apps.cli.main.config_exists", lambda: True)
        result = runner.invoke(app, ["scan", "--mode", "legacy"])
        assert result.exit_code != 0

    def test_legacy_mode_with_url(self, monkeypatch):
        calls = {}

        def fake_run_scan(target_url):
            calls["url"] = target_url

        monkeypatch.setattr("apps.cli.main.config_exists", lambda: True)
        monkeypatch.setattr("apps.cli.main._run_scan", fake_run_scan)

        result = runner.invoke(app, [
            "scan", "--mode", "legacy", "--target-url", "https://api.example.com/chat",
        ])
        assert result.exit_code == 0
        assert calls["url"] == "https://api.example.com/chat"


class TestCLIScanAgentMode:
    def test_agent_mode_requires_target_path(self, monkeypatch):
        monkeypatch.setattr("apps.cli.main.config_exists", lambda: True)
        result = runner.invoke(app, ["scan", "--mode", "agent"])
        assert result.exit_code != 0

    def test_agent_mode_dispatches_to_scanner(self, monkeypatch, minimal_repo: Path):
        calls: dict[str, object] = {}

        @dataclass
        class FakeScanResult:
            repository_path: str
            issues: list
            files_scanned: int
            scan_time_seconds: float
            total_cost_usd: float

        class FakeScanner:
            def __init__(self, model: str = "sonnet", debug: bool = False):
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

        result = runner.invoke(app, [
            "scan", "--mode", "agent",
            "--target-path", str(minimal_repo),
            "--model", "haiku",
            "--debug",
        ])
        assert result.exit_code == 0, result.output
        assert calls["model"] == "haiku"
        assert calls["debug"] is True
        assert calls["repo_path"] == str(minimal_repo)

    def test_agent_mode_with_dast(self, monkeypatch, minimal_repo: Path):
        calls: dict[str, object] = {}

        @dataclass
        class FakeScanResult:
            repository_path: str
            issues: list
            files_scanned: int
            scan_time_seconds: float
            total_cost_usd: float

        class FakeScanner:
            def __init__(self, model: str = "sonnet", debug: bool = False):
                calls["model"] = model

            def configure_dast(self, target_url: str):
                calls["dast_url"] = target_url

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

        result = runner.invoke(app, [
            "scan", "--mode", "agent",
            "--target-path", str(minimal_repo),
            "--dast",
            "--dast-url", "http://localhost:3000",
        ])
        assert result.exit_code == 0, result.output
        assert calls["dast_url"] == "http://localhost:3000"

    def test_agent_mode_dast_without_url_fails(self, monkeypatch, minimal_repo: Path):
        @dataclass
        class FakeScanResult:
            repository_path: str
            issues: list
            files_scanned: int
            scan_time_seconds: float
            total_cost_usd: float

        class FakeScanner:
            def __init__(self, model: str = "sonnet", debug: bool = False):
                pass

            async def scan(self, repo_path: str):
                return FakeScanResult(
                    repository_path=repo_path,
                    issues=[],
                    files_scanned=1,
                    scan_time_seconds=0.01,
                    total_cost_usd=0.0,
                )

        monkeypatch.setattr("apps.cli.main.Scanner", FakeScanner)
        monkeypatch.setattr("apps.cli.main.config_exists", lambda: True)

        result = runner.invoke(app, [
            "scan", "--mode", "agent",
            "--target-path", str(minimal_repo),
            "--dast",
        ])
        assert result.exit_code != 0


class TestCLIMainCallback:
    def test_no_args_shows_help(self, monkeypatch):
        monkeypatch.setattr("apps.cli.main.config_exists", lambda: True)
        result = runner.invoke(app, [])
        assert result.exit_code != 0
        assert "promptheus" in result.output.lower() or "scan" in result.output.lower()

    def test_main_agent_mode(self, monkeypatch, minimal_repo: Path):
        calls: dict[str, object] = {}

        @dataclass
        class FakeScanResult:
            repository_path: str
            issues: list
            files_scanned: int
            scan_time_seconds: float
            total_cost_usd: float

        class FakeScanner:
            def __init__(self, model: str = "sonnet", debug: bool = False):
                calls["model"] = model

            async def scan(self, repo_path: str):
                calls["scanned"] = True
                return FakeScanResult(
                    repository_path=repo_path,
                    issues=[],
                    files_scanned=1,
                    scan_time_seconds=0.01,
                    total_cost_usd=0.0,
                )

        monkeypatch.setattr("apps.cli.main.Scanner", FakeScanner)
        monkeypatch.setattr("apps.cli.main.config_exists", lambda: True)

        result = runner.invoke(app, [
            "--mode", "agent",
            "--target-path", str(minimal_repo),
        ])
        assert result.exit_code == 0, result.output
        assert calls.get("scanned") is True


class TestCLIConfigShow:
    def test_config_show_command(self, monkeypatch):
        monkeypatch.setattr("apps.cli.main.config_exists", lambda: True)
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "PROMPTHEUS" in result.output or "Config" in result.output


class TestCLIInitCommand:
    def test_init_command_exists(self):
        result = runner.invoke(app, ["init", "--help"])
        assert result.exit_code == 0
        assert "wizard" in result.output.lower() or "setup" in result.output.lower()
