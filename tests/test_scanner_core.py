"""Unit tests for PROMPTHEUS Scanner class initialization and configuration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from promptheus.scanner.scanner import Scanner, PROMPTHEUS_DIR


class TestScannerInit:
    def test_default_construction(self):
        scanner = Scanner()
        assert scanner.model == "sonnet"
        assert scanner.debug is False
        assert scanner.total_cost == 0.0
        assert scanner.dast_enabled is False
        assert scanner.dast_config == {}
        assert scanner.agentic_override is None

    def test_custom_model(self):
        scanner = Scanner(model="haiku")
        assert scanner.model == "haiku"

    def test_debug_mode(self):
        scanner = Scanner(debug=True)
        assert scanner.debug is True

    def test_model_and_debug(self):
        scanner = Scanner(model="opus", debug=True)
        assert scanner.model == "opus"
        assert scanner.debug is True


class TestScannerDASTConfig:
    def test_configure_dast_basic(self):
        scanner = Scanner()
        scanner.configure_dast("http://localhost:3000")
        assert scanner.dast_enabled is True
        assert scanner.dast_config["target_url"] == "http://localhost:3000"
        assert scanner.dast_config["timeout"] == 120
        assert scanner.dast_config["accounts_path"] is None

    def test_configure_dast_with_timeout(self):
        scanner = Scanner()
        scanner.configure_dast("http://localhost:3000", timeout=60)
        assert scanner.dast_config["timeout"] == 60

    def test_configure_dast_with_accounts(self):
        scanner = Scanner()
        scanner.configure_dast(
            "http://localhost:3000",
            accounts_path="/path/to/accounts.json",
        )
        assert scanner.dast_config["accounts_path"] == "/path/to/accounts.json"


class TestScannerAgenticDetection:
    def test_configure_agentic_override_true(self):
        scanner = Scanner()
        scanner.configure_agentic_detection(True)
        assert scanner.agentic_override is True

    def test_configure_agentic_override_false(self):
        scanner = Scanner()
        scanner.configure_agentic_detection(False)
        assert scanner.agentic_override is False

    def test_configure_agentic_override_none(self):
        scanner = Scanner()
        scanner.configure_agentic_detection(None)
        assert scanner.agentic_override is None


class TestScannerRuntimeStateReset:
    def test_reset_clears_cost(self):
        scanner = Scanner()
        scanner.total_cost = 1.23
        scanner._reset_scan_runtime_state()
        assert scanner.total_cost == 0.0


class TestScannerPathValidation:
    def test_require_repo_scoped_path_inside_repo(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        scanner = Scanner()
        result = scanner._require_repo_scoped_path(repo, repo / "sub" / "file.txt", operation="test")
        assert result == repo / "sub" / "file.txt"

    def test_require_repo_scoped_path_outside_repo_raises(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        scanner = Scanner()
        with pytest.raises(RuntimeError, match="resolves outside repository root"):
            scanner._require_repo_scoped_path(repo, temp_dir / "elsewhere", operation="test")

    def test_repo_output_path_relative(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        scanner = Scanner()
        result = scanner._repo_output_path(repo, ".promptheus/SECURITY.md", operation="test")
        assert "repo" in str(result)
        assert ".promptheus" in str(result)

    def test_repo_output_path_absolute_inside(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        abs_path = repo / ".promptheus" / "SECURITY.md"
        scanner = Scanner()
        result = scanner._repo_output_path(repo, abs_path, operation="test")
        assert result == abs_path

    def test_repo_output_path_absolute_outside_raises(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        outside_path = temp_dir / "outside" / "file.txt"
        scanner = Scanner()
        with pytest.raises(RuntimeError, match="resolves outside repository root"):
            scanner._repo_output_path(repo, outside_path, operation="test")


class TestScannerScanModeContext:
    def test_full_scan_context(self):
        scanner = Scanner()
        ctx = scanner._build_scan_execution_mode_context(
            single_subagent=None,
            resume_from=None,
            skip_subagents=[],
            dast_enabled_for_run=False,
        )
        assert "run_only_subagent=none" in ctx
        assert "resume_from_subagent=none" in ctx
        assert "skip_subagents=none" in ctx
        assert "dast_enabled=false" in ctx

    def test_single_subagent_context(self):
        scanner = Scanner()
        ctx = scanner._build_scan_execution_mode_context(
            single_subagent="code-review",
            resume_from=None,
            skip_subagents=["assessment", "threat-modeling"],
            dast_enabled_for_run=False,
        )
        assert "run_only_subagent=code-review" in ctx
        assert "skip_subagents=assessment,threat-modeling" in ctx

    def test_dast_enabled_context(self):
        scanner = Scanner()
        scanner.dast_config = {
            "target_url": "http://localhost:3000",
            "timeout": 90,
            "accounts_path": None,
        }
        ctx = scanner._build_scan_execution_mode_context(
            single_subagent=None,
            resume_from=None,
            skip_subagents=[],
            dast_enabled_for_run=True,
        )
        assert "dast_enabled=true" in ctx
        assert "dast_target_url=http://localhost:3000" in ctx
        assert "dast_timeout_seconds=90" in ctx

    def test_resume_from_context(self):
        scanner = Scanner()
        ctx = scanner._build_scan_execution_mode_context(
            single_subagent=None,
            resume_from="code-review",
            skip_subagents=["assessment", "threat-modeling"],
            dast_enabled_for_run=False,
        )
        assert "resume_from_subagent=code-review" in ctx


class TestScannerValidation:
    def test_scan_nonexistent_path_raises(self):
        import asyncio
        scanner = Scanner()
        with pytest.raises(ValueError, match="does not exist"):
            asyncio.run(scanner.scan("/nonexistent/path/12345"))

    def test_scan_subagent_invalid_name_raises(self, temp_dir: Path):
        import asyncio
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("print('hello')\n")
        scanner = Scanner()
        with pytest.raises(ValueError, match="Invalid subagent name"):
            asyncio.run(
                scanner.scan_subagent(str(repo), "nonexistent-agent", skip_checks=True)
            )
