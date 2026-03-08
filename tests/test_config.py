"""Unit tests for PROMPTHEUS configuration system (RuntimeConfig, LanguageConfig, ScanConfig)."""

from __future__ import annotations

from pathlib import Path

import pytest

from promptheus.config import (
    LanguageConfig,
    RuntimeConfig,
    ScanConfig,
    config,
)


class TestLanguageConfig:
    def test_supported_languages_keys(self):
        assert "python" in LanguageConfig.SUPPORTED_LANGUAGES
        assert "javascript" in LanguageConfig.SUPPORTED_LANGUAGES
        assert "typescript" in LanguageConfig.SUPPORTED_LANGUAGES
        assert "go" in LanguageConfig.SUPPORTED_LANGUAGES

    def test_python_extensions(self):
        exts = LanguageConfig.SUPPORTED_LANGUAGES["python"]
        assert ".py" in exts

    def test_detect_languages_python(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "main.py").write_text("print('hello')\n")
        detected = LanguageConfig.detect_languages(repo)
        assert "python" in detected

    def test_detect_languages_javascript(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "app.js").write_text("console.log('hi')\n")
        detected = LanguageConfig.detect_languages(repo)
        assert "javascript" in detected

    def test_detect_languages_multiple(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "main.py").write_text("pass\n")
        (repo / "app.ts").write_text("let x = 1;\n")
        detected = LanguageConfig.detect_languages(repo)
        assert "python" in detected
        assert "typescript" in detected

    def test_detect_languages_empty_repo(self, temp_dir: Path):
        repo = temp_dir / "empty"
        repo.mkdir()
        detected = LanguageConfig.detect_languages(repo)
        assert detected == set()

    def test_detect_languages_nonexistent_dir(self, temp_dir: Path):
        detected = LanguageConfig.detect_languages(temp_dir / "no-such-dir")
        assert detected == set()


class TestScanConfig:
    def test_artifacts_dir(self):
        assert ScanConfig.ARTIFACTS_DIR == ".promptheus"

    def test_blocked_db_tools_nonempty(self):
        assert len(ScanConfig.BLOCKED_DB_TOOLS) > 0
        assert "sqlite3" in ScanConfig.BLOCKED_DB_TOOLS

    def test_get_excluded_dirs_always_includes_git(self):
        excluded = ScanConfig.get_excluded_dirs(set())
        assert ".git" in excluded

    def test_get_excluded_dirs_includes_artifacts_dir(self):
        excluded = ScanConfig.get_excluded_dirs(set())
        assert ".promptheus" in excluded

    def test_get_excluded_dirs_includes_claude_dir(self):
        excluded = ScanConfig.get_excluded_dirs(set())
        assert ".claude" in excluded

    def test_get_excluded_dirs_python_extras(self):
        excluded = ScanConfig.get_excluded_dirs({"python"})
        assert "venv" in excluded or ".venv" in excluded

    def test_get_excluded_dirs_javascript_extras(self):
        excluded = ScanConfig.get_excluded_dirs({"javascript"})
        assert "node_modules" in excluded

    def test_get_excluded_dirs_multiple_languages(self):
        excluded = ScanConfig.get_excluded_dirs({"python", "javascript"})
        assert "node_modules" in excluded
        assert ".venv" in excluded

    def test_get_excluded_dirs_for_phase_basic(self):
        excluded = ScanConfig.get_excluded_dirs_for_phase("assessment", {"python"})
        assert ".git" in excluded
        assert ".promptheus" in excluded

    def test_get_excluded_dirs_for_phase_code_review_includes_artifacts(self):
        excluded = ScanConfig.get_excluded_dirs_for_phase("code-review", {"python"})
        assert ".promptheus" not in excluded

    def test_get_excluded_dirs_for_phase_dast_includes_claude(self):
        excluded = ScanConfig.get_excluded_dirs_for_phase("dast", {"python"})
        assert ".claude" not in excluded

    def test_get_excluded_dirs_for_phase_threat_modeling_includes_claude(self):
        excluded = ScanConfig.get_excluded_dirs_for_phase("threat-modeling", {"python"})
        assert ".claude" not in excluded


class TestRuntimeConfig:
    def test_singleton_instance_exists(self):
        assert config is not None
        assert isinstance(config, RuntimeConfig)

    def test_defaults(self):
        assert RuntimeConfig.DEFAULTS["agent_model"] == "sonnet"
        assert RuntimeConfig.DEFAULTS["max_turns"] == 50
        assert RuntimeConfig.DEFAULTS["pr_review_attempts"] == 3
        assert RuntimeConfig.DEFAULTS["pr_review_timeout_seconds"] == 180

    def test_get_agent_model_cli_override(self, monkeypatch):
        monkeypatch.delenv("PROMPTHEUS_ASSESSMENT_MODEL", raising=False)
        monkeypatch.delenv("PROMPTHEUS_AGENT_MODEL", raising=False)
        result = config.get_agent_model("assessment", cli_override="haiku")
        assert result == "haiku"

    def test_get_agent_model_env_override(self, monkeypatch):
        monkeypatch.setenv("PROMPTHEUS_ASSESSMENT_MODEL", "opus")
        result = config.get_agent_model("assessment", cli_override="haiku")
        assert result == "opus"

    def test_get_agent_model_global_env(self, monkeypatch):
        monkeypatch.delenv("PROMPTHEUS_ASSESSMENT_MODEL", raising=False)
        monkeypatch.setenv("PROMPTHEUS_AGENT_MODEL", "haiku")
        result = config.get_agent_model("assessment")
        assert result == "haiku"

    def test_get_max_turns_default(self, monkeypatch):
        monkeypatch.delenv("PROMPTHEUS_MAX_TURNS", raising=False)
        result = config.get_max_turns()
        assert result == 50

    def test_get_max_turns_env_override(self, monkeypatch):
        monkeypatch.setenv("PROMPTHEUS_MAX_TURNS", "100")
        result = config.get_max_turns()
        assert result == 100

    def test_get_max_turns_invalid_env_falls_back(self, monkeypatch):
        monkeypatch.setenv("PROMPTHEUS_MAX_TURNS", "not-a-number")
        result = config.get_max_turns()
        assert result == 50

    def test_get_max_turns_zero_falls_back(self, monkeypatch):
        monkeypatch.setenv("PROMPTHEUS_MAX_TURNS", "0")
        result = config.get_max_turns()
        assert result == 50

    def test_get_max_turns_negative_falls_back(self, monkeypatch):
        monkeypatch.setenv("PROMPTHEUS_MAX_TURNS", "-5")
        result = config.get_max_turns()
        assert result == 50

    def test_get_pr_review_attempts_default(self, monkeypatch):
        monkeypatch.delenv("PROMPTHEUS_PR_REVIEW_ATTEMPTS", raising=False)
        result = config.get_pr_review_attempts()
        assert result == 3

    def test_get_pr_review_attempts_env_override(self, monkeypatch):
        monkeypatch.setenv("PROMPTHEUS_PR_REVIEW_ATTEMPTS", "5")
        result = config.get_pr_review_attempts()
        assert result == 5

    def test_get_pr_review_timeout_seconds_default(self, monkeypatch):
        monkeypatch.delenv("PROMPTHEUS_PR_TIMEOUT_SECONDS", raising=False)
        result = config.get_pr_review_timeout_seconds()
        assert result == 180

    def test_get_pr_review_timeout_seconds_env_override(self, monkeypatch):
        monkeypatch.setenv("PROMPTHEUS_PR_TIMEOUT_SECONDS", "300")
        result = config.get_pr_review_timeout_seconds()
        assert result == 300
