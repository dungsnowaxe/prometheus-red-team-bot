"""Unit tests for PROMPTHEUS security hooks."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from promptheus.scanner.hooks import (
    _command_uses_blocked_db_tool,
    _is_promptheus_artifact_path,
    _is_within_tmp_dir,
    _normalize_hook_path,
    _path_contains_excluded,
    _sanitize_pr_grep_scope,
    _merge_exclude_patterns,
    _is_inside_repo,
    _record_blocked_path,
    create_dast_security_hook,
    create_pre_tool_hook,
    create_post_tool_hook,
    create_subagent_hook,
)
from promptheus.scanner.progress import ProgressTracker


def _make_console() -> Console:
    return Console(file=None, force_terminal=False, no_color=True)


def _make_tracker(phase: str | None = None, debug: bool = False) -> ProgressTracker:
    tracker = ProgressTracker(_make_console(), debug=debug)
    if phase:
        tracker.announce_phase(phase)
    return tracker


# ============================================================================
# Helper function tests
# ============================================================================

class TestNormalizeHookPath:
    def test_none_returns_empty(self):
        assert _normalize_hook_path(None) == ""

    def test_empty_string(self):
        assert _normalize_hook_path("") == ""

    def test_backslash_normalization(self):
        assert _normalize_hook_path("src\\auth\\login.py") == "src/auth/login.py"

    def test_strips_whitespace(self):
        assert _normalize_hook_path("  src/auth.py  ") == "src/auth.py"

    def test_null_byte_returns_empty(self):
        assert _normalize_hook_path("src/\x00evil.py") == ""


class TestIsPrometheusArtifactPath:
    def test_relative_match(self):
        assert _is_promptheus_artifact_path(".promptheus/SECURITY.md", "SECURITY.md") is True

    def test_absolute_match(self):
        assert _is_promptheus_artifact_path(
            "/repo/.promptheus/SECURITY.md", "SECURITY.md"
        ) is True

    def test_wrong_artifact_name(self):
        assert _is_promptheus_artifact_path(
            ".promptheus/SECURITY.md", "THREAT_MODEL.json"
        ) is False

    def test_wrong_directory(self):
        assert _is_promptheus_artifact_path("other/SECURITY.md", "SECURITY.md") is False

    def test_none_path(self):
        assert _is_promptheus_artifact_path(None, "SECURITY.md") is False


class TestPathContainsExcluded:
    def test_simple_match(self):
        assert _path_contains_excluded("venv/lib/python/site.py", {".venv", "venv"}) is True

    def test_nested_match(self):
        assert _path_contains_excluded("project/node_modules/express/index.js", {"node_modules"}) is True

    def test_no_match(self):
        assert _path_contains_excluded("src/auth/login.py", {"node_modules", "venv"}) is False

    def test_empty_path(self):
        assert _path_contains_excluded("", {"venv"}) is False

    def test_none_path(self):
        assert _path_contains_excluded(None, {"venv"}) is False

    def test_empty_excluded_set(self):
        assert _path_contains_excluded("src/auth.py", set()) is False

    def test_git_directory(self):
        assert _path_contains_excluded(".git/objects/pack", {".git"}) is True


class TestCommandUsesBlockedDbTool:
    def test_detects_sqlite3(self):
        result = _command_uses_blocked_db_tool("sqlite3 users.db", ["sqlite3", "psql"])
        assert result == "sqlite3"

    def test_detects_psql(self):
        result = _command_uses_blocked_db_tool("psql -h localhost", ["sqlite3", "psql"])
        assert result == "psql"

    def test_detects_mysql(self):
        result = _command_uses_blocked_db_tool("mysql -u root", ["mysql"])
        assert result == "mysql"

    def test_allows_non_db_command(self):
        result = _command_uses_blocked_db_tool("curl http://localhost", ["sqlite3", "psql"])
        assert result is None

    def test_empty_command(self):
        result = _command_uses_blocked_db_tool("", ["sqlite3"])
        assert result is None

    def test_none_command(self):
        result = _command_uses_blocked_db_tool(None, ["sqlite3"])
        assert result is None


class TestSanitizePrGrepScope:
    def test_normal_scope(self):
        assert _sanitize_pr_grep_scope("src") == "src"

    def test_nested_scope(self):
        assert _sanitize_pr_grep_scope("packages/core") == "packages/core"

    def test_empty_scope_defaults(self):
        assert _sanitize_pr_grep_scope("") == "src"

    def test_none_scope_defaults(self):
        assert _sanitize_pr_grep_scope(None) == "src"

    def test_absolute_path_blocked(self):
        assert _sanitize_pr_grep_scope("/etc/passwd") == "src"

    def test_parent_traversal_blocked(self):
        assert _sanitize_pr_grep_scope("../secret") == "src"


class TestMergeExcludePatterns:
    def test_no_existing_patterns(self):
        tool_input: dict[str, Any] = {}
        _merge_exclude_patterns(tool_input, ["venv/**"])
        assert tool_input["excludePatterns"] == ["venv/**"]

    def test_existing_list(self):
        tool_input: dict[str, Any] = {"excludePatterns": ["*.pyc"]}
        _merge_exclude_patterns(tool_input, ["venv/**"])
        assert tool_input["excludePatterns"] == ["*.pyc", "venv/**"]

    def test_existing_string(self):
        tool_input: dict[str, Any] = {"excludePatterns": "*.pyc"}
        _merge_exclude_patterns(tool_input, ["venv/**"])
        assert tool_input["excludePatterns"] == ["*.pyc", "venv/**"]

    def test_existing_tuple(self):
        tool_input: dict[str, Any] = {"excludePatterns": ("*.pyc",)}
        _merge_exclude_patterns(tool_input, ["venv/**"])
        assert tool_input["excludePatterns"] == ["*.pyc", "venv/**"]


class TestIsWithinTmpDir:
    def test_under_tmp(self):
        assert _is_within_tmp_dir("/tmp/test_file.py") is True

    def test_not_under_tmp(self):
        assert _is_within_tmp_dir("/home/user/file.py") is False

    def test_relative_path(self):
        assert _is_within_tmp_dir("relative/path.py") is False

    def test_traversal_attack(self):
        assert _is_within_tmp_dir("/tmp/../etc/passwd") is False

    def test_empty(self):
        assert _is_within_tmp_dir("") is False


class TestIsInsideRepo:
    def test_inside_repo(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        candidate = (repo / "src" / "auth.py").resolve()
        assert _is_inside_repo(repo, candidate) is True

    def test_outside_repo(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        candidate = (temp_dir / "outside" / "file.py").resolve()
        assert _is_inside_repo(repo, candidate) is False

    def test_none_candidate(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        assert _is_inside_repo(repo, None) is False

    def test_repo_root_itself(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        assert _is_inside_repo(repo, repo.resolve()) is True


class TestRecordBlockedPath:
    def test_records_path(self):
        observer: dict[str, Any] = {}
        _record_blocked_path(observer, "/evil/path")
        assert observer["blocked_out_of_repo_count"] == 1
        assert observer["blocked_paths"] == ["/evil/path"]

    def test_increments_count(self):
        observer: dict[str, Any] = {"blocked_out_of_repo_count": 2, "blocked_paths": ["/a", "/b"]}
        _record_blocked_path(observer, "/c")
        assert observer["blocked_out_of_repo_count"] == 3
        assert len(observer["blocked_paths"]) == 3

    def test_none_observer_noop(self):
        _record_blocked_path(None, "/evil/path")

    def test_none_path_noop(self):
        observer: dict[str, Any] = {}
        _record_blocked_path(observer, None)
        assert observer == {}


# ============================================================================
# DAST security hook tests
# ============================================================================

class TestDASTSecurityHook:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_blocks_sqlite3_in_dast_phase(self):
        tracker = _make_tracker(phase="dast")
        hook = create_dast_security_hook(tracker, _make_console(), False)
        result = self._run(hook(
            {"tool_name": "Bash", "tool_input": {"command": "sqlite3 users.db .dump"}},
            "tool-123",
            {},
        ))
        assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def test_blocks_psql_in_dast_phase(self):
        tracker = _make_tracker(phase="dast")
        hook = create_dast_security_hook(tracker, _make_console(), False)
        result = self._run(hook(
            {"tool_name": "Bash", "tool_input": {"command": "psql -h localhost"}},
            "tool-123",
            {},
        ))
        assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def test_allows_curl_in_dast_phase(self):
        tracker = _make_tracker(phase="dast")
        hook = create_dast_security_hook(tracker, _make_console(), False)
        result = self._run(hook(
            {"tool_name": "Bash", "tool_input": {"command": "curl http://localhost:3000"}},
            "tool-123",
            {},
        ))
        assert result == {}

    def test_allows_any_command_in_non_dast_phase(self):
        tracker = _make_tracker(phase="code-review")
        hook = create_dast_security_hook(tracker, _make_console(), False)
        result = self._run(hook(
            {"tool_name": "Bash", "tool_input": {"command": "sqlite3 test.db"}},
            "tool-123",
            {},
        ))
        assert result == {}

    def test_ignores_non_bash_tools(self):
        tracker = _make_tracker(phase="dast")
        hook = create_dast_security_hook(tracker, _make_console(), False)
        result = self._run(hook(
            {"tool_name": "Read", "tool_input": {"file_path": "auth.py"}},
            "tool-123",
            {},
        ))
        assert result == {}


# ============================================================================
# Pre-tool hook tests
# ============================================================================

class TestPreToolHook:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_blocks_infrastructure_directory_read(self):
        tracker = _make_tracker(phase="assessment")
        hook = create_pre_tool_hook(tracker, _make_console(), False, {"python"})
        result = self._run(hook(
            {"tool_name": "Read", "tool_input": {"file_path": "venv/lib/python3/site.py"}},
            "tool-123",
            {},
        ))
        assert "override_result" in result
        assert "Infrastructure directory" in result["override_result"]["content"]

    def test_allows_source_file_read(self):
        tracker = _make_tracker(phase="assessment")
        hook = create_pre_tool_hook(tracker, _make_console(), False, {"python"})
        result = self._run(hook(
            {"tool_name": "Read", "tool_input": {"file_path": "src/auth/login.py"}},
            "tool-123",
            {},
        ))
        assert result == {}

    def test_injects_grep_exclude_patterns(self):
        tracker = _make_tracker(phase="assessment")
        tool_input: dict[str, Any] = {"pattern": "password"}
        hook = create_pre_tool_hook(tracker, _make_console(), False, {"python"})
        self._run(hook(
            {"tool_name": "Grep", "tool_input": tool_input},
            "tool-123",
            {},
        ))
        assert "excludePatterns" in tool_input
        patterns = tool_input["excludePatterns"]
        assert any("venv" in p or ".venv" in p for p in patterns)

    def test_dast_write_allows_validation_artifact(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        tracker = _make_tracker(phase="dast")
        hook = create_pre_tool_hook(
            tracker, _make_console(), False, set(), pr_repo_root=repo,
        )
        result = self._run(hook(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": ".promptheus/DAST_VALIDATION.json"},
            },
            "tool-123",
            {},
        ))
        assert "override_result" not in result or not result.get("override_result", {}).get("is_error")

    def test_dast_write_blocks_arbitrary_file(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        tracker = _make_tracker(phase="dast")
        hook = create_pre_tool_hook(
            tracker, _make_console(), False, set(), pr_repo_root=repo,
        )
        result = self._run(hook(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": "src/backdoor.py"},
            },
            "tool-123",
            {},
        ))
        assert "override_result" in result
        assert result["override_result"]["is_error"] is True

    def test_dast_write_allows_tmp_dir(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        tracker = _make_tracker(phase="dast")
        hook = create_pre_tool_hook(
            tracker, _make_console(), False, set(), pr_repo_root=repo,
        )
        result = self._run(hook(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": "/tmp/test_payload.txt"},
            },
            "tool-123",
            {},
        ))
        assert "override_result" not in result or not result.get("override_result", {}).get("is_error")

    def test_pr_review_blocks_non_artifact_write(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        tracker = _make_tracker(phase="pr-code-review")
        hook = create_pre_tool_hook(
            tracker, _make_console(), False, set(), pr_repo_root=repo,
        )
        result = self._run(hook(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": "src/evil.py"},
            },
            "tool-123",
            {},
        ))
        assert "override_result" in result
        assert result["override_result"]["is_error"] is True

    def test_pr_review_allows_pr_vulnerabilities_write(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / ".promptheus").mkdir()
        tracker = _make_tracker(phase="pr-code-review")
        hook = create_pre_tool_hook(
            tracker, _make_console(), False, set(), pr_repo_root=repo,
        )
        result = self._run(hook(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": ".promptheus/PR_VULNERABILITIES.json"},
            },
            "tool-123",
            {},
        ))
        has_error = result.get("override_result", {}).get("is_error", False)
        has_deny = result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
        assert not has_error and not has_deny

    def test_out_of_repo_read_blocked(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        tracker = _make_tracker(phase="assessment")
        hook = create_pre_tool_hook(
            tracker, _make_console(), False, set(), pr_repo_root=repo,
        )
        result = self._run(hook(
            {"tool_name": "Read", "tool_input": {"file_path": "/etc/passwd"}},
            "tool-123",
            {},
        ))
        assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def test_pr_review_blocks_diff_context_read(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        tracker = _make_tracker(phase="pr-code-review")
        hook = create_pre_tool_hook(
            tracker, _make_console(), False, set(), pr_repo_root=repo,
        )
        result = self._run(hook(
            {"tool_name": "Read", "tool_input": {"file_path": ".promptheus/DIFF_CONTEXT.json"}},
            "tool-123",
            {},
        ))
        assert "override_result" in result
        assert "DIFF_CONTEXT.json" in result["override_result"]["content"]

    def test_pr_review_pathless_grep_gets_scoped(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "src").mkdir()
        tracker = _make_tracker(phase="pr-code-review")
        hook = create_pre_tool_hook(
            tracker, _make_console(), False, set(),
            pr_grep_default_path="src", pr_repo_root=repo,
        )
        tool_input: dict[str, Any] = {"pattern": "password"}
        result = self._run(hook(
            {"tool_name": "Grep", "tool_input": tool_input},
            "tool-123",
            {},
        ))
        updated = result.get("hookSpecificOutput", {}).get("updatedInput", {})
        assert updated.get("path") == "src"


# ============================================================================
# Post-tool hook and subagent hook tests
# ============================================================================

class TestPostToolHook:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_returns_empty_dict(self):
        tracker = _make_tracker()
        hook = create_post_tool_hook(tracker, _make_console(), False)
        result = self._run(hook(
            {"tool_name": "Read", "tool_input": {}, "tool_response": {}},
            "tool-123",
            {},
        ))
        assert isinstance(result, dict)


class TestSubagentHook:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_calls_on_subagent_stop(self):
        tracker = _make_tracker()
        tracker.subagent_stack.append("assessment")
        hook = create_subagent_hook(tracker)
        self._run(hook(
            {"agent_name": "assessment", "duration_ms": 5000},
            "tool-456",
            {},
        ))
        assert tracker.subagent_stack == []
