"""Unit tests for PROMPTHEUS security triage pre-filter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptheus.diff.parser import DiffContext, DiffFile, DiffHunk, DiffLine
from promptheus.scanner.triage import (
    SecuritySurfaceMap,
    TriageOverrides,
    TriageResult,
    _is_doc_or_test_path,
    build_security_surface_map,
    compute_triage_overrides,
    triage_diff,
)


def _make_diff_context(files: list[DiffFile] | None = None) -> DiffContext:
    changed = []
    for f in (files or []):
        path = f.new_path or f.old_path
        if path:
            changed.append(path)
    return DiffContext(
        files=files or [],
        added_lines=0,
        removed_lines=0,
        changed_files=changed,
    )


def _make_diff_file(
    path: str,
    hunk_contents: list[str] | None = None,
    is_new: bool = False,
    is_deleted: bool = False,
) -> DiffFile:
    hunks = []
    if hunk_contents:
        lines = [DiffLine("add", c, None, idx + 1) for idx, c in enumerate(hunk_contents)]
        hunks = [DiffHunk(old_start=1, old_count=0, new_start=1, new_count=len(lines), lines=lines)]
    return DiffFile(
        old_path=None,
        new_path=path,
        hunks=hunks,
        is_new=is_new,
        is_deleted=is_deleted,
        is_renamed=False,
    )


class TestIsDocOrTestPath:
    def test_doc_prefix(self):
        assert _is_doc_or_test_path("docs/guide.md") is True
        assert _is_doc_or_test_path("doc/api.md") is True

    def test_test_markers(self):
        assert _is_doc_or_test_path("src/tests/test_auth.py") is True
        assert _is_doc_or_test_path("src/auth.test.js") is True
        assert _is_doc_or_test_path("src/auth.spec.ts") is True
        assert _is_doc_or_test_path("src/__tests__/auth.py") is True

    def test_test_filename(self):
        assert _is_doc_or_test_path("test_runner.py") is True

    def test_non_test_non_doc(self):
        assert _is_doc_or_test_path("src/auth/login.py") is False
        assert _is_doc_or_test_path("lib/utils.js") is False


class TestSecuritySurfaceMap:
    def test_empty_map(self):
        m = SecuritySurfaceMap(vuln_paths=frozenset(), affected_components=frozenset())
        assert len(m.vuln_paths) == 0
        assert len(m.affected_components) == 0


class TestBuildSecuritySurfaceMap:
    def test_loads_vulnerabilities(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        vulns = [{"file_path": "src/auth.py"}, {"file_path": "src/api.py"}]
        (pd / "VULNERABILITIES.json").write_text(json.dumps(vulns))
        (pd / "THREAT_MODEL.json").write_text("[]")

        surface = build_security_surface_map(pd)
        assert len(surface.vuln_paths) == 2

    def test_loads_threat_model_components(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        threats = [{"affected_components": ["auth", "api"]}]
        (pd / "VULNERABILITIES.json").write_text("[]")
        (pd / "THREAT_MODEL.json").write_text(json.dumps(threats))

        surface = build_security_surface_map(pd)
        assert "auth" in surface.affected_components
        assert "api" in surface.affected_components

    def test_missing_files(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        surface = build_security_surface_map(pd)
        assert len(surface.vuln_paths) == 0
        assert len(surface.affected_components) == 0

    def test_invalid_json_handled(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        (pd / "VULNERABILITIES.json").write_text("{broken")
        surface = build_security_surface_map(pd)
        assert len(surface.vuln_paths) == 0


class TestTriageDiff:
    def test_low_risk_doc_only(self):
        diff = _make_diff_context([
            _make_diff_file("docs/README.md", ["Updated docs"], is_new=False)
        ])
        result = triage_diff(diff)
        assert result.classification == "low_risk"

    def test_security_relevant_command_signals(self):
        diff = _make_diff_context([
            _make_diff_file("src/runner.py", ["subprocess.run(cmd)", "exec( user_input)"])
        ])
        result = triage_diff(diff)
        assert result.classification == "security_relevant"
        assert "command_builder" in result.detector_hits

    def test_security_relevant_new_code_file(self):
        diff = _make_diff_context([
            _make_diff_file("src/new_handler.py", ["def handle():\n    pass"], is_new=True)
        ])
        result = triage_diff(diff)
        assert result.classification == "security_relevant"
        assert any("new_code_file" in r for r in result.reasons)

    def test_security_relevant_no_hunks(self):
        file = DiffFile(
            old_path=None, new_path="src/binary_file",
            hunks=[], is_new=False, is_deleted=False, is_renamed=False,
        )
        diff = _make_diff_context([file])
        result = triage_diff(diff)
        assert result.classification == "security_relevant"
        assert any("no_hunks" in r for r in result.reasons)

    def test_security_relevant_extensionless(self):
        diff = _make_diff_context([
            _make_diff_file("src/Makefile", ["all: build"])
        ])
        result = triage_diff(diff)
        # Extensionless files trigger fail-closed unless doc/test
        assert result.classification == "security_relevant"

    def test_security_relevant_baseline_vuln_match(self):
        surface = SecuritySurfaceMap(
            vuln_paths=frozenset({"src/auth.py"}),
            affected_components=frozenset(),
        )
        diff = _make_diff_context([
            _make_diff_file("src/auth.py", ["minor change"])
        ])
        result = triage_diff(diff, surface_map=surface)
        assert result.classification == "security_relevant"
        assert "src/auth.py" in result.matched_vuln_paths

    def test_with_promptheus_dir(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        (pd / "VULNERABILITIES.json").write_text('[{"file_path": "src/api.py"}]')
        (pd / "THREAT_MODEL.json").write_text("[]")

        diff = _make_diff_context([
            _make_diff_file("src/api.py", ["updated endpoint"])
        ])
        result = triage_diff(diff, promptheus_dir=pd)
        assert result.classification == "security_relevant"

    def test_auth_privilege_signals(self):
        diff = _make_diff_context([
            _make_diff_file("src/auth/middleware.py", ["check permission for admin role"])
        ])
        result = triage_diff(diff)
        assert result.classification == "security_relevant"
        assert "auth_privilege" in result.detector_hits

    def test_path_parser_signals(self):
        diff = _make_diff_context([
            _make_diff_file("src/file_handler.py", ["path.resolve() for upload handling"])
        ])
        result = triage_diff(diff)
        assert result.classification == "security_relevant"


class TestTriageResult:
    def test_fields(self):
        result = TriageResult(
            classification="security_relevant",
            reasons=("signal:command_builder",),
            max_file_score=85,
            detector_hits=("command_builder",),
            matched_vuln_paths=(),
            matched_components=(),
        )
        assert result.classification == "security_relevant"
        assert result.max_file_score == 85


class TestComputeTriageOverrides:
    def test_low_risk_returns_overrides(self):
        result = TriageResult(
            classification="low_risk",
            reasons=("default:low_risk",),
            max_file_score=20,
            detector_hits=(),
            matched_vuln_paths=(),
            matched_components=(),
        )
        overrides = compute_triage_overrides(result)
        assert overrides is not None
        assert overrides.pr_review_attempts == 1
        assert overrides.pr_timeout_seconds == 60

    def test_security_relevant_returns_none(self):
        result = TriageResult(
            classification="security_relevant",
            reasons=("signal:command_builder",),
            max_file_score=85,
            detector_hits=("command_builder",),
            matched_vuln_paths=(),
            matched_components=(),
        )
        assert compute_triage_overrides(result) is None
