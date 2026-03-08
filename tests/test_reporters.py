"""Unit tests for PROMPTHEUS reporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptheus.models.issue import SecurityIssue, Severity
from promptheus.models.result import ScanResult
from promptheus.reporters.json_reporter import JSONReporter
from promptheus.reporters.markdown_reporter import MarkdownReporter


def _make_scan_result(**overrides):
    defaults = {
        "repository_path": "/test/repo",
        "files_scanned": 10,
        "scan_time_seconds": 5.0,
        "total_cost_usd": 0.05,
        "issues": [],
        "dast_enabled": False,
        "dast_validation_rate": 0.0,
        "dast_scan_time_seconds": 0.0,
    }
    defaults.update(overrides)
    return ScanResult(**defaults)


def _make_issue(**overrides):
    defaults = {
        "id": "V-001",
        "title": "SQL Injection",
        "description": "User input not sanitized",
        "severity": Severity.HIGH,
        "file_path": "src/auth.py",
        "line_number": 42,
        "code_snippet": "query(f'SELECT * FROM users WHERE id = {user_id}')",
        "cwe_id": "CWE-89",
        "recommendation": "Use parameterized queries",
    }
    defaults.update(overrides)
    return SecurityIssue(**defaults)


class TestJSONReporter:
    def test_save_and_load(self, temp_dir: Path):
        result = _make_scan_result()
        output_path = temp_dir / "report.json"
        JSONReporter.save(result, output_path)
        assert output_path.exists()
        loaded = JSONReporter.load(output_path)
        assert loaded["repository_path"] == "/test/repo"
        assert loaded["files_scanned"] == 10

    def test_save_with_issues(self, temp_dir: Path):
        issue = _make_issue()
        result = _make_scan_result(issues=[issue])
        output_path = temp_dir / "report.json"
        JSONReporter.save(result, output_path)
        loaded = JSONReporter.load(output_path)
        assert len(loaded["issues"]) == 1
        assert loaded["issues"][0]["title"] == "SQL Injection"

    def test_creates_parent_dirs(self, temp_dir: Path):
        output_path = temp_dir / "subdir" / "deep" / "report.json"
        result = _make_scan_result()
        JSONReporter.save(result, output_path)
        assert output_path.exists()


class TestMarkdownReporter:
    def test_save_creates_file(self, temp_dir: Path):
        result = _make_scan_result()
        output_path = temp_dir / "report.md"
        MarkdownReporter.save(result, output_path)
        assert output_path.exists()
        content = output_path.read_text()
        assert "Security Scan Report" in content

    def test_generate_basic(self):
        result = _make_scan_result()
        md = MarkdownReporter.generate(result)
        assert "Security Scan Report" in md
        assert "/test/repo" in md
        assert "Files Scanned" in md

    def test_generate_with_issues(self):
        issues = [
            _make_issue(severity=Severity.CRITICAL, title="Critical Bug"),
            _make_issue(id="V-002", severity=Severity.LOW, title="Minor Issue"),
        ]
        result = _make_scan_result(issues=issues)
        md = MarkdownReporter.generate(result)
        assert "Critical Bug" in md
        assert "Minor Issue" in md

    def test_generate_with_cost(self):
        result = _make_scan_result(total_cost_usd=0.1234)
        md = MarkdownReporter.generate(result)
        assert "$0.1234" in md

    def test_generate_with_dast(self):
        result = _make_scan_result(
            dast_enabled=True,
            dast_validation_rate=0.85,
            dast_scan_time_seconds=12.5,
        )
        md = MarkdownReporter.generate(result)
        assert "DAST Enabled" in md
        assert "85.0%" in md

    def test_generate_long_scan_time(self):
        result = _make_scan_result(scan_time_seconds=125.5)
        md = MarkdownReporter.generate(result)
        assert "2m" in md

    def test_severity_summary(self):
        issues = [
            _make_issue(id="V-1", severity=Severity.CRITICAL),
            _make_issue(id="V-2", severity=Severity.HIGH),
            _make_issue(id="V-3", severity=Severity.MEDIUM),
            _make_issue(id="V-4", severity=Severity.LOW),
        ]
        result = _make_scan_result(issues=issues)
        md = MarkdownReporter.generate(result)
        assert "Critical" in md
        assert "High" in md

    def test_no_issues_message(self):
        result = _make_scan_result(issues=[])
        md = MarkdownReporter.generate(result)
        assert "No security issues" in md or "0" in md

    def test_creates_parent_dirs(self, temp_dir: Path):
        output_path = temp_dir / "subdir" / "report.md"
        result = _make_scan_result()
        MarkdownReporter.save(result, output_path)
        assert output_path.exists()
