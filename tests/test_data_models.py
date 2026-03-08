"""Unit tests for PROMPTHEUS data models (SecurityIssue, ScanResult, Severity, ValidationStatus)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptheus.models.issue import (
    SecurityIssue,
    Severity,
    ValidationStatus,
    SEVERITY_ORDER,
    SEVERITY_RANK,
)
from promptheus.models.result import ScanResult


class TestSeverityEnum:
    def test_all_severity_levels_exist(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_case_insensitive_matching(self):
        assert Severity("Critical") == Severity.CRITICAL
        assert Severity("HIGH") == Severity.HIGH
        assert Severity("medium") == Severity.MEDIUM
        assert Severity("Low") == Severity.LOW
        assert Severity("INFO") == Severity.INFO

    def test_informational_alias(self):
        assert Severity("informational") == Severity.INFO
        assert Severity("Informational") == Severity.INFO

    def test_invalid_severity_returns_none(self):
        assert Severity._missing_("bogus") is None
        assert Severity._missing_(42) is None

    def test_severity_order_ranks(self):
        assert SEVERITY_ORDER == ("info", "low", "medium", "high", "critical")
        assert SEVERITY_RANK["info"] < SEVERITY_RANK["low"]
        assert SEVERITY_RANK["low"] < SEVERITY_RANK["medium"]
        assert SEVERITY_RANK["medium"] < SEVERITY_RANK["high"]
        assert SEVERITY_RANK["high"] < SEVERITY_RANK["critical"]


class TestValidationStatus:
    def test_all_statuses_exist(self):
        assert ValidationStatus.VALIDATED.value == "VALIDATED"
        assert ValidationStatus.FALSE_POSITIVE.value == "FALSE_POSITIVE"
        assert ValidationStatus.UNVALIDATED.value == "UNVALIDATED"
        assert ValidationStatus.PARTIAL.value == "PARTIAL"


class TestSecurityIssue:
    @pytest.fixture
    def sample_issue(self) -> SecurityIssue:
        return SecurityIssue(
            id="VULN-001",
            severity=Severity.HIGH,
            title="SQL Injection",
            description="User input directly interpolated into SQL query",
            file_path="auth.py",
            line_number=42,
            code_snippet='query = f"SELECT * FROM users WHERE name=\'{name}\'"',
            cwe_id="CWE-89",
            recommendation="Use parameterized queries",
        )

    def test_basic_construction(self, sample_issue: SecurityIssue):
        assert sample_issue.id == "VULN-001"
        assert sample_issue.severity == Severity.HIGH
        assert sample_issue.title == "SQL Injection"
        assert sample_issue.file_path == "auth.py"
        assert sample_issue.line_number == 42
        assert sample_issue.cwe_id == "CWE-89"

    def test_optional_fields_default_to_none(self):
        issue = SecurityIssue(
            id="V1",
            severity=Severity.LOW,
            title="Test",
            description="Test desc",
            file_path="f.py",
            line_number=1,
            code_snippet="",
        )
        assert issue.recommendation is None
        assert issue.cwe_id is None
        assert issue.validation_status is None
        assert issue.dast_evidence is None
        assert issue.exploitability_score is None
        assert issue.validated_at is None
        assert issue.finding_type is None
        assert issue.attack_scenario is None
        assert issue.evidence is None

    def test_to_dict_basic(self, sample_issue: SecurityIssue):
        d = sample_issue.to_dict()
        assert d["id"] == "VULN-001"
        assert d["severity"] == "high"
        assert d["title"] == "SQL Injection"
        assert d["file_path"] == "auth.py"
        assert d["line_number"] == 42
        assert d["cwe_id"] == "CWE-89"
        assert "validation_status" not in d

    def test_to_dict_includes_pr_review_fields(self):
        issue = SecurityIssue(
            id="V2",
            severity=Severity.MEDIUM,
            title="Path Traversal",
            description="Unvalidated path",
            file_path="api.py",
            line_number=10,
            code_snippet="open(path)",
            finding_type="known_vuln",
            attack_scenario="Attacker controls filename param",
            evidence="GET /files?name=../../etc/passwd returns 200",
        )
        d = issue.to_dict()
        assert d["finding_type"] == "known_vuln"
        assert d["attack_scenario"] == "Attacker controls filename param"
        assert d["evidence"] is not None

    def test_to_dict_includes_dast_fields_when_present(self):
        issue = SecurityIssue(
            id="V3",
            severity=Severity.CRITICAL,
            title="RCE",
            description="Command injection",
            file_path="shell.py",
            line_number=5,
            code_snippet="os.system(cmd)",
            validation_status=ValidationStatus.VALIDATED,
            dast_evidence={"request": "...", "response": "..."},
            exploitability_score=9.5,
            validated_at="2026-03-06T12:00:00Z",
        )
        d = issue.to_dict()
        assert d["validation_status"] == "VALIDATED"
        assert d["dast_evidence"] == {"request": "...", "response": "..."}
        assert d["exploitability_score"] == 9.5
        assert d["validated_at"] == "2026-03-06T12:00:00Z"

    def test_is_validated_property(self):
        issue = SecurityIssue(
            id="V4", severity=Severity.HIGH, title="T", description="D",
            file_path="f.py", line_number=1, code_snippet="",
            validation_status=ValidationStatus.VALIDATED,
        )
        assert issue.is_validated is True
        assert issue.is_false_positive is False

    def test_is_false_positive_property(self):
        issue = SecurityIssue(
            id="V5", severity=Severity.LOW, title="T", description="D",
            file_path="f.py", line_number=1, code_snippet="",
            validation_status=ValidationStatus.FALSE_POSITIVE,
        )
        assert issue.is_validated is False
        assert issue.is_false_positive is True

    def test_unvalidated_issue(self):
        issue = SecurityIssue(
            id="V6", severity=Severity.MEDIUM, title="T", description="D",
            file_path="f.py", line_number=1, code_snippet="",
        )
        assert issue.is_validated is False
        assert issue.is_false_positive is False


class TestScanResult:
    @pytest.fixture
    def issues(self) -> list[SecurityIssue]:
        return [
            SecurityIssue(id="C1", severity=Severity.CRITICAL, title="Critical",
                          description="", file_path="a.py", line_number=1, code_snippet=""),
            SecurityIssue(id="H1", severity=Severity.HIGH, title="High",
                          description="", file_path="b.py", line_number=2, code_snippet=""),
            SecurityIssue(id="H2", severity=Severity.HIGH, title="High2",
                          description="", file_path="c.py", line_number=3, code_snippet=""),
            SecurityIssue(id="M1", severity=Severity.MEDIUM, title="Medium",
                          description="", file_path="d.py", line_number=4, code_snippet=""),
            SecurityIssue(id="L1", severity=Severity.LOW, title="Low",
                          description="", file_path="e.py", line_number=5, code_snippet=""),
        ]

    def test_empty_result(self):
        result = ScanResult(repository_path="/repo")
        assert result.issues == []
        assert result.files_scanned == 0
        assert result.scan_time_seconds == 0.0
        assert result.total_cost_usd == 0.0
        assert result.warnings == []
        assert result.dast_enabled is False

    def test_severity_counts(self, issues: list[SecurityIssue]):
        result = ScanResult(repository_path="/repo", issues=issues)
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 1
        assert result.low_count == 1

    def test_validated_issues_filter(self):
        issues = [
            SecurityIssue(id="V1", severity=Severity.HIGH, title="A",
                          description="", file_path="a.py", line_number=1, code_snippet="",
                          validation_status=ValidationStatus.VALIDATED),
            SecurityIssue(id="V2", severity=Severity.MEDIUM, title="B",
                          description="", file_path="b.py", line_number=2, code_snippet="",
                          validation_status=ValidationStatus.FALSE_POSITIVE),
            SecurityIssue(id="V3", severity=Severity.LOW, title="C",
                          description="", file_path="c.py", line_number=3, code_snippet="",
                          validation_status=ValidationStatus.UNVALIDATED),
            SecurityIssue(id="V4", severity=Severity.HIGH, title="D",
                          description="", file_path="d.py", line_number=4, code_snippet=""),
        ]
        result = ScanResult(repository_path="/repo", issues=issues)
        assert len(result.validated_issues) == 1
        assert result.validated_issues[0].id == "V1"
        assert len(result.false_positives) == 1
        assert result.false_positives[0].id == "V2"
        assert len(result.unvalidated_issues) == 1
        assert result.unvalidated_issues[0].id == "V3"

    def test_to_dict_structure(self, issues: list[SecurityIssue]):
        result = ScanResult(
            repository_path="/repo",
            issues=issues,
            files_scanned=42,
            scan_time_seconds=12.5,
            total_cost_usd=0.03,
        )
        d = result.to_dict()
        assert d["repository_path"] == "/repo"
        assert len(d["issues"]) == 5
        assert d["files_scanned"] == 42
        assert d["scan_time_seconds"] == 12.5
        assert d["total_cost_usd"] == 0.03
        assert d["summary"]["total"] == 5
        assert d["summary"]["critical"] == 1
        assert d["summary"]["high"] == 2
        assert "warnings" not in d  # omitted when empty

    def test_to_dict_includes_warnings(self):
        result = ScanResult(
            repository_path="/repo",
            warnings=["Timed out on phase 3"],
        )
        d = result.to_dict()
        assert "warnings" in d
        assert d["warnings"] == ["Timed out on phase 3"]

    def test_to_dict_includes_dast_metrics(self):
        result = ScanResult(
            repository_path="/repo",
            dast_enabled=True,
            dast_validation_rate=0.75,
            dast_false_positive_rate=0.1,
            dast_scan_time_seconds=30.0,
            issues=[
                SecurityIssue(id="V1", severity=Severity.HIGH, title="A",
                              description="", file_path="a.py", line_number=1, code_snippet="",
                              validation_status=ValidationStatus.VALIDATED),
            ],
        )
        d = result.to_dict()
        assert "dast_metrics" in d
        assert d["dast_metrics"]["enabled"] is True
        assert d["dast_metrics"]["validation_rate"] == 0.75
        assert d["dast_metrics"]["validated_count"] == 1

    def test_to_json_is_valid_json(self, issues: list[SecurityIssue]):
        result = ScanResult(repository_path="/repo", issues=issues, files_scanned=10)
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["files_scanned"] == 10
        assert len(parsed["issues"]) == 5
