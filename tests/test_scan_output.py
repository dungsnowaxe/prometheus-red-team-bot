"""Unit tests for PROMPTHEUS ScanOutput Pydantic model."""

from __future__ import annotations

import pytest

from promptheus.models.scan_output import (
    AffectedFile,
    ScanOutput,
    Vulnerability,
)
from promptheus.models.issue import Severity


class TestAffectedFile:
    def test_basic_construction(self):
        af = AffectedFile(file_path="src/auth.py")
        assert af.file_path == "src/auth.py"
        assert af.line_number is None
        assert af.code_snippet is None

    def test_with_line_number(self):
        af = AffectedFile(file_path="src/auth.py", line_number=42)
        assert af.line_number == 42

    def test_path_alias(self):
        af = AffectedFile.model_validate({"path": "src/auth.py"})
        assert af.file_path == "src/auth.py"

    def test_line_numbers_alias(self):
        af = AffectedFile.model_validate({"file_path": "a.py", "line_numbers": [10, 20]})
        assert af.line_number == [10, 20]


class TestVulnerability:
    def test_basic_construction(self):
        vuln = Vulnerability(
            threat_id="T-001",
            title="SQL Injection",
            description="User input in SQL query",
            severity=Severity.HIGH,
        )
        assert vuln.threat_id == "T-001"
        assert vuln.severity == Severity.HIGH

    def test_id_fallback_to_threat_id(self):
        vuln = Vulnerability.model_validate({
            "id": "VULN-42",
            "title": "XSS",
            "description": "Reflected XSS",
            "severity": "medium",
        })
        assert vuln.threat_id == "VULN-42"

    def test_missing_id_defaults_to_unknown(self):
        vuln = Vulnerability.model_validate({
            "title": "No ID",
            "description": "No ID provided",
            "severity": "low",
        })
        assert vuln.threat_id == "UNKNOWN-ID"

    def test_line_number_list_takes_first(self):
        vuln = Vulnerability.model_validate({
            "threat_id": "T1",
            "title": "Test",
            "description": "Test",
            "severity": "high",
            "line_number": [10, 20, 30],
        })
        assert vuln.line_number == 10

    def test_vulnerable_code_extraction(self):
        vuln = Vulnerability.model_validate({
            "threat_id": "T2",
            "title": "Test",
            "description": "Test",
            "severity": "high",
            "vulnerable_code": {
                "file": "auth.py",
                "line_numbers": [42],
                "code_snippet": "exec(user_input)",
            },
        })
        assert vuln.file_path == "auth.py"
        assert vuln.code_snippet == "exec(user_input)"

    def test_remediation_to_recommendation(self):
        vuln = Vulnerability.model_validate({
            "threat_id": "T3",
            "title": "Test",
            "description": "Test",
            "severity": "medium",
            "remediation": "Use parameterized queries",
        })
        assert vuln.recommendation == "Use parameterized queries"

    def test_remediation_dict_to_recommendation(self):
        vuln = Vulnerability.model_validate({
            "threat_id": "T4",
            "title": "Test",
            "description": "Test",
            "severity": "low",
            "remediation": {"recommendation": "Fix it", "priority": "high"},
        })
        assert vuln.recommendation == "Fix it"

    def test_proof_of_concept_to_evidence(self):
        vuln = Vulnerability.model_validate({
            "threat_id": "T5",
            "title": "Test",
            "description": "Test",
            "severity": "critical",
            "proof_of_concept": "curl -X POST ...",
        })
        assert vuln.evidence == "curl -X POST ..."

    def test_affected_files_string_list_conversion(self):
        vuln = Vulnerability.model_validate({
            "threat_id": "T6",
            "title": "Multi-file vuln",
            "description": "Test",
            "severity": "high",
            "affected_files": ["auth.py", "api.py", "config.py"],
        })
        assert len(vuln.affected_files) == 3
        assert vuln.affected_files[0].file_path == "auth.py"


class TestScanOutput:
    def test_validate_flat_list(self):
        data = [
            {
                "threat_id": "T1",
                "title": "SQLi",
                "description": "SQL injection",
                "severity": "high",
                "file_path": "auth.py",
                "line_number": 42,
                "code_snippet": "exec(q)",
                "cwe_id": "CWE-89",
                "recommendation": "Use prepared statements",
                "evidence": "Dumped users table",
            }
        ]
        output = ScanOutput.validate_input(data)
        assert len(output.vulnerabilities) == 1
        assert output.vulnerabilities[0].title == "SQLi"

    def test_validate_wrapped_vulnerabilities(self):
        data = {
            "vulnerabilities": [
                {
                    "threat_id": "T1",
                    "title": "XSS",
                    "description": "Reflected XSS",
                    "severity": "medium",
                    "file_path": "template.html",
                    "line_number": 10,
                    "code_snippet": "{{ user_input }}",
                    "cwe_id": "CWE-79",
                    "recommendation": "Escape output",
                    "evidence": None,
                }
            ]
        }
        output = ScanOutput.validate_input(data)
        assert len(output.vulnerabilities) == 1

    def test_validate_wrapped_issues(self):
        data = {
            "issues": [
                {
                    "threat_id": "T2",
                    "title": "Hardcoded secret",
                    "description": "API key in source",
                    "severity": "high",
                    "file_path": "config.py",
                    "line_number": 5,
                    "code_snippet": "API_KEY='sk-...'",
                    "cwe_id": "CWE-798",
                    "recommendation": "Use env vars",
                    "evidence": "grep found key",
                }
            ]
        }
        output = ScanOutput.validate_input(data)
        assert len(output.vulnerabilities) == 1

    def test_validate_invalid_type_raises(self):
        with pytest.raises(ValueError, match="Invalid input format"):
            ScanOutput.validate_input("not-a-list-or-dict")

    def test_empty_list(self):
        output = ScanOutput.validate_input([])
        assert len(output.vulnerabilities) == 0

    def test_get_json_schema_returns_dict(self):
        schema = ScanOutput.get_json_schema()
        assert isinstance(schema, dict)
        assert schema["type"] == "array"

    def test_get_output_format_returns_dict(self):
        fmt = ScanOutput.get_output_format()
        assert isinstance(fmt, dict)
