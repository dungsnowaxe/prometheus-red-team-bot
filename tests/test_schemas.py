"""Unit tests for PROMPTHEUS JSON schema validation and normalization."""

from __future__ import annotations

import json

import pytest

from promptheus.models.schemas import (
    ASI_THREAT_ID_RE,
    PR_VULNERABILITY_SCHEMA,
    VULNERABILITY_SCHEMA,
    WRAPPER_KEYS,
    _append_line_numbers_to_evidence,
    _coerce_evidence_to_string,
    _extract_line_numbers,
    _extract_primary_line_number,
    _normalize_pr_vulnerability_list,
    _parse_line_value,
    _parse_location_string,
    _strip_code_fences,
    _unwrap_json_array,
    derive_pr_finding_id,
    extract_asi_category,
    extract_cwe_id,
    fix_pr_vulnerabilities_json,
    fix_threat_model_json,
    fix_vulnerabilities_json,
    get_output_format_config,
    infer_finding_type,
    normalize_pr_vulnerability,
    validate_pr_vulnerabilities_json,
    validate_threat_model_json,
    validate_vulnerabilities_json,
)


class TestStripCodeFences:
    def test_no_fences(self):
        assert _strip_code_fences('[{"id": 1}]') == '[{"id": 1}]'

    def test_json_fences(self):
        content = '```json\n[{"id": 1}]\n```'
        assert _strip_code_fences(content) == '[{"id": 1}]'

    def test_plain_fences(self):
        content = '```\n[{"id": 1}]\n```'
        assert _strip_code_fences(content) == '[{"id": 1}]'

    def test_no_closing_fence(self):
        content = '```json\n[{"id": 1}]'
        assert _strip_code_fences(content) == '[{"id": 1}]'


class TestExtractAsiCategory:
    def test_valid_asi_id(self):
        assert extract_asi_category("THREAT-ASI01-001") == "ASI01"
        assert extract_asi_category("THREAT-ASI03-042") == "ASI03"

    def test_case_insensitive(self):
        assert extract_asi_category("threat-asi01-001") == "ASI01"

    def test_non_asi_id(self):
        assert extract_asi_category("T-001") is None

    def test_empty(self):
        assert extract_asi_category("") is None

    def test_none(self):
        assert extract_asi_category(None) is None


class TestFixThreatModelJson:
    def test_flat_array_unchanged(self):
        content = '[{"id": "T-1", "title": "Test"}]'
        fixed, was_modified = fix_threat_model_json(content)
        assert json.loads(fixed) == [{"id": "T-1", "title": "Test"}]
        assert not was_modified

    def test_unwraps_threats_key(self):
        content = json.dumps({"threats": [{"id": "T-1"}]})
        fixed, was_modified = fix_threat_model_json(content)
        assert json.loads(fixed) == [{"id": "T-1"}]
        assert was_modified

    def test_unwraps_generic_wrapper(self):
        content = json.dumps({"results": [{"id": "T-1"}]})
        fixed, was_modified = fix_threat_model_json(content)
        assert json.loads(fixed) == [{"id": "T-1"}]
        assert was_modified

    def test_strips_code_fences(self):
        content = '```json\n[{"id": "T-1"}]\n```'
        fixed, was_modified = fix_threat_model_json(content)
        assert json.loads(fixed) == [{"id": "T-1"}]
        assert was_modified

    def test_wraps_single_object(self):
        content = json.dumps({"id": "T-1", "title": "Test"})
        fixed, was_modified = fix_threat_model_json(content)
        result = json.loads(fixed)
        assert isinstance(result, list)
        assert len(result) == 1
        assert was_modified

    def test_empty_content(self):
        fixed, was_modified = fix_threat_model_json("")
        assert fixed == ""
        assert not was_modified

    def test_whitespace_only(self):
        fixed, was_modified = fix_threat_model_json("   ")
        assert not was_modified

    def test_invalid_json(self):
        fixed, was_modified = fix_threat_model_json("{broken")
        assert fixed == "{broken"


class TestValidateThreatModelJson:
    def _make_threat(self, **overrides):
        base = {
            "id": "T-001",
            "category": "Injection",
            "title": "SQL Injection",
            "description": "Desc",
            "severity": "high",
        }
        base.update(overrides)
        return base

    def test_valid_model(self):
        threats = [self._make_threat(id=f"T-{i}") for i in range(15)]
        content = json.dumps(threats)
        valid, error, warnings = validate_threat_model_json(content)
        assert valid
        assert error is None

    def test_empty_content(self):
        valid, error, warnings = validate_threat_model_json("")
        assert not valid
        assert "Empty" in error

    def test_invalid_json(self):
        valid, error, warnings = validate_threat_model_json("{broken")
        assert not valid
        assert "Invalid JSON" in error

    def test_not_an_array(self):
        valid, error, warnings = validate_threat_model_json('{"key": "value"}')
        assert not valid

    def test_wrapped_array(self):
        content = json.dumps({"threats": [self._make_threat()]})
        valid, error, warnings = validate_threat_model_json(content)
        assert valid

    def test_missing_required_fields(self):
        content = json.dumps([{"id": "T-1"}])
        valid, error, warnings = validate_threat_model_json(content)
        assert not valid
        assert "missing required fields" in error

    def test_invalid_severity(self):
        threat = self._make_threat(severity="bogus")
        valid, error, warnings = validate_threat_model_json(json.dumps([threat]))
        assert not valid
        assert "invalid severity" in error

    def test_few_threats_warning(self):
        threats = [self._make_threat()]
        valid, error, warnings = validate_threat_model_json(json.dumps(threats))
        assert valid
        assert any("Only" in w for w in warnings)

    def test_require_asi_no_asi_threats(self):
        threats = [self._make_threat(id=f"T-{i}") for i in range(12)]
        content = json.dumps(threats)
        valid, error, warnings = validate_threat_model_json(content, require_asi=True)
        assert not valid
        assert "ASI" in error

    def test_require_asi_with_asi_threats(self):
        threats = [self._make_threat(id=f"T-{i}") for i in range(10)]
        threats.append(self._make_threat(id="THREAT-ASI01-001"))
        threats.append(self._make_threat(id="THREAT-ASI03-001"))
        content = json.dumps(threats)
        valid, error, warnings = validate_threat_model_json(content, require_asi=True)
        assert valid

    def test_missing_critical_asi_warning(self):
        threats = [self._make_threat(id=f"T-{i}") for i in range(10)]
        threats.append(self._make_threat(id="THREAT-ASI01-001"))
        content = json.dumps(threats)
        valid, error, warnings = validate_threat_model_json(
            content, require_asi=True, critical_asi_categories={"ASI01", "ASI03"}
        )
        assert valid
        assert any("ASI03" in w for w in warnings)

    def test_non_dict_threat_fails(self):
        content = json.dumps([self._make_threat(), "not a dict"])
        valid, error, warnings = validate_threat_model_json(content)
        assert not valid
        assert "not an object" in error


class TestFixVulnerabilitiesJson:
    def test_flat_array_unchanged(self):
        content = '[{"threat_id": "V-1"}]'
        fixed, was_modified = fix_vulnerabilities_json(content)
        assert not was_modified

    def test_unwraps_wrapper(self):
        content = json.dumps({"vulnerabilities": [{"threat_id": "V-1"}]})
        fixed, was_modified = fix_vulnerabilities_json(content)
        assert json.loads(fixed) == [{"threat_id": "V-1"}]
        assert was_modified

    def test_empty_to_empty_array(self):
        fixed, was_modified = fix_vulnerabilities_json("")
        assert fixed == "[]"
        assert was_modified


class TestFixPrVulnerabilitiesJson:
    def test_flat_array(self):
        vuln = {
            "threat_id": "T-1",
            "finding_type": "known_vuln",
            "title": "SQLi",
            "description": "Desc",
            "severity": "high",
            "file_path": "a.py",
            "line_number": 42,
            "code_snippet": "code",
            "attack_scenario": "scenario",
            "evidence": "evidence",
            "cwe_id": "CWE-89",
            "recommendation": "Fix it",
        }
        content = json.dumps([vuln])
        fixed, was_modified = fix_pr_vulnerabilities_json(content)
        result = json.loads(fixed)
        assert isinstance(result, list)

    def test_unwraps_and_normalizes(self):
        vuln = {"title": "SQLi", "file_path": "a.py", "severity": "high", "line_number": 42}
        content = json.dumps({"findings": [vuln]})
        fixed, was_modified = fix_pr_vulnerabilities_json(content)
        result = json.loads(fixed)
        assert isinstance(result, list)
        assert was_modified
        assert result[0].get("threat_id")  # ID was derived

    def test_empty_to_empty_array(self):
        fixed, was_modified = fix_pr_vulnerabilities_json("")
        assert fixed == "[]"
        assert was_modified


class TestUnwrapJsonArray:
    def test_flat_array(self):
        stripped, data, modified = _unwrap_json_array('[{"id": 1}]')
        assert data is None
        assert not modified

    def test_wrapper_dict(self):
        content = json.dumps({"vulnerabilities": [{"id": 1}]})
        stripped, data, modified = _unwrap_json_array(content)
        assert data == [{"id": 1}]
        assert modified

    def test_single_object(self):
        content = json.dumps({"threat_id": "T-1", "title": "SQLi"})
        stripped, data, modified = _unwrap_json_array(content)
        assert data == [{"threat_id": "T-1", "title": "SQLi"}]
        assert modified

    def test_empty(self):
        stripped, data, modified = _unwrap_json_array("")
        assert stripped == "[]"
        assert modified

    def test_code_fences_stripped(self):
        content = '```json\n[{"id": 1}]\n```'
        stripped, data, modified = _unwrap_json_array(content)
        assert stripped == '[{"id": 1}]'
        assert modified


class TestDerivePrFindingId:
    def test_deterministic(self):
        vuln = {"file_path": "src/auth.py", "title": "SQLi", "line_number": 42}
        id1 = derive_pr_finding_id(vuln)
        id2 = derive_pr_finding_id(vuln)
        assert id1 == id2
        assert id1.startswith("PR-")

    def test_different_inputs(self):
        id1 = derive_pr_finding_id({"file_path": "a.py", "title": "A"})
        id2 = derive_pr_finding_id({"file_path": "b.py", "title": "B"})
        assert id1 != id2


class TestInferFindingType:
    def test_known_types(self):
        assert infer_finding_type({"category": "new_threat"}) == "new_threat"
        assert infer_finding_type({"type": "threat_enabler"}) == "threat_enabler"
        assert infer_finding_type({"type": "mitigation_removal"}) == "mitigation_removal"
        assert infer_finding_type({"category": "known_vuln"}) == "known_vuln"
        assert infer_finding_type({"type": "regression"}) == "regression"

    def test_shorthand(self):
        assert infer_finding_type({"category": "new"}) == "new_threat"
        assert infer_finding_type({"category": "known"}) == "known_vuln"
        assert infer_finding_type({"category": "enabler"}) == "threat_enabler"
        assert infer_finding_type({"category": "mitigation"}) == "mitigation_removal"

    def test_none_when_missing(self):
        assert infer_finding_type({}) is None

    def test_finding_type_field_used(self):
        assert infer_finding_type({"finding_type": "regression"}) == "regression"


class TestExtractCweId:
    def test_from_string_list(self):
        vuln = {"vulnerability_types": ["CWE-89: SQL Injection"]}
        assert extract_cwe_id(vuln) == "CWE-89"

    def test_from_dict_list(self):
        vuln = {"vulnerability_types": [{"id": "CWE-79", "name": "XSS"}]}
        assert extract_cwe_id(vuln) == "CWE-79"

    def test_no_cwe(self):
        vuln = {"vulnerability_types": ["No CWE here"]}
        assert extract_cwe_id(vuln) is None

    def test_no_vulnerability_types(self):
        assert extract_cwe_id({}) is None

    def test_not_a_list(self):
        assert extract_cwe_id({"vulnerability_types": "CWE-89"}) is None


class TestNormalizePrVulnerability:
    def test_complete_input(self):
        vuln = {
            "threat_id": "T-1",
            "finding_type": "known_vuln",
            "title": "SQLi",
            "description": "Desc",
            "severity": "high",
            "file_path": "auth.py",
            "line_number": 42,
            "code_snippet": "query(f'...')",
            "attack_scenario": "Inject SQL",
            "evidence": "Proof",
            "cwe_id": "CWE-89",
            "recommendation": "Parameterize",
        }
        result = normalize_pr_vulnerability(vuln)
        assert result["threat_id"] == "T-1"
        assert result["finding_type"] == "known_vuln"
        assert result["line_number"] == 42

    def test_derives_missing_threat_id(self):
        vuln = {"title": "SQLi", "file_path": "a.py", "severity": "high"}
        result = normalize_pr_vulnerability(vuln)
        assert result["threat_id"].startswith("PR-")

    def test_derives_finding_type(self):
        vuln = {"title": "SQLi", "category": "new_threat"}
        result = normalize_pr_vulnerability(vuln)
        assert result["finding_type"] == "new_threat"

    def test_defaults_finding_type_to_unknown(self):
        vuln = {"title": "SQLi"}
        result = normalize_pr_vulnerability(vuln)
        assert result["finding_type"] == "unknown"

    def test_location_dict_extraction(self):
        vuln = {"title": "T", "location": {"file": "src/api.py", "line": 100}}
        result = normalize_pr_vulnerability(vuln)
        assert result["file_path"] == "src/api.py"
        assert result["line_number"] == 100

    def test_location_string_extraction(self):
        vuln = {"title": "T", "location": "src/api.py:42"}
        result = normalize_pr_vulnerability(vuln)
        assert result["file_path"] == "src/api.py"
        assert result["line_number"] == 42

    def test_location_string_range(self):
        vuln = {"title": "T", "location": "src/api.py:111-208"}
        result = normalize_pr_vulnerability(vuln)
        assert result["file_path"] == "src/api.py"
        assert result["line_number"] == 111

    def test_file_alias(self):
        vuln = {"title": "T", "file": "src/auth.py"}
        result = normalize_pr_vulnerability(vuln)
        assert result["file_path"] == "src/auth.py"

    def test_line_alias(self):
        vuln = {"title": "T", "file_path": "a.py", "line": 55}
        result = normalize_pr_vulnerability(vuln)
        assert result["line_number"] == 55

    def test_bare_cwe(self):
        vuln = {"title": "T", "cwe": "862"}
        result = normalize_pr_vulnerability(vuln)
        assert result["cwe_id"] == "CWE-862"

    def test_mitigation_as_recommendation(self):
        vuln = {"title": "T", "mitigation": "Use prepared statements"}
        result = normalize_pr_vulnerability(vuln)
        assert result["recommendation"] == "Use prepared statements"

    def test_line_numbers_appended_to_evidence(self):
        vuln = {"title": "T", "evidence": "Proof", "line_numbers": [10, 20, 30]}
        result = normalize_pr_vulnerability(vuln)
        assert "line_numbers" in result["evidence"]

    def test_evidence_dict_coerced_to_string(self):
        vuln = {"title": "T", "evidence": {"request": "GET /api"}}
        result = normalize_pr_vulnerability(vuln)
        assert isinstance(result["evidence"], str)

    def test_vulnerability_types_extraction(self):
        vuln = {"title": "T", "vulnerability_types": ["CWE-79: XSS"]}
        result = normalize_pr_vulnerability(vuln)
        assert result["cwe_id"] == "CWE-79"


class TestExtractPrimaryLineNumber:
    def test_direct_value(self):
        assert _extract_primary_line_number({"line_number": 42}) == 42

    def test_string_value(self):
        assert _extract_primary_line_number({"line_number": "42"}) == 42

    def test_from_line_numbers_array(self):
        assert _extract_primary_line_number({"line_numbers": [10, 20]}) == 10

    def test_invalid_returns_zero(self):
        assert _extract_primary_line_number({"line_number": "abc"}) == 0

    def test_none_returns_zero(self):
        assert _extract_primary_line_number({}) == 0


class TestExtractLineNumbers:
    def test_valid_array(self):
        assert _extract_line_numbers({"line_numbers": [10, 20, 30]}) == [10, 20, 30]

    def test_non_list(self):
        assert _extract_line_numbers({"line_numbers": 42}) == []

    def test_mixed_values(self):
        assert _extract_line_numbers({"line_numbers": [10, "abc", 30]}) == [10, 30]

    def test_missing_key(self):
        assert _extract_line_numbers({}) == []


class TestParseLocationString:
    def test_path_with_line(self):
        path, line = _parse_location_string("src/auth.py:42")
        assert path == "src/auth.py"
        assert line == 42

    def test_path_with_range(self):
        path, line = _parse_location_string("src/auth.py:111-208")
        assert path == "src/auth.py"
        assert line == 111

    def test_path_only(self):
        path, line = _parse_location_string("src/auth.py")
        assert path == "src/auth.py"
        assert line is None

    def test_comma_separated(self):
        path, line = _parse_location_string("src/a.ts:16-119, src/b.ts")
        assert path == "src/a.ts"
        assert line == 16

    def test_empty(self):
        assert _parse_location_string("") == (None, None)

    def test_none(self):
        assert _parse_location_string(None) == (None, None)


class TestParseLineValue:
    def test_integer(self):
        assert _parse_line_value(42) == 42

    def test_zero(self):
        assert _parse_line_value(0) is None

    def test_negative(self):
        assert _parse_line_value(-1) is None

    def test_string_number(self):
        assert _parse_line_value("42") == 42

    def test_range_string(self):
        assert _parse_line_value("42-80") == 42

    def test_empty_string(self):
        assert _parse_line_value("") is None

    def test_non_numeric(self):
        assert _parse_line_value("abc") is None


class TestCoerceEvidenceToString:
    def test_string(self):
        assert _coerce_evidence_to_string("proof") == "proof"

    def test_none(self):
        assert _coerce_evidence_to_string(None) == ""

    def test_dict(self):
        result = _coerce_evidence_to_string({"request": "GET"})
        assert isinstance(result, str)
        assert "GET" in result

    def test_list(self):
        result = _coerce_evidence_to_string([1, 2, 3])
        assert isinstance(result, str)


class TestAppendLineNumbersToEvidence:
    def test_appends(self):
        result = _append_line_numbers_to_evidence("existing", [10, 20])
        assert "line_numbers: [10, 20]" in result

    def test_no_line_numbers(self):
        assert _append_line_numbers_to_evidence("existing", []) == "existing"

    def test_empty_evidence(self):
        result = _append_line_numbers_to_evidence("", [10])
        assert "line_numbers" in result

    def test_avoids_duplication(self):
        evidence = "existing\nline_numbers: [10]"
        result = _append_line_numbers_to_evidence(evidence, [10])
        assert result == evidence


class TestValidateVulnerabilitiesJson:
    def _make_vuln(self, **overrides):
        base = {
            "threat_id": "V-1",
            "title": "SQLi",
            "description": "Desc",
            "severity": "high",
            "file_path": "a.py",
            "line_number": 42,
            "code_snippet": "code",
            "cwe_id": "CWE-89",
            "recommendation": "Fix",
            "evidence": "Proof",
        }
        base.update(overrides)
        return base

    def test_valid(self):
        content = json.dumps([self._make_vuln()])
        valid, error = validate_vulnerabilities_json(content)
        assert valid
        assert error is None

    def test_empty(self):
        valid, error = validate_vulnerabilities_json("")
        assert not valid

    def test_not_array(self):
        valid, error = validate_vulnerabilities_json('{"key": "value"}')
        assert not valid

    def test_missing_fields(self):
        content = json.dumps([{"title": "SQLi"}])
        valid, error = validate_vulnerabilities_json(content)
        assert not valid
        assert "missing required fields" in error

    def test_invalid_severity(self):
        vuln = self._make_vuln(severity="bogus")
        valid, error = validate_vulnerabilities_json(json.dumps([vuln]))
        assert not valid
        assert "invalid severity" in error


class TestValidatePrVulnerabilitiesJson:
    def _make_pr_vuln(self, **overrides):
        base = {
            "threat_id": "T-1",
            "finding_type": "known_vuln",
            "title": "SQLi",
            "description": "Desc",
            "severity": "high",
            "file_path": "a.py",
            "line_number": 42,
            "code_snippet": "code",
            "attack_scenario": "Scenario",
            "evidence": "Proof",
            "cwe_id": "CWE-89",
            "recommendation": "Fix",
        }
        base.update(overrides)
        return base

    def test_valid(self):
        content = json.dumps([self._make_pr_vuln()])
        valid, error = validate_pr_vulnerabilities_json(content)
        assert valid
        assert error is None

    def test_empty(self):
        valid, error = validate_pr_vulnerabilities_json("")
        assert not valid

    def test_invalid_finding_type(self):
        vuln = self._make_pr_vuln(finding_type="bogus")
        valid, error = validate_pr_vulnerabilities_json(json.dumps([vuln]))
        assert not valid
        assert "invalid finding_type" in error

    def test_empty_evidence_field(self):
        vuln = self._make_pr_vuln(evidence="")
        valid, error = validate_pr_vulnerabilities_json(json.dumps([vuln]))
        assert not valid
        assert "empty required evidence" in error

    def test_invalid_line_number(self):
        vuln = self._make_pr_vuln(line_number=-1)
        valid, error = validate_pr_vulnerabilities_json(json.dumps([vuln]))
        assert not valid
        assert "invalid line_number" in error

    def test_invalid_severity(self):
        vuln = self._make_pr_vuln(severity="info")
        valid, error = validate_pr_vulnerabilities_json(json.dumps([vuln]))
        assert not valid
        assert "invalid severity" in error


class TestGetOutputFormatConfig:
    def test_structure(self):
        config = get_output_format_config()
        assert config["type"] == "json_schema"
        assert "schema" in config
