"""Unit tests for PROMPTHEUS artifact management."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptheus.scanner.artifacts import (
    ArtifactLoadError,
    ArtifactUpdateResult,
    update_pr_review_artifacts,
)


@pytest.fixture
def promptheus_dir(temp_dir: Path) -> Path:
    d = temp_dir / ".promptheus"
    d.mkdir()
    return d


class TestArtifactLoadError:
    def test_error_contains_path_and_message(self, promptheus_dir: Path):
        path = promptheus_dir / "THREAT_MODEL.json"
        err = ArtifactLoadError(path, "invalid JSON")
        assert err.path == path
        assert "invalid JSON" in str(err)
        assert str(path) in str(err)


class TestLoadJsonList:
    def test_missing_file_returns_empty(self, promptheus_dir: Path):
        from promptheus.scanner.artifacts import _load_json_list
        result = _load_json_list(promptheus_dir / "nonexistent.json")
        assert result == []

    def test_valid_array_loads(self, promptheus_dir: Path):
        from promptheus.scanner.artifacts import _load_json_list
        path = promptheus_dir / "data.json"
        path.write_text('[{"id": "T1"}]', encoding="utf-8")
        result = _load_json_list(path)
        assert len(result) == 1
        assert result[0]["id"] == "T1"

    def test_non_array_raises(self, promptheus_dir: Path):
        from promptheus.scanner.artifacts import _load_json_list
        path = promptheus_dir / "data.json"
        path.write_text('{"key": "value"}', encoding="utf-8")
        with pytest.raises(ArtifactLoadError, match="expected top-level JSON array"):
            _load_json_list(path)

    def test_invalid_json_raises(self, promptheus_dir: Path):
        from promptheus.scanner.artifacts import _load_json_list
        path = promptheus_dir / "data.json"
        path.write_text("{broken json", encoding="utf-8")
        with pytest.raises(ArtifactLoadError, match="invalid JSON"):
            _load_json_list(path)


class TestWriteJsonList:
    def test_round_trip(self, promptheus_dir: Path):
        from promptheus.scanner.artifacts import _write_json_list, _load_json_list
        path = promptheus_dir / "output.json"
        data = [{"id": "T1", "title": "Test"}]
        _write_json_list(path, data)
        loaded = _load_json_list(path)
        assert loaded == data

    def test_creates_parent_directories(self, temp_dir: Path):
        from promptheus.scanner.artifacts import _write_json_list
        path = temp_dir / "nested" / "dir" / "output.json"
        _write_json_list(path, [{"x": 1}])
        assert path.exists()
        assert json.loads(path.read_text()) == [{"x": 1}]

    def test_atomic_write_survives_overwrite(self, promptheus_dir: Path):
        from promptheus.scanner.artifacts import _write_json_list, _load_json_list
        path = promptheus_dir / "output.json"
        _write_json_list(path, [{"version": 1}])
        _write_json_list(path, [{"version": 2}])
        loaded = _load_json_list(path)
        assert loaded == [{"version": 2}]


class TestUpdatePrReviewArtifacts:
    def test_empty_vulns_returns_zeros(self, promptheus_dir: Path):
        result = update_pr_review_artifacts(promptheus_dir, [])
        assert result.threats_added == 0
        assert result.vulnerabilities_added == 0
        assert result.new_components_detected is False

    def test_new_threat_added(self, promptheus_dir: Path):
        (promptheus_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
        (promptheus_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

        pr_vulns = [
            {
                "finding_type": "new_threat",
                "threat_id": "T-PR-001",
                "title": "New auth bypass threat",
                "description": "Auth can be bypassed via token reuse",
                "severity": "HIGH",
                "file_path": "src/auth/login.py",
            }
        ]
        result = update_pr_review_artifacts(promptheus_dir, pr_vulns)
        assert result.threats_added == 1
        assert result.vulnerabilities_added == 0

        threats = json.loads((promptheus_dir / "THREAT_MODEL.json").read_text())
        assert len(threats) == 1
        assert threats[0]["id"] == "T-PR-001"

    def test_known_vuln_added(self, promptheus_dir: Path):
        (promptheus_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
        (promptheus_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

        pr_vulns = [
            {
                "finding_type": "known_vuln",
                "title": "SQL Injection",
                "severity": "HIGH",
                "file_path": "api.py",
                "line_number": 42,
            }
        ]
        result = update_pr_review_artifacts(promptheus_dir, pr_vulns)
        assert result.threats_added == 0
        assert result.vulnerabilities_added == 1

        vulns = json.loads((promptheus_dir / "VULNERABILITIES.json").read_text())
        assert len(vulns) == 1
        assert vulns[0]["source"] == "pr_review"

    def test_duplicate_threat_not_added_twice(self, promptheus_dir: Path):
        existing = [{"id": "T-PR-001", "category": "PR-Review", "title": "Existing"}]
        (promptheus_dir / "THREAT_MODEL.json").write_text(json.dumps(existing), encoding="utf-8")
        (promptheus_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

        pr_vulns = [
            {
                "finding_type": "new_threat",
                "threat_id": "T-PR-001",
                "title": "Duplicate",
                "severity": "HIGH",
                "file_path": "auth.py",
            }
        ]
        result = update_pr_review_artifacts(promptheus_dir, pr_vulns)
        assert result.threats_added == 0

    def test_duplicate_vuln_not_added_twice(self, promptheus_dir: Path):
        existing_vulns = [
            {"title": "SQL Injection", "severity": "HIGH", "file_path": "api.py", "line_number": 42}
        ]
        (promptheus_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
        (promptheus_dir / "VULNERABILITIES.json").write_text(
            json.dumps(existing_vulns), encoding="utf-8"
        )

        pr_vulns = [
            {
                "finding_type": "known_vuln",
                "title": "SQL Injection",
                "severity": "HIGH",
                "file_path": "api.py",
                "line_number": 42,
            }
        ]
        result = update_pr_review_artifacts(promptheus_dir, pr_vulns)
        assert result.vulnerabilities_added == 0

    def test_unknown_finding_type_treated_as_vuln(self, promptheus_dir: Path):
        (promptheus_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
        (promptheus_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

        pr_vulns = [
            {
                "title": "Untyped finding",
                "severity": "MEDIUM",
                "file_path": "utils.py",
                "line_number": 10,
            }
        ]
        result = update_pr_review_artifacts(promptheus_dir, pr_vulns)
        assert result.vulnerabilities_added == 1

    def test_new_components_detected(self, promptheus_dir: Path):
        existing_threats = [
            {"id": "T1", "affected_components": ["auth:py"]}
        ]
        (promptheus_dir / "THREAT_MODEL.json").write_text(
            json.dumps(existing_threats), encoding="utf-8"
        )
        (promptheus_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

        pr_vulns = [
            {
                "finding_type": "known_vuln",
                "title": "New component vuln",
                "severity": "HIGH",
                "file_path": "payments/checkout.py",
                "line_number": 5,
            }
        ]
        result = update_pr_review_artifacts(promptheus_dir, pr_vulns)
        assert result.new_components_detected is True

    def test_no_new_components_when_subset(self, promptheus_dir: Path):
        existing_threats = [
            {"id": "T1", "affected_components": ["src:py"]}
        ]
        (promptheus_dir / "THREAT_MODEL.json").write_text(
            json.dumps(existing_threats), encoding="utf-8"
        )
        (promptheus_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")

        pr_vulns = [
            {
                "finding_type": "known_vuln",
                "title": "Same component vuln",
                "severity": "HIGH",
                "file_path": "src/auth.py",
                "line_number": 5,
            }
        ]
        result = update_pr_review_artifacts(promptheus_dir, pr_vulns)
        assert result.new_components_detected is False

    def test_malformed_baseline_raises(self, promptheus_dir: Path):
        (promptheus_dir / "THREAT_MODEL.json").write_text("{not-an-array}", encoding="utf-8")
        with pytest.raises(ArtifactLoadError, match="invalid JSON"):
            update_pr_review_artifacts(promptheus_dir, [])

    def test_non_mapping_items_ignored(self, promptheus_dir: Path):
        (promptheus_dir / "THREAT_MODEL.json").write_text("[]", encoding="utf-8")
        (promptheus_dir / "VULNERABILITIES.json").write_text("[]", encoding="utf-8")
        pr_vulns = ["not-a-dict", 42, None]
        result = update_pr_review_artifacts(promptheus_dir, pr_vulns)
        assert result.threats_added == 0
        assert result.vulnerabilities_added == 0
