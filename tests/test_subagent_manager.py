"""Unit tests for PROMPTHEUS SubAgentManager."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptheus.scanner.subagent_manager import (
    ArtifactStatus,
    ScanMode,
    SubAgentManager,
    SUBAGENT_ARTIFACTS,
    SUBAGENT_ORDER,
)


class TestSubagentOrder:
    def test_order_starts_with_assessment(self):
        assert SUBAGENT_ORDER[0] == "assessment"

    def test_order_ends_with_dast(self):
        assert SUBAGENT_ORDER[-1] == "dast"

    def test_order_has_five_phases(self):
        assert len(SUBAGENT_ORDER) == 5

    def test_all_phases_in_artifacts_map(self):
        for phase in SUBAGENT_ORDER:
            assert phase in SUBAGENT_ARTIFACTS


class TestSubagentArtifacts:
    def test_assessment_creates_security_md(self):
        assert SUBAGENT_ARTIFACTS["assessment"]["creates"] == "SECURITY.md"
        assert SUBAGENT_ARTIFACTS["assessment"]["requires"] is None

    def test_threat_modeling_depends_on_security_md(self):
        assert SUBAGENT_ARTIFACTS["threat-modeling"]["creates"] == "THREAT_MODEL.json"
        assert SUBAGENT_ARTIFACTS["threat-modeling"]["requires"] == "SECURITY.md"

    def test_code_review_depends_on_threat_model(self):
        assert SUBAGENT_ARTIFACTS["code-review"]["creates"] == "VULNERABILITIES.json"
        assert SUBAGENT_ARTIFACTS["code-review"]["requires"] == "THREAT_MODEL.json"

    def test_report_depends_on_vulnerabilities(self):
        assert SUBAGENT_ARTIFACTS["report-generator"]["creates"] == "scan_results.json"
        assert SUBAGENT_ARTIFACTS["report-generator"]["requires"] == "VULNERABILITIES.json"

    def test_dast_depends_on_vulnerabilities(self):
        assert SUBAGENT_ARTIFACTS["dast"]["creates"] == "DAST_VALIDATION.json"
        assert SUBAGENT_ARTIFACTS["dast"]["requires"] == "VULNERABILITIES.json"


class TestCheckArtifact:
    def test_nonexistent_artifact(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        status = manager.check_artifact("SECURITY.md")
        assert status.exists is False
        assert status.valid is False

    def test_valid_json_artifact(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        vulns = [{"threat_id": "T1", "title": "SQLi", "severity": "high"}]
        (pd / "VULNERABILITIES.json").write_text(json.dumps(vulns), encoding="utf-8")

        manager = SubAgentManager(temp_dir)
        status = manager.check_artifact("VULNERABILITIES.json")
        assert status.exists is True
        assert status.valid is True
        assert status.issue_count == 1

    def test_invalid_json_artifact(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        (pd / "VULNERABILITIES.json").write_text("{broken", encoding="utf-8")

        manager = SubAgentManager(temp_dir)
        status = manager.check_artifact("VULNERABILITIES.json")
        assert status.exists is True
        assert status.valid is False
        assert "Invalid JSON" in (status.error or "")

    def test_valid_markdown_artifact(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        (pd / "SECURITY.md").write_text("# Security Assessment\nContent here.\n")

        manager = SubAgentManager(temp_dir)
        status = manager.check_artifact("SECURITY.md")
        assert status.exists is True
        assert status.valid is True

    def test_empty_markdown_artifact(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        (pd / "SECURITY.md").write_text("")

        manager = SubAgentManager(temp_dir)
        status = manager.check_artifact("SECURITY.md")
        assert status.exists is True
        assert status.valid is False
        assert status.error == "Empty file"

    def test_wrapped_vulnerabilities_json(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        data = {"vulnerabilities": [{"id": "V1"}, {"id": "V2"}]}
        (pd / "VULNERABILITIES.json").write_text(json.dumps(data), encoding="utf-8")

        manager = SubAgentManager(temp_dir)
        status = manager.check_artifact("VULNERABILITIES.json")
        assert status.issue_count == 2


class TestGetDependencies:
    def test_assessment_has_no_requirement(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        deps = manager.get_subagent_dependencies("assessment")
        assert deps["creates"] == "SECURITY.md"
        assert deps["requires"] is None

    def test_code_review_requires_threat_model(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        deps = manager.get_subagent_dependencies("code-review")
        assert deps["requires"] == "THREAT_MODEL.json"

    def test_unknown_subagent_raises(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        with pytest.raises(ValueError, match="Unknown sub-agent"):
            manager.get_subagent_dependencies("nonexistent")


class TestGetResumeSubagents:
    def test_resume_from_assessment(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        result = manager.get_resume_subagents("assessment")
        assert result == SUBAGENT_ORDER

    def test_resume_from_code_review(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        result = manager.get_resume_subagents("code-review")
        assert result == ["code-review", "report-generator", "dast"]

    def test_resume_from_dast(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        result = manager.get_resume_subagents("dast")
        assert result == ["dast"]

    def test_unknown_subagent_raises(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        with pytest.raises(ValueError, match="Unknown sub-agent"):
            manager.get_resume_subagents("bogus")


class TestValidatePrerequisites:
    def test_assessment_always_valid(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        is_valid, error = manager.validate_prerequisites("assessment")
        assert is_valid is True
        assert error is None

    def test_threat_modeling_missing_prereq(self, temp_dir: Path):
        manager = SubAgentManager(temp_dir)
        is_valid, error = manager.validate_prerequisites("threat-modeling")
        assert is_valid is False
        assert "SECURITY.md" in (error or "")

    def test_threat_modeling_with_prereq(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        (pd / "SECURITY.md").write_text("# Security Assessment\nContent.\n")

        manager = SubAgentManager(temp_dir)
        is_valid, error = manager.validate_prerequisites("threat-modeling")
        assert is_valid is True
        assert error is None

    def test_code_review_invalid_prereq(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        (pd / "THREAT_MODEL.json").write_text("{broken", encoding="utf-8")

        manager = SubAgentManager(temp_dir)
        is_valid, error = manager.validate_prerequisites("code-review")
        assert is_valid is False
        assert "Invalid prerequisite" in (error or "")


class TestScanMode:
    def test_enum_values(self):
        assert ScanMode.USE_EXISTING.value == "use_existing"
        assert ScanMode.FULL_RESCAN.value == "full_rescan"
        assert ScanMode.CANCEL.value == "cancel"


class TestArtifactStatus:
    def test_nonexistent_defaults(self):
        status = ArtifactStatus(exists=False)
        assert status.path is None
        assert status.valid is False
        assert status.age_hours is None
        assert status.size_bytes is None
        assert status.issue_count is None
        assert status.error is None
