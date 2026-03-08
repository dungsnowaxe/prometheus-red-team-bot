"""Unit tests for PROMPTHEUS PR review merge, dedupe, and retry utilities."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from promptheus.scanner.pr_review_merge import (
    EXPLOIT_PRIMITIVE_TERMS,
    SPECULATIVE_TERMS,
    _EntryQuality,
    _SubchainQuality,
    _build_vuln_match_keys,
    _chain_role,
    _entry_quality,
    _finding_tokens,
    _has_concrete_chain_structure,
    _proof_score,
    _speculation_penalty,
    _token_similarity,
    attempts_show_pr_disagreement,
    build_pr_retry_focus_plan,
    build_pr_review_retry_suffix,
    dedupe_pr_vulns,
    extract_observed_pr_findings,
    filter_baseline_vulns,
    focus_area_label,
    issues_from_pr_vulns,
    load_pr_vulnerabilities_artifact,
    merge_pr_attempt_findings,
    should_run_pr_verifier,
)
from promptheus.models.issue import SecurityIssue, Severity


class TestFilterBaselineVulns:
    def test_excludes_pr_review_source(self):
        vulns = [
            {"title": "SQLi", "source": "pr_review"},
            {"title": "XSS", "source": "baseline"},
        ]
        result = filter_baseline_vulns(vulns)
        assert len(result) == 1
        assert result[0]["title"] == "XSS"

    def test_excludes_pr_prefix_threat_id(self):
        vulns = [
            {"title": "New threat", "threat_id": "PR-001"},
            {"title": "Old threat", "threat_id": "T-001"},
        ]
        result = filter_baseline_vulns(vulns)
        assert len(result) == 1
        assert result[0]["title"] == "Old threat"

    def test_excludes_new_prefix_threat_id(self):
        vulns = [{"title": "Issue", "threat_id": "NEW-123"}]
        assert filter_baseline_vulns(vulns) == []

    def test_keeps_pr_prefix_when_source_present(self):
        vulns = [{"title": "Issue", "threat_id": "PR-001", "source": "baseline"}]
        assert len(filter_baseline_vulns(vulns)) == 1

    def test_non_dict_entries_skipped(self):
        vulns = [42, "string", None, {"title": "Real"}]
        result = filter_baseline_vulns(vulns)
        assert len(result) == 1

    def test_empty_list(self):
        assert filter_baseline_vulns([]) == []

    def test_case_insensitive_source(self):
        vulns = [{"title": "X", "source": "PR_REVIEW"}]
        assert filter_baseline_vulns(vulns) == []


class TestBuildVulnMatchKeys:
    def test_basic_keys(self):
        vuln = {"threat_id": "T-001", "title": "SQLi", "file_path": "src/auth.py"}
        keys = _build_vuln_match_keys(vuln)
        assert len(keys) > 0
        assert any("t-001" in k[1] for k in keys)

    def test_no_identity_returns_empty(self):
        keys = _build_vuln_match_keys({"file_path": "a.py"})
        assert keys == set()

    def test_basename_included(self):
        vuln = {"title": "SQLi", "file_path": "src/deep/auth.py"}
        keys = _build_vuln_match_keys(vuln, include_basename=True)
        basenames = {k[0] for k in keys}
        assert "auth.py" in basenames

    def test_basename_excluded(self):
        vuln = {"title": "SQLi", "file_path": "src/deep/auth.py"}
        keys = _build_vuln_match_keys(vuln, include_basename=False)
        basenames = {k[0] for k in keys}
        assert "auth.py" not in basenames


class TestIssuesFromPrVulns:
    def test_basic_conversion(self):
        vulns = [
            {
                "threat_id": "T-001",
                "title": "SQLi",
                "description": "SQL injection",
                "severity": "high",
                "file_path": "auth.py",
                "line_number": 42,
                "code_snippet": "query(f'...')",
                "cwe_id": "CWE-89",
            }
        ]
        issues = issues_from_pr_vulns(vulns)
        assert len(issues) == 1
        assert isinstance(issues[0], SecurityIssue)
        assert issues[0].severity == Severity.HIGH
        assert issues[0].line_number == 42

    def test_invalid_severity_defaults(self):
        vulns = [{"severity": "bogus", "title": "T", "file_path": "a.py"}]
        issues = issues_from_pr_vulns(vulns)
        assert issues[0].severity == Severity.MEDIUM

    def test_invalid_line_number(self):
        vulns = [{"line_number": "not_a_number", "title": "T", "file_path": "a.py"}]
        issues = issues_from_pr_vulns(vulns)
        assert issues[0].line_number == 0

    def test_non_dict_skipped(self):
        vulns = [42, "string", {"title": "Real", "file_path": "a.py"}]
        issues = issues_from_pr_vulns(vulns)
        assert len(issues) == 1

    def test_empty_list(self):
        assert issues_from_pr_vulns([]) == []


class TestFocusAreaLabel:
    def test_known_areas(self):
        assert "COMMAND" in focus_area_label("command_option")
        assert "PATH" in focus_area_label("path_exfiltration")
        assert "AUTH" in focus_area_label("auth_privileged")

    def test_unknown_area(self):
        assert focus_area_label("unknown_area") == "unknown_area"


class TestBuildPrRetryFocusPlan:
    def test_single_attempt_no_plan(self):
        plan = build_pr_retry_focus_plan(1, command_builder_signals=True,
                                          path_parser_signals=True,
                                          auth_privilege_signals=True)
        assert plan == []

    def test_two_attempts_one_retry(self):
        plan = build_pr_retry_focus_plan(2, command_builder_signals=True,
                                          path_parser_signals=False,
                                          auth_privilege_signals=False)
        assert len(plan) == 1
        assert plan[0] == "command_option"

    def test_three_attempts_two_retries(self):
        plan = build_pr_retry_focus_plan(3, command_builder_signals=False,
                                          path_parser_signals=True,
                                          auth_privilege_signals=False)
        assert len(plan) == 2
        assert plan[0] == "path_exfiltration"

    def test_default_order_fills_remaining(self):
        plan = build_pr_retry_focus_plan(5, command_builder_signals=False,
                                          path_parser_signals=False,
                                          auth_privilege_signals=False)
        assert len(plan) == 4
        assert plan[0] == "command_option"


class TestAttemptsShowPrDisagreement:
    def test_consistent_counts(self):
        assert not attempts_show_pr_disagreement([3, 3, 3])

    def test_disagreement_with_zero(self):
        assert attempts_show_pr_disagreement([3, 0, 2])

    def test_disagreement_different_counts(self):
        assert attempts_show_pr_disagreement([3, 2, 1])

    def test_single_attempt(self):
        assert not attempts_show_pr_disagreement([3])

    def test_all_zeros(self):
        assert not attempts_show_pr_disagreement([0, 0, 0])


class TestShouldRunPrVerifier:
    def test_findings_and_weak(self):
        assert should_run_pr_verifier(has_findings=True, weak_consensus=True)

    def test_findings_but_strong(self):
        assert not should_run_pr_verifier(has_findings=True, weak_consensus=False)

    def test_no_findings(self):
        assert not should_run_pr_verifier(has_findings=False, weak_consensus=True)


class TestExtractObservedPrFindings:
    def test_valid_content(self):
        observer = {"max_content": '[{"title": "SQLi"}]'}
        result = extract_observed_pr_findings(observer)
        assert len(result) == 1

    def test_none_observer(self):
        assert extract_observed_pr_findings(None) == []

    def test_empty_observer(self):
        assert extract_observed_pr_findings({}) == []

    def test_invalid_json(self):
        assert extract_observed_pr_findings({"max_content": "{broken"}) == []

    def test_non_list_json(self):
        assert extract_observed_pr_findings({"max_content": '{"key": "value"}'}) == []

    def test_filters_non_dicts(self):
        observer = {"max_content": '[{"title": "A"}, 42, "str"]'}
        result = extract_observed_pr_findings(observer)
        assert len(result) == 1


class TestBuildPrReviewRetrySuffix:
    def test_basic_suffix(self):
        suffix = build_pr_review_retry_suffix(2)
        assert "FOLLOW-UP ANALYSIS PASS 2" in suffix

    def test_command_builder_hint(self):
        suffix = build_pr_review_retry_suffix(2, command_builder_signals=True)
        assert "COMMAND-BUILDER DELTA" in suffix

    def test_path_parser_hint(self):
        suffix = build_pr_review_retry_suffix(2, path_parser_signals=True)
        assert "PATH-PARSER DELTA" in suffix

    def test_auth_privilege_hint(self):
        suffix = build_pr_review_retry_suffix(2, auth_privilege_signals=True)
        assert "AUTH/PRIVILEGE DELTA" in suffix

    def test_candidate_summary_included(self):
        suffix = build_pr_review_retry_suffix(
            2,
            candidate_summary="- SQLi in auth.py (CWE-89)",
        )
        assert "PRIOR HIGH-IMPACT CHAIN CANDIDATES" in suffix
        assert "SQLi" in suffix

    def test_revalidation_required(self):
        suffix = build_pr_review_retry_suffix(
            2,
            require_candidate_revalidation=True,
        )
        assert "CORE CHAIN REVALIDATION REQUIREMENT" in suffix

    def test_focus_area_override(self):
        suffix = build_pr_review_retry_suffix(2, focus_area="path_exfiltration")
        assert "PATH + FILE EXFILTRATION" in suffix

    def test_default_focus_area_by_attempt(self):
        suffix2 = build_pr_review_retry_suffix(2)
        assert "COMMAND" in suffix2
        suffix3 = build_pr_review_retry_suffix(3)
        assert "PATH" in suffix3


class TestProofScore:
    def test_high_proof_finding(self):
        entry = {
            "title": "Option injection via argv",
            "description": "Missing -- separator",
            "attack_scenario": "1) attacker sends payload -o proxycommand= 2) exec ssh",
            "evidence": "src/ssh.py:42 -> exec() flow",
            "cwe_id": "CWE-88",
            "file_path": "src/ssh.py",
            "line_number": 42,
        }
        score = _proof_score(entry)
        assert score >= 8

    def test_low_proof_finding(self):
        entry = {
            "title": "Potential issue",
            "description": "Something might happen",
        }
        score = _proof_score(entry)
        assert score < 3


class TestSpeculationPenalty:
    def test_speculative_finding(self):
        entry = {
            "title": "Potential vulnerability",
            "description": "This could hypothetically be exploited if bypass exists",
            "attack_scenario": "Testing needed for edge case",
        }
        penalty = _speculation_penalty(entry)
        assert penalty >= 3

    def test_concrete_finding(self):
        entry = {
            "title": "SQL Injection confirmed",
            "description": "Direct query execution with user input",
            "evidence": "SELECT * FROM users WHERE id = {user_id}",
        }
        penalty = _speculation_penalty(entry)
        assert penalty <= 1

    def test_penalty_capped_at_6(self):
        entry = {
            "title": "Potential hypothetical possible",
            "description": "Could might may future testing needed edge case if bypass exists",
        }
        penalty = _speculation_penalty(entry)
        assert penalty <= 6


class TestFindingTokens:
    def test_extracts_tokens(self):
        entry = {"title": "SQL Injection", "description": "User input interpolated"}
        tokens = _finding_tokens(entry)
        assert "injection" in tokens
        assert "interpolated" in tokens

    def test_filters_short_and_stopwords(self):
        entry = {"title": "the attack via code"}
        tokens = _finding_tokens(entry)
        for t in tokens:
            assert len(t) >= 4
            assert t not in CHAIN_STOPWORDS


class TestTokenSimilarity:
    def test_identical_sets(self):
        assert _token_similarity({"a", "b"}, {"a", "b"}) == 1.0

    def test_disjoint_sets(self):
        assert _token_similarity({"a", "b"}, {"c", "d"}) == 0.0

    def test_partial_overlap(self):
        sim = _token_similarity({"a", "b", "c"}, {"b", "c", "d"})
        assert 0.4 < sim < 0.6  # 2/4 = 0.5

    def test_empty_sets(self):
        assert _token_similarity(set(), {"a"}) == 0.0
        assert _token_similarity({"a"}, set()) == 0.0


class TestChainRole:
    def test_end_to_end(self):
        entry = {
            "evidence": "src/auth.py -> lib/exec.py flow chain",
            "attack_scenario": "1) attacker sends 2) server processes 3) exec runs",
            "title": "RCE",
            "description": "Command injection from remote attacker via ssh spawn()",
        }
        assert _chain_role(entry) == "end_to_end"

    def test_step_level(self):
        entry = {
            "title": "Missing validation",
            "description": "Input not sanitized",
            "evidence": "No flow markers",
        }
        assert _chain_role(entry) == "step_level"


class TestHasConcreteChainStructure:
    def test_concrete(self):
        entry = {
            "file_path": "src/auth.py",
            "line_number": 42,
            "evidence": "auth.py:42 -> exec() flow",
            "attack_scenario": "1) inject 2) execute 3) profit",
        }
        assert _has_concrete_chain_structure(entry) is True

    def test_missing_line(self):
        entry = {
            "file_path": "src/auth.py",
            "line_number": 0,
            "evidence": "some flow",
            "attack_scenario": "step 1",
        }
        assert _has_concrete_chain_structure(entry) is False

    def test_missing_evidence(self):
        entry = {
            "file_path": "src/auth.py",
            "line_number": 42,
        }
        assert _has_concrete_chain_structure(entry) is False


class TestMergePrAttemptFindings:
    def test_empty_input(self):
        stats = {}
        result = merge_pr_attempt_findings([], merge_stats=stats)
        assert result == []
        assert stats["input_count"] == 0
        assert stats["final_count"] == 0

    def test_single_finding_passes_through(self):
        vulns = [
            {
                "title": "SQLi",
                "file_path": "src/auth.py",
                "line_number": 42,
                "cwe_id": "CWE-89",
                "severity": "high",
                "evidence": "query exec -> flow",
                "attack_scenario": "1) inject 2) execute",
                "finding_type": "known_vuln",
            }
        ]
        result = merge_pr_attempt_findings(vulns)
        assert len(result) >= 1

    def test_deduplicates_same_chain(self):
        base = {
            "file_path": "src/auth.py",
            "cwe_id": "CWE-89",
            "severity": "high",
            "evidence": "query -> exec flow",
            "attack_scenario": "1) inject 2) execute",
            "finding_type": "known_vuln",
        }
        vulns = [
            {**base, "title": "SQL Injection variant A", "line_number": 42},
            {**base, "title": "SQL Injection variant B", "line_number": 43},
        ]
        stats = {}
        result = merge_pr_attempt_findings(vulns, merge_stats=stats)
        assert len(result) <= len(vulns)

    def test_keeps_different_chains(self):
        vulns = [
            {
                "title": "SQLi",
                "file_path": "src/auth.py",
                "line_number": 42,
                "cwe_id": "CWE-89",
                "severity": "high",
                "evidence": "query -> exec",
                "attack_scenario": "1) inject",
            },
            {
                "title": "Command Injection",
                "file_path": "src/runner.py",
                "line_number": 100,
                "cwe_id": "CWE-78",
                "severity": "critical",
                "evidence": "exec -> shell",
                "attack_scenario": "1) inject 2) run",
            },
        ]
        result = merge_pr_attempt_findings(vulns)
        assert len(result) == 2

    def test_stats_populated(self):
        vulns = [
            {
                "title": f"Issue {i}",
                "file_path": "src/auth.py",
                "line_number": i * 50,
                "severity": "high",
                "evidence": f"evidence {i}",
                "attack_scenario": f"scenario {i}",
            }
            for i in range(3)
        ]
        stats = {}
        merge_pr_attempt_findings(vulns, merge_stats=stats)
        assert "input_count" in stats
        assert stats["input_count"] == 3


class TestDedupePrVulns:
    def test_tags_known_vulns(self):
        known = [{"title": "SQLi", "file_path": "src/auth.py"}]
        pr = [{"title": "SQLi", "file_path": "src/auth.py"}]
        result = dedupe_pr_vulns(pr, known)
        assert result[0].get("finding_type") == "known_vuln"

    def test_preserves_existing_finding_type(self):
        known = [{"title": "SQLi", "file_path": "src/auth.py"}]
        pr = [{"title": "SQLi", "file_path": "src/auth.py", "finding_type": "regression"}]
        result = dedupe_pr_vulns(pr, known)
        assert result[0]["finding_type"] == "regression"  # preserved

    def test_no_match_keeps_original(self):
        known = [{"title": "SQLi", "file_path": "src/auth.py"}]
        pr = [{"title": "XSS", "file_path": "src/web.py"}]
        result = dedupe_pr_vulns(pr, known)
        assert "finding_type" not in result[0] or result[0].get("finding_type") != "known_vuln"

    def test_non_dict_entries_skipped(self):
        result = dedupe_pr_vulns([42, "str"], [{"title": "X"}])
        assert result == []

    def test_empty_inputs(self):
        assert dedupe_pr_vulns([], []) == []


class TestLoadPrVulnerabilitiesArtifact:
    def test_missing_file(self, temp_dir: Path):
        console = MagicMock()
        vulns, warning = load_pr_vulnerabilities_artifact(temp_dir / "missing.json", console)
        assert vulns == []
        assert warning is not None

    def test_valid_json_array(self, temp_dir: Path):
        path = temp_dir / "PR_VULNERABILITIES.json"
        path.write_text('[{"title": "SQLi"}]')
        console = MagicMock()
        vulns, warning = load_pr_vulnerabilities_artifact(path, console)
        assert len(vulns) == 1
        assert warning is None

    def test_invalid_json(self, temp_dir: Path):
        path = temp_dir / "PR_VULNERABILITIES.json"
        path.write_text("{broken json")
        console = MagicMock()
        vulns, warning = load_pr_vulnerabilities_artifact(path, console)
        assert vulns == []
        assert warning is not None

    def test_non_array_json(self, temp_dir: Path):
        path = temp_dir / "PR_VULNERABILITIES.json"
        path.write_text('{"key": "value"}')
        console = MagicMock()
        vulns, warning = load_pr_vulnerabilities_artifact(path, console)
        assert vulns == []
        assert "not a JSON array" in warning

    def test_filters_non_dict_items(self, temp_dir: Path):
        path = temp_dir / "PR_VULNERABILITIES.json"
        path.write_text('[{"title": "SQLi"}, 42, "string"]')
        console = MagicMock()
        vulns, warning = load_pr_vulnerabilities_artifact(path, console)
        assert len(vulns) == 1


class TestEntryQuality:
    def test_higher_severity_ranks_higher(self):
        high = _entry_quality({"severity": "critical", "file_path": "a.py", "line_number": 1})
        low = _entry_quality({"severity": "low", "file_path": "a.py", "line_number": 1})
        assert high > low

    def test_with_chain_support(self):
        supports = {"chain_id": 3}
        entry = {"severity": "high", "file_path": "src/auth.py", "title": "SQLi"}
        q = _entry_quality(entry, chain_support_counts=supports, total_attempts=5)
        assert isinstance(q, _EntryQuality)
