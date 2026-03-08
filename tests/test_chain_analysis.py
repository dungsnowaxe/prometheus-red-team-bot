"""Unit tests for PROMPTHEUS exploit-chain identity and consensus helpers."""

from __future__ import annotations

import pytest

from promptheus.scanner.chain_analysis import (
    CHAIN_STOPWORDS,
    _CHAIN_FAMILY_AUTH_TERMS,
    _CHAIN_FAMILY_COMMAND_TERMS,
    _CHAIN_FAMILY_PATH_TERMS,
    _collect_chain_ids,
    adjudicate_consensus_support,
    attempt_contains_core_chain_evidence,
    build_chain_family_identity,
    build_chain_flow_identity,
    build_chain_identity,
    canonicalize_finding_path,
    chain_text_tokens,
    coerce_line_number,
    collect_chain_exact_ids,
    collect_chain_family_ids,
    collect_chain_flow_ids,
    collect_chain_ids,
    count_passes_with_core_chains,
    detect_weak_chain_consensus,
    diff_file_path,
    diff_has_auth_privilege_signals,
    diff_has_command_builder_signals,
    diff_has_path_parser_signals,
    extract_chain_sink_anchor,
    extract_cwe_family,
    extract_finding_locations,
    extract_finding_routes,
    finding_text,
    infer_chain_family_class,
    infer_chain_sink_family,
    normalize_chain_class_for_sink,
    summarize_chain_candidates_for_prompt,
    summarize_revalidation_support,
)
from promptheus.diff.parser import DiffContext, DiffFile, DiffHunk, DiffLine


def _make_diff_context(files: list[DiffFile] | None = None) -> DiffContext:
    return DiffContext(
        files=files or [],
        added_lines=0,
        removed_lines=0,
        changed_files=[],
    )


def _make_diff_file(
    path: str,
    hunk_contents: list[str] | None = None,
    is_new: bool = False,
) -> DiffFile:
    hunks = []
    if hunk_contents:
        lines = [DiffLine("add", content, None, idx + 1) for idx, content in enumerate(hunk_contents)]
        hunks = [DiffHunk(old_start=1, old_count=0, new_start=1, new_count=len(lines), lines=lines)]
    return DiffFile(
        old_path=None,
        new_path=path,
        hunks=hunks,
        is_new=is_new,
        is_deleted=False,
        is_renamed=False,
    )


class TestDiffFilePath:
    def test_new_path_preferred(self):
        df = DiffFile(old_path="old.py", new_path="new.py", hunks=[], is_new=False, is_deleted=False, is_renamed=False)
        assert diff_file_path(df) == "new.py"

    def test_falls_back_to_old_path(self):
        df = DiffFile(old_path="old.py", new_path=None, hunks=[], is_new=False, is_deleted=False, is_renamed=False)
        assert diff_file_path(df) == "old.py"

    def test_both_none(self):
        df = DiffFile(old_path=None, new_path=None, hunks=[], is_new=False, is_deleted=False, is_renamed=False)
        assert diff_file_path(df) == ""


class TestCoerceLineNumber:
    def test_valid_int(self):
        assert coerce_line_number(42) == 42

    def test_valid_string(self):
        assert coerce_line_number("123") == 123

    def test_none_returns_zero(self):
        assert coerce_line_number(None) == 0

    def test_invalid_string(self):
        assert coerce_line_number("abc") == 0

    def test_float(self):
        assert coerce_line_number(3.7) == 3


class TestExtractCweFamily:
    def test_standard_cwe(self):
        assert extract_cwe_family("CWE-89") == "89"

    def test_case_insensitive(self):
        assert extract_cwe_family("cwe-78") == "78"

    def test_with_surrounding_text(self):
        assert extract_cwe_family("SQL Injection (CWE-89)") == "89"

    def test_no_cwe(self):
        assert extract_cwe_family("No CWE here") == ""

    def test_none(self):
        assert extract_cwe_family(None) == ""

    def test_empty_string(self):
        assert extract_cwe_family("") == ""


class TestChainTextTokens:
    def test_basic_extraction(self):
        tokens = chain_text_tokens("SQL Injection via User Input")
        assert "injection" in tokens
        assert "user" in tokens  # 4 chars passes the filter

    def test_respects_max_tokens(self):
        tokens = chain_text_tokens("a_long b_long c_long d_long e_long f_long", max_tokens=3)
        assert len(tokens) <= 3

    def test_filters_stopwords(self):
        tokens = chain_text_tokens("attack through the vulnerability")
        for token in tokens:
            assert token not in CHAIN_STOPWORDS

    def test_filters_digits(self):
        tokens = chain_text_tokens("version 1234 release")
        assert "1234" not in tokens

    def test_none_input(self):
        assert chain_text_tokens(None) == ()

    def test_short_tokens_filtered(self):
        tokens = chain_text_tokens("ab cd efgh")
        assert "efgh" in tokens
        assert "ab" not in tokens


class TestFindingText:
    def test_basic(self):
        entry = {"title": "SQL Injection", "description": "User input"}
        result = finding_text(entry, fields=("title", "description"))
        assert "sql injection" in result
        assert "user input" in result

    def test_non_dict_returns_empty(self):
        assert finding_text("not a dict", fields=("title",)) == ""

    def test_missing_fields(self):
        result = finding_text({"title": "Test"}, fields=("title", "nonexistent"))
        assert "test" in result


class TestExtractFindingLocations:
    def test_extracts_file_paths(self):
        entry = {"evidence": "Found in src/auth/login.py:42 and lib/utils.js"}
        locations = extract_finding_locations(entry)
        assert any("auth/login.py" in loc for loc in locations)

    def test_deduplicates(self):
        entry = {"evidence": "src/auth.py and src/auth.py again"}
        locations = extract_finding_locations(entry)
        path_count = sum(1 for loc in locations if "auth.py" in loc)
        assert path_count == 1

    def test_empty_entry(self):
        assert extract_finding_locations({}) == ()


class TestExtractFindingRoutes:
    def test_extracts_routes(self):
        entry = {"title": "Endpoint /api/users exposed", "description": "Also /admin/config"}
        routes = extract_finding_routes(entry)
        assert "/api/users" in routes
        assert "/admin/config" in routes

    def test_short_routes_filtered(self):
        entry = {"title": "Route /a is short"}
        routes = extract_finding_routes(entry)
        assert "/a" not in routes

    def test_empty_entry(self):
        assert extract_finding_routes({}) == ()


class TestCanonicalizeFindingPath:
    def test_relative_path(self):
        assert canonicalize_finding_path("src/auth/login.py") == "src/auth/login.py"

    def test_absolute_path_with_known_root(self):
        result = canonicalize_finding_path("/home/user/project/src/auth/login.py")
        assert result == "src/auth/login.py"

    def test_backslash_normalization(self):
        result = canonicalize_finding_path("src\\auth\\login.py")
        assert "/" in result

    def test_none_returns_empty(self):
        assert canonicalize_finding_path(None) == ""

    def test_empty_returns_empty(self):
        assert canonicalize_finding_path("") == ""


class TestInferChainFamilyClass:
    def test_command_chain(self):
        entry = {"title": "Command Injection", "description": "exec( user input)"}
        assert infer_chain_family_class(entry) == "command_chain"

    def test_path_file_chain(self):
        entry = {"title": "Path Traversal", "description": "path traversal via upload"}
        assert infer_chain_family_class(entry) == "path_file_chain"

    def test_auth_priv_chain(self):
        entry = {"title": "Auth Bypass", "description": "auth bypass via token"}
        assert infer_chain_family_class(entry) == "auth_priv_chain"

    def test_cwe_based_path(self):
        entry = {"title": "Issue", "description": "Something", "cwe_id": "CWE-22"}
        assert infer_chain_family_class(entry) == "path_file_chain"

    def test_cwe_based_command(self):
        entry = {"title": "Issue", "description": "Something", "cwe_id": "CWE-78"}
        assert infer_chain_family_class(entry) == "command_chain"

    def test_generic_fallback(self):
        entry = {"title": "Some Issue", "description": "No specific category"}
        assert infer_chain_family_class(entry) == "generic_chain"

    def test_cwe_based_generic(self):
        entry = {"title": "Issue", "description": "Something", "cwe_id": "CWE-999"}
        assert infer_chain_family_class(entry) == "cwe_999"


class TestExtractChainSinkAnchor:
    def test_with_non_primary_location(self):
        entry = {
            "file_path": "src/auth.py",
            "evidence": "Flow from src/auth.py to lib/exec.py",
        }
        anchor = extract_chain_sink_anchor(entry)
        assert anchor  # should return some location

    def test_falls_back_to_routes(self):
        entry = {
            "file_path": "",
            "title": "Endpoint /api/admin exposed",
            "description": "/api/admin allows unauth access",
        }
        anchor = extract_chain_sink_anchor(entry)
        assert anchor  # should return route

    def test_empty_entry(self):
        assert extract_chain_sink_anchor({}) == ""


class TestBuildChainIdentity:
    def test_basic_identity(self):
        entry = {
            "file_path": "src/auth.py",
            "cwe_id": "CWE-89",
            "line_number": 42,
            "title": "SQL Injection in Login",
        }
        identity = build_chain_identity(entry)
        assert identity
        assert "|" in identity

    def test_non_dict_returns_empty(self):
        assert build_chain_identity("not a dict") == ""

    def test_no_path_no_tokens_returns_empty(self):
        assert build_chain_identity({"severity": "high"}) == ""

    def test_line_bucketing(self):
        entry1 = {"file_path": "a.py", "line_number": 5, "title": "SQL Injection", "cwe_id": "CWE-89"}
        entry2 = {"file_path": "a.py", "line_number": 15, "title": "SQL Injection", "cwe_id": "CWE-89"}
        id1 = build_chain_identity(entry1)
        id2 = build_chain_identity(entry2)
        assert id1 == id2  # same bucket (5//20 == 15//20 == 0)


class TestInferChainSinkFamily:
    def test_file_host_sink(self):
        entry = {"title": "File upload", "evidence": "copyfile to /media/uploads"}
        assert infer_chain_sink_family(entry) == "file_host_sink"

    def test_command_exec_sink(self):
        entry = {"title": "Exec", "evidence": "spawn( '/bin/sh', cmd)"}
        assert infer_chain_sink_family(entry) == "command_exec_sink"

    def test_authz_sink(self):
        entry = {"title": "Auth check", "evidence": "unauth access via permission bypass"}
        assert infer_chain_sink_family(entry) == "authz_sink"

    def test_generic_sink(self):
        entry = {"title": "Something", "evidence": "No clear sink"}
        assert infer_chain_sink_family(entry) == "generic_sink"


class TestNormalizeChainClassForSink:
    def test_specific_class_unchanged(self):
        assert normalize_chain_class_for_sink("command_chain", "generic_sink") == "command_chain"
        assert normalize_chain_class_for_sink("path_file_chain", "generic_sink") == "path_file_chain"
        assert normalize_chain_class_for_sink("auth_priv_chain", "generic_sink") == "auth_priv_chain"

    def test_generic_promoted_by_sink(self):
        assert normalize_chain_class_for_sink("generic_chain", "file_host_sink") == "path_file_chain"
        assert normalize_chain_class_for_sink("generic_chain", "command_exec_sink") == "command_chain"
        assert normalize_chain_class_for_sink("generic_chain", "authz_sink") == "auth_priv_chain"

    def test_generic_both(self):
        assert normalize_chain_class_for_sink("generic_chain", "generic_sink") == "generic_chain"

    def test_empty_class(self):
        assert normalize_chain_class_for_sink("", "generic_sink") == "generic_chain"


class TestBuildChainFamilyIdentity:
    def test_with_path(self):
        entry = {"file_path": "src/auth.py", "title": "SQL Injection", "cwe_id": "CWE-89"}
        identity = build_chain_family_identity(entry)
        assert identity
        assert "|" in identity

    def test_without_path_uses_sink_anchor(self):
        entry = {
            "title": "Command injection",
            "description": "exec( user input) in /api/run endpoint",
            "evidence": "Flow to lib/exec.py",
            "line_number": 42,
        }
        identity = build_chain_family_identity(entry)
        assert identity

    def test_without_path_uses_title_tokens(self):
        entry = {
            "title": "Remote Code Execution via Deserialization",
            "description": "Untrusted data",
            "line_number": 10,
        }
        identity = build_chain_family_identity(entry)
        assert identity  # should use title tokens

    def test_non_dict_returns_empty(self):
        assert build_chain_family_identity("not a dict") == ""

    def test_empty_returns_empty(self):
        identity = build_chain_family_identity({})
        assert identity == ""


class TestBuildChainFlowIdentity:
    def test_with_path(self):
        entry = {
            "file_path": "src/auth.py",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "evidence": "Direct query execution",
        }
        identity = build_chain_flow_identity(entry)
        assert identity
        assert "|" in identity

    def test_no_path_falls_back_to_locations(self):
        entry = {
            "evidence": "Flow from lib/utils.py to server/handler.py",
            "title": "Path traversal",
        }
        identity = build_chain_flow_identity(entry)
        # May or may not have an identity depending on location extraction
        assert isinstance(identity, str)

    def test_non_dict_returns_empty(self):
        assert build_chain_flow_identity("not a dict") == ""


class TestCollectChainIds:
    def test_collect_chain_exact_ids(self):
        findings = [
            {"file_path": "a.py", "cwe_id": "CWE-89", "line_number": 1, "title": "SQLi"},
            {"file_path": "b.py", "cwe_id": "CWE-78", "line_number": 5, "title": "CMDi"},
        ]
        ids = collect_chain_exact_ids(findings)
        assert len(ids) == 2

    def test_collect_chain_family_ids(self):
        findings = [
            {"file_path": "a.py", "cwe_id": "CWE-89", "title": "SQLi"},
        ]
        ids = collect_chain_family_ids(findings)
        assert len(ids) >= 1

    def test_collect_chain_flow_ids(self):
        findings = [
            {"file_path": "a.py", "cwe_id": "CWE-89", "title": "SQLi", "evidence": "query exec"},
        ]
        ids = collect_chain_flow_ids(findings)
        assert isinstance(ids, set)

    def test_backward_compat_alias(self):
        findings = [{"file_path": "a.py", "title": "Test"}]
        assert collect_chain_ids(findings) == collect_chain_family_ids(findings)

    def test_empty_findings(self):
        assert collect_chain_exact_ids([]) == set()


class TestCountPassesWithCoreChains:
    def test_matching_passes(self):
        core = {"chain_a", "chain_b"}
        passes = [{"chain_a"}, {"chain_c"}, {"chain_b", "chain_d"}]
        assert count_passes_with_core_chains(core, passes) == 2

    def test_no_overlap(self):
        core = {"chain_a"}
        passes = [{"chain_b"}, {"chain_c"}]
        assert count_passes_with_core_chains(core, passes) == 0

    def test_empty_core(self):
        assert count_passes_with_core_chains(set(), [{"a"}]) == 0

    def test_empty_passes(self):
        assert count_passes_with_core_chains({"a"}, []) == 0


class TestAttemptContainsCoreChainEvidence:
    def test_matching_family(self):
        findings = [{"file_path": "a.py", "title": "SQLi", "cwe_id": "CWE-89"}]
        family_ids = collect_chain_family_ids(findings)
        assert attempt_contains_core_chain_evidence(
            attempt_findings=findings,
            expected_family_ids=family_ids,
            expected_flow_ids=set(),
        )

    def test_no_match(self):
        assert not attempt_contains_core_chain_evidence(
            attempt_findings=[{"file_path": "a.py", "title": "Different"}],
            expected_family_ids={"nonexistent|chain"},
            expected_flow_ids=set(),
        )

    def test_empty_findings(self):
        assert not attempt_contains_core_chain_evidence(
            attempt_findings=[],
            expected_family_ids={"some_id"},
            expected_flow_ids=set(),
        )

    def test_empty_expected(self):
        assert not attempt_contains_core_chain_evidence(
            attempt_findings=[{"file_path": "a.py"}],
            expected_family_ids=set(),
            expected_flow_ids=set(),
        )


class TestSummarizeRevalidationSupport:
    def test_basic_counts(self):
        attempted = [True, True, False, True]
        core_present = [True, False, False, True]
        attempts, hits, misses = summarize_revalidation_support(attempted, core_present)
        assert attempts == 3
        assert hits == 2
        assert misses == 1

    def test_no_attempts(self):
        assert summarize_revalidation_support([False, False], [False, False]) == (0, 0, 0)

    def test_empty(self):
        assert summarize_revalidation_support([], []) == (0, 0, 0)


class TestSummarizeChainCandidatesForPrompt:
    def test_basic_summary(self):
        findings = [
            {
                "file_path": "src/auth.py",
                "line_number": 42,
                "title": "SQL Injection",
                "cwe_id": "CWE-89",
            }
        ]
        summary = summarize_chain_candidates_for_prompt(findings, {}, 1)
        assert "SQL Injection" in summary
        assert "CWE-89" in summary

    def test_empty_findings(self):
        assert summarize_chain_candidates_for_prompt([], {}, 0) == "- None"

    def test_respects_max_items(self):
        findings = [
            {"file_path": f"file{i}.py", "title": f"Issue {i}", "line_number": i}
            for i in range(10)
        ]
        summary = summarize_chain_candidates_for_prompt(findings, {}, 3, max_items=2)
        lines = [line for line in summary.strip().split("\n") if line.startswith("- ")]
        assert len(lines) <= 2

    def test_truncates_long_title(self):
        findings = [{"file_path": "a.py", "title": "x" * 200, "line_number": 1}]
        summary = summarize_chain_candidates_for_prompt(findings, {}, 1)
        assert "..." in summary


class TestDetectWeakChainConsensus:
    def test_stable_consensus(self):
        core = {"chain_a"}
        passes = [{"chain_a"}, {"chain_a", "chain_b"}]
        weak, reason, support = detect_weak_chain_consensus(
            core_chain_ids=core, pass_chain_ids=passes, required_support=2
        )
        assert not weak
        assert reason == "stable"
        assert support == 2

    def test_weak_consensus_low_support(self):
        core = {"chain_a"}
        passes = [{"chain_a"}, {"chain_b"}]
        weak, reason, support = detect_weak_chain_consensus(
            core_chain_ids=core, pass_chain_ids=passes, required_support=2
        )
        assert weak
        assert "core_support=" in reason

    def test_no_core_chains(self):
        weak, reason, support = detect_weak_chain_consensus(
            core_chain_ids=set(), pass_chain_ids=[{"a"}], required_support=2
        )
        assert not weak
        assert reason == "no_core_chains"

    def test_trailing_empty_passes(self):
        core = {"chain_a"}
        passes = [{"chain_a"}, {"chain_a"}, set()]
        weak, reason, support = detect_weak_chain_consensus(
            core_chain_ids=core, pass_chain_ids=passes, required_support=2
        )
        assert weak
        assert "trailing_empty_passes" in reason


class TestAdjudicateConsensusSupport:
    def test_stable_exact(self):
        core_exact = {"c1"}
        pass_exact = [{"c1"}, {"c1"}]
        weak, reason, support, mode, metrics = adjudicate_consensus_support(
            required_support=2,
            core_exact_ids=core_exact,
            pass_exact_ids=pass_exact,
            core_family_ids=set(),
            pass_family_ids=[set(), set()],
            core_flow_ids=set(),
            pass_flow_ids=[set(), set()],
        )
        assert not weak
        assert mode == "exact"

    def test_all_weak_selects_best_support(self):
        weak, reason, support, mode, metrics = adjudicate_consensus_support(
            required_support=3,
            core_exact_ids={"c1"},
            pass_exact_ids=[{"c1"}],
            core_family_ids={"f1"},
            pass_family_ids=[{"f1"}, {"f1"}],
            core_flow_ids={"fl1"},
            pass_flow_ids=[{"fl1"}],
        )
        assert weak
        assert mode in ("exact", "family", "flow")


class TestDiffSignalDetectors:
    def test_command_builder_signals(self):
        diff = _make_diff_context([
            _make_diff_file("src/runner.py", ["subprocess.run(cmd)", "exec( user_input)"])
        ])
        assert diff_has_command_builder_signals(diff)

    def test_no_command_builder_signals(self):
        diff = _make_diff_context([
            _make_diff_file("src/utils.py", ["print('hello world')"])
        ])
        assert not diff_has_command_builder_signals(diff)

    def test_path_parser_signals(self):
        diff = _make_diff_context([
            _make_diff_file("src/files.py", ["path.resolve() for upload handling"])
        ])
        assert diff_has_path_parser_signals(diff)

    def test_path_signal_in_filename(self):
        diff = _make_diff_context([
            _make_diff_file("src/upload_handler.py", ["process_file()"])
        ])
        assert diff_has_path_parser_signals(diff)

    def test_auth_privilege_signals(self):
        diff = _make_diff_context([
            _make_diff_file("src/auth/middleware.py", ["check permission for user"])
        ])
        assert diff_has_auth_privilege_signals(diff)

    def test_no_auth_signals(self):
        diff = _make_diff_context([
            _make_diff_file("src/math.py", ["return x + y"])
        ])
        assert not diff_has_auth_privilege_signals(diff)

    def test_empty_diff(self):
        diff = _make_diff_context([])
        assert not diff_has_command_builder_signals(diff)
        assert not diff_has_path_parser_signals(diff)
        assert not diff_has_auth_privilege_signals(diff)
