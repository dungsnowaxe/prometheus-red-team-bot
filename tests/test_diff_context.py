"""Unit tests for PROMPTHEUS diff context extraction helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptheus.diff.context import (
    DEFAULT_CONTEXT_LIMIT,
    IGNORE_TOKENS,
    MATCHED_SECTIONS_LIMIT,
    SECURITY_ADJACENT_TOKENS,
    _build_tokens,
    _clip_text,
    _entry_path_candidates,
    _entry_text,
    _load_threat_model,
    _max_path_relevance,
    _path_parts,
    _rank_relevant_entries,
    _safe_text,
    _summarize_entries,
    _tokenize_path,
    check_vuln_overlap,
    extract_relevant_architecture,
    filter_relevant_threats,
    filter_relevant_vulnerabilities,
    normalize_repo_path,
    suggest_security_adjacent_files,
    summarize_threats_for_prompt,
    summarize_vulnerabilities_for_prompt,
)


class TestNormalizeRepoPath:
    def test_basic_path(self):
        assert normalize_repo_path("src/auth/login.py") == "src/auth/login.py"

    def test_leading_dot_slash(self):
        assert normalize_repo_path("./src/auth.py") == "src/auth.py"

    def test_double_dot_slash(self):
        assert normalize_repo_path("././src/auth.py") == "src/auth.py"

    def test_backslash(self):
        assert normalize_repo_path("src\\auth\\login.py") == "src/auth/login.py"

    def test_double_slash(self):
        assert normalize_repo_path("src//auth//login.py") == "src/auth/login.py"

    def test_non_string_returns_empty(self):
        assert normalize_repo_path(42) == ""
        assert normalize_repo_path(None) == ""

    def test_whitespace_stripped(self):
        assert normalize_repo_path("  src/auth.py  ") == "src/auth.py"


class TestTokenizePath:
    def test_basic_path(self):
        tokens = _tokenize_path("src/auth/login.py")
        assert "auth" in tokens
        assert "login" in tokens

    def test_hyphenated_parts(self):
        tokens = _tokenize_path("src/user-service/handler.py")
        assert "user" in tokens
        assert "service" in tokens


class TestBuildTokens:
    def test_filters_short_and_ignore_tokens(self):
        tokens = _build_tokens(["src/lib/main.py"])
        for token in tokens:
            assert len(token) >= 2
            assert token not in IGNORE_TOKENS

    def test_empty_input(self):
        assert _build_tokens([]) == []


class TestSafeText:
    def test_string_stripped(self):
        assert _safe_text("  hello  ") == "hello"

    def test_non_string(self):
        assert _safe_text(42) == ""
        assert _safe_text(None) == ""


class TestClipText:
    def test_short_text(self):
        assert _clip_text("short") == "short"

    def test_long_text(self):
        result = _clip_text("x" * 300, max_chars=100)
        assert len(result) <= 100
        assert result.endswith("...")

    def test_non_string(self):
        assert _clip_text(42) == ""


class TestPathParts:
    def test_basic(self):
        assert _path_parts("src/auth/login.py") == ("src", "auth", "login.py")

    def test_empty_parts_filtered(self):
        parts = _path_parts("src//auth.py")
        assert "" not in parts


class TestMaxPathRelevance:
    def test_exact_match(self):
        score = _max_path_relevance(["src/auth.py"], ["src/auth.py"])
        assert score >= 100

    def test_same_parent(self):
        score = _max_path_relevance(["src/auth/login.py"], ["src/auth/register.py"])
        assert score >= 80

    def test_no_match(self):
        score = _max_path_relevance(["src/auth.py"], ["lib/utils.py"])
        assert score < 50

    def test_empty_candidates(self):
        assert _max_path_relevance([], ["src/auth.py"]) == 0

    def test_empty_changed(self):
        assert _max_path_relevance(["src/auth.py"], []) == 0


class TestEntryText:
    def test_string_values(self):
        entry = {"title": "SQLi", "description": "Injection attack"}
        text = _entry_text(entry, ("title", "description"))
        assert "sqli" in text
        assert "injection attack" in text

    def test_list_values(self):
        entry = {"components": ["auth", "api"]}
        text = _entry_text(entry, ("components",))
        assert "auth" in text
        assert "api" in text

    def test_missing_key(self):
        text = _entry_text({"title": "X"}, ("title", "nonexistent"))
        assert "x" in text


class TestEntryPathCandidates:
    def test_file_path(self):
        entry = {"file_path": "src/auth.py"}
        candidates = _entry_path_candidates(entry)
        assert "src/auth.py" in candidates

    def test_affected_files_list_of_dicts(self):
        entry = {"affected_files": [{"file_path": "a.py"}, {"file_path": "b.py"}]}
        candidates = _entry_path_candidates(entry)
        assert "a.py" in candidates
        assert "b.py" in candidates

    def test_affected_files_list_of_strings(self):
        entry = {"affected_files": ["a.py", "b.py"]}
        candidates = _entry_path_candidates(entry)
        assert "a.py" in candidates

    def test_deduplication(self):
        entry = {"file_path": "a.py", "affected_files": ["a.py"]}
        candidates = _entry_path_candidates(entry)
        assert candidates.count("a.py") == 1


class TestRankRelevantEntries:
    def test_ranks_by_path_relevance(self):
        entries = [
            {"title": "Unrelated", "file_path": "lib/math.py"},
            {"title": "Auth issue", "file_path": "src/auth/login.py"},
        ]
        ranked = _rank_relevant_entries(
            entries, ["src/auth/register.py"], text_keys=("title",), max_items=10
        )
        assert len(ranked) >= 1
        assert ranked[0]["file_path"] == "src/auth/login.py"

    def test_max_items_respected(self):
        entries = [
            {"title": f"Issue {i}", "file_path": f"src/file{i}.py"} for i in range(10)
        ]
        ranked = _rank_relevant_entries(
            entries, ["src/file0.py"], text_keys=("title",), max_items=3
        )
        assert len(ranked) <= 3

    def test_zero_max_items(self):
        assert _rank_relevant_entries([{"title": "X"}], ["a.py"], text_keys=("title",), max_items=0) == []


class TestSummarizeEntries:
    def test_basic_summary(self):
        entries = [
            {"id": "T-1", "title": "SQLi", "severity": "high", "file_path": "auth.py"}
        ]
        summary = _summarize_entries(entries, id_key="id", max_chars=500)
        assert "T-1" in summary
        assert "SQLi" in summary

    def test_empty_entries(self):
        assert _summarize_entries([], id_key="id", max_chars=500) == "- None"

    def test_respects_max_chars(self):
        entries = [
            {"id": f"T-{i}", "title": f"Issue {i}", "severity": "high"} for i in range(100)
        ]
        summary = _summarize_entries(entries, id_key="id", max_chars=200)
        assert len(summary) <= 250  # some tolerance


class TestLoadThreatModel:
    def test_valid_array(self, temp_dir: Path):
        path = temp_dir / "THREAT_MODEL.json"
        path.write_text('[{"id": "T-1", "title": "Test"}]')
        entries = _load_threat_model(path)
        assert len(entries) == 1

    def test_wrapped_dict(self, temp_dir: Path):
        path = temp_dir / "THREAT_MODEL.json"
        path.write_text('{"threats": [{"id": "T-1"}]}')
        entries = _load_threat_model(path)
        assert len(entries) == 1

    def test_invalid_json(self, temp_dir: Path):
        path = temp_dir / "THREAT_MODEL.json"
        path.write_text("{broken")
        entries = _load_threat_model(path)
        assert entries == []

    def test_empty_file(self, temp_dir: Path):
        path = temp_dir / "THREAT_MODEL.json"
        path.write_text("")
        entries = _load_threat_model(path)
        assert entries == []

    def test_non_dict_entries_filtered(self, temp_dir: Path):
        path = temp_dir / "THREAT_MODEL.json"
        path.write_text('[{"id": "T-1"}, 42, "string"]')
        entries = _load_threat_model(path)
        assert len(entries) == 1


class TestExtractRelevantArchitecture:
    def test_matching_sections(self, temp_dir: Path):
        security_md = temp_dir / "SECURITY.md"
        security_md.write_text(
            "# Overview\nGeneral info.\n\n"
            "# Authentication\nAuth uses JWT tokens.\n\n"
            "# Database\nPostgreSQL backend.\n"
        )
        result = extract_relevant_architecture(security_md, ["src/auth/login.py"])
        assert "Authentication" in result
        assert "JWT" in result

    def test_no_matching_sections_returns_truncated(self, temp_dir: Path):
        security_md = temp_dir / "SECURITY.md"
        security_md.write_text("# Overview\nGeneral project info only.\n")
        result = extract_relevant_architecture(security_md, ["src/totally_unrelated.py"])
        assert "Overview" in result

    def test_missing_file(self, temp_dir: Path):
        result = extract_relevant_architecture(temp_dir / "missing.md", ["a.py"])
        assert result == ""

    def test_empty_file(self, temp_dir: Path):
        security_md = temp_dir / "SECURITY.md"
        security_md.write_text("")
        result = extract_relevant_architecture(security_md, ["a.py"])
        assert result == ""


class TestFilterRelevantThreats:
    def test_basic_filtering(self, temp_dir: Path):
        path = temp_dir / "THREAT_MODEL.json"
        threats = [
            {"id": "T-1", "title": "Auth bypass", "file_path": "src/auth/login.py"},
            {"id": "T-2", "title": "Math error", "file_path": "lib/math.py"},
        ]
        path.write_text(json.dumps(threats))
        result = filter_relevant_threats(path, ["src/auth/register.py"])
        assert len(result) >= 1
        assert result[0]["id"] == "T-1"

    def test_missing_file(self, temp_dir: Path):
        result = filter_relevant_threats(temp_dir / "missing.json", ["a.py"])
        assert result == []


class TestFilterRelevantVulnerabilities:
    def test_basic_filtering(self):
        vulns = [
            {"threat_id": "V-1", "title": "SQLi", "file_path": "src/auth.py"},
            {"threat_id": "V-2", "title": "XSS", "file_path": "lib/other.py"},
        ]
        result = filter_relevant_vulnerabilities(vulns, ["src/auth/login.py"])
        assert len(result) >= 1


class TestSummarizeForPrompt:
    def test_threats_summary(self):
        threats = [{"id": "T-1", "title": "SQLi", "severity": "high"}]
        summary = summarize_threats_for_prompt(threats)
        assert "T-1" in summary

    def test_vulns_summary(self):
        vulns = [{"threat_id": "V-1", "title": "XSS", "severity": "medium"}]
        summary = summarize_vulnerabilities_for_prompt(vulns)
        assert "V-1" in summary


class TestSuggestSecurityAdjacentFiles:
    def test_finds_adjacent_security_files(self, temp_dir: Path):
        repo = (temp_dir / "repo").resolve()
        src = repo / "src"
        src.mkdir(parents=True)
        (src / "handler.py").write_text("pass\n")
        (src / "auth.py").write_text("pass\n")
        (src / "middleware.py").write_text("pass\n")
        result = suggest_security_adjacent_files(repo, ["src/handler.py"])
        assert any("auth" in path for path in result)

    def test_excludes_test_files(self, temp_dir: Path):
        repo = (temp_dir / "repo").resolve()
        src = repo / "src"
        src.mkdir(parents=True)
        (src / "auth.py").write_text("pass\n")
        (src / "test_auth.py").write_text("pass\n")
        result = suggest_security_adjacent_files(repo, ["src/auth.py"])
        assert not any("test_auth" in path for path in result)

    def test_empty_changed_files(self, temp_dir: Path):
        repo = (temp_dir / "repo").resolve()
        repo.mkdir(parents=True, exist_ok=True)
        result = suggest_security_adjacent_files(repo, [])
        assert result == []

    def test_max_items_respected(self, temp_dir: Path):
        repo = (temp_dir / "repo").resolve()
        src = repo / "src"
        src.mkdir(parents=True, exist_ok=True)
        for i in range(20):
            (src / f"auth_module_{i}.py").write_text("pass\n")
        (src / "handler.py").write_text("pass\n")
        result = suggest_security_adjacent_files(repo, ["src/handler.py"], max_items=5)
        assert len(result) <= 5


class TestCheckVulnOverlap:
    def test_overlap_found(self, temp_dir: Path):
        path = temp_dir / "VULNERABILITIES.json"
        path.write_text('[{"file_path": "src/auth.py", "title": "SQLi"}]')
        result = check_vuln_overlap(path, ["src/auth.py"])
        assert len(result) == 1

    def test_no_overlap(self, temp_dir: Path):
        path = temp_dir / "VULNERABILITIES.json"
        path.write_text('[{"file_path": "src/auth.py", "title": "SQLi"}]')
        result = check_vuln_overlap(path, ["lib/math.py"])
        assert result == []

    def test_missing_file(self, temp_dir: Path):
        result = check_vuln_overlap(temp_dir / "missing.json", ["a.py"])
        assert result == []

    def test_invalid_json(self, temp_dir: Path):
        path = temp_dir / "VULNERABILITIES.json"
        path.write_text("{broken")
        result = check_vuln_overlap(path, ["a.py"])
        assert result == []
