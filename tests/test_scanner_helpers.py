"""Unit tests for PROMPTHEUS scanner pure helper functions."""

from __future__ import annotations

from pathlib import Path

import pytest

from promptheus.diff.parser import DiffContext, DiffFile, DiffHunk, DiffLine
from promptheus.scanner.scanner import (
    NON_CODE_SUFFIXES,
    _build_focused_diff_context,
    _derive_pr_default_grep_scope,
    _enforce_focused_diff_coverage,
    _format_diff_file_hints,
    _normalize_hypothesis_output,
    _summarize_diff_hunk_snippets,
    _summarize_diff_line_anchors,
    _write_diff_files_for_agent,
    score_diff_file_for_security_review,
)


def _make_diff_line(line_type: str, content: str, line_num: int = 1) -> DiffLine:
    if line_type == "add":
        return DiffLine("add", content, old_line_num=None, new_line_num=line_num)
    elif line_type == "remove":
        return DiffLine("remove", content, old_line_num=line_num, new_line_num=None)
    return DiffLine("context", content, old_line_num=line_num, new_line_num=line_num)


def _make_diff_file(
    path: str,
    hunk_contents: list[tuple[str, str]] | None = None,
    is_new: bool = False,
    is_deleted: bool = False,
    is_renamed: bool = False,
) -> DiffFile:
    hunks = []
    if hunk_contents:
        lines = [_make_diff_line(t, c, idx + 1) for idx, (t, c) in enumerate(hunk_contents)]
        hunks = [DiffHunk(old_start=1, old_count=0, new_start=1, new_count=len(lines), lines=lines)]
    return DiffFile(
        old_path=None,
        new_path=path,
        hunks=hunks,
        is_new=is_new,
        is_deleted=is_deleted,
        is_renamed=is_renamed,
    )


def _make_diff_context(files: list[DiffFile] | None = None) -> DiffContext:
    files = files or []
    changed = [f.new_path or f.old_path for f in files if f.new_path or f.old_path]
    added = sum(
        1 for f in files for h in f.hunks for l in h.lines if l.type == "add"
    )
    removed = sum(
        1 for f in files for h in f.hunks for l in h.lines if l.type == "remove"
    )
    return DiffContext(files=files, added_lines=added, removed_lines=removed, changed_files=changed)


class TestNonCodeSuffixes:
    def test_expected_suffixes(self):
        assert ".md" in NON_CODE_SUFFIXES
        assert ".txt" in NON_CODE_SUFFIXES
        assert ".png" in NON_CODE_SUFFIXES
        assert ".lock" in NON_CODE_SUFFIXES

    def test_code_suffixes_not_included(self):
        assert ".py" not in NON_CODE_SUFFIXES
        assert ".js" not in NON_CODE_SUFFIXES
        assert ".ts" not in NON_CODE_SUFFIXES


class TestScoreDiffFile:
    def test_code_file_base_score(self):
        df = _make_diff_file("src/auth.py", [("add", "pass")])
        score = score_diff_file_for_security_review(df)
        assert score >= 60

    def test_docs_penalty(self):
        df = _make_diff_file("docs/README.md", [("add", "text")])
        score = score_diff_file_for_security_review(df)
        assert score < 30

    def test_test_penalty(self):
        df = _make_diff_file("src/tests/test_auth.py", [("add", "test")])
        score = score_diff_file_for_security_review(df)
        df_src = _make_diff_file("src/auth.py", [("add", "code")])
        score_src = score_diff_file_for_security_review(df_src)
        assert score < score_src

    def test_new_file_bonus(self):
        df_new = _make_diff_file("src/handler.py", [("add", "code")], is_new=True)
        df_old = _make_diff_file("src/handler.py", [("add", "code")])
        assert score_diff_file_for_security_review(df_new) > score_diff_file_for_security_review(df_old)

    def test_renamed_file_bonus(self):
        df = _make_diff_file("src/handler.py", [("add", "code")], is_renamed=True)
        df_no = _make_diff_file("src/handler.py", [("add", "code")])
        assert score_diff_file_for_security_review(df) > score_diff_file_for_security_review(df_no)

    def test_security_path_hints(self):
        df = _make_diff_file("src/auth/middleware.py", [("add", "check")])
        score = score_diff_file_for_security_review(df)
        assert score > 80

    def test_non_code_suffix_no_base(self):
        df = _make_diff_file("README.md", [("add", "text")])
        score = score_diff_file_for_security_review(df)
        assert score < 60

    def test_empty_path(self):
        df = DiffFile(old_path=None, new_path=None, hunks=[], is_new=False, is_deleted=False, is_renamed=False)
        assert score_diff_file_for_security_review(df) == 0


class TestSummarizeDiffLineAnchors:
    def test_basic_summary(self):
        diff = _make_diff_context([
            _make_diff_file("src/auth.py", [("add", "new_function()")])
        ])
        summary = _summarize_diff_line_anchors(diff)
        assert "src/auth.py" in summary
        assert "new_function()" in summary

    def test_empty_diff(self):
        summary = _summarize_diff_line_anchors(_make_diff_context([]))
        assert "No changed files" in summary

    def test_removed_lines_counted(self):
        diff = _make_diff_context([
            _make_diff_file("src/auth.py", [("remove", "old_code")])
        ])
        summary = _summarize_diff_line_anchors(diff)
        assert "removed lines" in summary

    def test_long_snippet_truncated(self):
        diff = _make_diff_context([
            _make_diff_file("src/auth.py", [("add", "x" * 300)])
        ])
        summary = _summarize_diff_line_anchors(diff)
        assert "..." in summary

    def test_max_chars_enforced(self):
        files = [
            _make_diff_file(f"src/file_{i}.py", [("add", f"content_{i}" * 50)])
            for i in range(100)
        ]
        diff = _make_diff_context(files)
        summary = _summarize_diff_line_anchors(diff, max_chars=500)
        assert len(summary) <= 515  # slight tolerance


class TestSummarizeDiffHunkSnippets:
    def test_basic_snippets(self):
        diff = _make_diff_context([
            _make_diff_file("src/auth.py", [("add", "new_function()"), ("context", "existing")])
        ])
        summary = _summarize_diff_hunk_snippets(diff)
        assert "src/auth.py" in summary
        assert "+new_function()" in summary

    def test_empty_diff(self):
        summary = _summarize_diff_hunk_snippets(_make_diff_context([]))
        assert "No changed hunks" in summary

    def test_file_metadata(self):
        df = _make_diff_file("src/new.py", [("add", "code")], is_new=True)
        diff = _make_diff_context([df])
        summary = _summarize_diff_hunk_snippets(diff)
        assert "(new)" in summary

    def test_removed_line_prefix(self):
        diff = _make_diff_context([
            _make_diff_file("src/auth.py", [("remove", "old_code")])
        ])
        summary = _summarize_diff_hunk_snippets(diff)
        assert "-old_code" in summary


class TestNormalizeHypothesisOutput:
    def test_bullet_list(self):
        result = _normalize_hypothesis_output("- Hypothesis one\n- Hypothesis two")
        assert result.count("- ") == 2

    def test_asterisk_list(self):
        result = _normalize_hypothesis_output("* Hypothesis one\n* Hypothesis two")
        assert "- Hypothesis one" in result
        assert "- Hypothesis two" in result

    def test_numbered_list(self):
        result = _normalize_hypothesis_output("1. First\n2. Second\n3. Third")
        assert "- First" in result
        assert "- Second" in result

    def test_empty_input(self):
        assert _normalize_hypothesis_output("") == "- None generated."
        assert _normalize_hypothesis_output("   ") == "- None generated."

    def test_plain_text_wrapped(self):
        result = _normalize_hypothesis_output("Some hypothesis text without bullets")
        assert result.startswith("- ")

    def test_max_items_enforced(self):
        items = "\n".join(f"- Item {i}" for i in range(20))
        result = _normalize_hypothesis_output(items, max_items=5)
        assert result.count("- ") <= 5

    def test_max_chars_enforced(self):
        items = "\n".join(f"- {'x' * 100}" for i in range(100))
        result = _normalize_hypothesis_output(items, max_chars=500)
        assert len(result) <= 515

    def test_long_line_truncated(self):
        text = "x" * 400
        result = _normalize_hypothesis_output(text)
        assert "..." in result


class TestFormatDiffFileHints:
    def test_with_paths(self):
        result = _format_diff_file_hints(["diff_files/auth.py", "diff_files/api.py"])
        assert ".promptheus/diff_files/auth.py" in result
        assert "Read tool" in result

    def test_empty_paths(self):
        result = _format_diff_file_hints([])
        assert "No diff files" in result


class TestDerivePrDefaultGrepScope:
    def test_src_priority(self):
        diff = _make_diff_context([
            _make_diff_file("src/auth.py"),
            _make_diff_file("lib/utils.py"),
        ])
        assert _derive_pr_default_grep_scope(diff) == "src"

    def test_most_common_dir(self):
        diff = DiffContext(
            files=[],
            added_lines=0,
            removed_lines=0,
            changed_files=["pkg/a.py", "pkg/b.py", "lib/c.py"],
        )
        assert _derive_pr_default_grep_scope(diff) == "pkg"

    def test_no_valid_paths(self):
        diff = DiffContext(files=[], added_lines=0, removed_lines=0, changed_files=["README.md"])
        assert _derive_pr_default_grep_scope(diff) == "."


class TestBuildFocusedDiffContext:
    def test_prioritizes_security_relevant(self):
        files = [
            _make_diff_file("docs/README.md", [("add", "text")]),
            _make_diff_file("src/auth.py", [("add", "secure_code()")]),
            _make_diff_file("src/tests/test.py", [("add", "test_code()")]),
        ]
        diff = _make_diff_context(files)
        focused = _build_focused_diff_context(diff)
        paths = [f.new_path for f in focused.files]
        assert "src/auth.py" in paths

    def test_empty_diff(self):
        diff = _make_diff_context([])
        focused = _build_focused_diff_context(diff)
        assert focused.files == []

    def test_preserves_counts(self):
        files = [_make_diff_file("src/auth.py", [("add", "code"), ("remove", "old")])]
        diff = _make_diff_context(files)
        focused = _build_focused_diff_context(diff)
        assert focused.added_lines >= 0
        assert focused.removed_lines >= 0


class TestEnforceFocusedDiffCoverage:
    def test_no_drop_passes(self):
        files = [_make_diff_file("src/auth.py", [("add", "code")])]
        diff = _make_diff_context(files)
        _enforce_focused_diff_coverage(diff, diff)

    def test_dropped_files_raises(self):
        original_files = [
            _make_diff_file(f"src/file_{i}.py", [("add", f"code_{i}")])
            for i in range(50)
        ]
        original = _make_diff_context(original_files)
        focused = _make_diff_context(original_files[:5])
        with pytest.raises(RuntimeError, match="exceeds safe analysis limits"):
            _enforce_focused_diff_coverage(original, focused)


class TestWriteDiffFilesForAgent:
    def test_writes_files(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        files = [_make_diff_file("src/auth.py", [("add", "new_code()")])]
        diff = _make_diff_context(files)
        written = _write_diff_files_for_agent(pd, diff)
        assert len(written) == 1
        assert "src--auth.py" in written[0]

    def test_empty_diff(self, temp_dir: Path):
        pd = temp_dir / ".promptheus"
        pd.mkdir()
        written = _write_diff_files_for_agent(pd, _make_diff_context([]))
        assert written == []
