"""Unit tests for PROMPTHEUS unified diff parser."""

from __future__ import annotations

import pytest

from promptheus.diff.parser import (
    DiffContext,
    DiffFile,
    DiffHunk,
    DiffLine,
    HUNK_HEADER_RE,
    _merge_ranges,
    _parse_hunk_header,
    _strip_diff_prefix,
    parse_unified_diff,
)


class TestStripDiffPrefix:
    def test_a_prefix(self):
        assert _strip_diff_prefix("a/src/main.py") == "src/main.py"

    def test_b_prefix(self):
        assert _strip_diff_prefix("b/src/main.py") == "src/main.py"

    def test_dev_null(self):
        assert _strip_diff_prefix("/dev/null") is None
        assert _strip_diff_prefix("dev/null") is None

    def test_no_prefix(self):
        assert _strip_diff_prefix("src/main.py") == "src/main.py"

    def test_tab_separator(self):
        assert _strip_diff_prefix("a/main.py\t2024-01-01") == "main.py"

    def test_empty_after_strip(self):
        assert _strip_diff_prefix("a/") is None


class TestParseHunkHeader:
    def test_standard_header(self):
        old_start, old_count, new_start, new_count = _parse_hunk_header("@@ -1,5 +1,7 @@")
        assert old_start == 1
        assert old_count == 5
        assert new_start == 1
        assert new_count == 7

    def test_single_line_hunk(self):
        old_start, old_count, new_start, new_count = _parse_hunk_header("@@ -10 +10 @@")
        assert old_start == 10
        assert old_count == 1  # default
        assert new_start == 10
        assert new_count == 1

    def test_with_function_context(self):
        old_start, old_count, new_start, new_count = _parse_hunk_header(
            "@@ -50,3 +50,4 @@ def main():"
        )
        assert old_start == 50
        assert old_count == 3
        assert new_start == 50
        assert new_count == 4

    def test_invalid_header(self):
        assert _parse_hunk_header("not a header") == (0, 0, 0, 0)


class TestMergeRanges:
    def test_no_ranges(self):
        assert _merge_ranges([]) == []

    def test_single_range(self):
        assert _merge_ranges([(1, 5)]) == [(1, 5)]

    def test_non_overlapping(self):
        assert _merge_ranges([(1, 3), (5, 7)]) == [(1, 3), (5, 7)]

    def test_overlapping(self):
        assert _merge_ranges([(1, 5), (3, 8)]) == [(1, 8)]

    def test_adjacent(self):
        assert _merge_ranges([(1, 3), (4, 6)]) == [(1, 6)]

    def test_unsorted_input(self):
        assert _merge_ranges([(5, 7), (1, 3)]) == [(1, 3), (5, 7)]

    def test_contained_range(self):
        assert _merge_ranges([(1, 10), (3, 5)]) == [(1, 10)]


class TestParseUnifiedDiff:
    SIMPLE_DIFF = """diff --git a/main.py b/main.py
--- a/main.py
+++ b/main.py
@@ -1,3 +1,4 @@
 import os
+import sys
 
 def main():
"""

    NEW_FILE_DIFF = """diff --git a/new_file.py b/new_file.py
new file mode 100644
--- /dev/null
+++ b/new_file.py
@@ -0,0 +1,3 @@
+def hello():
+    print("hello")
+    return True
"""

    DELETED_FILE_DIFF = """diff --git a/old_file.py b/old_file.py
deleted file mode 100644
--- a/old_file.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def goodbye():
-    pass
"""

    RENAME_DIFF = """diff --git a/old_name.py b/new_name.py
rename from old_name.py
rename to new_name.py
"""

    MULTI_FILE_DIFF = """diff --git a/file1.py b/file1.py
--- a/file1.py
+++ b/file1.py
@@ -1,2 +1,3 @@
 line1
+added_line
 line2
diff --git a/file2.py b/file2.py
--- a/file2.py
+++ b/file2.py
@@ -1,2 +1,2 @@
-old_line
+new_line
 unchanged
"""

    def test_simple_addition(self):
        ctx = parse_unified_diff(self.SIMPLE_DIFF)
        assert len(ctx.files) == 1
        assert ctx.added_lines == 1
        assert ctx.removed_lines == 0
        assert ctx.changed_files == ["main.py"]
        assert ctx.files[0].new_path == "main.py"
        assert len(ctx.files[0].hunks) == 1
        added = [l for l in ctx.files[0].hunks[0].lines if l.type == "add"]
        assert len(added) == 1
        assert "import sys" in added[0].content

    def test_new_file(self):
        ctx = parse_unified_diff(self.NEW_FILE_DIFF)
        assert len(ctx.files) == 1
        assert ctx.files[0].is_new is True
        assert ctx.files[0].new_path == "new_file.py"
        assert ctx.added_lines == 3

    def test_deleted_file(self):
        ctx = parse_unified_diff(self.DELETED_FILE_DIFF)
        assert len(ctx.files) == 1
        assert ctx.files[0].is_deleted is True
        assert ctx.removed_lines == 2

    def test_renamed_file(self):
        ctx = parse_unified_diff(self.RENAME_DIFF)
        assert len(ctx.files) == 1
        assert ctx.files[0].is_renamed is True
        assert ctx.files[0].old_path == "old_name.py"
        assert ctx.files[0].new_path == "new_name.py"

    def test_multi_file(self):
        ctx = parse_unified_diff(self.MULTI_FILE_DIFF)
        assert len(ctx.files) == 2
        assert ctx.added_lines == 2  # one in each file
        assert ctx.removed_lines == 1
        assert len(ctx.changed_files) == 2

    def test_empty_diff(self):
        ctx = parse_unified_diff("")
        assert ctx.files == []
        assert ctx.added_lines == 0
        assert ctx.removed_lines == 0

    def test_no_newline_at_eof(self):
        diff = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1 +1 @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
"""
        ctx = parse_unified_diff(diff)
        assert ctx.added_lines == 1
        assert ctx.removed_lines == 1

    def test_context_lines_tracked(self):
        ctx = parse_unified_diff(self.SIMPLE_DIFF)
        hunk = ctx.files[0].hunks[0]
        context_lines = [l for l in hunk.lines if l.type == "context"]
        assert len(context_lines) >= 2

    def test_line_numbers_assigned(self):
        ctx = parse_unified_diff(self.SIMPLE_DIFF)
        hunk = ctx.files[0].hunks[0]
        added = [l for l in hunk.lines if l.type == "add"]
        assert added[0].new_line_num is not None
        assert added[0].old_line_num is None

    def test_to_json_roundtrip(self):
        ctx = parse_unified_diff(self.MULTI_FILE_DIFF)
        json_data = ctx.to_json()
        assert len(json_data["files"]) == 2
        assert json_data["added_lines"] == 2
        assert json_data["removed_lines"] == 1
        assert "main.py" not in json_data["changed_files"]


class TestDiffContextToJson:
    def test_serialization(self):
        ctx = DiffContext(
            files=[
                DiffFile(
                    old_path="a.py",
                    new_path="a.py",
                    hunks=[
                        DiffHunk(
                            old_start=1,
                            old_count=1,
                            new_start=1,
                            new_count=2,
                            lines=[
                                DiffLine("context", "existing", 1, 1),
                                DiffLine("add", "new line", None, 2),
                            ],
                        )
                    ],
                    is_new=False,
                    is_deleted=False,
                    is_renamed=False,
                )
            ],
            added_lines=1,
            removed_lines=0,
            changed_files=["a.py"],
        )
        data = ctx.to_json()
        assert data["files"][0]["old_path"] == "a.py"
        assert len(data["files"][0]["hunks"]) == 1
        assert len(data["files"][0]["hunks"][0]["lines"]) == 2
