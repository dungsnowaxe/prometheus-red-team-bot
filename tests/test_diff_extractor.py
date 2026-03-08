"""Unit tests for PROMPTHEUS diff extraction helpers (git ref validation)."""

from __future__ import annotations

import pytest

from promptheus.diff.extractor import (
    GIT_REF_PATTERN,
    _validate_git_ref,
    validate_git_ref,
)


class TestValidateGitRef:
    def test_valid_branch(self):
        validate_git_ref("main")

    def test_valid_commit_hash(self):
        validate_git_ref("abc123def456")

    def test_valid_parent_ref(self):
        validate_git_ref("HEAD~1")
        validate_git_ref("HEAD^2")

    def test_valid_two_dot_range(self):
        validate_git_ref("abc123..def456")

    def test_valid_three_dot_range(self):
        validate_git_ref("abc123...def456")

    def test_valid_branch_with_slash(self):
        validate_git_ref("feature/auth-improvements")

    def test_empty_ref_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_git_ref("")

    def test_four_dots_raises(self):
        with pytest.raises(ValueError, match="malformed range"):
            validate_git_ref("abc....def")

    def test_option_style_ref_raises(self):
        with pytest.raises(ValueError, match="option-style"):
            validate_git_ref("-all")

    def test_shell_metachar_raises(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_git_ref("main;rm -rf /")

    def test_empty_range_endpoint_raises(self):
        with pytest.raises(ValueError, match="malformed range"):
            validate_git_ref("abc..")

    def test_empty_three_dot_endpoint_raises(self):
        with pytest.raises(ValueError, match="malformed range"):
            validate_git_ref("...abc")

    def test_nested_dots_in_range_raises(self):
        with pytest.raises(ValueError, match="malformed range"):
            validate_git_ref("a..b...c")

    def test_backward_compat_alias(self):
        _validate_git_ref("main")


class TestGitRefPattern:
    def test_valid_patterns(self):
        assert GIT_REF_PATTERN.match("main")
        assert GIT_REF_PATTERN.match("feature/auth")
        assert GIT_REF_PATTERN.match("HEAD~1")
        assert GIT_REF_PATTERN.match("HEAD^2")
        assert GIT_REF_PATTERN.match("abc123")

    def test_invalid_patterns(self):
        assert not GIT_REF_PATTERN.match("$(command)")
        assert not GIT_REF_PATTERN.match("ref;injection")
        assert not GIT_REF_PATTERN.match("ref|pipe")
        assert not GIT_REF_PATTERN.match("ref`backtick`")
