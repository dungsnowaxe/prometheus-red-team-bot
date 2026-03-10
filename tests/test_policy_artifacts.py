"""Tests for policy artifact loading from merge-base (artifact trust boundary)."""

from __future__ import annotations

from pathlib import Path

import os
import subprocess

import pytest

from promptheus.scanner.policy_artifacts import (
    get_merge_base,
    materialize_policy_from_ref,
)


def test_get_merge_base_not_git_returns_none(temp_dir: Path) -> None:
    """get_merge_base returns None when path is not a git repo."""
    assert get_merge_base(temp_dir) is None


def test_materialize_policy_from_ref_non_git_returns_temp_dir(temp_dir: Path) -> None:
    """materialize_policy_from_ref returns a temp dir even when repo is not git (no files written)."""
    result = materialize_policy_from_ref(temp_dir, "HEAD")
    assert result is not None
    assert result.is_dir()
    # No policy files in non-git repo
    assert not (result / "risk_map.json").exists()


def test_materialize_policy_from_ref_git_repo_returns_temp_dir(tmp_path: Path) -> None:
    """In a git repo, materialize_policy_from_ref returns a temp dir (may be empty if no .promptheus at ref)."""
    (tmp_path / "file").write_text("x")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.com"}
    try:
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, timeout=5, env=env)
        subprocess.run(["git", "add", "file"], cwd=tmp_path, check=True, capture_output=True, timeout=5, env=env)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, check=True, capture_output=True, timeout=5, env=env)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip("git init/commit not available or failed (e.g. sandbox)")
    ref = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    ).stdout.strip()
    result = materialize_policy_from_ref(tmp_path, ref)
    assert result is not None
    assert result.is_dir()
