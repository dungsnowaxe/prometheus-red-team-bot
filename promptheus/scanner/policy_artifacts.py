"""Load policy artifacts from git merge-base for PR review (artifact trust boundary)."""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

POLICY_FILES = ("risk_map.json", "design_decisions.json", "THREAT_MODEL.json", "VULNERABILITIES.json")
PROMPTHEUS_PREFIX = ".promptheus/"


def get_merge_base(repo: Path, base_ref: Optional[str] = None) -> Optional[str]:
    """
    Return the merge-base commit of HEAD and the given ref (or default branch).

    Tries base_ref, then origin/main, then main. Returns None if not a git repo
    or merge-base cannot be determined.
    """
    for ref in (base_ref, "origin/main", "main"):
        if not ref:
            continue
        try:
            result = subprocess.run(
                ["git", "merge-base", "HEAD", ref],
                cwd=repo,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
    return None


def _git_show(repo: Path, ref: str, path: str) -> Optional[str]:
    """Return content of path at ref via git show, or None if missing/failed."""
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def materialize_policy_from_ref(
    repo: Path, ref: str, include_vulnerabilities: bool = False
) -> Optional[Path]:
    """
    Materialize policy artifacts from the given ref into a temporary directory.

    Writes risk_map.json, design_decisions.json, THREAT_MODEL.json (and optionally
    VULNERABILITIES.json) from ref into a temp dir. Returns that Path, or None
    if ref is invalid or repo is not a git repo.
    """
    files_to_fetch = [f for f in POLICY_FILES if f != "VULNERABILITIES.json"]
    if include_vulnerabilities:
        files_to_fetch.append("VULNERABILITIES.json")
    try:
        tmp = tempfile.mkdtemp(prefix="promptheus_policy_")
        tmp_path = Path(tmp)
        for name in files_to_fetch:
            content = _git_show(repo, ref, PROMPTHEUS_PREFIX + name)
            if content is not None:
                (tmp_path / name).write_text(content, encoding="utf-8")
        return tmp_path
    except (OSError, IOError):
        return None


