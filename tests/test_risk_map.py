"""Tests for risk_map generation and tier classification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptheus.scanner.risk_map import (
    TIER_CRITICAL,
    TIER_MODERATE,
    TIER_SKIP,
    TIER_UNMAPPED,
    classify_diff_tier,
    classify_file_tier,
    generate_risk_map,
    load_risk_map,
)


def test_generate_risk_map_produces_valid_json(temp_dir: Path) -> None:
    """generate_risk_map writes valid risk_map.json with critical/moderate/skip keys."""
    threat_dir = temp_dir / "promptheus"
    threat_dir.mkdir()
    threat_model = threat_dir / "THREAT_MODEL.json"
    threat_model.write_text(
        json.dumps([
            {"threat_id": "T1", "severity": "Critical", "affected_components": ["src/auth.py"]},
            {"threat_id": "T2", "severity": "Medium", "affected_components": ["lib/util.js"]},
        ]),
        encoding="utf-8",
    )
    out_path = threat_dir / "risk_map.json"
    generate_risk_map(threat_model, out_path)
    assert out_path.exists()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert "critical" in data
    assert "moderate" in data
    assert "skip" in data
    assert isinstance(data["critical"], list)
    assert isinstance(data["moderate"], list)
    assert isinstance(data["skip"], list)


def test_classify_file_tier_critical() -> None:
    """classify_file_tier returns critical when path matches critical glob."""
    risk_map = {
        "critical": ["src/auth*", "**/secrets*"],
        "moderate": ["lib/*"],
        "skip": ["docs/*"],
    }
    assert classify_file_tier("src/auth.py", risk_map) == TIER_CRITICAL
    assert classify_file_tier("src/auth/oauth.py", risk_map) == TIER_CRITICAL


def test_classify_file_tier_moderate() -> None:
    """classify_file_tier returns moderate when path matches moderate glob."""
    risk_map = {
        "critical": ["src/auth*"],
        "moderate": ["lib/*"],
        "skip": ["docs/*"],
    }
    assert classify_file_tier("lib/util.js", risk_map) == TIER_MODERATE


def test_classify_file_tier_skip() -> None:
    """classify_file_tier returns skip when path matches skip glob."""
    risk_map = {
        "critical": [],
        "moderate": [],
        "skip": ["*.md", "docs/*"],
    }
    assert classify_file_tier("README.md", risk_map) == TIER_SKIP
    assert classify_file_tier("docs/guide.md", risk_map) == TIER_SKIP


def test_classify_file_tier_unmapped() -> None:
    """classify_file_tier returns unmapped when no pattern matches."""
    risk_map = {
        "critical": ["src/auth*"],
        "moderate": ["lib/*"],
        "skip": ["docs/*"],
    }
    assert classify_file_tier("other/foo.py", risk_map) == TIER_UNMAPPED


def test_classify_diff_tier_highest_wins() -> None:
    """classify_diff_tier returns the highest tier among changed files."""
    risk_map = {
        "critical": ["src/auth*"],
        "moderate": ["lib/*"],
        "skip": ["docs/*"],
    }
    assert classify_diff_tier(["lib/a.js", "src/auth.py"], risk_map) == TIER_CRITICAL
    assert classify_diff_tier(["lib/a.js", "other/x.py"], risk_map) == TIER_MODERATE
    assert classify_diff_tier(["docs/readme.md"], risk_map) == TIER_SKIP


def test_classify_diff_tier_unmapped_defaults_moderate() -> None:
    """When all files are unmapped, classify_diff_tier returns moderate (Tier 2)."""
    risk_map = {"critical": [], "moderate": [], "skip": []}
    assert classify_diff_tier(["unknown/path.py"], risk_map) == TIER_MODERATE


def test_classify_diff_tier_empty_paths() -> None:
    """classify_diff_tier returns skip for empty file list."""
    risk_map = {"critical": ["src/*"], "moderate": [], "skip": []}
    assert classify_diff_tier([], risk_map) == TIER_SKIP


def test_load_risk_map_missing_returns_none(temp_dir: Path) -> None:
    """load_risk_map returns None when file is missing."""
    assert load_risk_map(temp_dir) is None


def test_load_risk_map_valid(temp_dir: Path) -> None:
    """load_risk_map returns dict when risk_map.json is valid."""
    (temp_dir / "risk_map.json").write_text(
        '{"critical": ["src/*"], "moderate": [], "skip": []}',
        encoding="utf-8",
    )
    data = load_risk_map(temp_dir)
    assert data is not None
    assert data["critical"] == ["src/*"]
