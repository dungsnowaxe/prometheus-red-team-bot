"""Unit tests for PROMPTHEUS scan state management."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptheus.scanner.state import (
    build_full_scan_entry,
    build_pr_review_entry,
    get_last_full_scan_commit,
    load_scan_state,
    scan_state_branch_matches,
    update_scan_state,
    utc_timestamp,
)


class TestLoadScanState:
    def test_missing_file_returns_none(self, temp_dir: Path):
        result = load_scan_state(temp_dir / "nonexistent.json")
        assert result is None

    def test_valid_json_dict(self, temp_dir: Path):
        state_path = temp_dir / "state.json"
        state_path.write_text('{"last_full_scan": {"commit": "abc123"}}')
        result = load_scan_state(state_path)
        assert result is not None
        assert result["last_full_scan"]["commit"] == "abc123"

    def test_invalid_json_returns_none(self, temp_dir: Path):
        state_path = temp_dir / "state.json"
        state_path.write_text("{broken")
        result = load_scan_state(state_path)
        assert result is None

    def test_non_dict_json_returns_none(self, temp_dir: Path):
        state_path = temp_dir / "state.json"
        state_path.write_text("[1, 2, 3]")
        result = load_scan_state(state_path)
        assert result is None


class TestUpdateScanState:
    def test_creates_new_state(self, temp_dir: Path):
        state_path = temp_dir / "state.json"
        entry = build_full_scan_entry(commit="abc123", branch="main", timestamp="2026-03-06T00:00:00Z")
        result = update_scan_state(state_path, full_scan=entry)
        assert result["last_full_scan"]["commit"] == "abc123"
        assert state_path.exists()

    def test_preserves_existing_fields(self, temp_dir: Path):
        state_path = temp_dir / "state.json"
        state_path.write_text(json.dumps({"custom_key": "value"}))
        entry = build_full_scan_entry(commit="def456", branch="main", timestamp="2026-03-06T00:00:00Z")
        result = update_scan_state(state_path, full_scan=entry)
        assert result["custom_key"] == "value"
        assert result["last_full_scan"]["commit"] == "def456"

    def test_update_pr_review(self, temp_dir: Path):
        state_path = temp_dir / "state.json"
        pr_entry = build_pr_review_entry(
            commit="abc123", commits_reviewed=["abc123", "def456"], timestamp="2026-03-06T00:00:00Z"
        )
        result = update_scan_state(state_path, pr_review=pr_entry)
        assert result["last_pr_review"]["commit"] == "abc123"
        assert len(result["last_pr_review"]["commits_reviewed"]) == 2

    def test_creates_parent_directories(self, temp_dir: Path):
        state_path = temp_dir / "nested" / "dir" / "state.json"
        entry = build_full_scan_entry(commit="abc", branch="dev", timestamp="2026-03-06T00:00:00Z")
        update_scan_state(state_path, full_scan=entry)
        assert state_path.exists()


class TestBuildEntries:
    def test_full_scan_entry(self):
        entry = build_full_scan_entry(commit="abc", branch="main", timestamp="2026-03-06T12:00:00Z")
        assert entry == {"commit": "abc", "branch": "main", "timestamp": "2026-03-06T12:00:00Z"}

    def test_pr_review_entry(self):
        entry = build_pr_review_entry(
            commit="abc", commits_reviewed=["abc", "def"], timestamp="2026-03-06T12:00:00Z"
        )
        assert entry["commit"] == "abc"
        assert entry["commits_reviewed"] == ["abc", "def"]
        assert entry["timestamp"] == "2026-03-06T12:00:00Z"


class TestScanStateBranchMatches:
    def test_matching_branch(self):
        state = {"last_full_scan": {"branch": "main", "commit": "abc"}}
        assert scan_state_branch_matches(state, "main") is True

    def test_non_matching_branch(self):
        state = {"last_full_scan": {"branch": "main", "commit": "abc"}}
        assert scan_state_branch_matches(state, "develop") is False

    def test_missing_full_scan(self):
        state = {}
        assert scan_state_branch_matches(state, "main") is False

    def test_non_dict_entry(self):
        state = {"last_full_scan": "not a dict"}
        assert scan_state_branch_matches(state, "main") is False


class TestGetLastFullScanCommit:
    def test_valid_commit(self):
        state = {"last_full_scan": {"commit": "abc123", "branch": "main"}}
        assert get_last_full_scan_commit(state) == "abc123"

    def test_missing_full_scan(self):
        assert get_last_full_scan_commit({}) is None

    def test_non_dict_entry(self):
        assert get_last_full_scan_commit({"last_full_scan": "string"}) is None

    def test_non_string_commit(self):
        assert get_last_full_scan_commit({"last_full_scan": {"commit": 123}}) is None


class TestUtcTimestamp:
    def test_format_ends_with_z(self):
        ts = utc_timestamp()
        assert ts.endswith("Z")

    def test_is_iso_format(self):
        ts = utc_timestamp()
        assert "T" in ts
        assert len(ts) >= 19
