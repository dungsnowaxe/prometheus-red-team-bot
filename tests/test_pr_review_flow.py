"""Unit tests for PROMPTHEUS PR review attempt-loop state and orchestration helpers."""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from promptheus.scanner.pr_review_flow import (
    PRAttemptState,
    PRReviewContext,
    PRReviewState,
)
from promptheus.diff.parser import DiffContext, DiffFile


def _empty_diff_context() -> DiffContext:
    return DiffContext(files=[], added_lines=0, removed_lines=0, changed_files=[])


class TestPRAttemptState:
    def test_defaults(self):
        state = PRAttemptState()
        assert state.carry_forward_candidate_summary == ""
        assert state.carry_forward_candidate_family_ids == set()
        assert state.carry_forward_candidate_flow_ids == set()

    def test_mutation(self):
        state = PRAttemptState()
        state.carry_forward_candidate_summary = "summary"
        state.carry_forward_candidate_family_ids.add("chain_a")
        assert "chain_a" in state.carry_forward_candidate_family_ids


class TestPRReviewContext:
    def test_construction(self, temp_dir: Path):
        ctx = PRReviewContext(
            repo=temp_dir,
            promptheus_dir=temp_dir / ".promptheus",
            focused_diff_context=_empty_diff_context(),
            diff_context=_empty_diff_context(),
            contextualized_prompt="prompt",
            baseline_vulns=[],
            pr_review_attempts=3,
            pr_timeout_seconds=120,
            pr_vulns_path=temp_dir / "PR_VULNERABILITIES.json",
            detected_languages={"python"},
            command_builder_signals=False,
            path_parser_signals=False,
            auth_privilege_signals=True,
            retry_focus_plan=["command_option"],
            diff_line_anchors="anchors",
            diff_hunk_snippets="snippets",
            pr_grep_default_scope="src",
            scan_start_time=1000.0,
            severity_threshold="high",
        )
        assert ctx.pr_review_attempts == 3
        assert ctx.auth_privilege_signals is True
        assert ctx.severity_threshold == "high"


class TestPRReviewState:
    def test_defaults(self):
        state = PRReviewState()
        assert state.warnings == []
        assert state.pr_vulns == []
        assert state.collected_pr_vulns == []
        assert state.ephemeral_pr_vulns == []
        assert state.artifact_loaded is False
        assert state.attempts_run == 0
        assert state.attempts_with_overwritten_artifact == 0
        assert state.attempt_finding_counts == []
        assert state.attempt_observed_counts == []
        assert state.attempt_focus_areas == []
        assert state.attempt_chain_ids == []
        assert state.attempt_chain_exact_ids == []
        assert state.attempt_chain_family_ids == []
        assert state.attempt_chain_flow_ids == []
        assert state.attempt_revalidation_attempted == []
        assert state.attempt_core_evidence_present == []
        assert state.chain_support_counts == {}
        assert state.flow_support_counts == {}
        assert isinstance(state.attempt_state, PRAttemptState)
        assert state.required_core_chain_pass_support == 2
        assert state.weak_consensus_reason == ""
        assert state.weak_consensus_triggered is False
        assert state.consensus_mode_used == "family"
        assert state.support_counts_snapshot == {"exact": 0, "family": 0, "flow": 0}
        assert state.pr_tool_guard_observer == {"blocked_out_of_repo_count": 0, "blocked_paths": []}
        assert state.merge_stats == {}
        assert state.raw_pr_finding_count == 0
        assert state.should_run_verifier is False
        assert state.passes_with_core_chain == 0
        assert state.attempt_outcome_counts_snapshot == []
        assert state.attempt_disagreement is False
        assert state.blocked_out_of_repo_tool_calls == 0
        assert state.revalidation_attempts == 0
        assert state.revalidation_core_hits == 0
        assert state.revalidation_core_misses == 0

    def test_mutation_isolation(self):
        state1 = PRReviewState()
        state2 = PRReviewState()
        state1.warnings.append("warn1")
        state1.collected_pr_vulns.append({"id": 1})
        state1.chain_support_counts["chain_a"] = 5
        assert state2.warnings == []
        assert state2.collected_pr_vulns == []
        assert state2.chain_support_counts == {}

    def test_attempt_tracking(self):
        state = PRReviewState()
        state.attempts_run = 3
        state.attempt_finding_counts.extend([5, 3, 0])
        state.attempt_observed_counts.extend([5, 4, 1])
        state.attempt_chain_family_ids.append({"chain_a"})
        state.attempt_chain_family_ids.append({"chain_a", "chain_b"})
        state.attempt_chain_family_ids.append(set())
        assert len(state.attempt_finding_counts) == 3
        assert len(state.attempt_chain_family_ids) == 3

    def test_weak_consensus_tracking(self):
        state = PRReviewState()
        state.weak_consensus_triggered = True
        state.weak_consensus_reason = "core_support=1/3 (<2)"
        state.consensus_mode_used = "flow"
        assert state.weak_consensus_triggered
        assert "core_support" in state.weak_consensus_reason

    def test_revalidation_tracking(self):
        state = PRReviewState()
        state.revalidation_attempts = 5
        state.revalidation_core_hits = 3
        state.revalidation_core_misses = 2
        assert state.revalidation_attempts == state.revalidation_core_hits + state.revalidation_core_misses

    def test_merge_stats(self):
        state = PRReviewState()
        state.merge_stats = {
            "input_count": 10,
            "canonical_count": 7,
            "final_count": 5,
            "speculative_dropped": 2,
            "subchain_collapsed": 1,
        }
        assert state.merge_stats["input_count"] == 10
        assert state.merge_stats["final_count"] == 5
