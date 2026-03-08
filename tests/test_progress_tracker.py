"""Unit tests for PROMPTHEUS ProgressTracker."""

from __future__ import annotations

from rich.console import Console

from promptheus.scanner.progress import (
    ProgressTracker,
    SECURITY_FILE,
    THREAT_MODEL_FILE,
    VULNERABILITIES_FILE,
    PR_VULNERABILITIES_FILE,
    SCAN_RESULTS_FILE,
)


def _make_tracker(debug: bool = False, single_subagent: str | None = None) -> ProgressTracker:
    console = Console(file=None, force_terminal=False, no_color=True)
    return ProgressTracker(console, debug=debug, single_subagent=single_subagent)


class TestProgressTrackerInit:
    def test_default_state(self):
        tracker = _make_tracker()
        assert tracker.current_phase is None
        assert tracker.tool_count == 0
        assert tracker.files_read == set()
        assert tracker.files_written == set()
        assert tracker.subagent_stack == []
        assert tracker.single_subagent is None

    def test_single_subagent_override(self):
        tracker = _make_tracker(single_subagent="code-review")
        assert tracker.single_subagent == "code-review"
        assert "1/1" in tracker.phase_display["code-review"]

    def test_debug_flag(self):
        tracker = _make_tracker(debug=True)
        assert tracker.debug is True


class TestProgressTrackerPhaseAnnouncement:
    def test_announce_phase_sets_current_phase(self):
        tracker = _make_tracker()
        tracker.announce_phase("assessment")
        assert tracker.current_phase == "assessment"
        assert tracker.phase_start_time is not None

    def test_announce_phase_resets_counters(self):
        tracker = _make_tracker()
        tracker.tool_count = 10
        tracker.files_read.add("a.py")
        tracker.files_written.add("b.py")
        tracker.announce_phase("code-review")
        assert tracker.tool_count == 0
        assert tracker.files_read == set()
        assert tracker.files_written == set()


class TestProgressTrackerToolTracking:
    def test_read_tool_tracks_file(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Read", {"file_path": "src/auth.py"})
        assert "src/auth.py" in tracker.files_read
        assert tracker.tool_count == 1

    def test_read_tool_with_path_key(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Read", {"path": "src/api.py"})
        assert "src/api.py" in tracker.files_read

    def test_write_tool_tracks_file(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Write", {"file_path": ".promptheus/SECURITY.md"})
        assert ".promptheus/SECURITY.md" in tracker.files_written

    def test_tool_count_increments(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Read", {"file_path": "a.py"})
        tracker.on_tool_start("Grep", {"pattern": "password"})
        tracker.on_tool_start("Write", {"file_path": "out.txt"})
        assert tracker.tool_count == 3

    def test_task_tool_pushes_subagent(self):
        tracker = _make_tracker()
        tracker.on_tool_start("Task", {
            "agent_name": "threat-modeling",
            "prompt": "Analyze threats",
        })
        assert "threat-modeling" in tracker.subagent_stack
        assert tracker.current_phase == "threat-modeling"


class TestProgressTrackerToolCompletion:
    def test_successful_completion_no_error(self):
        tracker = _make_tracker()
        tracker.on_tool_complete("Read", success=True)

    def test_failed_tool_with_message(self):
        tracker = _make_tracker()
        tracker.on_tool_complete("Read", success=False, error_msg="File not found")

    def test_failed_tool_without_message(self):
        tracker = _make_tracker()
        tracker.on_tool_complete("Write", success=False)


class TestProgressTrackerSubagentStop:
    def test_subagent_stop_pops_stack(self):
        tracker = _make_tracker()
        tracker.subagent_stack.append("assessment")
        tracker.on_subagent_stop("assessment", 5000)
        assert tracker.subagent_stack == []

    def test_subagent_stop_mismatched_name_leaves_stack(self):
        tracker = _make_tracker()
        tracker.subagent_stack.append("assessment")
        tracker.on_subagent_stop("code-review", 3000)
        assert tracker.subagent_stack == ["assessment"]


class TestProgressTrackerSummary:
    def test_get_summary_structure(self):
        tracker = _make_tracker()
        tracker.announce_phase("assessment")
        tracker.on_tool_start("Read", {"file_path": "a.py"})
        tracker.on_tool_start("Write", {"file_path": "out.md"})

        summary = tracker.get_summary()
        assert summary["current_phase"] == "assessment"
        assert summary["tool_count"] == 2
        assert summary["files_read"] == 1
        assert summary["files_written"] == 1
        assert summary["subagent_depth"] == 0


class TestProgressTrackerAssistantText:
    def test_debug_mode_logs_text(self):
        tracker = _make_tracker(debug=True)
        tracker.on_assistant_text("Analyzing the authentication module for SQL injection...")

    def test_non_debug_mode_suppresses_text(self):
        tracker = _make_tracker(debug=False)
        tracker.on_assistant_text("This should not appear in non-debug mode")


class TestProgressTrackerConstants:
    def test_artifact_file_names(self):
        assert SECURITY_FILE == "SECURITY.md"
        assert THREAT_MODEL_FILE == "THREAT_MODEL.json"
        assert VULNERABILITIES_FILE == "VULNERABILITIES.json"
        assert PR_VULNERABILITIES_FILE == "PR_VULNERABILITIES.json"
        assert SCAN_RESULTS_FILE == "scan_results.json"
