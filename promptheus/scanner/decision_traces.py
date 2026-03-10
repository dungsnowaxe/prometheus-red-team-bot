"""Load and match decision traces for PR review context injection."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Verdict that is typically excluded from "decision traces" section (finding was fixed)
VERDICT_FIXED = "fixed"

# Max decision traces to inject to keep prompt bounded
MAX_DECISION_TRACES_IN_PROMPT = 10


def load_decision_traces(decisions_dir: Path) -> list[dict[str, Any]]:
    """
    Load decision trace records from .promptheus/decisions/.

    Supports: (1) directory of *.json files, each one record; (2) single decisions.json array.
    Returns [] if directory missing or invalid. Merges all records into one list.
    """
    if not decisions_dir.exists() or not decisions_dir.is_dir():
        return []
    records: list[dict[str, Any]] = []
    # Single file decisions.json
    single = decisions_dir / "decisions.json"
    if single.exists():
        try:
            raw = single.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, list):
                records.extend(item for item in data if isinstance(item, dict))
            elif isinstance(data, dict):
                records.append(data)
        except (OSError, json.JSONDecodeError) as e:
            logger.debug("Could not load decisions.json: %s", e)
    # Individual *.json files (e.g. finding_id.json)
    for path in decisions_dir.glob("*.json"):
        if path.name == "decisions.json":
            continue
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                records.append(data)
        except (OSError, json.JSONDecodeError):
            continue
    return records


def match_decision_traces(
    decisions: list[dict[str, Any]],
    changed_files: list[str] | set[str],
    *,
    exclude_fixed: bool = True,
) -> list[dict[str, Any]]:
    """
    Return decisions that overlap the changed files.

    A decision matches if:
    - Any changed file is in the decision's mitigated_by list, or
    - The decision's component overlaps a changed path (path contains component or vice versa).
    When exclude_fixed is True, records with verdict "fixed" are omitted.
    """
    path_set = set(changed_files) if isinstance(changed_files, list) else set(changed_files)
    path_set_norm = {p.replace("\\", "/").lstrip("/") for p in path_set if p}
    matched: list[dict[str, Any]] = []
    for d in decisions:
        if not isinstance(d, dict):
            continue
        if exclude_fixed and str(d.get("verdict", "")).strip().lower() == VERDICT_FIXED:
            continue
        mitigated_by = d.get("mitigated_by") or []
        if not isinstance(mitigated_by, list):
            mitigated_by = []
        for m in mitigated_by:
            if not isinstance(m, str):
                continue
            m_norm = m.replace("\\", "/").lstrip("/")
            if m_norm in path_set_norm or any(m_norm in p or p in m_norm for p in path_set_norm):
                matched.append(d)
                break
        else:
            component = (d.get("component") or "").strip()
            if component:
                for p in path_set_norm:
                    if f"/{component}/" in p or p.endswith(f"/{component}") or component in p:
                        matched.append(d)
                        break
    return matched[:MAX_DECISION_TRACES_IN_PROMPT]


def format_decision_traces_for_prompt(
    decisions: list[dict[str, Any]],
    *,
    emphasize_mitigation_recheck: bool = False,
) -> str:
    """
    Format decision traces for injection into the PR review prompt.

    When emphasize_mitigation_recheck is True, prepend an instruction that the reviewer
    must re-validate that the mitigation still holds (used when changed files are in mitigated_by).
    """
    if not decisions:
        return ""
    lines = [
        "The following triage decisions apply to this diff. Do not re-report as new findings unless "
        "the rationale no longer holds or mitigation has been weakened.",
        "",
    ]
    if emphasize_mitigation_recheck:
        lines.insert(
            0,
            "**RE-VALIDATE MITIGATION: One or more changed files implement mitigations for past findings. "
            "Verify that the compensating controls still hold; if the change weakens them, report a finding.**",
        )
        lines.insert(1, "")
    for d in decisions:
        finding_id = d.get("finding_id", "?")
        verdict = d.get("verdict", "?")
        rationale = d.get("rationale", "")
        mitigated_by = d.get("mitigated_by") or []
        if isinstance(mitigated_by, list):
            mitigated_str = ", ".join(str(x) for x in mitigated_by[:5])
            if len(mitigated_by) > 5:
                mitigated_str += f" (+{len(mitigated_by) - 5} more)"
        else:
            mitigated_str = str(mitigated_by)
        lines.append(f"- **{finding_id}** (verdict: {verdict}): {rationale}")
        if mitigated_str:
            lines.append(f"  Mitigated by: {mitigated_str}")
        lines.append("")
    return "\n".join(lines).strip()
