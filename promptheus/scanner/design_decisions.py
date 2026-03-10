"""Load and match design decisions for code-review and PR-review prompt injection."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def load_design_decisions(promptheus_dir: Path) -> list[dict[str, Any]]:
    """
    Load design decisions from .promptheus/design_decisions.json.

    Returns a list of decision dicts. Returns [] if the file is missing, invalid, or empty.
    """
    path = promptheus_dir / "design_decisions.json"
    if not path.exists():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            return []
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("Could not load design_decisions.json: %s", e)
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def match_design_decisions(
    decisions: list[dict[str, Any]],
    paths: list[str] | set[str],
) -> list[dict[str, Any]]:
    """
    Return decisions that match the given paths.

    A decision matches if:
    - Any of its "references" (file paths) is in or equals a path in paths, or
    - Any path in paths contains the decision's "component" (e.g. path "src/gateway/auth.ts"
      and component "gateway/auth").
    """
    path_set = set(paths) if isinstance(paths, list) else set(paths)
    matched: list[dict[str, Any]] = []
    for d in decisions:
        refs = d.get("references") or []
        if not isinstance(refs, list):
            refs = []
        component = (d.get("component") or "").strip()
        for p in path_set:
            p_norm = p.replace("\\", "/")
            if p_norm in refs or any(ref.replace("\\", "/") == p_norm for ref in refs if isinstance(ref, str)):
                matched.append(d)
                break
            if component and f"/{component}/" in p_norm or p_norm.endswith(f"/{component}") or component in p_norm:
                matched.append(d)
                break
    return matched


def format_design_decisions_for_prompt(decisions: list[dict[str, Any]], max_entries: int = 15) -> str:
    """
    Format a list of design decisions for injection into an agent prompt.

    Caps at max_entries to avoid oversized prompts. Each entry includes
    decision, accepted_behaviors, and invalidation_conditions.
    """
    if not decisions:
        return ""
    lines = [
        "The following design decisions apply. Do NOT flag behaviors listed under "
        "'Accepted behaviors' as vulnerabilities unless one of 'Invalidation conditions' is met.",
        "",
    ]
    for d in decisions[:max_entries]:
        id_ = d.get("id", "?")
        decision = d.get("decision", "")
        accepted = d.get("accepted_behaviors") or []
        invalidation = d.get("invalidation_conditions") or []
        accepted_str = "\n  - ".join(str(x) for x in accepted) if accepted else " (none)"
        invalidation_str = "\n  - ".join(str(x) for x in invalidation) if invalidation else " (none)"
        lines.append(f"- **{id_}**: {decision}")
        lines.append("  Accepted behaviors:")
        lines.append(f"  - {accepted_str}")
        lines.append("  Invalidation conditions:")
        lines.append(f"  - {invalidation_str}")
        lines.append("")
    return "\n".join(lines).strip()
