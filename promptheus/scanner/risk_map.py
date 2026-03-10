"""Risk map generation from THREAT_MODEL.json and file-to-tier classification."""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Tier names in risk_map.json and for classification
TIER_CRITICAL = "critical"
TIER_MODERATE = "moderate"
TIER_SKIP = "skip"
TIER_UNMAPPED = "unmapped"

# Static skip patterns (non-security paths); not derived from threat model
STATIC_SKIP_PATTERNS = [
    "docs/*",
    "doc/*",
    "*.md",
    "*.test.*",
    "*.spec.*",
    "*test*",
    "*__tests__*",
    "*/.test.*",
    "CHANGELOG*",
    "README*",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "scripts/*",
    "*.min.js",
    "*.bundle.js",
]


def _component_to_glob(component: str) -> str | None:
    """
    Turn an affected_component string into a path glob for risk_map.

    - If it looks like a file path (contains / or has a common extension), convert to dir glob.
    - Otherwise return None (component names like "LLMChain" are not path-based).
    """
    if not component or not isinstance(component, str):
        return None
    s = component.strip().replace("\\", "/")
    # Strip trailing parenthetical (e.g. "promptheus/config.py (max_turns default 50)")
    if " (" in s:
        s = s.split(" (")[0].strip()
    if not s:
        return None
    # Path-like: contains slash or has extension
    has_slash = "/" in s
    ext = Path(s).suffix.lower()
    has_ext = ext in (".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".rb", ".php", ".json", ".yaml", ".yml")
    if not has_slash and not has_ext:
        return None
    parts = s.split("/")
    if len(parts) <= 1:
        return f"{s}*" if s else None
    # Directory-level: use path as prefix so we match any file under it
    return f"{s}*" if s.endswith("*") else f"{s}*"


def _severity_to_tier(severity: str) -> str | None:
    """Map threat severity to risk_map tier. None means no entry (unmapped -> Tier 2)."""
    if not severity:
        return None
    s = str(severity).lower()
    if s in ("critical", "high"):
        return TIER_CRITICAL
    if s == "medium":
        return TIER_MODERATE
    # low -> no entry (unmapped defaults to moderate)
    return None


def generate_risk_map(threat_model_path: Path, output_path: Path) -> None:
    """
    Generate .promptheus/risk_map.json from THREAT_MODEL.json.

    - critical/high severity threats -> critical tier globs
    - medium severity -> moderate tier globs
    - low severity -> no entry (unmapped files default to Tier 2)
    - Static skip patterns added to skip tier.
    """
    if not threat_model_path.exists():
        logger.debug("THREAT_MODEL.json not found, skipping risk_map generation")
        return
    try:
        raw = threat_model_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not load THREAT_MODEL.json for risk_map: %s", e)
        return
    if not isinstance(data, list):
        return

    critical_globs: set[str] = set()
    moderate_globs: set[str] = set()

    for threat in data:
        if not isinstance(threat, dict):
            continue
        severity = str(threat.get("severity", "")).strip()
        tier = _severity_to_tier(severity)
        if tier is None:
            continue
        components = threat.get("affected_components")
        if not isinstance(components, list):
            continue
        for comp in components:
            if not isinstance(comp, str):
                continue
            glob_pattern = _component_to_glob(comp)
            if glob_pattern:
                if tier == TIER_CRITICAL:
                    critical_globs.add(glob_pattern)
                else:
                    moderate_globs.add(glob_pattern)

    risk_map: dict[str, Any] = {
        TIER_CRITICAL: sorted(critical_globs),
        TIER_MODERATE: sorted(moderate_globs),
        TIER_SKIP: list(STATIC_SKIP_PATTERNS),
        "_meta": {
            "generated_from": "THREAT_MODEL.json",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "overrides_applied": False,
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(risk_map, indent=2) + "\n", encoding="utf-8")
    logger.debug("Wrote risk_map.json with %d critical, %d moderate, %d skip patterns",
                 len(critical_globs), len(moderate_globs), len(STATIC_SKIP_PATTERNS))


def load_risk_map(promptheus_dir: Path) -> dict[str, Any] | None:
    """Load risk_map.json if present. Returns None if missing or invalid."""
    path = promptheus_dir / "risk_map.json"
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _path_matches_glob(file_path: str, glob_pattern: str) -> bool:
    """Return True if file_path matches the glob pattern (Unix-style)."""
    normalized = file_path.replace("\\", "/")
    return fnmatch.fnmatch(normalized, glob_pattern) or fnmatch.fnmatch(normalized, f"*/{glob_pattern}")


def classify_file_tier(file_path: str, risk_map: dict[str, Any]) -> str:
    """
    Classify a single file path against risk_map globs.

    Order: critical first, then moderate, then skip. If no pattern matches, return TIER_UNMAPPED
    (caller treats unmapped as Tier 2 / moderate per spec).
    """
    if not file_path or not risk_map:
        return TIER_UNMAPPED
    path_norm = file_path.replace("\\", "/").lstrip("/")

    for pattern in risk_map.get(TIER_CRITICAL) or []:
        if _path_matches_glob(path_norm, pattern):
            return TIER_CRITICAL
    for pattern in risk_map.get(TIER_MODERATE) or []:
        if _path_matches_glob(path_norm, pattern):
            return TIER_MODERATE
    for pattern in risk_map.get(TIER_SKIP) or []:
        if _path_matches_glob(path_norm, pattern):
            return TIER_SKIP
    return TIER_UNMAPPED


def classify_diff_tier(file_paths: list[str] | set[str], risk_map: dict[str, Any] | None) -> str:
    """
    Classify a diff (list of changed files) by the highest tier among them.

    Returns TIER_CRITICAL, TIER_MODERATE, TIER_SKIP, or TIER_UNMAPPED.
    Unmapped files default to Tier 2 (moderate) per spec; so if any file is unmapped and none
    are critical, return TIER_MODERATE.
    """
    if not risk_map:
        return TIER_MODERATE  # No risk_map -> treat as moderate
    paths = set(file_paths) if isinstance(file_paths, list) else set(file_paths)
    if not paths:
        return TIER_SKIP
    tiers = [classify_file_tier(p, risk_map) for p in paths]
    if TIER_CRITICAL in tiers:
        return TIER_CRITICAL
    if TIER_MODERATE in tiers or TIER_UNMAPPED in tiers:
        return TIER_MODERATE
    return TIER_SKIP
