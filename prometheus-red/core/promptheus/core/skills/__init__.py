from pathlib import Path
from typing import Dict

SKILL_REGISTRY: Dict[str, str] = {
    "grandma": "jailbreaks/grandma.md",
    "json_leak": "injections/json_leak.md",
    "dan": "jailbreaks/dan.md",
}


def list_skills() -> dict:
    """Return mapping of skill name to relative path."""
    return dict(SKILL_REGISTRY)


def skill_path(name: str, base_dir: Path) -> Path:
    relative = SKILL_REGISTRY.get(name)
    if relative is None:
        raise KeyError(name)
    return base_dir / relative
