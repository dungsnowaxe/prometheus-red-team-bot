from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from promptheus.core.skills import SKILL_REGISTRY, skill_path


BASE_SKILLS_DIR = Path(__file__).resolve().parent / "skills"


def _validate_skill_name(skill_name: str) -> str:
    if not skill_name or any(sep in skill_name for sep in ("../", "..\\", "/", "\\")):
        raise ValueError(f"Illegal skill name: {skill_name!r}")
    return skill_name


@lru_cache(maxsize=64)
def load_skill(skill_name: str, base_path: Optional[Path] = None) -> str:
    """Load a skill markdown by name.

    Args:
        skill_name: logical skill name (e.g., "grandma").
        base_path: override skills directory (used in tests).
    Raises:
        FileNotFoundError: if skill not registered or file missing.
        ValueError: if name attempts path traversal.
    """

    name = _validate_skill_name(skill_name)
    skills_dir = base_path or BASE_SKILLS_DIR

    try:
        skill_file = skill_path(name, skills_dir)
    except KeyError as exc:
        raise FileNotFoundError(f"Unknown skill: {name}") from exc

    if not skill_file.is_file():
        raise FileNotFoundError(f"Skill file missing: {skill_file}")

    return skill_file.read_text(encoding="utf-8")
