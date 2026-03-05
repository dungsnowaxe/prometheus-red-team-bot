"""Load payloads from JSON."""

import json
from pathlib import Path
from typing import Any


def _payloads_path() -> Path:
    return Path(__file__).parent / "payloads.json"


def load_payloads() -> list[dict[str, Any]]:
    """Load payload list from core/attacks/payloads.json. Returns list of dicts with id, name, prompt, judge_expectation."""
    path = _payloads_path()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []
