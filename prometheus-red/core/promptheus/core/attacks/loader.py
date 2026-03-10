"""Load payloads from JSON."""

import json
from pathlib import Path
from typing import Any


def _payloads_path() -> Path:
    return Path(__file__).parent / "payloads.json"


def load_payloads(path: Path | None = None) -> list[dict[str, Any]]:
    """Load payload list from a JSON file."""
    path = path or _payloads_path()
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []
