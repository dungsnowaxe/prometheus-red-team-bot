from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional


def repair_json(text: str) -> Optional[Dict[str, Any]]:
    """Attempt to repair and parse JSON fragments from a text blob.

    Strategy:
    - try direct json.loads
    - fall back to extracting the first {...} block
    - return None if parsing still fails
    """

    if not text:
        return None

    candidates = [text]

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        candidates.append(match.group(0))

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None
