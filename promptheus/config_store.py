"""Persistent config file at ~/.config/promptheus/config.json (respects XDG_CONFIG_HOME)."""

import json
import os
from pathlib import Path
from typing import Any


def _config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "promptheus"


def _config_path() -> Path:
    return _config_dir() / "config.json"


def config_exists() -> bool:
    return _config_path().is_file()


def load_config() -> dict[str, Any]:
    path = _config_path()
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_config(data: dict[str, Any]) -> Path:
    """Write config dict to disk. Returns the path written to."""
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def config_path_display() -> str:
    return str(_config_path())
