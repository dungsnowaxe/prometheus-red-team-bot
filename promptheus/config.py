"""Settings resolution: env var -> config file -> default. Do not commit secrets."""

from __future__ import annotations

import os
from typing import Optional

from promptheus.config_store import load_config

_cache: dict | None = None


def _stored() -> dict:
    """Lazy-load the persistent config file (cached for the process lifetime)."""
    global _cache
    if _cache is None:
        _cache = load_config()
    return _cache


def reload_config() -> None:
    """Force re-read from disk (useful after wizard saves new config)."""
    global _cache
    _cache = None


def get_openai_api_key() -> Optional[str]:
    return os.getenv("OPENAI_API_KEY")


def get_judge_base_url() -> Optional[str]:
    return (
        os.getenv("PROMPTHEUS_JUDGE_BASE_URL")
        or _stored().get("base_url")
        or None
    )


def get_judge_api_key() -> Optional[str]:
    return (
        os.getenv("PROMPTHEUS_JUDGE_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or _stored().get("api_key")
        or None
    )


def get_judge_model() -> str:
    return (
        os.getenv("PROMPTHEUS_JUDGE_MODEL")
        or _stored().get("model")
        or "gpt-4o-mini"
    )


def get_slack_bot_token() -> Optional[str]:
    return os.getenv("SLACK_BOT_TOKEN")


def get_slack_app_token() -> Optional[str]:
    """Socket Mode app-level token (starts with xapp-)."""
    return os.getenv("SLACK_APP_TOKEN")


def get_loop_breaker_max_messages() -> int:
    return int(os.getenv("PROMPTHEUS_LOOP_BREAKER_MAX_MESSAGES", "5"))


def get_resolved_config_display() -> dict[str, str]:
    """Return the fully-resolved config with the API key masked (for `config show`)."""
    api_key = get_judge_api_key() or ""
    masked = api_key[:4] + "..." + api_key[-4:] if len(api_key) > 8 else ("***" if api_key else "(none)")
    return {
        "provider": _stored().get("provider", "(env / default)"),
        "api_key": masked,
        "base_url": get_judge_base_url() or "(default)",
        "model": get_judge_model(),
    }
