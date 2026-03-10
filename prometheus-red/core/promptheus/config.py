"""Configuration helpers for PROMPTHEUS (red)."""

from __future__ import annotations

import os
from typing import Optional


def get_judge_api_key() -> Optional[str]:
    return os.getenv("PROMPTHEUS_JUDGE_API_KEY") or os.getenv("OPENAI_API_KEY")


def get_judge_base_url() -> Optional[str]:
    return os.getenv("PROMPTHEUS_JUDGE_BASE_URL") or os.getenv("OPENAI_BASE_URL")


def get_judge_model() -> str:
    return os.getenv("PROMPTHEUS_JUDGE_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o-mini"


def get_judge_max_tokens() -> int | None:
    raw = os.getenv("PROMPTHEUS_JUDGE_MAX_TOKENS") or os.getenv("OPENAI_MAX_TOKENS")
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return max(1, value)


def get_attacker_api_key() -> Optional[str]:
    return (
        os.getenv("PROMPTHEUS_ATTACKER_API_KEY")
        or os.getenv("PROMPTHEUS_JUDGE_API_KEY")
        or os.getenv("OPENAI_API_KEY")
    )


def get_attacker_base_url() -> Optional[str]:
    return (
        os.getenv("PROMPTHEUS_ATTACKER_BASE_URL")
        or os.getenv("PROMPTHEUS_JUDGE_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
    )


def get_attacker_model() -> str:
    return (
        os.getenv("PROMPTHEUS_ATTACKER_MODEL")
        or os.getenv("PROMPTHEUS_JUDGE_MODEL")
        or os.getenv("OPENAI_MODEL")
        or "gpt-4o-mini"
    )


def get_loop_breaker_max_messages() -> int:
    raw = os.getenv("PROMPTHEUS_LOOP_BREAKER_MAX_MESSAGES", "5")
    try:
        value = int(raw)
    except ValueError:
        return 5
    return max(1, value)
