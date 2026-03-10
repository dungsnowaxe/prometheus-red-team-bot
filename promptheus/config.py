"""Shared PROMPTHEUS runtime configuration helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from promptheus.config_store import load_config

_cache: dict | None = None


def _stored() -> dict:
    """Lazy-load the persistent config file (cached for the process lifetime)."""
    global _cache
    if _cache is None:
        _cache = load_config()
    return _cache


def _get_int(name: str, default: int) -> int:
    """Read a positive integer env var, falling back when invalid."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _get_float(name: str, default: Optional[float]) -> Optional[float]:
    """Read a positive float env var; None or invalid => default."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def reload_config() -> None:
    """Force re-read from disk (useful after wizard saves new config)."""
    global _cache
    _cache = None


def get_openai_api_key() -> Optional[str]:
    return os.getenv("OPENAI_API_KEY")


def get_judge_base_url() -> Optional[str]:
    return os.getenv("PROMPTHEUS_JUDGE_BASE_URL") or _stored().get("base_url") or None


def get_judge_api_key() -> Optional[str]:
    return (
        os.getenv("PROMPTHEUS_JUDGE_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or _stored().get("api_key")
        or None
    )


def get_judge_model() -> str:
    return os.getenv("PROMPTHEUS_JUDGE_MODEL") or _stored().get("model") or "gpt-4o-mini"


def get_judge_max_response_chars() -> Optional[int]:
    """
    Max target response length (chars) before truncation. When set, responses longer
    than this are truncated and \"[truncated]\" is appended. None or 0 = no truncation.
    Env: PROMPTHEUS_JUDGE_MAX_RESPONSE_CHARS (default: None).
    """
    raw = os.getenv("PROMPTHEUS_JUDGE_MAX_RESPONSE_CHARS") or _stored().get("judge_max_response_chars")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def get_slack_bot_token() -> Optional[str]:
    return os.getenv("SLACK_BOT_TOKEN")


def get_slack_app_token() -> Optional[str]:
    """Socket Mode app-level token (starts with xapp-)."""
    return os.getenv("SLACK_APP_TOKEN")


def get_loop_breaker_max_messages() -> int:
    return _get_int("PROMPTHEUS_LOOP_BREAKER_MAX_MESSAGES", 5)


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


class LanguageConfig:
    """Language detection and file-extension metadata for scanner exclusions."""

    SUPPORTED_LANGUAGES: dict[str, tuple[str, ...]] = {
        "python": (".py",),
        "javascript": (".js", ".mjs", ".cjs", ".jsx"),
        "typescript": (".ts", ".tsx"),
        "go": (".go",),
        "java": (".java",),
        "ruby": (".rb",),
        "php": (".php",),
        "rust": (".rs",),
    }

    @classmethod
    def detect_languages(cls, repo: Path) -> set[str]:
        detected: set[str] = set()
        if not repo.exists():
            return detected

        for language, extensions in cls.SUPPORTED_LANGUAGES.items():
            for extension in extensions:
                if any(repo.rglob(f"*{extension}")):
                    detected.add(language)
                    break
        return detected


class ScanConfig:
    """Scan-time exclusions and safety defaults used by the agent scanner."""

    ARTIFACTS_DIR = ".promptheus"
    BLOCKED_DB_TOOLS = ("sqlite3", "psql", "mysql", "mariadb", "mongosh", "redis-cli")
    _BASE_EXCLUDED_DIRS = {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        "__pycache__",
        "dist",
        "build",
        "htmlcov",
    }
    _LANGUAGE_EXCLUDED_DIRS = {
        "python": {"venv", ".venv", ".eggs"},
        "javascript": {"node_modules", ".next", ".turbo"},
        "typescript": {"node_modules", ".next", ".turbo"},
        "go": {"vendor"},
        "java": {"target", ".gradle"},
        "ruby": {"vendor", ".bundle"},
        "php": {"vendor"},
        "rust": {"target"},
    }

    @classmethod
    def get_excluded_dirs(cls, detected_languages: set[str]) -> set[str]:
        excluded = set(cls._BASE_EXCLUDED_DIRS)
        excluded.add(cls.ARTIFACTS_DIR)
        excluded.add(".claude")
        for language in detected_languages:
            excluded.update(cls._LANGUAGE_EXCLUDED_DIRS.get(language, set()))
        return excluded

    @classmethod
    def get_excluded_dirs_for_phase(cls, phase: str, detected_languages: set[str]) -> set[str]:
        excluded = cls.get_excluded_dirs(detected_languages)
        if phase in {"threat-modeling", "dast"}:
            excluded.discard(".claude")
        if phase in {"code-review", "report-generator", "dast", "pr-code-review"}:
            excluded.discard(cls.ARTIFACTS_DIR)
        return excluded


class RuntimeConfig:
    """Facade used by the agent scanner and agent definition builder."""

    DEFAULTS = {
        "agent_model": "sonnet",
        "max_turns": 50,
        "pr_review_attempts": 3,
        "pr_review_timeout_seconds": 180,
    }

    def get_agent_model(self, agent_name: str, cli_override: str | None = None) -> str:
        env_key = f"PROMPTHEUS_{agent_name.upper()}_MODEL".replace("-", "_")
        return (
            os.getenv(env_key)
            or cli_override
            or os.getenv("PROMPTHEUS_AGENT_MODEL")
            or _stored().get("model")
            or self.DEFAULTS["agent_model"]
        )

    def get_max_turns(self) -> int:
        return _get_int("PROMPTHEUS_MAX_TURNS", self.DEFAULTS["max_turns"])

    def get_pr_review_attempts(self) -> int:
        return _get_int(
            "PROMPTHEUS_PR_REVIEW_ATTEMPTS",
            self.DEFAULTS["pr_review_attempts"],
        )

    def get_pr_review_timeout_seconds(self) -> int:
        return _get_int(
            "PROMPTHEUS_PR_TIMEOUT_SECONDS",
            self.DEFAULTS["pr_review_timeout_seconds"],
        )

    def get_max_scan_cost_usd(self) -> Optional[float]:
        """Optional max scan cost in USD; when set, scanner checks after run. Env: PROMPTHEUS_MAX_SCAN_COST_USD."""
        return _get_float("PROMPTHEUS_MAX_SCAN_COST_USD", None)

    def get_max_scan_files(self) -> Optional[int]:
        """Optional max repository file count; when exceeded requires --confirm-large-scan. Env: PROMPTHEUS_MAX_SCAN_FILES."""
        raw = os.getenv("PROMPTHEUS_MAX_SCAN_FILES")
        if raw is None:
            return None
        try:
            value = int(raw)
        except ValueError:
            return None
        return value if value > 0 else None

    def get_fix_remediation_enabled(self) -> bool:
        """Whether to run the fix-remediation agent after report (and DAST). Env: PROMPTHEUS_FIX_REMEDIATION_ENABLED (default: false)."""
        raw = os.getenv("PROMPTHEUS_FIX_REMEDIATION_ENABLED", "").strip().lower()
        return raw in ("1", "true", "yes")

    def get_dast_skills_dirs(self) -> list[Path]:
        """Additional DAST skill directories (besides package default). Env: PROMPTHEUS_DAST_SKILLS_DIRS (comma-separated paths)."""
        raw = os.getenv("PROMPTHEUS_DAST_SKILLS_DIRS", "").strip()
        if raw:
            return [Path(p.strip()).resolve() for p in raw.split(",") if p.strip()]
        stored = _stored().get("dast_skills_dirs")
        if isinstance(stored, list):
            return [Path(p).resolve() if isinstance(p, str) else Path(str(p)).resolve() for p in stored]
        return []

    def get_dast_cwe_skill_overrides(self) -> dict[str, str]:
        """Optional CWE ID -> skill name overrides for DAST. Env: PROMPTHEUS_DAST_CWE_SKILL_OVERRIDES (JSON object)."""
        raw = os.getenv("PROMPTHEUS_DAST_CWE_SKILL_OVERRIDES", "").strip()
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return {str(k): str(v) for k, v in data.items()}
            except (json.JSONDecodeError, TypeError):
                pass
        stored = _stored().get("dast_cwe_skill_overrides")
        if isinstance(stored, dict):
            return {str(k): str(v) for k, v in stored.items()}
        return {}

    def get_max_repo_mb(self) -> Optional[int]:
        """Optional max repository size in MB; when exceeded requires --confirm-large-scan. Env: PROMPTHEUS_MAX_REPO_MB."""
        raw = os.getenv("PROMPTHEUS_MAX_REPO_MB")
        if raw is None:
            return None
        try:
            value = int(raw)
        except ValueError:
            return None
        return value if value > 0 else None


config = RuntimeConfig()
