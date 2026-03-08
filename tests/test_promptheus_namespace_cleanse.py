"""Foundation tests for the PROMPTHEUS namespace cleanse."""

from __future__ import annotations

import importlib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN_EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".pytest_cache",
    "__pycache__",
    "htmlcov",
}
FORBIDDEN_TOKEN = "secure" + "vibes"
FORBIDDEN_ARTIFACT_DIR = "." + FORBIDDEN_TOKEN


def _iter_repo_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SCAN_EXCLUDED_PARTS for part in path.parts):
            continue
        files.append(path)
    return files


def test_repository_contains_no_legacy_namespace_references() -> None:
    offenders: list[str] = []

    for path in _iter_repo_files():
        rel_path = path.relative_to(REPO_ROOT)
        rel_path_lower = str(rel_path).lower()
        if FORBIDDEN_TOKEN in rel_path_lower:
            offenders.append(f"{rel_path} -> forbidden path name")
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        matches = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            lowered = line.lower()
            if FORBIDDEN_TOKEN in lowered or FORBIDDEN_ARTIFACT_DIR in lowered:
                matches.append(f"{line_number}:{line.strip()}")
        if matches:
            offenders.append(f"{rel_path} -> {' | '.join(matches[:3])}")

    assert not offenders, "Forbidden legacy namespace references remain:\n" + "\n".join(offenders)


def test_promptheus_config_exposes_agent_runtime_contract(temp_dir: Path) -> None:
    config_module = importlib.import_module("promptheus.config")

    assert hasattr(config_module, "config")
    assert hasattr(config_module, "LanguageConfig")
    assert hasattr(config_module, "ScanConfig")

    runtime_config = config_module.config
    language_config = config_module.LanguageConfig
    scan_config = config_module.ScanConfig

    assert callable(runtime_config.get_agent_model)
    assert callable(runtime_config.get_max_turns)
    assert callable(runtime_config.get_pr_review_attempts)
    assert callable(runtime_config.get_pr_review_timeout_seconds)

    assert runtime_config.get_agent_model("assessment", cli_override="haiku") == "haiku"
    assert isinstance(runtime_config.get_max_turns(), int)
    assert runtime_config.get_max_turns() > 0
    assert isinstance(runtime_config.get_pr_review_attempts(), int)
    assert runtime_config.get_pr_review_attempts() > 0
    assert isinstance(runtime_config.get_pr_review_timeout_seconds(), int)
    assert runtime_config.get_pr_review_timeout_seconds() > 0

    repo = temp_dir / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")

    assert isinstance(language_config.SUPPORTED_LANGUAGES, dict)
    assert "python" in language_config.SUPPORTED_LANGUAGES
    assert "python" in language_config.detect_languages(repo)

    assert isinstance(scan_config.BLOCKED_DB_TOOLS, tuple)
    assert scan_config.BLOCKED_DB_TOOLS

    excluded_dirs = scan_config.get_excluded_dirs({"python"})
    assert isinstance(excluded_dirs, set)
    assert ".git" in excluded_dirs

    dast_excluded_dirs = scan_config.get_excluded_dirs_for_phase("dast", {"python"})
    assert isinstance(dast_excluded_dirs, set)
    assert ".git" in dast_excluded_dirs
