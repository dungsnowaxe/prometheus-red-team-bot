"""Unit tests for PROMPTHEUS agentic detection module."""

from __future__ import annotations

from pathlib import Path

from promptheus.scanner.detection import (
    AgenticDetectionResult,
    STRONG_CATEGORIES,
    collect_agentic_detection_files,
    detect_agentic_patterns,
)


class TestAgenticDetectionResult:
    def test_non_agentic_result(self):
        result = AgenticDetectionResult(
            is_agentic=False,
            matched_categories=frozenset(),
            strong_categories=frozenset(),
            signals=(),
        )
        assert result.is_agentic is False
        assert len(result.signals) == 0


class TestDetectAgenticPatterns:
    def test_agentic_repo_two_categories(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "agent.py").write_text(
            "from openai import OpenAI\n"
            "tools = [function_call]\n"
        )
        files = [repo / "agent.py"]
        result = detect_agentic_patterns(repo, files)
        assert result.is_agentic is True
        assert len(result.matched_categories) >= 2

    def test_non_agentic_repo(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("print('hello world')\n")
        files = [repo / "app.py"]
        result = detect_agentic_patterns(repo, files)
        assert result.is_agentic is False

    def test_single_category_not_agentic(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "config.py").write_text("import openai\n")
        files = [repo / "config.py"]
        result = detect_agentic_patterns(repo, files)
        assert result.is_agentic is False
        assert "llm_apis" in result.matched_categories

    def test_strong_categories_tracked(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "agent.py").write_text(
            "import anthropic\nimport langchain\n"
        )
        files = [repo / "agent.py"]
        result = detect_agentic_patterns(repo, files)
        assert result.is_agentic is True
        assert result.strong_categories.issubset(STRONG_CATEGORIES)

    def test_signals_include_file_info(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "bot.py").write_text(
            "import openai\n"
            "tools = [function_call]\n"
        )
        files = [repo / "bot.py"]
        result = detect_agentic_patterns(repo, files)
        assert any("bot.py" in sig for sig in result.signals)

    def test_empty_files_list(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        result = detect_agentic_patterns(repo, [])
        assert result.is_agentic is False

    def test_nonexistent_file_skipped(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        result = detect_agentic_patterns(repo, [repo / "nonexistent.py"])
        assert result.is_agentic is False


class TestCollectAgenticDetectionFiles:
    def test_includes_code_files(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        code = repo / "app.py"
        code.write_text("pass\n")
        result = collect_agentic_detection_files(repo, [code], exclude_dirs=set())
        assert code in result

    def test_includes_manifest_files(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("openai\n")
        (repo / "pyproject.toml").write_text("[project]\n")
        result = collect_agentic_detection_files(repo, [], exclude_dirs=set())
        names = [p.name for p in result]
        assert "requirements.txt" in names
        assert "pyproject.toml" in names

    def test_excludes_directories(self, temp_dir: Path):
        repo = temp_dir / "repo"
        repo.mkdir()
        venv = repo / "venv"
        venv.mkdir()
        (venv / "requirements.txt").write_text("openai\n")
        result = collect_agentic_detection_files(repo, [], exclude_dirs={"venv"})
        assert not any("venv" in str(p) for p in result)
