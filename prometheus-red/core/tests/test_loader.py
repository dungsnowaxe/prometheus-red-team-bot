import pytest

from promptheus.core.loader import load_skill


def test_load_skill_success():
    text = load_skill("grandma")
    assert "grandmother" in text.lower()


def test_load_skill_unknown():
    with pytest.raises(FileNotFoundError):
        load_skill("missing-skill")


def test_load_skill_path_traversal_blocked():
    with pytest.raises(ValueError):
        load_skill("../etc/passwd")
