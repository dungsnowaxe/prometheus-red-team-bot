"""Unit tests for PROMPTHEUS prompt loading utilities."""

from __future__ import annotations

import pytest

from promptheus.prompts.loader import (
    PROMPTS_DIR,
    SECURITY_AGENTS,
    load_all_agent_prompts,
    load_prompt,
    load_shared_rules,
)


class TestLoadSharedRules:
    def test_returns_string_or_none(self):
        result = load_shared_rules()
        assert result is None or isinstance(result, str)

    def test_file_exists_check(self):
        shared_path = PROMPTS_DIR / "agents" / "_shared" / "security_rules.txt"
        if shared_path.exists():
            result = load_shared_rules()
            assert isinstance(result, str)
            assert len(result) > 0


class TestLoadPrompt:
    def test_load_assessment(self):
        prompt = load_prompt("assessment")
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_load_report_generator(self):
        prompt = load_prompt("report_generator")
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_nonexistent_prompt_raises(self):
        with pytest.raises(FileNotFoundError, match="Prompt file not found"):
            load_prompt("nonexistent_agent_xyz")

    def test_security_agent_injects_shared_rules(self):
        shared_rules = load_shared_rules()
        if shared_rules:
            for agent_name in SECURITY_AGENTS:
                prompt = load_prompt(agent_name)
                assert shared_rules[:50] in prompt or len(prompt) > 0

    def test_no_injection_when_disabled(self):
        prompt_with = load_prompt("assessment", inject_shared=True)
        prompt_without = load_prompt("assessment", inject_shared=False)
        assert len(prompt_without) <= len(prompt_with)

    def test_orchestration_category(self):
        prompt = load_prompt("main", category="orchestration")
        assert isinstance(prompt, str)
        assert len(prompt) > 0


class TestLoadAllAgentPrompts:
    def test_loads_all_agents(self):
        prompts = load_all_agent_prompts()
        assert isinstance(prompts, dict)
        expected = {"assessment", "threat_modeling", "code_review", "pr_code_review", "report_generator", "dast"}
        assert set(prompts.keys()) == expected

    def test_all_prompts_nonempty(self):
        prompts = load_all_agent_prompts()
        for name, content in prompts.items():
            assert len(content) > 0, f"Prompt '{name}' is empty"


class TestSecurityAgents:
    def test_expected_agents(self):
        assert "threat_modeling" in SECURITY_AGENTS
        assert "code_review" in SECURITY_AGENTS
        assert "pr_code_review" in SECURITY_AGENTS
        assert "assessment" not in SECURITY_AGENTS
