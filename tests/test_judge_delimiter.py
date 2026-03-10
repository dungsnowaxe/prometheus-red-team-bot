"""Tests for judge target-response delimiter and truncation."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from promptheus.core.judge.evaluator import (
    TARGET_RESPONSE_END,
    TARGET_RESPONSE_START,
    LLMJudge,
)


def test_delimiter_constants_exist() -> None:
    """Judge uses explicit delimiter tags around the target response."""
    assert TARGET_RESPONSE_START == "<target_response>"
    assert TARGET_RESPONSE_END == "</target_response>"


def test_user_message_contains_delimiters() -> None:
    """LLMJudge.evaluate builds user message with target response between delimiter tags."""
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value.choices = [
        MagicMock(message=MagicMock(content=json.dumps({"vulnerable": False, "reasoning": "ok", "severity": "Safe"})))
    ]
    judge = LLMJudge(api_key="test", model="gpt-4o-mini")
    judge._client = mock_client

    judge.evaluate(
        prompt="Hello",
        response="Target reply here",
        judge_expectation="Check for safety",
    )

    call = mock_client.chat.completions.create.call_args
    messages = call.kwargs["messages"]
    user_msg = next(m["content"] for m in messages if m["role"] == "user")
    assert TARGET_RESPONSE_START in user_msg
    assert TARGET_RESPONSE_END in user_msg
    assert "Target reply here" in user_msg


def test_truncation_when_max_chars_set() -> None:
    """When get_judge_max_response_chars returns a value, long response is truncated with [truncated]."""
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value.choices = [
        MagicMock(message=MagicMock(content=json.dumps({"vulnerable": False, "reasoning": "ok", "severity": "Safe"})))
    ]
    judge = LLMJudge(api_key="test", model="gpt-4o-mini")
    judge._client = mock_client

    long_response = "x" * 200

    with patch("promptheus.core.judge.evaluator.get_judge_max_response_chars", return_value=50):
        judge.evaluate(
            prompt="Hi",
            response=long_response,
            judge_expectation="Rubric",
        )

    call = mock_client.chat.completions.create.call_args
    user_msg = next(m["content"] for m in call.kwargs["messages"] if m["role"] == "user")
    assert "[truncated]" in user_msg
    assert "x" * 50 in user_msg
    assert "x" * 51 not in user_msg or user_msg.count("x") <= 50 + 1
