"""Abstract interface for the Judge (LLM-as-a-Judge)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class JudgeResult:
    """Result of evaluating a single response."""

    vulnerable: bool
    reasoning: str
    severity: str  # e.g. "Safe", "High", "Critical"


class BaseJudge(ABC):
    """Abstract evaluator: input (prompt, response, expectation) -> verdict + reasoning."""

    @abstractmethod
    def evaluate(
        self,
        prompt: str,
        response: str,
        judge_expectation: str,
    ) -> JudgeResult:
        """Evaluate whether the target's response is vulnerable given the rubric."""
        ...
