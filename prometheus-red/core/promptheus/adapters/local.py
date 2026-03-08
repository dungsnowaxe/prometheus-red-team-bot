from __future__ import annotations

from typing import Callable

from promptheus.adapters.base import TargetAdapter


class LocalFunctionAdapter(TargetAdapter):
    """Adapter that wraps a local Python callable."""

    def __init__(self, func: Callable[[str], str]):
        self.func = func
        self.name = getattr(func, "__name__", "local-function")

    def send_message(self, payload: str) -> str:
        return self.func(payload)
