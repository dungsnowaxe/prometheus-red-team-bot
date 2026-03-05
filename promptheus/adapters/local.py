"""Local adapter: call a Python callable to simulate the target bot."""

from collections.abc import Callable

from .base import TargetAdapter


class LocalAdapter(TargetAdapter):
    """Send prompt to a local callable (e.g. dummy bot for testing)."""

    def __init__(self, bot_fn: Callable[[str], str]):
        """
        bot_fn: function that takes a prompt string and returns the reply string.
        """
        self._bot_fn = bot_fn

    def send_prompt(self, prompt: str) -> str:
        return self._bot_fn(prompt)
