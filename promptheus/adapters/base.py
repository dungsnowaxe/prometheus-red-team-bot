"""Abstract base class for target adapters (PyRIT-style "Targets")."""

from abc import ABC, abstractmethod


class TargetAdapter(ABC):
    """Adapter to send a prompt to a target and get a text reply."""

    @abstractmethod
    def send_prompt(self, prompt: str) -> str:
        """Send prompt to the target; return the reply text. Raise on transport errors."""
        ...
