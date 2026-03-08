from __future__ import annotations

from abc import ABC, abstractmethod


class TargetAdapter(ABC):
    """Abstract adapter that sends a payload to a target and returns its response."""

    name: str = "target"

    @abstractmethod
    def send_message(self, payload: str) -> str:
        """Send payload to the target and return the textual response."""
        raise NotImplementedError
