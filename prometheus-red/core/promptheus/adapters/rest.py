from __future__ import annotations

from typing import Any, Dict, Optional

import requests

from promptheus.adapters.base import TargetAdapter


class RestAdapter(TargetAdapter):
    """Adapter that posts payloads to a REST endpoint."""

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        payload_field: str = "message",
    ):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
        self.payload_field = payload_field
        self.name = f"rest:{url}"

    def send_message(self, payload: str) -> str:
        body: Dict[str, Any] = {self.payload_field: payload}
        resp = requests.post(self.url, json=body, headers=self.headers, timeout=self.timeout)
        resp.raise_for_status()
        # Prefer JSON response body string if possible; otherwise raw text
        try:
            data = resp.json()
            return data if isinstance(data, str) else resp.text
        except ValueError:
            return resp.text
