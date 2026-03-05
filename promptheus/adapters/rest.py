"""REST API adapter: POST prompt to a target URL and return reply text."""

import httpx

from .base import TargetAdapter


class RestAPITarget(TargetAdapter):
    """HTTP target: send_prompt POSTs to target_url and parses reply from response body."""

    def __init__(
        self,
        target_url: str,
        *,
        timeout: float = 30.0,
        json_key_prompt: str = "prompt",
        json_key_reply: str = "reply",
    ):
        self._url = target_url.rstrip("/")
        self._timeout = timeout
        self._key_prompt = json_key_prompt
        self._key_reply = json_key_reply

    def send_prompt(self, prompt: str) -> str:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                self._url,
                json={self._key_prompt: prompt},
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, str):
                return data
            reply = data.get(self._key_reply) or data.get("response") or data.get("content") or data.get("text")
            if reply is None:
                return str(data)
            return str(reply)
