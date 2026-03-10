from __future__ import annotations

import time
from typing import Optional

from slack_sdk.web.client import WebClient

from promptheus.adapters.base import TargetAdapter


class SlackAdapter(TargetAdapter):
    """Post prompt to channel/thread and read the next reply from target bot."""

    def __init__(
        self,
        client: WebClient,
        channel_id: str,
        thread_ts: str,
        target_bot_user_id: Optional[str] = None,
        *,
        poll_interval: float = 2.0,
        poll_timeout: float = 60.0,
    ):
        self._client = client
        self._channel_id = channel_id
        self._thread_ts = thread_ts
        self._target_bot_user_id = target_bot_user_id
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self.name = f"slack:{channel_id}:{thread_ts}"

    def send_message(self, payload: str) -> str:
        # Mention target bot if provided.
        if self._target_bot_user_id:
            text = f"<@{self._target_bot_user_id}> {payload}"
        else:
            text = payload

        resp = self._client.chat_postMessage(
            channel=self._channel_id,
            thread_ts=self._thread_ts,
            text=text,
        )
        if not resp.get("ok"):
            return f"[Slack error: failed to post: {resp.get('error', 'unknown')}]"
        our_ts = resp.get("ts", "")

        deadline = time.monotonic() + self._poll_timeout
        while time.monotonic() < deadline:
            replies_resp = self._client.conversations_replies(
                channel=self._channel_id,
                ts=self._thread_ts,
                limit=200,
            )
            if not replies_resp.get("ok"):
                time.sleep(self._poll_interval)
                continue
            messages = replies_resp.get("messages") or []
            for msg in messages:
                msg_ts = msg.get("ts", "")
                if msg_ts <= our_ts:
                    continue
                if self._target_bot_user_id:
                    user = msg.get("user") or msg.get("bot_id")
                    bot_profile = msg.get("bot_profile") or {}
                    if not (
                        user == self._target_bot_user_id
                        or msg.get("bot_id") == self._target_bot_user_id
                        or bot_profile.get("id") == self._target_bot_user_id
                        or bot_profile.get("bot_id") == self._target_bot_user_id
                    ):
                        continue
                if msg.get("subtype") == "bot_message" or msg.get("user") or msg.get("bot_id"):
                    return (msg.get("text") or "").strip() or "[empty reply]"
            time.sleep(self._poll_interval)
        return "[Slack adapter: timeout waiting for target reply]"
