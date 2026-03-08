from __future__ import annotations

import time
from typing import Optional

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from promptheus.adapters.base import TargetAdapter


class SlackAdapter(TargetAdapter):
    """Slack adapter that posts to a channel and waits for a thread reply."""

    def __init__(
        self,
        bot_token: str,
        channel: str,
        target_bot_user: Optional[str] = None,
        poll_interval: float = 2.0,
        max_polls: int = 5,
    ):
        self.client = WebClient(token=bot_token)
        self.channel = channel
        self.target_bot_user = target_bot_user
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        self.name = f"slack:{channel}"

    def send_message(self, payload: str) -> str:
        try:
            post_resp = self.client.chat_postMessage(channel=self.channel, text=payload)
        except SlackApiError as exc:  # pragma: no cover - network failure path
            raise RuntimeError(f"Slack post failed: {exc.response['error']}") from exc

        thread_ts = post_resp.get("ts")
        if not thread_ts:
            return "(no thread timestamp returned)"

        for _ in range(self.max_polls):
            time.sleep(self.poll_interval)
            try:
                replies = self.client.conversations_replies(channel=self.channel, ts=thread_ts)
            except SlackApiError:
                continue

            messages = replies.get("messages", [])
            responses = [
                m for m in messages
                if m.get("ts") != thread_ts
                and (
                    self.target_bot_user is None
                    or m.get("user") == self.target_bot_user
                    or m.get("bot_id") == self.target_bot_user
                )
            ]
            if responses:
                msg = responses[0]
                text = msg.get("text") or ""
                if not text and "blocks" in msg:
                    text = str(msg["blocks"])
                return text

        return "(no reply received)"
