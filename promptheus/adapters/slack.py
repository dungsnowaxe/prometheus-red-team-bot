"""Slack adapter: post prompt to channel/thread and read next reply from target bot."""

import time
from typing import Optional

from slack_sdk.web.client import WebClient

from .base import TargetAdapter


class SlackAdapter(TargetAdapter):
    """
    Target adapter for Slack: post message to channel/thread (optionally @target_bot),
    then poll conversations_history/replies for the next message from the target bot.
    """

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

    def send_prompt(self, prompt: str) -> str:
        # Post our message in the thread (optionally mention target bot)
        if self._target_bot_user_id:
            text = f"<@{self._target_bot_user_id}> {prompt}"
        else:
            text = prompt
        resp = self._client.chat_postMessage(
            channel=self._channel_id,
            thread_ts=self._thread_ts,
            text=text,
        )
        if not resp.get("ok"):
            return f"[Slack error: failed to post: {resp.get('error', 'unknown')}]"
        our_ts = resp.get("ts", "")
        # Poll for the next reply in thread from target bot (or any bot if not specified)
        deadline = time.monotonic() + self._poll_timeout
        last_count = 0
        while time.monotonic() < deadline:
            replies_resp = self._client.conversations_replies(
                channel=self._channel_id,
                ts=self._thread_ts,
                limit=100,
            )
            if not replies_resp.get("ok"):
                time.sleep(self._poll_interval)
                continue
            messages = replies_resp.get("messages") or []
            # Find messages after our_ts from target bot
            for msg in messages:
                msg_ts = msg.get("ts", "")
                if msg_ts <= our_ts:
                    continue
                user = msg.get("user") or msg.get("bot_id")
                if self._target_bot_user_id and user != self._target_bot_user_id:
                    continue
                if msg.get("subtype") == "bot_message" or user:
                    return (msg.get("text") or "").strip() or "[empty reply]"
            time.sleep(self._poll_interval)
        return "[Slack adapter: timeout waiting for target reply]"
