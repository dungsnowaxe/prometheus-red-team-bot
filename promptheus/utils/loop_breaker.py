"""Prevent infinite bot-to-bot loops: do not reply if we already sent > N messages in thread."""

from typing import TYPE_CHECKING

from promptheus.config import get_loop_breaker_max_messages

if TYPE_CHECKING:
    from slack_sdk.web.client import WebClient


def is_safe_to_reply(
    client: "WebClient",
    channel_id: str,
    thread_ts: str,
    bot_user_id: str,
    *,
    max_messages: int | None = None,
) -> bool:
    """
    Return False if RedTeamBot has already sent more than max_messages (default 5) in this thread.
    Uses conversations.history filtered by bot_user_id; thread_ts is the thread root.
    """
    if max_messages is None:
        max_messages = get_loop_breaker_max_messages()
    count = 0
    cursor = None
    while True:
        resp = client.conversations_replies(
            channel=channel_id,
            ts=thread_ts,
            limit=200,
            cursor=cursor,
        )
        if not resp.get("ok"):
            return True  # On API error, allow reply to avoid blocking
        messages = resp.get("messages") or []
        for msg in messages:
            if msg.get("user") == bot_user_id:
                count += 1
            if count > max_messages:
                return False
        cursor = resp.get("response_metadata", {}).get("next_cursor")
        if not cursor:
            break
    return count <= max_messages
