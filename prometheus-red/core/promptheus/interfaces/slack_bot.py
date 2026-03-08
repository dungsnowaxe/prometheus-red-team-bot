from __future__ import annotations

import os
from typing import Dict

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

message_counts: Dict[str, int] = {}


def create_app() -> App:
    token = os.getenv("SLACK_BOT_TOKEN")
    signing_secret = os.getenv("SLACK_SIGNING_SECRET")
    if not token or not signing_secret:
        raise RuntimeError("SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET must be set")

    app = App(
        token=token,
        signing_secret=signing_secret,
        process_before_response=True,
        raise_error_for_unhandled_request=False,
    )

    @app.event({"type": "message"})
    def handle_message_events(body, say, logger):
        event = body.get("event", {})
        thread_ts = event.get("thread_ts") or event.get("ts")
        if not thread_ts:
            return

        count = message_counts.get(thread_ts, 0) + 1
        message_counts[thread_ts] = count

        if count > 5:
            say(thread_ts=thread_ts, text="Loop breaker triggered after 5 messages. Stopping thread.")
            return

        # Allow bot-to-bot chatter; acknowledge everything.
        user_or_bot = event.get("user") or event.get("bot_id") or "unknown"
        logger.info(f"Received message from {user_or_bot} in thread {thread_ts} (count {count})")

        say(thread_ts=thread_ts, text="PROMPTHEUS listener received your message.")

    return app


def main():
    app = create_app()
    app_token = os.getenv("SLACK_APP_TOKEN")
    if app_token:
        SocketModeHandler(app, app_token).start()
    else:
        port = int(os.getenv("PORT", "3000"))
        app.start(port=port)


if __name__ == "__main__":
    main()
