from __future__ import annotations

import os
import re
from typing import Optional

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv, find_dotenv

from promptheus.adapters.slack import SlackAdapter
from promptheus.core.engine import RedTeamEngine, Report
from promptheus.utils.loop_breaker import is_safe_to_reply

# Auto-load .env from current working directory if present.
load_dotenv(find_dotenv(usecwd=True))

_bot_user_id: Optional[str] = None


def _get_bot_user_id(client) -> Optional[str]:
    global _bot_user_id
    if _bot_user_id:
        return _bot_user_id
    resp = client.auth_test()
    _bot_user_id = resp.get("user_id") or resp.get("bot_id")
    return _bot_user_id


def _extract_mentions(text: str) -> list[str]:
    return re.findall(r"<@([A-Z0-9]+)>", text or "")


def _extract_target_id(text: str, bot_user_id: str) -> Optional[str]:
    mentions = _extract_mentions(text)
    for m in mentions:
        if m != bot_user_id:
            return m
    return None


def _is_attack_command(text: str, bot_user_id: str) -> bool:
    if not text:
        return False
    mentions = _extract_mentions(text)
    return bot_user_id in mentions and "attack" in text.lower()


def _format_report(report: Report) -> str:
    vulnerable = [r for r in report.results if r.vulnerable]
    safe = [r for r in report.results if not r.vulnerable]
    lines = [
        f"Scan complete: {len(vulnerable)} vulnerable, {len(safe)} safe.",
    ]
    for r in vulnerable[:3]:
        lines.append(f"- {r.name}: {r.severity} ({r.reasoning[:120]})")
    if len(vulnerable) > 3:
        lines.append(f"- ...and {len(vulnerable) - 3} more")
    return "\n".join(lines)


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
    def handle_message_events(body, say, client, logger):
        event = body.get("event", {})
        text = event.get("text") or ""
        channel_id = event.get("channel")
        thread_ts = event.get("thread_ts") or event.get("ts")
        if not thread_ts or not channel_id:
            return

        bot_user_id = _get_bot_user_id(client)
        if not bot_user_id:
            return

        if not _is_attack_command(text, bot_user_id):
            return

        target_id = _extract_target_id(text, bot_user_id)
        if not target_id:
            say(thread_ts=thread_ts, text="Usage: @RedTeamBot attack @TargetBot")
            return

        if not is_safe_to_reply(client, channel_id, thread_ts, bot_user_id):
            say(thread_ts=thread_ts, text="Loop breaker triggered. Stopping thread.")
            return

        logger.info(f"Starting attack in {channel_id} thread {thread_ts} vs {target_id}")
        say(thread_ts=thread_ts, text=f"Starting attack against <@{target_id}> ...")
        adapter = SlackAdapter(client, channel_id, thread_ts, target_bot_user_id=target_id)
        engine = RedTeamEngine(adapter)
        report = engine.run_scan(verbose_console=False)
        say(thread_ts=thread_ts, text=_format_report(report))

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
