"""
RedTeam Listener Bot: Slack Bolt app.
Trigger: @RedTeamBot attack @TargetBot. Loop breaker: do not reply if we already sent > 5 in thread.
"""

import re
from typing import Any, Optional

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk.web.client import WebClient

from promptheus.adapters.slack import SlackAdapter
from promptheus.config import get_slack_bot_token, get_slack_app_token
from promptheus.core.engine import RedTeamEngine
from promptheus.utils.loop_breaker import is_safe_to_reply


def _create_bolt_app() -> App:
    # Allow bot_message so we can optionally handle messages from other bots
    app = App(
        token=get_slack_bot_token(),
        process_before_response=True,
    )

    # Middleware: allow message events with subtype bot_message (Bolt by default may skip some)
    @app.middleware
    def allow_bot_messages(body: dict, next_: Any) -> None:
        next_()

    return app


app = _create_bolt_app()


def _parse_attack_mention(text: str, mentions: list[dict]) -> Optional[str]:
    """Parse 'attack @TargetBot' from message; return target user ID if found. mentions from block or event."""
    if "attack" not in text.lower():
        return None
    # Event format often has no blocks; text might be like "<@U123> attack <@U456>"
    # Extract user IDs from text
    match = re.search(r"attack\s+<@(U[A-Z0-9]+)>", text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


@app.event("app_mention")
def handle_app_mention(event: dict, client: WebClient, body: dict, logger: Any) -> None:
    """Trigger: @RedTeamBot attack @TargetBot -> run RedTeamEngine and post summary."""
    channel_id = event.get("channel")
    thread_ts = event.get("ts")
    text = event.get("text") or ""
    bot_user_id = body.get("authorizations", [{}])[0].get("user_id") or event.get("bot_id")
    if not bot_user_id and body.get("event", {}).get("bot_id"):
        bot_user_id = body["event"]["bot_id"]

    # Get our bot's user ID from auth
    auth = client.auth_test()
    if auth.get("ok"):
        bot_user_id = auth.get("user_id") or bot_user_id

    # Loop breaker: do not reply if we already sent > 5 in this thread
    if not is_safe_to_reply(client, channel_id, thread_ts, bot_user_id):
        logger.info("Loop breaker: skipping reply (max messages in thread reached)")
        return

    target_user_id = _parse_attack_mention(text, event.get("blocks") or [])
    if not target_user_id:
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text="Usage: `@RedTeamBot attack @TargetBot` — mention the target bot to run the scan.",
        )
        return

    # Run in thread (use thread_ts as thread root; if this is already a thread, same)
    client.chat_postMessage(
        channel=channel_id,
        thread_ts=thread_ts,
        text="Running red-team scan...",
    )
    adapter = SlackAdapter(
        client=client,
        channel_id=channel_id,
        thread_ts=thread_ts,
        target_bot_user_id=target_user_id,
    )
    engine = RedTeamEngine(adapter)
    report = engine.run_scan(verbose_console=False)

    vulnerable_count = sum(1 for r in report.results if r.vulnerable)
    summary_lines = [f"Scan complete: {vulnerable_count} vulnerable of {len(report.results)} payloads."]
    for r in report.results:
        status = "Vulnerable" if r.vulnerable else "Safe"
        summary_lines.append(f"• {r.name}: {status} ({r.severity})")
    client.chat_postMessage(
        channel=channel_id,
        thread_ts=thread_ts,
        text="\n".join(summary_lines),
    )


def main() -> None:
    """Run with Socket Mode (requires SLACK_APP_TOKEN)."""
    token = get_slack_bot_token()
    app_token = get_slack_app_token()
    if not token or not app_token:
        raise SystemExit("Set SLACK_BOT_TOKEN and SLACK_APP_TOKEN for Socket Mode.")
    handler = SocketModeHandler(app, app_token)
    handler.start()


if __name__ == "__main__":
    main()
