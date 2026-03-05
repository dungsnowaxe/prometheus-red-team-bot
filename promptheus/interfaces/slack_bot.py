"""Shim: Slack bot moved to apps.slack_bot.main. Preserves python -m promptheus.interfaces.slack_bot."""

from apps.slack_bot.main import main

if __name__ == "__main__":
    main()
