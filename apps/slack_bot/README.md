# Slack bot app

Slack listener: `@RedTeamBot attack @TargetBot` in a channel. Runs payload scan against the target bot in that thread.

**Run:**

```bash
export SLACK_BOT_TOKEN=xoxb-...
export SLACK_APP_TOKEN=xapp-...
python -m apps.slack_bot.main
# or (backward-compat shim)
python -m promptheus.interfaces.slack_bot
```

Requires: `promptheus[slack]` (or `promptheus[all]`).
