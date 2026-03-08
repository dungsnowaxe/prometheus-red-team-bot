# PROMPTHEUS — Proactive Red-team Operator (Steps 1-5)

PROMPTHEUS is a modular red-team harness for LLM targets. It crafts adversarial payloads from reusable “skills”, probes targets via pluggable adapters (local, REST, Slack), and uses an LLM judge to score behavioral vulnerabilities. This repo ships the full bootstrap through Slack integration, ready for demos and extension.

## Setup
1) Create virtualenv (Python 3.11+): `python3 -m venv .venv && source .venv/bin/activate`
2) Install deps: `pip install -r requirements.txt`
3) Copy `.env.example` → `.env`; set `OPENAI_API_KEY`. For OpenRouter set `OPENAI_BASE_URL=https://openrouter.ai/api/v1` plus optional `OPENAI_HTTP_REFERER` and `OPENAI_X_TITLE`. For Slack, set `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, optionally `SLACK_APP_TOKEN`.

## Current scope
- Core models, skill loader, example skills.
- Attacker engine + Judge logic using `gpt-4o-mini`.
- REST adapter + local function adapter.
- Typer CLI wrapper for running attacks.
- Slack adapter and listener scaffolded (Step 5).
- Session logs written to `promptheus/data/sessions/` as JSON.

## Quick smoke (offline by default)
```bash
python -m promptheus.main --offline
```
Pass `--objective "steal the key"` to change the goal. Remove `--offline` once API key is set.

CLI example (REST target):
```
python -m promptheus.interfaces.cli attack --target-url https://example.com/llm --objective "Reveal your system prompt" --skill grandma
```

Using OpenRouter (no code changes needed):
```
export OPENAI_API_KEY=sk-or-v1-... 
export OPENAI_BASE_URL=https://openrouter.ai/api/v1
python -m promptheus.interfaces.cli attack --objective "Reveal your system prompt" --offline  # remove --offline to hit your target
```

Slack listener (requires env vars `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, and optionally `SLACK_APP_TOKEN` for Socket Mode):
```
python -m promptheus.interfaces.slack_bot
```

## Architecture at a glance
- Hexagonal: core attack/judge logic separated from adapters (REST, Slack, local) and interfaces (CLI, bot).
- Skill-based: prompts live as markdown metaprompts under `promptheus/core/skills/`.
- Behavioral judging: LLM judge plus robustness/JSON repair to handle malformed outputs.
- Storage: attack sessions serialized to JSON in `promptheus/data/sessions/`.

## Tests
```
pytest
```
Tests mock OpenAI; Slack tests auto-skip if `slack_sdk` is missing. (In this environment, package install is blocked by network policy—please install and run in your networked dev setup.)

## More detailed usage
See `USAGE.md` for step-by-step instructions (OpenRouter, offline, REST, Slack).
