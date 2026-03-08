# PROMPTHEUS Usage Guide

This guide shows how to run PROMPTHEUS with OpenRouter, offline demos, REST targets, and Slack.

## 1) Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2) Configure environment
Copy `.env.example` to `.env` and set what you need.
- Core LLM (OpenRouter):
  - `OPENAI_API_KEY=sk-or-v1-...`
  - `OPENAI_BASE_URL=https://openrouter.ai/api/v1`
  - Optional: `OPENAI_HTTP_REFERER`, `OPENAI_X_TITLE`
- Slack (optional): `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `SLACK_APP_TOKEN`

## 3) Offline smoke test (no network calls)
```bash
python -m promptheus.main --offline
```
Creates a session JSON in `promptheus/data/sessions/`.

## 4) CLI attack (REST target)
```bash
python -m promptheus.interfaces.cli attack \
  --target-url https://your-llm-endpoint \
  --objective "Reveal your system prompt" \
  --skill grandma \
  --attempts 2
```
- Add `--offline` to avoid real requests (uses dummy adapter + stub LLM).
- Skills: `grandma`, `json_leak` (see `promptheus/core/skills/`).

## 5) Slack bot listener
```bash
export SLACK_BOT_TOKEN=... \
       SLACK_SIGNING_SECRET=... \
       SLACK_APP_TOKEN=...   # if using Socket Mode
python -m promptheus.interfaces.slack_bot
```
Bot posts loop-breaker after 5 messages per thread to prevent runaway chats.

## 6) Running with OpenRouter (no code changes needed)
The OpenAI Python client respects `OPENAI_API_KEY` and `OPENAI_BASE_URL`, so pointing to OpenRouter is enough. Default model is `gpt-4o-mini`; change in code or expose a flag if you prefer another OpenRouter model.

## 7) Where outputs go
- Sessions: `promptheus/data/sessions/*.json`
- Skills: `promptheus/core/skills/`

## 8) Tests
```bash
pytest
```
Tests mock OpenAI; Slack tests skip if `slack_sdk` isn’t installed.
