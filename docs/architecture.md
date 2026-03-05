# Architecture

## Hexagonal core

`promptheus/` is the shared core:

- **core/** — Engine, payloads, LLM judge. No UI or transport code.
- **adapters/** — How we talk to targets (REST, Slack, local).
- **interfaces/** — How users talk to us: CLI, Streamlit dashboard, FastAPI server, Slack bot.
- **config** — Env + file; no secrets in code.

New UIs (e.g. desktop, mobile) do not embed this core; they call the **API** (FastAPI) which uses the same core.

## Apps layer

App code lives under `apps/`; core stays in `promptheus/`.

```
apps/
├── cli/         → Typer CLI (promptheus script, python -m promptheus)
├── dashboard/   → Streamlit (streamlit run apps/dashboard/main.py)
├── slack_bot/   → Slack listener (python -m apps.slack_bot.main)
├── api/         → HTTP API (uvicorn apps.api.main:app)
├── desktop/     → (planned) native app → calls api
└── mobile/      → (planned) mobile app → calls api
```

Backward compatibility: `promptheus/interfaces/dashboard.py` and `promptheus/interfaces/slack_bot.py` are shims that delegate to the apps above.

- **Build/validate:** `./scripts/build.sh` (editable install + wheel build + import/CLI checks).
- **Later:** Desktop and mobile can be separate codebases (Tauri, React Native, etc.) that only depend on the API contract.

## Optional dependencies

- `pip install promptheus` — CLI, dashboard, Slack (current default).
- `pip install promptheus[api]` — adds FastAPI + uvicorn for the API server.
- `pip install promptheus[all]` — default + API extras.

Core (engine, judge, adapters) only needs `httpx` and `openai`; interface-specific deps (Typer, Streamlit, Slack Bolt, FastAPI) are in the main dependency list so one install still gives all current apps.
