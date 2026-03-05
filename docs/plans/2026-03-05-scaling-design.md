# Scaling design: apps layer and full migration

**Date:** 2026-03-05  
**Goal:** Scale PROMPTHEUS for more products (desktop app, mobile app) without tangling UIs.

## Decisions (implemented)

1. **`apps/` layer** — One directory per delivery surface; **app code lives under `apps/`** (cli, dashboard, slack_bot, api). `promptheus/` is **core only**: core/, adapters/, config, utils. No interface code in promptheus except shims.
2. **Full migration** — CLI, dashboard, Slack bot, and API code moved from `promptheus/interfaces/` to `apps/cli/`, `apps/dashboard/`, `apps/slack_bot/`, `apps/api/`. `promptheus/interfaces/` keeps only thin shims (dashboard.py, slack_bot.py) so old entrypoints still work.
3. **Shared API** — `apps/api/main.py` exposes FastAPI (GET /health, GET /payloads, POST /scan) for desktop/mobile.
4. **Optional dependencies** — `pyproject.toml`: `[api]` and `[all]` extras; base install unchanged.
5. **Placeholders** — `apps/desktop/`, `apps/mobile/` are README-only.
6. **Build and validate** — `scripts/build.sh`: editable install, wheel build, CLI/API/dashboard/core validation. Slack bot is compile-only (full run needs real tokens).

## Layout (after migration)

```
apps/
├── README.md
├── cli/           # main.py, wizard.py  → promptheus script
├── dashboard/     # main.py             → streamlit run apps/dashboard/main.py
├── slack_bot/    # main.py             → python -m apps.slack_bot.main
├── api/           # main.py             → uvicorn apps.api.main:app
├── desktop/       # README (planned)
└── mobile/        # README (planned)
promptheus/
├── core/, adapters/, utils/, config*.py
└── interfaces/    # shims: dashboard.py, slack_bot.py (backward compat)
scripts/
├── build.sh       # build + validate
└── mock_chat_server.py
```

## Backward compatibility

- `python -m promptheus` → `apps.cli.main:run_app`
- `streamlit run promptheus/interfaces/dashboard.py` → still works (shim)
- `python -m promptheus.interfaces.slack_bot` → still works (shim)
