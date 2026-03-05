# PROMPTHEUS apps

One directory per delivery surface. Core logic lives in `promptheus/`; app code lives here under `apps/`.

| App | Purpose | How to run |
|-----|---------|------------|
| **cli** | Scan from terminal | `python -m promptheus` or `promptheus scan -u <url>` |
| **dashboard** | Web UI (Streamlit) | `streamlit run apps/dashboard/main.py` or `streamlit run promptheus/interfaces/dashboard.py` (shim) |
| **slack_bot** | Slack RedTeam bot | `python -m apps.slack_bot.main` or `python -m promptheus.interfaces.slack_bot` (shim) |
| **api** | HTTP API for desktop/mobile | `uvicorn apps.api.main:app --reload` |
| **desktop** | *(planned)* Native desktop app | Will call `api` |
| **mobile** | *(planned)* Mobile app | Will call `api` |

Install only what you need:

```bash
pip install promptheus[cli]        # CLI only
pip install promptheus[dashboard]  # + Streamlit dashboard
pip install promptheus[slack]      # + Slack bot
pip install promptheus[api]        # + FastAPI server
pip install promptheus[all]        # Everything
```
