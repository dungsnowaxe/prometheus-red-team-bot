# API app

HTTP API for desktop and mobile clients: run scan, list payloads, get report as JSON.

**Run:**

```bash
uvicorn apps.api.main:app --reload --host 0.0.0.0 --port 8000
```

**Endpoints:**

- `GET /health` — liveness
- `GET /payloads` — list payloads (id, name)
- `POST /scan` — body `{ "target_url": "https://..." }` → full report

Requires: `promptheus[api]` (or `promptheus[all]`).
