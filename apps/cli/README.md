# CLI app

Terminal interface for running red-team scans.

**Run (from repo root):**

```bash
python -m promptheus scan --target-url https://your-api.com/chat
# or
promptheus scan -u https://your-api.com/chat
```

Entrypoint: `apps.cli.main:run_app` (also `python -m promptheus`).

Requires: `promptheus[cli]` (or `promptheus[all]`).
