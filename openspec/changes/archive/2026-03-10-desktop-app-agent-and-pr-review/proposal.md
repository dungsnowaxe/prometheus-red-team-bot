## Why

The Promptheus desktop app (from change `promptheus-desktop-app`) currently supports only legacy URL scan. Users who want to run **agent-mode** (full repo/codebase vulnerability scan) or **PR/code review** (security review of a diff or PR) must use the CLI. Extending the desktop app to support both workflows keeps a single install surface and gives security practitioners a GUI for repo scans and PR reviews without leaving the app.

## What Changes

- **Agent mode in desktop**: Add a desktop flow to run a full agent scan on a repository path (equivalent to `promptheus scan --mode agent --target-path <path>`). User selects or enters a repo path; optional settings for model, DAST, and large-scan confirmation. The app invokes the bundled CLI (or override) with the appropriate arguments, streams progress/stderr, and displays results (e.g. from scan output or from `.promptheus/` artifacts such as VULNERABILITIES.json or SCAN_RESULTS).
- **PR / code review in desktop**: Add a desktop flow to run a PR security review on a repository (commit range or branch). The backend is `Scanner.pr_review()` (repo path, diff context, options). If the CLI does not yet expose PR review, add a CLI surface (e.g. `promptheus pr-review --path <repo> [--range base..head | --last N]`) that builds the diff context and calls the existing scanner; the desktop then invokes that CLI or uses a small bridge that runs the same Python API. Results (findings, severity) are shown in the desktop UI.
- **Desktop UI**: Extend the existing single-window app with a way to choose mode (URL scan, agent scan, PR review) and mode-specific inputs (target URL vs repo path vs repo + range). Results and progress UX are consistent where possible; agent and PR runs may be long-running, so progress and optional cancellation are important.

## Capabilities

### New Capabilities

- `desktop-agent-mode`: Desktop UI and bridge to run agent-mode scan (repo path, optional model/DAST/confirm-large-scan). Invoke CLI (or equivalent) with `--mode agent --target-path <path>` and related flags; show progress and results (vulnerabilities/summary) in the app.
- `desktop-pr-review`: Desktop UI and bridge to run PR/code review (repo path, commit range or “last N commits”). Invoke CLI or Python API for `pr_review`; show progress and findings in the app. Depends on a defined CLI or API surface for PR review (add one if missing).

### Modified Capabilities

- None. This change extends the existing desktop app; no existing OpenSpec specs in this repo are modified.

## Impact

- **Affected code**: `apps/desktop/` (Electron UI: mode selector, agent form, PR review form, result views). Possibly `apps/cli/main.py` (new `pr-review` command or flags) and/or a small Python entrypoint for PR review used by the desktop bridge.
- **APIs**: No change to the Promptheus HTTP API. Desktop continues to use the bundled CLI (or override); new CLI commands or flags for agent and PR review as needed.
- **Dependencies**: No new runtime dependencies. Optional: machine-readable output (e.g. `--output json`) for agent scan so the desktop can parse results without reading `.promptheus/` files; if not added, desktop may read artifact files from a known location after the run.
- **Artifacts**: Desktop may display or link to `.promptheus/` artifacts (VULNERABILITIES.json, PR_VULNERABILITIES.json, etc.) produced by agent and PR review runs.
