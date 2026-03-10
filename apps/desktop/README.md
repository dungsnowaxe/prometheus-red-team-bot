# Promptheus Desktop

Electron desktop app for running Promptheus red-team scans. The **packaged app bundles the Promptheus CLI**—end users do not need to install Promptheus or Python separately.

The app supports three modes:

- **URL scan** — legacy API scan (target URL).
- **Agent scan** — full codebase vulnerability scan on a repository path (`promptheus scan --mode agent --target-path <path>`). Optional: model, DAST, DAST URL, confirm large scan.
- **PR review** — security review of a diff or branch (`promptheus pr-review --path <repo> [--range base..head | --last N]`). Results (findings with severity) are shown in the app when the CLI outputs JSON.

## Prerequisites

- **Node.js** 18+ and npm (for building and development)
- To **build the bundled CLI** (for packaging): Python 3 with Promptheus deps, and PyInstaller (`pip install pyinstaller`)

## Development

```bash
cd apps/desktop
npm install
npm start
```

For development, the app can use a **Promptheus CLI path override** in Settings (e.g. your local `promptheus` on PATH). If no override is set and no bundled CLI is present (dev run), scans will fail until you set the path or build a packaged app with the bundled CLI. Set the override to the repo’s CLI entrypoint (e.g. `promptheus` from a venv or `python -m promptheus` if your build exposes it) so that agent mode and PR review (including `pr-review` and `--output json`) are available.

## Packaging

1. **Optional: build the bundled CLI** (from repo root):
   ```bash
   cd /path/to/red-team-bot
   pip install pyinstaller   # if needed
   node apps/desktop/scripts/build-cli.js
   ```
   This produces `apps/desktop/resources/bin/promptheus` (or `promptheus.exe` on Windows). If you skip this, the packaged app will still run but scans will only work if the user sets a CLI path override.

2. **Package the app**:
   ```bash
   cd apps/desktop
   npm run make
   ```

   Produces an installable artifact for the current OS (e.g. macOS .app in `out/`, or Windows installer). The packaged app includes the bundled Promptheus CLI when you ran `build-cli.js`, so end users do not install Promptheus separately.

## Bundled CLI

The packaged app ships with a standalone Promptheus CLI binary (built with PyInstaller) for the target OS. Build it with `node apps/desktop/scripts/build-cli.js` from the repo root before `npm run make`. End users do not install Promptheus or Python. The bundled CLI must include the `pr-review` command and agent-mode `--output json` so that the desktop can run PR review and agent scans and display results in the UI.

## Scripts

- `npm start` — run the app in development
- `npm run package` — package the app (no installer)
- `npm run make` — package and create installer / app bundle
- `npm run build:cli` — build the standalone CLI into `resources/bin/` (run from repo root: `node apps/desktop/scripts/build-cli.js`)
