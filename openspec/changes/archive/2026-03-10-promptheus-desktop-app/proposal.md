## Why

Promptheus today is used via CLI, Streamlit dashboard, Slack bot, or the HTTP API. Users who want a native desktop experience (installable app, system tray, larger ecosystem of tooling) have no option. A desktop app makes Promptheus accessible to security practitioners who prefer a dedicated app, and aligns with the existing plan in `apps/README.md` for a desktop delivery surface.

## What Changes

- **New desktop app**: A native desktop application using **Electron** (with **electron-forge** for packaging/bundling) under `apps/desktop/`. The app provides a GUI for running red-team scans and viewing results. Instead of requiring a separate Promptheus API server, the desktop app uses an **Electron main-process bridge** to **execute the Promptheus CLI** (e.g. `promptheus scan --target-url <url>`) inside the Electron process and consume its output. One process for the user—no need to run the API.
- **CLI invocation from Electron**: The main process spawns the Promptheus CLI as a subprocess; the renderer receives progress and results via IPC. The CLI may need a machine-readable output option (e.g. `--output json`) so the desktop can parse results reliably; that is a small CLI addition if not already present.
- **Packaging and distribution**: Use electron-forge to build and package the app for at least one platform (e.g. macOS or Windows) so it can be installed and run. Python/promptheus is assumed to be available in the environment (or documented as a prerequisite) when running the packaged app, unless we later bundle a Python runtime.
- **Packaging and distribution**: Use electron-forge to build and package the app for at least one platform (e.g. macOS or Windows) so it can be installed and run. The packaged app SHALL include a bundled Promptheus CLI executable so users do not need to install Promptheus separately.

## Capabilities

### New Capabilities

- `desktop-app`: Native desktop application shell (Electron + electron-forge), scan UI (target URL, run scan), and results view. Uses an Electron bridge to run the Promptheus CLI from the main process and pass stdout/result data to the renderer via IPC; no separate API server.
- `desktop-packaging`: Build and package the desktop app with electron-forge for distribution (installer or app bundle) for at least one OS.

### Modified Capabilities

- **CLI (optional)**: If the CLI does not already support machine-readable output for legacy URL scans, add an option (e.g. `--output json`) so the desktop can parse scan results from stdout. Otherwise the desktop may parse existing output format or use another agreed contract.

## Impact

- **Affected code**: New directory `apps/desktop/` (Electron app, bridge to CLI). Possibly small CLI change (e.g. `--output json`) in `apps/cli/main.py` for desktop consumption.
- **APIs**: No dependency on the Promptheus HTTP API for the desktop; desktop invokes CLI only.
- **Dependencies**: Electron, electron-forge, and a **React** frontend under `apps/desktop/` with its own package.json. Build tooling will also produce a bundled Promptheus CLI executable for each supported OS (e.g. via PyInstaller) that is shipped inside the app.
- **Artifacts**: No new `.promptheus/` or server-side artifacts. Desktop may persist local preferences (window size, CLI path) in app-specific storage.
