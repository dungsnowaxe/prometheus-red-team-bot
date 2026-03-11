## Context

Promptheus has a Typer CLI (`promptheus scan --target-url <url>` for legacy URL scans) and a FastAPI server at `apps/api`. The repo already plans a desktop app in `apps/README.md`. The user prefers **Electron** for a larger ecosystem and **electron-forge** for packaging, and wants to avoid running a separate API: the desktop should **run the CLI from the Electron main process** via a bridge (subprocess), so users only run the desktop app and have the CLI executed inside it.

## Goals / Non-Goals

**Goals:**

- Deliver a native desktop application under `apps/desktop/` using Electron and electron-forge that allows users to run URL scans and view results.
- Use the **Promptheus CLI** as the backend by invoking it from the Electron main process (subprocess); no separate API server required.
- Package the app with electron-forge so it can be installed and run on at least one OS.

**Non-Goals:**

- Running or depending on the Promptheus HTTP API from the desktop (desktop uses CLI only).
- Implementing agent-mode scans, PR review, or other flows in the desktop app in the first version (URL scan only).
- Bundling a full Python + Promptheus runtime inside the app in v1 (CLI is a prerequisite in the environment unless we add bundling later).
- Mobile app or browser extension (desktop only).

## Decisions

### Desktop stack: Electron + electron-forge

- **Decision**: Use **Electron** with **electron-forge** as the packager/bundler. Use **React** (Vite) in the renderer; main process handles CLI invocation and IPC.
- **Rationale**: Larger ecosystem and team familiarity; electron-forge is the standard way to package and build Electron apps (make, publish, etc.).
- **Alternatives**: Tauri (smaller binary but smaller ecosystem); other packagers like electron-builder (forge is preferred per user).

### Renderer navigation: TanStack Router (when multi-page)

- **Decision**: Keep v1 as a single-screen app (no routing). If/when we add multiple pages (e.g. Settings, Logs, History), use **TanStack Router** in the React renderer to manage navigation.
- **Rationale**: Type-safe routing and scalable navigation once the UI grows beyond a single view.
- **Alternatives**: No router (fine for single-screen only); React Router (less type-safe in this codebase).

### CLI execution via Electron bridge

- **Decision**: The **main process** spawns the Promptheus CLI as a subprocess (e.g. `child_process.spawn('promptheus', ['scan', '--target-url', url])` or equivalent, using `promptheus` from PATH or a configurable path). Main process captures stdout/stderr and exit code, and sends progress/result data to the renderer via IPC (e.g. `ipcMain`/`ipcRenderer` or preload bridge). No HTTP API; the desktop is a thin UI over the CLI.
- **Rationale**: Single thing for the user to run (the desktop app); no need to start the API. Reuses the same code path as the CLI.
- **Alternatives**: Desktop calling the API (rejected—user asked to use CLI in-process instead); embedding Python in Node (heavy; subprocess is simpler).

### Machine-readable CLI output

- **Decision**: For the desktop to show results reliably, the CLI should emit machine-readable output for legacy URL scans. If it does not already, add an option (e.g. `--output json`) that prints a single JSON object (e.g. `{ "results": [ ... ] }`) to stdout on success. The main process parses this and sends it to the renderer. If the CLI already has a way to get structured output, use that instead.
- **Rationale**: Parsing Rich/table output is fragile; JSON is stable and easy to consume from Node.
- **Alternatives**: Parse human-readable stdout (brittle); use a sidecar file (extra complexity); keep API as optional backend (user said no—use CLI).

### UI scope for v1

- **Decision**: Single main window with: (1) Optional settings: path to `promptheus` (default: assume in PATH). (2) Scan: target URL input, "Run scan" button, progress indicator (e.g. "Running scan…" and stderr streamed to a log area if desired). (3) Results: after scan completes, display results (payload_id, name, vulnerable, severity, reasoning) in a table or list. No history of past scans in v1; one scan at a time.
- **Rationale**: Minimal viable desktop experience; no API URL or health check since we are not using the API.
- **Alternatives**: Multi-window or tray-only (adds complexity); full feature parity with CLI (out of scope).

### Packaging and distribution

- **Decision**: Use **electron-forge** to produce a platform artifact (e.g. macOS .app or DMG, Windows installer). Target at least one platform for the first release. The packaged app SHALL ship with a bundled Promptheus CLI executable so users do not install Promptheus separately.
- **Rationale**: electron-forge is the chosen packager; one packaged artifact per platform is enough for v1.
- **Alternatives**: Require users to install Promptheus separately (rejected); call the HTTP API (rejected for desktop); bundle a full Python environment instead of a standalone CLI binary (heavier).

### Bundling Promptheus CLI

- **Decision**: Build a **standalone Promptheus CLI executable per target OS** (e.g. using **PyInstaller** in `--onefile` or one-folder mode) and include it in the packaged Electron app as an extra resource. At runtime, the Electron main process resolves the bundled binary path (e.g. via `process.resourcesPath`) and spawns it for scans.
- **Rationale**: Users only install the desktop app; no Python or pip required. A prebuilt executable provides a stable contract for the Electron bridge.
- **Alternatives**: Ship a Python interpreter + venv in resources (larger and more complex); require system Python + pip install (worse UX).

## Risks / Trade-offs

- **Risk**: Bundled CLI binary is OS/arch-specific and must be built per target → **Mitigation**: Add build tasks per platform and CI packaging later; keep the bundling pipeline deterministic.
- **Risk**: Scan can take a long time; app might be closed → **Mitigation**: Show progress and stderr; optionally allow cancellation (kill subprocess) in a follow-up.
- **Trade-off**: Packaging now includes a CLI build step and increases app size.

## Migration Plan

- New code only under `apps/desktop/`. Optional small CLI change (e.g. `--output json`) if needed. No migration of existing users; desktop is additive.
- Rollback: remove or do not ship the desktop app; CLI and API unchanged.

## Open Questions

- If TanStack Router is introduced, choose the appropriate history strategy for Electron builds (e.g. hash or memory history) and keep it consistent across dev and packaged runs.
- Keep the desktop app as a separate npm project under `apps/desktop/` with its own package.json so it can be built without Python deps; document that running the app requires `promptheus` on PATH (or configured path).
