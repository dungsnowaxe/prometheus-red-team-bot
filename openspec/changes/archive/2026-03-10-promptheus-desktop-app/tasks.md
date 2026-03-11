## 1. Project setup

- [x] 1.1 Create `apps/desktop/` and initialize Electron project with electron-forge (Vite + React template)
- [x] 1.2 Add README in `apps/desktop/` with prerequisites, dev run, and note that the packaged app bundles the Promptheus CLI (no separate install for end users)
- [x] 1.3 Configure persistent store for app settings (e.g. electron-store or equivalent) for optional CLI path

## 2. CLI bridge and settings

- [x] 2.1 Implement in main process: spawn bundled Promptheus CLI (e.g. `promptheus scan --target-url <url>`) with optional override executable path; capture stdout, stderr, exit code
- [x] 2.2 Expose bridge to renderer via IPC (preload + ipcMain): e.g. `runScan(targetUrl)`, progress/result events; parse machine-readable output (e.g. JSON) if CLI supports it
- [x] 2.3 Add settings screen: optional override CLI path (default: use bundled CLI), save to persistent storage
- [x] 2.4 If CLI has no machine-readable output for URL scan, add e.g. `--output json` to CLI and use it from the desktop
- [x] 2.5 Add build step to produce a standalone Promptheus CLI executable for the target OS (e.g. PyInstaller) and include it in the electron-forge packaged app resources

## 3. Scan UI and results

- [x] 3.1 Add main screen: target URL input and "Run scan" button
- [x] 3.2 On "Run scan", invoke CLI via bridge; show progress or loading state until subprocess exits
- [x] 3.3 Results view: display scan results (payload_id, name, vulnerable, severity, reasoning) in table or list; show error message on non-zero exit or parse failure
- [x] 3.4 Stream or show stderr in a log area (optional) so users can see CLI progress or errors
- [ ] 3.5 If the UI grows beyond a single screen, add TanStack Router for multi-page navigation (e.g. Settings/Logs/History)

## 4. Packaging and documentation

- [x] 4.1 Configure electron-forge to produce installable artifact for at least one OS (e.g. macOS .app or Windows installer)
- [x] 4.2 Document in `apps/desktop/README.md` how to build with electron-forge, how to run in dev, and how the bundled Promptheus CLI is built and shipped (end users do not install it separately)
- [x] 4.3 Update root `apps/README.md` to replace "(planned)" for desktop with run/build instructions and link to `apps/desktop/`
