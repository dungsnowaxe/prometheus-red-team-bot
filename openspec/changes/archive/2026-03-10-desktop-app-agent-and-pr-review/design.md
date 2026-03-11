## Context

The Promptheus desktop app (Electron, React, bundled CLI) currently supports only legacy URL scan. The CLI supports agent mode (`promptheus scan --mode agent --target-path <path>` with options for model, DAST, confirm-large-scan) and the codebase has `Scanner.pr_review()` for PR security review, but PR review is not exposed as a CLI command today. Both flows are long-running and produce artifacts under `.promptheus/` (e.g. VULNERABILITIES.json, PR_VULNERABILITIES.json).

## Goals / Non-Goals

**Goals:**

- Add desktop UI and bridge support for **agent-mode** scan (repo path, optional model/DAST/confirm).
- Add desktop UI and bridge support for **PR/code review** (repo path, commit range or last-N). Establish a CLI or bridge so the desktop can invoke PR review.
- Reuse the existing desktop patterns: same main window, IPC bridge, progress/stderr streaming, results display. Keep URL scan as one of the modes.

**Non-Goals:**

- Changing how agent or PR review work internally (scanner, prompts, hooks). This change is desktop UX and invocation only.
- Adding TanStack Router for this change (single-window mode selector and forms are sufficient; router can be added later if the app grows).

## Decisions

### Mode selection and layout

- **Decision**: Single main window with a **mode selector** (e.g. tabs or radio: “URL scan” | “Agent scan” | “PR review”). Each mode has its own form (URL input vs repo path + options vs repo path + range). Results area is shared; progress and stderr are shown for the active run.
- **Rationale**: Keeps one window, avoids multiple routes; users switch mode then fill the form and run.
- **Alternatives**: Separate windows per mode (heavier); wizard that asks “what do you want to do?” then one form (same outcome, different UX).

### Agent mode: invoke CLI

- **Decision**: Reuse the existing desktop CLI bridge. For agent mode, the main process spawns the bundled CLI (or override) with args: `scan`, `--mode`, `agent`, `--target-path`, `<path>`, and optionally `--model`, `--dast`, `--dast-url`, `--confirm-large-scan`. No new subprocess abstraction; same spawn + stdout/stderr/exit code + optional streamed progress as today.
- **Rationale**: Consistency with URL scan; no duplicate scanner logic in the desktop.
- **Alternatives**: Call Python/Scanner from Node via a small helper process (adds complexity); run agent in a separate “worker” window (unnecessary for v1).

### Agent mode: results

- **Decision**: If the CLI gains an agent-mode `--output json` (or similar) that prints a summary to stdout, the desktop parses it and shows results in the existing results table/list. If not, the desktop SHALL show run status and stderr, and MAY offer “Open results folder” (e.g. open `.promptheus/` in the repo) or read a known artifact path (e.g. VULNERABILITIES.json) after exit and display a summary. Prefer adding a simple JSON output for agent scan so the desktop does not depend on reading the repo’s `.promptheus/` from the Electron process.
- **Rationale**: Agent runs can be long; users need feedback and a way to see outcomes without leaving the app where possible.
- **Alternatives**: Always read artifacts from disk (requires passing repo path back and resolving `.promptheus/`; cross-platform and permissions are simpler with CLI stdout).

### PR review: CLI surface

- **Decision**: Add a **CLI command** for PR review (e.g. `promptheus pr-review --path <repo> [--range base..head | --last N] [--output json]`) that builds `DiffContext` from the given range, calls `Scanner.pr_review()`, and prints a result (e.g. findings count, severity summary, or full JSON). The desktop then invokes this command like agent mode: same bridge, spawn with args, stream stderr, parse stdout if `--output json`.
- **Rationale**: Keeps “one way to run” (CLI) and makes PR review testable and scriptable; desktop stays a thin client.
- **Alternatives**: Desktop bundles a small Python script that only does PR review and is invoked by the main process (same idea, but a dedicated command is clearer); no CLI and desktop calls a local HTTP API (adds server surface).

### PR review: range and options

- **Decision**: Desktop PR form includes: repo path (required), and either a commit range (e.g. `main..feature`) or “last N commits” (defaults from config or simple default, e.g. 1). Optional: severity threshold, pr_review_attempts/timeout overrides. Pass these through to the CLI as flags. If the CLI uses env or config for attempts/timeout, document that; desktop can set env or add flags when the CLI supports them.
- **Rationale**: Matches how PR review is parameterized in the scanner; minimal first version.
- **Alternatives**: UI for “select branch” only (range inferred); no overrides in v1 (use config only).

### Long-running and cancellation

- **Decision**: For both agent and PR review, show a “Running…” state and stream stderr into the existing log area. Optionally add a “Cancel” button that kills the subprocess (same as URL scan can be extended). No requirement to persist in-progress run across app restarts for this change.
- **Rationale**: Long runs need feedback and a way to stop; cancellation is a small extension of the existing spawn/kill pattern.
- **Alternatives**: No cancel (user closes app); background jobs and a job list (out of scope for v1).

## Risks / Trade-offs

- **Risk**: Agent/PR runs can run for many minutes; user may think the app is stuck → **Mitigation**: Clear “Running…” label, stderr stream, and optional phase messages if the CLI emits them.
- **Risk**: PR review has no CLI today; adding it touches scanner and diff parsing → **Mitigation**: Implement CLI as a thin wrapper around existing `Scanner.pr_review()`; keep changes in one place (e.g. `apps/cli/main.py` and a small helper to build diff context from git).
- **Trade-off**: If we don’t add agent `--output json`, the desktop may need to read `.promptheus/` from the repo path; path and permissions must be handled carefully (e.g. only when run from a known workspace).

## Migration Plan

- Additive only: new UI and CLI surface. No migration of existing desktop or CLI behavior. Rollback: remove new UI and new CLI command; URL scan unchanged.

## Open Questions

- Exact CLI flags for `pr-review` (e.g. `--range` vs `--base`/`--head`, `--last` default) to be decided when implementing the CLI command.
- Whether agent scan will get `--output json` in this change or a follow-up; if follow-up, desktop will use “open folder” or artifact read as above.
