## 1. CLI: PR review command

- [x] 1.1 Add `pr-review` subcommand to Promptheus CLI (e.g. in `apps/cli/main.py`) with `--path`, `--range` (base..head), and `--last N`; build DiffContext from git and call Scanner.pr_review()
- [x] 1.2 Add `--output json` (and optionally `text`) for pr-review so stdout can be parsed by the desktop; document exit codes and output format

## 2. CLI: Agent mode output (optional for desktop)

- [x] 2.1 Add `--output json` for agent-mode scan (when `--mode agent`) so the desktop can parse results from stdout; keep backward compatibility for text output

## 3. Desktop: Mode selection and layout

- [x] 3.1 Add mode selector in the UI (e.g. tabs or radio: URL scan | Agent scan | PR review); keep single main window and shared results/log area
- [x] 3.2 Show the appropriate form (URL input, agent form, or PR form) based on selected mode; hide or disable irrelevant fields

## 4. Desktop: Agent mode

- [x] 4.1 Add agent scan form: repo path (required), optional model, DAST, DAST URL, confirm-large-scan (when CLI supports them)
- [x] 4.2 Extend main-process bridge to run agent scan: spawn CLI with `scan --mode agent --target-path <path>` and optional flags; reuse existing stderr streaming and exit handling
- [x] 4.3 Parse agent scan stdout when `--output json` is used and display results in the shared results area; otherwise show success/failure and optional “Open results folder” or read known artifact path
- [x] 4.4 (Optional) Add Cancel button that kills the agent scan subprocess when running

## 5. Desktop: PR review mode

- [x] 5.1 Add PR review form: repo path (required), commit range (e.g. base..head) or “last N commits” input
- [x] 5.2 Extend main-process bridge to run PR review: spawn CLI with `pr-review --path <repo> [--range ... | --last N]` and stream stderr; handle stdout when `--output json`
- [x] 5.3 Parse PR review stdout when JSON is available and display findings in the shared results area; otherwise show success/failure and optional link to artifacts
- [x] 5.4 (Optional) Add Cancel button that kills the PR review subprocess when running

## 6. Documentation and packaging

- [x] 6.1 Update desktop README (and main apps README if needed) to describe agent mode and PR review; document CLI path override for dev
- [x] 6.2 Ensure packaged app bundles a CLI that includes the pr-review command and agent --output json; no packaging changes required if CLI is already bundled as one binary/entrypoint
