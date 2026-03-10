## ADDED Requirements

### Requirement: User can run PR/code review from the desktop

The desktop app SHALL allow the user to run a PR security review on a repository. The user SHALL provide a repository path and a commit range (e.g. base..head) or a “last N commits” option. The app SHALL invoke the PR review backend (via a CLI command or equivalent bridge) and SHALL stream progress and show results when the run completes.

#### Scenario: User starts PR review

- **WHEN** the user has chosen "PR review" mode, entered a valid repo path and commit range (or last N), and triggers the run
- **THEN** the main process SHALL invoke the PR review (e.g. via `promptheus pr-review --path <repo> [--range base..head | --last N]`) and SHALL stream progress or stderr to the UI until the process exits

#### Scenario: User sees PR review progress

- **WHEN** a PR review is running
- **THEN** the app SHALL show a running state (e.g. "Running PR review…") and SHALL display stderr or progress in the log area

### Requirement: PR review results are visible in the app

The desktop app SHALL display the outcome of a PR review after it completes. If the backend provides machine-readable output (e.g. JSON on stdout), the app SHALL parse it and SHALL show findings (e.g. list of issues with severity and description). If not, the app SHALL at least indicate success or failure and MAY offer to open the repo’s `.promptheus/` folder or display a summary from known artifacts (e.g. PR_VULNERABILITIES.json).

#### Scenario: PR review completes with parseable output

- **WHEN** the PR review run exits with code 0 and prints machine-readable results (e.g. JSON) to stdout
- **THEN** the app SHALL parse the output and SHALL display the findings in the results area (e.g. table or list with severity and title)

#### Scenario: PR review fails or times out

- **WHEN** the PR review run exits with non-zero code or does not produce parseable output
- **THEN** the app SHALL show an error or incomplete state and SHALL NOT leave the UI in a permanent loading state

### Requirement: PR review form includes repo path and range

The desktop app SHALL provide a form for PR review that includes a required repository path and a way to specify the diff to review: either a commit range (e.g. base..head) or “last N commits”. The app SHALL pass these to the backend (CLI or bridge) when the user runs a PR review.

#### Scenario: User specifies commit range

- **WHEN** the user enters a repo path and a range such as `main..feature`
- **THEN** the app SHALL pass the range to the PR review backend (e.g. `--range main..feature`) when starting the run

#### Scenario: User specifies last N commits

- **WHEN** the user enters a repo path and selects or enters “last N commits” (e.g. N=5)
- **THEN** the app SHALL pass the corresponding option to the backend (e.g. `--last 5`) when starting the run

### Requirement: PR review is invokable via CLI or bridge

The system SHALL expose PR review in a way the desktop can invoke. Either the Promptheus CLI SHALL provide a command (e.g. `pr-review`) that accepts repo path and range/last-N and calls the existing Scanner.pr_review() logic, or the desktop SHALL use another defined bridge (e.g. a small Python entrypoint) that the packaged app can run. The desktop SHALL NOT implement PR review logic itself; it SHALL only invoke the backend and display results.

#### Scenario: CLI provides pr-review command

- **WHEN** the user runs `promptheus pr-review --path <repo> --range base..head` (or equivalent) from the command line
- **THEN** the CLI SHALL build the diff context, call the scanner’s PR review flow, and SHALL output a result (e.g. findings as JSON or summary to stdout)

#### Scenario: Desktop invokes PR review

- **WHEN** the desktop starts a PR review with repo path and range
- **THEN** the desktop SHALL invoke the same CLI command (or bridge) with the user-provided parameters and SHALL handle stdout/stderr and exit code as for other scan types
