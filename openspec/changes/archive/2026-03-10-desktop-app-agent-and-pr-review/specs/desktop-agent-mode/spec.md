## ADDED Requirements

### Requirement: User can run agent-mode scan from the desktop

The desktop app SHALL allow the user to select or enter a repository path and start an agent-mode scan (full codebase vulnerability scan). The app SHALL invoke the bundled Promptheus CLI (or configured override) with arguments equivalent to `scan --mode agent --target-path <path>` and SHALL support optional flags for model, DAST, and large-scan confirmation when the CLI supports them.

#### Scenario: User starts agent scan

- **WHEN** the user has chosen "Agent scan" mode, entered a valid repo path, and triggers the run
- **THEN** the main process SHALL spawn the CLI with `--mode agent --target-path <path>` and SHALL stream progress or stderr to the UI until the process exits

#### Scenario: User sees agent scan progress

- **WHEN** an agent scan is running
- **THEN** the app SHALL show a running state (e.g. "Running agent scan…") and SHALL display stderr or progress output in the log area so the user can see activity

### Requirement: Agent scan results are visible in the app

The desktop app SHALL display the outcome of an agent-mode scan after it completes. If the CLI provides machine-readable output (e.g. JSON on stdout), the app SHALL parse it and SHALL show a summary or list of findings (e.g. vulnerabilities, severity). If the CLI does not provide such output, the app SHALL at least indicate success or failure and MAY offer to open the repo’s `.promptheus/` folder or display a summary read from known artifact files.

#### Scenario: Agent scan completes with parseable output

- **WHEN** the CLI exits with code 0 and prints machine-readable results (e.g. JSON) to stdout
- **THEN** the app SHALL parse the output and SHALL display the results (e.g. vulnerabilities table or summary) in the results area

#### Scenario: Agent scan completes without parseable stdout

- **WHEN** the CLI exits with code 0 but does not produce machine-readable stdout
- **THEN** the app SHALL show a success state and SHALL NOT leave the UI in a permanent loading state; it MAY show a message such as "Scan complete. Open the repo’s .promptheus/ folder for reports."

### Requirement: Agent scan form includes path and optional options

The desktop app SHALL provide a form for agent mode that includes a required repository path input and, when supported by the CLI, optional controls for model, DAST enablement, DAST URL, and large-scan confirmation. The app SHALL pass these options to the CLI when the user runs a scan.

#### Scenario: User sets optional agent options

- **WHEN** the user fills the agent form with repo path and optional model or DAST settings
- **THEN** the app SHALL pass the corresponding CLI flags (e.g. `--model`, `--dast`, `--dast-url`, `--confirm-large-scan`) when spawning the scan
