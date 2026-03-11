## ADDED Requirements

### Requirement: CLI path configuration

The desktop app SHALL use a bundled Promptheus CLI executable by default. The desktop app SHALL allow the user to optionally set and persist an override path to a Promptheus CLI executable (e.g. for development or debugging). If an override is not set, the app SHALL invoke the bundled executable. The app SHALL persist the override value across restarts using app-specific storage.

#### Scenario: User sets CLI path

- **WHEN** the user opens settings and enters an override CLI path (or clears it to use the bundled CLI)
- **THEN** the app SHALL save the value and use it when spawning the CLI for scans

#### Scenario: User restarts app

- **WHEN** the user closes and reopens the desktop app
- **THEN** the app SHALL load the last saved override CLI path (or default to the bundled CLI) and use it for scan invocations

### Requirement: Run scan via CLI from main process

The desktop app SHALL run a red-team scan by invoking the Promptheus CLI from the Electron main process (e.g. subprocess spawn with `promptheus scan --target-url <url>` and any machine-readable output flag). The main process SHALL capture stdout, stderr, and exit code and SHALL communicate progress and results to the renderer via IPC.

#### Scenario: User starts a scan

- **WHEN** the user enters a valid target URL and triggers "Run scan"
- **THEN** the main process SHALL spawn the CLI with the target URL and SHALL send progress or status to the renderer (e.g. "Running…") until the process exits

#### Scenario: Scan completes successfully

- **WHEN** the CLI exits with code 0 and produces machine-readable output (e.g. JSON on stdout)
- **THEN** the main process SHALL parse the output and SHALL send the results to the renderer; the renderer SHALL display them (e.g. payload_id, name, vulnerable, severity, reasoning) in a readable list or table

#### Scenario: Scan fails

- **WHEN** the CLI exits with non-zero code or produces no parseable output
- **THEN** the app SHALL show an error message to the user (e.g. stderr or "Scan failed") and SHALL NOT leave the UI in a permanent loading state

### Requirement: Single main window and settings

The desktop app SHALL provide a single main window that includes: an optional settings area (CLI path), a form to enter target URL and run a scan, and an area to view scan results. The app SHALL NOT require multiple windows for core usage.

#### Scenario: User opens settings

- **WHEN** the user opens the settings or preferences section
- **THEN** the user SHALL be able to view and edit the CLI path (or clear it to use PATH)

#### Scenario: User runs a scan and sees results

- **WHEN** the user has entered a target URL and started a scan
- **THEN** the app SHALL show progress until the CLI exits and SHALL display the returned results in the same window
