## ADDED Requirements

### Requirement: Optional per-scan cost budget

The system SHALL support an optional per-scan cost limit (e.g. via `PROMPTHEUS_MAX_SCAN_COST_USD` or config). After each subagent completes, the scanner SHALL check cumulative cost for the run. If the limit is set and cumulative cost exceeds it, the scanner SHALL stop before starting the next subagent and SHALL report that the budget was exceeded.

#### Scenario: Scan stops when budget exceeded

- **WHEN** a cost limit is set and cumulative cost after the current subagent exceeds that limit
- **THEN** the scanner SHALL not start the next subagent and SHALL exit with a clear message indicating budget exceeded

#### Scenario: No budget set

- **WHEN** no cost limit is configured
- **THEN** the scan SHALL proceed without cost-based stopping

### Requirement: Optional repo size and file-count limits

The system SHALL support optional limits on repository size (e.g. max files or max total size). When limits are set and the repository exceeds them at scan start, the system SHALL either require explicit user confirmation (e.g. `--confirm-large-scan`) or SHALL refuse to start and SHALL explain the limit.

#### Scenario: Large repo requires confirmation when limit set

- **WHEN** file count or repo size limit is set and the repo exceeds it
- **THEN** the scanner SHALL not start unless the user provides confirmation (e.g. CLI flag) or SHALL exit with a message describing the limit and how to confirm

#### Scenario: Repo within limits

- **WHEN** the repo is within configured limits (or no limits are set)
- **THEN** the scan SHALL start without confirmation

### Requirement: Optional pre-scan cost estimate

The system SHALL support an option (e.g. `--estimate-cost`) that produces an estimated cost range for the scan without performing a full scan. The estimate MAY be based on phase count, max_turns, and optionally repository file count or size. The system SHALL NOT call the model API for actual scan work when estimate is requested.

#### Scenario: User requests cost estimate

- **WHEN** the user runs the CLI with the estimate-only flag
- **THEN** the system SHALL output an estimated cost range (or message that estimation is not available) and SHALL NOT run the full scan
