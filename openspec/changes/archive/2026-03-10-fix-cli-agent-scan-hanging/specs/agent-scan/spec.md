## ADDED Requirements

### Requirement: Agent scan must detect completion without ResultMessage
The agent scan MUST detect when all expected subagents have completed even if the Claude Agent SDK does not send a ResultMessage. The scan MUST track subagent completion via the SubagentStop hook and MUST exit the message loop when all expected subagents have finished.

#### Scenario: Scan completes via subagent tracking
- **WHEN** all expected subagents (assessment, threat-modeling, code-review, report-generator, optional dast/fix-remediation) have completed
- **THEN** the scan MUST exit the message loop and return results
- **AND** the system MUST NOT wait indefinitely for a ResultMessage

#### Scenario: Expected subagents are tracked correctly
- **WHEN** the scan starts with DAST enabled
- **THEN** the expected subagents MUST include: assessment, threat-modeling, code-review, report-generator, dast
- **AND** when fix-remediation is enabled, expected subagents MUST also include: fix-remediation

#### Scenario: Completion detection works with single subagent mode
- **WHEN** the scan is run with a single subagent (e.g., --single-subagent code-review)
- **THEN** the scan MUST complete when that single subagent finishes
- **AND** completion detection MUST NOT wait for other subagents

### Requirement: Agent scan must provide progress feedback until completion
The agent scan MUST continue to provide real-time progress feedback via the ProgressTracker until completion is detected (either via ResultMessage or subagent tracking).

#### Scenario: Progress updates continue until completion
- **WHEN** the agent scan is running and receiving messages
- **THEN** the system MUST display progress updates (tools executed, files read)
- **AND** progress updates MUST continue until the completion condition is met

#### Scenario: Progress stops cleanly at completion
- **WHEN** completion is detected (via ResultMessage or subagent tracking)
- **THEN** the system MUST print a completion separator ("=" characters)
- **AND** the system MUST proceed to load and return results

### Requirement: Agent scan handles partial results gracefully
When the agent scan terminates due to timeout or completion detection without all artifacts complete, the system MUST handle partial results gracefully.

#### Scenario: Partial results are returned on timeout
- **WHEN** a timeout occurs during agent scan
- **THEN** the system MUST return any available partial results
- **AND** the error message MUST indicate that results may be incomplete

#### Scenario: Missing artifacts are handled
- **WHEN** expected scan artifacts (e.g., VULNERABILITIES.json) are missing after completion
- **THEN** the system MUST raise a clear error indicating which artifacts are missing
- **AND** the error MUST guide the user to check logs or run with --debug
