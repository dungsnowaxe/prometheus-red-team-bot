## ADDED Requirements

### Requirement: Agent scan must timeout after configured duration
The agent scan MUST terminate after the configured timeout duration (PROMPHEUS_SCAN_TIMEOUT_SECONDS, default 3600s) when waiting for completion messages from the Claude Agent SDK. The scan MUST return a partial result with an error message indicating timeout occurred.

#### Scenario: Timeout occurs during scan
- **WHEN** the agent scan is waiting for completion messages and the configured timeout duration elapses
- **THEN** the scan MUST terminate with asyncio.TimeoutError
- **AND** the system MUST return partial results (if any) with a timeout error message
- **AND** the error message MUST include: elapsed time, tools executed, files processed

#### Scenario: Timeout is configurable
- **WHEN** the PROMPHEUS_SCAN_TIMEOUT_SECONDS environment variable is set
- **THEN** the scan MUST use that value for the timeout duration
- **AND** the default MUST be 3600 seconds (1 hour) when not specified

#### Scenario: Timeout can be disabled
- **WHEN** PROMPHEUS_SCAN_TIMEOUT_SECONDS is set to 0 or None
- **THEN** the scan MUST NOT apply a timeout (infinite wait)

### Requirement: Timeout error message provides actionable guidance
The timeout error message MUST provide the user with information about scan progress and suggest next steps for diagnosis.

#### Scenario: Timeout message includes progress information
- **WHEN** a timeout occurs during agent scan
- **THEN** the error message MUST include: elapsed time, number of tools executed, number of files processed
- **AND** the error message MUST suggest running with --debug flag for more information

#### Scenario: Timeout message distinguishes timeout from other errors
- **WHEN** a scan fails due to timeout
- **THEN** the error message MUST clearly indicate "timeout" as the cause
- **AND** the message MUST be distinguishable from other scan failures (e.g., API errors, permission errors)
