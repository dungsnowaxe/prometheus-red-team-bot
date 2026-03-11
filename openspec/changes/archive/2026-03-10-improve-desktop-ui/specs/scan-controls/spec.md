## ADDED Requirements

### Requirement: Cancel button terminates running scan
The Cancel button SHALL be visible and enabled whenever a scan is in progress. Clicking it SHALL immediately terminate the CLI subprocess and reset the UI to an idle state.

#### Scenario: Cancel button visible during scan
- **WHEN** a scan is running
- **THEN** the Cancel button is visible and enabled

#### Scenario: Cancel terminates subprocess
- **WHEN** the user clicks Cancel during a running scan
- **THEN** the CLI subprocess receives SIGTERM and is terminated
- **AND** the UI `running` state is set to false
- **AND** a "Scan cancelled" message is shown in the log panel

#### Scenario: Cancel button hidden when idle
- **WHEN** no scan is running
- **THEN** the Cancel button is not visible

### Requirement: Run button with loading state
The Run button SHALL show a loading indicator while a scan is in progress and SHALL be disabled to prevent duplicate scans.

#### Scenario: Run button disabled during scan
- **WHEN** a scan is in progress
- **THEN** the Run button is disabled and shows a loading spinner or text indicator

#### Scenario: Run button re-enabled after scan
- **WHEN** a scan completes or is cancelled
- **THEN** the Run button is re-enabled and the loading indicator is removed

### Requirement: Scan state management
The app SHALL track scan state (idle, running, completed, cancelled, error) and update all controls accordingly.

#### Scenario: UI reflects idle state
- **WHEN** no scan has been run or previous scan is complete
- **THEN** all inputs are enabled, Run button is enabled, Cancel is hidden

#### Scenario: UI reflects running state
- **WHEN** a scan is in progress
- **THEN** all inputs are disabled, Run button is disabled with loading, Cancel is visible

#### Scenario: UI reflects error state
- **WHEN** a scan exits with non-zero code
- **THEN** the error is displayed with the exit code, inputs are re-enabled, Run button is re-enabled
