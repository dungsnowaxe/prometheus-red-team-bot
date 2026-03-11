## MODIFIED Requirements

### Requirement: Stop output streaming on cancellation
When a scan is cancelled, the system SHALL immediately stop capturing and displaying output from the CLI subprocess.

#### Scenario: No new output after cancel
- **WHEN** a running scan is cancelled via the cancel button
- **THEN** the system SHALL stop appending new output events to the log
- **AND** any output events already in transit SHALL be discarded
- **AND** a cancellation message SHALL be displayed in the log

#### Scenario: Cancel button terminates output listener
- **WHEN** user clicks the cancel button
- **THEN** the output event listener SHALL be marked as inactive
- **AND** subsequent IPC scan-output events SHALL be ignored
- **AND** the scan running state SHALL be set to false

### Requirement: Cancellation message display
When a scan is cancelled, the system SHALL display a clear indication in the log output.

#### Scenario: Cancellation marker in log
- **WHEN** a scan is cancelled
- **THEN** the message "--- Scan cancelled ---" SHALL be appended to the log
- **AND** this message SHALL be the last entry in the log (barring in-transit events)
