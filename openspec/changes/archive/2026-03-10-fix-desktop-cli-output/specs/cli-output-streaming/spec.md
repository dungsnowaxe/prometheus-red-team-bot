## ADDED Requirements

### Requirement: Capture both stdout and stderr streams
The desktop app SHALL capture and display output from both stdout and stderr streams of the CLI subprocess.

#### Scenario: Agent mode shows progress output
- **WHEN** agent mode scan is running
- **THEN** output from both stdout and stderr SHALL be displayed in the CLI Output window
- **AND** output SHALL be displayed in the order it was produced by the CLI

#### Scenario: URL scan shows all output
- **WHEN** URL scan is running
- **THEN** output from both stdout and stderr SHALL be displayed in the CLI Output window

#### Scenario: PR review shows all output
- **WHEN** PR review is running
- **THEN** output from both stdout and stderr SHALL be displayed in the CLI Output window

### Requirement: Merge output streams sequentially
The system SHALL merge stdout and stderr output into a single log display, preserving temporal order.

#### Scenario: Interleaved output displays correctly
- **WHEN** CLI writes to stdout and stderr in alternating sequence
- **THEN** the log display SHALL show messages in the same sequence they were written
- **AND** no distinction between stdout and stderr SHALL be visually indicated (color, styling)
