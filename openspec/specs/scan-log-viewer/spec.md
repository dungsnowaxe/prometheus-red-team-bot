## ADDED Requirements

### Requirement: Terminal-style log panel during scanning
The app SHALL display a terminal-style panel that shows real-time CLI output (stderr) during scanning. The panel SHALL use a dark background with monospace font and auto-scroll to the latest output.

#### Scenario: Log panel appears when scan starts
- **WHEN** the user clicks Run to start a scan
- **THEN** a terminal-style panel appears below the controls showing "Starting scan..."

#### Scenario: Real-time stderr output displayed
- **WHEN** the CLI subprocess emits stderr output during scanning
- **THEN** each line appears in the log panel in real-time with monospace font

#### Scenario: Auto-scroll to bottom
- **WHEN** new log output is appended to the panel
- **THEN** the panel automatically scrolls to show the latest output

#### Scenario: Log panel uses ScrollArea
- **WHEN** the log output exceeds the visible area
- **THEN** the panel uses a shadcn ScrollArea component allowing manual scroll-back through history

### Requirement: Log panel visibility control
The log panel SHALL remain visible after scan completion so users can review the full output. It SHALL clear when a new scan starts.

#### Scenario: Log persists after scan completion
- **WHEN** a scan finishes (success or failure)
- **THEN** the log panel remains visible with all accumulated output

#### Scenario: Log clears on new scan
- **WHEN** the user starts a new scan
- **THEN** the log panel clears all previous output and starts fresh
