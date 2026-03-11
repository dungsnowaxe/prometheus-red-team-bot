## ADDED Requirements

### Requirement: Smart auto-scroll behavior
The log viewer SHALL automatically scroll to the bottom when new output arrives only if the user is already viewing the bottom of the log.

#### Scenario: Auto-scroll when at bottom
- **WHEN** user is viewing the bottom of the log (within 50px threshold)
- **AND** new output arrives
- **THEN** the log viewer SHALL automatically scroll to the bottom
- **AND** the user SHALL see the latest output

#### Scenario: No auto-scroll when scrolled up
- **WHEN** user has manually scrolled up to view earlier log content
- **AND** new output arrives
- **THEN** the log viewer SHALL NOT automatically scroll
- **AND** the user SHALL remain at their current scroll position
- **AND** new output SHALL be added to the log but not immediately visible

#### Scenario: Resume auto-scroll after scrolling to bottom
- **WHEN** user has scrolled up to view earlier content
- **AND** user scrolls back to the bottom of the log
- **AND** new output arrives
- **THEN** the log viewer SHALL resume auto-scrolling to the bottom

### Requirement: Scroll position tolerance
The system SHALL consider the user to be "at the bottom" of the log when within 50 pixels of the bottom edge.

#### Scenario: Near-bottom counts as at bottom
- **WHEN** user is within 50 pixels of the log bottom
- **AND** new output arrives
- **THEN** auto-scroll SHALL be triggered
