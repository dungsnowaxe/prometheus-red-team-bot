## ADDED Requirements

### Requirement: Optional fix-remediation subagent

The system SHALL support an optional subagent (e.g. fix-remediation or fix-suggestions) that reads `.promptheus/VULNERABILITIES.json` and produces `.promptheus/FIX_SUGGESTIONS.json` with suggested fixes. The agent SHALL have access only to Read and Write tools and SHALL be allowed to Write only under `.promptheus/`. The agent SHALL NOT modify repository source files.

#### Scenario: Fix agent enabled and run after report phase

- **WHEN** the fix-remediation agent is enabled (config or flag) and the scan runs through report-generator (and optionally DAST)
- **THEN** the orchestrator SHALL invoke the fix-remediation agent once and the agent SHALL write FIX_SUGGESTIONS.json to .promptheus/

#### Scenario: Fix agent disabled

- **WHEN** the fix-remediation agent is not enabled
- **THEN** the agent SHALL NOT be invoked and FIX_SUGGESTIONS.json SHALL NOT be created by the scanner

### Requirement: FIX_SUGGESTIONS.json schema

The fix-remediation agent SHALL produce a JSON artifact that is an array of suggestion objects. Each object SHALL include at least: vulnerability_id (or threat_id), file_path, recommendation or explanation. Each object MAY include code_snippet_suggestion or patch-like content. The format SHALL be documented so downstream tools can consume it.

#### Scenario: Valid FIX_SUGGESTIONS.json written

- **WHEN** the fix-remediation agent completes successfully
- **THEN** the file .promptheus/FIX_SUGGESTIONS.json SHALL exist and SHALL be a valid JSON array; each element SHALL have the required fields

#### Scenario: Advisory only

- **WHEN** the fix-remediation agent runs
- **THEN** the system SHALL NOT apply any changes to repository files; output is advisory only
