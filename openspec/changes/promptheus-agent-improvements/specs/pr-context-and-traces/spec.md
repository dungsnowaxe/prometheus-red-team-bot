## ADDED Requirements

### Requirement: Decision traces stored in .promptheus/decisions/

The system SHALL support storing triage decision records under `.promptheus/decisions/` (e.g. one JSON file per finding or aggregated). Each record SHALL include at least: finding_id, verdict (e.g. false_positive, accepted_risk, mitigated_by, fixed), rationale, and when applicable mitigated_by (list of file paths). The system SHALL allow these records to be created by a human or future tool (e.g. CLI or API).

#### Scenario: Decision record is written

- **WHEN** a triage decision is recorded (e.g. via CLI or future integration)
- **THEN** a record SHALL be written under .promptheus/decisions/ with the required fields

#### Scenario: Decisions loaded for PR context

- **WHEN** building PR review context and decision trace files exist
- **THEN** the system SHALL load decisions whose component or mitigated_by paths overlap the changed files and SHALL inject relevant traces into the prompt (excluding verdict fixed where specified)

### Requirement: Decision traces resurfaced when mitigated_by files change

When preparing PR review context, if any changed file appears in a decision record's `mitigated_by` list, that decision SHALL be included in the context and the prompt SHALL instruct the reviewer to re-validate that the mitigation still holds.

#### Scenario: Changed file is in mitigated_by

- **WHEN** the PR diff modifies a file that is listed in a decision's mitigated_by
- **THEN** that decision SHALL be injected into the PR review prompt with an instruction to re-check the mitigation

### Requirement: Relevant threats and findings for PR context

The system SHALL inject into the PR review prompt relevant threats (from THREAT_MODEL.json) and relevant findings (from VULNERABILITIES.json) that relate to the changed files. Matching MAY be by exact path/component or by keyword/semantic search (e.g. BM25 or qmd when available). The system SHALL cap the amount of injected context to avoid oversized prompts.

#### Scenario: Relevant threat injected

- **WHEN** a threat's affected_components or references match the changed files (by path or keyword)
- **THEN** a summary of that threat SHALL be included in the "Relevant threats" section of the PR review prompt

#### Scenario: Context cap applied

- **WHEN** the set of matched threats and findings is large
- **THEN** the system SHALL limit the number or size of injected items (e.g. top N by relevance) so the prompt size remains bounded
