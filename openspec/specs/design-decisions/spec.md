## ADDED Requirements

### Requirement: Design decisions file schema

The system SHALL support a design decisions file at `.promptheus/design_decisions.json` (or a path configured by the user). Each entry SHALL include at least: `id`, `component`, `decision`, `accepted_behaviors` (array of strings), `invalidation_conditions` (array of strings). Entries MAY include `references` (file paths), `rationale`, `decided_by`, `decided_at`.

#### Scenario: Valid design decisions file is loaded

- **WHEN** the file exists and contains valid JSON array of objects with required fields
- **THEN** the system SHALL load and use it for matching and prompt injection

#### Scenario: Missing or invalid file

- **WHEN** the file is missing or JSON is invalid
- **THEN** the system SHALL proceed without design decisions (no failure); no design decisions section is injected

### Requirement: Design decisions injected into code-review and PR-review prompts

When running code-review or PR-review, the system SHALL match design decision entries to the code under review by exact path/component (e.g. changed files or scanned paths). Matched entries SHALL be injected into a "Design decisions" section of the agent prompt. The prompt SHALL instruct the agent not to flag behaviors listed in `accepted_behaviors` unless one of `invalidation_conditions` is met.

#### Scenario: Matched decision is injected for PR review

- **WHEN** a PR touches a file that appears in a design decision's `references` or matches its `component`
- **THEN** that decision's text (decision, accepted_behaviors, invalidation_conditions) SHALL appear in the PR review prompt and the agent SHALL be told not to report accepted behaviors as vulnerabilities unless invalidation conditions apply

#### Scenario: No match

- **WHEN** no design decision matches the changed or scanned paths
- **THEN** no design decisions section is added to the prompt
