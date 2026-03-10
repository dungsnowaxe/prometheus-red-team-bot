## ADDED Requirements

### Requirement: Policy artifacts loaded from merge-base in PR review

When running PR review, the system SHALL load policy artifacts (risk_map.json, design_decisions.json, THREAT_MODEL.json, and when used for context VULNERABILITIES.json) from the git merge-base of the PR (or from the configured default branch) rather than from the working tree. Loading SHALL use git show <ref>:.promptheus/<file> (or equivalent) so that the PR cannot change policy to lower the review bar.

#### Scenario: Policy read from merge-base

- **WHEN** PR review runs and policy artifacts are needed
- **THEN** the system SHALL read .promptheus/risk_map.json, design_decisions.json, THREAT_MODEL.json (and VULNERABILITIES.json if used) from the merge-base commit (or default branch) and SHALL NOT use the working-tree versions of these files

#### Scenario: Not a git repo or merge-base unavailable

- **WHEN** the repository is not a git repo or merge-base cannot be determined
- **THEN** the system SHALL fall back to reading from the working tree and SHALL log a warning

### Requirement: PRs that modify policy files treated as critical

When the PR diff adds or modifies any file under .promptheus/ that is considered a policy artifact (e.g. risk_map.json, design_decisions.json, THREAT_MODEL.json), the system SHALL classify the PR as critical (Tier 1) regardless of other changed files, so that full review depth and rigor apply.

#### Scenario: PR modifies design_decisions.json

- **WHEN** the PR diff includes changes to .promptheus/design_decisions.json (or other listed policy files)
- **THEN** the PR SHALL be classified as Tier 1 (critical) and SHALL receive the same deep review as other critical changes

#### Scenario: PR does not touch policy files

- **WHEN** the PR diff does not add or modify any policy artifact under .promptheus/
- **THEN** tier SHALL be determined only by risk_map and other normal classification rules
