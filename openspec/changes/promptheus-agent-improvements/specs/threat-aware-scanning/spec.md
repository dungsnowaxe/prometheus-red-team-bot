## ADDED Requirements

### Requirement: risk_map.json derived from THREAT_MODEL.json

The system SHALL be able to generate `.promptheus/risk_map.json` from an existing `THREAT_MODEL.json`. The risk map SHALL map severity and affected components to file path globs and SHALL assign each to a tier: critical (Tier 1), moderate (Tier 2), or skip (Tier 3). Generation SHALL run after a full scan that produces THREAT_MODEL.json, or on demand when THREAT_MODEL exists.

#### Scenario: risk_map generated after full scan

- **WHEN** a full scan completes and THREAT_MODEL.json exists
- **THEN** the system SHALL (optionally or by default) generate or update risk_map.json with critical/moderate/skip glob lists derived from threat severity and affected_components

#### Scenario: risk_map used for classification

- **WHEN** PR review or full scan uses threat-aware mode
- **THEN** changed files (or scanned paths) SHALL be matched against risk_map globs and SHALL receive a tier classification (highest tier wins when multiple files)

### Requirement: Tier-based routing for PR review

When threat-aware scanning is enabled for PR review, the system SHALL classify the diff by the highest tier among changed files (using risk_map). Tier 1 (critical) SHALL receive deeper review (e.g. more attempts or higher-capability model). Tier 2 (moderate) SHALL receive standard review. Tier 3 (skip) SHALL receive no LLM review (or minimal). Unmapped files SHALL default to Tier 2.

#### Scenario: Critical file in diff gets Tier 1 treatment

- **WHEN** the diff touches at least one file matching a critical glob in risk_map
- **THEN** the PR review SHALL use Tier 1 settings (e.g. more attempts, longer timeout, or Opus)

#### Scenario: All files in skip tier

- **WHEN** all changed files match only skip patterns in risk_map
- **THEN** the system SHALL skip LLM-based review for that diff (or apply minimal review) and SHALL record the classification

### Requirement: Static skip patterns in risk_map

The risk map SHALL include static skip patterns for known non-security paths (e.g. docs, tests, CI config). Files matching only skip patterns SHALL be classified as Tier 3 (skip).

#### Scenario: Doc-only change classified skip

- **WHEN** the only changed files match risk_map skip patterns (e.g. docs/*, *.test.ts)
- **THEN** the classification SHALL be Tier 3 (skip)
