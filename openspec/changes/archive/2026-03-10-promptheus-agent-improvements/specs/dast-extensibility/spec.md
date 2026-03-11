## ADDED Requirements

### Requirement: Configurable DAST skill directories

The system SHALL support an optional configuration (e.g. config key or env) that specifies one or more directories from which to discover DAST skills in addition to the default (e.g. package `.claude/skills/dast/` or repo `.claude/skills/dast/`). When set, the scanner SHALL discover skills from both the default and the configured directories.

#### Scenario: Additional skill directory configured

- **WHEN** the user configures an extra DAST skills directory
- **THEN** the DAST agent SHALL have access to skills from that directory as well as the default location

#### Scenario: No extra directories

- **WHEN** no extra directories are configured
- **THEN** behavior SHALL remain as today (default discovery only)

### Requirement: Custom CWE to skill mapping

The system SHALL support optional overrides that map CWE IDs to skill names (e.g. CWE-XXX → my-custom-skill). When a vulnerability has a CWE that is not covered by the default skill set but has an override, the DAST agent SHALL use the specified skill for validation if that skill exists.

#### Scenario: Override maps CWE to custom skill

- **WHEN** a vulnerability has cwe_id CWE-123 and the user has configured CWE-123 → my-skill
- **THEN** the DAST phase SHALL attempt to use my-skill for that vulnerability when my-skill is available

#### Scenario: No override

- **WHEN** no override exists for a given CWE
- **THEN** the existing default CWE→skill logic SHALL apply (e.g. built-in skill or UNVALIDATED)
