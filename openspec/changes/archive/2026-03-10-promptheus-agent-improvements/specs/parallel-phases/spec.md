## ADDED Requirements

### Requirement: Report-generator and DAST run in parallel when both enabled

When both report-generator and DAST are enabled for a scan (e.g. full scan with --target-url), the system SHALL run the report-generator and DAST phases in parallel after the code-review phase completes. Both phases consume VULNERABILITIES.json; neither depends on the other's output. The system SHALL wait for both to complete before merging results and finishing the scan.

#### Scenario: Both phases enabled

- **WHEN** the user runs a full scan with DAST enabled (e.g. --target-url set) and report-generator is in the pipeline
- **THEN** after code-review completes, report-generator and DAST SHALL be started in parallel; the scan SHALL complete only after both have finished

#### Scenario: Only one phase enabled

- **WHEN** DAST is not enabled (e.g. no --target-url) or report-generator is skipped
- **THEN** the remaining phase SHALL run as today (no parallel execution required)

### Requirement: Results merged after parallel completion

After both report-generator and DAST complete, the system SHALL merge DAST validation results into the scan result (e.g. scan_results.json or in-memory ScanResult) using the same merge logic as today. The final output SHALL include both report data and DAST validation data where applicable.

#### Scenario: Merge after parallel run

- **WHEN** report-generator and DAST have both finished
- **THEN** the scanner SHALL produce a single ScanResult that includes report-generator output and DAST_VALIDATION.json data (or equivalent) so CLI and API behavior is unchanged
