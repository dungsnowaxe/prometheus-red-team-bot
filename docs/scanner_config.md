# Scanner configuration and features

This document summarizes scanner-related configuration, CLI flags, and features introduced for cost controls, threat-aware scanning, and artifact trust.

## Cost and size limits

- **`PROMPTHEUS_MAX_SCAN_COST_USD`** — Optional max scan cost in USD. After the run, if exceeded, a warning is logged (scan is not aborted).
- **`PROMPTHEUS_MAX_SCAN_FILES`** — Optional max repository file count. If the repo has more code files than this, the scan fails unless **`--confirm-large-scan`** is passed (or the limit is increased).
- **`PROMPTHEUS_MAX_REPO_MB`** — Optional max repository code size in MB. Same behavior as above when exceeded.
- **`--estimate-cost`** — CLI flag. Prints a cost estimate (phases, turns, file count) and exits without running the scan.
- **`--confirm-large-scan`** — CLI flag. Allows running when file count or repo size exceeds the configured limits.

## Design decisions and decision traces

- **Design decisions** — Optional `.promptheus/design_decisions.json` is loaded and matched to changed/scanned paths; matched entries are injected into the code-review and PR-review prompts to reduce false positives. Schema: [design_decisions_schema.md](design_decisions_schema.md).
- **Decision traces** — Optional `.promptheus/decisions/` (e.g. `decisions.json` or `*.json`) is loaded and matched to changed files for PR review; when a changed file is in a decision’s `mitigated_by`, the reviewer is instructed to re-validate. Schema: [decision_traces_schema.md](decision_traces_schema.md).

## Threat-aware scanning (risk map)

- After a full scan, if `.promptheus/THREAT_MODEL.json` exists, the scanner generates `.promptheus/risk_map.json` (critical/moderate/skip tiers from severity and affected components).
- **PR review** uses the risk map to classify the diff:
  - **Tier 1 (critical)** — Deeper review (higher attempts/timeout).
  - **Tier 2 (moderate)** — Standard review.
  - **Tier 3 (skip)** — No LLM review (0 attempts).
- Unmapped files default to Tier 2. Design: [design-threat-aware-incremental-scanning.md](design-threat-aware-incremental-scanning.md).

## Fix-remediation agent (Phase 6)

- **`PROMPTHEUS_FIX_REMEDIATION_ENABLED`** — Set to `true` (or `1`/`yes`) to run the fix-remediation agent after report (and DAST). The agent reads `VULNERABILITIES.json` and writes `.promptheus/FIX_SUGGESTIONS.json` (advisory only; it does not modify repo files). Schema: [fix_suggestions_schema.md](fix_suggestions_schema.md).

## DAST extensibility

- **`PROMPTHEUS_DAST_SKILLS_DIRS`** — Comma-separated paths to additional DAST skill directories. Skills from these dirs are merged with the default package skills under `.claude/skills/dast/`.
- **`PROMPTHEUS_DAST_CWE_SKILL_OVERRIDES`** — JSON object mapping CWE IDs to skill names (e.g. `{"CWE-123":"my-skill"}`). When a vulnerability has a CWE in this map, the DAST phase uses the specified skill if available.

## Artifact trust boundary (PR review)

- In PR review, policy artifacts (**risk_map.json**, **design_decisions.json**, **THREAT_MODEL.json**) are loaded from the **merge-base** of the current branch (e.g. `origin/main`) via `git show <ref>:.promptheus/<file>`, so the PR cannot lower the review bar by changing policy in the working tree. If the repo is not a git repo or merge-base is unavailable, the scanner falls back to the working tree and logs a warning.
- If the PR **adds or modifies** any of these policy files under `.promptheus/`, the PR is classified as **Tier 1 (critical)** regardless of other changed files.

## Judge (target response delimiter and truncation)

- The judge wraps the target response in `<target_response>...</target_response>` and instructs the model to treat only that block as the target response.
- **`PROMPTHEUS_JUDGE_MAX_RESPONSE_CHARS`** — Optional max length (characters) for the target response; if exceeded, the response is truncated and `[truncated]` is appended.
