# Decision traces schema

Decision traces record triage outcomes for findings so the PR reviewer can avoid re-flagging the same issues and can re-validate when mitigating code changes.

## Location

- Directory: `.promptheus/decisions/`
- Format: one JSON file per finding (e.g. `{finding_id}.json`) or a single `decisions.json` array. This implementation supports loading all `*.json` files from the directory.

## Record schema

Each decision record SHALL include at least:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `finding_id` | string | Yes | Identifier tying to a vulnerability or PR finding (e.g. threat_id, or custom id like `sv-2026-0225-007`). |
| `verdict` | string | Yes | One of: `false_positive`, `accepted_risk`, `mitigated_by`, `deferred`, `fixed`. |
| `rationale` | string | Yes | Why this verdict was chosen. |
| `mitigated_by` | array of strings | No | File paths that implement the mitigation. When any of these files change in a PR, the decision is resurfaced and the reviewer is asked to re-validate that the mitigation still holds. |
| `component` | string | No | Component or area (e.g. `Sandbox/Exec`) for matching to changed files. |
| `decided_by` | string | No | Person or tool. |
| `decided_at` | string | No | Date (e.g. `2026-02-26`). |
| `related_findings` | array of strings | No | Other finding IDs for context. |

## Verdict meanings

- **false_positive**: Not a real vulnerability; do not re-report unless the same pattern appears again.
- **accepted_risk**: Real risk, accepted with rationale; revisit when conditions change.
- **mitigated_by**: Risk exists but compensating controls (listed in `mitigated_by` paths) address it; when those files change, re-validate.
- **deferred**: Will fix later.
- **fixed**: Addressed in code; exclude from prompt when loading (or include only to avoid re-flagging).

## Example

```json
{
  "finding_id": "sv-2026-0225-007",
  "title": "Exec obfuscation detector gaps",
  "component": "Sandbox/Exec",
  "severity": "HIGH",
  "verdict": "accepted_risk",
  "rationale": "Single-variable indirection is low-exploitability because exec allowlist restricts to known binaries.",
  "conditions": "Revisit if exec allowlist implementation changes",
  "mitigated_by": ["src/agents/pi-tools.safe-bins.ts", "src/agents/sandbox-tool-policy.ts"],
  "decided_by": "anshuman",
  "decided_at": "2026-02-26",
  "related_findings": ["sv-2026-0225-004"]
}
```

## Matching for PR context

- Load all decision records from `.promptheus/decisions/` (directory or single file).
- Exclude records with `verdict: "fixed"` when building context (optional; can include to suppress re-finding).
- Include a decision when: (1) any changed file path is in `mitigated_by`, or (2) changed files overlap `component` (path/component match).
- When a decision is included because a changed file is in `mitigated_by`, the prompt SHALL instruct the reviewer to re-validate that the mitigation still holds.
