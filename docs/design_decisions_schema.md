# Design decisions schema

Design decisions are stored in `.promptheus/design_decisions.json` and tell the code-review and PR-review agents which behaviors are intentional so they are not flagged as vulnerabilities unless invalidation conditions are met.

## File location

- Default: `<repo>/.promptheus/design_decisions.json`
- Optional override via config (future).

## Schema

The file MUST be a JSON array of decision objects. Each object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier (e.g. `DD-001`). |
| `component` | string | Yes | Component or area (e.g. `gateway/auth`). Used for matching. |
| `decision` | string | Yes | Short description of the decision. |
| `accepted_behaviors` | array of strings | Yes | Behaviors that are intentional; do not report as vulnerabilities. |
| `invalidation_conditions` | array of strings | Yes | When to revisit (e.g. "Introduction of tiered gateway tokens"). |
| `references` | array of strings | No | File paths that this decision applies to. Used for exact matching. |
| `rationale` | string | No | Why this decision was made. |
| `decided_by` | string | No | Person or team. |
| `decided_at` | string | No | Date (e.g. `2026-02-26`). |

## Example

```json
[
  {
    "id": "DD-001",
    "component": "gateway/auth",
    "decision": "Shared gateway token holders are fully trusted operators. Self-declared scopes are preserved for token-authenticated connections.",
    "rationale": "Gateway token is the operator-level shared secret. Restricting scopes for token holders broke headless API workflows (#27494).",
    "references": ["src/gateway/server/ws-connection/message-handler.ts", "src/gateway/server/ws-connection/auth-context.ts"],
    "accepted_behaviors": [
      "Token-authenticated operators retain self-declared scopes",
      "No scope clearing when sharedAuthOk is true"
    ],
    "invalidation_conditions": [
      "Introduction of tiered/scoped gateway tokens with different trust levels",
      "Gateway token shared with untrusted third parties"
    ],
    "decided_by": "kevin-shenghui",
    "decided_at": "2026-02-26"
  }
]
```

## Matching

- **PR review**: Decisions are matched to the diff when any changed file path is in `references` or when the path/component overlaps (e.g. path contains component). Matched decisions are injected into the PR review prompt.
- **Full scan (code-review)**: All decisions from the file are injected into the code-review prompt so the agent can avoid flagging accepted behaviors.

## Prompt instruction

The injected section instructs the agent: do not flag behaviors listed in `accepted_behaviors` as vulnerabilities unless one of `invalidation_conditions` is met.
