# FIX_SUGGESTIONS.json Schema

The fix-remediation agent (Phase 6, when enabled via `PROMPTHEUS_FIX_REMEDIATION_ENABLED=true`) writes `.promptheus/FIX_SUGGESTIONS.json`. This file is **advisory only**: the agent does not modify any repository source files.

## Location

- Path: `.promptheus/FIX_SUGGESTIONS.json`
- Created only when the fix-remediation phase is enabled and run.

## Format

A **flat JSON array** of suggestion objects. No wrapper object.

```json
[
  {
    "vulnerability_id": "THREAT-001",
    "file_path": "src/auth.py",
    "recommendation": "Use parameterized queries.",
    "code_snippet_suggestion": "cursor.execute('SELECT ...', (user_id,))",
    "explanation": "Binds user_id as parameter to prevent SQL injection."
  },
  {
    "vulnerability_id": "THREAT-002",
    "file_path": "src/config.py",
    "recommendation": "Set file permissions to 0600 after writing.",
    "explanation": "Restricts config file to owner read/write."
  }
]
```

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `vulnerability_id` | Yes | Matches `threat_id` from VULNERABILITIES.json. |
| `file_path` | Yes | Repository-relative path of the affected file. |
| `recommendation` or `explanation` | At least one | Human-readable fix guidance. |
| `code_snippet_suggestion` | No | Optional example fixed code or patch snippet (short). |

## Advisory only

- The fix-remediation agent has **Read** and **Write** tools; writes are restricted to `.promptheus/` by existing hooks.
- No repository source files are modified. Downstream tools may use FIX_SUGGESTIONS.json for display, IDE hints, or automated patching at the user's discretion.
