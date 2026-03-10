## Why

PROMPTHEUS today treats all code and all changes equally: full scans and PR reviews use the same depth and budget for every file. That wastes spend on low-risk changes and under-invests in security-critical paths. There is no way to declare intentional design so the reviewer avoids false positives, no cost controls, and the judge is vulnerable to prompt injection from target responses. Implementing the improvements from the exploration will reduce cost, improve signal-to-noise, and harden the pipeline.

## What Changes

- **Judge input sanitization**: Delimit and isolate target response content in the LLM judge prompt so a malicious target cannot inject instructions (addresses THREAT-ASI01-001).
- **Design decisions file**: Introduce `.promptheus/design_decisions.json` (schema: component, decision, accepted_behaviors, invalidation_conditions). Inject matched decisions into code-review and PR-review prompts so the agent does not flag accepted behaviors unless invalidation conditions are met.
- **Cost controls**: Optional per-scan budget (stop when cost exceeds limit), repo size/file-count limits with confirmation for large repos, and optional pre-scan cost estimate.
- **Threat-aware scanning**: Derive `.promptheus/risk_map.json` from `THREAT_MODEL.json` (component → glob → tier). Classify full-scan and PR-review work by tier (critical / moderate / skip). Route critical paths to deeper review (e.g. Opus) and skip tier to no-LLM; moderate gets standard model. Align with `docs/design-threat-aware-incremental-scanning.md` Phases 1–3.
- **PR context and traces**: Semantic or keyword-based retrieval of relevant threats, findings, and design decisions for the changed files in PR review. Record triage decisions in `.promptheus/decisions/` (finding_id, verdict, rationale, mitigated_by). Resurface decisions when `mitigated_by` files change.
- **Fix/remediation agent**: Optional subagent that reads `VULNERABILITIES.json` and writes `.promptheus/FIX_SUGGESTIONS.json` with suggested patches or line-level recommendations (advisory only; no automatic patching).
- **DAST extensibility**: Discover DAST skills from config or a designated directory; support custom CWE→skill mapping (CLI or config) so teams can plug in additional skills without changing core code.
- **Parallel phases**: When both report-generator and DAST are enabled, run them in parallel (both consume `VULNERABILITIES.json`); merge results after both complete.
- **Artifact trust boundary**: In PR review flows, load policy artifacts (e.g. `risk_map.json`, `design_decisions.json`, `THREAT_MODEL.json`) from merge-base or default branch, not from PR head. If the PR modifies these files, treat the PR as critical and review with full rigor.

## Capabilities

### New Capabilities

- `judge-sanitization`: Sanitize and delimit target response content in the judge evaluator prompt to prevent prompt injection from malicious target responses (THREAT-ASI01-001).
- `design-decisions`: Schema and file for design decisions (`.promptheus/design_decisions.json`) and injection of matched decisions into code-review and PR-review prompts to reduce false positives on accepted behaviors.
- `cost-controls`: Per-scan budget limit, repo size/file-count limits with confirmation, and optional pre-scan cost estimate.
- `threat-aware-scanning`: risk_map.json derivation from THREAT_MODEL, tier-based classification (critical/moderate/skip), and model/depth routing for full scan and PR review.
- `pr-context-and-traces`: Semantic or keyword-based context retrieval for PR review (relevant threats, findings, design decisions) and decision traces (record and resurface triage when mitigated_by changes).
- `fix-remediation-agent`: Optional agent that produces FIX_SUGGESTIONS.json from VULNERABILITIES.json (advisory only).
- `dast-extensibility`: DAST skill discovery and configurable CWE→skill mapping.
- `parallel-phases`: Run report-generator and DAST in parallel when both are enabled; merge results.
- `artifact-trust-boundary`: Load .promptheus policy artifacts from merge-base (or default branch) in PR flows; treat PRs that modify policy as critical.

### Modified Capabilities

- None (all new capabilities; no existing openspec specs in repo).

## Impact

- **Affected code**: `promptheus/core/judge/evaluator.py`, `promptheus/config.py`, `promptheus/scanner/scanner.py`, `promptheus/scanner/triage.py`, `promptheus/scanner/pr_review_flow.py`, `promptheus/agents/definitions.py`, `promptheus/prompts/` (orchestration and agent prompts), DAST skill loading and discovery. New modules for risk_map generation, context injection, and decision traces.
- **APIs**: CLI flags for budget, cost estimate, design-decisions path; config keys for cost and DAST skill mapping. No breaking changes to existing CLI contract unless we add required flags (we will use optional flags only).
- **Dependencies**: Optional qmd for semantic context (or fallback to BM25/keyword). No new required runtime dependencies.
- **Artifacts**: New files under `.promptheus/`: `risk_map.json`, `design_decisions.json`, `decisions/*.json`, `FIX_SUGGESTIONS.json` (when fix agent enabled). Existing artifacts unchanged in schema.
