## 1. Judge sanitization

- [x] 1.1 Add delimiters (e.g. `<target_response>...</target_response>`) around target response in judge user message in `promptheus/core/judge/evaluator.py`
- [x] 1.2 Update judge system prompt to instruct model to treat only delimited content as target response
- [x] 1.3 Add optional config/env for max target response length and truncate + append "[truncated]" when exceeded

## 2. Design decisions

- [x] 2.1 Define and document schema for `.promptheus/design_decisions.json` (id, component, decision, accepted_behaviors, invalidation_conditions, references, etc.)
- [x] 2.2 Add loader for design_decisions.json with safe fallback when file missing or invalid
- [x] 2.3 Implement matching logic (path/component) for design decisions against changed or scanned paths
- [x] 2.4 Inject "Design decisions" section into code-review and PR-review prompt assembly with matched entries and instruction not to flag accepted behaviors unless invalidation conditions met

## 3. Cost controls

- [x] 3.1 Add optional `PROMPTHEUS_MAX_SCAN_COST_USD` (and config) and check cumulative cost after each subagent; stop and report when exceeded
- [x] 3.2 Add optional repo size/file-count limits and require `--confirm-large-scan` (or fail) when repo exceeds limits
- [x] 3.3 Add `--estimate-cost` CLI flag that outputs cost estimate without running full scan (e.g. phase count, max_turns, optional file count)

## 4. Threat-aware scanning – risk_map

- [x] 4.1 Implement risk_map generation from THREAT_MODEL.json (severity + affected_components → globs, tiers: critical/moderate/skip; add static skip patterns)
- [x] 4.2 Wire risk_map generation to run after full scan when THREAT_MODEL exists (optional or default)
- [x] 4.3 Add file-to-tier classification using risk_map globs (highest tier wins per diff or per scan)

## 5. Threat-aware scanning – PR tiering

- [x] 5.1 In PR review, classify changed files using risk_map; set tier (Tier 1/2/3) for the diff
- [x] 5.2 Route PR review by tier: Tier 1 → deeper review (e.g. more attempts or Opus), Tier 2 → standard, Tier 3 → skip or minimal
- [x] 5.3 Unmapped files default to Tier 2; document behavior

## 6. PR context and decision traces

- [x] 6.1 Define schema for decision trace records under `.promptheus/decisions/` (finding_id, verdict, rationale, mitigated_by, etc.)
- [x] 6.2 Add loading of decision traces and filter by path/component overlap with changed files; inject "Decision traces" section into PR prompt
- [x] 6.3 When any changed file is in a decision's mitigated_by, include that decision and instruct reviewer to re-validate mitigation
- [x] 6.4 Add relevant threats/findings injection (path/component or keyword/BM25) with cap on injected size; integrate with existing threat/vuln summary

## 7. Fix-remediation agent

- [x] 7.1 Add fix-remediation (or fix-suggestions) agent definition in `promptheus/agents/definitions.py` (Read, Write to .promptheus only)
- [x] 7.2 Add prompt that reads VULNERABILITIES.json and produces FIX_SUGGESTIONS.json (schema: vulnerability_id, file_path, recommendation, optional code_snippet_suggestion, explanation)
- [x] 7.3 Add orchestration phase (after report-generator/DAST) to invoke fix-remediation when enabled via config/flag
- [x] 7.4 Document FIX_SUGGESTIONS.json format and that output is advisory only

## 8. DAST extensibility

- [x] 8.1 Add optional config (e.g. `dast_skills_dirs`) for additional DAST skill directories; discover skills from default + configured dirs
- [x] 8.2 Add optional CWE→skill overrides (config or CLI); DAST phase uses override when present and skill exists

## 9. Parallel phases

- [x] 9.1 After code-review, when both report-generator and DAST are enabled, start both in parallel (e.g. asyncio.gather or equivalent)
- [x] 9.2 Wait for both to complete; merge DAST results into scan result using existing merge logic
- [x] 9.3 Update orchestration prompt/docs to describe parallel report + DAST where applicable

## 10. Artifact trust boundary

- [x] 10.1 In PR review flow, load risk_map.json, design_decisions.json, THREAT_MODEL.json (and VULNERABILITIES.json when used for context) from merge-base via `git show <merge-base>:.promptheus/<file>`
- [x] 10.2 Fallback to working tree when not a git repo or merge-base unavailable; log warning
- [x] 10.3 If PR diff adds or modifies any policy file under .promptheus/, classify PR as Tier 1 (critical) regardless of other files

## 11. Documentation and tests

- [x] 11.1 Update README and docs for new flags (budget, estimate-cost, confirm-large-scan), design_decisions schema, decision traces, and threat-aware scanning
- [x] 11.2 Add tests for judge delimiter and truncation behavior
- [x] 11.3 Add tests for risk_map generation and tier classification
- [x] 11.4 Add tests for artifact trust boundary (load from merge-base; PR modifying policy → Tier 1)
