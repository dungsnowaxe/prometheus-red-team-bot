## Context

PROMPTHEUS uses the Claude Agent SDK with sequential subagents (assessment → threat-modeling → code-review → report-generator → optional DAST). Artifacts live under `.promptheus/`. PR review uses triage (security_relevant vs low_risk) to reduce attempts/timeout but does not route by file risk tier. The design doc `docs/design-threat-aware-incremental-scanning.md` describes risk_map, design decisions, and qmd-based context injection but is not yet implemented. The judge evaluator interpolates target response directly into the user prompt, and there are no cost caps or fix-suggestion agents.

## Goals / Non-Goals

**Goals:**

- Harden the judge against prompt injection from target responses.
- Reduce false positives via design decisions and decision traces.
- Add cost controls and optional cost estimation.
- Introduce threat-aware tiering (risk_map, critical/moderate/skip) for full scan and PR review.
- Improve PR context with semantic or keyword-based retrieval and decision traces.
- Add an optional fix/remediation agent and DAST skill extensibility.
- Run report-generator and DAST in parallel when both are enabled.
- Load policy artifacts from merge-base in PR flows.

**Non-Goals:**

- Implementing full qmd integration in the first slice (fallback to keyword/BM25 is acceptable).
- Changing existing artifact schemas (VULNERABILITIES.json, THREAT_MODEL.json) beyond additive fields.
- Automatic application of fix suggestions (advisory only).
- Breaking existing CLI defaults (all new behavior behind flags or config).

## Decisions

### Judge sanitization

- **Decision**: Wrap target response in explicit XML-style delimiters in the judge user message and instruct the judge to treat only the content between delimiters as the target response. Optionally truncate response to a max length (e.g. 16KB) before interpolation.
- **Rationale**: Delimiters are simple, model-visible, and avoid regex-based stripping that might break legitimate content. Truncation limits damage from huge injected payloads.
- **Alternatives**: Separate API call with response in a dedicated field (bigger change); escaping special tokens (provider-dependent and brittle).

### Design decisions schema and matching

- **Decision**: Single file `.promptheus/design_decisions.json`: array of objects with `id`, `component`, `decision`, `rationale`, `references` (file paths), `accepted_behaviors`, `invalidation_conditions`, optional `decided_by`, `decided_at`. Matching: exact path/component match against changed files (PR) or scanned paths (full scan); optional later: qmd/BM25 for semantic match. Inject a "Design decisions" section into code-review and PR-review prompts with matched entries and instruction: do not flag accepted behaviors unless invalidation_conditions are met.
- **Rationale**: Keeps schema in one place; references enable exact matching without extra tooling. Optional semantic match can be added in pr-context-and-traces.
- **Alternatives**: Per-component files; storing in THREAT_MODEL (mixes threats with intent).

### Cost controls

- **Decision**: (1) Optional env/config `PROMPTHEUS_MAX_SCAN_COST_USD`; scanner checks cumulative cost after each subagent and stops before starting the next if over limit. (2) Optional `PROMPTHEUS_MAX_FILES` / `PROMPTHEUS_MAX_REPO_MB`; at scan start, count files and optionally size; if over limit, warn and require explicit confirmation (e.g. `--confirm-large-scan`) or fail. (3) Optional `--estimate-cost` CLI flag: run a dry run (e.g. count phases and max_turns, optionally sample file count) and print an estimated cost range without calling the API.
- **Rationale**: Budget and size limits prevent runaway cost; estimate helps users decide before running.
- **Alternatives**: Per-phase budget (finer but more complex); mandatory limits (breaking; we keep optional).

### Risk map and tiering

- **Decision**: After a full scan (or when THREAT_MODEL.json exists), generate `.promptheus/risk_map.json` from THREAT_MODEL: for each threat, take `affected_components` and `severity`; resolve components to file paths via grep/AST or directory heuristics; map severity to tier (critical/high → Tier 1, medium → Tier 2, low → Tier 2 or skip); add static skip patterns (docs, tests, CI). risk_map format: `{ "critical": ["glob*"], "moderate": ["..."], "skip": ["..."] }`. Full scan: tier influences which model/depth (e.g. Tier 1 → Opus, Tier 2 → Sonnet); implementation can start with “single model” and tier only affecting PR review. PR review: classify changed files by risk_map; highest tier in the diff drives attempts/timeout and whether to inject extra context (see context injection).
- **Rationale**: Aligns with design doc; glob-based triage is fast and deterministic.
- **Alternatives**: LLM-based tiering (costly and non-deterministic); no full-scan tiering in v1 (only PR).

### PR context and decision traces

- **Decision**: (1) Context injection: in PR review prompt assembly, besides existing threat/vuln summaries, add a section “Relevant design decisions” (from design_decisions.json matched by path/component) and “Relevant decision traces” (from `.promptheus/decisions/*.json` where component/path overlaps changed files, excluding verdict `fixed`). Optionally use qmd or a simple keyword/BM25 search over THREAT_MODEL and VULNERABILITIES to pull in relevant threats/findings by text similarity to changed file paths or content; if qmd unavailable, use path/component and threat_id only. (2) Decision traces: when a human (or future tool) triages a finding, write a record to `.promptheus/decisions/<id>.json` with finding_id, verdict (false_positive, accepted_risk, mitigated_by, deferred, fixed), rationale, mitigated_by (file paths), decided_at. When building PR context, if any changed file is in a decision’s mitigated_by, include that decision and instruct the reviewer to re-validate that the mitigation still holds.
- **Rationale**: Design decisions and traces reduce repeat false positives and preserve institutional knowledge; resurfacing when mitigated_by changes avoids stale “accepted” state.
- **Alternatives**: qmd-only (adds dependency); no decision traces in v1 (only design decisions).

### Fix/remediation agent

- **Decision**: New optional subagent `fix-remediation` (or `fix-suggestions`): definition in agents/definitions.py; prompt: read VULNERABILITIES.json, for each item suggest a fix (patch snippet or line-level recommendation), write `.promptheus/FIX_SUGGESTIONS.json`. No Write tool to repo source; only Write to `.promptheus/`. Orchestration prompt: after report-generator (and optionally after DAST), if enabled via config/flag, invoke fix-remediation once. Output schema: array of { vulnerability_id, file_path, recommendation, code_snippet_suggestion, explanation }.
- **Rationale**: Keeps fixes advisory and avoids touching user code; single phase keeps orchestration simple.
- **Alternatives**: Agent that patches files (rejected: too risky); separate CLI command only (still valid as follow-up).

### DAST extensibility

- **Decision**: (1) Skill discovery: keep discovering skills from `.claude/skills/dast/` (or package default); add optional config key `dast_skills_dirs` (list of paths) so users can add more directories. (2) CWE→skill mapping: today mapping is implicit from skill metadata; add optional config/CLI `dast_cwe_skill_overrides` (e.g. CWE-XXX → skill_name) so a custom skill can be used for a CWE that currently has no built-in skill.
- **Rationale**: Minimal change to existing DAST flow; overrides allow custom skills without forking.
- **Alternatives**: Full plugin API (overkill for now).

### Parallel report-generator and DAST

- **Decision**: When both report-generator and DAST are enabled, start both after code-review completes (both consume VULNERABILITIES.json). Use asyncio.gather or equivalent; wait for both to finish; then merge DAST results into scan result (existing merge logic). Orchestration prompt stays sequential for assessment → threat-modeling → code-review; after code-review, “Phase 4a: report-generator” and “Phase 4b: DAST” can be described as parallel in the design; implementation uses two Task invocations in parallel (or one orchestrator turn that schedules both and waits).
- **Rationale**: Saves wall-clock time; no artifact conflict since they write different files.
- **Alternatives**: Keep sequential (simpler but slower).

### Artifact trust boundary

- **Decision**: In PR review, when loading `risk_map.json`, `design_decisions.json`, `THREAT_MODEL.json`, and (if present) `VULNERABILITIES.json` for context, read from the merge-base (or configured default branch) via `git show <merge-base>:.promptheus/<file>`, not from the working tree. If the PR adds or modifies any of these policy files under `.promptheus/`, classify the PR as critical (e.g. Tier 1) regardless of other files, so the full review depth applies.
- **Rationale**: Prevents a PR from lowering the bar by editing policy; merge-base is the standard “approved” state.
- **Alternatives**: Always use default branch (simpler but may miss recent baseline); no special handling for policy-file changes (weaker security).

## Risks / Trade-offs

- **Risk**: risk_map derivation from THREAT_MODEL may produce coarse or wrong path globs (e.g. component names not resolving to paths). **Mitigation**: Document resolution heuristics; allow manual override file (e.g. risk_map.overrides.json) merged after generation; start with conservative “unmapped → Tier 2”.
- **Risk**: Design decisions and traces add prompt length. **Mitigation**: Cap number of injected decisions/traces (e.g. top 10 by relevance); truncate long text.
- **Risk**: Parallel DAST + report-generator could double peak resource use. **Mitigation**: Both are I/O and API bound; acceptable for typical usage; document for very large repos.
- **Risk**: Loading from merge-base requires git; fails in non-repo or shallow clone. **Mitigation**: Fallback to working tree when git merge-base unavailable; log warning.

## Migration Plan

1. **Deploy**: Ship behind feature flags or optional config (e.g. `PROMPTHEUS_THREAT_AWARE_SCAN=1`, `PROMPTHEUS_DESIGN_DECISIONS_PATH`, etc.). Defaults preserve current behavior.
2. **Rollback**: Disable flags or remove config; scanner behaves as today. New artifacts (risk_map, design_decisions, decisions/) are optional; their absence does not break existing scans.
3. **Docs**: Update README and docs/ for new flags, design_decisions schema, and decision trace format. Add a short “Threat-aware scanning” section pointing to design-threat-aware-incremental-scanning.md.

## Open Questions

- Whether to ship qmd-based semantic context in the first release or only path/component/keyword fallback.
- Exact format of FIX_SUGGESTIONS.json (patch vs line-level) and whether to align with an existing patch format (e.g. unified diff snippet) for downstream tooling.
