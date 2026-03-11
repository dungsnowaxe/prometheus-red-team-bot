# Changelog

All notable changes to PROMPTHEUS will be documented in this file.

## [0.1.0] - 2026-03-12

### Added
- 50 LLM security payloads across 6 attack vectors (prompt injection, tool abuse, multi-turn, memory, identity, infra)
- LLM-as-a-Judge evaluation with Critical/High/Medium/Safe severity classification
- Agent Scan: 6-agent codebase security audit (architecture assessment, threat modeling, code review, report, DAST, fix remediation)
- PR/Commit Review: risk-based security triage for git diffs
- DAST validation: dynamic testing to confirm static findings
- CLI with `scan`, `pr-review`, `init`, `config show` commands
- Multi-provider support: Claude, OpenAI, OpenRouter, Groq, Ollama, GLM, any OpenAI-compatible endpoint
- Desktop App (Electron) with bundled CLI — no Python required
- Streamlit dashboard for visual scan results
- Slack Bot integration with loop breaker
- REST API (FastAPI)
- OWASP Agentic Security Initiative (ASI 2026) threat classification
