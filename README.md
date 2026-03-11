<div align="center">

# PROMPTHEUS

**Proactive Red-team Operator for Model PenTesting & Heuristic Exploit Utility System**

*Steals fire from the gods. LLM red-team security auditing.*

[![PyPI version](https://img.shields.io/pypi/v/promptheus.svg)](https://pypi.org/project/promptheus/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/dungsnowaxe/prometheus-red-team-bot/actions/workflows/release.yml/badge.svg)](https://github.com/dungsnowaxe/prometheus-red-team-bot/actions)

</div>

---

AI agents are being given more power every day — calling tools, reading files, sending emails, executing code. Traditional security testing wasn't designed to find LLM-specific vulnerabilities: prompt injection, goal hijacking, tool abuse, memory poisoning.

**PROMPTHEUS fills that gap.**

---

## Install

### Option A — pip (requires Python 3.10+)

```bash
pip install promptheus
promptheus init   # first-run setup wizard
```

To upgrade later:
```bash
pip install --upgrade promptheus
```

### Option B — Binary download (no Python required)

Download the latest release for your platform from the [Releases page](https://github.com/dungsnowaxe/prometheus-red-team-bot/releases):

| Platform | File |
|----------|------|
| macOS | `promptheus-macos` |
| Windows | `promptheus-windows.exe` |
| Linux | `promptheus-linux` |

**macOS/Linux:** Make executable and run:
```bash
chmod +x promptheus-macos
./promptheus-macos init
```

**Windows:** Run from PowerShell:
```powershell
.\promptheus-windows.exe init
```

---

## Quick Start

```bash
# First-time setup (choose your AI provider + enter API key)
promptheus init

# Scan an AI API endpoint
promptheus scan -u https://your-ai-app.com/chat

# Audit a codebase with AI agents
promptheus scan --mode agent --target-path /path/to/repo

# Review security of recent commits
promptheus pr-review --path /path/to/repo --last 5
```

No API key? Run without one — Judge defaults to Mock mode (always returns Safe), useful for testing the pipeline.

---

## What it does

### Payload Attack Engine

50 security payloads across 6 attack vectors:

| Vector | Examples |
|--------|---------|
| **Prompt injection** | Direct override, Base64, YAML, sandwich, translation trap |
| **Tool abuse** | Shell exec, file read/write, SSRF, API key generation, privilege escalation |
| **Multi-turn attacks** | Conditional trigger, deferred execution, implicit consent |
| **Memory attacks** | Cross-session exfiltration and poisoning |
| **Identity & auth** | System prompt extraction, developer prompt leak, approval bypass |
| **Infra attacks** | Denial of Wallet, unsafe code execution, lazy error handling |

Each payload includes a `judge_expectation` rubric — the LLM Judge classifies results as `Critical`, `High`, `Medium`, or `Safe`.

### Agent Scan — Full Codebase Security Audit

6 AI agents analyze your codebase:

| Agent | Output |
|-------|--------|
| Architecture Assessment | `SECURITY.md` |
| Threat Modeling (OWASP ASI 2026) | `THREAT_MODEL.json` |
| Code Review | `VULNERABILITIES.json` |
| Report Generator | `scan_results.json` |
| DAST Validation *(optional)* | `DAST_VALIDATION.json` |
| Fix Remediation *(optional)* | Inline suggestions |

### PR / Commit Review

Risk-based security triage on git diffs — integrated into your development workflow.

```bash
promptheus pr-review --path . --last 1
promptheus pr-review --path . --range main..feature/new-agent --severity high
```

---

## All commands

```bash
promptheus init                          # First-run setup wizard
promptheus config show                   # View current config (API key masked)

# Scan
promptheus scan -u <url>                 # Attack an AI API endpoint
promptheus scan --mode agent \
  --target-path <path> \
  --model sonnet                         # Full codebase audit with AI agents

# PR review
promptheus pr-review --path <repo> \
  --last <N>                             # Review last N commits
promptheus pr-review --path <repo> \
  --range <base..head>                   # Review commit range
```

Full options: `promptheus --help` or `promptheus scan --help`.

---

## Supported AI Providers

No lock-in — works with any OpenAI-compatible endpoint:

| Provider | Notes |
|----------|-------|
| **Claude** (Haiku / Sonnet / Opus) | Recommended for agent scan |
| **OpenRouter** | 200+ models via one API key |
| **OpenAI** | GPT-4o, GPT-4o-mini |
| **Groq** | Free tier, fast inference |
| **Ollama** | Local models, no API key needed |
| **GLM / Zhipu AI** | Alternative provider |
| **Custom** | Any OpenAI-compatible endpoint |

---

## Other interfaces

| Interface | How to run |
|-----------|-----------|
| **Desktop App** | Download from [Releases](https://github.com/dungsnowaxe/prometheus-red-team-bot/releases) — bundled CLI, no Python needed |
| **Streamlit Dashboard** | `streamlit run apps/dashboard/main.py` |
| **REST API** | `uvicorn apps.api.main:app` |
| **Slack Bot** | See [Slack Bot setup](apps/slack_bot/README.md) |

---

## Contributing

Pull requests welcome. Please open an issue first to discuss major changes.

```bash
git clone https://github.com/dungsnowaxe/prometheus-red-team-bot
cd prometheus-red-team-bot
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.
