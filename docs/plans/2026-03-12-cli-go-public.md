# CLI Go-Public Setup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make PROMPTHEUS production-ready for public release — MIT license, professional README, auto-build binaries for macOS/Windows/Linux via GitHub Actions, and PyPI auto-publish on tag push.

**Architecture:** All changes are documentation and CI/CD config — no core code changes. GitHub Actions triggers on `v*` tags: builds PyInstaller binaries in parallel across 3 OS, publishes to PyPI, creates GitHub Release.

**Tech Stack:** GitHub Actions, PyInstaller (existing spec at `apps/desktop/promptheus-cli.spec`), `python -m build`, `twine`, hatchling.

---

### Task 1: Fix repo hygiene

**Files:**
- Modify: `.gitignore`
- Bash: `git restore --staged` to unstage files that shouldn't be committed

**Step 1: Add missing entries to .gitignore**

Open `.gitignore` and append at the bottom:

```
# Claude Code local settings
.claude/

# Backup files
*.bak
```

**Step 2: Unstage the two problematic staged files**

```bash
git restore --staged .claude/settings.local.json
git restore --staged promptheus/core/attacks/payloads.json.bak
```

**Step 3: Verify they're no longer staged**

```bash
git status --short
```

Expected: `.claude/settings.local.json` and `payloads.json.bak` should appear as untracked (??), not staged (A).

**Step 4: Commit the .gitignore change**

```bash
git add .gitignore
git commit -m "chore: ignore .claude/ dir and *.bak files"
```

---

### Task 2: Create LICENSE file

**Files:**
- Create: `LICENSE`

**Step 1: Create MIT LICENSE**

Create file `LICENSE` at repo root with this exact content (replace `<YEAR>` with `2026` and `<AUTHOR>` with your name/org):

```
MIT License

Copyright (c) 2026 PROMPTHEUS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Step 2: Commit**

```bash
git add LICENSE
git commit -m "chore: add MIT license"
```

---

### Task 3: Create CHANGELOG.md

**Files:**
- Create: `CHANGELOG.md`

**Step 1: Create initial CHANGELOG**

Create `CHANGELOG.md` at repo root:

```markdown
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
```

**Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add initial CHANGELOG for v0.1.0"
```

---

### Task 4: Rewrite README.md

**Files:**
- Modify: `README.md` (full rewrite)

**Step 1: Replace README.md with the professional version**

Full content for `README.md`:

````markdown
<div align="center">

# PROMPTHEUS

**Proactive Red-team Operator for Model PenTesting & Heuristic Exploit Utility System**

*Steals fire from the gods. LLM red-team security auditing.*

[![PyPI version](https://img.shields.io/pypi/v/promptheus.svg)](https://pypi.org/project/promptheus/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/release.yml/badge.svg)](https://github.com/YOUR_USERNAME/YOUR_REPO/actions)

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

Download the latest release for your platform from the [Releases page](https://github.com/YOUR_USERNAME/YOUR_REPO/releases):

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

**Windows:** Double-click `promptheus-windows.exe` or run from PowerShell:
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

6 AI agents analyze your codebase in parallel:

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

# Scan commands
promptheus scan -u <url>                 # Legacy: attack an API endpoint
promptheus scan --mode agent \
  --target-path <path> \
  --model sonnet                         # Agent: full codebase audit

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
| **Desktop App** | Download from [Releases](https://github.com/YOUR_USERNAME/YOUR_REPO/releases) — bundled CLI, no Python needed |
| **Streamlit Dashboard** | `streamlit run apps/dashboard/main.py` |
| **REST API** | `uvicorn apps.api.main:app` |
| **Slack Bot** | See [Slack Bot setup](apps/slack_bot/README.md) |

---

## Contributing

Pull requests welcome. Please open an issue first to discuss major changes.

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO
cd YOUR_REPO
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.
````

**Step 2: Replace `YOUR_USERNAME/YOUR_REPO` with real values**

Find the actual GitHub repo URL:
```bash
git remote -v
```

Then do a find-replace in README.md for `YOUR_USERNAME/YOUR_REPO`.

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README for public release"
```

---

### Task 5: Create GitHub Actions release workflow

**Files:**
- Create: `.github/workflows/release.yml`

**Step 1: Create the workflows directory**

```bash
mkdir -p .github/workflows
```

**Step 2: Create `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  build-binary:
    name: Build binary (${{ matrix.os }})
    strategy:
      matrix:
        include:
          - os: macos-latest
            artifact_name: promptheus
            asset_name: promptheus-macos
          - os: windows-latest
            artifact_name: promptheus.exe
            asset_name: promptheus-windows.exe
          - os: ubuntu-latest
            artifact_name: promptheus
            asset_name: promptheus-linux
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -e ".[all]"
          pip install pyinstaller

      - name: Build binary
        run: pyinstaller apps/desktop/promptheus-cli.spec --distpath dist/

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.asset_name }}
          path: dist/${{ matrix.artifact_name }}

  publish-pypi:
    name: Publish to PyPI
    runs-on: ubuntu-latest
    environment: release
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Build package
        run: |
          pip install build
          python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

  create-release:
    name: Create GitHub Release
    needs: [build-binary, publish-pypi]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: artifacts/

      - name: Extract changelog for this version
        id: changelog
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          NOTES=$(awk "/^## \[$VERSION\]/,/^## \[/" CHANGELOG.md | head -n -1)
          echo "notes<<EOF" >> $GITHUB_OUTPUT
          echo "$NOTES" >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          body: ${{ steps.changelog.outputs.notes }}
          files: |
            artifacts/promptheus-macos/promptheus
            artifacts/promptheus-linux/promptheus
            artifacts/promptheus-windows.exe/promptheus.exe
```

**Step 3: Commit**

```bash
git add .github/
git commit -m "ci: add GitHub Actions release workflow (binary + PyPI)"
```

---

### Task 6: Set up PyPI Trusted Publishing

This is a one-time manual step in the browser — no secrets needed, uses OIDC.

**Step 1: Create PyPI account**

Go to [pypi.org](https://pypi.org) → Register (if not already done).

**Step 2: Add Trusted Publisher on PyPI**

1. Go to [pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing)
2. Under "Add a new pending publisher", fill in:
   - **PyPI Project Name:** `promptheus`
   - **Owner:** your GitHub username
   - **Repository name:** your repo name
   - **Workflow filename:** `release.yml`
   - **Environment name:** `release`
3. Click "Add"

**Step 3: Create `release` environment in GitHub**

1. Go to your GitHub repo → Settings → Environments → New environment
2. Name it `release`
3. No additional rules needed

---

### Task 7: Test the full release flow

**Step 1: Verify package builds locally**

```bash
pip install build
python -m build
ls dist/
```

Expected: `dist/promptheus-0.1.0.tar.gz` and `dist/promptheus-0.1.0-py3-none-any.whl`

**Step 2: Test install from wheel locally**

```bash
pip install dist/promptheus-0.1.0-py3-none-any.whl --force-reinstall
promptheus --help
```

Expected: Help text prints without errors.

**Step 3: Push a test tag to trigger the workflow**

```bash
git tag v0.1.0
git push origin v0.1.0
```

**Step 4: Monitor the workflow**

```bash
gh run list --workflow=release.yml
gh run watch
```

Expected: All 3 jobs pass (build-binary ×3, publish-pypi, create-release).

**Step 5: Verify release artifacts**

```bash
gh release view v0.1.0
```

Expected: Release page shows 3 binary downloads + changelog notes.

---

## Notes for later

- **Upgrade to MkDocs docs site** when the project grows — host on GitHub Pages with `mkdocs gh-deploy`. Good structure: Getting Started, CLI Reference, Attack Payloads, Agent Scan, PR Review, Integrations (Slack, API, Desktop).
- **Homebrew tap** for `brew install promptheus` — create a separate repo `homebrew-promptheus` with a Formula file pointing to the GitHub Release binaries.
- **`promptheus update` command** — auto-check latest PyPI version and print upgrade notice.
