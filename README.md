# PROMPTHEUS

**P**roactive **R**ed-team **O**perator for **M**odel **P**en**T**esting & **H**euristic **E**xploit **U**tility **S**ystem — steals fire (prompts) from the gods. Very on-theme for LLM red teaming.

```
                    ·  ·  ·  ·  ·      ← the gods' fire (prompts)
                      \  |  /
                   ____*_*____
                  |  OLYMPUS   |
                   \__________/
                          |
                          |   stealing
                    \     |     /
                     \   /|\   /
                      \_/   \_/
                        |
                   _____|_____
                  | PROMPTHEUS |
                  |     o      |       figure
                  |    /|\     |
                  |    / \     |
                   \__/   \__/
                     *     *           fire in hand
```

Lightweight red-team tool for AI/LLM targets: run prompt-based attacks through multiple adapters (local, REST, Slack) and evaluate responses with an LLM judge.

## Architecture (Hexagonal / Ports & Adapters)

```
promptheus/
├── core/
│   ├── attacks/            # Payload library (payloads.json + loader)
│   ├── judge/              # LLM-as-a-Judge (evaluator)
│   └── engine.py           # Orchestrator
├── adapters/
│   ├── base.py             # TargetAdapter ABC
│   ├── local.py            # Python callable target
│   ├── rest.py             # HTTP/REST API target
│   └── slack.py            # Slack channel/thread target
├── interfaces/             # Shims only; app code lives in apps/
│   ├── dashboard.py        # → apps.dashboard.main
│   └── slack_bot.py       # → apps.slack_bot.main
├── utils/
│   └── loop_breaker.py     # Bot-to-bot loop prevention
└── config.py               # Env-based settings (no secrets in code)
```

**Scaling to more products:** The repo has an `apps/` layer — app code lives under `apps/` (cli, dashboard, slack_bot, api); core stays in `promptheus/`. Desktop and mobile will call the HTTP API (`apps.api.main`). See [apps/README.md](apps/README.md) and [docs/architecture.md](docs/architecture.md). Build/validate: `./scripts/build.sh`.

## Environment variables

### Judge (LLM)

You have multiple options for the LLM judge:

1. **OpenAI** (default):
   - `OPENAI_API_KEY=sk-...`
   - `PROMPTHEUS_JUDGE_MODEL=gpt-4o-mini` (default)

2. **OpenAI-compatible APIs** — Groq, Ollama, Together, OpenRouter, Azure, GLM (Zhipu)...
   - `PROMPTHEUS_JUDGE_BASE_URL` = base URL (e.g., `https://api.groq.com/openai/v1`, `http://localhost:11434/v1` for Ollama)
   - `PROMPTHEUS_JUDGE_API_KEY` = API key for that provider (Groq: from groq.com, Ollama: leave empty or `ollama`)
   - `PROMPTHEUS_JUDGE_MODEL` = model name (e.g., `llama3.1-8b`, `mixtral-8x7b-32768`)

3. **No key set** → Judge uses **MockJudge**: always returns "Safe" for testing pipeline/adapters only (not real evaluation).

Ví dụ **Ollama** (chạy local, không cần key):
```bash
export PROMPTHEUS_JUDGE_BASE_URL=http://localhost:11434/v1
export PROMPTHEUS_JUDGE_MODEL=llama3.2
# Không cần PROMPTHEUS_JUDGE_API_KEY (Ollama không bắt buộc)
```

Ví dụ **Groq** (free tier, cần đăng ký groq.com):
```bash
export PROMPTHEUS_JUDGE_API_KEY=gsk_...
export PROMPTHEUS_JUDGE_BASE_URL=https://api.groq.com/openai/v1
export PROMPTHEUS_JUDGE_MODEL=llama-3.1-8b-instant
```

Ví dụ **GLM (Zhipu AI / 智谱)** — lấy key tại https://open.bigmodel.cn/usercenter/apikeys:
```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://open.bigmodel.cn/api/paas/v4
export PROMPTHEUS_JUDGE_API_KEY=your_zhipu_api_key
export PROMPTHEUS_JUDGE_MODEL=glm-4-flash
```

Chi tiết từng bước: xem [USAGE.md](USAGE.md).

### Slack (nếu dùng bot Slack)

- **`SLACK_BOT_TOKEN`** — For Slack bot (interfaces/slack_bot).
- **`SLACK_APP_TOKEN`** — Socket Mode app-level token (xapp-...) for Slack bot.
- **`PROMPTHEUS_LOOP_BREAKER_MAX_MESSAGES`** — Optional; default `5` (max bot messages per thread before loop breaker stops replies).

Do not commit API keys; use `.env` or your shell.

## Setup

```bash
cd /path/to/red-team-bot

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the setup wizard (optional - configure API provider)
promptheus init
```

**Last verified:** 2026-03-10 ✅

## Development workflow (per SDD)

1. **Local** — Core, Judge, LocalAdapter. Test with a dummy Python function that mimics a vulnerable bot.
2. **Web** — RestAdapter and Streamlit dashboard. Test against a local API (e.g. Vercel app).
3. **Slack** — Two Slack apps: Bot A (victim/echo bot), Bot B (RedTeamBot). Verify loop breaker after 5 exchanges.

## Running

### CLI

The PROMPHEUS CLI supports two scan modes:

#### 1. Legacy Mode (REST API target)

```bash
# Activate venv first
source .venv/bin/activate

# Set Judge (OpenAI / GLM / Ollama / Groq) for real evaluation; omit for Mock
promptheus scan --target-url https://your-api.com/chat
# or with short flag
promptheus scan -u https://your-api.com/chat
```

The target API should accept POST JSON with a `prompt` (or configurable key) and return a body with `reply` / `response` / `content` / `text`.

#### 2. Agent Mode (codebase vulnerability scan)

```bash
# Scan a local repository with AI agents
promptheus scan --mode agent --target-path /path/to/repo

# With options
promptheus scan --mode agent --target-path /path/to/repo \
  --model sonnet \          # Model choice (sonnet, haiku, opus)
  --debug \                 # Verbose output
  --dast \                  # Enable DAST validation
  --dast-url http://localhost:3000  # Target URL for DAST

# Large repositories (exceeds limits)
promptheus scan --mode agent --target-path /path/to/large/repo \
  --confirm-large-scan      # Proceed despite file/size limits
```

Agent mode runs multiple AI agents (architecture assessment, threat modeling, code review, report generation, optional DAST) to perform a comprehensive security audit. Results are saved to `.promptheus/` in the target repository.

**Agent mode configuration:**
- `PROMPTHEUS_SCAN_TIMEOUT_SECONDS` — Timeout for agent scan in seconds (default: 3600 = 1 hour). Set to `0` to disable timeout.
- `PROMPTHEUS_MAX_SCAN_FILES` — Maximum file count limit (requires `--confirm-large-scan` when exceeded)
- `PROMPTHEUS_MAX_REPO_MB` — Maximum repository size in MB (requires `--confirm-large-scan` when exceeded)

#### 3. PR Review (diff-based security review)

```bash
# Review a commit range
promptheus pr-review --path /path/to/repo --range main..feature-branch

# Review last N commits
promptheus pr-review --path /path/to/repo --last 10

# With severity filter
promptheus pr-review --path /path/to/repo --range main..feature --severity medium
```

### Local mock target (for testing)

Run a deliberately vulnerable mock chatbot, then scan it:

```bash
# Terminal 1: start mock server
python scripts/mock_chat_server.py

# Terminal 2: run scan (or use the dashboard with URL http://127.0.0.1:8765/chat)
promptheus scan -u http://127.0.0.1:8765/chat
```

The mock server responds to the default payloads (system prompt leak, tool injection, error-handling leak) so you can verify Judge findings.

### Streamlit dashboard

```bash
streamlit run apps/dashboard/main.py
# or (backward-compat): streamlit run promptheus/interfaces/dashboard.py
```

Enter Target URL and click **Start Attack**. Results appear in a table with vulnerable rows highlighted in red.

### Desktop app (Electron)

```bash
cd apps/desktop
npm install
npm start      # Development mode
npm run make   # Build packaged app with bundled CLI
```

The desktop app supports:
- **URL scan** — Legacy API scan against a target URL
- **Agent scan** — Full codebase vulnerability scan on a repository path
- **PR review** — Security review of diffs and branches

The packaged app includes a bundled Promptheus CLI — end users don't need to install Python or Promptheus separately.

### Slack bot (Socket Mode)

```bash
export SLACK_BOT_TOKEN=xoxb-...
export SLACK_APP_TOKEN=xapp-...
export OPENAI_API_KEY=sk-...
python -m promptheus.interfaces.slack_bot
```

In Slack, mention the bot and the target bot: **@RedTeamBot attack @TargetBot**. The bot runs the payload scan against the target bot in that thread and posts a summary. Loop breaker: if RedTeamBot has already sent more than 5 messages in the same thread, it will not reply again.

## Payloads

Edit `promptheus/core/attacks/payloads.json`. Default payloads (Part 4):

1. **System Prompt Extraction** — Tries to leak system instructions.
2. **Tool Call Injection** — Tries to trigger a refund/tool call.
3. **Lazy Error Handling** — Malformed input to trigger stack traces or secrets in errors.

Each payload has `id`, `name`, `prompt`, and `judge_expectation` (rubric for the LLM judge).

## References

- [Scanner configuration](docs/scanner_config.md) — Cost limits, threat-aware scanning, design decisions, fix-remediation, artifact trust (for codebase security scans)
- [Timeout configuration](docs/timeout_configuration.md) — Agent scan timeout settings and troubleshooting
- [Desktop app](apps/desktop/README.md) — Native desktop application with bundled CLI
- [Apps directory](apps/README.md) — Overview of all Promptheus applications
- PyRIT (Microsoft) — Adapter-style "Targets"
- Promptfoo — LLM rubric / scoring
- Slack Bolt (Python) — Bot framework; we intentionally allow bot_message and use a loop breaker
