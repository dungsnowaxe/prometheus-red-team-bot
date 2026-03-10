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

Bạn **không bắt buộc** phải có OpenAI. Có 3 cách:

1. **OpenAI** (mặc định):
   - `OPENAI_API_KEY=sk-...`
   - `PROMPTHEUS_JUDGE_MODEL=gpt-4o-mini` (mặc định)

2. **LLM khác (API tương thích OpenAI)** — Groq, Ollama, Together, OpenRouter, Azure...
   - `PROMPTHEUS_JUDGE_BASE_URL` = base URL (vd: `https://api.groq.com/openai/v1`, `http://localhost:11434/v1` cho Ollama)
   - `PROMPTHEUS_JUDGE_API_KEY` = API key của provider đó (Groq: lấy tại groq.com, Ollama: để trống hoặc `ollama`)
   - `PROMPTHEUS_JUDGE_MODEL` = tên model (vd: `llama3.1-8b`, `mixtral-8x7b-32768`)

3. **Không set key nào** → Judge dùng **MockJudge**: luôn trả "Safe", chỉ để test pipeline/adapters (không đánh giá thật).

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
```

**Last verified:** 2026-03-04 ✅

## Development workflow (per SDD)

1. **Local** — Core, Judge, LocalAdapter. Test with a dummy Python function that mimics a vulnerable bot.
2. **Web** — RestAdapter and Streamlit dashboard. Test against a local API (e.g. Vercel app).
3. **Slack** — Two Slack apps: Bot A (victim/echo bot), Bot B (RedTeamBot). Verify loop breaker after 5 exchanges.

## Running

### CLI (REST target)

```bash
# Activate venv first
source .venv/bin/activate

# Set Judge (OpenAI / GLM / Ollama / Groq) nếu cần đánh giá thật; không set = Mock
python -m promptheus scan --target-url https://your-api.com/chat
# hoặc dùng short flag
python -m promptheus scan -u https://your-api.com/chat
```

The target API should accept POST JSON with a `prompt` (or configurable key) and return a body with `reply` / `response` / `content` / `text`.

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

- [Scanner configuration](docs/scanner_config.md) — Cost limits, threat-aware scanning, design decisions, fix-remediation, artifact trust (for codebase security scans).
- PyRIT (Microsoft) — Adapter-style "Targets".
- Promptfoo — LLM rubric / scoring.
- Slack Bolt (Python) — Bot framework; we intentionally allow bot_message and use a loop breaker.
