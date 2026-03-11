# AI Provider Setup

PROMPTHEUS supports any OpenAI-compatible endpoint. Run `promptheus init` for an interactive wizard, or set environment variables manually.

---

## Claude (Anthropic) — Recommended for Agent Scan

Best choice for `--mode agent` and `pr-review` — the multi-agent pipeline is optimized for Claude.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export PROMPTHEUS_SCAN_MODEL=claude-sonnet-4-6   # or claude-haiku-4-5, claude-opus-4-6
```

Get a key at [console.anthropic.com](https://console.anthropic.com).

---

## OpenAI

```bash
export PROMPTHEUS_JUDGE_API_KEY=sk-...
export PROMPTHEUS_JUDGE_MODEL=gpt-4o-mini        # or gpt-4o
```

---

## OpenRouter — 200+ models via one key

```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://openrouter.ai/api/v1
export PROMPTHEUS_JUDGE_API_KEY=sk-or-v1-...
export PROMPTHEUS_JUDGE_MODEL=anthropic/claude-3-haiku  # any model slug
```

Get a key at [openrouter.ai](https://openrouter.ai).

---

## Groq — Free tier, fast inference

```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://api.groq.com/openai/v1
export PROMPTHEUS_JUDGE_API_KEY=gsk_...
export PROMPTHEUS_JUDGE_MODEL=llama-3.1-8b-instant
```

Get a key at [groq.com](https://groq.com).

---

## Ollama — Local models, no API key

Run models locally with no internet or API key required.

```bash
# Install Ollama: https://ollama.com
ollama pull llama3.2

export PROMPTHEUS_JUDGE_BASE_URL=http://localhost:11434/v1
export PROMPTHEUS_JUDGE_MODEL=llama3.2
# No API key needed
```

---

## GLM / Zhipu AI

```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://open.bigmodel.cn/api/paas/v4
export PROMPTHEUS_JUDGE_API_KEY=your_zhipu_key
export PROMPTHEUS_JUDGE_MODEL=glm-4-flash
```

Get a key at [open.bigmodel.cn](https://open.bigmodel.cn/usercenter/apikeys).

---

## Custom / Self-hosted

Any endpoint that speaks the OpenAI API format:

```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://your-endpoint.com/v1
export PROMPTHEUS_JUDGE_API_KEY=your_key
export PROMPTHEUS_JUDGE_MODEL=your-model-name
```

---

## No key — Mock Judge

If no API key is set, PROMPTHEUS uses **MockJudge** — always returns `Safe`. Useful for testing the pipeline and UI without spending tokens.

```bash
# Don't export anything — MockJudge activates automatically
promptheus scan -u https://httpbin.org/post --max-payloads 3
```

---

## How PROMPTHEUS uses the Claude Agent SDK

The `--mode agent` scan and `pr-review` commands are built on the **Claude Agent SDK**, where Claude autonomously orchestrates a pipeline of specialized sub-agents:

```
promptheus scan --mode agent
        ↓
  Scanner (Python)
        ↓
  Claude (Orchestrator)          ← Claude Agent SDK
    ├── Architecture Assessment Agent
    ├── Threat Modeling Agent
    ├── Code Review Agent
    ├── Report Generator Agent
    ├── DAST Validation Agent (optional)
    └── Fix Remediation Agent (optional)
```

Each agent has a focused role and writes structured output to `.promptheus/` in your repo. See [architecture.md](architecture.md) for full details on how the agent pipeline works and how to extend it.
