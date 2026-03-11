# Hướng dẫn sử dụng PROMPTHEUS

**PROMPTHEUS** — **P**roactive **R**ed-team **O**perator for **M**odel **P**en**T**esting & **H**euristic **E**xploit **U**tility **S**ystem. Steals fire (prompts) from the gods. LLM red-team security auditing.

## 1. Phiên bản hiện tại đã chạy được chưa?

**Có.** Bạn có thể chạy ngay sau khi cài dependency. Nếu **không set bất kỳ API key nào**, Judge sẽ dùng chế độ **Mock** (luôn trả "Safe") — dùng để test pipeline và giao diện.

**Last verified:** 2026-03-11 ✅

---

## 2. Cài đặt (lần đầu)

```bash
cd /path/to/red-team-bot

# Tạo virtual environment (khuyến nghị trên macOS/Linux)
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Cài dependency (cách 1 — editable install, khuyến nghị)
pip install -e ".[all]"

# Hoặc cách 2
pip install -r requirements.txt
```

Kiểm tra CLI:

```bash
promptheus --help
```

### Sử dụng CLI:

```bash
# Legacy scan — tấn công một URL target
promptheus scan --target-url https://example.com/chat
promptheus scan -u https://example.com/chat          # short flag

# Agent mode — quét toàn bộ codebase bằng AI
promptheus scan --mode agent --target-path /path/to/repo

# PR review — review diff/commit
promptheus pr-review --path /path/to/repo --last 3

# Setup wizard — cấu hình AI provider lần đầu
promptheus init

# Xem config hiện tại
promptheus config show
```

---

## 3. Chạy không cần API key (Mock Judge)

Dùng để test: adapter, engine, CLI, dashboard đều chạy; Judge luôn trả **Safe**.

```bash
# Không cần export gì cả
python -m promptheus scan -u https://httpbin.org/post
```

(Lưu ý: `https://httpbin.org/post` chỉ echo body, không phải chatbot — dùng để xem pipeline chạy. Kết quả Judge sẽ là Safe vì Mock.)

---

## 4. Agent Mode — Quét bảo mật codebase bằng AI

Agent mode sử dụng nhiều AI agents để thực hiện audit bảo mật toàn diện cho codebase:

```bash
# Quét cơ bản
promptheus scan --mode agent --target-path /path/to/repo

# Với các tùy chọn
promptheus scan --mode agent --target-path /path/to/repo \
  --model sonnet \          # Chọn model (sonnet, haiku, opus)
  --debug \                 # Chi tiết output
  --dast \                  # Bật DAST validation
  --dast-url http://localhost:3000  # URL cho DAST

# Repo lớn (vượt giới hạn)
promptheus scan --mode agent --target-path /path/to/large/repo \
  --confirm-large-scan      # Tiếp tục despite vượt giới hạn file/size
```

**Các agents chạy:**
1. **Architecture Assessment** — Phân tích kiến trúc, tạo SECURITY.md
2. **Threat Modeling** — STRIDE analysis, tạo THREAT_MODEL.json
3. **Code Review** — Tìm vulnerabilities, tạo VULNERABILITIES.json
4. **Report Generation** — Tổng hợp kết quả, tạo scan_results.json
5. **DAST Validation** (tùy chọn) — Validate vulnerabilities qua HTTP testing

**Kết quả lưu tại:** `.promptheus/` trong target repository.

**Cấu hình Agent mode:**
- `PROMPTHEUS_SCAN_TIMEOUT_SECONDS` — Timeout cho scan (giây, mặc định: 3600 = 1 giờ). Set `0` để tắt timeout.
- `PROMPTHEUS_MAX_SCAN_FILES` — Giới hạn số file (yêu cầu `--confirm-large-scan` khi vượt)
- `PROMPTHEUS_MAX_REPO_MB` — Giới hạn dung lượng repo MB (yêu cầu `--confirm-large-scan` khi vượt)

---

## 5. Setup AI Provider cho Agent Mode

Agent mode dùng Claude Agent SDK — yêu cầu **Anthropic API key** hoặc route qua **OpenRouter**.

### 5.1. Anthropic trực tiếp

```bash
export ANTHROPIC_API_KEY="sk-ant-xxxx"
promptheus scan --mode agent --target-path .
```

### 5.2. OpenRouter (hỗ trợ nhiều provider, có free tier)

Lấy API key tại https://openrouter.ai/keys rồi thêm vào `~/.zshrc`:

```bash
export OPENROUTER_API_KEY="sk-or-v1-xxxx"
export ANTHROPIC_BASE_URL="https://openrouter.ai/api"
export ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
export ANTHROPIC_API_KEY="placeholder"  # Bắt buộc, không để trống
```

```bash
source ~/.zshrc
promptheus scan --mode agent --target-path . --model sonnet
```

> **Lưu ý:** Agent mode chỉ hoạt động với **Claude models** (`haiku`, `sonnet`, `opus`). Không dùng được non-Claude models (Qwen, Llama...) cho agent mode.

### 5.3. Chọn model cho agent mode

```bash
promptheus scan --mode agent --target-path . --model haiku   # Rẻ nhất, nhanh nhất
promptheus scan --mode agent --target-path . --model sonnet  # Cân bằng (mặc định)
promptheus scan --mode agent --target-path . --model opus    # Mạnh nhất, đắt nhất
```

### 5.4. Setup wizard (cách đơn giản nhất)

Thay vì set env vars thủ công, dùng wizard:

```bash
promptheus init
```

Wizard hỏi chọn provider (OpenAI, Groq, Ollama, GLM, Custom) và lưu config vào file — không cần export env vars mỗi lần.

Xem config đã lưu:

```bash
promptheus config show
```

---

## 6. Chọn LLM cho Judge (legacy scan)

Judge dùng cho legacy scan (`promptheus scan -u ...`). Cần **một** trong các cách sau.

### 6.1. OpenAI

```bash
export OPENAI_API_KEY=sk-proj-xxxx
export PROMPTHEUS_JUDGE_MODEL=gpt-4o-mini    # mặc định, có thể bỏ qua
python -m promptheus scan -u https://your-api.com/chat
```

### 6.2. GLM (Zhipu AI / 智谱)

API tương thích OpenAI. Lấy API key tại: https://open.bigmodel.cn/usercenter/apikeys

```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://open.bigmodel.cn/api/paas/v4
export PROMPTHEUS_JUDGE_API_KEY=your_zhipu_api_key
export PROMPTHEUS_JUDGE_MODEL=glm-4-flash
python -m promptheus scan -u https://your-api.com/chat
```

Model thường dùng: `glm-4-flash`, `glm-4`, `glm-4-long`.

### 6.3. Ollama (local, không cần key)

```bash
# Trước đó: cài Ollama, chạy ollama pull llama3.2
export PROMPTHEUS_JUDGE_BASE_URL=http://localhost:11434/v1
export PROMPTHEUS_JUDGE_MODEL=llama3.2
python -m promptheus scan -u https://your-api.com/chat
```

### 6.4. Groq (free tier)

```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://api.groq.com/openai/v1
export PROMPTHEUS_JUDGE_API_KEY=gsk_xxxx
export PROMPTHEUS_JUDGE_MODEL=llama-3.1-8b-instant
python -m promptheus scan -u https://your-api.com/chat
```

---

## 7. Các cách chạy chính

### 7.1. CLI — Legacy REST API scan

Target API cần nhận POST JSON (mặc định key `prompt`) và trả về JSON có một trong các key: `reply`, `response`, `content`, `text`.

```bash
python -m promptheus scan -u https://your-api.com/chat
# hoặc dạng đầy đủ
python -m promptheus scan --target-url https://your-api.com/chat
```

### 7.2. Dashboard (Streamlit)

Giao diện web: nhập URL → bấm **Start Attack** → xem bảng kết quả (hàng Vulnerable màu đỏ).

```bash
streamlit run promptheus/interfaces/dashboard.py
```

Mở trình duyệt theo địa chỉ in ra (thường `http://localhost:8501`). Cần set env Judge (OpenAI/GLM/Ollama/...) như mục 4 nếu muốn đánh giá thật; không set thì vẫn chạy với Mock.

### 7.3. Agent Mode — Quét bảo mật codebase

```bash
# Quét cơ bản
promptheus scan --mode agent --target-path /path/to/repo

# Với debug mode
promptheus scan --mode agent --target-path /path/to/repo --debug

# Với DAST validation
promptheus scan --mode agent --target-path /path/to/repo \
  --dast --dast-url http://localhost:3000
```

Kết quả được lưu tại `.promptheus/` trong target repository:
- `SECURITY.md` — Architecture assessment
- `THREAT_MODEL.json` — Threat model
- `VULNERABILITIES.json` — Security findings
- `scan_results.json` — Full report
- `DAST_VALIDATION.json` — DAST results (nếu bật)

### 7.4. PR Review — Review diff/branch

```bash
# Review commit range
promptheus pr-review --path /path/to/repo --range main..feature-branch

# Review N commits gần nhất
promptheus pr-review --path /path/to/repo --last 1

# Với severity filter
promptheus pr-review --path /path/to/repo --range main..feature --severity medium

# Output JSON
promptheus pr-review --path /path/to/repo --last 1 --output json
```

> **Lưu ý:** Nếu diff quá lớn sẽ báo lỗi `exceeds safe analysis limits`. Giải pháp: dùng `--last 1` hoặc chia nhỏ range thay vì `--last 3` hay nhiều hơn.

### 6.5. Test với Local Adapter (không cần HTTP)

Dùng khi bạn muốn test engine + Judge với một hàm Python giả lập bot:

```python
# test_local.py
from promptheus.adapters.local import LocalAdapter
from promptheus.core.engine import RedTeamEngine

def fake_bot(prompt: str) -> str:
    if "You are a" in prompt:
        return "You are a helpful assistant."
    return "I cannot do that."

adapter = LocalAdapter(fake_bot)
engine = RedTeamEngine(adapter)
report = engine.run_scan()
for r in report.results:
    print(r.name, "->", "Vulnerable" if r.vulnerable else "Safe")
```

Chạy:

```bash
# Set Judge (OpenAI/GLM/Ollama) nếu muốn đánh giá thật; không set = Mock
python test_local.py
```

### 7.6. Slack Bot (tùy chọn)

Cần 2 Slack app (một victim bot, một RedTeamBot). Trong Slack gõ: **@RedTeamBot attack @TargetBot**.

```bash
export SLACK_BOT_TOKEN=xoxb-...
export SLACK_APP_TOKEN=xapp-...
# Judge: dùng OpenAI / GLM / Ollama như trên
python -m promptheus.interfaces.slack_bot
```

---

## 8. Tóm tắt biến môi trường

### Agent Mode (Anthropic / OpenRouter)

| Biến | Ý nghĩa |
|------|--------|
| `ANTHROPIC_API_KEY` | Anthropic API key (trực tiếp) |
| `ANTHROPIC_BASE_URL` | Base URL override (dùng khi route qua OpenRouter: `https://openrouter.ai/api`) |
| `ANTHROPIC_AUTH_TOKEN` | Auth token thay thế khi dùng OpenRouter |
| `OPENROUTER_API_KEY` | OpenRouter API key (set rồi trỏ `ANTHROPIC_AUTH_TOKEN` vào) |

### Judge (LLM — legacy scan)

| Biến | Ý nghĩa |
|------|--------|
| `OPENAI_API_KEY` | Key OpenAI (nếu dùng OpenAI) |
| `PROMPTHEUS_JUDGE_BASE_URL` | Base URL API (bắt buộc khi dùng Ollama/Groq/GLM) |
| `PROMPTHEUS_JUDGE_API_KEY` | Key Judge (GLM/Groq/...); nếu không set thì dùng `OPENAI_API_KEY` |
| `PROMPTHEUS_JUDGE_MODEL` | Tên model (mặc định `gpt-4o-mini`) |

**GLM (Zhipu):**
- `PROMPTHEUS_JUDGE_BASE_URL=https://open.bigmodel.cn/api/paas/v4`
- `PROMPTHEUS_JUDGE_API_KEY=<key từ open.bigmodel.cn>`
- `PROMPTHEUS_JUDGE_MODEL=glm-4-flash` (hoặc `glm-4`, `glm-4-long`)

### Agent Mode Configuration

| Biến | Ý nghĩa | Mặc định |
|------|---------|----------|
| `PROMPTHEUS_SCAN_TIMEOUT_SECONDS` | Timeout cho agent scan (giây) | `3600` (1 giờ) |
| `PROMPTHEUS_MAX_SCAN_FILES` | Giới hạn số file | (không giới hạn) |
| `PROMPTHEUS_MAX_REPO_MB` | Giới hạn dung lượng repo (MB) | (không giới hạn) |
| `PROMPTHEUS_FIX_REMEDIATION_ENABLED` | Bật agent fix-remediation | `false` |

**Lưu ý timeout:**
- Set `PROMPTHEUS_SCAN_TIMEOUT_SECONDS=0` để **tắt timeout** (chờ vô hạn)
- Tăng giá trị timeout cho repo rất lớn (>30 phút scan)
- Giảm giá trị timeout để fail nhanh hơn khi có vấn đề

---

## 9. Payloads

File `promptheus/core/attacks/payloads.json` chứa 3 payload mặc định:

1. **System Prompt Extraction** — cố lộ system prompt.
2. **Tool Call Injection** — cố gọi tool/refund.
3. **Lazy Error Handling** — input lỗi để xem stack trace/secret.

Có thể sửa file này để thêm/bớt payload; mỗi item cần `id`, `name`, `prompt`, `judge_expectation`.

---

## 10. Troubleshooting

### Lỗi "bad interpreter" khi chạy pip

Nếu venv được tạo từ đường dẫn khác, cần tạo lại:

```bash
python3 -m venv .venv --clear
source .venv/bin/activate
pip install -r requirements.txt
```

### Lỗi module not found

Đảm bảo đã activate venv trước khi chạy:

```bash
source .venv/bin/activate
python -m promptheus --help
```

### Muốn test nhanh không cần API

```bash
promptheus scan -u https://httpbin.org/post
```

### Agent mode bị timeout?

Nếu agent scan bị timeout sau 1 giờ (mặc định):

```bash
# Tăng timeout lên 2 giờ
export PROMPTHEUS_SCAN_TIMEOUT_SECONDS=7200
promptheus scan --mode agent --target-path /path/to/large/repo

# Hoặc tắt timeout hoàn toàn (không khuyến nghị)
export PROMPTHEUS_SCAN_TIMEOUT_SECONDS=0
promptheus scan --mode agent --target-path /path/to/large/repo
```

### Agent mode bị treo không có output?

1. Thử với `--debug` flag để xem chi tiết:
   ```bash
   promptheus scan --mode agent --target-path /path/to/repo --debug
   ```

2. Kiểm tra file giới hạn:
   ```bash
   # Với --confirm-large-scan để bỏ qua giới hạn
   promptheus scan --mode agent --target-path /path/to/repo --confirm-large-scan
   ```

3. Kiểm tra kết quả partial trong `.promptheus/` — có thể một số agents đã hoàn thành.

### PR review báo lỗi "exceeds safe analysis limits"?

Diff quá lớn. Chia nhỏ range:

```bash
# Thay vì --last 3 (có thể chứa commit 130 files)
promptheus pr-review --path . --last 1

# Hoặc chỉ review 1 commit cụ thể
promptheus pr-review --path . --range abc1234..def5678
```

### Lỗi model không tìm thấy khi dùng OpenRouter?

Kiểm tra `ANTHROPIC_BASE_URL` đúng format (không có `/v1`):

```bash
echo $ANTHROPIC_BASE_URL
# Phải ra: https://openrouter.ai/api

# Nếu sai, sửa lại trong ~/.zshrc
export ANTHROPIC_BASE_URL="https://openrouter.ai/api"  # Không có /v1
export ANTHROPIC_API_KEY="placeholder"                  # Không để trống
source ~/.zshrc
```

---

## 11. Quick Start Commands

```bash
# 1. Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"

# 2. Lần đầu: chạy wizard chọn AI provider
promptheus init

# 3. Xem config
promptheus config show

# 4. Test legacy scan (không cần API key)
promptheus scan -u https://httpbin.org/post

# 5. Agent mode — quét codebase
promptheus scan --mode agent --target-path . --model haiku

# 6. PR review — 1 commit gần nhất
promptheus pr-review --path . --last 1

# 7. Xem kết quả scan
cat .promptheus/scan_results.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
s = data.get('summary', {})
print(f\"CRITICAL: {s.get('critical',0)} | HIGH: {s.get('high',0)} | MEDIUM: {s.get('medium',0)}\")
for i in data.get('issues', []):
    print(f\"[{i.get('severity','?').upper():8}] {i.get('title','')}\")
"

# 8. Chạy Dashboard
streamlit run apps/dashboard/main.py
```

### Desktop App

```bash
cd apps/desktop
npm install
npm start  # Chạy desktop app (built-in Electron + CLI)
```
