# Hướng dẫn sử dụng PROMPTHEUS

**PROMPTHEUS** — **P**roactive **R**ed-team **O**perator for **M**odel **P**en**T**esting & **H**euristic **E**xploit **U**tility **S**ystem. Steals fire (prompts) from the gods. LLM red-team security auditing.

## 1. Phiên bản hiện tại đã chạy được chưa?

**Có.** Bạn có thể chạy ngay sau khi cài dependency. Nếu **không set bất kỳ API key nào**, Judge sẽ dùng chế độ **Mock** (luôn trả "Safe") — dùng để test pipeline và giao diện.

**Last verified:** 2026-03-04 ✅

---

## 2. Cài đặt (lần đầu)

```bash
cd /path/to/red-team-bot

# Tạo virtual environment (khuyến nghị trên macOS/Linux)
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Cài dependency
pip install -r requirements.txt
```

Kiểm tra CLI:

```bash
python -m promptheus --help
```

### Sử dụng CLI:

```bash
# Cách 1: Dùng subcommand (khuyến nghị)
python -m promptheus scan --target-url https://example.com/chat

# Cách 2: Dùng short flag
python -m promptheus scan -u https://example.com/chat
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

## 4. Chọn LLM cho Judge (đánh giá thật)

Cần **một** trong các cách sau. Chỉ cần set biến môi trường trước khi chạy.

### 4.1. OpenAI

```bash
export OPENAI_API_KEY=sk-proj-xxxx
export PROMPTHEUS_JUDGE_MODEL=gpt-4o-mini    # mặc định, có thể bỏ qua
python -m promptheus scan -u https://your-api.com/chat
```

### 4.2. GLM (Zhipu AI / 智谱)

API tương thích OpenAI. Lấy API key tại: https://open.bigmodel.cn/usercenter/apikeys

```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://open.bigmodel.cn/api/paas/v4
export PROMPTHEUS_JUDGE_API_KEY=your_zhipu_api_key
export PROMPTHEUS_JUDGE_MODEL=glm-4-flash
python -m promptheus scan -u https://your-api.com/chat
```

Model thường dùng: `glm-4-flash`, `glm-4`, `glm-4-long`.

### 4.3. Ollama (local, không cần key)

```bash
# Trước đó: cài Ollama, chạy ollama pull llama3.2
export PROMPTHEUS_JUDGE_BASE_URL=http://localhost:11434/v1
export PROMPTHEUS_JUDGE_MODEL=llama3.2
python -m promptheus scan -u https://your-api.com/chat
```

### 4.4. Groq (free tier)

```bash
export PROMPTHEUS_JUDGE_BASE_URL=https://api.groq.com/openai/v1
export PROMPTHEUS_JUDGE_API_KEY=gsk_xxxx
export PROMPTHEUS_JUDGE_MODEL=llama-3.1-8b-instant
python -m promptheus scan -u https://your-api.com/chat
```

---

## 5. Các cách chạy chính

### 5.1. CLI — quét một REST API

Target API cần nhận POST JSON (mặc định key `prompt`) và trả về JSON có một trong các key: `reply`, `response`, `content`, `text`.

```bash
python -m promptheus scan -u https://your-api.com/chat
# hoặc dạng đầy đủ
python -m promptheus scan --target-url https://your-api.com/chat
```

### 5.2. Dashboard (Streamlit)

Giao diện web: nhập URL → bấm **Start Attack** → xem bảng kết quả (hàng Vulnerable màu đỏ).

```bash
streamlit run promptheus/interfaces/dashboard.py
```

Mở trình duyệt theo địa chỉ in ra (thường `http://localhost:8501`). Cần set env Judge (OpenAI/GLM/Ollama/...) như mục 4 nếu muốn đánh giá thật; không set thì vẫn chạy với Mock.

### 5.3. Test với Local Adapter (không cần HTTP)

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

### 5.4. Slack Bot (tùy chọn)

Cần 2 Slack app (một victim bot, một RedTeamBot). Trong Slack gõ: **@RedTeamBot attack @TargetBot**.

```bash
export SLACK_BOT_TOKEN=xoxb-...
export SLACK_APP_TOKEN=xapp-...
# Judge: dùng OpenAI / GLM / Ollama như trên
python -m promptheus.interfaces.slack_bot
```

---

## 6. Tóm tắt biến môi trường Judge (LLM)

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

---

## 7. Payloads

File `promptheus/core/attacks/payloads.json` chứa 3 payload mặc định:

1. **System Prompt Extraction** — cố lộ system prompt.
2. **Tool Call Injection** — cố gọi tool/refund.
3. **Lazy Error Handling** — input lỗi để xem stack trace/secret.

Có thể sửa file này để thêm/bớt payload; mỗi item cần `id`, `name`, `prompt`, `judge_expectation`.

---

## 8. Troubleshooting

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
python -m promptheus scan -u https://httpbin.org/post
```

---

## 9. Quick Start Commands

```bash
# 1. Setup
source .venv/bin/activate

# 2. Test với Mock Judge (không cần API key)
python -m promptheus scan -u https://httpbin.org/post

# 3. Chạy Dashboard
streamlit run promptheus/interfaces/dashboard.py

# 4. Với LLM Judge (ví dụ OpenAI)
export OPENAI_API_KEY=sk-xxx
python -m promptheus scan -u https://your-api.com/chat
```
