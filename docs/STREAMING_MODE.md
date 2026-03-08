# Streaming Mode - Real-Time Progress Tracking

## Overview

PROMPTHEUS supports **real-time streaming progress** mode for security scans. This eliminates long silent periods during scans (10-20+ minutes) and provides continuous feedback about what the scanner is doing.

**Quick Start:**
```bash
promptheus scan .              # Real-time progress (always enabled)
promptheus scan . --debug      # + Agent narration/thinking
```

## Problem It Solves

Traditional security scans can take 10-20+ minutes on large codebases with minimal progress feedback. Users would see:

```
━━━ Phase 3/4: Code Review (Security Analysis) ━━━
  ⏳ Analyzing... (20 tools used)
[10 minutes of silence]
  ⏳ Analyzing... (30 tools used)
```

This led to:
- Uncertainty about scan progress
- Unclear if scanner is stuck or working
- Poor user experience during long operations
- No visibility into what files/patterns are being analyzed

## Solution: Real-Time Progress Tracking

PROMPTHEUS uses the Claude Agent SDK's **hooks system** to provide real-time updates on:

✅ **Tool Usage** - See every Read, Grep, Write operation as it happens  
✅ **File Operations** - Know which files are being analyzed  
✅ **Sub-Agent Lifecycle** - Deterministic phase start/stop events  
✅ **Cost Tracking** - Real-time cost accumulation  
✅ **Agent Narration** - Optional debug mode shows agent thinking

## Usage

Real-time progress is always enabled. Use the `--debug` flag for verbose output:

```bash
# Basic scan with real-time progress
promptheus scan .

# Verbose debug output (shows agent narration)
promptheus scan . --debug

# Scan specific directory
promptheus scan /path/to/large/repo
```

## Example Output

### Old Design (Before Progress Tracking)
```
📁 Scanning: /Users/user/repos/myapp
🤖 Model: sonnet
============================================================

✅ Phase 1/4: Architecture Assessment Complete
   Created: SECURITY.md

━━━ Phase 2/4: Threat Modeling (STRIDE Analysis) ━━━

[long silence]

✅ Phase 2/4: Threat Modeling (STRIDE Analysis) Complete
   Created: THREAT_MODEL.json
```

### Current Design (With Progress Tracking)
```
📁 Scanning: /Users/user/repos/myapp
🤖 Model: sonnet
============================================================

━━━ Phase 1/4: Architecture Assessment ━━━

  🤖 Starting assessment: Analyze this codebase and create SECURITY.md...
  📖 Reading pyproject.toml
  📖 Reading package.json
  🗂️  Finding files: *.py, *.ts, *.tsx
  📖 Reading src/main.py
  📖 Reading server/routes.ts
  🔍 Searching: authentication|auth|login
  📖 Reading server/middleware/auth.ts
  🔍 Searching: database|db|postgres|mysql
  📖 Reading config/database.py
  💾 Writing SECURITY.md

✅ Phase 1/4: Architecture Assessment Complete
   Duration: 45.3s | Tools: 47 | Files: 23 read, 1 written
   Created: SECURITY.md

━━━ Phase 2/4: Threat Modeling (STRIDE Analysis) ━━━

  🤖 Starting threat-modeling: Analyze threats based on SECURITY.md...
  📖 Reading SECURITY.md
  🔍 Searching: API|endpoint|route
  📖 Reading server/routes.ts
  🔍 Searching: authentication|authorization
  💾 Writing THREAT_MODEL.json

✅ Phase 2/4: Threat Modeling (STRIDE Analysis) Complete
   Duration: 67.2s | Tools: 34 | Files: 15 read, 1 written
   Created: THREAT_MODEL.json

━━━ Phase 3/4: Code Review (Security Analysis) ━━━

  🤖 Starting code-review: Validate threats and find vulnerabilities...
  📖 Reading THREAT_MODEL.json
  📖 Reading server/routes.ts
  🔍 Searching: Stripe.*webhook.*verify
  📖 Reading server/index.ts
  🔍 Searching: csrf|CSRF
  📖 Reading client/src/pages/BlogPost.tsx
  🔍 Searching: dangerouslySetInnerHTML|innerHTML
  📖 Reading shared/schema.ts
  🔍 Searching: password.*hash|bcrypt|scrypt
  💾 Writing VULNERABILITIES.json

✅ Phase 3/4: Code Review (Security Analysis) Complete
   Duration: 789.4s | Tools: 156 | Files: 87 read, 1 written
   Created: VULNERABILITIES.json

━━━ Phase 4/4: Report Generation ━━━

  🤖 Starting report-generator: Create final scan results...
  📖 Reading VULNERABILITIES.json
  💾 Writing scan_results.json

✅ Phase 4/4: Report Generation Complete
   Duration: 12.1s | Tools: 8 | Files: 1 read, 1 written
   Created: scan_results.json

━━━ Phase 5/5: DAST Validation (Optional) ━━━

ℹ️  Note: DAST phase only runs when --target-url is provided

  🤖 Starting dast: Validate vulnerabilities via HTTP testing...
  📖 Reading VULNERABILITIES.json
  🔍 Loading skill: authorization-testing (CWE-639, CWE-269, CWE-862)
  📖 Reading .promptheus/DAST_TEST_ACCOUNTS.json
  🌐 Testing: http://localhost:3000/api/user/456 (IDOR validation)
  🔐 Authenticating as user1 (ID: 123)
  ✅ Baseline: GET /api/user/123 → 200 OK
  ❌ Test: GET /api/user/456 → 200 OK (Expected 403) - VALIDATED
  💾 Writing DAST_VALIDATION.json

✅ Phase 5/5: DAST Validation Complete
   Duration: 34.7s | Tools: 23 | Files: 2 read, 1 written
   Created: DAST_VALIDATION.json
   Validated: 3 vulnerabilities | False Positives: 1 | Partial: 0 | Unvalidated: 2
```

## Technical Details

### Architecture

Streaming mode uses `ClaudeSDKClient` with three key hooks to track progress across **5 agents** (4 required + 1 optional DAST):

1. **PreToolUse** - Fires before each tool execution
   - Shows file reads, searches, writes in real-time
   - Detects sub-agent orchestration

2. **PostToolUse** - Fires after each tool completes
   - Reports tool failures with error messages
   - Tracks success/failure rates

3. **SubagentStop** - Fires when sub-agent completes
   - Provides deterministic phase boundaries
   - Reports duration, tool count, file operations
   - Eliminates need for file polling
   - Tracks completion of all 5 phases (Phase 5 only if --target-url provided)

### Progress Tracking

The `ProgressTracker` class maintains:
- Current phase context
- Tool usage counter
- Set of files read/written
- Sub-agent call stack
- Phase timing information

### Performance Impact

Streaming mode has minimal performance overhead:
- ~2-5% additional latency from hook processing
- Minimal API cost overhead
- Slightly higher memory for progress tracking (~1-2 MB)

### Debug Mode

Add `--debug` flag for maximum verbosity:

```bash
promptheus scan . --debug
```

This shows:
- Agent narration (thinking process)
- Real-time cost updates
- Detailed error messages
- Hook execution traces

## When Progress Tracking Helps Most

### Especially Useful For:
✅ Large codebases (1000+ files)  
✅ Long-running scans (>5 minutes)  
✅ Production security audits  
✅ CI/CD pipelines (progress visibility)  
✅ Debugging or monitoring scans  
✅ Understanding what the scanner is analyzing

### Output Control:
- Use `--quiet` for minimal output
- Use `--debug` for maximum verbosity with agent narration
- Use `--format json` for machine-readable output

## Implementation Details

### Progress Tracking Features

| Feature | Implementation |
|---------|----------------|
| Phase detection | ✅ Deterministic (SubagentStop hook) |
| Tool visibility | ✅ Real-time (PreToolUse hook) |
| Sub-agent tracking | ✅ Automatic lifecycle events |
| File operations | ✅ Visible (reads/writes) |
| Cost updates | ✅ Real-time (debug mode) |
| Agent narration | ✅ Available (debug mode) |
| DAST phase | ⚠️ Optional (only with --target-url flag) |
| Performance overhead | ~2-5% additional latency |
| Memory usage | Low (~1-2 MB extra)

---

## Implementation Details

### Architecture

Streaming mode migrates from the simple `query()` API to `ClaudeSDKClient` with hooks for real-time event capture.

**Key Components:**

1. **Scanner Class** (`packages/core/promptheus/scanner/scanner.py`)
   - Uses `ClaudeSDKClient` with hooks for real-time events
   - Implements three hooks for complete visibility
   - Returns `ScanResult` with all vulnerability findings
   - Compatible with all existing agent definitions

2. **ProgressTracker Class**
   - Tracks tool usage, files read/written, sub-agent stack
   - Smart output formatting with emojis and colors
   - Phase timing and statistics
   - Debug mode for agent narration

3. **Hook System** (Closures)

```python
# PreToolUse - Fires before any tool executes
async def pre_tool_hook(input_data: dict, tool_use_id: str, ctx: dict):
    tool_name = input_data.get("tool_name")
    tool_input = input_data.get("tool_input", {})
    tracker.on_tool_start(tool_name, tool_input)
    return {}

# PostToolUse - Fires after tool completes
async def post_tool_hook(input_data: dict, tool_use_id: str, ctx: dict):
    tool_name = input_data.get("tool_name")
    is_error = input_data.get("tool_response", {}).get("is_error", False)
    tracker.on_tool_complete(tool_name, not is_error)
    return {}

# SubagentStop - DETERMINISTIC phase completion marker
async def subagent_hook(input_data: dict, tool_use_id: str, ctx: dict):
    agent_name = input_data.get("agent_name")
    duration_ms = input_data.get("duration_ms", 0)
    tracker.on_subagent_stop(agent_name, duration_ms)
    return {}
```

**Why Closures?** Hooks are defined as closures inside `scan()` method to capture the `tracker` instance. This avoids needing a `hook_context` parameter (which isn't supported by the SDK).

---
