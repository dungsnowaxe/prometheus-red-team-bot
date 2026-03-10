# Fix CLI Agent Scan Hanging - Design

## Context

The CLI agent scan uses `ClaudeSDKClient.receive_messages()` to stream progress updates during scans. The scanner waits in an infinite loop for a `ResultMessage` to signal completion:

```python
async for message in client.receive_messages():
    # ... process messages ...
    elif isinstance(message, ResultMessage):
        break  # Exit loop
```

**Current Problem**: When the agent doesn't send a `ResultMessage`, or when the SDK's message stream ends without signaling completion, the loop hangs indefinitely. Users see partial progress (e.g., "80 tools, 27 files read") and then silence.

**Affected Code**:
- `promptheus/scanner/scanner.py` - `_execute_scan()` method, lines 2196-2212
- `apps/cli/main.py` - `_run_agent_scan()` wrapper

**Constraints**:
- Must maintain backward compatibility with existing scan modes
- Must preserve real-time progress tracking functionality
- Cannot modify external `ClaudeSDKClient` behavior

## Goals / Non-Goals

**Goals:**
- Detect scan completion even when `ResultMessage` is missing
- Add configurable timeout to prevent indefinite hanging
- Provide clear error messages when timeout occurs
- Add debug logging to diagnose message streaming issues

**Non-Goals:**
- Modifying the Claude Agent SDK itself
- Changing the scan result format or structure
- Adding new CLI flags or options (use existing config)

## Decisions

### 1. Timeout with `asyncio.wait_for()`

**Decision**: Wrap `receive_messages()` loop with `asyncio.wait_for()` using a configurable timeout.

**Rationale**:
- Standard Python asyncio pattern for timeout handling
- Clean exception handling with `asyncio.TimeoutError`
- Allows graceful exit with informative message

**Alternatives Considered**:
- Manual timeout tracking with `time.time()` - More code, less idiomatic
- Separate monitoring task - Adds complexity without benefit
- Letting SDK handle timeouts - SDK doesn't expose this capability

### 2. Completion Detection via Subagent Tracking

**Decision**: Use `ProgressTracker.subagent_stack` to detect when all expected subagents have completed.

**Rationale**:
- `ProgressTracker` already tracks subagent lifecycle via `SubagentStop` hook
- When subagent_stack is empty after initial population, all agents are done
- Works independently of `ResultMessage` arrival

**Implementation**:
```python
# Track expected subagents at start
expected_subagents = {"assessment", "threat-modeling", "code-review", "report-generator"}
if dast_enabled:
    expected_subagents.add("dast")
if fix_remediation_enabled:
    expected_subagents.add("fix-remediation")

# In message loop, check completion
if completed_subagents >= expected_subagents:
    break
```

### 3. Configurable Timeout via Environment Variable

**Decision**: Add `PROMPHEUS_SCAN_TIMEOUT_SECONDS` config option (default: 3600s = 1 hour).

**Rationale**:
- Large repos can take 30+ minutes to scan
- Users can override for their specific use case
- Consistent with existing config pattern (`PROMPHEUS_MAX_SCAN_FILES`, etc.)

### 4. Enhanced Error Messages

**Decision**: When timeout occurs, show:
- How long the scan ran
- How many tools were executed
- How many files were processed
- Suggestion to try with `--debug` flag

**Rationale**:
- Helps users understand if scan was making progress
- Guides them to get more diagnostic information

## Risks / Trade-offs

**Risk**: Timeout might be too short for legitimate long-running scans on massive codebases.

**Mitigation**:
- Default timeout of 1 hour is generous for most scans
- Configurable via environment variable
- Clear message indicates timeout (not silent failure)

**Risk**: False positive completion detection could exit scan early.

**Mitigation**:
- Only exit when BOTH conditions are met: (timeout OR all subagents complete) AND no active tool execution
- Add warning in debug mode when completing without `ResultMessage`

**Trade-off**: Added complexity vs. reliability.

**Decision**: Reliability wins. Hanging scans are a critical UX issue that must be fixed.

## Migration Plan

1. Add config option `PROMPHEUS_SCAN_TIMEOUT_SECONDS` to `promptheus/config.py`
2. Modify `_execute_scan()` to wrap message loop with timeout and completion detection
3. Add unit tests for timeout scenarios
4. Add integration test with simulated missing `ResultMessage`
5. Roll out with feature flag (default enabled)

**Rollback Strategy**: If timeout causes issues, can set to `None` (infinite) or very large value to disable.

## Open Questions

1. **What should happen to partial results when timeout occurs?**
   - **Decision**: Return whatever results exist (may be incomplete). User can decide if they want to retry.

2. **Should we automatically retry on timeout?**
   - **Decision**: No. User should investigate with `--debug` first. Auto-retry could waste API credits.
