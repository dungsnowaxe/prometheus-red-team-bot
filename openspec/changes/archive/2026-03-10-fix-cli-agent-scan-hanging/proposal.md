# Fix CLI Agent Scan Hanging

## Why

The CLI agent scan mode (`promptheus scan --mode agent --target-path <path>`) hangs indefinitely without completing or showing results. The scan processes files and executes tools but stops waiting for completion messages that never arrive, leaving users with no feedback and forcing manual termination.

## What Changes

- **Add timeout mechanism** to prevent indefinite hanging in `receive_messages()` loop
- **Add completion detection** to detect when all subagents have finished even without explicit ResultMessage
- **Add graceful error handling** with informative messages when scan hangs or times out
- **Add debug logging** to help diagnose future issues with message streaming

## Capabilities

### New Capabilities

- `scan-timeout`: Timeout mechanism for agent scan operations to prevent indefinite hanging

### Modified Capabilities

- `agent-scan`: Add timeout and completion detection to existing agent scan behavior

## Impact

- **Affected code**: `apps/cli/main.py`, `promptheus/scanner/scanner.py`
- **User experience**: Scans will complete with clear error messages instead of hanging indefinitely
- **API changes**: None - this is an internal fix with no external API changes
- **Dependencies**: No new dependencies required
