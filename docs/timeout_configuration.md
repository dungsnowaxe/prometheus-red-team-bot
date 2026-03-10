# Agent Scan Timeout Configuration

## Overview

The PROMPTHEUS agent mode has a configurable timeout to prevent indefinite hanging when scans encounter issues. The timeout ensures that scans terminate with clear progress information instead of hanging silently.

## Configuration

### Environment Variable

```
PROMPTHEUS_SCAN_TIMEOUT_SECONDS
```

**Default:** `3600` (1 hour)
**Type:** Integer (seconds) or `0` to disable

### Usage Examples

```bash
# Default: 1 hour timeout
promptheus scan --mode agent --target-path /path/to/repo

# Increase to 2 hours for large repositories
export PROMPTHEUS_SCAN_TIMEOUT_SECONDS=7200
promptheus scan --mode agent --target-path /path/to/large/repo

# Disable timeout (infinite wait) - not recommended
export PROMPTHEUS_SCAN_TIMEOUT_SECONDS=0
promptheus scan --mode agent --target-path /path/to/repo

# Short timeout for quick testing (5 minutes)
export PROMPTHEUS_SCAN_TIMEOUT_SECONDS=300
promptheus scan --mode agent --target-path /path/to/small/repo
```

## Timeout Behavior

When a timeout occurs:

1. **Scan terminates** with detailed progress information
2. **Error message shows:**
   - Elapsed time
   - Tools executed
   - Files processed
   - Subagents completed
3. **Suggestion** to run with `--debug` for more details
4. **Partial results** may be available in `.promptheus/` directory

### Example Timeout Error

```
❌ Scan timeout after 3600.0s (limit: 3600s)
   Progress: 156 tools executed, 87 files read, 3/5 subagents completed
   💡 Try again with --debug for more details, or increase PROMPTHEUS_SCAN_TIMEOUT_SECONDS
```

## Completion Detection

The scanner has two completion mechanisms:

1. **ResultMessage** from Claude Agent SDK (primary)
2. **Subagent tracking** (fallback) - completes when all expected subagents finish

The timeout is a safety net that ensures termination even when both mechanisms fail.

## Choosing a Timeout Value

| Repository Size | Recommended Timeout | Notes |
|----------------|---------------------|-------|
| Small (< 100 files) | 600-1200s (10-20 min) | Quick scans |
| Medium (100-1000 files) | 1800-3600s (30-60 min) | Default setting |
| Large (1000-5000 files) | 7200s (2 hours) | Complex codebases |
| Very Large (> 5000 files) | 10800s (3 hours) or disable | Enterprise projects |

## Troubleshooting

### Scan times out but appears to be making progress

**Solution:** Increase the timeout value
```bash
export PROMPTHEUS_SCAN_TIMEOUT_SECONDS=7200  # 2 hours
```

### Scan times out immediately

**Possible causes:**
- Configuration issue (API keys, model access)
- Network connectivity problem
- Claude SDK connection failure

**Solution:** Run with `--debug` flag to identify the issue
```bash
promptheus scan --mode agent --target-path /path/to/repo --debug
```

### Scan completes without timeout but results are incomplete

**Possible causes:**
- Some subagents failed silently
- API rate limiting
- Insufficient max_turns configuration

**Solution:** Check `.promptheus/` directory for partial results and logs

## Related Configuration

Other scan limits that work alongside timeout:

- `PROMPTHEUS_MAX_SCAN_FILES` - File count limit (requires `--confirm-large-scan`)
- `PROMPTHEUS_MAX_REPO_MB` - Repository size limit in MB (requires `--confirm-large-scan`)
- `PROMPTHEUS_MAX_TURNS` - Maximum agent conversation turns (default: 50)
