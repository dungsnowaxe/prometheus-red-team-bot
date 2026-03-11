## Context

The desktop app's CLI Output window provides real-time visibility into scan operations. Currently, three issues impede user experience:

1. **Missing stdout**: Only `stderr` events are captured in `App.jsx`, but the Promptheus CLI writes most agent-mode progress output to `stdout`
2. **Zombie output after cancel**: The `onScanOutput` listener remains active after cancellation, continuing to accumulate log events
3.Forced auto-scroll**: `LogViewer.jsx` unconditionally scrolls to bottom on every log update, preventing manual scroll review

The existing `scan.js` correctly streams both stdout and stderr to the frontend via IPC, but the frontend only consumes stderr. Electron's IPC model and existing scroll-area component provide the building blocks for fixes.

## Goals / Non-Goals

**Goals:**
- Capture and display both stdout and stderr streams from CLI subprocess
- Stop log accumulation when scan is cancelled
- Allow users to scroll up and review earlier output without auto-scroll interruption
- Auto-scroll to bottom when new output arrives and user is already at bottom

**Non-Goals:**
- Changing the CLI's output format or behavior
- Modifying the Electron subprocess spawning logic
- Adding log filtering or search capabilities

## Decisions

### 1. Combined stdout+stderr log state

**Decision**: Merge stdout and stderr into a single log state rather than maintaining separate buffers.

**Rationale**: The CLI's output is temporally ordered—mixing stdout and stderr preserves sequence. Separate buffers would require coordinated scrolling and complicate the UX. A single string with interleaved output matches user expectations for terminal-like behavior.

**Alternatives considered**:
- Separate stdout/stderr panels: Rejected—adds UI complexity and loses ordering context
- Styling differences for stdout vs stderr: Rejected—out of scope, could be added later

### 2. Cancellation via scan ID tracking

**Decision**: Track active scan state with a flag to ignore output events after cancellation.

**Rationale**: Electron's IPC `send()` continues delivering events even after process kill. A running flag on each scan listener (or global scan active state) provides a simple guard. When cancelled, set flag to false—output handler checks flag before appending to log.

**Alternatives considered**:
- Cleanup IPC listener on cancel: Rejected—React useEffect cleanup would be complex; listener is global
- Send explicit "cancelled" event from main process: Rejected—adds IPC complexity for simple state

### 3. Smart auto-scroll using scroll position detection

**Decision**: Track whether user has manually scrolled away from bottom using the scroll-area component's scroll state. Only auto-scroll when already at bottom.

**Rationale**: When user scrolls up to read earlier logs, they've expressed intent to view history. Auto-scrolling steals control and frustrates users. Detecting "near bottom" preserves auto-scroll for passive monitoring while respecting manual navigation.

**Alternatives considered**:
- Toggle button for auto-scroll on/off: Rejected—requires manual management, smart default is better
- Never auto-scroll: Rejected—defeats purpose of live output monitoring

## Risks / Trade-offs

**Risk**: Scroll detection may be unreliable across platforms (macOS/Windows/Linux) due to ScrollArea component internals.

**Mitigation**: Use tolerance threshold (e.g., within 50px of bottom counts as "at bottom") to account for pixel rounding differences.

**Trade-off**: Combined stdout+stderr loses distinction between output streams.

**Acceptable because**: Users care about message content and sequence, not which stream carried the data. Future enhancement could add ANSI color codes for visual distinction.

**Risk**: Output events after cancel may still briefly arrive before flag check.

**Mitigation**: Set cancellation flag synchronously in `cancelScan()` before calling IPC. Check flag first in output handler.
