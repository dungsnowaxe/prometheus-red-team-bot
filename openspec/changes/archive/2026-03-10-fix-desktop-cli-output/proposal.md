## Why

The desktop app's CLI Output window has three critical bugs that prevent users from effectively monitoring scan progress: (1) only stderr is captured and displayed, missing stdout where most CLI output appears during agent mode; (2) after cancelling a scan, the output continues to receive and display error logs; and (3) the log viewer always auto-scrolls to bottom, preventing users from scrolling up to review earlier output.

## What Changes

- **Capture both stdout and stderr** from CLI subprocess and display all output in the log viewer
- **Stop output streaming** when scan is cancelled to prevent continued log accumulation
- **Add smart auto-scroll behavior** that only scrolls to bottom when user is at the bottom, allowing manual scroll to read earlier logs

## Capabilities

### New Capabilities

- `cli-output-streaming`: Capture and display real-time output from CLI subprocesses including both stdout and stderr streams

- `log-viewer-scroll-control`: Auto-scroll behavior that respects user intent—scrolls to bottom when new output arrives and user is at bottom, but does not interrupt manual scrolling

### Modified Capabilities

- `scan-cancellation`: Properly terminate subprocess output streaming when scan is cancelled

## Impact

**Affected code:**
- `src/components/LogViewer.jsx` - Add scroll-aware auto-scroll behavior
- `src/App.jsx` - Capture stdout events in addition to stderr, stop output listener on cancel
- `src/main.js` - May need event for cancelled state notification

**No external dependencies or API changes** - This is purely frontend behavior fixes for existing Electron IPC communication.
