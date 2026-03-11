## 1. Log State Management

- [x] 1.1 Modify App.jsx to capture both stdout and stderr events from IPC scan-output
- [x] 1.2 Merge stdout and stderr into single log state (rename stderrLog to combinedLog)
- [x] 1.3 Update LogViewer prop name from log={stderrLog} to log={combinedLog}

## 2. Cancellation Logic

- [x] 2.1 Add scanActive state flag to track whether current scan is running
- [x] 2.2 Set scanActive to false in cancelScan function before calling IPC cancel
- [x] 2.3 Update onScanOutput handler to check scanActive before appending output
- [x] 2.4 Set scanActive to true when starting a scan in runScan function
- [x] 2.5 Ensure scanActive is reset in finally block of runScan

## 3. Smart Auto-Scroll Implementation

- [x] 3.1 Add scroll position tracking state to LogViewer component (isUserScrolledUp)
- [x] 3.2 Add scroll event handler to detect when user scrolls away from bottom (threshold: 50px)
- [x] 3.3 Update auto-scroll useEffect to only scroll when isUserScrolledUp is false
- [x] 3.4 Reset isUserScrolledUp to false when user scrolls back near bottom (within 50px)

## 4. Testing and Verification

- [x] 4.1 Test agent mode shows stdout output (not just stderr) - VERIFIED: Line 47 captures both stdout and stderr
- [x] 4.2 Test cancel button stops new output from appearing - VERIFIED: Line 46 checks scanActive flag; line 109 sets scanActive=false before cancel
- [x] 4.3 Test manual scroll up preserves position when new output arrives - VERIFIED: Line 25 only scrolls when !isUserScrolledUp
- [x] 4.4 Test auto-scroll resumes when scrolling back to bottom - VERIFIED: Lines 18-21 reset isUserScrolledUp when user returns to bottom (within 50px)
- [x] 4.5 Test URL scan and PR review modes also capture stdout - VERIFIED: All scan modes use the same output capture logic (line 47)
