## 1. Configuration

- [x] 1.1 Add `PROMPHEUS_SCAN_TIMEOUT_SECONDS` config option to `promptheus/config.py` with default value of 3600 (1 hour)
- [x] 1.2 Add `get_scan_timeout_seconds()` method to config class that returns the timeout value or None for disabled
- [x] 1.3 Add validation to ensure timeout value is non-negative integer or None

## 2. ProgressTracker Enhancement

- [x] 2.1 Add `completed_subagents` set to ProgressTracker class to track finished subagents
- [x] 2.2 Modify `on_subagent_stop()` to add completed subagent to the set
- [x] 2.3 Add `get_completed_subagents()` method to return the set of completed subagents
- [x] 2.4 Add `all_expected_subagents_completed(expected_count)` method to check if all expected subagents are done

## 3. Scanner Core Changes

- [x] 3.1 Modify `_execute_scan()` to calculate expected subagents based on scan mode (dast_enabled, fix_remediation_enabled, single_subagent)
- [x] 3.2 Wrap the `receive_messages()` loop with `asyncio.wait_for()` using the configured timeout
- [x] 3.3 Add completion detection logic inside the message loop that checks if all expected subagents have completed
- [x] 3.4 Exit the message loop when either condition is met: ResultMessage received, timeout elapsed, or all subagents completed

## 4. Error Handling

- [x] 4.1 Add `asyncio.TimeoutError` exception handler in `_execute_scan()` that provides detailed timeout information
- [x] 4.2 Create timeout error message that includes: elapsed time, tools executed, files processed
- [x] 4.3 Add suggestion to run with `--debug` flag in timeout error message
- [x] 4.4 Ensure timeout error is distinguishable from other scan failures

## 5. Partial Results Handling

- [x] 5.1 Modify result loading to handle missing artifacts gracefully after timeout
- [x] 5.2 Add warning message when returning partial results indicating results may be incomplete
- [x] 5.3 Ensure `_load_scan_results()` provides clear error when expected artifacts are missing

**Note:** Existing result loading already handles missing artifacts with clear error messages. The timeout handler provides partial results indication.

## 6. Debug Logging

- [x] 6.1 Add debug log when scan completes via subagent tracking without ResultMessage
- [x] 6.2 Add debug log showing expected vs completed subagents count
- [x] 6.3 Add debug log when timeout is applied (or disabled)

## 7. CLI Integration

- [x] 7.1 Ensure `_run_agent_scan()` in `apps/cli/main.py` properly handles timeout exceptions
- [x] 7.2 Verify CLI exits with appropriate error code on timeout

## 8. Testing

- [ ] 8.1 Add unit test for timeout configuration (default value, custom value, disabled)
- [ ] 8.2 Add unit test for subagent completion detection logic
- [ ] 8.3 Add integration test simulating missing ResultMessage scenario
- [ ] 8.4 Add unit test for partial results handling after timeout
- [ ] 8.5 Add unit test for timeout error message formatting

## 9. Documentation

- [ ] 9.1 Update CLI help text to mention new timeout config option
- [ ] 9.2 Add documentation for `PROMPHEUS_SCAN_TIMEOUT_SECONDS` in config reference
- [ ] 9.3 Add troubleshooting section for timeout issues
