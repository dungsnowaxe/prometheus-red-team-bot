# Implementation Plan: PROMPTHEUS Agent-Based Security Scanning

## Overview

This implementation plan focuses on implementing agent-based security scanning capabilities in PROMPTHEUS. The core scanner, agents, hooks, and models need to be built and tested. This plan covers testing, implementation, CLI/dashboard integration, configuration, and documentation.

**Implementation Language**: Python

**Test-First Approach**: All tasks follow red-green-refactor cycle - write tests first, verify they fail, implement to pass, then refactor.

## Tasks

- [ ] 1. Test Infrastructure Setup
  - Set up pytest configuration with coverage reporting
  - Configure test fixtures for mock Claude SDK client
  - Create test data repositories (minimal, medium, large)
  - Set up mock HTTP server for DAST testing
  - Configure hypothesis for property-based testing
  - _Requirements: Testing Strategy, Mock Strategy_

- [ ] 2. Core Scanner Tests
  - [ ] 2.1 Write unit tests for Scanner class
    - Test scanner initialization with different modes
    - Test mode validation (legacy, agent, hybrid)
    - Test configuration validation
    - Test scan execution flow
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  
  - [ ] 2.2 Implement Scanner test fixes
    - Fix any issues discovered by tests
    - Ensure all scanner modes work correctly
    - _Requirements: 1.1-1.7_
  
  - [ ]* 2.3 Write property test for mode consistency
    - **Property 1: Mode Consistency**
    - **Validates: Requirements 1.1, 1.7, 18.2**
  
  - [ ]* 2.4 Write property test for cost accumulation
    - **Property 15: Cost Accumulation**
    - **Validates: Requirements 1.6**

- [ ] 3. Agent Orchestration Tests
  - [ ] 3.1 Write unit tests for AgentOrchestrator
    - Test agent phase ordering
    - Test phase failure handling
    - Test resume functionality
    - Test single agent execution
    - Test skip agents functionality
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 2.6, 2.7_
  
  - [ ] 3.2 Implement orchestrator test fixes
    - Fix any issues discovered by tests
    - Ensure phase ordering is correct
    - _Requirements: 2.1-2.7_
  
  - [ ]* 3.3 Write property test for phase ordering
    - **Property 2: Phase Ordering**
    - **Validates: Requirements 2.1, 2.2**
  
  - [ ]* 3.4 Write property test for artifact completeness
    - **Property 3: Artifact Completeness**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.6, 6.7**

- [ ] 4. Progress Tracking Tests
  - [ ] 4.1 Write unit tests for ProgressTracker
    - Test tool usage tracking
    - Test file operation tracking
    - Test phase timing
    - Test debug mode output
    - Test summary generation
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8_
  
  - [ ] 4.2 Implement progress tracker test fixes
    - Fix any issues discovered by tests
    - Ensure accurate tracking
    - _Requirements: 4.1-4.8_
  
  - [ ]* 4.3 Write property test for progress accuracy
    - **Property 6: Progress Tracking Accuracy**
    - **Validates: Requirements 4.2, 4.3, 4.4, 4.5**

- [ ] 5. Security Hooks Tests
  - [ ] 5.1 Write unit tests for security hooks
    - Test DAST database tool blocking
    - Test infrastructure directory exclusion
    - Test DAST write restrictions
    - Test PR review write restrictions
    - Test repository boundary enforcement
    - Test pathless grep scope injection
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9_
  
  - [ ] 5.2 Implement security hook test fixes
    - Fix any issues discovered by tests
    - Ensure all security boundaries are enforced
    - _Requirements: 5.1-5.9_
  
  - [ ]* 5.3 Write property test for repository boundary enforcement
    - **Property 9: Repository Boundary Enforcement**
    - **Validates: Requirements 5.6**
  
  - [ ]* 5.4 Write property test for infrastructure exclusion
    - **Property 11: Infrastructure Directory Exclusion**
    - **Validates: Requirements 5.2, 5.3**

- [ ] 6. Artifact Management Tests
  - [ ] 6.1 Write unit tests for ArtifactManager
    - Test artifact writing and reading
    - Test JSON validation
    - Test auto-fix for common JSON issues
    - Test artifact existence checks
    - Test cleanup operations
    - _Requirements: 6.1-6.10_
  
  - [ ] 6.2 Implement artifact manager test fixes
    - Fix any issues discovered by tests
    - Ensure artifact validation works correctly
    - _Requirements: 6.1-6.10_
  
  - [ ]* 6.3 Write property test for JSON validation
    - **Property 19: JSON Artifact Validation**
    - **Validates: Requirements 6.8, 6.9**

- [ ] 7. DAST Validation Tests
  - [ ] 7.1 Write unit tests for DAST validation
    - Test skill-to-CWE matching
    - Test validation status assignment
    - Test HTTP test execution
    - Test evidence capture
    - Test skill syncing
    - _Requirements: 7.1-7.10_
  
  - [ ] 7.2 Implement DAST validation test fixes
    - Fix any issues discovered by tests
    - Ensure validation logic is correct
    - _Requirements: 7.1-7.10_
  
  - [ ]* 7.3 Write property test for DAST validation consistency
    - **Property 4: DAST Validation Consistency**
    - **Validates: Requirements 7.4, 7.5, 7.6, 7.7, 7.8**
  
  - [ ]* 7.4 Write property test for skill-CWE mapping
    - **Property 8: Skill-CWE Mapping**
    - **Validates: Requirements 7.4, 8.1, 8.6**

- [ ] 8. Skill System Tests
  - [ ] 8.1 Write unit tests for SkillLoader
    - Test skill discovery
    - Test skill loading
    - Test skill validation
    - Test skill syncing
    - Test CWE mapping
    - _Requirements: 8.1-8.7_
  
  - [ ] 8.2 Implement skill loader test fixes
    - Fix any issues discovered by tests
    - Ensure skill loading works correctly
    - _Requirements: 8.1-8.7_
  
  - [ ]* 8.3 Write property test for skill structure preservation
    - **Property 18: Skill Structure Preservation**
    - **Validates: Requirements 8.5**

- [ ] 9. PR Review Flow Tests
  - [ ] 9.1 Write unit tests for PR review components
    - Test diff parsing
    - Test context extraction
    - Test hypothesis generation
    - Test finding merging
    - Test baseline filtering
    - _Requirements: 9.1-9.10_
  
  - [ ] 9.2 Implement PR review test fixes
    - Fix any issues discovered by tests
    - Ensure PR review flow works correctly
    - _Requirements: 9.1-9.10_
  
  - [ ]* 9.3 Write property test for chain deduplication
    - **Property 16: Chain Deduplication**
    - **Validates: Requirements 9.8, 10.4**
  
  - [ ]* 9.4 Write property test for baseline filtering
    - **Property 17: Baseline Filtering**
    - **Validates: Requirements 9.9**

- [ ] 10. Data Models Tests
  - [ ] 10.1 Write unit tests for data models
    - Test SecurityIssue model validation
    - Test ScanResult model methods
    - Test severity filtering
    - Test validation status filtering
    - Test issue counting methods
    - _Requirements: 12.1-12.8_
  
  - [ ] 10.2 Implement data model test fixes
    - Fix any issues discovered by tests
    - Ensure model methods work correctly
    - _Requirements: 12.1-12.8_
  
  - [ ]* 10.3 Write property test for severity ordering
    - **Property 5: Severity Ordering**
    - **Validates: Requirements 12.6, 12.8**

- [ ] 11. Error Handling Tests
  - [ ] 11.1 Write unit tests for error scenarios
    - Test phase failure handling
    - Test missing prerequisites
    - Test DAST target unreachable
    - Test invalid skill structure
    - Test configuration validation
    - Test artifact parsing errors
    - _Requirements: 13.1-13.8_
  
  - [ ] 11.2 Implement error handling test fixes
    - Fix any issues discovered by tests
    - Ensure error messages are clear
    - _Requirements: 13.1-13.8_
  
  - [ ]* 11.3 Write property test for error capture
    - **Property 20: Error Capture on Phase Failure**
    - **Validates: Requirements 13.1, 13.2**

- [ ] 12. Checkpoint - Core Tests Complete
  - Ensure all core component tests pass
  - Review test coverage (target: 85%+)
  - Ask the user if questions arise

- [ ] 13. Configuration System
  - [ ] 13.1 Write tests for config.py
    - Test AgentConfig initialization
    - Test environment variable loading
    - Test per-agent model overrides
    - Test excluded directories configuration
    - Test validation rules
    - _Requirements: 19.1-19.7_
  
  - [ ] 13.2 Implement config.py
    - Create AgentConfig dataclass
    - Implement environment variable support
    - Add per-agent model override logic
    - Add excluded directories per language
    - Implement configuration validation
    - _Requirements: 19.1-19.7_
  
  - [ ]* 13.3 Write property test for configuration validation
    - **Property 14: Configuration Validation Before Execution**
    - **Validates: Requirements 1.2, 13.4**

- [ ] 14. CLI Integration
  - [ ] 14.1 Write tests for CLI updates
    - Test --mode flag handling
    - Test --dast and --target-url flags
    - Test --resume-from and --subagent flags
    - Test --debug and --quiet flags
    - Test help text and examples
    - Test error handling
    - _Requirements: 1.1-1.7, 18.1-18.7_
  
  - [ ] 14.2 Update apps/cli/main.py
    - Add --mode flag with choices (legacy, agent, hybrid)
    - Add --dast flag and --dast-url option
    - Add --resume-from and --subagent options
    - Add --debug and --quiet flags
    - Update help text with examples
    - Integrate with UnifiedScanner
    - Add progress display
    - _Requirements: 1.1-1.7, 18.1-18.7_
  
  - [ ]* 14.3 Write integration tests for CLI
    - Test CLI commands end-to-end
    - Test flag combinations
    - Test error scenarios

- [ ] 15. Dashboard Integration
  - [ ] 15.1 Write tests for dashboard updates
    - Test mode selector UI
    - Test real-time progress display
    - Test DAST configuration panel
    - Test results display for agent mode
    - _Requirements: 1.1-1.7, 4.1-4.8_
  
  - [ ] 15.2 Update apps/dashboard/main.py
    - Add mode selector dropdown
    - Add real-time progress display widget
    - Add DAST configuration panel
    - Update results display for agent mode
    - Add streaming progress updates
    - _Requirements: 1.1-1.7, 4.1-4.8_
  
  - [ ]* 15.3 Write integration tests for dashboard
    - Test dashboard UI components
    - Test mode switching
    - Test progress updates

- [ ] 16. Integration Tests
  - [ ] 16.1 Write end-to-end integration tests
    - Test legacy mode scan on test repository
    - Test agent mode scan on test repository
    - Test hybrid mode scan on test repository
    - Test DAST validation with mock HTTP server
    - Test PR review flow with test diff
    - Test resume functionality
    - Test error recovery scenarios
    - _Requirements: All requirements_
  
  - [ ] 16.2 Fix integration test failures
    - Debug and fix any integration issues
    - Ensure all workflows work end-to-end
    - _Requirements: All requirements_

- [ ] 17. Checkpoint - Integration Complete
  - Ensure all integration tests pass
  - Verify CLI and dashboard work correctly
  - Ask the user if questions arise

- [ ] 18. Documentation
  - [ ] 18.1 Update README.md
    - Add agent mode overview
    - Add installation instructions for new dependencies
    - Add quick start examples for all modes
    - Add DAST setup instructions
    - Add troubleshooting section
    - _Requirements: 18.1-18.7_
  
  - [ ] 18.2 Create AGENT_MODE_GUIDE.md
    - Explain agent-based scanning workflow
    - Document each agent phase
    - Provide configuration examples
    - Explain artifact structure
    - Document skill system
    - _Requirements: 2.1-2.7, 3.1-3.11, 8.1-8.7_
  
  - [ ] 18.3 Create MIGRATION_GUIDE.md
    - Explain changes from legacy to agent mode
    - Provide migration steps
    - Document breaking changes (if any)
    - Provide example configurations
    - _Requirements: 18.1-18.7_
  
  - [ ] 18.4 Update USAGE.md
    - Document new CLI flags
    - Add agent mode examples
    - Add DAST examples
    - Add PR review examples
    - Document configuration options
    - _Requirements: 1.1-1.7, 7.1-7.10, 9.1-9.10_
  
  - [ ] 18.5 Create API documentation
    - Document Scanner API
    - Document AgentOrchestrator API
    - Document configuration options
    - Document data models
    - _Requirements: All requirements_

- [ ] 19. Performance Testing and Optimization
  - [ ] 19.1 Write performance benchmarks
    - Benchmark scan duration for different repo sizes
    - Benchmark memory usage
    - Benchmark API costs
    - _Requirements: Performance Considerations_
  
  - [ ] 19.2 Optimize performance bottlenecks
    - Implement caching where appropriate
    - Optimize file operations
    - Optimize artifact parsing
    - _Requirements: Performance Considerations_
  
  - [ ]* 19.3 Write performance regression tests
    - Test scan duration stays within bounds
    - Test memory usage stays within bounds

- [ ] 20. Backward Compatibility Verification
  - [ ] 20.1 Write backward compatibility tests
    - Test legacy mode produces identical results
    - Test existing adapters still work
    - Test existing payloads.json format
    - Test existing CLI flags
    - _Requirements: 18.1-18.7_
  
  - [ ] 20.2 Fix backward compatibility issues
    - Fix any breaking changes
    - Ensure legacy mode is unchanged
    - _Requirements: 18.1-18.7_
  
  - [ ]* 20.3 Write property test for backward compatibility
    - **Property 7: Backward Compatibility**
    - **Validates: Requirements 18.1, 18.2, 18.3, 18.4, 18.5, 18.6**

- [ ] 21. Final Checkpoint - Complete System Test
  - Run full test suite with coverage report
  - Verify all requirements are met
  - Test all modes on real repositories
  - Verify documentation is complete and accurate
  - Ask the user if questions arise

## Notes

- Tasks marked with `*` are optional property-based tests that can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Test-first approach: write tests before implementation for all new code
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- Integration tests validate end-to-end workflows
- Most scanner components are already implemented - focus is on testing and integration
