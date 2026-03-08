# PROMPTHEUS Test Suite

This directory contains the comprehensive test suite for PROMPTHEUS agent-based security scanning.

## Test Structure

```
tests/
├── __init__.py              # Test package initialization
├── conftest.py              # Shared fixtures and configuration
├── test_scanner.py          # Scanner tests (Task 2)
├── test_orchestrator.py     # Agent orchestration tests (Task 3)
├── test_progress.py         # Progress tracking tests (Task 4)
├── test_hooks.py            # Security hooks tests (Task 5)
├── test_artifacts.py        # Artifact management tests (Task 6)
├── test_dast.py             # DAST validation tests (Task 7)
├── test_skills.py           # Skill system tests (Task 8)
├── test_pr_review.py        # PR review flow tests (Task 9)
├── test_models.py           # Data models tests (Task 10)
├── test_errors.py           # Error handling tests (Task 11)
├── test_config.py           # Configuration tests (Task 13)
├── test_cli.py              # CLI integration tests (Task 14)
├── test_dashboard.py        # Dashboard integration tests (Task 15)
├── integration/             # Integration tests (Task 16)
│   ├── test_e2e_agent.py
│   ├── test_e2e_dast.py
│   └── test_e2e_hybrid.py
└── property/                # Property-based tests (optional)
    ├── test_properties_scanner.py
    ├── test_properties_chains.py
    └── test_properties_validation.py
```

## Running Tests

### All Tests
```bash
make test
# or
pytest
```

### Unit Tests Only
```bash
make test-unit
# or
pytest -m unit
```

### Integration Tests Only
```bash
make test-integration
# or
pytest -m integration
```

### End-to-End Tests Only
```bash
make test-e2e
# or
pytest -m e2e
```

### Property-Based Tests Only
```bash
make test-property
# or
pytest -m property
```

### With Coverage Report
```bash
make test-cov
# or
pytest --cov=promptheus --cov=apps --cov-report=html
```

## Test Markers

Tests are marked with the following markers:

- `@pytest.mark.unit` - Unit tests (fast, isolated)
- `@pytest.mark.integration` - Integration tests (slower, multiple components)
- `@pytest.mark.e2e` - End-to-end tests (slowest, full workflows)
- `@pytest.mark.slow` - Slow running tests
- `@pytest.mark.dast` - DAST-related tests
- `@pytest.mark.property` - Property-based tests using Hypothesis

## Test Fixtures

Common fixtures are defined in `conftest.py`:

### Repository Fixtures
- `minimal_repo` - Small test repo with 1-2 vulnerabilities
- `medium_repo` - Medium test repo with 5-10 vulnerabilities
- `large_repo` - Large test repo with 20+ vulnerabilities

### Mock Fixtures
- `mock_claude_client` - Mock Claude SDK client
- `mock_claude_response` - Mock Claude API response
- `mock_http_server` - Mock HTTP server for DAST

### Artifact Fixtures
- `valid_security_md` - Valid SECURITY.md content
- `valid_threat_model_json` - Valid THREAT_MODEL.json content
- `valid_vulnerabilities_json` - Valid VULNERABILITIES.json content
- `valid_dast_validation_json` - Valid DAST_VALIDATION.json content

### Configuration Fixtures
- `scan_config_legacy` - Legacy mode configuration
- `scan_config_agent` - Agent mode configuration
- `scan_config_agent_with_dast` - Agent mode with DAST
- `scan_config_hybrid` - Hybrid mode configuration

## Test-First Development

All tests follow the red-green-refactor cycle:

1. **Red**: Write a failing test that defines desired behavior
2. **Green**: Write minimal code to make the test pass
3. **Refactor**: Improve code while keeping tests green

## Coverage Goals

- Core scanner logic: 90%+
- Agent orchestration: 85%+
- Progress tracking: 80%+
- Artifact management: 90%+
- Skill loading: 85%+
- Overall: 85%+

## Writing New Tests

When adding new tests:

1. Add appropriate markers (`@pytest.mark.unit`, etc.)
2. Use descriptive test names: `test_<what>_<when>_<expected>`
3. Follow Given-When-Then structure in docstrings
4. Use fixtures from `conftest.py` when possible
5. Mock external dependencies (Claude API, HTTP calls)
6. Keep tests isolated and independent

Example:
```python
import pytest

@pytest.mark.unit
def test_scanner_validates_config_when_dast_enabled_without_url():
    """Test scanner rejects DAST config without target URL.
    
    GIVEN: Configuration with DAST enabled but no target URL
    WHEN: Scanner is initialized
    THEN: ValidationError is raised with descriptive message
    """
    # Test implementation
```

## Continuous Integration

Tests run automatically on:
- Every commit (unit tests)
- Pull requests (all tests)
- Main branch merges (all tests + coverage report)

## Troubleshooting

### Tests Fail with API Errors
- Ensure `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` are set to test values
- Check that `setup_test_env` fixture is working

### Coverage Too Low
- Run `pytest --cov-report=html` to see uncovered lines
- Add tests for missing branches and edge cases

### Slow Tests
- Use `pytest -m "not slow"` to skip slow tests during development
- Consider mocking expensive operations

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [Hypothesis documentation](https://hypothesis.readthedocs.io/)
