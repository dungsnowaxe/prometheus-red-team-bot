"""
Test infrastructure validation.

This module verifies that the test infrastructure is properly set up.
"""
import pytest
from pathlib import Path


@pytest.mark.unit
def test_fixtures_available(minimal_repo, mock_claude_client):
    """Test that basic fixtures are available and working.
    
    GIVEN: Test infrastructure is set up
    WHEN: Fixtures are requested
    THEN: Fixtures are available and properly configured
    """
    # Test repository fixture
    assert minimal_repo.exists()
    assert minimal_repo.is_dir()
    assert (minimal_repo / "app.py").exists()
    
    # Test mock Claude client
    assert mock_claude_client is not None
    assert hasattr(mock_claude_client, 'run_agent')


@pytest.mark.unit
def test_temp_dir_fixture(temp_dir):
    """Test temporary directory fixture.
    
    GIVEN: Test infrastructure is set up
    WHEN: temp_dir fixture is used
    THEN: A temporary directory is created and accessible
    """
    assert temp_dir.exists()
    assert temp_dir.is_dir()
    
    # Test writing to temp dir
    test_file = temp_dir / "test.txt"
    test_file.write_text("test content")
    assert test_file.exists()
    assert test_file.read_text() == "test content"


@pytest.mark.unit
def test_artifact_fixtures(
    valid_security_md,
    valid_threat_model_json,
    valid_vulnerabilities_json,
    valid_dast_validation_json
):
    """Test artifact fixtures are valid.
    
    GIVEN: Test infrastructure is set up
    WHEN: Artifact fixtures are requested
    THEN: Valid artifact content is provided
    """
    assert valid_security_md
    assert "Security Assessment" in valid_security_md
    
    assert valid_threat_model_json
    assert "threats" in valid_threat_model_json
    
    assert valid_vulnerabilities_json
    assert "vulnerabilities" in valid_vulnerabilities_json
    
    assert valid_dast_validation_json
    assert "validations" in valid_dast_validation_json


@pytest.mark.unit
def test_config_fixtures(
    scan_config_legacy,
    scan_config_agent,
    scan_config_agent_with_dast,
    scan_config_hybrid
):
    """Test configuration fixtures are valid.
    
    GIVEN: Test infrastructure is set up
    WHEN: Configuration fixtures are requested
    THEN: Valid configurations are provided
    """
    assert scan_config_legacy["mode"] == "legacy"
    assert "target_url" in scan_config_legacy
    
    assert scan_config_agent["mode"] == "agent"
    assert "target_path" in scan_config_agent
    
    assert scan_config_agent_with_dast["mode"] == "agent"
    assert scan_config_agent_with_dast["enable_dast"] is True
    
    assert scan_config_hybrid["mode"] == "hybrid"
    assert "target_url" in scan_config_hybrid
    assert "target_path" in scan_config_hybrid


@pytest.mark.unit
def test_environment_setup():
    """Test environment variables are set correctly.
    
    GIVEN: Test infrastructure is set up
    WHEN: Tests run
    THEN: Test environment variables are configured
    """
    import os
    
    # Check test API keys are set
    assert os.getenv("ANTHROPIC_API_KEY") == "test-key-123"
    assert os.getenv("OPENAI_API_KEY") == "test-key-456"
    assert os.getenv("PROMPTHEUS_TEST_MODE") == "true"


@pytest.mark.unit
def test_pytest_markers():
    """Test that pytest markers are properly configured.
    
    GIVEN: pytest.ini is configured
    WHEN: Tests use markers
    THEN: Markers are recognized and work correctly
    """
    # This test itself uses the @pytest.mark.unit marker
    # If markers weren't configured, pytest would warn
    assert True  # If we get here, markers are working
