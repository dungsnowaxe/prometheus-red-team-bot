"""
Pytest configuration and shared fixtures for PROMPTHEUS tests.
"""
import os
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import Mock, MagicMock

import pytest


# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def minimal_repo(temp_dir: Path) -> Path:
    """Create a minimal test repository with 1-2 vulnerabilities."""
    repo_path = temp_dir / "minimal_repo"
    repo_path.mkdir()
    
    # Create a simple Python file with SQL injection vulnerability
    (repo_path / "app.py").write_text("""
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
""")
    
    # Create a requirements file
    (repo_path / "requirements.txt").write_text("sqlite3\n")
    
    return repo_path


@pytest.fixture
def medium_repo(temp_dir: Path) -> Path:
    """Create a medium test repository with 5-10 vulnerabilities."""
    repo_path = temp_dir / "medium_repo"
    repo_path.mkdir()
    
    # Create multiple files with various vulnerabilities
    (repo_path / "auth.py").write_text("""
import hashlib

def authenticate(username, password):
    # Weak hashing algorithm (MD5)
    hashed = hashlib.md5(password.encode()).hexdigest()
    # SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    return execute_query(query)
""")
    
    (repo_path / "api.py").write_text("""
import os

def read_file(filename):
    # Path traversal vulnerability
    filepath = os.path.join('/var/data', filename)
    with open(filepath, 'r') as f:
        return f.read()

def execute_command(cmd):
    # Command injection vulnerability
    os.system(f"echo {cmd}")
""")
    
    (repo_path / "config.py").write_text("""
# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"
SECRET_KEY = "my-secret-key"
""")
    
    return repo_path


@pytest.fixture
def large_repo(temp_dir: Path) -> Path:
    """Create a large test repository with 20+ vulnerabilities."""
    repo_path = temp_dir / "large_repo"
    repo_path.mkdir()
    
    # Create directory structure
    (repo_path / "src").mkdir()
    (repo_path / "src" / "auth").mkdir()
    (repo_path / "src" / "api").mkdir()
    (repo_path / "src" / "utils").mkdir()
    
    # Add multiple files with vulnerabilities
    files = {
        "src/auth/login.py": """
import jwt
def login(username, password):
    # Weak JWT secret
    token = jwt.encode({'user': username}, 'secret', algorithm='HS256')
    return token
""",
        "src/auth/session.py": """
import pickle
def load_session(data):
    # Insecure deserialization
    return pickle.loads(data)
""",
        "src/api/endpoints.py": """
from flask import request
def upload_file():
    # Unrestricted file upload
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')
""",
        "src/utils/crypto.py": """
from Crypto.Cipher import DES
def encrypt(data, key):
    # Weak encryption (DES)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
""",
    }
    
    for filepath, content in files.items():
        full_path = repo_path / filepath
        full_path.write_text(content)
    
    return repo_path


# ============================================================================
# Mock Claude SDK Fixtures
# ============================================================================

@pytest.fixture
def mock_claude_client() -> Mock:
    """Create a mock Claude SDK client for testing without API calls."""
    client = Mock()
    
    # Mock successful agent execution
    client.run_agent = Mock(return_value={
        "status": "success",
        "artifacts": ["SECURITY.md"],
        "duration_ms": 1000,
        "tools_used": 5,
    })
    
    # Mock agent creation
    client.create_agent = Mock(return_value=Mock(id="test-agent-123"))
    
    return client


@pytest.fixture
def mock_claude_response() -> dict:
    """Create a mock Claude API response."""
    return {
        "id": "msg_123",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "text",
                "text": "Analysis complete. Found 3 vulnerabilities."
            }
        ],
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 1000,
            "output_tokens": 500
        }
    }


# ============================================================================
# Mock HTTP Server Fixtures
# ============================================================================

@pytest.fixture
def mock_http_server() -> Mock:
    """Create a mock HTTP server for DAST testing."""
    server = Mock()
    
    # Mock successful HTTP response
    server.get = Mock(return_value=Mock(
        status_code=200,
        text="<html><body>Success</body></html>",
        headers={"Content-Type": "text/html"}
    ))
    
    # Mock vulnerable endpoint
    server.post = Mock(return_value=Mock(
        status_code=200,
        text="User: admin",
        headers={"Content-Type": "text/plain"}
    ))
    
    return server


# ============================================================================
# Artifact Fixtures
# ============================================================================

@pytest.fixture
def valid_security_md() -> str:
    """Valid SECURITY.md artifact content."""
    return """# Security Assessment

## Architecture Overview
This is a Python web application using Flask framework.

## Components
- Authentication module
- API endpoints
- Database layer

## Security Posture
Medium risk - several vulnerabilities identified.
"""


@pytest.fixture
def valid_threat_model_json() -> str:
    """Valid THREAT_MODEL.json artifact content."""
    return """{
  "threats": [
    {
      "id": "T001",
      "category": "Injection",
      "title": "SQL Injection in user authentication",
      "severity": "HIGH",
      "affected_components": ["auth.py"],
      "attack_scenario": "Attacker can bypass authentication",
      "vulnerability_types": ["CWE-89"],
      "mitigation": "Use parameterized queries"
    }
  ]
}"""


@pytest.fixture
def valid_vulnerabilities_json() -> str:
    """Valid VULNERABILITIES.json artifact content."""
    return """{
  "vulnerabilities": [
    {
      "id": "V001",
      "severity": "HIGH",
      "title": "SQL Injection in get_user function",
      "description": "User input is directly concatenated into SQL query",
      "file_path": "app.py",
      "line_number": 7,
      "cwe_id": "CWE-89",
      "recommendation": "Use parameterized queries with placeholders"
    }
  ]
}"""


@pytest.fixture
def valid_dast_validation_json() -> str:
    """Valid DAST_VALIDATION.json artifact content."""
    return """{
  "validations": [
    {
      "vulnerability_id": "V001",
      "cwe_id": "CWE-89",
      "skill_used": "sql-injection-basic",
      "validation_status": "VALIDATED",
      "evidence": "Successfully extracted database contents",
      "test_details": {
        "url": "http://localhost:3000/api/user",
        "method": "POST",
        "status": 200,
        "response_snippet": "admin:password123"
      }
    }
  ]
}"""


# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture
def scan_config_legacy() -> dict:
    """Legacy mode scan configuration."""
    return {
        "mode": "legacy",
        "target_url": "https://api.example.com/chat",
        "enable_streaming": False
    }


@pytest.fixture
def scan_config_agent(minimal_repo: Path) -> dict:
    """Agent mode scan configuration."""
    return {
        "mode": "agent",
        "target_path": str(minimal_repo),
        "enable_dast": False,
        "enable_streaming": True,
        "max_turns": 50
    }


@pytest.fixture
def scan_config_agent_with_dast(minimal_repo: Path) -> dict:
    """Agent mode with DAST scan configuration."""
    return {
        "mode": "agent",
        "target_path": str(minimal_repo),
        "enable_dast": True,
        "dast_target_url": "http://localhost:3000",
        "dast_timeout": 120,
        "enable_streaming": True
    }


@pytest.fixture
def scan_config_hybrid(minimal_repo: Path) -> dict:
    """Hybrid mode scan configuration."""
    return {
        "mode": "hybrid",
        "target_url": "https://api.example.com/chat",
        "target_path": str(minimal_repo),
        "enable_dast": True,
        "dast_target_url": "http://localhost:3000",
        "enable_streaming": True
    }


# ============================================================================
# Environment Setup
# ============================================================================

@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Set up test environment variables."""
    # Mock API keys to avoid accidental real API calls
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-456")
    
    # Set test mode
    monkeypatch.setenv("PROMPTHEUS_TEST_MODE", "true")


# ============================================================================
# Cleanup Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_artifacts(temp_dir: Path):
    """Clean up test artifacts after each test."""
    yield
    # Cleanup happens automatically with temp_dir fixture
