# PROMPTHEUS Namespace Cleanse Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove the legacy namespace/runtime references from the PROMPTHEUS codebase and restore a coherent `promptheus` namespace for the new agent-scanning foundation.

**Architecture:** Keep the legacy payload engine and the new agent-scanning stack under the same top-level `promptheus` package. Replace cross-package imports and human-facing runtime strings in the scanner/model/prompt layers, then rebuild the small config contract that the scanner stack expects.

**Tech Stack:** Python, pytest, Rich, Pydantic, Claude Agent SDK

---

### Task 1: Lock Namespace Expectations With Tests

**Files:**
- Create: `tests/test_promptheus_namespace_cleanse.py`
- Test: `tests/test_promptheus_namespace_cleanse.py`

**Step 1: Write the failing tests**

```python
def test_repository_contains_no_legacy_namespace_references():
    ...

def test_promptheus_config_exposes_agent_runtime_contract():
    ...
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_promptheus_namespace_cleanse.py -v`
Expected: FAIL because legacy namespace references still exist and `promptheus.config` lacks the agent config contract.

**Step 3: Write minimal implementation**

```python
# Replace legacy imports/strings with PROMPTHEUS equivalents.
# Add config facade/classes expected by scanner and agent modules.
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/test_promptheus_namespace_cleanse.py -v`
Expected: PASS

### Task 2: Rename Runtime Imports and Messages

**Files:**
- Modify: `promptheus/agents/__init__.py`
- Modify: `promptheus/agents/definitions.py`
- Modify: `promptheus/diff/__init__.py`
- Modify: `promptheus/diff/context.py`
- Modify: `promptheus/models/__init__.py`
- Modify: `promptheus/models/result.py`
- Modify: `promptheus/models/scan_output.py`
- Modify: `promptheus/prompts/loader.py`
- Modify: `promptheus/reporters/__init__.py`
- Modify: `promptheus/reporters/json_reporter.py`
- Modify: `promptheus/reporters/markdown_reporter.py`
- Modify: `promptheus/scanner/__init__.py`
- Modify: `promptheus/scanner/artifacts.py`
- Modify: `promptheus/scanner/chain_analysis.py`
- Modify: `promptheus/scanner/hooks.py`
- Modify: `promptheus/scanner/pr_review_flow.py`
- Modify: `promptheus/scanner/pr_review_merge.py`
- Modify: `promptheus/scanner/scanner.py`
- Modify: `promptheus/scanner/triage.py`

**Step 1: Replace package imports**

```python
from promptheus.models.result import ScanResult
from promptheus.prompts.loader import load_prompt
```

**Step 2: Replace user-facing branding**

```python
"Write rejected by PROMPTHEUS validation."
".promptheus/PR_VULNERABILITIES.json"
```

**Step 3: Keep artifact naming decisions explicit**

```python
# Keep artifact directory naming explicit and normalized to `.promptheus`.
```

**Step 4: Run focused tests**

Run: `pytest tests/test_promptheus_namespace_cleanse.py -v`
Expected: PASS

### Task 3: Rebuild Agent Runtime Config Contract

**Files:**
- Modify: `promptheus/config.py`
- Test: `tests/test_promptheus_namespace_cleanse.py`

**Step 1: Define the missing contract**

```python
class LanguageConfig:
    SUPPORTED_LANGUAGES = {...}

class ScanConfig:
    BLOCKED_DB_TOOLS = (...)
```

**Step 2: Add config facade methods**

```python
class RuntimeConfig:
    def get_agent_model(self, agent_name: str, cli_override: str | None = None) -> str: ...
    def get_max_turns(self) -> int: ...
    def get_pr_review_attempts(self) -> int: ...
    def get_pr_review_timeout_seconds(self) -> int: ...
```

**Step 3: Export the facade**

```python
config = RuntimeConfig()
```

**Step 4: Run focused tests**

Run: `pytest tests/test_promptheus_namespace_cleanse.py -v`
Expected: PASS

### Task 4: Add Dependency Declarations For Existing Runtime Imports

**Files:**
- Modify: `pyproject.toml`

**Step 1: Add missing runtime dependencies**

```toml
dependencies = [
  "claude-agent-sdk",
  "pydantic>=2",
]
```

**Step 2: Verify packaging config remains valid**

Run: `pytest tests/test_promptheus_namespace_cleanse.py -v`
Expected: PASS

### Task 5: Verify the Foundation Slice

**Files:**
- Test: `tests/test_promptheus_namespace_cleanse.py`

**Step 1: Run focused namespace tests**

Run: `pytest tests/test_promptheus_namespace_cleanse.py -v`
Expected: PASS

**Step 2: Run lint diagnostics on touched files**

Run: IDE diagnostics
Expected: No new errors in edited files

**Step 3: Decide next slice**

```text
Next: scanner import coverage and CLI integration.
```
