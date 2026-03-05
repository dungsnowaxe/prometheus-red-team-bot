#!/usr/bin/env bash
# Build and validate PROMPTHEUS (core + apps).
# Usage: ./scripts/build.sh   or   bash scripts/build.sh
# Uses .venv if present, else current python/pip.
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ -d ".venv" ]; then
  PIP=".venv/bin/pip"
  PYTHON=".venv/bin/python"
else
  PIP="pip"
  PYTHON="python"
fi

echo "==> Installing in editable mode..."
"$PIP" install -e . -q

echo "==> Building wheel..."
"$PIP" install build -q
"$PYTHON" -m build --wheel -q -o dist/
ls -la dist/*.whl

echo "==> Validation: CLI..."
"$PYTHON" -m promptheus --help > /dev/null
promptheus --help > /dev/null 2>/dev/null || true
echo "    CLI OK"

echo "==> Validation: API app..."
"$PYTHON" -c "
from apps.api.main import app
assert app
routes = [r.path for r in app.routes if hasattr(r, 'path')]
assert '/health' in routes
assert '/scan' in routes
print('    API OK')
"

echo "==> Validation: Dashboard (import only)..."
"$PYTHON" -c "
from apps.dashboard.main import run
assert callable(run)
print('    Dashboard OK')
"

echo "==> Validation: Slack bot (compile only; full run requires SLACK_BOT_TOKEN + SLACK_APP_TOKEN)..."
"$PYTHON" -m py_compile apps/slack_bot/main.py
echo "    Slack bot OK"

echo "==> Validation: promptheus core..."
"$PYTHON" -c "
from promptheus.core.engine import RedTeamEngine
from promptheus.core.attacks import load_payloads
p = load_payloads()
assert isinstance(p, list)
print('    Core OK')
"

echo ""
echo "Build and validation passed."
