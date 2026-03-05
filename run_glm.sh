#!/bin/bash

# PROMPTHEUS Red-Team Bot - GLM Runner
# Usage: ./run_glm.sh [target_url]

# Activate virtual environment
source "$(dirname "$0")/.venv/bin/activate"

# GLM (Zhipu AI) Configuration
export PROMPTHEUS_JUDGE_BASE_URL=https://api.z.ai/api/coding/paas/v4

# Prompt for API key
read -p "Enter your GLM API key: " API_KEY
export PROMPTHEUS_JUDGE_API_KEY="$API_KEY"

# Prompt for model (with default)
read -p "Enter model [glm-4-flash]: " MODEL
export PROMPTHEUS_JUDGE_MODEL="${MODEL:-glm-4-flash}"

# Target URL (default to httpbin for testing)
TARGET_URL="${1:-https://contest.birdeye.fun}"

echo ""
echo "Running PROMPTHEUS scan with GLM ($PROMPTHEUS_JUDGE_MODEL)..."
echo "Target: $TARGET_URL"
echo ""

# Run the scan
python -m promptheus scan -u "$TARGET_URL"
