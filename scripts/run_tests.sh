#!/bin/bash
# Test runner script for PROMPTHEUS

set -e

echo "================================"
echo "PROMPTHEUS Test Suite"
echo "================================"
echo ""

# Parse arguments
TEST_TYPE="${1:-all}"
COVERAGE="${2:-false}"

case "$TEST_TYPE" in
    unit)
        echo "Running unit tests..."
        pytest -m unit -v
        ;;
    integration)
        echo "Running integration tests..."
        pytest -m integration -v
        ;;
    e2e)
        echo "Running end-to-end tests..."
        pytest -m e2e -v
        ;;
    property)
        echo "Running property-based tests..."
        pytest -m property -v
        ;;
    all)
        if [ "$COVERAGE" = "true" ]; then
            echo "Running all tests with coverage..."
            pytest --cov=promptheus --cov=apps --cov-report=html --cov-report=term-missing -v
        else
            echo "Running all tests..."
            pytest -v
        fi
        ;;
    *)
        echo "Unknown test type: $TEST_TYPE"
        echo "Usage: $0 [unit|integration|e2e|property|all] [coverage]"
        exit 1
        ;;
esac

echo ""
echo "================================"
echo "Tests completed successfully!"
echo "================================"
