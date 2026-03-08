.PHONY: help install install-dev test test-unit test-integration test-e2e test-property test-cov clean lint format type-check

help:
	@echo "PROMPTHEUS Development Commands"
	@echo "================================"
	@echo "install          Install production dependencies"
	@echo "install-dev      Install development dependencies"
	@echo "test             Run all tests"
	@echo "test-unit        Run unit tests only"
	@echo "test-integration Run integration tests only"
	@echo "test-e2e         Run end-to-end tests only"
	@echo "test-property    Run property-based tests only"
	@echo "test-cov         Run tests with coverage report"
	@echo "lint             Run linting checks"
	@echo "format           Format code with black"
	@echo "type-check       Run type checking with mypy"
	@echo "clean            Clean up generated files"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,test]"
	pip install -r requirements-dev.txt

test:
	pytest

test-unit:
	pytest -m unit

test-integration:
	pytest -m integration

test-e2e:
	pytest -m e2e

test-property:
	pytest -m property

test-cov:
	pytest --cov=promptheus --cov=apps --cov-report=html --cov-report=term-missing

lint:
	ruff check promptheus apps tests

format:
	black promptheus apps tests

type-check:
	mypy promptheus apps

clean:
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
