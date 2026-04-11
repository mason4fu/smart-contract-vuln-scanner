.PHONY: setup test lint fmt build clean forge-build forge-test verify eval-smartbugs-reentrancy

# Python environment
setup:
	uv sync
	uv run pre-commit install

test:
	uv run pytest

lint:
	uv run ruff check src/ tests/

fmt:
	uv run ruff format src/ tests/

# Foundry
forge-build:
	forge build

forge-test:
	forge test -v

# Full verification
verify: lint test forge-build forge-test
	@echo "All checks passed."

# Benchmark (optional): SmartBugs Curated reentrancy subset; needs solc installs
eval-smartbugs-reentrancy:
	uv run python scripts/eval_smartbugs_reentrancy.py --csv reports/smartbugs_reentrancy_eval.csv

clean:
	Remove-Item -Recurse -Force -ErrorAction SilentlyContinue out, cache, .pytest_cache, htmlcov
	Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
