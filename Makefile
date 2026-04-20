.PHONY: lint test typecheck security ci dev fmt clean

lint:
	ruff check domino/ tests/
	ruff format --check domino/ tests/

fmt:
	ruff format domino/ tests/
	ruff check --fix domino/ tests/

test:
	pytest --cov=domino --cov-report=term-missing tests/

typecheck:
	mypy domino/

security:
	bandit -r domino/ -q
	pip-audit

ci: lint typecheck test security

dev:
	pip install -e ".[dev]"

clean:
	rm -rf build/ dist/ *.egg-info .coverage .mypy_cache .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
