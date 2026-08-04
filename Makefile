.PHONY: test lint typecheck check

test:
	pytest

lint:
	ruff check .

typecheck:
	mypy src

check: test lint typecheck
	python -m compileall -q src tests
