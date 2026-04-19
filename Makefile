.DEFAULT_GOAL := all

.PHONY: all install lint format typecheck test precommit build docker clean

install:
	uv pip install -e ".[dev]"

lint:
	ruff check src/

format:
	ruff format src/

typecheck:
	mypy src/mulder

test:
	pytest tests/ -v

precommit:
	pre-commit run --all-files

build:
	python -m build

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

all: lint format typecheck test
