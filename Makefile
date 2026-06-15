.DEFAULT_GOAL := all

CONTAINER_ENGINE ?= $(shell \
	if command -v docker >/dev/null 2>&1; then echo docker; \
	elif command -v podman >/dev/null 2>&1; then echo podman; \
	elif command -v container >/dev/null 2>&1; then echo container; \
	else echo docker; fi)

IMAGE_NAME ?= mulder
IMAGE_TAG  ?= dev

.PHONY: all install lint format typecheck test precommit container-build container-run clean

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

container-build:
	$(CONTAINER_ENGINE) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

container-run:
	$(CONTAINER_ENGINE) run -it --privileged \
		-v $(EVIDENCE_DIR):/evidence:ro \
		-v $(CASE_DIR):/home/mulder/.mulder/cases \
		$(IMAGE_NAME):$(IMAGE_TAG)

clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

all: lint format typecheck test
