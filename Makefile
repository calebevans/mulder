.DEFAULT_GOAL := all

CONTAINER_ENGINE ?= $(shell \
	if command -v docker >/dev/null 2>&1; then echo docker; \
	elif command -v podman >/dev/null 2>&1; then echo podman; \
	elif command -v container >/dev/null 2>&1; then echo container; \
	else echo docker; fi)

IMAGE_NAME ?= mulder
IMAGE_TAG  ?= dev

.PHONY: all install hooks lint format typecheck test precommit build dist-check assets-lock container-build container-run clean

install:
	uv pip install -e ".[dev]"

# Run once after cloning. The installed git hook checks the *staged* set at
# commit time, which is the only local check a brand-new file cannot slip past
# (see the note on `precommit` below).
hooks:
	pre-commit install

# lint/format/typecheck are fast inner-loop targets, not the gate: they cover
# less than CI does. `make precommit` is the gate. ruff's scope here matches
# the pre-commit hooks, which pass no path restriction and so cover tests/ too.
lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

# CI runs mypy --strict over src/ *and* tests/ inside pre-commit's own isolated
# environment. This target is the narrower src-only pass; use `make precommit`
# before pushing.
typecheck:
	mypy src/mulder

test:
	pytest tests/ -v

# `pre-commit run --all-files` enumerates files with `git ls-files`, which lists
# tracked files only -- a newly written file that has not been `git add`-ed is
# invisible to every hook, so this target would report a clean pass and CI would
# then fail on it. Passing the tracked *and* untracked-not-ignored set closes
# that gap.
precommit:
	pre-commit run --files $$(git ls-files -co --exclude-standard)

# Maintainer chore, never CI: downloads every digest-pinnable asset and
# rewrites src/mulder/assets/assets.lock. Re-run it in the same PR as any
# Dockerfile version bump -- tests/test_manifest_parity.py fails otherwise.
assets-lock:
	uv run python -m mulder.assets.lockgen

build:
	uv build

# There is deliberately no `publish` target: uploading to PyPI is irreversible
# and happens only through the human-approved `pypi` environment in publish.yml.
dist-check: build
	uvx twine check --strict dist/*

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

# The default goal is the gate CI actually enforces: the pre-commit hooks
# (ruff, ruff-format, mypy --strict over src/ and tests/) plus the test suite.
all: precommit test
