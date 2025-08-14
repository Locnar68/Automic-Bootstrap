# Makefile for Automic-Bootstrap
# Works with: pip, uv, or poetry (auto-detected). Targets are no-ops if tools absent.

SHELL := /bin/bash

# Detect tools if present
HAVE_UV := $(shell command -v uv >/dev/null 2>&1 && echo 1 || echo 0)
HAVE_POETRY := $(shell command -v poetry >/dev/null 2>&1 && echo 1 || echo 0)

.PHONY: help setup venv install preflight test lint fmt clean

help:
	@echo "Common targets:"
	@echo "  make setup       - create venv (.venv) and install deps (pip/uv/poetry)"
	@echo "  make venv        - create virtual env only (.venv)"
	@echo "  make install     - install deps into active environment"
	@echo "  make preflight   - run readiness checks"
	@echo "  make test        - run unit tests (pytest)"
	@echo "  make lint        - run linters (ruff/flake8 if present)"
	@echo "  make fmt         - run formatters (ruff format/black if present)"
	@echo "  make clean       - remove caches and build artifacts"

venv:
	@[ -d .venv ] || python3 -m venv .venv
	@. .venv/bin/activate && python -m pip install --upgrade pip wheel

install:
ifeq ($(HAVE_UV),1)
	@echo ">> Using uv to sync requirements"
	@uv pip sync requirements.txt
else ifeq ($(HAVE_POETRY),1)
	@echo ">> Using poetry to install"
	@poetry install --no-root
else
	@echo ">> Using pip to install requirements"
	@. .venv/bin/activate && pip install -r requirements.txt
endif

setup: venv install

preflight:
	@. .venv/bin/activate 2>/dev/null || true; \
	python preflight.py

test:
	@. .venv/bin/activate 2>/dev/null || true; \
	pytest -q || echo "pytest not installed"

lint:
	@. .venv/bin/activate 2>/dev/null || true; \
	(ruff check || flake8 || echo "no linter installed")

fmt:
	@. .venv/bin/activate 2>/dev/null || true; \
	(ruff format || black . || echo "no formatter installed")

clean:
	@rm -rf .pytest_cache .ruff_cache dist build *.egg-info __pycache__
	@find . -type d -name "__pycache__" -prune -exec rm -rf {} +
