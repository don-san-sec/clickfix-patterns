.PHONY: test help setup docs

VENV := .venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip

help:
	@echo "ClickFix Attack Detection Patterns"
	@echo ""
	@echo "Targets:"
	@echo "  make setup - create venv, install dependencies and git hooks"
	@echo "  make test  - run pattern tests"
	@echo "  make docs  - generate documentation"

$(VENV)/bin/activate:
	python3 -m venv $(VENV)

setup: $(VENV)/bin/activate
	$(PIP) install -r requirements.txt
	@echo "Installing git pre-commit hook..."
	@mkdir -p .git/hooks
	@printf '#!/bin/sh\nmake test\n' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Done! Pre-commit hook will run 'make test' before each commit."

test: $(VENV)/bin/activate
	$(PYTHON) scripts/test/run.py

docs: $(VENV)/bin/activate
	$(PYTHON) scripts/docs/generate.py
