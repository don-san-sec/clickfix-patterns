.PHONY: test help setup docs

help:
	@echo "ClickFix Attack Detection Patterns"
	@echo ""
	@echo "Targets:"
	@echo "  make setup       - install dependencies"
	@echo "  make test        - run pattern tests"
	@echo "  make docs        - generate documentation"

setup:
	python3 -m pip install -r requirements.txt

test:
	python3 scripts/run_tests.py

docs:
	python3 scripts/generate_docs.py
