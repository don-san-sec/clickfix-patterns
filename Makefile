.PHONY: test help

help:
	@echo "ClickFix Attack Detection Patterns"
	@echo ""
	@echo "Targets:"
	@echo "  make test        - run pattern tests"

test:
	python3 scripts/run_tests.py
