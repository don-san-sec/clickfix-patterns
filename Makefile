.PHONY: test test-all help

help:
	@echo "ClickFix Attack Detection Patterns"
	@echo ""
	@echo "Targets:"
	@echo "  make test        - run stable pattern tests (excludes experimental)"
	@echo "  make test-all    - run ALL tests including experimental patterns"

test:
	python3 scripts/run_tests.py

test-all:
	python3 scripts/run_tests.py --all
