#!/usr/bin/env python3
"""ClickFix Pattern Test Runner."""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from yaml_parser import parse_yaml_pattern

# ANSI color codes
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
NC = "\033[0m"  # No Color
BOLD = "\033[1m"


class TestResult:
    def __init__(self):
        self.total_patterns = 0
        self.passed_patterns = 0
        self.failed_patterns = 0
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.failures = []


def test_command(pattern: re.Pattern, command: str, should_match: bool) -> bool:
    matches = pattern.search(command) is not None
    return matches if should_match else not matches


def test_pattern(yaml_file: Path, result: TestResult) -> bool:
    pattern_name = yaml_file.stem

    try:
        pattern_data = parse_yaml_pattern(yaml_file)
    except Exception as e:
        print(f"{RED}✗{NC} {pattern_name}: Failed to parse YAML: {e}")
        return False

    patterns = []
    if pattern_data.get("patterns"):
        for p in pattern_data["patterns"]:
            try:
                compiled = re.compile(p["pattern"], re.IGNORECASE | re.DOTALL)
                patterns.append(compiled)
            except re.error as e:
                print(f"{RED}✗{NC} {pattern_name} ({p['name']}): Invalid regex: {e}")
                return False
    elif pattern_data.get("pattern"):
        try:
            compiled = re.compile(pattern_data["pattern"], re.IGNORECASE | re.DOTALL)
            patterns.append(compiled)
        except re.error as e:
            print(f"{RED}✗{NC} {pattern_name}: Invalid regex: {e}")
            return False
    else:
        print(f"{RED}✗{NC} {pattern_name}: Missing pattern")
        return False

    malicious_count = 0
    benign_count = 0
    malicious_passed = 0
    benign_passed = 0
    malicious_failed = 0
    benign_failed = 0

    for line in pattern_data["malicious"]:
        if not line.strip():
            continue

        malicious_count += 1
        result.total_tests += 1

        matched = any(test_command(p, line, True) for p in patterns)
        if matched:
            malicious_passed += 1
            result.passed_tests += 1
        else:
            malicious_failed += 1
            result.failed_tests += 1
            result.failures.append(
                f"{RED}✗{NC} {pattern_name}: FALSE NEGATIVE - Should block: {YELLOW}{line[:80]}{NC}"
            )

    for line in pattern_data["benign"]:
        if not line.strip():
            continue

        benign_count += 1
        result.total_tests += 1

        matched = any(test_command(p, line, True) for p in patterns)
        if not matched:
            benign_passed += 1
            result.passed_tests += 1
        else:
            benign_failed += 1
            result.failed_tests += 1
            result.failures.append(
                f"{RED}✗{NC} {pattern_name}: FALSE POSITIVE - Should allow: {YELLOW}{line[:80]}{NC}"
            )

    total_pattern_tests = malicious_count + benign_count
    passed_pattern_tests = malicious_passed + benign_passed
    failed_pattern_tests = malicious_failed + benign_failed

    if failed_pattern_tests == 0 and total_pattern_tests > 0:
        print(
            f"{GREEN}✓{NC} {BOLD}{pattern_name}{NC} ({GREEN}{passed_pattern_tests}{NC}/{total_pattern_tests}) - "
            f"Malicious: {malicious_passed}/{malicious_count}, Benign: {benign_passed}/{benign_count}"
        )
        result.passed_patterns += 1
        return True
    else:
        print(
            f"{RED}✗{NC} {BOLD}{pattern_name}{NC} ({RED}{failed_pattern_tests} FAILED{NC}/{total_pattern_tests}) - "
            f"Malicious: {malicious_passed}/{malicious_count}, Benign: {benign_passed}/{benign_count}"
        )
        result.failed_patterns += 1
        return False


def main():
    print(f"{BOLD}{CYAN}{'━' * 60}{NC}")
    print(f"{BOLD}{CYAN}  ClickFix Pattern Test Suite{NC}")
    print(f"{BOLD}{CYAN}{'━' * 60}{NC}")
    print()

    patterns_dir = Path(__file__).parent.parent / "patterns"

    result = TestResult()

    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        pattern_arg = sys.argv[1]

        if not pattern_arg.endswith(".yaml"):
            pattern_arg = pattern_arg + ".yaml"

        yaml_file = patterns_dir / pattern_arg
        if not yaml_file.exists():
            print(f"{RED}Error:{NC} Pattern file not found: {pattern_arg}")
            sys.exit(1)

        result.total_patterns = 1
        print(f"{BLUE}Testing pattern:{NC} {yaml_file.stem}")
        print()
        test_pattern(yaml_file, result)
    else:
        print(f"{BLUE}Testing all patterns...{NC}")
        print()
        yaml_files = (
            sorted(patterns_dir.glob("critical-*.yaml"))
            + sorted(patterns_dir.glob("high-*.yaml"))
            + sorted(patterns_dir.glob("medium-*.yaml"))
        )

        result.total_patterns = len(yaml_files)

        for yaml_file in yaml_files:
            test_pattern(yaml_file, result)

    print()
    print(f"{BOLD}{CYAN}{'━' * 60}{NC}")
    print(f"{BOLD}{CYAN}  Test Summary{NC}")
    print(f"{BOLD}{CYAN}{'━' * 60}{NC}")
    print()

    if result.failed_patterns == 0:
        print(
            f"{GREEN}✓{NC} Patterns: {GREEN}{BOLD}{result.passed_patterns}{NC}/{result.total_patterns} passed"
        )
    else:
        print(
            f"{RED}✗{NC} Patterns: {GREEN}{result.passed_patterns}{NC}/"
            f"{RED}{BOLD}{result.failed_patterns} failed{NC}/{result.total_patterns} total"
        )

    if result.failed_tests == 0:
        print(
            f"{GREEN}✓{NC} Tests:    {GREEN}{BOLD}{result.passed_tests}{NC}/{result.total_tests} passed"
        )
    else:
        print(
            f"{RED}✗{NC} Tests:    {GREEN}{result.passed_tests}{NC}/"
            f"{RED}{BOLD}{result.failed_tests} failed{NC}/{result.total_tests} total"
        )

    if result.total_tests > 0:
        pass_percent = (result.passed_tests * 100) // result.total_tests
        print(f"   Success Rate: {BOLD}{pass_percent}%{NC}")

    if result.failures:
        print()
        print(f"{BOLD}{RED}Failed Test Details:{NC}")
        print(f"{RED}{'━' * 60}{NC}")
        for failure in result.failures:
            print(f"  {failure}")

    print()
    print(f"{BOLD}{CYAN}{'━' * 60}{NC}")

    if result.failed_tests == 0 and result.total_tests > 0:
        print(f"{GREEN}{BOLD}All tests passed!{NC}")
        sys.exit(0)
    else:
        print(f"{RED}{BOLD}Some tests failed.{NC}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        print("ClickFix Pattern Test Runner")
        print()
        print("Usage:")
        print("  ./run_tests.py              # Run all pattern tests")
        print("  ./run_tests.py PATTERN      # Run specific pattern file")
        print()
        print("Examples:")
        print("  ./run_tests.py                          # Test all patterns")
        print("  ./run_tests.py critical-01-base64-powershell")
        print()
        sys.exit(0)

    main()
