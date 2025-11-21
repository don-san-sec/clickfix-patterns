#!/usr/bin/env python3
"""
ClickFix Pattern Test Runner
Tests regex patterns against known good/bad commands
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

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


def parse_yaml_pattern(yaml_file: Path) -> Dict:
    """Parse a simple YAML pattern file. No external dependencies.
    Supports both single pattern and multiple patterns format."""
    content = yaml_file.read_text()

    pattern_data = {
        "name": "",
        "severity": "",
        "description": "",
        "pattern": "",
        "patterns": [],  # Support for multiple patterns
        "malicious": [],
        "benign": [],
    }

    lines = content.splitlines()
    current_section = None
    multiline_value = []
    current_pattern = None
    in_patterns_list = False

    for line in lines:
        stripped = line.strip()

        # Skip empty lines
        if not stripped:
            continue

        # Handle list items
        if stripped.startswith("- "):
            item = stripped[2:].strip()

            # Check if this is a pattern definition in patterns list
            if current_section == "patterns":
                # Start of a new pattern object
                if item.startswith("name:"):
                    if current_pattern:
                        pattern_data["patterns"].append(current_pattern)
                    current_pattern = {
                        "name": item[5:].strip(),
                        "pattern": "",
                        "description": "",
                    }
                    in_patterns_list = True
                continue

            # Remove quotes if present for test cases
            if item.startswith('"') and item.endswith('"'):
                item = item[1:-1].replace('\\"', '"')

            if current_section == "malicious":
                pattern_data["malicious"].append(item)
            elif current_section == "benign":
                pattern_data["benign"].append(item)
            continue

        # Handle key-value pairs
        if ":" in line and not line.startswith("  "):
            # Save previous multiline value
            if multiline_value and current_section:
                if current_section == "pattern" and not in_patterns_list:
                    pattern_data[current_section] = "\n".join(multiline_value).strip()
                multiline_value = []

            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if key in ["name", "severity"]:
                pattern_data[key] = value
                current_section = None
                in_patterns_list = False
            elif key in ["description", "pattern"]:
                current_section = key
                if value and value != "|" and value != ">":
                    multiline_value = [value]
            elif key == "patterns":
                current_section = key
                in_patterns_list = True
            elif key in ["malicious", "benign"]:
                current_section = key
                in_patterns_list = False
        # Handle indented content for patterns list
        elif line.startswith("  ") and in_patterns_list and current_pattern:
            key_val = line.strip()
            if ":" in key_val:
                key, _, value = key_val.partition(":")
                key = key.strip()
                value = value.strip()
                if key == "pattern":
                    current_pattern["pattern"] = value
                elif key == "description":
                    current_pattern["description"] = value
        # Handle multiline content
        elif (
            current_section in ["description", "pattern"]
            and line.startswith(" ")
            and not in_patterns_list
        ):
            multiline_value.append(line.strip())

    # Save last multiline value
    if multiline_value and current_section:
        pattern_data[current_section] = "\n".join(multiline_value).strip()

    # Save last pattern in patterns list
    if current_pattern:
        pattern_data["patterns"].append(current_pattern)

    return pattern_data


def test_command(pattern: re.Pattern, command: str, should_match: bool) -> bool:
    """Test a single command against a pattern."""
    matches = pattern.search(command) is not None

    if should_match:
        return matches  # True positive if matches, False negative if not
    else:
        return not matches  # True negative if doesn't match, False positive if matches


def test_pattern(yaml_file: Path, result: TestResult) -> bool:
    """Test a single pattern from YAML file."""
    pattern_name = yaml_file.stem

    try:
        pattern_data = parse_yaml_pattern(yaml_file)
    except Exception as e:
        print(f"{RED}✗{NC} {pattern_name}: Failed to parse YAML: {e}")
        return False

    # Get pattern(s) - support both single pattern and multiple patterns
    patterns = []
    if pattern_data.get("patterns"):
        # Multiple patterns format
        for p in pattern_data["patterns"]:
            try:
                compiled = re.compile(p["pattern"], re.IGNORECASE | re.DOTALL)
                patterns.append(compiled)
            except re.error as e:
                print(f"{RED}✗{NC} {pattern_name} ({p['name']}): Invalid regex: {e}")
                return False
    elif pattern_data.get("pattern"):
        # Single pattern format
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

    # Test malicious commands (should match)
    for line in pattern_data["malicious"]:
        if not line.strip():
            continue

        malicious_count += 1
        result.total_tests += 1

        # Test against all patterns - any match is a pass
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

    # Test benign commands (should NOT match)
    for line in pattern_data["benign"]:
        if not line.strip():
            continue

        benign_count += 1
        result.total_tests += 1

        # Test against all patterns - no match is a pass
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

    # Calculate results
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

    # Get patterns directory
    patterns_dir = Path(__file__).parent.parent / "patterns"

    result = TestResult()

    # Check for --all flag
    include_experimental = "--all" in sys.argv

    # Check if specific pattern requested
    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        pattern_arg = sys.argv[1]

        # Add .yaml extension if not present
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
        # Test all patterns
        if include_experimental:
            print(f"{BLUE}Testing all patterns (including experimental)...{NC}")
            print()
            yaml_files = (
                sorted(patterns_dir.glob("critical-*.yaml"))
                + sorted(patterns_dir.glob("high-*.yaml"))
                + sorted(patterns_dir.glob("medium-*.yaml"))
                + sorted(patterns_dir.glob("experimental-*.yaml"))
            )
        else:
            print(f"{BLUE}Testing all patterns (excluding experimental)...{NC}")
            print()
            yaml_files = (
                sorted(patterns_dir.glob("critical-*.yaml"))
                + sorted(patterns_dir.glob("high-*.yaml"))
                + sorted(patterns_dir.glob("medium-*.yaml"))
            )
            # Filter out experimental patterns
            yaml_files = [f for f in yaml_files if "experimental" not in f.name]

        result.total_patterns = len(yaml_files)

        for yaml_file in yaml_files:
            test_pattern(yaml_file, result)

    # Print summary
    print()
    print(f"{BOLD}{CYAN}{'━' * 60}{NC}")
    print(f"{BOLD}{CYAN}  Test Summary{NC}")
    print(f"{BOLD}{CYAN}{'━' * 60}{NC}")
    print()

    # Pattern summary
    if result.failed_patterns == 0:
        print(
            f"{GREEN}✓{NC} Patterns: {GREEN}{BOLD}{result.passed_patterns}{NC}/{result.total_patterns} passed"
        )
    else:
        print(
            f"{RED}✗{NC} Patterns: {GREEN}{result.passed_patterns}{NC}/"
            f"{RED}{BOLD}{result.failed_patterns} failed{NC}/{result.total_patterns} total"
        )

    # Test summary
    if result.failed_tests == 0:
        print(
            f"{GREEN}✓{NC} Tests:    {GREEN}{BOLD}{result.passed_tests}{NC}/{result.total_tests} passed"
        )
    else:
        print(
            f"{RED}✗{NC} Tests:    {GREEN}{result.passed_tests}{NC}/"
            f"{RED}{BOLD}{result.failed_tests} failed{NC}/{result.total_tests} total"
        )

    # Calculate percentages
    if result.total_tests > 0:
        pass_percent = (result.passed_tests * 100) // result.total_tests
        print(f"   Success Rate: {BOLD}{pass_percent}%{NC}")

    # Print failed test details if any
    if result.failures:
        print()
        print(f"{BOLD}{RED}Failed Test Details:{NC}")
        print(f"{RED}{'━' * 60}{NC}")
        for failure in result.failures:
            print(f"  {failure}")

    print()
    print(f"{BOLD}{CYAN}{'━' * 60}{NC}")

    # Exit with appropriate code
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
        print(
            "  ./run_tests.py              # Run all pattern tests (excludes experimental)"
        )
        print("  ./run_tests.py --all        # Run ALL tests including experimental")
        print("  ./run_tests.py PATTERN      # Run specific pattern file")
        print()
        print("Examples:")
        print("  ./run_tests.py                          # Test all patterns")
        print(
            "  ./run_tests.py --all                    # Test all including experimental"
        )
        print("  ./run_tests.py critical-01-base64-powershell")
        print("  ./run_tests.py experimental-high-05-download-commands")
        print()
        print(
            "Note: Experimental patterns require allowlists and are skipped by default."
        )
        print()
        sys.exit(0)

    main()
