#!/usr/bin/env python3
"""ClickFix Pattern Test Runner."""

import re
import sys
from pathlib import Path

import yaml

PATTERNS_DIR = Path("patterns")


def check_format(pattern: str) -> str | None:
    """Check pattern format. Returns error message or None if valid."""
    p = pattern.strip()
    if p.startswith("(?i)") and not (p.startswith("(?i)(") and p.endswith(")")):
        return (
            "Pattern with (?i) must use (?i)(<pattern>) format to ensure "
            "inline flags apply to all branches and top-level alternation "
            "is not misparsed by some regex engines"
        )
    return None


def compile_patterns(data: dict) -> list[re.Pattern]:
    """Extract and compile regex patterns from pattern data."""
    patterns = []

    if data.get("patterns"):
        for p in data["patterns"]:
            pattern = p["pattern"].strip()
            if err := check_format(pattern):
                raise ValueError(f"{p['name']}: {err}")
            patterns.append(re.compile(pattern, re.DOTALL))
    elif data.get("pattern"):
        pattern = data["pattern"].strip()
        if err := check_format(pattern):
            raise ValueError(err)
        patterns.append(re.compile(pattern, re.DOTALL))
    else:
        raise ValueError("Missing pattern")

    return patterns


def run_tests(patterns: list[re.Pattern], malicious: list, benign: list) -> list[str]:
    """Run tests and return list of failure messages."""
    failures = []
    for line in malicious:
        if line.strip() and not any(p.search(line) for p in patterns):
            failures.append(f"FALSE NEGATIVE - Should block: {line[:80]}")
    for line in benign:
        if line.strip() and any(p.search(line) for p in patterns):
            failures.append(f"FALSE POSITIVE - Should allow: {line[:80]}")
    return failures


def test_pattern(yaml_file: Path) -> tuple[int, int, list[str]]:
    """Test a pattern file. Returns (passed, failed, failure_messages)."""
    name = yaml_file.stem
    try:
        data = yaml.safe_load(yaml_file.read_text())
        patterns = compile_patterns(data)
        malicious = data.get("malicious", [])
        benign = data.get("benign", [])
        test_failures = run_tests(patterns, malicious, benign)
        failures = [f"{name}: {f}" for f in test_failures]
        total = len(malicious) + len(benign)
    except Exception as e:
        return 0, 1, [f"{name}: {e}"]

    return total - len(failures), len(failures), failures


def get_pattern_files() -> list[Path]:
    """Get list of pattern files to test."""
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        pattern_arg = sys.argv[1]
        if not pattern_arg.endswith(".yaml"):
            pattern_arg += ".yaml"
        path = PATTERNS_DIR / pattern_arg
        if not path.exists():
            print(f"Error: Pattern file not found: {pattern_arg}")
            sys.exit(1)
        return [path]

    return (
        sorted(PATTERNS_DIR.glob("critical-*.yaml"))
        + sorted(PATTERNS_DIR.glob("high-*.yaml"))
        + sorted(PATTERNS_DIR.glob("medium-*.yaml"))
    )


def main():
    yaml_files = get_pattern_files()
    total_passed = 0
    total_failed = 0
    all_failures = []

    for yaml_file in yaml_files:
        passed, failed, failures = test_pattern(yaml_file)
        total_passed += passed
        total_failed += failed
        all_failures.extend(failures)

    if all_failures:
        print("\nFailures:")
        for f in all_failures:
            print(f"  ✗ {f}")
        print()

    total = total_passed + total_failed
    print(f"Patterns: {len(yaml_files)} | Tests: {total_passed}/{total} passed", end="")

    if total_failed:
        print(f" | {total_failed} failed")
        sys.exit(1)
    else:
        print(" ✓")
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("Usage: run.py [PATTERN]")
        print("  Run all tests or test a specific pattern file")
        sys.exit(0)
    main()
