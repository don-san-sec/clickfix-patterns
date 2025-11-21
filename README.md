# ClickFix Attack Detection

Regex patterns for detecting ClickFix social engineering attacks.

## What is ClickFix?

ClickFix is a social engineering attack that tricks users into copying and executing malicious commands. This project provides regex patterns to detect such attacks.

## Quick Start

```bash
make test       # Run stable pattern tests (100% pass rate)
make test-all   # Run all tests including experimental patterns
```

## Documentation

Download **[PATTERNS.md](../../releases/latest)** from the latest release for complete pattern documentation with descriptions and regex patterns. Auto-updated on every commit.

## Structure

```
patterns/                           # Pattern definitions (YAML only)
├── critical-XX-name.yaml           # Tier 1: Critical risk (6 patterns)
├── high-XX-name.yaml               # Tier 2: High risk (10 patterns)
├── medium-XX-name.yaml             # Tier 3: Medium risk (7 patterns)
└── experimental-*-XX-name.yaml     # Require allowlists (5 patterns)

scripts/                            # Tools
├── run_tests.py                    # Pattern testing
└── generate_docs.py                # Documentation generation
```

Each pattern is a YAML file containing:
- `name` - Pattern identifier
- `severity` - Risk level (critical, high, medium)
- `description` - What the pattern detects and why
- `pattern` - The regex pattern (or `patterns` for multiple sub-patterns)
- `malicious` - Commands that should be blocked (test cases)
- `benign` - Commands that should be allowed (test cases)

## License

MIT License - see [LICENSE](LICENSE) file for details.
