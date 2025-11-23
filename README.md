# ClickFix Pattern Library

Regex patterns for detecting ClickFix social engineering attacks.

## What is ClickFix?

ClickFix is a social engineering attack that tricks users into copying and executing malicious commands. This project provides regex patterns to detect such attacks.

## Quick Start

```bash
make test       # Run stable pattern tests (100% pass rate)
make test-all   # Run all tests including experimental patterns
```

## Documentation

View the **[Pattern Documentation](https://dsepashvili.github.io/clickfix/)** on GitHub Pages for complete pattern details with descriptions, regex patterns, and severity levels. Auto-updated on every commit.

## Structure

```
patterns/                           # Pattern definitions (YAML only)
├── critical-XX-name.yaml           # Tier 1: Critical risk patterns
├── high-XX-name.yaml               # Tier 2: High risk patterns
├── medium-XX-name.yaml             # Tier 3: Medium risk patterns
└── experimental-*-XX-name.yaml     # Patterns requiring allowlists

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