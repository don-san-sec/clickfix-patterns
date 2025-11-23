# ClickFix Pattern Library

Regex patterns for detecting ClickFix social engineering attacks.

## What is ClickFix?

ClickFix is a social engineering attack that tricks users into copying and executing malicious commands. This project provides regex patterns to detect such attacks.

## Quick Start

```bash
make setup      # Install dependencies (first time only)
make test       # Run pattern tests
make docs       # Generate documentation
```

## Documentation

View the **[Pattern Documentation](https://don-san-sec.github.io/clickfix-patterns/)** on GitHub Pages for complete pattern details with descriptions, regex patterns, and severity levels. Auto-updated on every commit.

The documentation includes an **interactive Pattern Tester** - click "🧪 Test String" in the header to test strings against all patterns instantly.

## Structure

```
patterns/                           # Pattern definitions (YAML only)
├── critical-XX-name.yaml           # Tier 1: Critical risk patterns
├── high-XX-name.yaml               # Tier 2: High risk patterns
└── medium-XX-name.yaml             # Tier 3: Medium risk patterns

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

## Pattern Tester

The [hosted documentation](https://don-san-sec.github.io/clickfix-patterns/) includes an interactive **Pattern Tester**:

1. Click "🧪 Test String" button in the header
2. Enter any string or command to test
3. Click "Test String" to see which patterns match
4. Toggle back to "📋 Show Patterns" to view the pattern list

Perfect for:
- Finding false positives in legitimate commands
- Testing new patterns before deployment
- Debugging pattern behavior

## License

MIT License - see [LICENSE](LICENSE) file for details.