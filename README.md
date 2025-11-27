# [ClickFix Pattern Library](https://don-san-sec.github.io/clickfix-patterns/)

Library of regex patterns for detecting ClickFix social engineering attacks, designed to be applied to clipboard contents.

## Overview

### What is ClickFix?

ClickFix is a social engineering technique that tricks users into copying and executing malicious commands. Attackers disguise PowerShell, bash, or other scripts as "fixes" for fake errors—prompting victims to paste dangerous code into their terminal or Run dialog.

### How to Use This Library

This library provides regex patterns organized by severity level that can be applied to clipboard contents to detect potential ClickFix attacks. Meant to be used with browser extensions or other tools that can monitor clipboard contents and apply these patterns to warn users before they execute malicious commands.

![ClickFix Pattern Library](.github/media/banner.png)

## Development

```bash
make setup      # Install dependencies
make test       # Run pattern tests
make docs       # Generate documentation
```

**Testing specific patterns:**

```bash
./scripts/test/run.py critical-01-base64-powershell   # Test single pattern
./scripts/test/run.py                                 # Test all patterns
```

**Pattern structure:**

```
patterns/
├── critical-01-base64-powershell.yaml
├── critical-02-hidden-powershell.yaml
├── high-01-encoded-commands.yaml
├── high-02-iex-download.yaml
└── medium-01-suspicious-patterns.yaml
```

Each YAML pattern contains:
- **name** - Pattern identifier
- **severity** - Risk level (critical/high/medium)
- **description** - Detection intent
- **pattern** - Regex pattern(s)
- **malicious** - Test cases that should match
- **benign** - Test cases that should not match
