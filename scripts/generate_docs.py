#!/usr/bin/env python3
"""
Generate pattern documentation from YAML files
Creates PATTERNS.md with all pattern details
"""

import re
from pathlib import Path
from typing import Dict, List


def parse_yaml_pattern(yaml_file: Path) -> Dict:
    """Parse a YAML pattern file without external dependencies."""
    content = yaml_file.read_text()

    pattern_data = {
        "name": "",
        "severity": "",
        "description": "",
        "pattern": "",
        "patterns": [],
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

        # Handle test sections - save any pending multiline values first
        if stripped in ["malicious:", "benign:"]:
            if multiline_value and current_section:
                if current_section == "pattern" and not in_patterns_list:
                    pattern_data[current_section] = (
                        multiline_value[0]
                        if len(multiline_value) == 1
                        else "\n".join(multiline_value).strip()
                    )
                elif current_section == "description":
                    pattern_data[current_section] = " ".join(multiline_value).strip()
                multiline_value = []
            current_section = None
            continue

        # Handle list items in patterns
        if stripped.startswith("- ") and current_section == "patterns":
            item = stripped[2:].strip()
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

        # Handle key-value pairs
        if ":" in line and not line.startswith("  "):
            # Save previous multiline value
            if multiline_value and current_section:
                if current_section == "pattern" and not in_patterns_list:
                    pattern_data[current_section] = (
                        multiline_value[0]
                        if len(multiline_value) == 1
                        else "\n".join(multiline_value).strip()
                    )
                elif current_section == "description":
                    pattern_data[current_section] = " ".join(multiline_value).strip()
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
                if value and value not in ["|", ">"]:
                    multiline_value = [value]
            elif key == "patterns":
                current_section = key
                in_patterns_list = True
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
        if current_section == "pattern":
            pattern_data[current_section] = (
                multiline_value[0]
                if len(multiline_value) == 1
                else "\n".join(multiline_value).strip()
            )
        elif current_section == "description":
            pattern_data[current_section] = " ".join(multiline_value).strip()

    # Save last pattern in patterns list
    if current_pattern:
        pattern_data["patterns"].append(current_pattern)

    return pattern_data


def generate_documentation(output_file: Path):
    """Generate pattern documentation."""
    patterns_dir = Path(__file__).parent.parent / "patterns"

    # Collect all patterns by severity
    patterns_by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "experimental": [],
    }

    # Get all yaml files
    for yaml_file in sorted(patterns_dir.glob("*.yaml")):
        pattern_data = parse_yaml_pattern(yaml_file)

        # Categorize by severity
        if "experimental" in yaml_file.name:
            patterns_by_severity["experimental"].append((yaml_file, pattern_data))
        else:
            severity = pattern_data["severity"]
            if severity in patterns_by_severity:
                patterns_by_severity[severity].append((yaml_file, pattern_data))

    # Generate markdown
    with open(output_file, "w") as f:
        f.write("# ClickFix Detection Patterns\n\n")

        # Count patterns
        stable_count = (
            len(patterns_by_severity["critical"])
            + len(patterns_by_severity["high"])
            + len(patterns_by_severity["medium"])
        )
        experimental_count = len(patterns_by_severity["experimental"])

        f.write(
            f"**{stable_count} stable + {experimental_count} experimental = {stable_count + experimental_count} total**\n\n"
        )
        f.write("---\n\n")

        # Critical patterns
        if patterns_by_severity["critical"]:
            f.write("## Critical Severity\n\n")
            for yaml_file, data in patterns_by_severity["critical"]:
                f.write(f"### {data['name']}\n\n")
                f.write(f"{data['description']}\n\n")

                if data["patterns"]:
                    for p in data["patterns"]:
                        f.write(f"- `{p['pattern']}`\n")
                elif data["pattern"]:
                    f.write(f"```regex\n{data['pattern']}\n```\n\n")

                f.write("---\n\n")

        # High patterns
        if patterns_by_severity["high"]:
            f.write("## High Severity\n\n")
            for yaml_file, data in patterns_by_severity["high"]:
                f.write(f"### {data['name']}\n\n")
                f.write(f"{data['description']}\n\n")

                if data["patterns"]:
                    for p in data["patterns"]:
                        f.write(f"- `{p['pattern']}`\n")
                elif data["pattern"]:
                    f.write(f"```regex\n{data['pattern']}\n```\n\n")

                f.write("---\n\n")

        # Medium patterns
        if patterns_by_severity["medium"]:
            f.write("## Medium Severity\n\n")
            for yaml_file, data in patterns_by_severity["medium"]:
                f.write(f"### {data['name']}\n\n")
                f.write(f"{data['description']}\n\n")

                if data["patterns"]:
                    for p in data["patterns"]:
                        f.write(f"- `{p['pattern']}`\n")
                elif data["pattern"]:
                    f.write(f"```regex\n{data['pattern']}\n```\n\n")

                f.write("---\n\n")

        # Experimental patterns
        if patterns_by_severity["experimental"]:
            f.write("## Experimental Patterns\n\n")
            for yaml_file, data in patterns_by_severity["experimental"]:
                f.write(f"### {data['name']}\n\n")
                f.write(f"{data['description']}\n\n")

                if data["patterns"]:
                    for p in data["patterns"]:
                        f.write(f"- `{p['pattern']}`\n")
                elif data["pattern"]:
                    f.write(f"```regex\n{data['pattern']}\n```\n\n")

                f.write("---\n\n")


def main():
    """Generate documentation."""
    output_file = Path(__file__).parent.parent / "PATTERNS.md"

    print(f"Generating pattern documentation...")
    generate_documentation(output_file)
    print(f"✓ Generated {output_file}")


if __name__ == "__main__":
    main()
