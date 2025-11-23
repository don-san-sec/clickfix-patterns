#!/usr/bin/env python3
"""Shared YAML parser for ClickFix patterns."""

from pathlib import Path
from typing import Dict


def parse_yaml_pattern(yaml_file: Path) -> Dict:
    """Parse a YAML pattern file without external dependencies."""
    content = yaml_file.read_text()

    pattern_data = {
        "name": "",
        "severity": "",
        "description": "",
        "pattern": "",
        "patterns": [],
        "malicious": [],
        "benign": [],
    }

    lines = content.splitlines()
    current_section = None
    multiline_value = []
    current_pattern = None
    in_patterns_list = False
    in_test_list = False

    for line in lines:
        stripped = line.strip()

        if not stripped:
            continue

        # Handle test sections
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
            current_section = stripped[:-1]
            in_test_list = True
            in_patterns_list = False
            continue

        # Handle list items in test sections
        if (
            stripped.startswith("- ")
            and in_test_list
            and current_section in ["malicious", "benign"]
        ):
            item = stripped[2:].strip()
            if item.startswith('"') and item.endswith('"'):
                item = item[1:-1].replace('\\"', '"')
            elif item.startswith("'") and item.endswith("'"):
                item = item[1:-1]
            pattern_data[current_section].append(item)
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
                in_test_list = False
            continue

        # Handle key-value pairs
        if ":" in line and not line.startswith("  "):
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
                in_test_list = False
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
