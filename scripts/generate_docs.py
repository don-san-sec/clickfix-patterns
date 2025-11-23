#!/usr/bin/env python3
"""
Generate HTML pattern documentation from YAML files for GitHub Pages
"""

import re
import urllib.parse
from pathlib import Path
from typing import Dict, List, Tuple

from jinja2 import Environment, FileSystemLoader


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
            current_section = stripped[:-1]  # Remove the colon
            in_test_list = True
            in_patterns_list = False
            continue

        # Handle list items in test sections (malicious/benign)
        if (
            stripped.startswith("- ")
            and in_test_list
            and current_section in ["malicious", "benign"]
        ):
            item = stripped[2:].strip()
            # Remove quotes if present
            if item.startswith('"') and item.endswith('"'):
                item = item[1:-1]
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


def get_detection_intent(name: str, description: str) -> str:
    """Extract what the pattern is intended to detect."""
    if "Detects" in description:
        parts = description.split("Detects", 1)
        if len(parts) > 1:
            intent = parts[1].split(".")[0].strip()
            return intent

    # Fallback to description first sentence
    first_sentence = description.split(".")[0].strip()
    if first_sentence:
        return first_sentence

    return ""


def generate_pattern_id(name: str) -> str:
    """Generate a URL-safe ID from pattern name."""
    return name.replace("_", "-").replace(" ", "-").lower()


def extract_malicious_examples(pattern_data: Dict) -> List[str]:
    """Extract malicious test cases from pattern data."""
    if "malicious" in pattern_data and pattern_data["malicious"]:
        # Return first 5 examples
        return pattern_data["malicious"][:5]
    return []


def load_patterns(patterns_dir: Path) -> Dict[str, List[Tuple]]:
    """Load all pattern files and organize by severity."""
    patterns_by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
    }

    for yaml_file in sorted(patterns_dir.glob("*.yaml")):
        pattern_data = parse_yaml_pattern(yaml_file)
        severity = pattern_data["severity"]
        if severity in patterns_by_severity:
            patterns_by_severity[severity].append((yaml_file, pattern_data))

    return patterns_by_severity


def prepare_template_data(patterns_by_severity: Dict[str, List[Tuple]]) -> Dict:
    """Prepare data for Jinja2 template."""
    # Calculate counts
    total_count = (
        len(patterns_by_severity["critical"])
        + len(patterns_by_severity["high"])
        + len(patterns_by_severity["medium"])
    )

    # Severity configuration
    severity_configs = [
        ("critical", "Critical", "Critical"),
        ("high", "High", "High"),
        ("medium", "Medium", "Medium"),
    ]

    # Build severities data
    severities = []
    for severity_key, severity_label, severity_badge in severity_configs:
        patterns = []
        for yaml_file, data in patterns_by_severity[severity_key]:
            regex_pattern = data["pattern"]
            patterns.append(
                {
                    "id": generate_pattern_id(data["name"]),
                    "name": data["name"],
                    "description": data["description"],
                    "intent": get_detection_intent(data["name"], data["description"]),
                    "regex": regex_pattern,
                    "malicious_examples": extract_malicious_examples(data),
                }
            )

        severities.append(
            (
                severity_key,
                {
                    "label": severity_label,
                    "badge": severity_badge,
                    "patterns": patterns,
                },
            )
        )

    return {
        "total_count": total_count,
        "severities": severities,
    }


def generate_html_documentation(output_dir: Path):
    """Generate HTML pattern documentation."""
    patterns_dir = Path(__file__).parent.parent / "patterns"
    scripts_dir = Path(__file__).parent

    # Load patterns
    patterns_by_severity = load_patterns(patterns_dir)

    # Prepare template data
    template_data = prepare_template_data(patterns_by_severity)

    # Setup Jinja2
    env = Environment(loader=FileSystemLoader(scripts_dir))
    # Custom URL encoder that encodes forward slashes too
    env.filters["urlencode"] = lambda s: urllib.parse.quote(s, safe="")
    template = env.get_template("template.html")

    # Render template
    html = template.render(**template_data)

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write HTML file
    html_file = output_dir / "index.html"
    html_file.write_text(html)


def main():
    """Generate documentation."""
    output_dir = Path(__file__).parent.parent / "docs"

    print(f"Generating HTML pattern documentation...")
    generate_html_documentation(output_dir)

    # Create .nojekyll file for GitHub Pages
    nojekyll_file = output_dir / ".nojekyll"
    nojekyll_file.touch()

    print(f"✓ Generated {output_dir / 'index.html'}")
    print(f"✓ Created {nojekyll_file}")


if __name__ == "__main__":
    main()
