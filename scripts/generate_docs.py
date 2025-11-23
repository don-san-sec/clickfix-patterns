#!/usr/bin/env python3
"""
Generate HTML pattern documentation from YAML files for GitHub Pages
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


def html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def generate_html_documentation(output_dir: Path):
    """Generate HTML pattern documentation."""
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

    # Count patterns
    stable_count = (
        len(patterns_by_severity["critical"])
        + len(patterns_by_severity["high"])
        + len(patterns_by_severity["medium"])
    )
    experimental_count = len(patterns_by_severity["experimental"])
    total_count = stable_count + experimental_count

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate HTML
    html_file = output_dir / "index.html"
    with open(html_file, "w") as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ClickFix Detection Patterns</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
        }

        .subtitle {
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }

        h2 {
            color: #34495e;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #3498db;
            font-size: 1.8em;
        }

        h2.critical {
            border-bottom-color: #e74c3c;
        }

        h2.high {
            border-bottom-color: #e67e22;
        }

        h2.medium {
            border-bottom-color: #f39c12;
        }

        h2.experimental {
            border-bottom-color: #9b59b6;
        }

        .pattern {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 25px;
            border-radius: 4px;
        }

        .pattern.critical {
            border-left-color: #e74c3c;
        }

        .pattern.high {
            border-left-color: #e67e22;
        }

        .pattern.medium {
            border-left-color: #f39c12;
        }

        .pattern.experimental {
            border-left-color: #9b59b6;
        }

        .pattern-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .pattern-name {
            font-size: 1.3em;
            font-weight: 600;
            color: #2c3e50;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge.critical {
            background: #e74c3c;
            color: white;
        }

        .severity-badge.high {
            background: #e67e22;
            color: white;
        }

        .severity-badge.medium {
            background: #f39c12;
            color: white;
        }

        .severity-badge.experimental {
            background: #9b59b6;
            color: white;
        }

        .pattern-description {
            color: #555;
            margin-bottom: 15px;
            line-height: 1.7;
        }

        .pattern-regex {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .stats {
            background: #ecf0f1;
            padding: 15px 20px;
            border-radius: 4px;
            margin-bottom: 30px;
            text-align: center;
        }

        .stats strong {
            color: #2c3e50;
            font-size: 1.2em;
        }

        footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }

        footer a {
            color: #3498db;
            text-decoration: none;
        }

        footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>ClickFix Detection Patterns</h1>
        <p class="subtitle">Comprehensive detection patterns for ClickFix social engineering attacks</p>

        <div class="stats">
            <strong>""")

        f.write(
            f"{stable_count} stable + {experimental_count} experimental = {total_count} total patterns</strong>"
        )

        f.write("""
        </div>
""")

        # Critical patterns
        if patterns_by_severity["critical"]:
            f.write('        <h2 class="critical">Critical Severity</h2>\n')
            for yaml_file, data in patterns_by_severity["critical"]:
                f.write(f'        <div class="pattern critical">\n')
                f.write(f'            <div class="pattern-header">\n')
                f.write(
                    f'                <div class="pattern-name">{html_escape(data["name"])}</div>\n'
                )
                f.write(
                    f'                <span class="severity-badge critical">Critical</span>\n'
                )
                f.write(f"            </div>\n")
                f.write(
                    f'            <div class="pattern-description">{html_escape(data["description"])}</div>\n'
                )

                if data["pattern"]:
                    f.write(
                        f'            <div class="pattern-regex">{html_escape(data["pattern"])}</div>\n'
                    )

                f.write(f"        </div>\n\n")

        # High patterns
        if patterns_by_severity["high"]:
            f.write('        <h2 class="high">High Severity</h2>\n')
            for yaml_file, data in patterns_by_severity["high"]:
                f.write(f'        <div class="pattern high">\n')
                f.write(f'            <div class="pattern-header">\n')
                f.write(
                    f'                <div class="pattern-name">{html_escape(data["name"])}</div>\n'
                )
                f.write(
                    f'                <span class="severity-badge high">High</span>\n'
                )
                f.write(f"            </div>\n")
                f.write(
                    f'            <div class="pattern-description">{html_escape(data["description"])}</div>\n'
                )

                if data["pattern"]:
                    f.write(
                        f'            <div class="pattern-regex">{html_escape(data["pattern"])}</div>\n'
                    )

                f.write(f"        </div>\n\n")

        # Medium patterns
        if patterns_by_severity["medium"]:
            f.write('        <h2 class="medium">Medium Severity</h2>\n')
            for yaml_file, data in patterns_by_severity["medium"]:
                f.write(f'        <div class="pattern medium">\n')
                f.write(f'            <div class="pattern-header">\n')
                f.write(
                    f'                <div class="pattern-name">{html_escape(data["name"])}</div>\n'
                )
                f.write(
                    f'                <span class="severity-badge medium">Medium</span>\n'
                )
                f.write(f"            </div>\n")
                f.write(
                    f'            <div class="pattern-description">{html_escape(data["description"])}</div>\n'
                )

                if data["pattern"]:
                    f.write(
                        f'            <div class="pattern-regex">{html_escape(data["pattern"])}</div>\n'
                    )

                f.write(f"        </div>\n\n")

        # Experimental patterns
        if patterns_by_severity["experimental"]:
            f.write('        <h2 class="experimental">Experimental Patterns</h2>\n')
            for yaml_file, data in patterns_by_severity["experimental"]:
                f.write(f'        <div class="pattern experimental">\n')
                f.write(f'            <div class="pattern-header">\n')
                f.write(
                    f'                <div class="pattern-name">{html_escape(data["name"])}</div>\n'
                )
                f.write(
                    f'                <span class="severity-badge experimental">Experimental</span>\n'
                )
                f.write(f"            </div>\n")
                f.write(
                    f'            <div class="pattern-description">{html_escape(data["description"])}</div>\n'
                )

                if data["pattern"]:
                    f.write(
                        f'            <div class="pattern-regex">{html_escape(data["pattern"])}</div>\n'
                    )

                f.write(f"        </div>\n\n")

        f.write("""
        <footer>
            <p>Generated from <a href="https://github.com/dsepashvili/clickfix" target="_blank">ClickFix Detection Patterns</a></p>
        </footer>
    </div>
</body>
</html>
""")


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
