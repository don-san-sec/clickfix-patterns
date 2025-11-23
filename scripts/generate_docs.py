#!/usr/bin/env python3
"""Generate HTML pattern documentation from YAML files for GitHub Pages."""

import re
import urllib.parse
from pathlib import Path
from typing import Dict, List, Tuple

from jinja2 import Environment, FileSystemLoader
from yaml_parser import parse_yaml_pattern


def get_detection_intent(name: str, description: str) -> str:
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


def clean_regex_for_javascript(pattern: str) -> str:
    cleaned = re.sub(r"\(\?[imsxADSUXJ-]+\)", "", pattern)
    return cleaned


def generate_pattern_id(name: str) -> str:
    return name.replace("_", "-").replace(" ", "-").lower()


def format_pattern_name(name: str) -> str:
    parts = name.split("-")

    if len(parts) < 3:
        return name
    number = parts[1]
    description = "-".join(parts[2:])
    description_words = description.split("-")
    formatted_description = " ".join(word.capitalize() for word in description_words)

    return f"[{number}] {formatted_description}"


def extract_malicious_examples(pattern_data: Dict) -> List[str]:
    if "malicious" in pattern_data and pattern_data["malicious"]:
        return pattern_data["malicious"][:5]
    return []


def load_patterns(patterns_dir: Path) -> Dict[str, List[Tuple]]:
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
    total_count = (
        len(patterns_by_severity["critical"])
        + len(patterns_by_severity["high"])
        + len(patterns_by_severity["medium"])
    )

    severity_configs = [
        ("critical", "Critical", "Critical"),
        ("high", "High", "High"),
        ("medium", "Medium", "Medium"),
    ]

    severities = []
    for severity_key, severity_label, severity_badge in severity_configs:
        patterns = []
        for yaml_file, data in patterns_by_severity[severity_key]:
            regex_pattern = data["pattern"]
            js_regex_pattern = clean_regex_for_javascript(regex_pattern)
            patterns.append(
                {
                    "id": generate_pattern_id(data["name"]),
                    "name": data["name"],
                    "display_name": format_pattern_name(data["name"]),
                    "description": data["description"],
                    "intent": get_detection_intent(data["name"], data["description"]),
                    "regex": regex_pattern,
                    "js_regex": js_regex_pattern,
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
    patterns_dir = Path(__file__).parent.parent / "patterns"
    scripts_dir = Path(__file__).parent
    patterns_by_severity = load_patterns(patterns_dir)
    template_data = prepare_template_data(patterns_by_severity)
    env = Environment(loader=FileSystemLoader(scripts_dir))
    env.filters["urlencode"] = lambda s: urllib.parse.quote(s, safe="")
    template = env.get_template("template.html")
    html = template.render(**template_data)
    output_dir.mkdir(parents=True, exist_ok=True)
    html_file = output_dir / "index.html"
    html_file.write_text(html)


def main():
    output_dir = Path(__file__).parent.parent / "docs"

    print(f"Generating HTML pattern documentation...")
    generate_html_documentation(output_dir)
    nojekyll_file = output_dir / ".nojekyll"
    nojekyll_file.touch()

    print(f"✓ Generated {output_dir / 'index.html'}")
    print(f"✓ Created {nojekyll_file}")


if __name__ == "__main__":
    main()
