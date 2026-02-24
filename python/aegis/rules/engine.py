"""Rules engine — loads and applies YAML-based rules."""

from __future__ import annotations

from pathlib import Path

import yaml


class RulesEngine:
    """Loads rules from YAML files and applies them."""

    def __init__(self):
        self.rules: list[dict] = []

    def load_defaults(self):
        """Load default rules from the defaults/ directory."""
        defaults_dir = Path(__file__).parent / "defaults"
        if defaults_dir.exists():
            for yml_file in sorted(defaults_dir.glob("*.yml")):
                self.load_file(yml_file)

    def load_file(self, path: Path):
        """Load rules from a YAML file."""
        content = path.read_text()
        data = yaml.safe_load(content)
        if isinstance(data, list):
            self.rules.extend(data)
        elif isinstance(data, dict) and "rules" in data:
            self.rules.extend(data["rules"])

    def check_package(self, name: str, ecosystem: str, metadata: dict | None = None) -> list[dict]:
        """Check a package against all loaded rules.

        Returns list of triggered rule results.
        """
        results = []
        metadata = metadata or {}

        for rule in self.rules:
            rule_type = rule.get("type")
            if rule_type == "blocklist":
                if name.lower() in [n.lower() for n in rule.get("names", [])]:
                    results.append({
                        "rule": rule.get("name", "blocklist"),
                        "severity": rule.get("severity", "high"),
                        "description": rule.get("description", f"Package '{name}' is blocklisted"),
                    })
            elif rule_type == "pattern":
                import re
                for pattern in rule.get("patterns", []):
                    if re.search(pattern, name, re.IGNORECASE):
                        results.append({
                            "rule": rule.get("name", "pattern_match"),
                            "severity": rule.get("severity", "medium"),
                            "description": rule.get("description", f"Package name matches suspicious pattern"),
                        })
            elif rule_type == "metadata":
                # Check metadata-based rules
                condition = rule.get("condition", {})
                field = condition.get("field")
                op = condition.get("op")
                value = condition.get("value")
                if field and op and field in metadata:
                    actual = metadata[field]
                    triggered = False
                    if op == "lt" and actual < value:
                        triggered = True
                    elif op == "gt" and actual > value:
                        triggered = True
                    elif op == "eq" and actual == value:
                        triggered = True

                    if triggered:
                        results.append({
                            "rule": rule.get("name", "metadata_check"),
                            "severity": rule.get("severity", "low"),
                            "description": rule.get("description", f"Metadata check failed: {field} {op} {value}"),
                        })

        return results
