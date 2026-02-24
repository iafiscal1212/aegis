"""Tests for AEGIS rules engine."""

import pytest

from aegis.rules.engine import RulesEngine


class TestRulesEngine:
    def test_load_defaults(self):
        engine = RulesEngine()
        engine.load_defaults()
        assert len(engine.rules) > 0

    def test_blocklist_rule(self):
        engine = RulesEngine()
        engine.load_defaults()

        # Known typosquat should be caught
        results = engine.check_package("colourama", "python")
        assert any(r["severity"] == "critical" for r in results)

    def test_safe_package(self):
        engine = RulesEngine()
        engine.load_defaults()

        results = engine.check_package("requests", "python")
        # requests is not blocklisted
        blocklist_hits = [r for r in results if r["rule"] == "known_typosquats"]
        assert len(blocklist_hits) == 0

    def test_metadata_rule(self):
        engine = RulesEngine()
        engine.load_defaults()

        # New package (3 days old) should trigger
        results = engine.check_package("new-pkg", "python", metadata={"age_days": 3})
        assert any("new" in r["description"].lower() for r in results)

    def test_custom_rule(self):
        engine = RulesEngine()
        engine.rules = [
            {
                "name": "test_blocklist",
                "type": "blocklist",
                "severity": "high",
                "description": "Test blocklist",
                "names": ["bad-package"],
            }
        ]

        results = engine.check_package("bad-package", "python")
        assert len(results) == 1
        assert results[0]["severity"] == "high"

    def test_pattern_rule(self):
        engine = RulesEngine()
        engine.rules = [
            {
                "name": "test_pattern",
                "type": "pattern",
                "severity": "medium",
                "description": "Suspicious pattern",
                "patterns": [r"^python-.*-official$"],
            }
        ]

        results = engine.check_package("python-requests-official", "python")
        assert len(results) == 1

        results = engine.check_package("requests", "python")
        assert len(results) == 0
