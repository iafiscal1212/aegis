"""Tests for AEGIS database."""

import pytest
from pathlib import Path

from aegis.db.models import AegisDB


@pytest.fixture
def db(tmp_path):
    """Create a temporary database."""
    db_path = tmp_path / "test_aegis.db"
    db = AegisDB(db_path=db_path)
    db.initialize()
    return db


class TestAegisDB:
    def test_initialize(self, db):
        assert db.db_path.exists()

    def test_log_decision(self, db):
        db.log_decision("requests", "python", "allow", "No issues found")
        decisions = db.get_recent_decisions()
        assert len(decisions) == 1
        assert decisions[0]["package_name"] == "requests"
        assert decisions[0]["action"] == "allow"

    def test_log_multiple_decisions(self, db):
        db.log_decision("requests", "python", "allow", "Safe")
        db.log_decision("reqeusts", "python", "block", "Typosquat")
        db.log_decision("flask", "python", "allow", "Safe")

        decisions = db.get_recent_decisions()
        assert len(decisions) == 3

    def test_upsert_package(self, db):
        db.upsert_package("requests", "python", "2.31.0", risk_score=0.0)
        pkg = db.get_package("requests", "python")
        assert pkg is not None
        assert pkg["name"] == "requests"
        assert pkg["risk_score"] == 0.0

    def test_upsert_updates(self, db):
        db.upsert_package("requests", "python", "2.30.0", risk_score=0.0)
        db.upsert_package("requests", "python", "2.31.0", risk_score=0.1)
        pkg = db.get_package("requests", "python")
        assert pkg["version"] == "2.31.0"
        assert pkg["risk_score"] == 0.1

    def test_get_nonexistent_package(self, db):
        assert db.get_package("nonexistent", "python") is None

    def test_get_stats(self, db):
        stats = db.get_stats()
        assert stats["packages"] == 0
        assert stats["decisions"] == 0

        db.log_decision("pkg1", "python", "allow")
        db.upsert_package("pkg1", "python")

        stats = db.get_stats()
        assert stats["packages"] == 1
        assert stats["decisions"] == 1

    def test_recent_decisions_limit(self, db):
        for i in range(10):
            db.log_decision(f"pkg{i}", "python", "allow")

        decisions = db.get_recent_decisions(limit=5)
        assert len(decisions) == 5

    def test_decisions_ordered_by_time(self, db):
        db.log_decision("first", "python", "allow")
        db.log_decision("second", "python", "block")

        decisions = db.get_recent_decisions()
        # Most recent first
        assert decisions[0]["package_name"] == "second"
        assert decisions[1]["package_name"] == "first"
