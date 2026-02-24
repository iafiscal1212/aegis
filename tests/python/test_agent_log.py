"""Tests for agent dashboard: registry_cache, agent_stats, agent_decisions."""

from datetime import datetime, timezone, timedelta

import pytest

from aegis.db.models import AegisDB


@pytest.fixture
def db(tmp_path):
    """Create a temporary database."""
    db_path = tmp_path / "test_aegis.db"
    db = AegisDB(db_path=db_path)
    db.initialize()
    return db


class TestRegistryCache:
    def test_cache_miss(self, db):
        result = db.get_registry_cache("nonexistent", "python")
        assert result is None

    def test_cache_hit(self, db):
        db.set_registry_cache("requests", "python", True)
        result = db.get_registry_cache("requests", "python")
        assert result is True

    def test_cache_negative(self, db):
        db.set_registry_cache("fake-pkg", "python", False)
        result = db.get_registry_cache("fake-pkg", "python")
        assert result is False

    def test_cache_ttl_expired(self, db):
        db.set_registry_cache("old-pkg", "python", True)
        # Manually set checked_at to 2 hours ago
        conn = db._connect()
        old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn.execute(
            "UPDATE registry_cache SET checked_at = ? WHERE package_name = ?",
            (old_time, "old-pkg"),
        )
        conn.commit()
        conn.close()

        result = db.get_registry_cache("old-pkg", "python", ttl=3600)
        assert result is None  # Expired

    def test_cache_upsert(self, db):
        db.set_registry_cache("pkg", "python", True)
        db.set_registry_cache("pkg", "python", False)
        result = db.get_registry_cache("pkg", "python")
        assert result is False

    def test_cache_different_ecosystems(self, db):
        db.set_registry_cache("pkg", "python", True)
        db.set_registry_cache("pkg", "node", False)
        assert db.get_registry_cache("pkg", "python") is True
        assert db.get_registry_cache("pkg", "node") is False


class TestAgentStats:
    def test_empty_stats(self, db):
        stats = db.get_agent_stats()
        assert stats == []

    def test_stats_with_data(self, db):
        db.log_decision("requests", "python", "allow", agent_name="claude-code")
        db.log_decision("flask", "python", "allow", agent_name="claude-code")
        db.log_decision("fakepkg", "python", "block", agent_name="claude-code")
        db.log_decision("express", "node", "warn", agent_name="cursor")

        stats = db.get_agent_stats()
        assert len(stats) == 2

        claude_stats = next(s for s in stats if s["agent_name"] == "claude-code")
        assert claude_stats["total"] == 3
        assert claude_stats["allowed"] == 2
        assert claude_stats["blocked"] == 1
        assert claude_stats["warned"] == 0

        cursor_stats = next(s for s in stats if s["agent_name"] == "cursor")
        assert cursor_stats["total"] == 1
        assert cursor_stats["warned"] == 1

    def test_stats_excludes_null_agent(self, db):
        db.log_decision("requests", "python", "allow", agent_name=None)
        db.log_decision("flask", "python", "allow", agent_name="claude-code")

        stats = db.get_agent_stats()
        assert len(stats) == 1
        assert stats[0]["agent_name"] == "claude-code"


class TestAgentDecisions:
    def test_filter_by_agent(self, db):
        db.log_decision("requests", "python", "allow", agent_name="claude-code")
        db.log_decision("express", "node", "allow", agent_name="cursor")
        db.log_decision("flask", "python", "block", agent_name="claude-code")

        decisions = db.get_agent_decisions("claude-code")
        assert len(decisions) == 2
        assert all(d["agent_name"] == "claude-code" for d in decisions)

    def test_empty_filter(self, db):
        db.log_decision("requests", "python", "allow", agent_name="claude-code")
        decisions = db.get_agent_decisions("nonexistent")
        assert decisions == []

    def test_limit(self, db):
        for i in range(10):
            db.log_decision(f"pkg{i}", "python", "allow", agent_name="claude-code")

        decisions = db.get_agent_decisions("claude-code", limit=3)
        assert len(decisions) == 3
