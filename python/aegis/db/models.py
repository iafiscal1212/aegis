"""AEGIS database — SQLite local storage for decisions and package data."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from aegis.config import get_config_dir


class AegisDB:
    """SQLite database for AEGIS local data."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or (get_config_dir() / "aegis.db")
        self._ensure_initialized()

    def _ensure_initialized(self):
        """Auto-initialize if DB exists."""
        if self.db_path.exists():
            # Verify tables exist
            try:
                conn = self._connect()
                conn.execute("SELECT 1 FROM packages LIMIT 1")
                conn.close()
            except sqlite3.OperationalError:
                self.initialize()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def initialize(self):
        """Create database tables."""
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                version TEXT,
                ecosystem TEXT NOT NULL,
                risk_score REAL DEFAULT 0.0,
                first_seen TEXT NOT NULL,
                last_checked TEXT NOT NULL,
                metadata_json TEXT,
                UNIQUE(name, ecosystem)
            );

            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                user_override INTEGER DEFAULT 0,
                agent_name TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rules_version (
                id INTEGER PRIMARY KEY,
                version TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_decisions_package ON decisions(package_name);
            CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name, ecosystem);
        """)
        conn.commit()
        conn.close()

    def log_decision(
        self,
        package_name: str,
        ecosystem: str,
        action: str,
        reason: str = "",
        user_override: bool = False,
        agent_name: str | None = None,
    ):
        """Log a security decision."""
        conn = self._connect()
        conn.execute(
            """INSERT INTO decisions (package_name, ecosystem, action, reason, user_override, agent_name, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                package_name,
                ecosystem,
                action,
                reason,
                int(user_override),
                agent_name,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        conn.close()

    def upsert_package(
        self,
        name: str,
        ecosystem: str,
        version: str | None = None,
        risk_score: float = 0.0,
        metadata_json: str | None = None,
    ):
        """Insert or update a package record."""
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        conn.execute(
            """INSERT INTO packages (name, ecosystem, version, risk_score, first_seen, last_checked, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(name, ecosystem) DO UPDATE SET
                   version = excluded.version,
                   risk_score = excluded.risk_score,
                   last_checked = excluded.last_checked,
                   metadata_json = excluded.metadata_json""",
            (name, ecosystem, version, risk_score, now, now, metadata_json),
        )
        conn.commit()
        conn.close()

    def get_package(self, name: str, ecosystem: str) -> dict | None:
        """Get a package record."""
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM packages WHERE name = ? AND ecosystem = ?",
            (name, ecosystem),
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_recent_decisions(self, limit: int = 50) -> list[dict]:
        """Get recent decisions."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        """Get database statistics."""
        conn = self._connect()
        pkg_count = conn.execute("SELECT COUNT(*) FROM packages").fetchone()[0]
        dec_count = conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        conn.close()
        return {"packages": pkg_count, "decisions": dec_count}
