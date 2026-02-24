"""Database migrations for AEGIS."""

from __future__ import annotations

import sqlite3
from pathlib import Path


MIGRATIONS = [
    # Migration 1: Initial schema (handled by models.py initialize)
    None,
    # Future migrations go here as SQL strings
]


def get_current_version(conn: sqlite3.Connection) -> int:
    """Get current schema version."""
    try:
        row = conn.execute("PRAGMA user_version").fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0


def run_migrations(db_path: Path):
    """Run pending migrations."""
    conn = sqlite3.connect(str(db_path))
    current = get_current_version(conn)

    for i, migration in enumerate(MIGRATIONS):
        if i <= current or migration is None:
            continue
        conn.executescript(migration)
        conn.execute(f"PRAGMA user_version = {i}")
        conn.commit()

    conn.close()
