"""AEGIS utility functions."""

from __future__ import annotations

import os


def is_ai_agent_context() -> bool:
    """Detect if running inside an AI coding agent.

    Checks for known environment variables set by AI tools.
    """
    indicators = [
        "CLAUDE_CODE",
        "CURSOR_SESSION",
        "AIDER_SESSION",
        "COPILOT_AGENT",
        "CONTINUE_SESSION",
    ]
    return any(os.environ.get(var) for var in indicators)


def normalize_ecosystem(manager: str) -> str:
    """Normalize a package manager name to an ecosystem."""
    mapping = {
        "pip": "python",
        "pip3": "python",
        "python": "python",
        "npm": "node",
        "npx": "node",
        "yarn": "node",
        "pnpm": "node",
        "bun": "node",
        "cargo": "rust",
        "apt": "system",
        "apt-get": "system",
    }
    return mapping.get(manager.lower(), "unknown")
