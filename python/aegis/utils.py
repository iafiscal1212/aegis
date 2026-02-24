"""AEGIS utility functions."""

from __future__ import annotations

from aegis.monitor.process import detect_ai_agent, get_agent_risk_level


def is_ai_agent_context() -> bool:
    """Detect if running inside any AI coding agent."""
    return detect_ai_agent() is not None


def get_ai_context() -> dict:
    """Get full AI agent context information.

    Returns dict with:
        is_agent: bool
        agent_name: str | None
        risk_level: "none" | "standard" | "elevated" | "high"
    """
    agent = detect_ai_agent()
    return {
        "is_agent": agent is not None,
        "agent_name": agent,
        "risk_level": get_agent_risk_level(agent),
    }


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
