"""Process analysis — detect AI agent context from process tree."""

from __future__ import annotations

import os


def get_parent_process_name() -> str | None:
    """Get the name of the parent process."""
    try:
        ppid = os.getppid()
        cmdline_path = f"/proc/{ppid}/cmdline"
        if os.path.exists(cmdline_path):
            with open(cmdline_path, "rb") as f:
                cmdline = f.read().decode("utf-8", errors="replace")
                return cmdline.split("\x00")[0]
    except Exception:
        pass
    return None


def detect_ai_agent() -> str | None:
    """Detect if running inside a known AI coding agent.

    Returns the agent name or None.
    """
    # Environment variable checks
    env_indicators = {
        "CLAUDE_CODE": "claude-code",
        "CURSOR_SESSION": "cursor",
        "AIDER_SESSION": "aider",
        "COPILOT_AGENT": "copilot",
        "CONTINUE_SESSION": "continue",
    }

    for var, agent in env_indicators.items():
        if os.environ.get(var):
            return agent

    # Process tree check
    parent = get_parent_process_name()
    if parent:
        parent_lower = parent.lower()
        if "claude" in parent_lower:
            return "claude-code"
        if "cursor" in parent_lower:
            return "cursor"
        if "aider" in parent_lower:
            return "aider"

    return None
