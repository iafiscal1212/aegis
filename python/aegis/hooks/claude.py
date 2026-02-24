"""AEGIS hook for Claude Code — PreToolUse integration."""

from __future__ import annotations

import json
from pathlib import Path


def parse_hook_payload(payload: dict) -> str | None:
    """Extract the Bash command from a Claude Code hook payload.

    Returns the command string if tool_name is "Bash" and tool_input.command
    exists, otherwise None (not a Bash invocation).
    """
    if payload.get("tool_name") != "Bash":
        return None
    tool_input = payload.get("tool_input", {})
    command = tool_input.get("command")
    if not command or not isinstance(command, str):
        return None
    return command


def get_hook_config() -> dict:
    """Generate the Claude Code hook config for PreToolUse.

    Returns the dict to merge into ~/.claude/settings.json under
    "hooks.PreToolUse".
    """
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "aegis check-hook",
                        }
                    ],
                }
            ]
        }
    }


def install_hook(scope: str = "user") -> Path:
    """Install the AEGIS hook into Claude Code settings.

    Performs a safe merge: reads existing settings, adds/updates the
    PreToolUse hook without removing other hooks or settings.

    Returns the path to the settings file.
    """
    settings_path = Path.home() / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing settings
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    else:
        settings = {}

    # Ensure hooks.PreToolUse exists
    hooks = settings.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])

    # Check if AEGIS hook already exists
    aegis_entry = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": "aegis check-hook",
            }
        ],
    }

    already_installed = False
    for entry in pre_tool_use:
        for h in entry.get("hooks", []):
            if h.get("command") == "aegis check-hook":
                already_installed = True
                break

    if not already_installed:
        pre_tool_use.append(aegis_entry)

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    return settings_path
