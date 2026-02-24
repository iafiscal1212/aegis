"""Process analysis — detect AI agent context from process tree.

Supports detection of all major AI coding agents:
- Claude Code (Anthropic)
- Cursor
- GitHub Copilot / Copilot Workspace
- Aider
- Continue.dev
- Cody (Sourcegraph)
- Windsurf (Codeium)
- Gemini Code Assist (Google)
- Amazon Q Developer
- Tabnine
- Ollama-based agents
- OpenAI / ChatGPT-based tools
- AntiGravity
- Devin (Cognition)
- SWE-agent
- OpenHands (ex-OpenDevin)
- Sweep AI
- Mentat
- GPT Engineer / Smol Developer
"""

from __future__ import annotations

import os
from pathlib import Path


# --- Environment variable → agent name mapping ---
# Covers known env vars set by AI coding tools and wrappers
ENV_INDICATORS: dict[str, str] = {
    # Anthropic
    "CLAUDE_CODE": "claude-code",
    "CLAUDE_SESSION": "claude-code",
    "ANTHROPIC_AGENT": "claude-code",
    # Cursor
    "CURSOR_SESSION": "cursor",
    "CURSOR_TRACE_ID": "cursor",
    # GitHub Copilot
    "COPILOT_AGENT": "copilot",
    "GITHUB_COPILOT": "copilot",
    "COPILOT_WORKSPACE": "copilot-workspace",
    # Aider
    "AIDER_SESSION": "aider",
    "AIDER_MODEL": "aider",
    # Continue.dev
    "CONTINUE_SESSION": "continue",
    "CONTINUE_GLOBAL_DIR": "continue",
    # Cody (Sourcegraph)
    "CODY_AGENT": "cody",
    "SRC_ACCESS_TOKEN": "cody",
    # Windsurf (Codeium)
    "WINDSURF_SESSION": "windsurf",
    "CODEIUM_API_KEY": "windsurf",
    # Google Gemini
    "GEMINI_API_KEY": "gemini",
    "GOOGLE_AI_STUDIO": "gemini",
    "IDX_CHANNEL": "project-idx",
    # Amazon Q
    "AMAZON_Q_SESSION": "amazon-q",
    "AWS_CODECATALYST": "amazon-q",
    # Tabnine
    "TABNINE_API_KEY": "tabnine",
    # Ollama
    "OLLAMA_HOST": "ollama",
    "OLLAMA_MODELS": "ollama",
    # OpenAI
    "OPENAI_API_KEY": "openai",
    # Devin
    "DEVIN_SESSION": "devin",
    # SWE-agent
    "SWE_AGENT": "swe-agent",
    # OpenHands (ex-OpenDevin)
    "OPENHANDS_SESSION": "openhands",
    # Sweep AI
    "SWEEP_SESSION": "sweep",
    # Mentat
    "MENTAT_SESSION": "mentat",
    # GPT Engineer
    "GPTE_SESSION": "gpt-engineer",
    # AntiGravity
    "ANTIGRAVITY_SESSION": "antigravity",
    "ANTIGRAVITY_API": "antigravity",
    # Replit Agent
    "REPLIT_AGENT": "replit-agent",
    "REPL_ID": "replit",
    # Generic AI agent indicators
    "AI_AGENT": "generic-ai-agent",
    "LLM_AGENT": "generic-ai-agent",
}

# --- Process name patterns ---
# Substrings to look for in parent/ancestor process names
PROCESS_PATTERNS: dict[str, str] = {
    "claude": "claude-code",
    "cursor": "cursor",
    "copilot": "copilot",
    "aider": "aider",
    "continue": "continue",
    "cody": "cody",
    "windsurf": "windsurf",
    "codeium": "windsurf",
    "gemini": "gemini",
    "ollama": "ollama",
    "devin": "devin",
    "swe-agent": "swe-agent",
    "swe_agent": "swe-agent",
    "openhands": "openhands",
    "opendevin": "openhands",
    "sweep": "sweep",
    "mentat": "mentat",
    "gpt-engineer": "gpt-engineer",
    "smol-developer": "gpt-engineer",
    "antigravity": "antigravity",
    "tabnine": "tabnine",
    "amazon-q": "amazon-q",
    "replit": "replit-agent",
}


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


def get_process_ancestors(max_depth: int = 5) -> list[str]:
    """Walk up the process tree and collect ancestor command names.

    Returns a list of command names from the immediate parent up to max_depth.
    """
    ancestors = []
    try:
        pid = os.getppid()
        for _ in range(max_depth):
            cmdline_path = f"/proc/{pid}/cmdline"
            stat_path = f"/proc/{pid}/stat"

            if not os.path.exists(cmdline_path):
                break

            # Read command name
            with open(cmdline_path, "rb") as f:
                cmdline = f.read().decode("utf-8", errors="replace")
                cmd = cmdline.split("\x00")[0]
                if cmd:
                    ancestors.append(cmd)

            # Get parent PID
            if not os.path.exists(stat_path):
                break
            with open(stat_path) as f:
                stat = f.read()
                # Format: pid (name) state ppid ...
                parts = stat.split(")")
                if len(parts) < 2:
                    break
                rest = parts[-1].strip().split()
                if len(rest) < 2:
                    break
                ppid = int(rest[1])
                if ppid <= 1:
                    break
                pid = ppid
    except Exception:
        pass
    return ancestors


def detect_ai_agent() -> str | None:
    """Detect if running inside any known AI coding agent.

    Uses three detection strategies:
    1. Environment variables (most reliable)
    2. Parent process name
    3. Process tree ancestors (walks up to 5 levels)

    Returns the agent name or None.
    """
    # Strategy 1: Environment variables
    for var, agent in ENV_INDICATORS.items():
        val = os.environ.get(var)
        if val:
            # Some env vars (like OPENAI_API_KEY) exist even without an agent
            # Only count them if there are other agent indicators too
            if var in ("OPENAI_API_KEY", "GEMINI_API_KEY", "OLLAMA_HOST", "OLLAMA_MODELS"):
                # These are common API keys — only flag if a more specific
                # indicator is also present
                continue
            return agent

    # Strategy 2: Check for specific agent env var patterns
    # Some agents set custom vars we don't know about yet
    for key in os.environ:
        key_lower = key.lower()
        if any(p in key_lower for p in ("_agent_", "ai_coding", "llm_session")):
            return "unknown-ai-agent"

    # Strategy 3: Process name matching (immediate parent)
    parent = get_parent_process_name()
    if parent:
        parent_lower = parent.lower()
        for pattern, agent in PROCESS_PATTERNS.items():
            if pattern in parent_lower:
                return agent

    # Strategy 4: Process tree ancestors (deeper search)
    ancestors = get_process_ancestors(max_depth=5)
    for ancestor in ancestors:
        ancestor_lower = ancestor.lower()
        for pattern, agent in PROCESS_PATTERNS.items():
            if pattern in ancestor_lower:
                return agent

    # Strategy 5: Check for Claude Code hooks specifically
    # If AEGIS is invoked via a PreToolUse hook, the settings file exists
    claude_settings = Path.home() / ".claude" / "settings.json"
    if claude_settings.exists():
        try:
            import json
            settings = json.loads(claude_settings.read_text())
            hooks = settings.get("hooks", {})
            if any("aegis" in str(v).lower() for v in hooks.values()):
                # AEGIS is configured as a Claude Code hook
                return "claude-code"
        except Exception:
            pass

    return None


def get_agent_risk_level(agent: str | None) -> str:
    """Get the risk level for an AI agent context.

    Returns: "none", "standard", "elevated", "high"
    """
    if agent is None:
        return "none"

    # Well-known commercial agents with safety measures
    low_risk = {"copilot", "cody", "tabnine", "amazon-q", "windsurf", "project-idx"}
    # Agents that run arbitrary commands
    high_risk = {"devin", "swe-agent", "openhands", "sweep", "gpt-engineer",
                 "generic-ai-agent", "unknown-ai-agent", "replit-agent"}

    if agent in high_risk:
        return "high"
    if agent in low_risk:
        return "standard"
    return "elevated"
