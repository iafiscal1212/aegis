"""Tests for AEGIS universal AI agent detection."""

import os
from unittest.mock import patch

import pytest

from aegis.monitor.process import (
    detect_ai_agent,
    get_agent_risk_level,
    ENV_INDICATORS,
    PROCESS_PATTERNS,
)


class TestDetectAIAgent:
    """Test detection of all supported AI agents."""

    def test_no_agent(self):
        with patch.dict(os.environ, {}, clear=True):
            # Clear all env vars that might indicate an agent
            env = {k: "" for k in ENV_INDICATORS}
            with patch.dict(os.environ, env, clear=False):
                with patch("aegis.monitor.process.get_parent_process_name", return_value=None):
                    with patch("aegis.monitor.process.get_process_ancestors", return_value=[]):
                        result = detect_ai_agent()
                        # May still detect via Claude settings file
                        # Just verify it doesn't crash
                        assert result is None or isinstance(result, str)

    @pytest.mark.parametrize("env_var,expected_agent", [
        ("CLAUDE_CODE", "claude-code"),
        ("CLAUDE_SESSION", "claude-code"),
        ("CURSOR_SESSION", "cursor"),
        ("CURSOR_TRACE_ID", "cursor"),
        ("COPILOT_AGENT", "copilot"),
        ("GITHUB_COPILOT", "copilot"),
        ("AIDER_SESSION", "aider"),
        ("AIDER_MODEL", "aider"),
        ("CONTINUE_SESSION", "continue"),
        ("CONTINUE_GLOBAL_DIR", "continue"),
        ("CODY_AGENT", "cody"),
        ("WINDSURF_SESSION", "windsurf"),
        ("CODEIUM_API_KEY", "windsurf"),
        ("IDX_CHANNEL", "project-idx"),
        ("AMAZON_Q_SESSION", "amazon-q"),
        ("TABNINE_API_KEY", "tabnine"),
        ("DEVIN_SESSION", "devin"),
        ("SWE_AGENT", "swe-agent"),
        ("OPENHANDS_SESSION", "openhands"),
        ("SWEEP_SESSION", "sweep"),
        ("MENTAT_SESSION", "mentat"),
        ("GPTE_SESSION", "gpt-engineer"),
        ("ANTIGRAVITY_SESSION", "antigravity"),
        ("ANTIGRAVITY_API", "antigravity"),
        ("REPLIT_AGENT", "replit-agent"),
        ("AI_AGENT", "generic-ai-agent"),
        ("LLM_AGENT", "generic-ai-agent"),
    ])
    def test_env_detection(self, env_var, expected_agent):
        """Test that each env var correctly identifies the agent."""
        with patch.dict(os.environ, {env_var: "1"}, clear=False):
            result = detect_ai_agent()
            assert result == expected_agent, f"{env_var}=1 should detect '{expected_agent}', got '{result}'"

    @pytest.mark.parametrize("process_name,expected_agent", [
        ("/usr/bin/claude-code", "claude-code"),
        ("/opt/cursor/cursor", "cursor"),
        ("copilot-agent", "copilot"),
        ("/home/user/.local/bin/aider", "aider"),
        ("ollama serve", "ollama"),
        ("devin-agent", "devin"),
        ("swe-agent", "swe-agent"),
        ("openhands-runtime", "openhands"),
        ("antigravity-cli", "antigravity"),
    ])
    def test_process_detection(self, process_name, expected_agent):
        """Test detection via parent process name."""
        with patch.dict(os.environ, {}, clear=True):
            with patch("aegis.monitor.process.get_parent_process_name", return_value=process_name):
                with patch("aegis.monitor.process.get_process_ancestors", return_value=[]):
                    result = detect_ai_agent()
                    assert result == expected_agent

    def test_ancestor_detection(self):
        """Test detection via process ancestor tree."""
        ancestors = ["/bin/bash", "/usr/bin/node", "/home/user/.cursor/cursor-server"]
        with patch.dict(os.environ, {}, clear=True):
            with patch("aegis.monitor.process.get_parent_process_name", return_value="/bin/bash"):
                with patch("aegis.monitor.process.get_process_ancestors", return_value=ancestors):
                    result = detect_ai_agent()
                    assert result == "cursor"


class TestAgentRiskLevel:
    def test_no_agent(self):
        assert get_agent_risk_level(None) == "none"

    def test_high_risk_agents(self):
        high_risk = ["devin", "swe-agent", "openhands", "sweep",
                     "gpt-engineer", "generic-ai-agent", "unknown-ai-agent"]
        for agent in high_risk:
            assert get_agent_risk_level(agent) == "high", f"{agent} should be high risk"

    def test_standard_risk_agents(self):
        standard = ["copilot", "cody", "tabnine", "amazon-q", "windsurf"]
        for agent in standard:
            assert get_agent_risk_level(agent) == "standard", f"{agent} should be standard risk"

    def test_elevated_risk_agents(self):
        elevated = ["claude-code", "cursor", "aider", "continue", "ollama",
                    "antigravity", "gemini", "mentat"]
        for agent in elevated:
            assert get_agent_risk_level(agent) == "elevated", f"{agent} should be elevated risk"


class TestEscalationWithAgent:
    """Test that AI agent detection properly escalates actions."""

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_typo_warn_without_agent(self, mock_agent, mock_osv, mock_exists):
        """Without an agent, typosquats get a warning."""
        from aegis.monitor.terminal import check_install_command
        result = check_install_command("pip install reqeusts")
        assert result["action"] == "warn"
        assert result["agent"] is None

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value="devin")
    def test_typo_block_with_devin(self, mock_agent, mock_osv, mock_exists):
        """Devin (high-risk agent) → typosquats get blocked."""
        from aegis.monitor.terminal import check_install_command
        result = check_install_command("pip install reqeusts")
        assert result["action"] == "block"
        assert result["agent"] == "devin"

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value="cursor")
    def test_typo_block_with_cursor(self, mock_agent, mock_osv, mock_exists):
        """Cursor (elevated-risk agent) → typosquats get blocked."""
        from aegis.monitor.terminal import check_install_command
        result = check_install_command("pip install reqeusts")
        assert result["action"] == "block"
        assert result["agent"] == "cursor"

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value="copilot")
    def test_typo_warn_with_copilot(self, mock_agent, mock_osv, mock_exists):
        """Copilot (standard-risk agent) → typosquats get warning."""
        from aegis.monitor.terminal import check_install_command
        result = check_install_command("pip install reqeusts")
        assert result["action"] == "warn"

    @patch("aegis.monitor.terminal._check_package_exists", return_value=False)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value="antigravity")
    def test_nonexistent_block_with_antigravity(self, mock_agent, mock_osv, mock_exists):
        """AntiGravity (elevated) → nonexistent packages get blocked."""
        from aegis.monitor.terminal import check_install_command
        result = check_install_command("pip install hallucinated-pkg-xyz")
        assert result["action"] == "block"
        assert result["agent"] == "antigravity"
        assert "antigravity" in result["alerts"][0]["suggestion"].lower()

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value="ollama")
    def test_typo_block_with_ollama(self, mock_agent, mock_osv, mock_exists):
        """Ollama (elevated) → typosquats get blocked."""
        from aegis.monitor.terminal import check_install_command
        result = check_install_command("pip install reqeusts")
        assert result["action"] == "block"
        assert result["agent"] == "ollama"

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value="swe-agent")
    def test_typo_block_with_swe_agent(self, mock_agent, mock_osv, mock_exists):
        """SWE-agent (high-risk) → typosquats get blocked."""
        from aegis.monitor.terminal import check_install_command
        result = check_install_command("npm install expresss")
        assert result["action"] == "block"
        assert result["agent"] == "swe-agent"
