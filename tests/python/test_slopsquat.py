"""Tests for slopsquatting detection and agent context in terminal monitor."""

from unittest.mock import patch

import pytest

from aegis.monitor.terminal import check_install_command


class TestSlopsquattingAgent:
    """Slopsquatting detection when an AI agent is detected."""

    @patch("aegis.monitor.terminal._check_package_exists", return_value=False)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_agent_nonexistent_package_blocked(self, mock_agent, mock_osv, mock_exists):
        """Agent + non-existent package → block (slopsquatting)."""
        result = check_install_command("pip install fake-ai-pkg", forced_agent="claude-code")
        assert result["action"] == "block"
        assert result["agent"] == "claude-code"
        assert any("slopsquatting" in a["reason"].lower() for a in result["alerts"])

    @patch("aegis.monitor.terminal._check_package_exists", return_value=False)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_human_nonexistent_package_warned(self, mock_agent, mock_osv, mock_exists):
        """Human + non-existent package → warn (not block)."""
        result = check_install_command("pip install fake-ai-pkg")
        assert result["action"] == "warn"
        assert result["agent"] is None

    @patch("aegis.monitor.terminal._check_package_exists", return_value=True)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_agent_existing_package_allowed(self, mock_agent, mock_osv, mock_exists):
        """Agent + existing package → allow."""
        result = check_install_command("pip install requests", forced_agent="claude-code")
        assert result["action"] == "allow"


class TestForcedAgent:
    """Test forced_agent parameter overrides auto-detection."""

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value="cursor")
    def test_forced_agent_overrides_detection(self, mock_agent, mock_osv, mock_exists):
        result = check_install_command("pip install requests", forced_agent="claude-code")
        assert result["agent"] == "claude-code"

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value="cursor")
    def test_auto_detection_when_no_forced(self, mock_agent, mock_osv, mock_exists):
        result = check_install_command("pip install requests")
        assert result["agent"] == "cursor"


class TestAgentBlocklist:
    """Test agent_blocklist config."""

    @patch("aegis.monitor.terminal._check_package_exists", return_value=True)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    @patch("aegis.monitor.terminal.AegisConfig.load_or_create")
    def test_blocklisted_agent_blocks_all(self, mock_config, mock_agent, mock_osv, mock_exists):
        from aegis.config import AegisConfig
        config = AegisConfig()
        config.agent_blocklist = ["evil-agent"]
        mock_config.return_value = config

        result = check_install_command("pip install requests", forced_agent="evil-agent")
        assert result["action"] == "block"
        assert "agent blocklist" in result["alerts"][0]["reason"].lower()

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    @patch("aegis.monitor.terminal.AegisConfig.load_or_create")
    def test_non_blocklisted_agent_passes(self, mock_config, mock_agent, mock_osv, mock_exists):
        from aegis.config import AegisConfig
        config = AegisConfig()
        config.agent_blocklist = ["evil-agent"]
        mock_config.return_value = config

        result = check_install_command("pip install requests", forced_agent="claude-code")
        assert result["action"] == "allow"


class TestAgentAllowlist:
    """Test agent_allowlist config (no escalation for trusted agents)."""

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    @patch("aegis.monitor.terminal.AegisConfig.load_or_create")
    def test_allowlisted_agent_no_escalation(self, mock_config, mock_agent, mock_osv, mock_exists):
        from aegis.config import AegisConfig
        config = AegisConfig()
        config.agent_allowlist = ["trusted-bot"]
        mock_config.return_value = config

        result = check_install_command("pip install requests", forced_agent="trusted-bot")
        assert result["action"] == "allow"


class TestAgentTyposquatThreshold:
    """Test that agents get a stricter typosquat threshold."""

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_agent_stricter_threshold(self, mock_agent, mock_osv, mock_exists):
        # "requets" is distance 1 from "requests"
        # Agent threshold=1 → should catch it
        result = check_install_command("pip install requets", forced_agent="claude-code")
        assert result["action"] in ("warn", "block")
        assert len(result["alerts"]) > 0

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_human_lenient_threshold(self, mock_agent, mock_osv, mock_exists):
        # "requets" is distance 1 from "requests"
        # Human threshold=2 → also catches it (1 <= 2)
        result = check_install_command("pip install requets")
        assert result["action"] in ("warn", "block")
