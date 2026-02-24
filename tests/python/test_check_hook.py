"""Tests for the aegis check-hook CLI command."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from aegis.cli import main


@pytest.fixture
def runner():
    return CliRunner()


class TestCheckHook:
    def test_non_bash_passthrough(self, runner):
        payload = json.dumps({"tool_name": "Edit", "tool_input": {"file": "foo.py"}})
        result = runner.invoke(main, ["check-hook"], input=payload)
        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_invalid_json_passthrough(self, runner):
        result = runner.invoke(main, ["check-hook"], input="not json at all")
        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_empty_input(self, runner):
        result = runner.invoke(main, ["check-hook"], input="")
        assert result.exit_code == 0

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_safe_install_allow(self, mock_agent, mock_osv, mock_exists, runner):
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "pip install requests"},
        })
        result = runner.invoke(main, ["check-hook"], input=payload)
        assert result.exit_code == 0
        assert result.output.strip() == ""

    @patch("aegis.monitor.terminal._check_package_exists", return_value=False)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_nonexistent_package_block(self, mock_agent, mock_osv, mock_exists, runner):
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "pip install totally-hallucinated-pkg"},
        })
        result = runner.invoke(main, ["check-hook"], input=payload)
        assert result.exit_code == 0
        output = json.loads(result.output)
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    @patch("aegis.monitor.terminal.detect_ai_agent", return_value=None)
    def test_typosquat_block(self, mock_agent, mock_osv, mock_exists, runner):
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "pip install requets"},
        })
        result = runner.invoke(main, ["check-hook"], input=payload)
        assert result.exit_code == 0
        # Claude Code hook uses forced_agent="claude-code" so threshold=1
        # "requets" is distance 1 from "requests" → caught with threshold 1
        output = json.loads(result.output)
        assert output["hookSpecificOutput"]["permissionDecision"] in ("deny", "ask")

    def test_non_install_passthrough(self, runner):
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        result = runner.invoke(main, ["check-hook"], input=payload)
        assert result.exit_code == 0
        assert result.output.strip() == ""

    def test_bash_without_command_key(self, runner):
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"timeout": 5000},
        })
        result = runner.invoke(main, ["check-hook"], input=payload)
        assert result.exit_code == 0
        assert result.output.strip() == ""
