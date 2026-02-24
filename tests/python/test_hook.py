"""Tests for AEGIS hooks — Claude Code payload parsing."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from aegis.hooks.claude import parse_hook_payload, get_hook_config, install_hook


class TestParseHookPayload:
    def test_bash_install(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "pip install requests"}}
        assert parse_hook_payload(payload) == "pip install requests"

    def test_bash_non_install(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        assert parse_hook_payload(payload) == "ls -la"

    def test_non_bash_tool(self):
        payload = {"tool_name": "Edit", "tool_input": {"file": "foo.py"}}
        assert parse_hook_payload(payload) is None

    def test_bash_missing_command(self):
        payload = {"tool_name": "Bash", "tool_input": {}}
        assert parse_hook_payload(payload) is None

    def test_empty_payload(self):
        assert parse_hook_payload({}) is None

    def test_missing_tool_input(self):
        payload = {"tool_name": "Bash"}
        assert parse_hook_payload(payload) is None

    def test_empty_command_string(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": ""}}
        assert parse_hook_payload(payload) is None

    def test_command_not_string(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": 123}}
        assert parse_hook_payload(payload) is None


class TestGetHookConfig:
    def test_structure(self):
        config = get_hook_config()
        assert "hooks" in config
        assert "PreToolUse" in config["hooks"]
        entries = config["hooks"]["PreToolUse"]
        assert len(entries) == 1
        assert entries[0]["matcher"] == "Bash"
        assert entries[0]["hooks"][0]["command"] == "aegis check-hook"

    def test_hook_type(self):
        config = get_hook_config()
        hook = config["hooks"]["PreToolUse"][0]["hooks"][0]
        assert hook["type"] == "command"


class TestInstallHook:
    def test_install_creates_file(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        with patch("aegis.hooks.claude.Path.home", return_value=tmp_path):
            result = install_hook()

        assert settings_path.exists()
        data = json.loads(settings_path.read_text())
        assert "hooks" in data
        hooks = data["hooks"]["PreToolUse"]
        assert any(
            h.get("command") == "aegis check-hook"
            for entry in hooks
            for h in entry.get("hooks", [])
        )

    def test_install_merges_existing(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps({
            "someOtherSetting": True,
            "hooks": {"PostToolUse": []}
        }))

        with patch("aegis.hooks.claude.Path.home", return_value=tmp_path):
            install_hook()

        data = json.loads(settings_path.read_text())
        assert data["someOtherSetting"] is True
        assert "PostToolUse" in data["hooks"]
        assert "PreToolUse" in data["hooks"]

    def test_install_idempotent(self, tmp_path):
        with patch("aegis.hooks.claude.Path.home", return_value=tmp_path):
            install_hook()
            install_hook()

        settings_path = tmp_path / ".claude" / "settings.json"
        data = json.loads(settings_path.read_text())
        # Should not duplicate the hook
        aegis_hooks = [
            h
            for entry in data["hooks"]["PreToolUse"]
            for h in entry.get("hooks", [])
            if h.get("command") == "aegis check-hook"
        ]
        assert len(aegis_hooks) == 1
