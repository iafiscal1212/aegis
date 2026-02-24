"""Tests for AEGIS terminal monitor."""

from unittest.mock import patch

import pytest

from aegis.monitor.terminal import (
    check_install_command,
    _parse_command_python,
    _levenshtein,
    _check_typosquat_python,
)


class TestPythonFallbackParser:
    """Test the pure Python command parser."""

    def test_pip_install(self):
        result = _parse_command_python("pip install requests")
        assert result is not None
        assert result["ecosystem"] == "python"
        assert result["packages"][0]["name"] == "requests"

    def test_pip_install_multiple(self):
        result = _parse_command_python("pip install flask django numpy")
        assert len(result["packages"]) == 3

    def test_pip_install_with_version(self):
        result = _parse_command_python("pip install requests==2.28.0")
        assert result["packages"][0]["name"] == "requests"

    def test_npm_install(self):
        result = _parse_command_python("npm install express")
        assert result["ecosystem"] == "node"
        assert result["packages"][0]["name"] == "express"

    def test_cargo_add(self):
        result = _parse_command_python("cargo add serde")
        assert result["ecosystem"] == "rust"

    def test_non_install(self):
        assert _parse_command_python("pip list") is None
        assert _parse_command_python("npm run build") is None
        assert _parse_command_python("ls -la") is None

    def test_empty(self):
        assert _parse_command_python("") is None
        assert _parse_command_python("pip") is None

    def test_flags_ignored(self):
        result = _parse_command_python("pip install --pre torch")
        assert result is not None
        assert any(p["name"] == "torch" for p in result["packages"])


class TestLevenshtein:
    def test_same(self):
        assert _levenshtein("abc", "abc") == 0

    def test_one_edit(self):
        assert _levenshtein("abc", "adc") == 1

    def test_requests_typo(self):
        assert _levenshtein("requests", "reqeusts") == 2

    def test_empty(self):
        assert _levenshtein("", "abc") == 3
        assert _levenshtein("abc", "") == 3


class TestTyposquatPythonFallback:
    def test_known_package(self):
        result = _check_typosquat_python("requests", "python", 2)
        assert not result["is_suspect"]

    def test_typo_detected(self):
        result = _check_typosquat_python("reqeusts", "python", 2)
        assert result["is_suspect"]
        assert result["closest_match"] == "requests"

    def test_colorama_typo(self):
        result = _check_typosquat_python("colourama", "python", 2)
        assert result["is_suspect"]

    def test_unknown_safe(self):
        result = _check_typosquat_python("my-unique-internal-tool", "python", 2)
        assert not result["is_suspect"]


class TestCheckInstallCommand:
    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    def test_safe_package_allowed(self, mock_osv, mock_exists):
        result = check_install_command("pip install requests")
        assert result["action"] == "allow"

    @patch("aegis.monitor.terminal._check_package_exists", return_value=None)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    def test_typo_detected(self, mock_osv, mock_exists):
        result = check_install_command("pip install reqeusts")
        assert result["action"] in ("warn", "block")
        assert len(result["alerts"]) > 0

    def test_non_install_passthrough(self):
        result = check_install_command("pip list")
        assert result["action"] == "allow"

    def test_empty_command(self):
        result = check_install_command("")
        assert result["action"] == "allow"

    @patch("aegis.monitor.terminal._check_package_exists", return_value=False)
    @patch("aegis.monitor.terminal._check_osv", return_value=[])
    def test_nonexistent_package_warned(self, mock_osv, mock_exists):
        result = check_install_command("pip install totally-fake-pkg-xyz-123")
        assert result["action"] in ("warn", "block")
