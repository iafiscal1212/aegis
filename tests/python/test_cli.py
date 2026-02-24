"""Tests for AEGIS CLI."""

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from aegis.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_aegis_dir(tmp_path):
    """Use a temporary directory instead of ~/.aegis/."""
    aegis_dir = tmp_path / ".aegis"
    # Patch get_config_dir everywhere it's imported
    with patch("aegis.config.get_config_dir", return_value=aegis_dir), \
         patch("aegis.cli.get_config_dir", return_value=aegis_dir), \
         patch("aegis.db.models.get_config_dir", return_value=aegis_dir):
        yield aegis_dir


def test_cli_help(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "AEGIS" in result.output


def test_init_creates_config(runner, temp_aegis_dir):
    result = runner.invoke(main, ["init"])
    assert result.exit_code == 0
    assert temp_aegis_dir.exists()
    assert (temp_aegis_dir / "config.yml").exists()
    assert (temp_aegis_dir / "aegis.db").exists()


def test_status_not_initialized(runner, temp_aegis_dir):
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0


def test_status_after_init(runner, temp_aegis_dir):
    runner.invoke(main, ["init"])
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0


def test_config_display(runner, temp_aegis_dir):
    runner.invoke(main, ["init"])
    result = runner.invoke(main, ["config"])
    assert result.exit_code == 0
    assert "mode" in result.output


def test_log_empty(runner, temp_aegis_dir):
    runner.invoke(main, ["init"])
    result = runner.invoke(main, ["log"])
    assert result.exit_code == 0


@patch("aegis.monitor.terminal._check_package_exists", return_value=None)
@patch("aegis.monitor.terminal._check_osv", return_value=[])
def test_check_safe_package(mock_osv, mock_exists, runner, temp_aegis_dir):
    """Check a known safe package passes."""
    runner.invoke(main, ["init"])
    result = runner.invoke(main, ["check", "pip", "install", "requests"])
    assert result.exit_code == 0


@patch("aegis.monitor.terminal._check_package_exists", return_value=None)
@patch("aegis.monitor.terminal._check_osv", return_value=[])
def test_check_typosquat(mock_osv, mock_exists, runner, temp_aegis_dir):
    """Check a typosquatted package is caught."""
    runner.invoke(main, ["init"])
    result = runner.invoke(main, ["check", "pip", "install", "reqeusts"])
    # Should warn or block (exit 1)
    assert result.exit_code == 1


def test_check_non_install(runner, temp_aegis_dir):
    """Non-install commands should pass through."""
    runner.invoke(main, ["init"])
    result = runner.invoke(main, ["check", "pip", "list"])
    assert result.exit_code == 0
