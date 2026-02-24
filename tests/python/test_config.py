"""Tests for AEGIS configuration."""

from pathlib import Path
from unittest.mock import patch

import pytest

from aegis.config import AegisConfig, get_config_dir


@pytest.fixture
def temp_config_dir(tmp_path):
    config_dir = tmp_path / ".aegis"
    with patch("aegis.config.get_config_dir", return_value=config_dir):
        yield config_dir


class TestAegisConfig:
    def test_default_values(self):
        config = AegisConfig()
        assert config.mode == "interactive"
        assert config.typosquat_enabled is True
        assert config.typosquat_threshold == 2
        assert config.osv_check is True
        assert config.ecosystems["python"] is True

    def test_save_and_load(self, temp_config_dir):
        config = AegisConfig()
        config.config_path = temp_config_dir / "config.yml"
        config.mode = "strict"
        config.allowlist = ["numpy", "pandas"]
        config.save()

        loaded = AegisConfig.from_file(config.config_path)
        assert loaded.mode == "strict"
        assert loaded.allowlist == ["numpy", "pandas"]

    def test_load_or_create_new(self, temp_config_dir):
        config = AegisConfig.load_or_create()
        assert config.mode == "interactive"
        assert (temp_config_dir / "config.yml").exists()

    def test_load_or_create_existing(self, temp_config_dir):
        # Create first
        config = AegisConfig.load_or_create()
        config.mode = "permissive"
        config.save()

        # Load again
        loaded = AegisConfig.load_or_create()
        assert loaded.mode == "permissive"

    def test_to_dict(self):
        config = AegisConfig()
        d = config.to_dict()
        assert "mode" in d
        assert "ecosystems" in d
        assert "typosquat" in d
        assert "allowlist" in d

    def test_blocklist(self, temp_config_dir):
        config = AegisConfig()
        config.config_path = temp_config_dir / "config.yml"
        config.blocklist = ["colourama", "evil-package"]
        config.save()

        loaded = AegisConfig.from_file(config.config_path)
        assert "colourama" in loaded.blocklist
