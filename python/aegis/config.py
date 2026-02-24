"""AEGIS configuration management."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


def get_config_dir() -> Path:
    """Get the AEGIS config directory (~/.aegis/)."""
    return Path.home() / ".aegis"


@dataclass
class AegisConfig:
    mode: str = "interactive"  # interactive | strict | permissive
    ecosystems: dict[str, bool] = field(default_factory=lambda: {
        "python": True,
        "node": True,
        "rust": True,
    })
    typosquat_threshold: int = 2
    typosquat_enabled: bool = True
    lifecycle_block_preinstall: bool = True
    lifecycle_block_postinstall: str = "warn"  # block | warn | allow
    osv_check: bool = True
    notifications_terminal: bool = True
    notifications_desktop: bool = False
    allowlist: list[str] = field(default_factory=list)
    blocklist: list[str] = field(default_factory=list)
    config_path: Path = field(default_factory=lambda: get_config_dir() / "config.yml")

    @classmethod
    def load_or_create(cls) -> AegisConfig:
        """Load config from file or create default."""
        config_path = get_config_dir() / "config.yml"

        if config_path.exists():
            return cls.from_file(config_path)

        config = cls()
        config.save()
        return config

    @classmethod
    def from_file(cls, path: Path) -> AegisConfig:
        """Load config from a YAML file."""
        data = yaml.safe_load(path.read_text()) or {}

        config = cls()
        config.config_path = path
        config.mode = data.get("mode", config.mode)

        eco = data.get("ecosystems", {})
        if eco:
            config.ecosystems = {
                "python": eco.get("python", True),
                "node": eco.get("node", True),
                "rust": eco.get("rust", True),
            }

        ts = data.get("typosquat", {})
        if ts:
            config.typosquat_threshold = ts.get("threshold", config.typosquat_threshold)
            config.typosquat_enabled = ts.get("enabled", config.typosquat_enabled)

        ls = data.get("lifecycle_scripts", {})
        if ls:
            config.lifecycle_block_preinstall = ls.get("block_preinstall", True)
            config.lifecycle_block_postinstall = ls.get("block_postinstall", "warn")

        config.osv_check = data.get("osv_check", config.osv_check)

        notif = data.get("notifications", {})
        if notif:
            config.notifications_terminal = notif.get("terminal", True)
            config.notifications_desktop = notif.get("desktop", False)

        config.allowlist = data.get("allowlist", [])
        config.blocklist = data.get("blocklist", [])

        return config

    def to_dict(self) -> dict:
        """Convert to dict for YAML serialization."""
        return {
            "mode": self.mode,
            "ecosystems": self.ecosystems,
            "typosquat": {
                "threshold": self.typosquat_threshold,
                "enabled": self.typosquat_enabled,
            },
            "lifecycle_scripts": {
                "block_preinstall": self.lifecycle_block_preinstall,
                "block_postinstall": self.lifecycle_block_postinstall,
            },
            "osv_check": self.osv_check,
            "notifications": {
                "terminal": self.notifications_terminal,
                "desktop": self.notifications_desktop,
            },
            "allowlist": self.allowlist,
            "blocklist": self.blocklist,
        }

    def save(self):
        """Save config to file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(yaml.dump(self.to_dict(), default_flow_style=False))
