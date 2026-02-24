"""AEGIS hooks for generic AI agents — Cursor, Aider, shell."""

from __future__ import annotations

from pathlib import Path

from aegis.config import get_config_dir


def get_cursor_rules() -> str:
    """Generate .cursorrules content that instructs Cursor to use AEGIS."""
    return """\
# AEGIS Security Rules for Cursor
# Place this file in your project root as .cursorrules

## Package Installation
- Before installing ANY package, verify it exists in the official registry.
- NEVER install packages without checking for typosquatting.
- If AEGIS is installed, always run: aegis check <manager> install <package>
- Do NOT install packages that AEGIS blocks or warns about without user confirmation.

## Security
- Do not disable AEGIS hooks or shell integrations.
- Report any AEGIS warnings to the user before proceeding.
"""


def get_aider_config() -> dict:
    """Generate config for .aider.conf.yml that integrates AEGIS."""
    return {
        "lint-cmd": "aegis check pip install",
        "auto-lint": True,
        "show-diffs": True,
    }


def install_shell_hook() -> Path:
    """Install the AEGIS shell hook programmatically.

    Copies/creates shell_hook.sh into ~/.aegis/ and returns its path.
    """
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    hook_path = config_dir / "shell_hook.sh"

    # Try to copy from package source first
    src = Path(__file__).parent.parent / "monitor" / "shell_hook.sh"
    if src.exists():
        hook_path.write_text(src.read_text())
    else:
        hook_path.write_text(_default_shell_hook())

    hook_path.chmod(0o755)
    return hook_path


def _default_shell_hook() -> str:
    return """\
#!/bin/bash
# AEGIS Shell Hook — intercepts package install commands
# Source this file in your .bashrc or .zshrc:
#   source ~/.aegis/shell_hook.sh

aegis_pip() {
    if command -v aegis &>/dev/null; then
        aegis check pip "$@" && command pip "$@"
    else
        command pip "$@"
    fi
}

aegis_pip3() {
    if command -v aegis &>/dev/null; then
        aegis check pip3 "$@" && command pip3 "$@"
    else
        command pip3 "$@"
    fi
}

aegis_npm() {
    if command -v aegis &>/dev/null; then
        aegis check npm "$@" && command npm "$@"
    else
        command npm "$@"
    fi
}

aegis_yarn() {
    if command -v aegis &>/dev/null; then
        aegis check yarn "$@" && command yarn "$@"
    else
        command yarn "$@"
    fi
}

aegis_cargo() {
    if command -v aegis &>/dev/null; then
        aegis check cargo "$@" && command cargo "$@"
    else
        command cargo "$@"
    fi
}

alias pip='aegis_pip'
alias pip3='aegis_pip3'
alias npm='aegis_npm'
alias yarn='aegis_yarn'
alias cargo='aegis_cargo'

# Indicate AEGIS is active
if command -v aegis &>/dev/null; then
    echo "[AEGIS] Shell hooks active. Package installs are protected."
fi
"""
