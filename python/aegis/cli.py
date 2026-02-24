"""AEGIS CLI — Command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis.config import AegisConfig, get_config_dir
from aegis.db.models import AegisDB
from aegis.alert import format_decision, AlertLevel

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(package_name="aegis-security")
def main():
    """AEGIS — AI Environment Guardian & Integrity Shield.

    Supply chain security for developers and AI coding agents.
    """


@main.command()
def init():
    """Initialize AEGIS (~/.aegis/ with config and DB)."""
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)

    # Create default config
    config = AegisConfig.load_or_create()
    console.print(f"[green]Config created:[/green] {config.config_path}")

    # Initialize DB
    db = AegisDB()
    db.initialize()
    console.print(f"[green]Database created:[/green] {db.db_path}")

    # Copy shell hook
    hook_path = config_dir / "shell_hook.sh"
    if not hook_path.exists():
        hook_src = Path(__file__).parent / "monitor" / "shell_hook.sh"
        if hook_src.exists():
            hook_path.write_text(hook_src.read_text())
        else:
            _write_default_shell_hook(hook_path)
    console.print(f"[green]Shell hook:[/green] {hook_path}")

    console.print()
    console.print(Panel(
        f"[bold]Add to your .bashrc or .zshrc:[/bold]\n\n"
        f"  source {hook_path}\n",
        title="Next step",
        border_style="cyan",
    ))


@main.command()
@click.argument("manager")
@click.argument("args", nargs=-1)
def check(manager: str, args: tuple[str, ...]):
    """Check a package install command before execution.

    Used by shell hooks: aegis check pip install requests
    """
    from aegis.monitor.terminal import check_install_command

    full_cmd = f"{manager} {' '.join(args)}"
    result = check_install_command(full_cmd)

    if result["action"] == "block":
        for alert in result["alerts"]:
            format_decision(alert, console=err_console)
        sys.exit(1)
    elif result["action"] == "warn":
        for alert in result["alerts"]:
            format_decision(alert, console=err_console)
        # In interactive mode, ask user
        config = AegisConfig.load_or_create()
        if config.mode == "interactive":
            if not click.confirm("Proceed anyway?", default=False, err=True):
                sys.exit(1)
    # action == "allow" → exit 0 (success)


@main.command()
@click.argument("target", default=".")
def scan(target: str):
    """Scan a directory or package for suspicious patterns."""
    from aegis.analyzer.package import scan_directory, scan_package_name

    target_path = Path(target)

    if target_path.is_dir():
        console.print(f"[bold]Scanning directory:[/bold] {target_path.resolve()}")
        results = scan_directory(target_path)
    else:
        console.print(f"[bold]Scanning package:[/bold] {target}")
        results = scan_package_name(target)

    if not results["findings"]:
        console.print("[green]No suspicious patterns found.[/green]")
        return

    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Description")
    table.add_column("File")
    table.add_column("Line")

    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }

    for f in results["findings"]:
        sev = f.get("severity", "info")
        table.add_row(
            f"[{severity_colors.get(sev, '')}]{sev.upper()}[/]",
            f.get("category", ""),
            f.get("description", ""),
            f.get("file", ""),
            str(f.get("line", "")),
        )

    console.print(table)
    console.print(f"\n[bold]Risk score:[/bold] {results['risk_score']:.2f}/1.00")


@main.command()
def log():
    """View decision history."""
    db = AegisDB()
    decisions = db.get_recent_decisions(limit=50)

    if not decisions:
        console.print("[dim]No decisions recorded yet.[/dim]")
        return

    table = Table(title="Decision History")
    table.add_column("Time")
    table.add_column("Package")
    table.add_column("Ecosystem")
    table.add_column("Action", style="bold")
    table.add_column("Reason")

    action_colors = {"allow": "green", "warn": "yellow", "block": "red"}

    for d in decisions:
        action = d["action"]
        color = action_colors.get(action, "")
        table.add_row(
            d["timestamp"],
            d["package_name"],
            d["ecosystem"],
            f"[{color}]{action.upper()}[/]",
            d.get("reason", ""),
        )

    console.print(table)


@main.command()
def config():
    """View current configuration."""
    cfg = AegisConfig.load_or_create()
    import yaml

    console.print(Panel(
        yaml.dump(cfg.to_dict(), default_flow_style=False),
        title=f"Config: {cfg.config_path}",
        border_style="blue",
    ))


@main.command()
def status():
    """Show AEGIS status."""
    config_dir = get_config_dir()
    db_path = config_dir / "aegis.db"

    console.print("[bold]AEGIS Status[/bold]\n")
    console.print(f"  Config dir:  {config_dir}")
    console.print(f"  Initialized: {'[green]yes[/green]' if config_dir.exists() else '[red]no[/red]'}")
    console.print(f"  Database:    {'[green]exists[/green]' if db_path.exists() else '[red]missing[/red]'}")

    # Check shell hook
    shell_hook = config_dir / "shell_hook.sh"
    console.print(f"  Shell hook:  {'[green]exists[/green]' if shell_hook.exists() else '[yellow]not installed[/yellow]'}")

    # Try to load Rust core
    try:
        from aegis import aegis_core  # noqa: F401
        console.print("  Rust core:   [green]loaded[/green]")
    except ImportError:
        console.print("  Rust core:   [yellow]not available (pure Python fallback)[/yellow]")

    # DB stats
    if db_path.exists():
        db = AegisDB()
        stats = db.get_stats()
        console.print(f"\n  Packages analyzed: {stats['packages']}")
        console.print(f"  Decisions logged:  {stats['decisions']}")


def _write_default_shell_hook(path: Path):
    """Write the default shell hook script."""
    path.write_text("""\
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
""")


if __name__ == "__main__":
    main()
