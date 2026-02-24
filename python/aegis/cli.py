"""AEGIS CLI — Command-line interface."""

from __future__ import annotations

import json
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


@main.command("check-hook")
def check_hook():
    """Check a Claude Code hook payload from stdin.

    Reads JSON from stdin (PreToolUse payload), extracts the Bash command,
    and runs AEGIS checks with forced_agent="claude-code".

    Protocol:
      - allow  → exit 0, no output
      - warn   → exit 0, JSON with permissionDecision: "ask"
      - block  → exit 0, JSON with permissionDecision: "deny"
    """
    from aegis.hooks.claude import parse_hook_payload
    from aegis.monitor.terminal import check_install_command

    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        # Invalid JSON → pass through (allow)
        sys.exit(0)

    command = parse_hook_payload(payload)
    if command is None:
        # Not a Bash tool call → pass through
        sys.exit(0)

    result = check_install_command(command, forced_agent="claude-code")

    if result["action"] == "block":
        reasons = "; ".join(a.get("reason", "") for a in result["alerts"] if a.get("reason"))
        output = {
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "permissionDecisionReason": f"AEGIS: {reasons}",
            }
        }
        print(json.dumps(output))
    elif result["action"] == "warn":
        reasons = "; ".join(a.get("reason", "") for a in result["alerts"] if a.get("reason"))
        output = {
            "hookSpecificOutput": {
                "permissionDecision": "ask",
                "permissionDecisionReason": f"AEGIS: {reasons}",
            }
        }
        print(json.dumps(output))
    # action == "allow" → exit 0, no output


@main.command("agent-log")
@click.option("--agent", default=None, help="Filter by agent name")
@click.option("--stats", is_flag=True, help="Show summary statistics by agent")
@click.option("--limit", default=50, help="Number of records to show")
def agent_log(agent: str | None, stats: bool, limit: int):
    """View agent activity dashboard."""
    db = AegisDB()

    if stats:
        rows = db.get_agent_stats()
        if not rows:
            console.print("[dim]No agent activity recorded yet.[/dim]")
            return

        table = Table(title="Agent Activity Summary")
        table.add_column("Agent")
        table.add_column("Total", justify="right")
        table.add_column("Allowed", justify="right", style="green")
        table.add_column("Warned", justify="right", style="yellow")
        table.add_column("Blocked", justify="right", style="red")

        for r in rows:
            table.add_row(
                r["agent_name"] or "(unknown)",
                str(r["total"]),
                str(r["allowed"]),
                str(r["warned"]),
                str(r["blocked"]),
            )
        console.print(table)
        return

    if agent:
        decisions = db.get_agent_decisions(agent, limit=limit)
    else:
        decisions = db.get_recent_decisions(limit=limit)

    if not decisions:
        console.print("[dim]No decisions recorded yet.[/dim]")
        return

    table = Table(title=f"Agent Log{f' ({agent})' if agent else ''}")
    table.add_column("Time")
    table.add_column("Agent")
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
            d.get("agent_name") or "-",
            d["package_name"],
            d["ecosystem"],
            f"[{color}]{action.upper()}[/]",
            d.get("reason", ""),
        )

    console.print(table)


@main.group()
def hook():
    """Manage AEGIS hooks for AI agents and shells."""


@hook.command("install")
@click.argument("target", type=click.Choice(["claude", "shell", "browser"]))
def hook_install(target: str):
    """Install an AEGIS hook.

    \b
    Targets:
      claude  — Install PreToolUse hook in ~/.claude/settings.json
      shell   — Install shell_hook.sh in ~/.aegis/
      browser — Install native messaging host for browser extension
    """
    if target == "claude":
        from aegis.hooks.claude import install_hook
        path = install_hook()
        console.print(f"[green]Claude Code hook installed:[/green] {path}")
    elif target == "shell":
        from aegis.hooks.generic import install_shell_hook
        path = install_shell_hook()
        console.print(f"[green]Shell hook installed:[/green] {path}")
        console.print(Panel(
            f"[bold]Add to your .bashrc or .zshrc:[/bold]\n\n  source {path}\n",
            title="Next step",
            border_style="cyan",
        ))
    elif target == "browser":
        from aegis.browser.native_host import install_native_host
        path = install_native_host()
        console.print(f"[green]Browser native host installed:[/green] {path}")


@hook.command("status")
def hook_status():
    """Show which AEGIS hooks are installed."""
    config_dir = get_config_dir()

    # Claude Code hook
    claude_settings = Path.home() / ".claude" / "settings.json"
    claude_installed = False
    if claude_settings.exists():
        try:
            settings = json.loads(claude_settings.read_text())
            for entry in settings.get("hooks", {}).get("PreToolUse", []):
                for h in entry.get("hooks", []):
                    if h.get("command") == "aegis check-hook":
                        claude_installed = True
        except (json.JSONDecodeError, OSError):
            pass
    status = "[green]installed[/green]" if claude_installed else "[yellow]not installed[/yellow]"
    console.print(f"  Claude Code: {status}")

    # Shell hook
    shell_hook = config_dir / "shell_hook.sh"
    status = "[green]installed[/green]" if shell_hook.exists() else "[yellow]not installed[/yellow]"
    console.print(f"  Shell hook:  {status}")

    # Browser native host
    native_host = config_dir / "native_host.json"
    if not native_host.exists():
        # Also check common native messaging host locations
        native_host = Path.home() / ".config" / "google-chrome" / "NativeMessagingHosts" / "com.aegis.security.json"
    status = "[green]installed[/green]" if native_host.exists() else "[yellow]not installed[/yellow]"
    console.print(f"  Browser:     {status}")


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
