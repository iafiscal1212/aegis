"""AEGIS alert system — terminal and desktop notifications."""

from __future__ import annotations

from enum import Enum

from rich.console import Console
from rich.panel import Panel


class AlertLevel(Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


def format_decision(alert: dict, console: Console | None = None) -> None:
    """Display an alert to the terminal using Rich."""
    if console is None:
        console = Console(stderr=True)

    level = alert.get("level", "info")
    package = alert.get("package", "unknown")
    reason = alert.get("reason", "")
    suggestion = alert.get("suggestion", "")

    styles = {
        "block": ("red", "BLOCKED"),
        "warn": ("yellow", "WARNING"),
        "allow": ("green", "ALLOWED"),
    }

    color, label = styles.get(level, ("white", "INFO"))

    content = f"[bold]Package:[/bold] {package}\n"
    if reason:
        content += f"[bold]Reason:[/bold]  {reason}\n"
    if suggestion:
        content += f"[bold]Hint:[/bold]    {suggestion}"

    console.print(Panel(
        content.strip(),
        title=f"[{color} bold]AEGIS {label}[/]",
        border_style=color,
    ))
