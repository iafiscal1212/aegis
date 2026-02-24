"""Destructive command detector for AI agents.

Philosophy: NEVER block, only ASK. The user may legitimately want to run
destructive commands — AEGIS just ensures it's intentional.
"""

from __future__ import annotations

import re


# --------------------------------------------------------------------------- #
# Critical patterns — ask with detailed reason
# --------------------------------------------------------------------------- #

_CRITICAL_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # rm -rf / variants
    (
        re.compile(r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\s*$"),
        "filesystem_destroy",
        "rm -rf / would destroy the entire filesystem",
    ),
    (
        re.compile(r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\*"),
        "filesystem_destroy",
        "rm -rf /* would destroy all top-level directories",
    ),
    (
        re.compile(r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+~/?(\s|$)"),
        "filesystem_destroy",
        "rm -rf ~ would destroy the entire home directory",
    ),
    # dd to block devices
    (
        re.compile(r"\bdd\b.*\bof=/dev/"),
        "disk_overwrite",
        "dd to a block device can destroy disk data irreversibly",
    ),
    # Filesystem formatting
    (
        re.compile(r"\bmkfs\b"),
        "disk_format",
        "mkfs would format a filesystem, destroying all data on it",
    ),
    (
        re.compile(r"\bfdisk\b"),
        "disk_partition",
        "fdisk modifies disk partition tables",
    ),
    (
        re.compile(r"\bparted\b"),
        "disk_partition",
        "parted modifies disk partition tables",
    ),
    # Fork bomb
    (
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        "fork_bomb",
        "Fork bomb — would crash the system by exhausting resources",
    ),
    # Recursive permissions on root
    (
        re.compile(r"\bchmod\s+.*-R\s+777\s+/\s*$"),
        "permissions_destroy",
        "chmod -R 777 / would make every file world-writable",
    ),
    (
        re.compile(r"\bchown\s+.*-R\s+\S+\s+/\s*$"),
        "permissions_destroy",
        "chown -R on / would change ownership of all files",
    ),
    # Write to block device
    (
        re.compile(r">\s*/dev/[hs]d[a-z]"),
        "disk_overwrite",
        "Redirecting output to a block device overwrites the disk",
    ),
    # Remote code execution via pipe
    (
        re.compile(r"\b(curl|wget)\b.*\|\s*(ba)?sh\b"),
        "remote_code_exec",
        "Piping remote content to shell executes arbitrary code",
    ),
    # SQL destructive — database level
    (
        re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE),
        "sql_destroy",
        "DROP DATABASE would permanently delete an entire database",
    ),
    (
        re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
        "sql_destroy",
        "DROP TABLE would permanently delete a table and its data",
    ),
    (
        re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
        "sql_destroy",
        "TRUNCATE TABLE would delete all rows irreversibly",
    ),
    # System shutdown/reboot
    (
        re.compile(r"\b(shutdown|reboot)\b"),
        "system_shutdown",
        "This command would shut down or reboot the system",
    ),
    (
        re.compile(r"\binit\s+0\b"),
        "system_shutdown",
        "init 0 would halt the system",
    ),
    # Git force push to main/master
    (
        re.compile(r"\bgit\s+push\s+.*--force\b.*\b(main|master)\b"),
        "git_force_push",
        "Force push to main/master can overwrite shared history",
    ),
    (
        re.compile(r"\bgit\s+push\s+.*\b(main|master)\b.*--force\b"),
        "git_force_push",
        "Force push to main/master can overwrite shared history",
    ),
]

# --------------------------------------------------------------------------- #
# Warning patterns — ask with brief reason
# --------------------------------------------------------------------------- #

_WARNING_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # rm -rf (any path, recursive+force)
    (
        re.compile(r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+\S+"),
        "recursive_delete",
        "Recursive forced delete — make sure the path is correct",
    ),
    # rm -r (recursive without force)
    (
        re.compile(r"\brm\s+.*-[a-zA-Z]*r\s+\S+"),
        "recursive_delete",
        "Recursive delete — make sure the path is correct",
    ),
    # Git hard reset / clean
    (
        re.compile(r"\bgit\s+reset\s+--hard\b"),
        "git_destructive",
        "git reset --hard discards all uncommitted changes",
    ),
    (
        re.compile(r"\bgit\s+clean\s+.*-[a-zA-Z]*f"),
        "git_destructive",
        "git clean -f removes untracked files permanently",
    ),
    # kill -9 / pkill -9
    (
        re.compile(r"\b(kill|pkill)\s+.*-9\b"),
        "process_kill",
        "Signal 9 (SIGKILL) terminates processes without cleanup",
    ),
    (
        re.compile(r"\b(kill|pkill)\s+-9\b"),
        "process_kill",
        "Signal 9 (SIGKILL) terminates processes without cleanup",
    ),
    # systemctl stop/disable
    (
        re.compile(r"\bsystemctl\s+(stop|disable)\b"),
        "service_control",
        "Stopping/disabling a service may affect system functionality",
    ),
    # Docker destructive
    (
        re.compile(r"\bdocker\s+rm\s+.*-f\b"),
        "docker_destructive",
        "Forcefully removing Docker containers",
    ),
    (
        re.compile(r"\bdocker\s+system\s+prune\s+.*-a\b"),
        "docker_destructive",
        "docker system prune -a removes all unused images, containers, and networks",
    ),
    # chmod 777 (not recursive on root — that's critical)
    (
        re.compile(r"\bchmod\s+777\b"),
        "permissions_unsafe",
        "chmod 777 makes files world-readable and writable",
    ),
    # SQL DELETE without WHERE
    (
        re.compile(r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", re.IGNORECASE),
        "sql_delete",
        "DELETE FROM without WHERE would delete all rows in the table",
    ),
]


def check_destructive_command(command: str) -> dict | None:
    """Check if a command is potentially destructive.

    Returns:
        dict with {"level": "critical"|"warning", "reason": str, "category": str}
        or None if the command appears safe.
    """
    # Check critical patterns first (higher priority)
    for pattern, category, reason in _CRITICAL_PATTERNS:
        if pattern.search(command):
            return {"level": "critical", "reason": reason, "category": category}

    # Then check warning patterns
    for pattern, category, reason in _WARNING_PATTERNS:
        if pattern.search(command):
            return {"level": "warning", "reason": reason, "category": category}

    return None
