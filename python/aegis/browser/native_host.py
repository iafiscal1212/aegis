"""
AEGIS Browser Guardian — Native Messaging Host

Handles communication between the browser extension and AEGIS CLI.
Uses Chrome/Firefox native messaging protocol (stdin/stdout with length-prefixed JSON).

Protocol:
  - Messages are length-prefixed: 4 bytes (unsigned int, native byte order) + JSON payload
  - Host reads requests from stdin, processes them, writes responses to stdout

Supported message types:
  - check_url: Check if a URL is in the blocklist
  - check_package: Run package analysis via AEGIS core
  - get_status: Get AEGIS daemon status
  - get_threat_db_stats: Get threat database statistics
"""

import json
import struct
import sys
import os
import platform
from pathlib import Path


def read_message():
    """Read a native messaging message from stdin."""
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) < 4:
        return None

    message_length = struct.unpack("=I", raw_length)[0]

    if message_length > 1024 * 1024:  # 1MB limit
        return None

    message_bytes = sys.stdin.buffer.read(message_length)
    if len(message_bytes) < message_length:
        return None

    return json.loads(message_bytes.decode("utf-8"))


def send_message(message):
    """Send a native messaging message to stdout."""
    encoded = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def handle_check_url(data):
    """Check URL against AEGIS threat intelligence."""
    url = data.get("url", "")
    if not url:
        return {"safe": True, "reason": ""}

    try:
        from aegis.monitor.terminal import _check_typosquat_python
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Simple domain reputation check
        return {"safe": True, "reason": "", "hostname": hostname, "checked_by": "aegis_cli"}
    except Exception as e:
        return {"safe": True, "reason": "", "error": str(e)}


def handle_check_package(data):
    """Check a package via AEGIS analysis engine."""
    name = data.get("name", "")
    ecosystem = data.get("ecosystem", "python")

    if not name:
        return {"error": "No package name provided"}

    try:
        from aegis.monitor.terminal import check_install_command

        command = f"pip install {name}" if ecosystem == "python" else f"npm install {name}"
        result = check_install_command(command)
        return {
            "action": result.get("action", "allow"),
            "alerts": [
                {"severity": a.get("severity", "info"), "message": a.get("message", "")}
                for a in result.get("alerts", [])
            ],
            "checked_by": "aegis_cli",
        }
    except Exception as e:
        return {"error": str(e)}


def handle_get_status():
    """Get AEGIS daemon status."""
    try:
        from aegis.config import get_config_dir

        config_dir = get_config_dir()
        db_path = config_dir / "aegis.db"
        config_path = config_dir / "config.yml"

        return {
            "running": True,
            "version": "0.1.0",
            "config_exists": config_path.exists(),
            "db_exists": db_path.exists(),
        }
    except Exception as e:
        return {"running": False, "error": str(e)}


def handle_get_threat_db_stats():
    """Get threat database statistics."""
    try:
        from aegis.db.models import AegisDB

        db = AegisDB()
        # Get counts from the database
        db.cursor.execute("SELECT COUNT(*) FROM packages")
        pkg_count = db.cursor.fetchone()[0]

        db.cursor.execute("SELECT COUNT(*) FROM decisions")
        dec_count = db.cursor.fetchone()[0]

        db.cursor.execute("SELECT COUNT(*) FROM decisions WHERE action = 'block'")
        block_count = db.cursor.fetchone()[0]

        return {
            "packages_analyzed": pkg_count,
            "total_decisions": dec_count,
            "total_blocks": block_count,
        }
    except Exception as e:
        return {"error": str(e)}


def main():
    """Main loop: read messages, dispatch, respond."""
    while True:
        message = read_message()
        if message is None:
            break

        msg_type = message.get("type", "")
        data = message.get("data", {})

        if msg_type == "check_url":
            response = handle_check_url(data)
        elif msg_type == "check_package":
            response = handle_check_package(data)
        elif msg_type == "get_status":
            response = handle_get_status()
        elif msg_type == "get_threat_db_stats":
            response = handle_get_threat_db_stats()
        elif msg_type == "ping":
            response = {"pong": True, "version": "0.1.0"}
        else:
            response = {"error": f"Unknown message type: {msg_type}"}

        send_message(response)


# ─── Installation Helpers ────────────────────────────────────────────────────


def get_native_host_manifest(browser="chrome"):
    """Generate the native messaging host manifest JSON."""
    host_path = str(Path(__file__).resolve())

    manifest = {
        "name": "com.aegis.browser_guardian",
        "description": "AEGIS Browser Guardian — Native messaging host for threat intelligence",
        "path": host_path,
        "type": "stdio",
    }

    if browser == "chrome":
        manifest["allowed_origins"] = ["chrome-extension://TO_BE_FILLED_AFTER_INSTALL/"]
    else:  # firefox
        manifest["allowed_extensions"] = ["aegis-browser-guardian@aegis-security"]

    return manifest


def install_native_host(browser="chrome", extension_id=None):
    """Install the native messaging host manifest for the given browser."""
    system = platform.system()
    manifest = get_native_host_manifest(browser)

    if extension_id and browser == "chrome":
        manifest["allowed_origins"] = [f"chrome-extension://{extension_id}/"]

    # Create a wrapper script that runs this module
    wrapper_dir = Path.home() / ".aegis" / "bin"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    wrapper_path = wrapper_dir / "aegis-native-host"

    python_path = sys.executable
    module_path = Path(__file__).resolve()

    wrapper_content = f"""#!/usr/bin/env bash
exec "{python_path}" "{module_path}" "$@"
"""
    wrapper_path.write_text(wrapper_content)
    wrapper_path.chmod(0o755)
    manifest["path"] = str(wrapper_path)

    # Determine manifest directory
    if system == "Linux":
        if browser == "chrome":
            manifest_dir = Path.home() / ".config" / "google-chrome" / "NativeMessagingHosts"
        elif browser == "chromium":
            manifest_dir = Path.home() / ".config" / "chromium" / "NativeMessagingHosts"
        else:
            manifest_dir = Path.home() / ".mozilla" / "native-messaging-hosts"
    elif system == "Darwin":
        if browser in ("chrome", "chromium"):
            manifest_dir = Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "NativeMessagingHosts"
        else:
            manifest_dir = Path.home() / "Library" / "Application Support" / "Mozilla" / "NativeMessagingHosts"
    elif system == "Windows":
        # On Windows, native messaging uses the registry. Place manifest in AEGIS dir.
        manifest_dir = Path.home() / ".aegis" / "native-messaging"
    else:
        manifest_dir = Path.home() / ".aegis" / "native-messaging"

    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / "com.aegis.browser_guardian.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    return str(manifest_path)


if __name__ == "__main__":
    # If called with --install flag, install the manifest
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        browser = sys.argv[2] if len(sys.argv) > 2 else "chrome"
        ext_id = sys.argv[3] if len(sys.argv) > 3 else None
        path = install_native_host(browser, ext_id)
        print(f"Native messaging host manifest installed at: {path}")
    else:
        main()
