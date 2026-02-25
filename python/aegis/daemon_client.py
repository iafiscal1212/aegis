"""Client for communicating with aegisd daemon via Unix socket IPC."""

import json
import os
import socket
import struct
from pathlib import Path
from typing import Optional


class DaemonError(Exception):
    """Error communicating with aegisd."""


class DaemonClient:
    """Connects to aegisd via Unix socket using length-prefix JSON protocol."""

    SYSTEM_SOCKET = "/run/aegis/aegisd.sock"
    TIMEOUT = 10.0

    def __init__(self, socket_path: str | None = None):
        self.socket_path = socket_path or self._find_socket()
        self._sock: socket.socket | None = None

    @staticmethod
    def _find_socket() -> str:
        """Find aegisd socket path."""
        # System socket (root daemon)
        if os.path.exists(DaemonClient.SYSTEM_SOCKET):
            return DaemonClient.SYSTEM_SOCKET
        # User socket
        home = Path.home()
        user_sock = home / ".aegis" / "aegisd.sock"
        if user_sock.exists():
            return str(user_sock)
        # Default to system path
        return DaemonClient.SYSTEM_SOCKET

    def connect(self) -> None:
        """Connect to daemon socket."""
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(self.TIMEOUT)
        try:
            self._sock.connect(self.socket_path)
        except (ConnectionRefusedError, FileNotFoundError, PermissionError) as e:
            self._sock = None
            raise DaemonError(f"Cannot connect to aegisd at {self.socket_path}: {e}")

    def close(self) -> None:
        """Close connection."""
        if self._sock:
            self._sock.close()
            self._sock = None

    def _send(self, msg: dict) -> dict:
        """Send a message and receive response."""
        if not self._sock:
            self.connect()

        data = json.dumps(msg).encode("utf-8")
        # Length prefix: 4 bytes little-endian
        header = struct.pack("<I", len(data))

        try:
            self._sock.sendall(header + data)

            # Read response header
            resp_header = self._recv_exact(4)
            resp_len = struct.unpack("<I", resp_header)[0]

            if resp_len > 1024 * 1024:  # 1MB max
                raise DaemonError("Response too large")

            resp_data = self._recv_exact(resp_len)
            return json.loads(resp_data.decode("utf-8"))

        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            self._sock = None
            raise DaemonError(f"Connection lost: {e}")

    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes."""
        data = bytearray()
        while len(data) < n:
            chunk = self._sock.recv(n - len(data))
            if not chunk:
                raise DaemonError("Connection closed by daemon")
            data.extend(chunk)
        return bytes(data)

    # --- Public API ---

    def ping(self) -> bool:
        """Check if daemon is alive."""
        try:
            resp = self._send({"type": "ping"})
            return resp.get("status") == "ok"
        except DaemonError:
            return False

    def check(self, command: str, agent: str = "") -> dict:
        """Check a package install command.

        Returns: {"action": "allow|warn|block", "alerts": [...], "agent": str}
        """
        return self._send({
            "type": "check",
            "command": command,
            "agent": agent,
        })

    def check_hook(self, command: str, agent: str = "claude") -> dict:
        """Process a Claude Code PreToolUse hook payload.

        Returns: {"action": "allow|warn|block", "alerts": [...], "agent": str}
        """
        return self._send({
            "type": "check_hook",
            "command": command,
            "agent": agent,
        })

    def check_package(self, name: str, ecosystem: str = "python",
                      agent: str = "") -> dict:
        """Check a single package.

        Returns: {"action": "allow|warn|block", "alerts": [...]}
        """
        return self._send({
            "type": "check_package",
            "name": name,
            "ecosystem": ecosystem,
            "agent": agent,
        })

    def status(self) -> dict:
        """Get daemon status.

        Returns: {"version": str, "mode": str, "bpf": str, "packages": int, ...}
        """
        return self._send({"type": "status"})

    def reload_config(self) -> dict:
        """Reload daemon configuration."""
        return self._send({"type": "reload_config"})

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


def is_daemon_running(socket_path: str | None = None) -> bool:
    """Quick check if daemon is available."""
    try:
        client = DaemonClient(socket_path)
        return client.ping()
    except Exception:
        return False
