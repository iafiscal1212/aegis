"""Tests for daemon client (mocked socket)."""

import json
import socket
import struct
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


class MockDaemonServer:
    """Mock aegisd for testing the client."""

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(socket_path)
        self.server.listen(1)
        self._thread = None
        self._running = False
        self.responses = {}

    def set_response(self, msg_type: str, response: dict):
        self.responses[msg_type] = response

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while self._running:
            try:
                self.server.settimeout(0.5)
                conn, _ = self.server.accept()
                self._handle(conn)
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, conn):
        try:
            header = conn.recv(4)
            if len(header) < 4:
                return
            length = struct.unpack("<I", header)[0]
            data = conn.recv(length)
            msg = json.loads(data)

            msg_type = msg.get("type", "")
            resp = self.responses.get(msg_type, {"status": "error", "message": "unknown"})
            resp_bytes = json.dumps(resp).encode()
            conn.sendall(struct.pack("<I", len(resp_bytes)) + resp_bytes)
        finally:
            conn.close()

    def stop(self):
        self._running = False
        self.server.close()
        if self._thread:
            self._thread.join(timeout=2)


@pytest.fixture
def mock_daemon(tmp_path):
    sock_path = str(tmp_path / "aegisd.sock")
    server = MockDaemonServer(sock_path)
    server.set_response("ping", {"status": "ok", "message": "pong"})
    server.set_response("status", {
        "status": "ok",
        "version": "1.0.0",
        "mode": "interactive",
        "bpf": "unavailable",
        "packages": 42,
        "decisions": 100,
        "blocked": 5,
        "agents": [],
    })
    server.set_response("check", {
        "status": "ok",
        "action": "allow",
        "alerts": [],
        "agent": "",
    })
    server.start()
    yield sock_path, server
    server.stop()


def test_ping(mock_daemon):
    sock_path, _ = mock_daemon
    from aegis.daemon_client import DaemonClient
    client = DaemonClient(sock_path)
    assert client.ping() is True
    client.close()


def test_status(mock_daemon):
    sock_path, _ = mock_daemon
    from aegis.daemon_client import DaemonClient
    client = DaemonClient(sock_path)
    resp = client.status()
    assert resp["status"] == "ok"
    assert resp["version"] == "1.0.0"
    assert resp["packages"] == 42
    client.close()


def test_check_allow(mock_daemon):
    sock_path, _ = mock_daemon
    from aegis.daemon_client import DaemonClient
    client = DaemonClient(sock_path)
    resp = client.check("pip install requests")
    assert resp["action"] == "allow"
    client.close()


def test_check_block(mock_daemon):
    sock_path, server = mock_daemon
    server.set_response("check", {
        "status": "ok",
        "action": "block",
        "alerts": ["[BLOCK] reqeusts: possible typosquat of 'requests'"],
        "agent": "claude",
    })
    from aegis.daemon_client import DaemonClient
    client = DaemonClient(sock_path)
    resp = client.check("pip install reqeusts", agent="claude")
    assert resp["action"] == "block"
    assert len(resp["alerts"]) == 1
    client.close()


def test_connection_failure():
    from aegis.daemon_client import DaemonClient, DaemonError
    client = DaemonClient("/tmp/nonexistent_aegis_sock_test")
    assert client.ping() is False


def test_context_manager(mock_daemon):
    sock_path, _ = mock_daemon
    from aegis.daemon_client import DaemonClient
    with DaemonClient(sock_path) as client:
        assert client.ping() is True


def test_is_daemon_running(mock_daemon):
    sock_path, _ = mock_daemon
    from aegis.daemon_client import is_daemon_running
    assert is_daemon_running(sock_path) is True
    assert is_daemon_running("/tmp/nonexistent_sock") is False
