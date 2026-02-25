"""Integration tests for eBPF enforcement.

These tests require:
- Linux 5.7+ with CONFIG_BPF_LSM=y
- Root privileges
- aegisd running with eBPF enabled

Skip with: pytest -m "not ebpf"
"""

import json
import os
import signal
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.ebpf


def is_root():
    return os.geteuid() == 0


def daemon_running():
    try:
        from aegis.daemon_client import is_daemon_running
        return is_daemon_running()
    except Exception:
        return False


def bpf_available():
    try:
        with open("/sys/kernel/security/lsm") as f:
            return "bpf" in f.read()
    except Exception:
        return False


skip_not_root = pytest.mark.skipif(not is_root(), reason="Requires root")
skip_no_daemon = pytest.mark.skipif(not daemon_running(), reason="aegisd not running")
skip_no_bpf = pytest.mark.skipif(not bpf_available(), reason="BPF LSM not available")


@skip_not_root
@skip_no_daemon
class TestDaemonConnection:
    """Test daemon IPC works."""

    def test_ping(self):
        from aegis.daemon_client import DaemonClient
        with DaemonClient() as client:
            assert client.ping()

    def test_status_shows_bpf(self):
        from aegis.daemon_client import DaemonClient
        with DaemonClient() as client:
            resp = client.status()
            assert resp["status"] == "ok"
            assert "bpf" in resp

    def test_check_safe_package(self):
        from aegis.daemon_client import DaemonClient
        with DaemonClient() as client:
            resp = client.check("pip install requests")
            assert resp["action"] == "allow"

    def test_check_typosquat(self):
        from aegis.daemon_client import DaemonClient
        with DaemonClient() as client:
            resp = client.check("pip install reqeusts", agent="claude")
            assert resp["action"] in ("warn", "block")
            assert len(resp["alerts"]) > 0


@skip_not_root
@skip_no_daemon
@skip_no_bpf
class TestKernelEnforcement:
    """Test kernel-level enforcement (requires eBPF active)."""

    def test_daemon_self_protection(self):
        """kill -9 aegisd should fail."""
        result = subprocess.run(
            ["pidof", "aegisd"], capture_output=True, text=True
        )
        if result.returncode != 0:
            pytest.skip("aegisd not running")

        pid = int(result.stdout.strip().split()[0])

        # Try to kill -9 the daemon
        ret = subprocess.run(
            ["kill", "-9", str(pid)], capture_output=True, text=True
        )
        # Should fail with EPERM
        assert ret.returncode != 0 or "Operation not permitted" in ret.stderr

        # Daemon should still be running
        time.sleep(0.5)
        assert subprocess.run(["pidof", "aegisd"], capture_output=True).returncode == 0

    def test_aegisd_binary_protected(self):
        """rm /usr/local/bin/aegisd should fail."""
        if not os.path.exists("/usr/local/bin/aegisd"):
            pytest.skip("aegisd not installed")

        ret = subprocess.run(
            ["rm", "/usr/local/bin/aegisd"], capture_output=True, text=True
        )
        assert ret.returncode != 0
        assert os.path.exists("/usr/local/bin/aegisd")
