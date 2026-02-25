"""Installer for aegisd daemon binary and systemd service."""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

AEGISD_INSTALL_PATH = Path("/usr/local/bin/aegisd")
CONFIG_DIR = Path("/etc/aegis")
STATE_DIR = Path("/var/lib/aegis")
RUN_DIR = Path("/run/aegis")
SYSTEMD_DIR = Path("/usr/lib/systemd/system")


def _find_bundled_aegisd() -> Path | None:
    """Find aegisd binary bundled with the Python package."""
    # Check package data
    pkg_dir = Path(__file__).parent
    candidates = [
        pkg_dir / "data" / "aegisd",
        pkg_dir / "bin" / "aegisd",
        pkg_dir.parent.parent / "native" / "build" / "aegisd",
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    return None


def _check_kernel_bpf_support() -> dict:
    """Check if the running kernel supports BPF LSM."""
    result = {
        "bpf_lsm": False,
        "kernel_version": platform.release(),
        "btf_available": False,
        "details": [],
    }

    # Check kernel version >= 5.7
    try:
        major, minor = map(int, platform.release().split(".")[:2])
        if major > 5 or (major == 5 and minor >= 7):
            result["details"].append(f"Kernel {major}.{minor} >= 5.7: OK")
        else:
            result["details"].append(
                f"Kernel {major}.{minor} < 5.7: BPF LSM not supported"
            )
            return result
    except (ValueError, IndexError):
        result["details"].append("Cannot parse kernel version")
        return result

    # Check if BPF is in LSM list
    try:
        lsm_path = Path("/sys/kernel/security/lsm")
        if lsm_path.exists():
            lsms = lsm_path.read_text().strip()
            result["bpf_lsm"] = "bpf" in lsms.split(",")
            result["details"].append(f"LSMs: {lsms}")
        else:
            result["details"].append("/sys/kernel/security/lsm not found")
    except PermissionError:
        result["details"].append("Cannot read /sys/kernel/security/lsm")

    # Check BTF
    btf_path = Path("/sys/kernel/btf/vmlinux")
    result["btf_available"] = btf_path.exists()
    result["details"].append(
        f"BTF: {'available' if result['btf_available'] else 'not available'}"
    )

    return result


def install(force: bool = False) -> bool:
    """Install aegisd daemon.

    Returns True on success.
    """
    if os.geteuid() != 0:
        print("Error: daemon installation requires root privileges.")
        print("Run: sudo aegis daemon install")
        return False

    # Find binary
    aegisd_src = _find_bundled_aegisd()
    if not aegisd_src:
        print("Error: aegisd binary not found.")
        print("Build it with: cd native && mkdir build && cd build && cmake .. && make")
        return False

    # Check kernel
    kernel = _check_kernel_bpf_support()
    print(f"Kernel: {kernel['kernel_version']}")
    for detail in kernel["details"]:
        print(f"  {detail}")

    if not kernel["bpf_lsm"]:
        print("\nWARNING: BPF LSM not available. aegisd will run in userspace-only mode.")
        print("For full kernel enforcement, enable CONFIG_BPF_LSM and add 'bpf' to LSM list.")

    # Create directories
    for d in [CONFIG_DIR, STATE_DIR, RUN_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    # Copy binary
    if AEGISD_INSTALL_PATH.exists() and not force:
        print(f"\nWARNING: {AEGISD_INSTALL_PATH} already exists. Use --force to overwrite.")
    else:
        shutil.copy2(aegisd_src, AEGISD_INSTALL_PATH)
        os.chmod(AEGISD_INSTALL_PATH, 0o755)
        print(f"\nInstalled: {AEGISD_INSTALL_PATH}")

    # Copy default config if not exists
    default_config = CONFIG_DIR / "config.yml"
    if not default_config.exists():
        src_config = Path(__file__).parent.parent.parent / "native" / "etc" / "aegis-default.yml"
        if src_config.exists():
            shutil.copy2(src_config, default_config)
            print(f"Config: {default_config}")
        else:
            # Write minimal default config
            default_config.write_text(
                "mode: interactive\n"
                "ecosystems:\n"
                "  python:\n"
                "    enabled: true\n"
                "  node:\n"
                "    enabled: true\n"
                "  rust:\n"
                "    enabled: true\n"
                "typosquat_enabled: true\n"
                "typosquat_threshold: 2\n"
                "agent_mode: strict\n"
                "agent_typosquat_threshold: 1\n"
                "slopsquat_check: true\n"
                "osv_check: true\n"
            )
            print(f"Config (default): {default_config}")

    # Install systemd service
    service_src = Path(__file__).parent.parent.parent / "native" / "etc" / "aegisd.service"
    service_dst = SYSTEMD_DIR / "aegisd.service"
    if service_src.exists():
        shutil.copy2(service_src, service_dst)
    else:
        # Write minimal service file
        service_dst.write_text(
            "[Unit]\n"
            "Description=AEGIS Security Daemon\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=notify\n"
            f"ExecStart={AEGISD_INSTALL_PATH} --foreground\n"
            "ExecReload=/bin/kill -HUP $MAINPID\n"
            "Restart=on-failure\n"
            "OOMScoreAdjust=-1000\n"
            "LimitMEMLOCK=infinity\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
    print(f"Service: {service_dst}")

    # Reload systemd
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("\nDone. To start: sudo systemctl start aegisd")
    print("To enable at boot: sudo systemctl enable aegisd")

    return True


def uninstall() -> bool:
    """Remove aegisd daemon."""
    if os.geteuid() != 0:
        print("Error: daemon uninstallation requires root privileges.")
        return False

    # Stop service
    subprocess.run(["systemctl", "stop", "aegisd"], check=False)
    subprocess.run(["systemctl", "disable", "aegisd"], check=False)

    # Remove files
    for path in [
        AEGISD_INSTALL_PATH,
        SYSTEMD_DIR / "aegisd.service",
    ]:
        if path.exists():
            path.unlink()
            print(f"Removed: {path}")

    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("\nDaemon uninstalled. Config and data preserved in /etc/aegis/ and /var/lib/aegis/")
    return True
