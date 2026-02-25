# AEGIS v1.0 — Kernel-Level Supply Chain Security

[![PyPI](https://img.shields.io/pypi/v/aegis-security)](https://pypi.org/project/aegis-security/)
[![CI](https://github.com/iafiscal1212/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/iafiscal1212/aegis/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**AI Environment Guardian & Integrity Shield**

AEGIS protects developers and AI coding agents from supply chain attacks (typosquatting, slopsquatting, dependency confusion) using **eBPF LSM** for kernel-level enforcement that cannot be bypassed from userspace.

## Why v1.0? Kernel Enforcement

AEGIS v0.2.x ran entirely in userspace. An adversary (or a compromised LLM) could:
- `kill -9 aegis` — dead
- `pip uninstall aegis-security` — gone
- `alias rm='rm'` — bypassed

**v1.0 moves enforcement to the Linux kernel** via eBPF LSM hooks:

| Threat | v0.2.x | v1.0 |
|--------|--------|------|
| `pip install evil-pkg` (blocklisted) | Python check | **Kernel EPERM** (O(1) BPF map) |
| `kill -9 aegisd` | Process dies | **EPERM** (task_kill hook) |
| `rm /usr/local/bin/aegisd` | File deleted | **EPERM** (inode_unlink hook) |
| Agent reads `.ssh/` | Not detected | **EPERM** (file_open hook) |
| Agent installs unknown package | Python check | **Kernel block + async analysis** |

## Architecture

```
┌──────────────────── KERNEL SPACE ────────────────────┐
│  eBPF LSM Hooks                    BPF Maps          │
│  ├─ bprm_check_security           ├─ blocked_packages│
│  ├─ file_open                      ├─ allowed_packages│
│  ├─ inode_unlink                   ├─ agent_pids     │
│  └─ task_kill                      └─ config_map     │
└──────────────────────┬───────────────────────────────┘
                       │ ring buffer
┌──────────────────────▼───────────────────────────────┐
│  aegisd (C++ daemon, CAP_BPF)                        │
│  ├─ PolicyEngine (YAML → BPF maps)                   │
│  ├─ TyposquatDetector (Levenshtein + Jaro-Winkler)   │
│  ├─ AgentMonitor (/proc scanner)                     │
│  ├─ HttpClient (PyPI/npm/OSV.dev)                    │
│  └─ IPC Server (Unix socket)                         │
└──────────────────────┬───────────────────────────────┘
                       │ Unix socket
┌──────────────────────▼───────────────────────────────┐
│  aegis CLI (Python, pip install aegis-security)      │
│  ├─ Same commands: check, scan, init, status         │
│  ├─ New: aegis daemon {start,stop,status,install}    │
│  ├─ Hooks: Claude Code, shell, browser               │
│  └─ Fallback: works without daemon (v0.2.x mode)    │
└──────────────────────────────────────────────────────┘
```

## Quick Start

### Install CLI (all platforms)

```bash
pip install aegis-security
aegis init
```

### Install Claude Code Hook

```bash
aegis hook install claude
# → writes PreToolUse hook to ~/.claude/settings.json
# Claude Code is now protected
```

### Install Kernel Daemon (Linux)

```bash
# Build aegisd
cd native && mkdir build && cd build
cmake .. -DAEGIS_ENABLE_BPF=ON
make -j$(nproc)

# Install and start
sudo aegis daemon install
sudo systemctl enable --now aegisd
```

### Verify

```bash
# Check daemon status
aegis daemon status

# Test typosquatting detection
aegis check pip install reqeusts
# → BLOCK: possible typosquat of 'requests'

# Test kernel enforcement (with eBPF)
kill -9 $(pidof aegisd)
# → Operation not permitted

rm /usr/local/bin/aegisd
# → Operation not permitted
```

## Features

### Typosquatting Detection
Levenshtein distance + Jaro-Winkler similarity against 220+ popular packages across Python, Node.js, and Rust ecosystems.

### Slopsquatting / Hallucination Detection
Verifies packages exist in their registry before installation. Blocks AI agent "hallucinated" package names.

### AI Agent Awareness
Automatically detects Claude Code, Cursor, Copilot, Aider, and other AI coding agents. Applies stricter thresholds (default-deny for unknown packages from agents).

### Vulnerability Scanning
Queries OSV.dev for known CVEs before installation.

### Credential Protection (eBPF)
Prevents package install scripts from reading `.ssh/`, `.aws/`, `.env`, `.npmrc`, `.pypirc` when running in an agent context.

### Self-Protection (eBPF)
- Daemon cannot be killed (except `systemctl stop`)
- Binary cannot be deleted
- Config cannot be tampered with

### Destructive Command Detection
Catches `rm -rf /`, `DROP DATABASE`, fork bombs, `curl | sh`, and 40+ patterns of dangerous shell operations.

## Hooks

### Claude Code
```bash
aegis hook install claude
# Installs PreToolUse hook in ~/.claude/settings.json
```

### Shell
```bash
aegis hook install shell
# Source in .bashrc: source ~/.aegis/shell_hook.sh
```

### Browser Extension
```bash
aegis hook install browser
# Installs native messaging host for Chrome/Firefox extension
```

## Configuration

`~/.aegis/config.yml` (or `/etc/aegis/config.yml` for system daemon):

```yaml
mode: interactive          # interactive / strict / permissive
typosquat_enabled: true
typosquat_threshold: 2     # Levenshtein distance
agent_mode: strict         # strict / moderate / permissive
agent_typosquat_threshold: 1
slopsquat_check: true
osv_check: true

ecosystems:
  python: { enabled: true }
  node: { enabled: true }
  rust: { enabled: true }

allowlist: []
blocklist: []
agent_blocklist: []
agent_allowlist: []
```

## Kernel Requirements

| Feature | Minimum | Recommended |
|---------|---------|-------------|
| eBPF LSM | Linux 5.7 | Linux 5.15+ |
| BTF | `CONFIG_DEBUG_INFO_BTF=y` | Ubuntu 22.04+ |
| LSM | `bpf` in `/sys/kernel/security/lsm` | Add to boot params |

**Fallback**: If the kernel doesn't support BPF LSM, AEGIS works in pure userspace mode (v0.2.x behavior). No functionality is lost, only kernel enforcement.

## Building from Source

### C++ Daemon

```bash
# Dependencies (Ubuntu/Debian)
sudo apt install cmake g++ pkg-config \
  libyaml-cpp-dev libsqlite3-dev libcurl4-openssl-dev

# Without eBPF (userspace-only daemon)
cd native && mkdir build && cd build
cmake .. -DAEGIS_ENABLE_BPF=OFF
make -j$(nproc)

# With eBPF
sudo apt install libbpf-dev libelf-dev zlib1g-dev clang bpftool
cmake .. -DAEGIS_ENABLE_BPF=ON
make -j$(nproc)
```

### Python + Rust

```bash
pip install maturin
maturin develop
pip install -e ".[dev]"
pytest
```

## CLI Commands

```
aegis init                    Initialize AEGIS
aegis check <cmd>             Check a package install command
aegis scan <dir|pkg>          Scan for suspicious patterns
aegis status                  Show AEGIS + daemon status
aegis log                     View decision history
aegis agent-log               View AI agent activity
aegis daemon install          Install aegisd + systemd service
aegis daemon start            Start daemon
aegis daemon stop             Stop daemon
aegis daemon status           Detailed daemon status
aegis daemon reload           Reload config (SIGHUP)
aegis hook install <target>   Install hook (claude/shell/browser)
aegis hook status             Show installed hooks
```

## Development

```bash
# Prerequisites: Python 3.11+ + Rust toolchain (optional) + C++17 compiler
git clone https://github.com/iafiscal1212/aegis.git
cd aegis
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Build Rust extension (optional — pure Python fallback works)
pip install maturin && maturin develop

# Build C++ daemon
cd native && mkdir build && cd build && cmake .. && make -j$(nproc)

# Test
pytest                    # Python tests
cargo test                # Rust tests
cd native/build && ctest  # C++ tests
```

## License

MIT
