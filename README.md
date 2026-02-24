# AEGIS — AI Environment Guardian & Integrity Shield

**Supply chain security for developers and AI coding agents.**

AEGIS intercepts package installations in real-time, detecting typosquatting, malicious scripts, and vulnerable dependencies *before* they reach your system.

## Why AEGIS?

AI coding agents (Claude Code, Copilot, Cursor) can install packages and run commands — but nobody verifies what they install. AEGIS fills that gap:

- **Real-time interception** — catches `pip install`, `npm install`, `cargo add` before execution
- **Typosquatting detection** — Levenshtein distance + normalization against top packages
- **Static analysis** — YARA rules for malicious patterns in setup.py, package.json
- **Vulnerability check** — OSV.dev API integration for known CVEs
- **AI-aware** — higher scrutiny for packages suggested by AI agents (slopsquatting)

## Quick Start

```bash
# Install
pip install aegis-security

# Initialize
aegis init

# Activate shell hooks (add to .bashrc/.zshrc)
source ~/.aegis/shell_hook.sh

# Now pip/npm commands are protected
pip install reqeusts  # → BLOCKED: Did you mean "requests"?
pip install requests  # → ALLOWED: known safe package
```

## Commands

```
aegis init           # Initialize ~/.aegis/ with config and DB
aegis watch          # Daemon mode — monitor terminal in real-time
aegis scan .         # Scan current project directory
aegis scan <pkg>     # Analyze a package before installing
aegis check pip install <pkg>  # One-shot check (used by shell hook)
aegis config         # View/edit configuration
aegis log            # View decision history
aegis status         # Daemon status
```

## Architecture

```
┌─────────────────────────────────────────┐
│            AEGIS CLI (Python)           │
├─────────────────────────────────────────┤
│          Orchestrator (Python)          │
│  Terminal Monitor │ Package Analyzer    │
├─────────────────────────────────────────┤
│          Rust Core (via PyO3)           │
│  Command Parser │ Typosquat Detector   │
│  Pattern Engine │ Hash Checker         │
├─────────────────────────────────────────┤
│        Threat Intelligence             │
│  SQLite DB │ OSV.dev │ PyPI/npm APIs   │
└─────────────────────────────────────────┘
```

## Configuration

```yaml
# ~/.aegis/config.yml
mode: interactive  # interactive | strict | permissive
ecosystems:
  python: true
  node: true
  rust: true
typosquat:
  threshold: 2
  enabled: true
osv_check: true
allowlist:
  - numpy
  - pandas
  - flask
blocklist:
  - colourama  # known typosquat
```

## Development

```bash
# Prerequisites: Rust toolchain + Python 3.11+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
pip install maturin
maturin develop

# Test
cargo test
pytest
```

## License

MIT
