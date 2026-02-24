# AEGIS — AI Environment Guardian & Integrity Shield

[![PyPI](https://img.shields.io/pypi/v/aegis-security)](https://pypi.org/project/aegis-security/)
[![CI](https://github.com/iafiscal1212/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/iafiscal1212/aegis/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Supply-chain security for developers and AI coding agents.**

AEGIS intercepts package installations and destructive commands in real-time — detecting typosquatting, malicious scripts, vulnerable dependencies, and dangerous shell operations *before* they reach your system.

## Why AEGIS?

AI coding agents (Claude Code, Copilot, Cursor) can install packages and run arbitrary commands — but nobody verifies what they do. AEGIS fills that gap:

- **Destructive command detection** — catches `rm -rf /`, `DROP DATABASE`, fork bombs, `curl | sh`, and more
- **Typosquatting detection** — Levenshtein distance + normalization against top packages
- **Slopsquatting detection** — flags non-existent packages hallucinated by AI agents
- **Vulnerability check** — OSV.dev API integration for known CVEs
- **AI-aware** — higher scrutiny when the command comes from an AI agent
- **Three ecosystems** — Python (pip), Node.js (npm/yarn/pnpm), Rust (cargo)

## Claude Code Hook (primary use case)

AEGIS integrates as a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that intercepts every Bash command Claude Code tries to run:

```bash
# Install AEGIS
pip install aegis-security
aegis init

# Install the Claude Code hook
aegis hook install claude
# → writes PreToolUse hook to ~/.claude/settings.json

# That's it — Claude Code is now protected
```

When Claude Code attempts a dangerous operation, AEGIS:
- **Allows** safe commands silently (exit 0, no output)
- **Warns** on suspicious packages → prompts you to approve or deny
- **Blocks** critical destructive commands → denies execution with explanation

## Quick Start (shell hook)

For protecting your own terminal (without Claude Code):

```bash
pip install aegis-security
aegis init

# Activate shell hooks (add to .bashrc/.zshrc)
aegis hook install shell
source ~/.aegis/shell_hook.sh

# Now pip/npm commands are protected
pip install reqeusts  # → BLOCKED: typosquat of "requests"
pip install requests  # → ALLOWED: known safe package
```

## Commands

```
aegis init                          Initialize ~/.aegis/ with config and DB
aegis check pip install <pkg>       Check a command before execution (used by hooks)
aegis check-hook                    Check a Claude Code hook payload from stdin
aegis scan [target]                 Scan a directory or package for suspicious patterns
aegis hook install [claude|shell|browser]   Install an AEGIS hook
aegis hook status                   Show which hooks are installed
aegis config                        View current configuration
aegis log                           View decision history
aegis agent-log                     View AI agent activity dashboard
aegis status                        Show AEGIS status
```

## Browser Extension

AEGIS includes a Chromium extension (`aegis-browser/`) that detects copy-paste of suspicious install commands from web pages. Install the native messaging host with:

```bash
aegis hook install browser
```

## Architecture

```
┌───────────────────────────────────────────┐
│           AEGIS CLI (Python)              │
│  Claude Code hook · Shell hook · Browser  │
├───────────────────────────────────────────┤
│          Orchestrator (Python)            │
│  Destructive Cmd │ Package Analyzer       │
│  Agent Detector  │ Slopsquat Checker      │
├───────────────────────────────────────────┤
│          Rust Core (via PyO3)             │
│  Command Parser  │ Typosquat Detector     │
│  Pattern Engine  │ Hash Checker           │
├───────────────────────────────────────────┤
│        Threat Intelligence                │
│  SQLite DB │ OSV.dev │ PyPI/npm APIs      │
└───────────────────────────────────────────┘
```

Rust core is optional — AEGIS falls back to pure Python if the native extension isn't available.

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
# Prerequisites: Python 3.11+ (tested on 3.11, 3.12, 3.13) + Rust toolchain (optional)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Setup
git clone https://github.com/iafiscal1212/aegis.git
cd aegis
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Build Rust extension (optional — pure Python fallback works)
pip install maturin
maturin develop

# Test
pytest
cargo test  # if Rust toolchain installed
```

## License

MIT
