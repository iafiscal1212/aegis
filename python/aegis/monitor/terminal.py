"""Terminal monitor — intercepts and analyzes package install commands."""

from __future__ import annotations

from aegis.config import AegisConfig
from aegis.db.models import AegisDB
from aegis.monitor.process import detect_ai_agent, get_agent_risk_level


def check_install_command(command: str) -> dict:
    """Check a package install command and return a decision.

    Returns:
        dict with keys:
            action: "allow" | "warn" | "block"
            alerts: list of alert dicts
            agent: str | None — detected AI agent name
    """
    config = AegisConfig.load_or_create()
    alerts = []

    # Try Rust core first, fall back to pure Python
    parsed = _parse_command(command)
    if parsed is None:
        return {"action": "allow", "alerts": [], "agent": None}

    ecosystem = parsed["ecosystem"]
    packages = parsed["packages"]

    # Check if ecosystem is enabled
    if not config.ecosystems.get(ecosystem, True):
        return {"action": "allow", "alerts": [], "agent": None}

    # Detect AI agent context (universal detection)
    agent_name = detect_ai_agent()
    risk_level = get_agent_risk_level(agent_name)
    # high-risk agents → block suspicious, elevated → warn→block, standard → warn
    escalate = risk_level in ("high", "elevated")

    for pkg in packages:
        pkg_name = pkg["name"]

        # Check blocklist
        if pkg_name.lower() in [b.lower() for b in config.blocklist]:
            alerts.append({
                "level": "block",
                "package": pkg_name,
                "reason": "Package is in blocklist",
                "suggestion": "Remove from blocklist in ~/.aegis/config.yml to allow",
                "agent": agent_name,
            })
            continue

        # Check allowlist
        if pkg_name.lower() in [a.lower() for a in config.allowlist]:
            continue

        # Typosquatting check
        if config.typosquat_enabled:
            typo_result = _check_typosquat(pkg_name, ecosystem, config.typosquat_threshold)
            if typo_result and typo_result["is_suspect"]:
                level = "block" if escalate else "warn"
                closest = typo_result["closest_match"]
                agent_hint = f" (detected agent: {agent_name})" if agent_name else ""
                alerts.append({
                    "level": level,
                    "package": pkg_name,
                    "reason": typo_result.get("reason", f"Possible typosquat of '{closest}'"),
                    "suggestion": f'Did you mean "{closest}"?{agent_hint}',
                    "agent": agent_name,
                })
                continue

        # Check if package exists via API (async in future)
        existence = _check_package_exists(pkg_name, ecosystem)
        if existence is not None and not existence:
            level = "block" if escalate else "warn"
            agent_hint = ""
            if agent_name:
                agent_hint = f" Agent '{agent_name}' may have hallucinated this name."
            alerts.append({
                "level": level,
                "package": pkg_name,
                "reason": f"Package '{pkg_name}' does not exist in {ecosystem} registry",
                "suggestion": f"Slopsquatting risk.{agent_hint}",
                "agent": agent_name,
            })
            continue

        # OSV vulnerability check
        if config.osv_check:
            vulns = _check_osv(pkg_name, ecosystem)
            if vulns:
                alerts.append({
                    "level": "warn",
                    "package": pkg_name,
                    "reason": f"{len(vulns)} known vulnerability(ies) found",
                    "suggestion": f"Check: https://osv.dev/list?q={pkg_name}",
                    "agent": agent_name,
                })

    # Log decisions
    _log_decisions(parsed, alerts, agent_name)

    # Determine overall action
    if any(a["level"] == "block" for a in alerts):
        action = "block"
    elif any(a["level"] == "warn" for a in alerts):
        action = "warn"
    else:
        action = "allow"

    return {"action": action, "alerts": alerts, "agent": agent_name}


def _parse_command(command: str) -> dict | None:
    """Parse command using Rust core or fallback."""
    try:
        from aegis.aegis_core import parse_command
        return parse_command(command)
    except ImportError:
        return _parse_command_python(command)


def _parse_command_python(command: str) -> dict | None:
    """Pure Python fallback for command parsing."""
    parts = command.strip().split()
    if len(parts) < 2:
        return None

    manager = parts[0].rsplit("/", maxsplit=1)[-1]
    ecosystem_map = {
        "pip": "python", "pip3": "python",
        "npm": "node", "yarn": "node", "pnpm": "node",
        "cargo": "rust",
    }
    ecosystem = ecosystem_map.get(manager)
    if not ecosystem:
        return None

    # Detect install subcommand
    if ecosystem == "rust":
        if parts[1] not in ("add", "install"):
            return None
    elif parts[1] not in ("install", "i", "add"):
        return None

    packages = []
    for part in parts[2:]:
        if part.startswith("-"):
            continue
        name = part.split("==")[0].split(">=")[0].split("<=")[0].split("@")[0]
        if name:
            packages.append({"name": name, "version": None})

    if not packages:
        return None

    return {
        "ecosystem": ecosystem,
        "packages": packages,
        "is_install": True,
        "source": "registry",
        "raw_command": command,
    }


def _check_typosquat(name: str, ecosystem: str, threshold: int) -> dict | None:
    """Check for typosquatting using Rust core or fallback."""
    try:
        from aegis.aegis_core import check_typosquat
        return check_typosquat(name, ecosystem, threshold)
    except ImportError:
        return _check_typosquat_python(name, ecosystem, threshold)


def _check_typosquat_python(name: str, ecosystem: str, threshold: int) -> dict | None:
    """Pure Python fallback for typosquatting detection."""
    # Minimal fallback — just check obvious typos of top packages
    top_packages = {
        "python": [
            "requests", "numpy", "pandas", "flask", "django", "colorama",
            "boto3", "urllib3", "setuptools", "pyyaml", "cryptography",
        ],
        "node": [
            "express", "react", "lodash", "axios", "typescript", "webpack",
        ],
    }

    known = top_packages.get(ecosystem, [])
    normalized = name.lower().replace("-", "_")

    for pkg in known:
        pkg_norm = pkg.lower().replace("-", "_")
        if pkg_norm == normalized:
            return {"query": name, "is_suspect": False, "closest_match": pkg, "distance": 0.0, "reason": None}

        # Simple Levenshtein check
        dist = _levenshtein(normalized, pkg_norm)
        if 0 < dist <= threshold:
            return {
                "query": name,
                "is_suspect": True,
                "closest_match": pkg,
                "distance": dist / max(len(normalized), len(pkg_norm)),
                "reason": f"Levenshtein distance {dist} from '{pkg}'",
            }

    return {"query": name, "is_suspect": False, "closest_match": None, "distance": 1.0, "reason": None}


def _levenshtein(a: str, b: str) -> int:
    """Simple Levenshtein distance."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + cost))
        prev = curr
    return prev[len(b)]


def _check_package_exists(name: str, ecosystem: str) -> bool | None:
    """Quick check if package exists in registry. Returns None if can't check."""
    try:
        import httpx

        urls = {
            "python": f"https://pypi.org/pypi/{name}/json",
            "node": f"https://registry.npmjs.org/{name}",
        }
        url = urls.get(ecosystem)
        if not url:
            return None

        resp = httpx.head(url, timeout=5.0, follow_redirects=True)
        return resp.status_code == 200
    except Exception:
        return None  # Can't check — don't block


def _check_osv(name: str, ecosystem: str) -> list[dict]:
    """Check OSV.dev for known vulnerabilities."""
    try:
        import httpx

        osv_ecosystem = {
            "python": "PyPI",
            "node": "npm",
            "rust": "crates.io",
        }.get(ecosystem)
        if not osv_ecosystem:
            return []

        resp = httpx.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": name, "ecosystem": osv_ecosystem}},
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulns", [])
    except Exception:
        pass
    return []


def _log_decisions(parsed: dict, alerts: list[dict], agent_name: str | None = None):
    """Log decisions to the database."""
    try:
        db = AegisDB()
        for pkg in parsed["packages"]:
            pkg_alerts = [a for a in alerts if a.get("package") == pkg["name"]]
            if pkg_alerts:
                for alert in pkg_alerts:
                    db.log_decision(
                        package_name=pkg["name"],
                        ecosystem=parsed["ecosystem"],
                        action=alert["level"],
                        reason=alert.get("reason", ""),
                        agent_name=agent_name,
                    )
            else:
                db.log_decision(
                    package_name=pkg["name"],
                    ecosystem=parsed["ecosystem"],
                    action="allow",
                    reason="No issues found",
                    agent_name=agent_name,
                )
    except Exception:
        pass  # Don't block installs if DB fails
