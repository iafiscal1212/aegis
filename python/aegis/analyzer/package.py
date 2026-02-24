"""Package analyzer — orchestrates static analysis of packages."""

from __future__ import annotations

from pathlib import Path


def scan_directory(target: Path) -> dict:
    """Scan a directory for suspicious patterns in install scripts."""
    findings = []

    # Files to analyze
    suspect_files = [
        ("setup.py", "python_setup"),
        ("setup.cfg", "python_setup"),
        ("package.json", "package_json"),
    ]

    for filename, analyzer_type in suspect_files:
        filepath = target / filename
        if filepath.exists():
            content = filepath.read_text(errors="replace")
            file_findings = _analyze_file(content, str(filepath), analyzer_type)
            findings.extend(file_findings)

    # Scan all .py files in the directory for suspicious patterns
    for py_file in target.rglob("*.py"):
        # Skip venv, node_modules, etc.
        rel = py_file.relative_to(target)
        skip_dirs = {"venv", ".venv", "node_modules", "__pycache__", ".git", ".tox"}
        if any(part in skip_dirs for part in rel.parts):
            continue

        content = py_file.read_text(errors="replace")
        file_findings = _analyze_file(content, str(rel), "source")
        findings.extend(file_findings)

    # Scan .js files too
    for js_file in target.rglob("*.js"):
        rel = js_file.relative_to(target)
        skip_dirs = {"node_modules", ".git", "dist", "build"}
        if any(part in skip_dirs for part in rel.parts):
            continue

        content = js_file.read_text(errors="replace")
        file_findings = _analyze_file(content, str(rel), "source")
        findings.extend(file_findings)

    risk_score = _calculate_risk_score(findings)

    return {
        "findings": findings,
        "risk_score": risk_score,
        "files_scanned": len(list(target.rglob("*.py"))) + len(list(target.rglob("*.js"))),
    }


def scan_package_name(name: str) -> dict:
    """Scan a package by name — download and analyze."""
    findings = []

    # Check PyPI metadata
    from aegis.analyzer.pypi import get_package_info

    info = get_package_info(name)
    if info:
        if info.get("age_days", 999) < 30:
            findings.append({
                "severity": "medium",
                "category": "new_package",
                "description": f"Package is only {info['age_days']} days old",
                "file": "PyPI metadata",
                "line": None,
            })
        if info.get("downloads_last_month", 0) < 100:
            findings.append({
                "severity": "low",
                "category": "low_popularity",
                "description": f"Low download count: {info.get('downloads_last_month', 0)}/month",
                "file": "PyPI metadata",
                "line": None,
            })
        if info.get("maintainer_count", 0) == 1:
            findings.append({
                "severity": "low",
                "category": "single_maintainer",
                "description": "Package has a single maintainer",
                "file": "PyPI metadata",
                "line": None,
            })

    # Check OSV for known vulnerabilities
    from aegis.analyzer.osv import check_vulnerabilities

    vulns = check_vulnerabilities(name, "python")
    for vuln in vulns:
        findings.append({
            "severity": "high",
            "category": "known_vulnerability",
            "description": f"{vuln.get('id', 'Unknown')}: {vuln.get('summary', 'No description')}",
            "file": "OSV.dev",
            "line": None,
        })

    risk_score = _calculate_risk_score(findings)
    return {"findings": findings, "risk_score": risk_score}


def _analyze_file(content: str, filename: str, analyzer_type: str) -> list[dict]:
    """Analyze a single file using Rust core or fallback."""
    try:
        from aegis import aegis_core

        if analyzer_type == "python_setup":
            return aegis_core.analyze_python_setup(content, filename)
        elif analyzer_type == "package_json":
            return aegis_core.analyze_package_json(content, filename)
        else:
            return aegis_core.match_patterns(content, filename)
    except ImportError:
        return _analyze_file_python(content, filename, analyzer_type)


def _analyze_file_python(content: str, filename: str, analyzer_type: str) -> list[dict]:
    """Pure Python fallback for file analysis."""
    import re

    findings = []
    dangerous_patterns = [
        (r"\bexec\s*\(", "high", "code_execution", "exec() call"),
        (r"\beval\s*\(", "high", "code_execution", "eval() call"),
        (r"subprocess\.(call|run|Popen)\s*\(", "high", "process_spawn", "subprocess call"),
        (r"os\.(system|popen)\s*\(", "high", "process_spawn", "os.system/popen call"),
        (r"base64\.b64decode\s*\(", "medium", "obfuscation", "base64 decode"),
        (r"\.ssh/", "critical", "credential_access", "SSH key access"),
        (r"\.aws/credentials", "critical", "credential_access", "AWS credentials access"),
    ]

    for pattern, severity, category, description in dangerous_patterns:
        for i, line in enumerate(content.split("\n")):
            if re.search(pattern, line):
                findings.append({
                    "severity": severity,
                    "category": category,
                    "description": description,
                    "file": filename,
                    "line": i + 1,
                    "snippet": line.strip()[:120],
                })

    return findings


def _calculate_risk_score(findings: list[dict]) -> float:
    """Calculate risk score from findings."""
    if not findings:
        return 0.0

    weights = {"info": 0.0, "low": 0.05, "medium": 0.15, "high": 0.35, "critical": 0.6}
    score = sum(weights.get(f.get("severity", "info"), 0.1) for f in findings)
    return min(score, 1.0)
