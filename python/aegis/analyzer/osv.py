"""OSV.dev API client — check for known vulnerabilities."""

from __future__ import annotations


ECOSYSTEM_MAP = {
    "python": "PyPI",
    "node": "npm",
    "rust": "crates.io",
}


def check_vulnerabilities(name: str, ecosystem: str, version: str | None = None) -> list[dict]:
    """Query OSV.dev for known vulnerabilities.

    Returns a list of vulnerability dicts with: id, summary, severity, url.
    """
    osv_eco = ECOSYSTEM_MAP.get(ecosystem)
    if not osv_eco:
        return []

    try:
        import httpx

        payload = {"package": {"name": name, "ecosystem": osv_eco}}
        if version:
            payload["version"] = version

        resp = httpx.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=10.0,
        )
        if resp.status_code != 200:
            return []

        data = resp.json()
        vulns = data.get("vulns", [])

        return [
            {
                "id": v.get("id", "UNKNOWN"),
                "summary": v.get("summary", "No description available"),
                "url": f"https://osv.dev/vulnerability/{v.get('id', '')}",
                "severity": _extract_severity(v),
            }
            for v in vulns
        ]
    except Exception:
        return []


def _extract_severity(vuln: dict) -> str:
    """Extract severity from OSV vulnerability data."""
    severity_data = vuln.get("severity", [])
    if severity_data:
        for s in severity_data:
            score_str = s.get("score", "")
            if score_str:
                try:
                    score = float(score_str)
                    if score >= 9.0:
                        return "critical"
                    if score >= 7.0:
                        return "high"
                    if score >= 4.0:
                        return "medium"
                    return "low"
                except ValueError:
                    pass
    return "medium"  # default if no score
