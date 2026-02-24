"""npm registry API client — fetch package metadata."""

from __future__ import annotations

from datetime import datetime, timezone


def get_package_info(name: str) -> dict | None:
    """Fetch package metadata from npm registry.

    Returns dict with: name, version, age_days, maintainer_count, etc.
    """
    try:
        import httpx

        resp = httpx.get(
            f"https://registry.npmjs.org/{name}",
            timeout=10.0,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()

        # Creation time
        time_info = data.get("time", {})
        created = time_info.get("created")
        age_days = None
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
            except (ValueError, TypeError):
                pass

        # Maintainers
        maintainers = data.get("maintainers", [])

        # Latest version info
        dist_tags = data.get("dist-tags", {})
        latest_version = dist_tags.get("latest")

        return {
            "name": data.get("name", name),
            "version": latest_version,
            "description": data.get("description"),
            "age_days": age_days,
            "maintainer_count": len(maintainers),
            "has_homepage": bool(data.get("homepage")),
            "license": data.get("license"),
            "release_count": len(data.get("versions", {})),
        }
    except Exception:
        return None


def check_package_exists(name: str) -> bool | None:
    """Quick check if package exists on npm."""
    try:
        import httpx

        resp = httpx.head(
            f"https://registry.npmjs.org/{name}",
            timeout=5.0,
            follow_redirects=True,
        )
        return resp.status_code == 200
    except Exception:
        return None
