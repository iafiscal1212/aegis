"""PyPI API client — fetch package metadata and scoring."""

from __future__ import annotations

from datetime import datetime, timezone


def get_package_info(name: str) -> dict | None:
    """Fetch package metadata from PyPI.

    Returns dict with: name, version, age_days, maintainer_count, has_homepage, etc.
    Returns None if package not found or API error.
    """
    try:
        import httpx

        resp = httpx.get(
            f"https://pypi.org/pypi/{name}/json",
            timeout=10.0,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        info = data.get("info", {})
        releases = data.get("releases", {})

        # Calculate age
        first_release = None
        for version_files in releases.values():
            for file_info in version_files:
                upload_time = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        if first_release is None or dt < first_release:
                            first_release = dt
                    except (ValueError, TypeError):
                        pass

        age_days = None
        if first_release:
            now = datetime.now(timezone.utc)
            age_days = (now - first_release).days

        # Maintainer info
        author = info.get("author") or info.get("maintainer") or ""
        maintainer_email = info.get("maintainer_email") or info.get("author_email") or ""

        return {
            "name": info.get("name", name),
            "version": info.get("version"),
            "summary": info.get("summary"),
            "age_days": age_days,
            "maintainer_count": 1 if author else 0,
            "author": author,
            "maintainer_email": maintainer_email,
            "has_homepage": bool(info.get("home_page") or info.get("project_url")),
            "license": info.get("license"),
            "release_count": len(releases),
        }
    except Exception:
        return None


def check_package_exists(name: str) -> bool | None:
    """Quick HEAD check if package exists on PyPI."""
    try:
        import httpx

        resp = httpx.head(
            f"https://pypi.org/pypi/{name}/json",
            timeout=5.0,
            follow_redirects=True,
        )
        return resp.status_code == 200
    except Exception:
        return None
