"""crates.io API client — fetch Rust crate metadata."""

from __future__ import annotations

from datetime import datetime, timezone


def get_package_info(name: str) -> dict | None:
    """Fetch crate metadata from crates.io."""
    try:
        import httpx

        resp = httpx.get(
            f"https://crates.io/api/v1/crates/{name}",
            timeout=10.0,
            headers={"User-Agent": "aegis-security/0.1.0"},
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        crate_info = data.get("crate", {})

        created = crate_info.get("created_at")
        age_days = None
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
            except (ValueError, TypeError):
                pass

        return {
            "name": crate_info.get("name", name),
            "version": crate_info.get("max_version"),
            "description": crate_info.get("description"),
            "age_days": age_days,
            "downloads": crate_info.get("downloads", 0),
            "has_homepage": bool(crate_info.get("homepage")),
            "license": crate_info.get("license"),
        }
    except Exception:
        return None
