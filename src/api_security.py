"""Small role-based API-key gate for the local academic application."""

import hmac
import os


def role_for_key(
    presented_key: str | None,
    analyst_key: str | None = None,
    viewer_key: str | None = None,
) -> str | None:
    if not presented_key:
        return None
    analyst_key = analyst_key if analyst_key is not None else os.getenv("CYBERGUARD_ANALYST_API_KEY")
    viewer_key = viewer_key if viewer_key is not None else os.getenv("CYBERGUARD_VIEWER_API_KEY")
    if analyst_key and hmac.compare_digest(presented_key, analyst_key):
        return "analyst"
    if viewer_key and hmac.compare_digest(presented_key, viewer_key):
        return "viewer"
    return None


def access_keys_configured() -> bool:
    return bool(os.getenv("CYBERGUARD_ANALYST_API_KEY") or os.getenv("CYBERGUARD_VIEWER_API_KEY"))
