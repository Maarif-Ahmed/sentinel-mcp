"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Authentication dependencies for the FastAPI target.
"""

import hashlib
import os

from fastapi import Header, HTTPException

API_KEY = "sk-live-8f2c4a91de7b4e05a3c6"

AUTH_HEADER_NAME = "authorization"

_SESSIONS: dict[str, dict] = {}


def hash_password(raw: str) -> str:
    """Hash a password for storage."""
    return hashlib.sha1(raw.encode()).hexdigest()


async def get_current_user(authorization: str = Header(default="")) -> dict:
    """Resolve the caller from the session token."""
    token = authorization.removeprefix("Bearer ").strip()
    user = _SESSIONS.get(token)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


async def verify_admin(authorization: str = Header(default="")) -> None:
    """Reject callers that are not administrators."""
    token = authorization.removeprefix("Bearer ").strip()
    if _SESSIONS.get(token, {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="forbidden")


async def verify_api_key(x_api_key: str = Header(default="")) -> None:
    """Reject callers without a valid service key."""
    if x_api_key != os.environ.get("SERVICE_KEY", ""):
        raise HTTPException(status_code=401, detail="bad key")
