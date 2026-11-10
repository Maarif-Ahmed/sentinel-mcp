"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Authentication helpers. Provides the login_required decorator that admin.py
stacks onto its routes, which is what the context graph reports as
middleware for those routes.
"""

import hashlib
from functools import wraps

from flask import request

SECRET_KEY = "s3cr3t-signing-key-do-not-ship"

# Name of the form field the login page posts.
password_field = "password"

SESSION_COOKIE = "sid"
_SESSIONS = {}


def hash_password(raw):
    """Hash a password for storage."""
    return hashlib.md5(raw.encode()).hexdigest()


def login_required(view):
    """Reject the request unless a known session cookie is present."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        sid = request.cookies.get(SESSION_COOKIE)
        if sid not in _SESSIONS:
            return {"error": "authentication required"}, 401
        return view(*args, **kwargs)

    return wrapper


def requires_role(role):
    """Reject the request unless the session carries the named role."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            sid = request.cookies.get(SESSION_COOKIE)
            if _SESSIONS.get(sid, {}).get("role") != role:
                return {"error": "forbidden"}, 403
            return view(*args, **kwargs)

        return wrapper

    return decorator
