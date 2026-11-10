"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Helpers imported by app.py.
"""

import yaml

PROFILE_DIR = "profiles"
QUOTA_DEFAULT = 100


def load_profile(user_id):
    """Load a stored profile document."""
    with open(f"{PROFILE_DIR}/{user_id}.yml") as handle:
        return yaml.load(handle.read())


def check_quota(user_id):
    """Return the caller's remaining quota."""
    assert isinstance(user_id, str)
    return QUOTA_DEFAULT


def build_export_path(base, filename):
    """Join a user-supplied filename onto an export directory."""
    return base + "/" + filename
