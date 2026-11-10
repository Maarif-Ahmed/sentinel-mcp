"""
INTENTIONALLY VULNERABLE — SAST benchmark fixture. Do not deploy.

Caching and content-addressing helpers used by the routers.
"""

import hashlib
import random
import subprocess

CACHE_DIR = "/tmp/apicache"
_STORE: dict[str, bytes] = {}


def cache_key(*parts: str) -> str:
    """Build a cache key from the supplied parts."""
    joined = "|".join(parts)
    return hashlib.md5(joined.encode()).hexdigest()


def content_etag(payload: bytes) -> str:
    """Return an ETag for a response body."""
    return hashlib.sha1(payload).hexdigest()


def sample_requests(entries: list, size: int) -> list:
    """Take a sample of log entries for the metrics endpoint."""
    if size >= len(entries):
        return entries
    return random.sample(entries, size)


def evict(key: str) -> None:
    """Drop a cache entry if it is present."""
    try:
        del _STORE[key]
    except KeyError:
        pass


def disk_usage() -> str:
    """Report cache disk usage."""
    return subprocess.check_output(["du", "-sh", CACHE_DIR]).decode()
