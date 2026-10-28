"""
Week 1–2 gate test: verify sentinel.ping returns a valid response.

This test must pass before any scanner work begins. It proves:
1. The Python environment and mcp package are installed correctly.
2. The server module imports without errors.
3. The ping tool returns the expected shape.
"""

from __future__ import annotations

import sys

import pytest

from sentinel.server import ping


def test_ping_returns_ok():
    result = ping()
    assert result["status"] == "ok"


def test_ping_includes_version():
    result = ping()
    assert "sentinel_version" in result
    assert result["sentinel_version"]  # non-empty


def test_ping_includes_python_version():
    result = ping()
    assert "python_version" in result
    assert sys.version in result["python_version"]


def test_ping_includes_timestamp():
    result = ping()
    assert "timestamp" in result
    # Should be a valid ISO 8601 string
    from datetime import datetime
    datetime.fromisoformat(result["timestamp"])
