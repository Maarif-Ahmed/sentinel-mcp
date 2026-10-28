"""
Sentinel MCP — CLI entry point.

Usage:
    sentinel serve      Start the MCP server over stdio (for MCP client config)
    sentinel ping       Quick health check (not via MCP, direct Python call)
"""

from __future__ import annotations

import sys


def main() -> None:
    args = sys.argv[1:]
    command = args[0] if args else "serve"

    if command == "serve":
        from sentinel.server import serve
        serve()
    elif command == "ping":
        from sentinel.server import ping
        import json
        print(json.dumps(ping(), indent=2))
    else:
        print(f"Unknown command: {command!r}. Available: serve, ping", file=sys.stderr)
        sys.exit(1)
