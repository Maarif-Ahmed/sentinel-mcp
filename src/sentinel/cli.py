"""
Sentinel MCP — CLI entry point.

Usage:
    sentinel serve                        Start the MCP server over stdio
    sentinel ping                         Quick health check (direct Python call)
    sentinel report <repo_path> [--out <dir>]
                                          Scan repo and write JSON + HTML report
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
        import json
        from sentinel.server import ping
        print(json.dumps(ping(), indent=2))

    elif command == "report":
        _cmd_report(args[1:])

    else:
        _usage()
        sys.exit(1)


def _cmd_report(args: list[str]) -> None:
    import json
    from pathlib import Path

    repo_path: str | None = None
    out_dir: str | None = None

    i = 0
    while i < len(args):
        if args[i] in ("--out", "-o") and i + 1 < len(args):
            out_dir = args[i + 1]
            i += 2
        elif not args[i].startswith("-"):
            repo_path = args[i]
            i += 1
        else:
            print(f"Unknown flag: {args[i]!r}", file=sys.stderr)
            sys.exit(1)

    if not repo_path:
        print("Usage: sentinel report <repo_path> [--out <output_dir>]", file=sys.stderr)
        sys.exit(1)

    resolved = Path(repo_path)
    if not resolved.is_absolute():
        resolved = Path.cwd() / resolved
    resolved = resolved.resolve()

    if not resolved.exists() or not resolved.is_dir():
        print(f"Error: {repo_path!r} is not an existing directory.", file=sys.stderr)
        sys.exit(1)

    out = Path(out_dir).resolve() if out_dir else resolved / "sentinel-report"
    out.mkdir(parents=True, exist_ok=True)

    print(f"Scanning {resolved} …", flush=True)

    from sentinel.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator()
    enriched = orchestrator.scan(resolved)

    # Fetch recent audit events
    from pathlib import Path as _Path
    db_path = _Path.home() / ".sentinel" / "audit.db"
    events: list = []
    if db_path.exists():
        from sentinel.audit import AuditLogger
        events = AuditLogger(db_path).get_recent(str(resolved), 500)

    from sentinel.report import ReportGenerator
    gen = ReportGenerator()
    json_path, html_path = gen.write(enriched, events, out)

    result = {
        "finding_count": len(enriched),
        "json_path": str(json_path),
        "html_path": str(html_path),
    }
    print(json.dumps(result, indent=2))


def _usage() -> None:
    print(
        "Usage:\n"
        "  sentinel serve                         Start MCP server over stdio\n"
        "  sentinel ping                          Health check\n"
        "  sentinel report <path> [--out <dir>]  Scan and generate report",
        file=sys.stderr,
    )
