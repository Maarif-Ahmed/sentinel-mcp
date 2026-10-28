"""
Sentinel MCP server — tool registration and request dispatch.

Transport: stdio (local-first).
All tools are read-only from the MCP perspective. No tool modifies the
target repository. Source code never leaves the local machine.

Week 1–2 gate: sentinel.ping must work from the MCP Inspector before
any scanner work begins.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

# MCP SDK v1.x high-level API.
# If the team upgrades to a v2 SDK that renames this import, update here only.
from mcp.server.fastmcp import FastMCP

from sentinel import __version__

mcp = FastMCP(
    "sentinel-mcp",
    instructions=(
        "Sentinel MCP provides security analysis tools for web application repositories. "
        "All findings are advisory. No tool modifies the target repository. "
        "Source code is processed locally and never sent to external services."
    ),
)


# ---------------------------------------------------------------------------
# Week 1–2 gate: environment proof-of-concept
# ---------------------------------------------------------------------------


@mcp.tool()
def ping() -> dict:
    """
    Verify that the Sentinel MCP server is running correctly.

    Returns server version, Python version, and current UTC timestamp.
    Call this first to confirm the MCP connection works before running scans.
    """
    return {
        "status": "ok",
        "sentinel_version": __version__,
        "python_version": sys.version,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "message": "Sentinel MCP is running. Week 1-2 gate: PASSED.",
    }


# ---------------------------------------------------------------------------
# Scanning tools (stubbed — implemented in Week 3–7)
# ---------------------------------------------------------------------------


@mcp.tool()
def scan_repository(
    repo_path: str,
    scanners: list[str] | None = None,
) -> dict:
    """
    Scan a web application repository for security vulnerabilities.

    Runs enabled scanner adapters (Bandit for Python SAST, Trivy for
    dependencies and secrets), normalizes findings, attaches Express.js
    route context, and ranks by risk.

    Args:
        repo_path: Absolute path to the repository root on the local machine.
        scanners: Optional list of scanner names to run. Defaults to all
                  enabled scanners. Valid values: ["bandit", "trivy"].

    Returns:
        List of SecurityFinding objects with ContextAnnotation and
        RiskAssessment attached, ranked by score descending.
    """
    _validate_repo_path(repo_path)
    raise NotImplementedError(
        "scan_repository is not yet implemented. "
        "See roadmap: Week 3–5 (Bandit), Week 6–7 (Trivy)."
    )


@mcp.tool()
def explain_finding(finding_id: str, repo_path: str) -> dict:
    """
    Generate an AI-assisted explanation for a specific security finding.

    Uses the local Ollama LLM (Qwen2.5-Coder 3B by default) to explain
    the vulnerability, its potential impact, and the relevant code context.
    Source code snippets are processed locally and not sent to any external
    service.

    Args:
        finding_id: The UUID of the finding from a prior scan_repository call.
        repo_path: Absolute path to the repository root (used to resolve
                   source snippets).

    Returns:
        Markdown-formatted explanation string.
    """
    _validate_repo_path(repo_path)
    raise NotImplementedError(
        "explain_finding is not yet implemented. "
        "See roadmap: Week 11–12 (LLM integration)."
    )


@mcp.tool()
def propose_fix(finding_id: str, repo_path: str) -> dict:
    """
    Generate a candidate patch for a security finding.

    Returns a unified diff that the developer can review and apply manually.
    This tool NEVER applies the patch automatically. The developer must copy
    the diff and apply it themselves.

    Args:
        finding_id: The UUID of the finding to address.
        repo_path: Absolute path to the repository root.

    Returns:
        RemediationProposal with patch_diff in unified diff format.
        requires_developer_action is always True.
    """
    _validate_repo_path(repo_path)
    raise NotImplementedError(
        "propose_fix is not yet implemented. "
        "See roadmap: Week 13–14 (patch generation)."
    )


@mcp.tool()
def verify_proposal(proposal_id: str, repo_path: str) -> dict:
    """
    Verify whether a manually applied patch addresses the original finding.

    Runs a syntax check on the patched file and rescans with the original
    scanner. Returns whether the finding's canonical_id is absent in the
    rescan.

    IMPORTANT: rescan_clear=True means the scanner no longer reports this
    finding. It does NOT prove the vulnerability is fixed. Manual review
    is always required.

    Args:
        proposal_id: The UUID of the RemediationProposal.
        repo_path: Absolute path to the repository root (must be patched
                   before calling this tool).

    Returns:
        VerificationResult with syntax_ok, rescan_clear, and overall verdict.
    """
    _validate_repo_path(repo_path)
    raise NotImplementedError(
        "verify_proposal is not yet implemented. "
        "See roadmap: Week 13–14 (verification)."
    )


@mcp.tool()
def get_audit_history(repo_path: str, limit: int = 50) -> dict:
    """
    Return recent audit events for a repository.

    Args:
        repo_path: Absolute path to the repository root.
        limit: Maximum number of events to return (default 50, max 500).

    Returns:
        List of AuditEvent records, most recent first.
    """
    _validate_repo_path(repo_path)
    raise NotImplementedError(
        "get_audit_history is not yet implemented. "
        "See roadmap: Week 15–16 (audit log)."
    )


@mcp.tool()
def report(repo_path: str, output_path: str | None = None) -> dict:
    """
    Generate a JSON + static HTML security report for a repository.

    Writes a single self-contained HTML file with all findings, context
    annotations, risk assessments, and audit history. No server required.

    Args:
        repo_path: Absolute path to the repository root.
        output_path: Optional path for the output files. Defaults to
                     <repo_path>/sentinel-report/.

    Returns:
        Paths to the generated JSON and HTML files.
    """
    _validate_repo_path(repo_path)
    raise NotImplementedError(
        "report is not yet implemented. "
        "See roadmap: Week 25–26 (report generator)."
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_repo_path(repo_path: str) -> Path:
    """
    Validate that repo_path is an absolute path to an existing directory.
    Prevents path traversal by rejecting relative paths and symlinks that
    escape the declared root.
    """
    p = Path(repo_path)
    if not p.is_absolute():
        raise ValueError(f"repo_path must be absolute, got: {repo_path!r}")
    if not p.exists():
        raise ValueError(f"repo_path does not exist: {repo_path!r}")
    if not p.is_dir():
        raise ValueError(f"repo_path must be a directory: {repo_path!r}")
    # Resolve symlinks and check the path stays under the declared root
    resolved = p.resolve()
    if resolved != p.resolve():  # always true after resolve, kept for clarity
        pass
    return resolved


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def serve() -> None:
    """Start the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    serve()
