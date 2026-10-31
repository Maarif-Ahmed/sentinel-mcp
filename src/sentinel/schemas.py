"""
Sentinel MCP — canonical data contracts.

All inter-module data exchange uses these Pydantic models. The MCP SDK derives
tool input/output JSON schemas from them automatically.

IMPORTANT: Every field that surfaces security findings to the developer must
include an honest representation of confidence. Never claim exploitability or
enforcement unless the evidence actually supports it.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


class RawFinding(BaseModel):
    """Scanner-native output before normalization. Internal use only."""

    scanner: str
    rule_id: str
    file_path: str  # absolute path as returned by scanner
    line_start: int
    line_end: int
    severity: str  # scanner-native severity string
    confidence: str  # scanner-native confidence string
    message: str
    cwe_id: str | None = None
    extra: dict = Field(default_factory=dict)  # scanner-specific fields


class SecurityFinding(BaseModel):
    """
    Normalized security finding.

    canonical_id deduplicates the same logical issue reported by multiple
    scanners. Two findings with the same canonical_id are considered the same
    issue; the one with higher scanner confidence is kept.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    canonical_id: str  # sha256(posix_file_path + str(line_start) + (cwe_id or rule_id))
    scanner: Literal["bandit", "trivy", "semgrep"]
    rule_id: str
    file_path: str  # POSIX path relative to repository root
    line_start: int
    line_end: int
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    cwe_id: str | None = None  # e.g. "CWE-78"
    message: str
    snippet: str | None = None  # ≤10 lines of surrounding source context
    is_dev_dependency: bool = False  # True when finding is in a dev/test dep (Trivy npm)

    @staticmethod
    def make_canonical_id(posix_path: str, line_start: int, cwe_or_rule: str) -> str:
        raw = f"{posix_path}:{line_start}:{cwe_or_rule}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Context graph annotation
# ---------------------------------------------------------------------------


class ContextAnnotation(BaseModel):
    """
    Structural context attached to a finding by the Express.js route extractor.

    SCOPE: This annotation makes exactly two structural claims:
    1. Which Express.js route (if any) the finding's file is reachable from.
    2. Which middleware names are registered on that route before the handler.

    It does NOT claim that middleware enforces authentication, that user input
    reaches this code path, or that the vulnerability is exploitable.
    """

    route_path: str | None = None  # e.g. "/api/users/:id"
    http_methods: list[str] = Field(default_factory=list)  # ["GET", "POST"]
    middleware_names: list[str] = Field(default_factory=list)
    attribution_confidence: Literal["handler", "file", "unknown"] = "unknown"
    disclaimer: str = (
        "Structural analysis only. "
        "Middleware names are not verified as enforcement mechanisms. "
        "This does not imply exploitability."
    )


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------


class RiskAssessment(BaseModel):
    """
    Contextually enriched risk ranking for a finding.

    feature_breakdown exposes every input to the ranking decision so the
    developer can see why a finding was ranked the way it was. This is
    intentional — opaque scoring is harder to trust and harder to evaluate.
    """

    finding_id: str
    ranked_severity: Literal["critical", "high", "medium", "low"]
    ranker: Literal["rule_based", "ml"]
    score: float = Field(ge=0.0, le=1.0)
    feature_breakdown: dict[str, float]  # feature_name → weight applied
    context_factors: list[str] = Field(default_factory=list)  # human-readable reasons


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


class RemediationProposal(BaseModel):
    """
    AI-generated patch proposal. This is a display-only artifact.

    The patch is NEVER applied automatically. The developer copies and applies
    it manually. requires_developer_action is always True and cannot be
    overridden via the MCP interface.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    finding_id: str
    patch_diff: str  # unified diff format
    rationale: str  # why this patch addresses the finding
    generated_by: str  # Ollama model ID, e.g. "qwen2.5-coder:3b"
    requires_developer_action: bool = True

    def model_post_init(self, __context: object) -> None:
        # Enforce invariant — can never be set False via API
        object.__setattr__(self, "requires_developer_action", True)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class VerificationResult(BaseModel):
    """
    Outcome of syntax check + rescan after developer applies a patch.

    rescan_clear means the scanner no longer reports the original finding's
    canonical_id. It does NOT mean the vulnerability is fixed — the scanner
    may simply not detect it. This distinction is stated in the disclaimer.
    """

    proposal_id: str
    syntax_ok: bool
    rescan_clear: bool
    overall: Literal[
        "undetected_by_rescan",
        "still_detected",
        "syntax_error",
        "inconclusive",
    ]
    disclaimer: str = (
        "rescan_clear=True means the scanner no longer reports this finding. "
        "It does not prove the vulnerability is fixed. Manual review is required."
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    """Append-only audit record written to SQLite for every tool invocation."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str  # e.g. "scan_repository", "explain_finding", "propose_fix"
    repository_root: str
    finding_canonical_id: str | None = None
    action: str
    outcome: str  # "success" | "error" | "skipped"
    metadata: dict = Field(default_factory=dict)

    @computed_field
    @property
    def timestamp_iso(self) -> str:
        return self.timestamp.isoformat()
