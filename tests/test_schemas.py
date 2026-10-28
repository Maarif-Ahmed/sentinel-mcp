"""
Data contract tests — verify Pydantic models enforce their invariants.
"""

from __future__ import annotations

import pytest

from sentinel.schemas import (
    AuditEvent,
    ContextAnnotation,
    RemediationProposal,
    RiskAssessment,
    SecurityFinding,
    VerificationResult,
)


class TestSecurityFinding:
    def test_canonical_id_is_deterministic(self):
        id1 = SecurityFinding.make_canonical_id("src/app.js", 42, "CWE-89")
        id2 = SecurityFinding.make_canonical_id("src/app.js", 42, "CWE-89")
        assert id1 == id2

    def test_canonical_id_differs_for_different_inputs(self):
        id1 = SecurityFinding.make_canonical_id("src/app.js", 42, "CWE-89")
        id2 = SecurityFinding.make_canonical_id("src/app.js", 43, "CWE-89")
        assert id1 != id2

    def test_rejects_invalid_severity(self):
        with pytest.raises(Exception):
            SecurityFinding(
                canonical_id="abc",
                scanner="bandit",
                rule_id="B601",
                file_path="src/app.py",
                line_start=10,
                line_end=10,
                severity="EXTREME",  # invalid
                confidence="high",
                message="test",
            )


class TestRemediationProposal:
    def test_requires_developer_action_always_true(self):
        proposal = RemediationProposal(
            finding_id="test-id",
            patch_diff="--- a\n+++ b\n",
            rationale="test",
            generated_by="qwen2.5-coder:3b",
            requires_developer_action=False,  # should be overridden
        )
        assert proposal.requires_developer_action is True


class TestContextAnnotation:
    def test_disclaimer_always_present(self):
        annotation = ContextAnnotation(route_path="/api/users")
        assert len(annotation.disclaimer) > 0
        assert "Structural analysis only" in annotation.disclaimer


class TestVerificationResult:
    def test_disclaimer_always_present(self):
        result = VerificationResult(
            proposal_id="test",
            syntax_ok=True,
            rescan_clear=True,
            overall="undetected_by_rescan",
        )
        assert "Manual review" in result.disclaimer
