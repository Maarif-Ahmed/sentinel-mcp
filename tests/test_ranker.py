"""
Week 11-12 milestone gate — Part 1: RuleBasedRanker.

Tests verify:
  - score is in [0, 1]
  - feature_breakdown contains all expected keys
  - high-severity + high-confidence findings score higher than low ones
  - exposure_bonus applied when route has no auth middleware
  - auth_present_penalty applied when route has auth middleware
  - CWE weight is higher for high-impact CWEs
  - Trivy findings get dependency_bonus
  - ranked_severity maps correctly from score
"""

from __future__ import annotations

import pytest

from sentinel.ranker import RuleBasedRanker
from sentinel.schemas import ContextAnnotation, SecurityFinding


def _make_finding(
    severity: str = "high",
    confidence: str = "high",
    scanner: str = "bandit",
    cwe_id: str | None = "CWE-89",
) -> SecurityFinding:
    return SecurityFinding(
        canonical_id=SecurityFinding.make_canonical_id("app.py", 10, cwe_id or "B999"),
        scanner=scanner,
        rule_id="B608",
        file_path="app.py",
        line_start=10,
        line_end=10,
        severity=severity,
        confidence=confidence,
        cwe_id=cwe_id,
        message="test finding",
    )


def _make_context(
    route_path: str | None = "/api/test",
    middleware_names: list[str] | None = None,
) -> ContextAnnotation:
    return ContextAnnotation(
        route_path=route_path,
        http_methods=["GET"],
        middleware_names=middleware_names or [],
        attribution_confidence="handler" if route_path else "unknown",
    )


class TestRuleBasedRanker:
    def test_score_in_range(self):
        ranker = RuleBasedRanker()
        finding = _make_finding()
        result = ranker.rank(finding, _make_context())
        assert 0.0 <= result.score <= 1.0

    def test_feature_breakdown_keys_present(self):
        ranker = RuleBasedRanker()
        result = ranker.rank(_make_finding(), _make_context())
        expected_keys = {
            "severity_score", "confidence_score", "cwe_weight",
            "exposure_bonus", "auth_present_penalty", "dependency_bonus",
        }
        assert expected_keys.issubset(result.feature_breakdown.keys())

    def test_high_severity_scores_higher_than_low(self):
        ranker = RuleBasedRanker()
        high = ranker.rank(_make_finding(severity="high", confidence="high"), _make_context())
        low = ranker.rank(_make_finding(severity="low", confidence="low"), _make_context())
        assert high.score > low.score

    def test_exposure_bonus_applied_on_unauthenticated_route(self):
        ranker = RuleBasedRanker()
        no_auth = ranker.rank(_make_finding(), _make_context(middleware_names=[]))
        assert no_auth.feature_breakdown["exposure_bonus"] == 2.0
        assert no_auth.feature_breakdown["auth_present_penalty"] == 0.0

    def test_auth_penalty_applied_on_authenticated_route(self):
        ranker = RuleBasedRanker()
        with_auth = ranker.rank(
            _make_finding(),
            _make_context(middleware_names=["authMiddleware"]),
        )
        assert with_auth.feature_breakdown["auth_present_penalty"] == 1.0
        assert with_auth.feature_breakdown["exposure_bonus"] == 0.0

    def test_no_route_context_no_exposure_bonus(self):
        ranker = RuleBasedRanker()
        no_route = ranker.rank(_make_finding(), _make_context(route_path=None))
        assert no_route.feature_breakdown["exposure_bonus"] == 0.0
        assert no_route.feature_breakdown["auth_present_penalty"] == 0.0

    def test_high_impact_cwe_gets_weight_2(self):
        ranker = RuleBasedRanker()
        result = ranker.rank(_make_finding(cwe_id="CWE-89"), _make_context())
        assert result.feature_breakdown["cwe_weight"] == 2.0

    def test_low_impact_cwe_gets_weight_1(self):
        ranker = RuleBasedRanker()
        result = ranker.rank(_make_finding(cwe_id="CWE-400"), _make_context())
        assert result.feature_breakdown["cwe_weight"] == 1.0

    def test_trivy_finding_gets_dependency_bonus(self):
        ranker = RuleBasedRanker()
        trivy = ranker.rank(_make_finding(scanner="trivy"), _make_context())
        bandit = ranker.rank(_make_finding(scanner="bandit"), _make_context())
        assert trivy.feature_breakdown["dependency_bonus"] == 1.0
        assert bandit.feature_breakdown["dependency_bonus"] == 0.0
        assert trivy.score > bandit.score

    def test_ranked_severity_is_valid_literal(self):
        ranker = RuleBasedRanker()
        result = ranker.rank(_make_finding(), _make_context())
        assert result.ranked_severity in ("critical", "high", "medium", "low")

    def test_ranker_label_is_rule_based(self):
        ranker = RuleBasedRanker()
        result = ranker.rank(_make_finding(), _make_context())
        assert result.ranker == "rule_based"

    def test_unauthenticated_route_scores_higher_than_authenticated(self):
        """Public routes (no auth middleware) should rank higher than protected ones."""
        ranker = RuleBasedRanker()
        finding = _make_finding(severity="high", confidence="high")
        public = ranker.rank(finding, _make_context(middleware_names=[]))
        protected = ranker.rank(finding, _make_context(middleware_names=["authMiddleware"]))
        assert public.score > protected.score

    def test_context_factors_non_empty(self):
        ranker = RuleBasedRanker()
        result = ranker.rank(_make_finding(), _make_context())
        assert len(result.context_factors) >= 1
