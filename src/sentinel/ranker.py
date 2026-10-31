"""
Risk ranker — scores and re-ranks SecurityFindings by exploitability signal.

Two implementations behind RankerProvider:
  - RuleBasedRanker: transparent weighted formula (Week 11–12)
  - MLRanker: experimental XGBoost/RF model (FYP-II, Week 19–21)

The rule-based ranker is the default. Every feature and weight is visible in
the returned RiskAssessment.feature_breakdown so developers can see exactly
why a finding was ranked the way it was.

Feature weights (tunable via config):
  severity_score       0–4 points  (critical=4, high=3, medium=2, low=1, info=0)
  confidence_score     0–2 points  (high=2, medium=1, low=0)
  exposure_bonus       +2          if route has no auth middleware by name heuristic
  auth_present_penalty -1          if route has a named middleware ending in 'auth'
  dependency_bonus     +1          if finding is from trivy (dependency surface)
  cwe_weight           0–2 points  CWE tier (critical web CWEs get 2, others get 1)
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sentinel.schemas import ContextAnnotation, RiskAssessment, SecurityFinding

_SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONFIDENCE_SCORE = {"high": 2, "medium": 1, "low": 0}

# CWEs with direct exploitation potential for web apps get weight 2
_HIGH_IMPACT_CWES = {
    "CWE-89",   # SQL Injection
    "CWE-79",   # XSS
    "CWE-78",   # OS Command Injection
    "CWE-22",   # Path Traversal
    "CWE-502",  # Insecure Deserialization
    "CWE-798",  # Hardcoded Credentials
    "CWE-611",  # XML External Entity
    "CWE-94",   # Code Injection
    "CWE-287",  # Improper Authentication
    "CWE-306",  # Missing Authentication
}

# Heuristic: middleware names that suggest authentication enforcement
_AUTH_MIDDLEWARE_HINTS = {
    "auth", "authenticate", "authenticated", "isauth", "isloggedin",
    "requireauth", "requirelogin", "verifytoken", "checkauth",
    "passport", "jwt", "session",
}


class RankerProvider(ABC):
    @abstractmethod
    def rank(
        self,
        finding: SecurityFinding,
        context: ContextAnnotation | None,
    ) -> RiskAssessment:
        """Compute a RiskAssessment for a finding."""


class RuleBasedRanker(RankerProvider):
    """
    Transparent weighted feature ranker.

    All weights are explicit; no black-box scoring.
    """

    def rank(
        self,
        finding: SecurityFinding,
        context: ContextAnnotation | None,
    ) -> RiskAssessment:
        breakdown: dict[str, float] = {}

        # Base: severity
        sev = _SEVERITY_SCORE.get(finding.severity, 0)
        breakdown["severity_score"] = float(sev)

        # Base: confidence
        conf = _CONFIDENCE_SCORE.get(finding.confidence, 0)
        breakdown["confidence_score"] = float(conf)

        # CWE impact tier
        cwe_w = 2.0 if finding.cwe_id in _HIGH_IMPACT_CWES else 1.0
        breakdown["cwe_weight"] = cwe_w

        # Context-derived features
        exposure_bonus = 0.0
        auth_penalty = 0.0
        if context is not None and context.route_path is not None:
            mw_lower = [m.lower() for m in context.middleware_names]
            has_auth_hint = any(
                hint in mw_name
                for mw_name in mw_lower
                for hint in _AUTH_MIDDLEWARE_HINTS
            )

            if not has_auth_hint:
                # No named auth middleware found — treat as publicly exposed
                exposure_bonus = 2.0
            else:
                auth_penalty = 1.0

            breakdown["exposure_bonus"] = exposure_bonus
            breakdown["auth_present_penalty"] = auth_penalty
        else:
            breakdown["exposure_bonus"] = 0.0
            breakdown["auth_present_penalty"] = 0.0

        # Dependency finding bonus (Trivy findings cover the supply chain surface)
        dep_bonus = 1.0 if finding.scanner == "trivy" else 0.0
        breakdown["dependency_bonus"] = dep_bonus

        raw_score = sev + conf + cwe_w + exposure_bonus - auth_penalty + dep_bonus

        # Normalise to 0.0–1.0; max possible = 4+2+2+2+0+1 = 11
        score = min(raw_score / 11.0, 1.0)

        ranked_severity = _score_to_severity(score)

        context_factors = _build_context_factors(finding, context, breakdown)

        return RiskAssessment(
            finding_id=finding.id,
            ranked_severity=ranked_severity,
            ranker="rule_based",
            score=round(score, 4),
            feature_breakdown=breakdown,
            context_factors=context_factors,
        )


def _score_to_severity(score: float) -> str:
    if score >= 0.75:
        return "critical"
    if score >= 0.55:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


def _build_context_factors(
    finding: SecurityFinding,
    context: ContextAnnotation | None,
    breakdown: dict[str, float],
) -> list[str]:
    factors: list[str] = []

    if finding.severity in ("critical", "high"):
        factors.append(f"Scanner reported {finding.severity} severity")
    if finding.confidence == "high":
        factors.append("Scanner confidence is high")
    if finding.cwe_id in _HIGH_IMPACT_CWES:
        factors.append(f"{finding.cwe_id} is a high-impact web vulnerability class")

    if context is not None and context.route_path is not None:
        factors.append(f"Attributable to route: {context.route_path}")
        if breakdown.get("exposure_bonus", 0) > 0:
            factors.append(
                "No named authentication middleware detected on this route "
                "(structural check only — not verified enforcement)"
            )
        if breakdown.get("auth_present_penalty", 0) > 0:
            factors.append(
                f"Route has middleware that may enforce authentication: "
                f"{context.middleware_names} "
                f"(structural check only — not verified enforcement)"
            )
    else:
        factors.append("Route attribution unavailable — context score not applied")

    return factors
