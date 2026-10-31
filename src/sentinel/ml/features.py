"""
sentinel.ml.features — Feature extraction for the ML ranker experiment.

Extracts a fixed-length numeric feature vector from a SecurityFinding +
optional ContextAnnotation. The same extractor is used at train time
(benchmarks/evaluate.py) and at inference time (MLRanker.rank()).

Feature vector (13 dimensions):
  0  severity_score      — scanner-reported severity: critical=4, high=3, medium=2, low=1, info=0
  1  confidence_score    — scanner confidence: high=2, medium=1, low=0
  2  is_dependency       — 1 if scanner=="trivy" (supply-chain surface), else 0
  3  is_dev_dependency   — 1 if finding is in a devDependency (from package-lock.json)
  4  cwe_high_impact     — 1 if CWE in the high-impact web CWE set, else 0
  5  cwe_injection       — 1 if CWE is an injection class (SQLi/XSS/CMDi/etc.)
  6  cwe_authn           — 1 if CWE is an authentication class
  7  cwe_path_traversal  — 1 if CWE-22 / CWE-23
  8  has_route           — 1 if route attribution is available
  9  route_depth         — number of segments in the route path (0 if none)
  10 has_auth_middleware — 1 if any middleware name matches an auth hint
  11 middleware_count    — number of middleware names on the route
  12 exposure_score      — 1.0 if route with no auth hint; 0.5 if route with auth hint; 0.0 if no route
"""

from __future__ import annotations

from sentinel.ranker import _AUTH_MIDDLEWARE_HINTS, _HIGH_IMPACT_CWES, _SEVERITY_SCORE, _CONFIDENCE_SCORE
from sentinel.schemas import ContextAnnotation, SecurityFinding

# CWE subsets for finer-grained features
_INJECTION_CWES = {"CWE-89", "CWE-79", "CWE-78", "CWE-94", "CWE-77", "CWE-917"}
_AUTHN_CWES = {"CWE-287", "CWE-306", "CWE-307", "CWE-798", "CWE-259"}
_TRAVERSAL_CWES = {"CWE-22", "CWE-23"}

FEATURE_NAMES = [
    "severity_score",
    "confidence_score",
    "is_dependency",
    "is_dev_dependency",
    "cwe_high_impact",
    "cwe_injection",
    "cwe_authn",
    "cwe_path_traversal",
    "has_route",
    "route_depth",
    "has_auth_middleware",
    "middleware_count",
    "exposure_score",
]


def extract(
    finding: SecurityFinding,
    context: ContextAnnotation | None,
) -> list[float]:
    """Return a list of floats aligned with FEATURE_NAMES."""
    cwe = finding.cwe_id or ""

    sev = float(_SEVERITY_SCORE.get(finding.severity, 0))
    conf = float(_CONFIDENCE_SCORE.get(finding.confidence, 0))
    is_dep = 1.0 if finding.scanner == "trivy" else 0.0
    is_dev = 1.0 if getattr(finding, "is_dev_dependency", False) else 0.0
    cwe_hi = 1.0 if cwe in _HIGH_IMPACT_CWES else 0.0
    cwe_inj = 1.0 if cwe in _INJECTION_CWES else 0.0
    cwe_auth = 1.0 if cwe in _AUTHN_CWES else 0.0
    cwe_trav = 1.0 if cwe in _TRAVERSAL_CWES else 0.0

    if context is not None and context.route_path:
        has_route = 1.0
        # count non-empty path segments (e.g. "/api/users/:id" → 3)
        route_depth = float(len([s for s in context.route_path.split("/") if s]))
        mw_lower = [m.lower() for m in context.middleware_names]
        has_auth_mw = 1.0 if any(
            hint in mw for mw in mw_lower for hint in _AUTH_MIDDLEWARE_HINTS
        ) else 0.0
        mw_count = float(len(context.middleware_names))
        exposure_score = 0.5 if has_auth_mw else 1.0
    else:
        has_route = 0.0
        route_depth = 0.0
        has_auth_mw = 0.0
        mw_count = 0.0
        exposure_score = 0.0

    return [
        sev,
        conf,
        is_dep,
        is_dev,
        cwe_hi,
        cwe_inj,
        cwe_auth,
        cwe_trav,
        has_route,
        route_depth,
        has_auth_mw,
        mw_count,
        exposure_score,
    ]
