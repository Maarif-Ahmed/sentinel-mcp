"""
ScanOrchestrator — runs the full pipeline for a single repository scan.

Pipeline:
  scan → normalize → enrich (context) → rank → (optionally explain / propose)

All components are injected via constructor so tests can substitute fakes.
The orchestrator owns no I/O state — it delegates to adapter classes.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.context.graph import ContextGraph, ContextGraphBuilder
from sentinel.normalizer import FindingNormalizer
from sentinel.ranker import RankerProvider, RuleBasedRanker
from sentinel.scanners.bandit import BanditAdapter
from sentinel.scanners.base import ScannerAdapter, ScannerNotAvailableError
from sentinel.scanners.trivy import TrivyAdapter
from sentinel.schemas import (
    AuditEvent,
    ContextAnnotation,
    RiskAssessment,
    SecurityFinding,
)


class EnrichedFinding:
    """A SecurityFinding bundled with its ContextAnnotation and RiskAssessment."""

    __slots__ = ("finding", "context", "risk")

    def __init__(
        self,
        finding: SecurityFinding,
        context: ContextAnnotation,
        risk: RiskAssessment,
    ) -> None:
        self.finding = finding
        self.context = context
        self.risk = risk

    def to_dict(self) -> dict:
        return {
            "finding": self.finding.model_dump(),
            "context": self.context.model_dump(),
            "risk": self.risk.model_dump(),
        }


class ScanOrchestrator:
    def __init__(
        self,
        scanners: list[ScannerAdapter] | None = None,
        ranker: RankerProvider | None = None,
    ) -> None:
        self._scanners: list[ScannerAdapter] = scanners or [
            BanditAdapter(),
            TrivyAdapter(),
        ]
        self._ranker: RankerProvider = ranker or RuleBasedRanker()

    def scan(
        self,
        repo_path: Path,
        requested_scanners: list[str] | None = None,
    ) -> list[EnrichedFinding]:
        """Run the pipeline and return findings sorted by risk score descending."""
        findings, _errors = self.scan_with_diagnostics(repo_path, requested_scanners)
        return findings

    def scan_with_diagnostics(
        self,
        repo_path: Path,
        requested_scanners: list[str] | None = None,
    ) -> tuple[list[EnrichedFinding], list[dict]]:
        """
        Run scanners, normalize, enrich with context, rank.

        Args:
            repo_path: Resolved absolute path to repository root.
            requested_scanners: Optional allowlist of scanner names.
                                 None means run all available scanners.

        Returns:
            (findings sorted by risk score descending, scanner diagnostics).

        Scanner failures are collected rather than swallowed: a crashed
        scanner otherwise produces a partial scan that is indistinguishable
        from a clean one, which silently corrupts any evaluation built on it.
        """
        repo_path = repo_path.resolve()

        # --- 1. Run scanners ---
        from sentinel.schemas import RawFinding
        all_raw: list[RawFinding] = []
        errors: list[dict] = []
        active_scanners = self._select_scanners(requested_scanners)

        for scanner in active_scanners:
            if not scanner.is_available():
                errors.append({"scanner": scanner.name, "status": "unavailable"})
                continue
            try:
                raw = scanner.run(repo_path)
                all_raw.extend(raw)
            except ScannerNotAvailableError as e:
                errors.append(
                    {"scanner": scanner.name, "status": "unavailable", "detail": str(e)}
                )
            except Exception as e:
                errors.append(
                    {
                        "scanner": scanner.name,
                        "status": "failed",
                        "detail": f"{type(e).__name__}: {e}",
                    }
                )

        # --- 2. Normalize and deduplicate ---
        normalizer = FindingNormalizer(repo_path)
        findings: list[SecurityFinding] = normalizer.normalize(all_raw)

        # --- 3. Build context graph ---
        ctx_builder = ContextGraphBuilder(repo_path)
        ctx_graph: ContextGraph = ctx_builder.build()

        # --- 4. Enrich each finding with context + risk assessment ---
        enriched: list[EnrichedFinding] = []
        for finding in findings:
            context = ctx_graph.annotate_finding(finding)
            risk = self._ranker.rank(finding, context)
            enriched.append(EnrichedFinding(finding, context, risk))

        # Sort by risk score descending. canonical_id breaks ties so that the
        # same repository always produces the same ordering — otherwise
        # Precision@K partly reflects scanner output order.
        enriched.sort(key=lambda e: (-e.risk.score, e.finding.canonical_id))
        return enriched, errors

    def _select_scanners(
        self, requested: list[str] | None
    ) -> list[ScannerAdapter]:
        if requested is None:
            return self._scanners
        return [s for s in self._scanners if s.name in requested]
