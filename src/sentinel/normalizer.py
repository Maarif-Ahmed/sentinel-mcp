"""
FindingNormalizer — converts RawFinding → SecurityFinding with deduplication.

Deduplication key: canonical_id = sha256(posix_file_path:line_start:cwe_or_rule)[:16]

When two scanners report the same logical issue (same file + line + CWE), the
finding with higher confidence is kept. Same confidence → first seen is kept.

The normalizer also:
- Converts absolute file paths to POSIX paths relative to the repo root
- Extracts a source code snippet (≤10 lines) for context
- Sanitizes file paths against path traversal
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from sentinel.schemas import RawFinding, SecurityFinding

# Scanner confidence → numeric for comparison
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

# Severity normalization for scanner-specific strings that slipped through
_SEVERITY_NORMALIZE: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "warning": "low",
    "error": "high",
}

# Confidence has its own vocabulary — reusing the severity map let values
# like "info" or "critical" through before being coerced.
_CONFIDENCE_NORMALIZE: dict[str, str] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "definite": "high",
    "firm": "medium",
    "tentative": "low",
}


class FindingNormalizer:
    def __init__(self, repo_root: Path, snippet_context_lines: int = 5) -> None:
        self._repo_root = repo_root.resolve()
        self._snippet_context = snippet_context_lines

    def normalize(self, raw_findings: list[RawFinding]) -> list[SecurityFinding]:
        """
        Normalize and deduplicate raw findings.

        Returns findings sorted by severity (critical → info) then confidence.
        """
        # (canonical_id, scanner, rule_id) → best finding for that exact rule.
        # canonical_id alone is file+line+CWE, so two DIFFERENT rules from one
        # scanner hash identically — B602 (shell=True) and B607 (partial path)
        # fire on the same call and need different fixes. Keying on rule_id as
        # well stops one of them being silently discarded.
        buckets: dict[tuple[str, str, str], SecurityFinding] = {}

        for raw in raw_findings:
            finding = self._to_security_finding(raw)
            if finding is None:
                continue
            key = (finding.canonical_id, finding.scanner, finding.rule_id)
            existing = buckets.get(key)
            if existing is None or (
                _CONFIDENCE_RANK.get(finding.confidence, 0)
                > _CONFIDENCE_RANK.get(existing.confidence, 0)
            ):
                buckets[key] = finding

        # Cross-scanner agreement is still collapsed: when two scanners report
        # the same location, the developer should see it once, with the
        # agreement recorded rather than thrown away.
        by_location: dict[str, list[SecurityFinding]] = {}
        for finding in buckets.values():
            by_location.setdefault(finding.canonical_id, []).append(finding)

        out: list[SecurityFinding] = []
        for group in by_location.values():
            scanners = {f.scanner for f in group}
            if len(scanners) == 1:
                out.extend(group)
                continue

            def _best_confidence(scanner: str) -> int:
                return max(
                    _CONFIDENCE_RANK.get(f.confidence, 0)
                    for f in group
                    if f.scanner == scanner
                )

            primary = max(sorted(scanners), key=_best_confidence)
            others = sorted(scanners - {primary})
            for finding in group:
                if finding.scanner == primary:
                    finding.corroborated_by = others
                    out.append(finding)

        return _sort_findings(out)

    def _to_security_finding(self, raw: RawFinding) -> SecurityFinding | None:
        posix_path = self._to_posix_relative(raw.file_path)
        if posix_path is None:
            return None  # path escapes repo root — skip

        severity = _SEVERITY_NORMALIZE.get(raw.severity.lower(), "low")
        confidence = _CONFIDENCE_NORMALIZE.get(raw.confidence.lower(), "low")

        cwe_or_rule = raw.cwe_id or raw.rule_id
        canonical_id = SecurityFinding.make_canonical_id(
            posix_path, raw.line_start, cwe_or_rule
        )

        snippet = self._extract_snippet(raw.file_path, raw.line_start, raw.line_end)

        return SecurityFinding(
            canonical_id=canonical_id,
            scanner=raw.scanner,  # type: ignore[arg-type]
            rule_id=raw.rule_id,
            file_path=posix_path,
            line_start=raw.line_start,
            line_end=raw.line_end,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            cwe_id=raw.cwe_id,
            message=raw.message,
            snippet=snippet,
            is_dev_dependency=bool(raw.extra.get("is_dev_dependency", False)),
        )

    def _to_posix_relative(self, path_str: str) -> str | None:
        """
        Convert an absolute or relative path to a POSIX path relative to repo_root.
        Returns None if the path escapes the repository root (path traversal guard).
        """
        p = Path(path_str)
        if not p.is_absolute():
            p = self._repo_root / p

        try:
            resolved = p.resolve()
            relative = resolved.relative_to(self._repo_root)
            return str(PurePosixPath(relative))
        except ValueError:
            # Path is outside the repo root — skip this finding
            return None

    def _extract_snippet(
        self, abs_path_str: str, line_start: int, line_end: int
    ) -> str | None:
        """
        Read ≤10 lines of source context around the finding.
        Returns None on any I/O error (file missing, binary, etc.).
        """
        try:
            p = Path(abs_path_str)
            if not p.is_absolute():
                # Scanners that emit repo-relative paths would otherwise be
                # resolved against the process CWD and silently yield None.
                p = self._repo_root / p
            if not p.is_file():
                return None
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            # 1-indexed: line_start=1 → lines[0]
            ctx_start = max(0, line_start - 1 - self._snippet_context)
            ctx_end = min(len(lines), line_end + self._snippet_context)
            selected = lines[ctx_start:ctx_end]
            if not selected:
                return None
            # Prefix each line with its 1-indexed number
            numbered = [
                f"{ctx_start + i + 1:4d}  {line}"
                for i, line in enumerate(selected)
            ]
            return "\n".join(numbered)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Sorting helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def _sort_findings(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 5),
            _CONFIDENCE_ORDER.get(f.confidence, 3),
        ),
    )
