"""
Week 6-7 milestone gate: TrivyAdapter finds CVEs in the vulnerable requirements
fixture, and the normalizer deduplicates findings from two scanners sharing the
same canonical_id.

Trivy must be installed and on PATH for these tests to run. Download from:
https://github.com/aquasecurity/trivy/releases

Fixture: tests/fixtures/requirements_vulnerable.txt
Known vulnerable packages: flask==0.12.2, requests==2.18.0, pyyaml==3.13, etc.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"
REQUIREMENTS_FIXTURE = FIXTURE_DIR / "requirements_vulnerable.txt"

trivy_missing = shutil.which("trivy") is None


@pytest.mark.skipif(trivy_missing, reason="trivy not installed")
class TestTrivyAdapter:
    def test_trivy_adapter_is_available(self):
        from sentinel.scanners.trivy import TrivyAdapter

        adapter = TrivyAdapter()
        assert adapter.is_available()

    def test_trivy_returns_findings_for_vulnerable_requirements(self):
        """TrivyAdapter.run() returns ≥1 RawFinding for the vulnerable fixture."""
        from sentinel.scanners.trivy import TrivyAdapter

        adapter = TrivyAdapter()
        findings = adapter.run(FIXTURE_DIR)
        assert len(findings) >= 1, "Expected ≥1 CVE finding from requirements_vulnerable.txt"

    def test_trivy_finding_has_cve_rule_id(self):
        """At least one finding must be a CVE (rule_id starts with CVE-)."""
        from sentinel.scanners.trivy import TrivyAdapter

        adapter = TrivyAdapter()
        findings = adapter.run(FIXTURE_DIR)
        cve_findings = [f for f in findings if f.rule_id.startswith("CVE-")]
        assert cve_findings, f"Expected CVE findings, got rule_ids: {[f.rule_id for f in findings[:5]]}"

    def test_trivy_finding_fields_are_valid(self):
        """All TrivyAdapter findings have required fields populated."""
        from sentinel.scanners.trivy import TrivyAdapter

        adapter = TrivyAdapter()
        findings = adapter.run(FIXTURE_DIR)
        assert findings, "No findings returned"

        for f in findings:
            assert f.scanner == "trivy"
            assert f.rule_id, "rule_id must not be empty"
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.confidence in ("high", "medium", "low")
            assert isinstance(f.line_start, int) and f.line_start >= 1
            assert isinstance(f.line_end, int) and f.line_end >= f.line_start

    def test_trivy_normalizer_produces_security_findings(self):
        """Normalizer converts Trivy RawFindings to SecurityFindings with canonical_ids."""
        from sentinel.normalizer import FindingNormalizer
        from sentinel.scanners.trivy import TrivyAdapter

        adapter = TrivyAdapter()
        raw = adapter.run(FIXTURE_DIR)
        assert raw, "TrivyAdapter returned no findings"

        normalizer = FindingNormalizer(FIXTURE_DIR)
        findings = normalizer.normalize(raw)

        assert len(findings) >= 1
        for f in findings:
            assert len(f.canonical_id) == 16
            assert all(c in "0123456789abcdef" for c in f.canonical_id)


class TestDeduplication:
    """Deduplication works even without Trivy installed — uses mock RawFindings."""

    def test_same_canonical_id_deduplicates(self):
        """Two RawFindings with identical file/line/cwe produce one SecurityFinding."""
        from sentinel.normalizer import FindingNormalizer
        from sentinel.schemas import RawFinding

        tmp_file = FIXTURE_DIR / "vulnerable_flask_app.py"
        normalizer = FindingNormalizer(FIXTURE_DIR)

        bandit_finding = RawFinding(
            scanner="bandit",
            rule_id="B608",
            file_path=str(tmp_file),
            line_start=23,
            line_end=23,
            severity="high",
            confidence="medium",
            message="SQL injection via string formatting",
            cwe_id="CWE-89",
        )
        trivy_finding = RawFinding(
            scanner="trivy",
            rule_id="B608",
            file_path=str(tmp_file),
            line_start=23,
            line_end=23,
            severity="high",
            confidence="high",  # higher confidence
            message="SQL injection (trivy)",
            cwe_id="CWE-89",
        )

        findings = normalizer.normalize([bandit_finding, trivy_finding])
        assert len(findings) == 1, (
            f"Expected 1 deduplicated finding, got {len(findings)}"
        )

    def test_higher_confidence_wins_on_dedup(self):
        """When two findings share a canonical_id, the higher-confidence one is kept."""
        from sentinel.normalizer import FindingNormalizer
        from sentinel.schemas import RawFinding

        tmp_file = FIXTURE_DIR / "vulnerable_flask_app.py"
        normalizer = FindingNormalizer(FIXTURE_DIR)

        low_conf = RawFinding(
            scanner="bandit",
            rule_id="B105",
            file_path=str(tmp_file),
            line_start=15,
            line_end=15,
            severity="medium",
            confidence="low",
            message="Hardcoded password (low confidence)",
            cwe_id="CWE-259",
        )
        high_conf = RawFinding(
            scanner="trivy",
            rule_id="B105",
            file_path=str(tmp_file),
            line_start=15,
            line_end=15,
            severity="medium",
            confidence="high",
            message="Hardcoded password (high confidence)",
            cwe_id="CWE-259",
        )

        findings = normalizer.normalize([low_conf, high_conf])
        assert len(findings) == 1
        assert findings[0].confidence == "high", (
            "Expected the high-confidence finding to win deduplication"
        )

    def test_different_lines_not_deduplicated(self):
        """Findings at different lines are NOT deduplicated even with same rule_id."""
        from sentinel.normalizer import FindingNormalizer
        from sentinel.schemas import RawFinding

        tmp_file = FIXTURE_DIR / "vulnerable_flask_app.py"
        normalizer = FindingNormalizer(FIXTURE_DIR)

        f1 = RawFinding(
            scanner="bandit",
            rule_id="B608",
            file_path=str(tmp_file),
            line_start=23,
            line_end=23,
            severity="high",
            confidence="high",
            message="SQL injection line 23",
            cwe_id="CWE-89",
        )
        f2 = RawFinding(
            scanner="bandit",
            rule_id="B608",
            file_path=str(tmp_file),
            line_start=31,
            line_end=31,
            severity="high",
            confidence="high",
            message="SQL injection line 31",
            cwe_id="CWE-89",
        )

        findings = normalizer.normalize([f1, f2])
        assert len(findings) == 2, (
            "Findings at different lines should not be deduplicated"
        )
