"""
Week 3-5 milestone gate: scan_repository returns ≥1 SecurityFinding with a
correctly-formed canonical_id when pointed at the vulnerable Flask fixture.

These tests call Bandit as a real subprocess. Bandit must be installed in the
active environment (pip install bandit).

Fixture: tests/fixtures/vulnerable_flask_app.py
Known issues (confirmed by manual review):
  B608  SQL injection     line 23  CWE-89
  B307  eval()            line 31  CWE-78
  B105  hardcoded pw      line 15  CWE-259
  B102  exec()            line 36  CWE-78
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"
FLASK_FIXTURE = FIXTURE_DIR / "vulnerable_flask_app.py"


def _bandit_available() -> bool:
    """True if bandit is reachable — on PATH or in the active venv's Scripts dir."""
    if shutil.which("bandit"):
        return True
    venv_bin = Path(sys.executable).parent
    return any((venv_bin / name).is_file() for name in ("bandit", "bandit.exe"))


bandit_missing = not _bandit_available()


@pytest.mark.skipif(bandit_missing, reason="bandit not installed")
class TestBanditAdapter:
    def test_bandit_adapter_returns_findings(self):
        """BanditAdapter.run() returns ≥1 RawFinding for the Flask fixture."""
        from sentinel.scanners.bandit import BanditAdapter

        adapter = BanditAdapter()
        assert adapter.is_available(), "bandit must be on PATH"

        findings = adapter.run(FIXTURE_DIR)
        assert len(findings) >= 1, "Expected ≥1 raw finding from the fixture"

    def test_bandit_finds_sql_injection(self):
        """B608 (SQL injection) must appear for vulnerable_flask_app.py."""
        from sentinel.scanners.bandit import BanditAdapter

        adapter = BanditAdapter()
        findings = adapter.run(FIXTURE_DIR)
        rule_ids = {f.rule_id for f in findings}
        assert "B608" in rule_ids, f"Expected B608 in findings, got: {rule_ids}"

    def test_bandit_finds_eval(self):
        """B307 (eval) must appear for vulnerable_flask_app.py."""
        from sentinel.scanners.bandit import BanditAdapter

        adapter = BanditAdapter()
        findings = adapter.run(FIXTURE_DIR)
        rule_ids = {f.rule_id for f in findings}
        assert "B307" in rule_ids, f"Expected B307 in findings, got: {rule_ids}"


@pytest.mark.skipif(bandit_missing, reason="bandit not installed")
class TestFindingNormalizer:
    def test_normalizer_produces_security_findings(self):
        """Normalizer converts RawFindings to SecurityFindings with canonical_ids."""
        from sentinel.normalizer import FindingNormalizer
        from sentinel.scanners.bandit import BanditAdapter

        adapter = BanditAdapter()
        raw = adapter.run(FIXTURE_DIR)
        assert raw, "BanditAdapter returned no findings"

        normalizer = FindingNormalizer(FIXTURE_DIR)
        findings = normalizer.normalize(raw)

        assert len(findings) >= 1
        for f in findings:
            # canonical_id must be a 16-char hex string
            assert len(f.canonical_id) == 16
            assert all(c in "0123456789abcdef" for c in f.canonical_id)

    def test_canonical_id_is_stable(self):
        """Scanning the same fixture twice produces the same canonical_ids."""
        from sentinel.normalizer import FindingNormalizer
        from sentinel.scanners.bandit import BanditAdapter

        adapter = BanditAdapter()
        normalizer = FindingNormalizer(FIXTURE_DIR)

        first = {f.canonical_id for f in normalizer.normalize(adapter.run(FIXTURE_DIR))}
        second = {f.canonical_id for f in normalizer.normalize(adapter.run(FIXTURE_DIR))}

        assert first == second, "canonical_ids changed between identical scans"

    def test_canonical_id_formula(self):
        """canonical_id matches sha256(posix_path:line_start:cwe_or_rule)[:16]."""
        from sentinel.normalizer import FindingNormalizer
        from sentinel.schemas import SecurityFinding
        from sentinel.scanners.bandit import BanditAdapter

        adapter = BanditAdapter()
        normalizer = FindingNormalizer(FIXTURE_DIR)
        findings = normalizer.normalize(adapter.run(FIXTURE_DIR))

        for f in findings:
            cwe_or_rule = f.cwe_id or f.rule_id
            expected = SecurityFinding.make_canonical_id(
                f.file_path, f.line_start, cwe_or_rule
            )
            assert f.canonical_id == expected, (
                f"canonical_id mismatch for {f.rule_id} at {f.file_path}:{f.line_start}"
            )

    def test_no_path_traversal_outside_root(self, tmp_path):
        """Findings whose file paths escape the repo root are dropped."""
        from sentinel.normalizer import FindingNormalizer
        from sentinel.schemas import RawFinding

        normalizer = FindingNormalizer(tmp_path)
        # Construct a raw finding whose path is outside tmp_path
        outside = RawFinding(
            scanner="bandit",
            rule_id="B999",
            file_path="C:/Windows/system32/evil.py",
            line_start=1,
            line_end=1,
            severity="high",
            confidence="high",
            message="test",
        )
        findings = normalizer.normalize([outside])
        assert findings == [], "Path-traversal finding should be dropped"
