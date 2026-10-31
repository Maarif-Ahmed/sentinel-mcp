"""
Week 13-14 milestone gate — Part 2: SyntaxChecker + VerificationPipeline.

Tests verify:
  - SyntaxChecker correctly identifies valid/invalid Python files
  - Unknown file extensions are skipped (not errored)
  - VerificationPipeline returns VerificationResult with correct overall verdict
  - disclaimer is always present on VerificationResult
  - proposal_id flows through to the result
  - syntax_error stops the pipeline before rescan
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.schemas import SecurityFinding, VerificationResult
from sentinel.verification import SyntaxChecker, VerificationPipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_PY = """\
import sqlite3

def get_user(user_id: int):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
"""

_INVALID_PY = """\
def broken(:
    pass
"""


def _make_finding(file_path: str = "app.py") -> SecurityFinding:
    return SecurityFinding(
        canonical_id=SecurityFinding.make_canonical_id(file_path, 5, "CWE-89"),
        scanner="bandit",
        rule_id="B608",
        file_path=file_path,
        line_start=5,
        line_end=5,
        severity="high",
        confidence="high",
        cwe_id="CWE-89",
        message="SQL injection",
    )


# ---------------------------------------------------------------------------
# SyntaxChecker tests
# ---------------------------------------------------------------------------

class TestSyntaxChecker:
    def test_valid_python_returns_true(self, tmp_path: Path):
        f = tmp_path / "good.py"
        f.write_text(_VALID_PY, encoding="utf-8")
        ok, msg = SyntaxChecker().check(f)
        assert ok is True
        assert "ok" in msg.lower() or "syntax" in msg.lower()

    def test_invalid_python_returns_false(self, tmp_path: Path):
        f = tmp_path / "bad.py"
        f.write_text(_INVALID_PY, encoding="utf-8")
        ok, msg = SyntaxChecker().check(f)
        assert ok is False
        assert msg != ""

    def test_unknown_extension_is_skipped(self, tmp_path: Path):
        f = tmp_path / "data.txt"
        f.write_text("not code", encoding="utf-8")
        ok, msg = SyntaxChecker().check(f)
        assert ok is True
        assert "skipped" in msg.lower()

    def test_syntax_error_message_contains_line_number(self, tmp_path: Path):
        f = tmp_path / "bad.py"
        f.write_text(_INVALID_PY, encoding="utf-8")
        ok, msg = SyntaxChecker().check(f)
        assert ok is False
        assert any(ch.isdigit() for ch in msg), "Error message should reference a line number"


# ---------------------------------------------------------------------------
# VerificationPipeline tests
# ---------------------------------------------------------------------------

class TestVerificationPipeline:
    def test_syntax_error_gives_syntax_error_overall(self, tmp_path: Path):
        bad = tmp_path / "app.py"
        bad.write_text(_INVALID_PY, encoding="utf-8")

        finding = _make_finding("app.py")
        pipeline = VerificationPipeline(tmp_path)
        result = pipeline.verify("prop-123", finding)

        assert isinstance(result, VerificationResult)
        assert result.syntax_ok is False
        assert result.overall == "syntax_error"

    def test_valid_file_no_vuln_returns_undetected_or_inconclusive(self, tmp_path: Path):
        """
        Clean Python file (no SQL injection) — rescan should not find the
        original finding, so overall is either 'undetected_by_rescan' or
        'inconclusive' (when Bandit is unavailable).
        """
        clean = tmp_path / "app.py"
        clean.write_text(_VALID_PY, encoding="utf-8")

        finding = _make_finding("app.py")
        pipeline = VerificationPipeline(tmp_path)
        result = pipeline.verify("prop-456", finding)

        assert result.syntax_ok is True
        assert result.overall in ("undetected_by_rescan", "inconclusive")

    def test_disclaimer_always_present(self, tmp_path: Path):
        good = tmp_path / "app.py"
        good.write_text(_VALID_PY, encoding="utf-8")

        finding = _make_finding("app.py")
        result = VerificationPipeline(tmp_path).verify("prop-789", finding)

        assert result.disclaimer
        assert "manual review" in result.disclaimer.lower() or "not prove" in result.disclaimer.lower()

    def test_proposal_id_flows_through(self, tmp_path: Path):
        good = tmp_path / "app.py"
        good.write_text(_VALID_PY, encoding="utf-8")

        finding = _make_finding("app.py")
        result = VerificationPipeline(tmp_path).verify("my-proposal-id", finding)

        assert result.proposal_id == "my-proposal-id"

    def test_result_has_all_required_fields(self, tmp_path: Path):
        good = tmp_path / "app.py"
        good.write_text(_VALID_PY, encoding="utf-8")

        finding = _make_finding("app.py")
        result = VerificationPipeline(tmp_path).verify("prop-fields", finding)

        assert hasattr(result, "syntax_ok")
        assert hasattr(result, "rescan_clear")
        assert hasattr(result, "overall")
        assert hasattr(result, "disclaimer")
        assert result.overall in ("undetected_by_rescan", "still_detected", "syntax_error", "inconclusive")
