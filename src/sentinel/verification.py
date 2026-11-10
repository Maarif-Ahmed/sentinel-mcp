"""
Verification engine — syntax check + rescan after developer applies a patch.

Two stages:
  1. SyntaxChecker: validates that the patched file parses without errors
     (Python: ast.parse; JS/TS: 'node --check' subprocess if Node is available)
  2. RescanEngine: re-runs the original scanner and reports whether an
     equivalent finding is still present

IMPORTANT: a CLEAR outcome means the scanner no longer reports this finding.
It does NOT prove the vulnerability is fixed. The scanner may have missed it,
or the fix may be incomplete. Manual review is required.

Matching uses SecurityFinding.fingerprint (file + rule/CWE), not canonical_id
(which pins the finding to a line number). A patch that inserts or removes
lines shifts every line below it, so canonical_id comparison would report an
untouched vulnerability as fixed.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
from enum import Enum
from pathlib import Path

from sentinel.normalizer import FindingNormalizer
from sentinel.scanners.bandit import BanditAdapter
from sentinel.schemas import SecurityFinding, VerificationResult


class RescanOutcome(str, Enum):
    """Tri-state rescan result.

    INCONCLUSIVE is distinct from CLEAR on purpose: a scanner that could not
    run tells us nothing, and must never be reported as a successful fix.
    """

    CLEAR = "clear"
    STILL_PRESENT = "still_present"
    INCONCLUSIVE = "inconclusive"


class SyntaxChecker:
    """Validates file syntax after a patch is applied."""

    def check(self, file_path: Path) -> tuple[bool, str]:
        """
        Returns (ok: bool, message: str).
        ok=True means no syntax errors detected.
        """
        suffix = file_path.suffix.lower()

        if suffix == ".py":
            return self._check_python(file_path)
        if suffix in (".js", ".mjs", ".cjs", ".ts"):
            return self._check_javascript(file_path)
        # Unknown extension — skip syntax check
        return True, f"Syntax check skipped for extension {suffix!r}"

    def _check_python(self, file_path: Path) -> tuple[bool, str]:
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            ast.parse(source, filename=str(file_path))
            return True, "Python syntax OK"
        except SyntaxError as e:
            return False, f"Python syntax error at line {e.lineno}: {e.msg}"
        except Exception as e:
            return False, f"Python parse error: {e}"

    def _check_javascript(self, file_path: Path) -> tuple[bool, str]:
        if shutil.which("node") is None:
            return True, "JavaScript syntax check skipped (node not on PATH)"
        try:
            result = subprocess.run(
                ["node", "--check", str(file_path)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                return True, "JavaScript syntax OK"
            return False, f"JavaScript syntax error: {result.stderr.strip()[:300]}"
        except subprocess.TimeoutExpired:
            return True, "JavaScript syntax check timed out — skipped"
        except Exception as e:
            return True, f"JavaScript syntax check failed: {e} — skipped"


class RescanEngine:
    """Re-runs the original scanner after a patch and checks if the finding persists."""

    def __init__(self, repo_root: Path) -> None:
        self._repo_root = repo_root
        self._normalizer = FindingNormalizer(repo_root)
        self._bandit = BanditAdapter()

    def rescan(self, original_finding: SecurityFinding) -> tuple[RescanOutcome, str]:
        """Rescan and report whether an equivalent finding is still present."""
        scanner = original_finding.scanner

        if scanner == "bandit":
            return self._rescan_with_bandit(original_finding)

        return RescanOutcome.INCONCLUSIVE, (
            f"Rescan for scanner '{scanner}' is not implemented. "
            "Manual verification required."
        )

    def _rescan_with_bandit(
        self, finding: SecurityFinding
    ) -> tuple[RescanOutcome, str]:
        target_file = self._repo_root / finding.file_path
        if not target_file.is_file():
            # The file vanishing is not evidence of a fix — it may have been
            # moved, renamed, or the wrong repo_path was supplied.
            return RescanOutcome.INCONCLUSIVE, (
                f"File not found: {finding.file_path}. Cannot verify."
            )

        if not self._bandit.is_available():
            return RescanOutcome.INCONCLUSIVE, "bandit is not available — rescan skipped"

        try:
            raw_findings = self._bandit.run(target_file.parent)
            normalized = self._normalizer.normalize(raw_findings)
        except Exception as e:
            return RescanOutcome.INCONCLUSIVE, f"Rescan failed: {e}"

        fingerprints = {f.fingerprint for f in normalized}
        if finding.fingerprint in fingerprints:
            return RescanOutcome.STILL_PRESENT, (
                f"An equivalent finding ({finding.rule_id} in {finding.file_path}) "
                "is still reported after the patch."
            )
        return RescanOutcome.CLEAR, (
            f"No {finding.rule_id} finding remains in {finding.file_path}."
        )


class VerificationPipeline:
    """Runs syntax check then rescan; computes overall VerificationResult."""

    def __init__(self, repo_root: Path) -> None:
        self._syntax_checker = SyntaxChecker()
        self._rescan_engine = RescanEngine(repo_root)
        self._repo_root = repo_root

    def verify(
        self, proposal_id: str, finding: SecurityFinding
    ) -> VerificationResult:
        file_path = self._repo_root / finding.file_path

        # Stage 1: syntax check
        syntax_ok, _syntax_msg = self._syntax_checker.check(file_path)
        if not syntax_ok:
            return VerificationResult(
                proposal_id=proposal_id,
                syntax_ok=False,
                rescan_clear=False,
                overall="syntax_error",
            )

        # Stage 2: rescan
        outcome, _rescan_msg = self._rescan_engine.rescan(finding)

        overall = {
            RescanOutcome.CLEAR: "undetected_by_rescan",
            RescanOutcome.STILL_PRESENT: "still_detected",
            RescanOutcome.INCONCLUSIVE: "inconclusive",
        }[outcome]

        return VerificationResult(
            proposal_id=proposal_id,
            syntax_ok=syntax_ok,
            rescan_clear=outcome is RescanOutcome.CLEAR,
            overall=overall,  # type: ignore[arg-type]
        )
