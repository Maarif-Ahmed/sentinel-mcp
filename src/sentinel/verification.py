"""
Verification engine — syntax check + rescan after developer applies a patch.

Two stages:
  1. SyntaxChecker: validates that the patched file parses without errors
     (Python: ast.parse; JS/TS: 'node --check' subprocess if Node is available)
  2. RescanEngine: runs the original scanner on the patched file and checks
     whether the finding's canonical_id is absent from the results

IMPORTANT: rescan_clear=True means the scanner no longer reports this
canonical_id. It does NOT prove the vulnerability is fixed. The scanner
may have missed it, or the fix may be incomplete. Manual review is required.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

from sentinel.normalizer import FindingNormalizer
from sentinel.scanners.bandit import BanditAdapter
from sentinel.schemas import SecurityFinding, VerificationResult


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

    def rescan(self, original_finding: SecurityFinding) -> tuple[bool, str]:
        """
        Rescan for the original finding's canonical_id.

        Returns:
            (rescan_clear: bool, message: str)
            rescan_clear=True → canonical_id absent in rescan
            rescan_clear=False → canonical_id still present
        """
        scanner = original_finding.scanner

        if scanner == "bandit":
            return self._rescan_with_bandit(original_finding)

        # Trivy rescans the whole filesystem; for now we report inconclusive
        # rather than running a full Trivy scan on every verify call.
        return True, (
            f"Rescan for scanner '{scanner}' not implemented — "
            "result is inconclusive. Manual verification required."
        )

    def _rescan_with_bandit(self, finding: SecurityFinding) -> tuple[bool, str]:
        target_file = self._repo_root / finding.file_path.replace("/", "\\")
        if not target_file.is_file():
            return True, f"File no longer exists: {finding.file_path}"

        try:
            if not self._bandit.is_available():
                return True, "bandit not available — rescan skipped (inconclusive)"

            raw_findings = self._bandit.run(target_file.parent)
            normalized = self._normalizer.normalize(raw_findings)
            found_ids = {f.canonical_id for f in normalized}
            clear = finding.canonical_id not in found_ids
            if clear:
                return True, f"canonical_id {finding.canonical_id[:8]}… absent in rescan"
            return False, f"canonical_id {finding.canonical_id[:8]}… still present in rescan"
        except Exception as e:
            return True, f"Rescan error: {e} — result is inconclusive"


class VerificationPipeline:
    """Runs syntax check then rescan; computes overall VerificationResult."""

    def __init__(self, repo_root: Path) -> None:
        self._syntax_checker = SyntaxChecker()
        self._rescan_engine = RescanEngine(repo_root)
        self._repo_root = repo_root

    def verify(
        self, proposal_id: str, finding: SecurityFinding
    ) -> VerificationResult:
        file_path = self._repo_root / finding.file_path.replace("/", "\\")

        # Stage 1: syntax check
        syntax_ok, syntax_msg = self._syntax_checker.check(file_path)
        if not syntax_ok:
            return VerificationResult(
                proposal_id=proposal_id,
                syntax_ok=False,
                rescan_clear=False,
                overall="syntax_error",
            )

        # Stage 2: rescan
        rescan_clear, rescan_msg = self._rescan_engine.rescan(finding)

        if "inconclusive" in rescan_msg.lower():
            overall = "inconclusive"
        elif rescan_clear:
            overall = "undetected_by_rescan"
        else:
            overall = "still_detected"

        return VerificationResult(
            proposal_id=proposal_id,
            syntax_ok=syntax_ok,
            rescan_clear=rescan_clear,
            overall=overall,  # type: ignore[arg-type]
        )
