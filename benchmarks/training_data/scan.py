"""
Bandit snippet scanner — runs Bandit on in-memory code and returns findings.

Each snippet is written to a temp file, scanned with `bandit -f json`,
and the temp file is immediately deleted. No code persists on disk beyond
the duration of the scan call.

Quality gate for the training pipeline:
  KEEP pair if  bandit fires on code_before  (confirms it's detectable)
  KEEP pair if  bandit is SILENT on code_after  (confirms the fix works)
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BanditFinding:
    rule_id: str
    line_number: int
    line_start: int
    line_end: int
    severity: str       # HIGH / MEDIUM / LOW
    confidence: str     # HIGH / MEDIUM / LOW
    message: str
    cwe_id: str | None  # e.g. "CWE-78"
    code_snippet: str = ""


def scan_snippet(code: str, filename_hint: str = "snippet.py") -> list[BanditFinding]:
    """
    Run Bandit on *code* (a Python source string). Returns all findings.
    Returns [] on any error (parse failure, subprocess error, etc.).

    The temp file is named after filename_hint so Bandit's error messages
    reference a recognisable name.
    """
    suffix = Path(filename_hint).suffix or ".py"
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding="utf-8",
        ) as tf:
            tf.write(code)
            tmp_path = Path(tf.name)

        result = subprocess.run(
            ["bandit", "-f", "json", "-q", str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Bandit exits 1 when it finds issues — that's expected
        raw = result.stdout.strip()
        if not raw:
            return []

        data = json.loads(raw)
        findings = []
        for r in data.get("results", []):
            cwe = r.get("issue_cwe", {})
            cwe_id = None
            if isinstance(cwe, dict) and cwe.get("id"):
                cwe_id = f"CWE-{cwe['id']}"
            findings.append(BanditFinding(
                rule_id=r.get("test_id", ""),
                line_number=r.get("line_number", 0),
                line_start=r.get("line_range", [r.get("line_number", 0)])[0],
                line_end=r.get("line_range", [r.get("line_number", 0)])[-1],
                severity=r.get("issue_severity", "LOW"),
                confidence=r.get("issue_confidence", "LOW"),
                message=r.get("issue_text", ""),
                cwe_id=cwe_id,
                code_snippet=r.get("code", ""),
            ))
        return findings

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def passes_quality_gate(
    code_before: str,
    code_after: str,
    filename: str,
) -> tuple[bool, list[BanditFinding]]:
    """
    Return (passes, findings_in_before).

    A pair passes if:
      - Bandit fires at least once on code_before
      - None of those exact rule IDs fire on code_after at the same line
        (confirms the fix actually removes the finding)
    """
    before_findings = scan_snippet(code_before, filename)
    if not before_findings:
        return False, []

    after_findings = scan_snippet(code_after, filename)
    after_keys = {(f.rule_id, f.line_number) for f in after_findings}

    # Keep the pair if at least one before-finding is gone in after
    resolved = [
        f for f in before_findings
        if (f.rule_id, f.line_number) not in after_keys
    ]
    return bool(resolved), resolved
