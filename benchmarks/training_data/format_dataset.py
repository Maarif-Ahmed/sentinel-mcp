"""
Instruction-pair formatter — converts (PairRecord, BanditFinding, diff) into
the message format used for QLoRA fine-tuning.

Output format (one JSON object per line, JSONL):
  {
    "id": "CVE-2019-12345-sha256truncated",
    "messages": [
      {"role": "system",    "content": "..."},
      {"role": "user",      "content": "..."},
      {"role": "assistant", "content": "<unified diff>"}
    ],
    "metadata": {
      "cve_id": "CVE-2019-12345",
      "cwe_id": "CWE-89",
      "rule_id": "B608",
      "diff_lines": 4,
      "filename": "views.py"
    }
  }

This matches the HuggingFace chat-template format expected by unsloth/trl.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from benchmarks.training_data.extract import PairRecord
from benchmarks.training_data.scan import BanditFinding


# ---------------------------------------------------------------------------
# System prompt (mirrors remediation.py exactly so fine-tune aligns)
# ---------------------------------------------------------------------------

_SYSTEM_PATCH = """\
You are a security engineer generating minimal, targeted code patches.

Rules:
- Return ONLY a unified diff in standard format:
    --- a/filename
    +++ b/filename
    @@ -line,count +line,count @@
     context line
    -removed line
    +added line
- The line marked with ">>>" is the EXACT vulnerable line. Only modify that line.
- Do NOT include any explanation, markdown code fences, or prose.
- Make the smallest change that addresses the vulnerability.
- If you truly cannot produce a safe patch, output: # CANNOT_PATCH: <reason>\
"""

_CONTEXT_RADIUS = 10  # lines each side, same as remediation.py


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

def _build_context_block(code: str, finding: BanditFinding) -> str:
    """Format a ±CONTEXT_RADIUS line window with >>> on the vulnerable line."""
    lines = code.splitlines()
    start = max(0, finding.line_start - 1 - _CONTEXT_RADIUS)
    end   = min(len(lines), finding.line_end + _CONTEXT_RADIUS)
    result = []
    for i, line in enumerate(lines[start:end], start=start):
        lineno = i + 1
        marker = ">>>" if finding.line_start <= lineno <= finding.line_end else "   "
        result.append(f"{lineno:4d} {marker} {line}")
    return "\n".join(result)


def _clean_diff(diff: str) -> str:
    """Strip markdown fences, normalise newlines, keep only the diff block."""
    cleaned = re.sub(r"```(?:diff|patch)?\n?", "", diff).strip()
    # Ensure it starts with the header
    if not cleaned.startswith("---"):
        # Try to find the diff header inside the string
        m = re.search(r"^(--- .+)", cleaned, re.MULTILINE)
        if m:
            cleaned = cleaned[m.start():]
    return cleaned


def format_instruction_pair(
    record: PairRecord,
    finding: BanditFinding,
) -> dict | None:
    """
    Build one training example.

    Returns None if the diff in record is not a valid unified diff
    referencing the found line (quality gate).
    """
    diff = _clean_diff(record.diff)
    if not diff.startswith("---"):
        return None

    # Verify the diff actually covers the finding's line region
    hunk_lines = [int(m.group(1)) for m in re.finditer(r"^@@ -(\d+)", diff, re.MULTILINE)]
    if hunk_lines and not any(abs(h - finding.line_start) <= 15 for h in hunk_lines):
        return None  # diff doesn't address the finding — skip

    context_block = _build_context_block(record.code_before, finding)

    user_content = (
        f"Finding: {finding.rule_id}"
        + (f"  CWE: {finding.cwe_id}" if finding.cwe_id else "")
        + f"\nFile: {record.filename}  Line: {finding.line_start}\n"
        f"Description: {finding.message}\n\n"
        f"Affected code (>>> marks the vulnerable line):\n{context_block}\n\n"
        f"Generate the unified diff.\n"
        f"The diff header must be:\n"
        f"--- a/{record.filename}\n"
        f"+++ b/{record.filename}"
    )

    pair_id = hashlib.sha256(
        f"{record.cve_id}{record.filename}{finding.line_start}".encode()
    ).hexdigest()[:12]

    return {
        "id": f"{record.cve_id}-{pair_id}",
        "messages": [
            {"role": "system",    "content": _SYSTEM_PATCH},
            {"role": "user",      "content": user_content},
            {"role": "assistant", "content": diff},
        ],
        "metadata": {
            "cve_id":      record.cve_id,
            "cwe_id":      record.cwe_id,
            "rule_id":     finding.rule_id,
            "severity":    finding.severity,
            "confidence":  finding.confidence,
            "diff_lines":  record.diff_size,
            "filename":    record.filename,
            "repo_url":    record.repo_url,
        },
    }


def write_jsonl(examples: list[dict], out_path: Path) -> None:
    """Write examples to a JSONL file, one object per line."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")


def write_metadata_csv(examples: list[dict], out_path: Path) -> None:
    """Write a flat CSV of metadata fields for quick analysis."""
    import csv
    if not examples:
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["id"] + list(examples[0]["metadata"].keys())
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for ex in examples:
            row = {"id": ex["id"]}
            row.update(ex["metadata"])
            w.writerow(row)
