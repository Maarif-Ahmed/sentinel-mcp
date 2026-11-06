"""
CVEfixes loader — yields Python vulnerability/fix pairs.

Supports two sources:
  --source sqlite   path to CVEfixes.db (canonical, ~2 GB)
  --source hf       HuggingFace dataset (default: "bstee615/cvefixes")

CVEfixes schema (v1.0.7):
  commits      : hash, repo_url, description
  cve_descriptions : CVE_ID, description, severity, cwe_id
  file_changes : hash, filename, old_path, new_path, change_type,
                 diff, code_before, code_after, programming_language,
                 num_lines_added, num_lines_deleted

Download the SQLite file from:
  https://github.com/secureIT-project/CVEfixes/releases
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Data record
# ---------------------------------------------------------------------------

@dataclass
class PairRecord:
    cve_id: str
    cwe_id: str | None
    filename: str               # original filename from the commit
    code_before: str            # vulnerable file / function content
    code_after: str             # fixed file / function content
    diff: str                   # unified diff (from CVEfixes or recomputed)
    commit_message: str = ""
    repo_url: str = ""
    num_lines_added: int = 0
    num_lines_deleted: int = 0

    @property
    def diff_size(self) -> int:
        return self.num_lines_added + self.num_lines_deleted


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

_PYTHON_EXTENSIONS = {".py"}

# CWEs that Bandit can reliably detect — used to prioritise, not to hard-filter
BANDIT_DETECTABLE_CWES = {
    "CWE-78",   # OS command injection → B602-B607
    "CWE-89",   # SQL injection → B608
    "CWE-259",  # Hardcoded password → B105-B107
    "CWE-321",  # Hardcoded key → B105-B107
    "CWE-502",  # Unsafe deserialization → B301-B303
    "CWE-676",  # Dangerous function → B308 etc.
    "CWE-327",  # Weak crypto → B303-B306
    "CWE-330",  # Weak PRNG → B311
    "CWE-611",  # XML external entity → B405-B408
    "CWE-22",   # Path traversal → B306-related
}

MIN_DIFF_LINES = 1
MAX_DIFF_LINES = 60   # avoid massive refactors
MIN_CODE_CHARS = 50   # skip trivial stubs


def _is_python(filename: str) -> bool:
    return Path(filename).suffix.lower() in _PYTHON_EXTENSIONS


def _diff_line_count(diff: str) -> int:
    return sum(1 for l in diff.splitlines() if l.startswith(("+", "-"))
               and not l.startswith(("---", "+++")))


def _record_ok(rec: PairRecord) -> bool:
    if not rec.code_before or not rec.code_after:
        return False
    if len(rec.code_before) < MIN_CODE_CHARS:
        return False
    if not rec.diff:
        return False
    n = _diff_line_count(rec.diff)
    return MIN_DIFF_LINES <= n <= MAX_DIFF_LINES


# ---------------------------------------------------------------------------
# SQLite loader
# ---------------------------------------------------------------------------

def load_from_sqlite(db_path: Path, limit: int = 0) -> Iterator[PairRecord]:
    """
    Yield PairRecord objects from a local CVEfixes SQLite database.

    limit=0 means no limit.
    """
    db_path = Path(db_path)
    if not db_path.exists():
        raise FileNotFoundError(f"CVEfixes database not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Discover available table/column names (schema varies slightly by release)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r["name"] for r in cur.fetchall()}

    cve_table = "cve_descriptions" if "cve_descriptions" in tables else "cve_description"

    query = f"""
        SELECT
            fc.filename,
            fc.diff,
            fc.code_before,
            fc.code_after,
            fc.programming_language,
            COALESCE(fc.num_lines_added, 0)   AS lines_added,
            COALESCE(fc.num_lines_deleted, 0) AS lines_deleted,
            c.repo_url,
            c.description  AS commit_msg,
            cd.CVE_ID      AS cve_id,
            cd.cwe_id
        FROM file_changes fc
        JOIN commits c ON fc.hash = c.hash
        LEFT JOIN {cve_table} cd ON c.cve_id = cd.CVE_ID
        WHERE fc.change_type = 'MODIFY'
          AND (
              fc.programming_language = 'Python'
              OR LOWER(fc.filename) LIKE '%.py'
          )
          AND fc.code_before IS NOT NULL
          AND fc.code_after  IS NOT NULL
          AND fc.diff        IS NOT NULL
          AND LENGTH(fc.code_before) > {MIN_CODE_CHARS}
    """
    if limit:
        query += f" LIMIT {limit}"

    cur.execute(query)
    for row in cur:
        rec = PairRecord(
            cve_id=row["cve_id"] or "UNKNOWN",
            cwe_id=row["cwe_id"],
            filename=row["filename"],
            code_before=row["code_before"],
            code_after=row["code_after"],
            diff=row["diff"],
            commit_message=row["commit_msg"] or "",
            repo_url=row["repo_url"] or "",
            num_lines_added=int(row["lines_added"] or 0),
            num_lines_deleted=int(row["lines_deleted"] or 0),
        )
        if _record_ok(rec):
            yield rec

    conn.close()


# ---------------------------------------------------------------------------
# HuggingFace loader
# ---------------------------------------------------------------------------

def load_from_huggingface(
    dataset_name: str = "bstee615/cvefixes",
    split: str = "train",
    limit: int = 0,
) -> Iterator[PairRecord]:
    """
    Yield PairRecord objects from a HuggingFace dataset.

    Known working datasets:
      bstee615/cvefixes       — mirrors the SQLite schema as Arrow tables
      mootez-saad/CVEfixes-10K — 10k Python-only subset

    Install: pip install datasets
    """
    try:
        from datasets import load_dataset  # type: ignore[import]
    except ImportError as e:
        raise RuntimeError(
            "HuggingFace datasets not installed. "
            "Run: pip install datasets"
        ) from e

    ds = load_dataset(dataset_name, split=split, streaming=True)
    count = 0
    for row in ds:
        if limit and count >= limit:
            break

        # --- Schema normalisation ---
        # hitoshura25/cvefixes: file_paths is a list; code fields use different names
        file_paths = row.get("file_paths")
        if isinstance(file_paths, list):
            # Pick first Python file from the list; skip row if none
            py_files = [f for f in file_paths if _is_python(f)]
            if not py_files:
                continue
            filename = py_files[0]
            # Filter: row-level language field must be Python too
            if row.get("language", "").lower() not in ("python", ""):
                continue
        else:
            filename = row.get("filename") or row.get("file_name") or ""
            if not _is_python(filename):
                continue

        diff = (
            row.get("diff_with_context")
            or row.get("diff")
            or ""
        )
        code_before = (
            row.get("code_before")
            or row.get("before")
            or row.get("vulnerable_code")
            or ""
        )
        code_after = (
            row.get("code_after")
            or row.get("after")
            or row.get("fixed_code")
            or ""
        )
        rec = PairRecord(
            cve_id=row.get("cve_id") or row.get("CVE_ID") or "UNKNOWN",
            cwe_id=row.get("cwe_id") or row.get("CWE_ID"),
            filename=filename,
            code_before=code_before,
            code_after=code_after,
            diff=diff,
            commit_message=row.get("commit_message") or row.get("description") or "",
            repo_url=row.get("repo_url") or "",
            num_lines_added=int(row.get("num_lines_added") or 0),
            num_lines_deleted=int(row.get("num_lines_deleted") or 0),
        )
        if _record_ok(rec):
            yield rec
            count += 1
