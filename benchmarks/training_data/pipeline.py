"""
CVEfixes → QLoRA training data pipeline.

Usage
-----
# From SQLite (download CVEfixes.db first):
  python -m benchmarks.training_data.pipeline \\
      --source sqlite --db path/to/CVEfixes.db \\
      --output benchmarks/results/training_pairs.jsonl

# From HuggingFace (requires: pip install datasets):
  python -m benchmarks.training_data.pipeline \\
      --source hf --dataset bstee615/cvefixes \\
      --output benchmarks/results/training_pairs.jsonl

# Quick dry-run with synthetic examples (no download needed):
  python -m benchmarks.training_data.pipeline --source demo

Options
-------
  --limit N       stop after N candidates (default: unlimited)
  --target N      stop after N accepted pairs (default: 5000)
  --output PATH   JSONL output path
  --no-gate       skip Bandit quality gate (faster, lower quality)
  --verbose       print each accepted/rejected decision

Pipeline steps
--------------
1. Load records from CVEfixes (SQLite or HuggingFace)
2. Filter: Python files, diff 1-60 lines (extract.py)
3. Bandit quality gate: fires on before, silent on after (scan.py)
4. Format as instruction pairs (format_dataset.py)
5. Write JSONL + metadata CSV
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Demo / synthetic pairs (no download needed — for pipeline smoke test)
# ---------------------------------------------------------------------------

_DEMO_PAIRS = [
    {
        "cve_id": "DEMO-001",
        "cwe_id": "CWE-89",
        "filename": "views.py",
        "code_before": (
            "import sqlite3\n\n"
            "def get_user(user_id):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    query = 'SELECT * FROM users WHERE id = %s' % user_id\n"
            "    return conn.execute(query).fetchone()\n"
        ),
        "code_after": (
            "import sqlite3\n\n"
            "def get_user(user_id):\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    query = 'SELECT * FROM users WHERE id = ?'\n"
            "    return conn.execute(query, (user_id,)).fetchone()\n"
        ),
        "diff": (
            "--- a/views.py\n+++ b/views.py\n"
            "@@ -5,1 +5,2 @@\n"
            "-    query = 'SELECT * FROM users WHERE id = %s' % user_id\n"
            "-    return conn.execute(query).fetchone()\n"
            "+    query = 'SELECT * FROM users WHERE id = ?'\n"
            "+    return conn.execute(query, (user_id,)).fetchone()\n"
        ),
    },
    {
        "cve_id": "DEMO-002",
        "cwe_id": "CWE-259",
        "filename": "config.py",
        "code_before": (
            "import os\n\n"
            "DB_PASSWORD = 'supersecret123'\n"
            "DEBUG = True\n"
        ),
        "code_after": (
            "import os\n\n"
            "DB_PASSWORD = os.environ['DB_PASSWORD']\n"
            "DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'\n"
        ),
        "diff": (
            "--- a/config.py\n+++ b/config.py\n"
            "@@ -3,1 +3,1 @@\n"
            "-DB_PASSWORD = 'supersecret123'\n"
            "+DB_PASSWORD = os.environ['DB_PASSWORD']\n"
        ),
    },
    {
        "cve_id": "DEMO-003",
        "cwe_id": "CWE-78",
        "filename": "utils.py",
        "code_before": (
            "import subprocess\n\n"
            "def run_cmd(user_input):\n"
            "    cmd = 'ls ' + user_input\n"
            "    result = subprocess.run(cmd, shell=True, capture_output=True)\n"
            "    return result.stdout\n"
        ),
        "code_after": (
            "import subprocess\n\n"
            "def run_cmd(user_input):\n"
            "    result = subprocess.run(['ls', user_input], capture_output=True)\n"
            "    return result.stdout\n"
        ),
        "diff": (
            "--- a/utils.py\n+++ b/utils.py\n"
            "@@ -4,2 +4,1 @@\n"
            "-    cmd = 'ls ' + user_input\n"
            "-    result = subprocess.run(cmd, shell=True, capture_output=True)\n"
            "+    result = subprocess.run(['ls', user_input], capture_output=True)\n"
        ),
    },
]


def _load_demo():
    from benchmarks.training_data.extract import PairRecord
    for d in _DEMO_PAIRS:
        yield PairRecord(
            cve_id=d["cve_id"],
            cwe_id=d["cwe_id"],
            filename=d["filename"],
            code_before=d["code_before"],
            code_after=d["code_after"],
            diff=d["diff"],
        )


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run(
    source: str,
    db_path: Path | None,
    hf_dataset: str,
    output_path: Path,
    limit: int,
    target: int,
    use_gate: bool,
    skip_bandit: bool,
    verbose: bool,
) -> None:
    from benchmarks.training_data.extract import load_from_sqlite, load_from_huggingface
    from benchmarks.training_data.scan import passes_quality_gate
    from benchmarks.training_data.format_dataset import (
        format_instruction_pair, format_cve_pair, write_jsonl, write_metadata_csv
    )

    # 1 — Source
    if source == "demo":
        records = _load_demo()
        print("Demo mode: using 3 synthetic pairs (no download needed).")
    elif source == "sqlite":
        if not db_path:
            print("ERROR: --db is required for --source sqlite", file=sys.stderr)
            sys.exit(1)
        records = load_from_sqlite(db_path, limit=limit)
        print(f"Loading from SQLite: {db_path}")
    else:  # hf
        records = load_from_huggingface(hf_dataset, limit=limit)
        print(f"Loading from HuggingFace: {hf_dataset}")

    # 2 — Process
    accepted: list[dict] = []
    seen = 0
    skipped_no_bandit = 0
    skipped_no_format = 0
    t0 = time.time()

    for record in records:
        seen += 1
        if target and len(accepted) >= target:
            break

        if skip_bandit:
            # Accept all CVE-fix pairs; validate diff format only
            example = format_cve_pair(record)
            if example is None:
                skipped_no_format += 1
                if verbose:
                    print(f"  SKIP (bad diff): {record.cve_id} {record.filename}")
                continue
        else:
            if use_gate:
                ok, findings = passes_quality_gate(
                    record.code_before, record.code_after, record.filename
                )
            else:
                from benchmarks.training_data.scan import scan_snippet
                findings = scan_snippet(record.code_before, record.filename)
                ok = bool(findings)

            if not ok or not findings:
                skipped_no_bandit += 1
                if verbose:
                    print(f"  SKIP (no bandit finding): {record.cve_id} {record.filename}")
                continue

            # Use the first (highest severity) finding as the training target
            findings.sort(key=lambda f: (
                {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.severity, 3),
                {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.confidence, 3),
            ))
            example = format_instruction_pair(record, findings[0])
            if example is None:
                skipped_no_format += 1
                if verbose:
                    print(f"  SKIP (diff/format mismatch): {record.cve_id} {record.filename}")
                continue

        accepted.append(example)
        if verbose or len(accepted) % 100 == 0:
            elapsed = time.time() - t0
            rate = seen / elapsed if elapsed > 0 else 0
            rule = findings[0].rule_id if not skip_bandit and findings else example["metadata"]["rule_id"]
            print(
                f"  [{len(accepted):>5} accepted / {seen:>6} seen]  "
                f"{record.cve_id}  {rule}  {record.filename}"
                f"  ({rate:.1f} rec/s)"
            )

    # 3 — Write output
    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s:")
    print(f"  Candidates seen    : {seen}")
    if not skip_bandit:
        print(f"  No Bandit finding  : {skipped_no_bandit}")
    print(f"  Diff format mismatch: {skipped_no_format}")
    print(f"  Accepted pairs     : {len(accepted)}")

    if accepted:
        write_jsonl(accepted, output_path)
        csv_path = output_path.with_suffix(".csv")
        write_metadata_csv(accepted, csv_path)
        print(f"\nOutput:")
        print(f"  JSONL    : {output_path}  ({output_path.stat().st_size // 1024} KB)")
        print(f"  Metadata : {csv_path}")

        # Rule distribution
        from collections import Counter
        rules = Counter(ex["metadata"]["rule_id"] for ex in accepted)
        cwes  = Counter(ex["metadata"]["cwe_id"]  for ex in accepted)
        print(f"\nTop Bandit rules  : {rules.most_common(8)}")
        print(f"Top CWEs          : {cwes.most_common(8)}")
    else:
        print("\nNo pairs accepted — nothing written.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build QLoRA training data from CVEfixes."
    )
    parser.add_argument(
        "--source", choices=["sqlite", "hf", "demo"], default="demo",
        help="Data source: sqlite (local DB), hf (HuggingFace), demo (synthetic test)",
    )
    parser.add_argument("--db",      type=Path, default=None,
                        help="Path to CVEfixes.db (required for --source sqlite)")
    parser.add_argument("--dataset", default="bstee615/cvefixes",
                        help="HuggingFace dataset name (for --source hf)")
    parser.add_argument("--output",  type=Path,
                        default=Path("benchmarks/results/training_pairs.jsonl"))
    parser.add_argument("--limit",   type=int, default=0,
                        help="Max candidates to read (0 = unlimited)")
    parser.add_argument("--target",  type=int, default=5000,
                        help="Stop after this many accepted pairs")
    parser.add_argument("--no-gate", action="store_true",
                        help="Skip Bandit quality gate on code_after (still runs on code_before)")
    parser.add_argument("--skip-bandit", action="store_true",
                        help="Accept all CVE-fix pairs; skip all Bandit scanning (fastest, noisiest)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    run(
        source=args.source,
        db_path=args.db,
        hf_dataset=args.dataset,
        output_path=args.output,
        limit=args.limit,
        target=args.target,
        use_gate=not args.no_gate,
        skip_bandit=args.skip_bandit,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
