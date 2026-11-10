"""
benchmarks/label.py — interactive TP/FP labelling.

Walks the annotation template one finding at a time, showing the source
around the flagged line together with its route context, and writes the
chosen label straight back to the CSV. Progress is saved after every answer,
so the session can be stopped and resumed.

Usage:
    python -m benchmarks.label --csv benchmarks/results/flask-vulnerable/annotation_template.csv
    python -m benchmarks.label --csv ... --annotator 2
    python -m benchmarks.label --csv ... --review      # revisit answered rows

Labels:
    tp    the finding identifies a real vulnerability
    fp    the pattern is flagged but is not a vulnerability here
    skip  out of scope or not assessable
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

_VALID = {"t": "tp", "f": "fp", "s": "skip"}
_CONTEXT_LINES = 6


def _load(csv_path: Path) -> tuple[list[dict], list[str]]:
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader), list(reader.fieldnames or [])


def _save(csv_path: Path, rows: list[dict], fields: list[str]) -> None:
    # Write beside the target then replace, so an interrupted write cannot
    # truncate labels already recorded.
    tmp = csv_path.with_suffix(csv_path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, csv_path)


def _repo_root(csv_path: Path, explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    scan = csv_path.parent / "scan_results.json"
    if not scan.exists():
        return None
    try:
        meta = json.loads(scan.read_text(encoding="utf-8")).get("meta", {})
        return Path(meta["repo"]) if meta.get("repo") else None
    except (json.JSONDecodeError, OSError):
        return None


def _snippet(repo: Path | None, file_path: str, line_start: str) -> str:
    if repo is None:
        return "  (source unavailable — pass --repo to show code)"
    try:
        target = repo / file_path
        if not target.is_file():
            return f"  (not found: {file_path})"
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        focus = int(line_start)
    except (OSError, ValueError):
        return "  (source unavailable)"

    start = max(0, focus - 1 - _CONTEXT_LINES)
    end = min(len(lines), focus + _CONTEXT_LINES)
    out = []
    for idx in range(start, end):
        marker = ">>" if idx + 1 == focus else "  "
        out.append(f"  {marker} {idx + 1:4d} | {lines[idx]}")
    return "\n".join(out)


def _show(
    row: dict,
    position: int,
    total: int,
    repo: Path | None,
    label_col: str | None = None,
    notes_col: str | None = None,
) -> None:
    print("\n" + "=" * 72)
    print(f"  [{position}/{total}]  {row['rule_id']}  {row['cwe_id'] or 'no CWE'}"
          f"   ({row['scanner']})")
    print("=" * 72)
    print(f"  {row['file_path']}:{row['line_start']}")
    print(f"  severity={row['severity']}  confidence={row['confidence']}"
          f"  ranked={row['ranked_severity']}  score={row['score']}")
    if row.get("route_path"):
        print(f"  route     : {row['route_path']}  [{row.get('http_methods', '')}]")
        print(f"  middleware: {row.get('middleware_names') or '(none)'}")
    else:
        print("  route     : (not attributable)")
    print()
    print(f"  {row['message'][:400]}")
    print()
    print(_snippet(repo, row["file_path"], row["line_start"]))

    # In review, the existing answer and its reasoning have to be visible —
    # otherwise the reviewer is re-deciding blind rather than checking.
    existing = row.get(label_col, "").strip() if label_col else ""
    if existing:
        print()
        print(f"  existing label : {existing.upper()}")
        note = row.get(notes_col, "").strip() if notes_col else ""
        if note:
            print(f"  reasoning      : {note}")


def run(
    csv_path: Path,
    annotator: str,
    repo: Path | None,
    review: bool,
    scanner: str | None = None,
) -> None:
    rows, fields = _load(csv_path)
    if not rows:
        print("[ERROR] no rows in template", file=sys.stderr)
        sys.exit(1)

    label_col = f"{annotator}_label"
    notes_col = f"{annotator}_notes"
    reviewed_col = f"{annotator}_reviewed"

    # Per-row evidence that a human actually looked at this finding. A
    # provenance flag passed on the command line asserts review; this
    # records it, so the claim can be checked instead of trusted.
    if reviewed_col not in fields:
        fields.append(reviewed_col)
        for r in rows:
            r.setdefault(reviewed_col, "")
    if label_col not in fields:
        print(f"[ERROR] column {label_col!r} not in template", file=sys.stderr)
        sys.exit(1)

    targets = [
        i for i, r in enumerate(rows)
        if (review or not r.get(label_col, "").strip())
        and (scanner is None or r.get("scanner") == scanner)
    ]
    if not targets:
        done = sum(1 for r in rows if r.get(label_col, "").strip())
        scope = f" from {scanner}" if scanner else ""
        print(f"Nothing to do{scope}: {done}/{len(rows)} rows labelled by {annotator}.")
        print("Pass --review to revisit answered rows.")
        return

    print(f"Labelling as {annotator} — {len(targets)} row(s) to go.")
    print("  t = tp    f = fp    s = skip    n = note    b = back    q = save & quit")

    pos = 0
    while 0 <= pos < len(targets):
        idx = targets[pos]
        row = rows[idx]
        _show(row, pos + 1, len(targets), repo, label_col, notes_col)

        current = row.get(label_col, "").strip()
        prompt = (f"\n  keep {current.upper()} (enter) or t/f/s > "
                  if current else "\n  label > ")
        try:
            answer = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nStopped. Progress saved.")
            break

        if answer == "q":
            print("Saved.")
            break
        if answer == "b":
            pos = max(0, pos - 1)
            continue
        if answer == "n":
            try:
                row[notes_col] = input("  note > ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            _save(csv_path, rows, fields)
            continue
        if answer in _VALID:
            chosen = _VALID[answer]
            if current and chosen != current:
                # The old reasoning argued for the old label; keeping it
                # attached to a different answer would misrepresent both.
                row[notes_col] = f"[revised from {current}] "
            row[label_col] = chosen
            row[reviewed_col] = "y"
            _save(csv_path, rows, fields)
            pos += 1
            continue
        if answer == "" and current:
            row[reviewed_col] = "y"
            _save(csv_path, rows, fields)
            pos += 1
            continue
        print("  ? expected t, f, s, n, b or q")

    _save(csv_path, rows, fields)
    done = sum(1 for r in rows if r.get(label_col, "").strip())
    print(f"\n{annotator}: {done}/{len(rows)} labelled → {csv_path}")


def main() -> None:
    p = argparse.ArgumentParser(description="Interactive TP/FP labelling")
    p.add_argument("--csv", required=True, help="Path to annotation_template.csv")
    p.add_argument("--annotator", default="1", choices=["1", "2"],
                   help="Which annotator column to fill (default: 1)")
    p.add_argument("--repo", default=None,
                   help="Target repo root (default: read from scan_results.json)")
    p.add_argument("--review", action="store_true",
                   help="Revisit rows that already have a label")
    p.add_argument("--scanner", default=None,
                   help="Only walk rows from this scanner, e.g. bandit")
    args = p.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"[ERROR] {csv_path} not found", file=sys.stderr)
        sys.exit(1)

    run(csv_path, f"annotator{args.annotator}", _repo_root(csv_path, args.repo),
        args.review, args.scanner)


if __name__ == "__main__":
    main()
