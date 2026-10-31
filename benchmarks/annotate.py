"""
benchmarks/annotate.py — Annotation helpers and inter-rater agreement.

Usage:
    # After both annotators fill in annotation_template.csv:
    python -m benchmarks.annotate --csv benchmarks/results/annotation_template.csv

    # Check progress (how many rows each annotator has filled):
    python -m benchmarks.annotate --csv benchmarks/results/annotation_template.csv --progress

Outputs:
    - Per-annotator label counts
    - Cohen's κ (agreement between annotator1 and annotator2)
    - List of disagreements for resolution
    - benchmarks/results/ground_truth.json  (consensus labels, after κ ≥ 0.6)

Label values (case-insensitive):
    tp    — True positive: finding corresponds to a known Juice Shop vulnerability
    fp    — False positive: finding does not correspond to a real vulnerability
    skip  — Out of scope / not assessable (e.g. minified file, test fixture)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

_VALID_LABELS = {"tp", "fp", "skip"}
_KAPPA_TARGET = 0.6


def _load(csv_path: Path) -> list[dict]:
    with csv_path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _normalise(label: str) -> str:
    return label.strip().lower()


def _labelled_rows(rows: list[dict], annotator: str) -> list[dict]:
    col = f"{annotator}_label"
    return [r for r in rows if _normalise(r.get(col, "")) in _VALID_LABELS]


def cohens_kappa(labels1: list[str], labels2: list[str]) -> float:
    """Compute Cohen's κ for two sequences of categorical labels."""
    if len(labels1) != len(labels2) or not labels1:
        return 0.0

    n = len(labels1)
    categories = sorted(_VALID_LABELS)

    # Observed agreement
    p_o = sum(a == b for a, b in zip(labels1, labels2)) / n

    # Expected agreement
    c1 = Counter(labels1)
    c2 = Counter(labels2)
    p_e = sum((c1[c] / n) * (c2[c] / n) for c in categories)

    if p_e == 1.0:
        return 1.0
    return (p_o - p_e) / (1.0 - p_e)


def progress(rows: list[dict]) -> None:
    a1 = _labelled_rows(rows, "annotator1")
    a2 = _labelled_rows(rows, "annotator2")
    print(f"Total findings  : {len(rows)}")
    print(f"Annotator 1 done: {len(a1)} / {len(rows)}")
    print(f"Annotator 2 done: {len(a2)} / {len(rows)}")


def analyse(rows: list[dict], out_dir: Path) -> None:
    # Find rows where BOTH annotators have filled a label
    both = [
        r for r in rows
        if _normalise(r.get("annotator1_label", "")) in _VALID_LABELS
        and _normalise(r.get("annotator2_label", "")) in _VALID_LABELS
    ]

    if not both:
        print("[INFO] No rows have both annotators' labels yet.")
        progress(rows)
        return

    labels1 = [_normalise(r["annotator1_label"]) for r in both]
    labels2 = [_normalise(r["annotator2_label"]) for r in both]

    kappa = cohens_kappa(labels1, labels2)

    print(f"Jointly annotated: {len(both)} / {len(rows)}")
    print()

    # Per-annotator counts
    for name, lbls in [("Annotator 1", labels1), ("Annotator 2", labels2)]:
        c = Counter(lbls)
        print(f"{name}: tp={c['tp']}  fp={c['fp']}  skip={c['skip']}")
    print()
    print(f"Cohen's κ = {kappa:.3f}  (target ≥ {_KAPPA_TARGET})", end="")
    if kappa >= _KAPPA_TARGET:
        print("  ✓ PASSED")
    else:
        print(f"  ✗ BELOW TARGET — resolve disagreements first")

    # Disagreements
    disagreements = [r for r, l1, l2 in zip(both, labels1, labels2) if l1 != l2]
    if disagreements:
        print(f"\nDisagreements ({len(disagreements)}):")
        print(f"  {'canonical_id':<36}  {'A1':>4}  {'A2':>4}  file_path")
        print(f"  {'-'*36}  {'-'*4}  {'-'*4}  ---------")
        for r in disagreements:
            cid = r["canonical_id"][:36]
            a1 = _normalise(r["annotator1_label"])
            a2 = _normalise(r["annotator2_label"])
            fp = r["file_path"][-60:]
            print(f"  {cid:<36}  {a1:>4}  {a2:>4}  {fp}")
    else:
        print("\nNo disagreements — perfect agreement on all jointly labelled rows.")

    # Write ground truth JSON if κ ≥ target
    if kappa >= _KAPPA_TARGET:
        # Consensus: prefer tp over fp (conservative); skip stays skip
        ground_truth = []
        for r, l1, l2 in zip(both, labels1, labels2):
            if l1 == l2:
                consensus = l1
            elif "tp" in (l1, l2):
                consensus = "tp"   # err on the side of inclusion
            else:
                consensus = "skip"

            ground_truth.append({
                "canonical_id":    r["canonical_id"],
                "scanner":         r["scanner"],
                "rule_id":         r["rule_id"],
                "cwe_id":          r.get("cwe_id", ""),
                "file_path":       r["file_path"],
                "line_start":      r["line_start"],
                "severity":        r["severity"],
                "ranked_severity": r["ranked_severity"],
                "score":           float(r["score"]),
                "route_path":      r.get("route_path", ""),
                "consensus_label": consensus,
                "annotator1_label": l1,
                "annotator2_label": l2,
                "annotator1_notes": r.get("annotator1_notes", ""),
                "annotator2_notes": r.get("annotator2_notes", ""),
            })

        gt_path = out_dir / "ground_truth.json"
        gt_path.write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")
        tp_count = sum(1 for g in ground_truth if g["consensus_label"] == "tp")
        print(f"\nGround truth saved → {gt_path}")
        print(f"  TP: {tp_count}  FP/skip: {len(ground_truth)-tp_count}")
        print(f"\nReady for ML ranker experiment (Week 19–21).")
    else:
        print(f"\nResolve disagreements to raise κ above {_KAPPA_TARGET} before proceeding to ML experiment.")


def main() -> None:
    p = argparse.ArgumentParser(description="Annotation analysis and Cohen's κ")
    p.add_argument("--csv", required=True,
                   help="Path to filled annotation_template.csv")
    p.add_argument("--progress", action="store_true",
                   help="Show completion progress only (no κ calculation)")
    args = p.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"[ERROR] {csv_path} not found", file=sys.stderr)
        sys.exit(1)

    rows = _load(csv_path)
    out_dir = csv_path.parent

    if args.progress:
        progress(rows)
    else:
        analyse(rows, out_dir)


if __name__ == "__main__":
    main()
