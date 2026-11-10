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


def make_blind(rows: list[dict], csv_path: Path, hide: str, fill: str) -> None:
    """Write a copy with one annotator's columns removed.

    A second annotator who can see the first annotator's answers is not an
    independent judge, and Cohen's κ over two non-independent columns is
    meaningless. Stripping them is what makes the agreement statistic real.
    """
    out_path = csv_path.parent / f"annotation_blind_{fill}.csv"
    drop = {f"{hide}_label", f"{hide}_notes", f"{hide}_reviewed"}
    fields = [f for f in rows[0].keys() if f not in drop]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            blank = {k: r.get(k, "") for k in fields}
            for col in (f"{fill}_label", f"{fill}_notes", f"{fill}_reviewed"):
                blank[col] = ""
            writer.writerow(blank)

    print(f"Blind template → {out_path}")
    print(f"  {hide}'s columns removed; {fill}'s columns blank.")
    print(f"  {len(rows)} findings to annotate.")
    print()
    print("  Hand this file to the second annotator. They run:")
    print(f"    python -m benchmarks.label --csv {out_path} --annotator {fill[-1]}")
    print("  Then merge their answers back with:")
    print(f"    python -m benchmarks.annotate --csv <main csv> --merge-blind {out_path}")


def merge_blind(rows: list[dict], csv_path: Path, blind_path: Path) -> None:
    """Merge a blind annotator's labels back into the main template."""
    if not blind_path.exists():
        print(f"[ERROR] {blind_path} not found", file=sys.stderr)
        sys.exit(1)

    with blind_path.open(encoding="utf-8") as f:
        blind = list(csv.DictReader(f))

    incoming = {
        (r.get("canonical_id", ""), r.get("rule_id", "")): r for r in blind
    }
    fields = list(rows[0].keys())
    merged = 0

    for row in rows:
        src = incoming.get((row.get("canonical_id", ""), row.get("rule_id", "")))
        if src is None:
            continue
        for ann in ("annotator1", "annotator2"):
            label = src.get(f"{ann}_label", "").strip()
            if not label:
                continue
            # Only fill a column the main template has not already answered,
            # so a merge can never quietly overwrite existing annotation.
            if row.get(f"{ann}_label", "").strip():
                continue
            row[f"{ann}_label"] = label
            row[f"{ann}_notes"] = src.get(f"{ann}_notes", "")
            row[f"{ann}_reviewed"] = src.get(f"{ann}_reviewed", "")
            merged += 1

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Merged {merged} label(s) from {blind_path.name} → {csv_path.name}")
    print("Run without --merge-blind to compute Cohen's κ.")


def analyse_single(
    rows: list[dict],
    out_dir: Path,
    annotator: str,
    provenance: str = "human_single",
) -> None:
    """Emit ground truth from one annotator's labels, without κ.

    Inter-rater agreement is undefined for a single annotator, so it is not
    reported rather than being computed against a copied column. The output
    records annotation_mode so the provenance travels with the dataset.
    """
    col = f"{annotator}_label"
    labelled = _labelled_rows(rows, annotator)

    print(f"Annotation mode : {provenance.upper()} ({annotator})")
    print(f"Labelled        : {len(labelled)} / {len(rows)}")
    if not labelled:
        print("[INFO] No labels yet — nothing to write.")
        return

    counts = Counter(_normalise(r[col]) for r in labelled)
    print(f"Labels          : tp={counts['tp']}  fp={counts['fp']}  skip={counts['skip']}")
    print()
    print("[NOTE] Cohen's κ is not computed: it measures agreement between two")
    print("       independent annotators and is undefined for one. Report this")
    print("       dataset as single-annotator and state it as a limitation.")

    if provenance.startswith("ai_"):
        reviewed = sum(
            1 for r in labelled
            if _normalise(r.get(f"{annotator}_reviewed", "")) == "y"
        )
        print()
        if provenance == "ai_draft_reviewed":
            if reviewed < len(labelled):
                # Refuse rather than warn: an overstated provenance claim is
                # worse than no dataset, because it travels into the write-up.
                print(f"[REFUSED] --provenance ai_draft_reviewed claims human review,")
                print(f"          but only {reviewed}/{len(labelled)} rows are marked")
                print(f"          reviewed. Nothing was written.")
                print(f"          Review them first:")
                print(f"            python -m benchmarks.label --csv <csv> --review")
                print(f"          Or record the dataset honestly with:")
                print(f"            --provenance ai_draft_unreviewed")
                return
            print("[PROVENANCE] AI-drafted labels, confirmed row-by-row by a human")
            print("             reviewer. Still a single annotator, so κ does not")
            print("             apply and this is not independent annotation.")
        else:
            print("[PROVENANCE] These labels were drafted by an AI assistant and have")
            print("             NOT been reviewed by a human. They are not independent")
            print("             annotation and must not be reported as such. Review")
            print("             with: python -m benchmarks.label --csv <csv> --review")

    ground_truth = []
    for r in labelled:
        label = _normalise(r[col])
        ground_truth.append({
            "canonical_id":     r["canonical_id"],
            "scanner":          r["scanner"],
            "rule_id":          r["rule_id"],
            "cwe_id":           r.get("cwe_id", ""),
            "file_path":        r["file_path"],
            "line_start":       r["line_start"],
            "severity":         r["severity"],
            "ranked_severity":  r["ranked_severity"],
            "score":            float(r["score"]),
            "route_path":       r.get("route_path", ""),
            "consensus_label":  label,
            "annotation_mode":  provenance,
            "annotated_by":     annotator,
            f"{annotator}_label": label,
            f"{annotator}_notes": r.get(f"{annotator}_notes", ""),
        })

    gt_path = out_dir / "ground_truth.json"
    gt_path.write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")
    tp_count = sum(1 for g in ground_truth if g["consensus_label"] == "tp")
    print(f"\nGround truth saved → {gt_path}")
    print(f"  TP: {tp_count}  FP/skip: {len(ground_truth)-tp_count}")

    if tp_count and len(ground_truth) - tp_count:
        base = max(tp_count, len(ground_truth) - tp_count) / len(ground_truth)
        print(f"  Majority-class base rate: {base:.2f}")
        if base >= 0.9:
            print("  [WARN] Base rate this high leaves Precision@K little headroom.")


def analyse(rows: list[dict], out_dir: Path, provenance: str = "two_human") -> None:
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

    if provenance == "ai_plus_human":
        print()
        print("[PROVENANCE] annotator1 is an AI draft; annotator2 is an independent")
        print("             human. This κ measures AI–human agreement, NOT agreement")
        print("             between two independent human annotators. Say so wherever")
        print("             the figure is reported.")

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
                "annotation_mode": provenance,
                "cohens_kappa":    round(kappa, 4),
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
    p.add_argument("--single-annotator", metavar="N", nargs="?", const="1",
                   choices=["1", "2"],
                   help="Build ground truth from one annotator's labels. "
                        "Cohen's κ is not reported — it is undefined for a "
                        "single annotator.")
    p.add_argument("--provenance", default="human_single",
                   choices=["human_single", "ai_draft_unreviewed", "ai_draft_reviewed",
                            "two_human", "ai_plus_human"],
                   help="How the labels were produced. Recorded in every "
                        "ground-truth row so the origin travels with the data.")
    p.add_argument("--make-blind", metavar="FILL", nargs="?", const="annotator2",
                   choices=["annotator1", "annotator2"],
                   help="Write a copy with the OTHER annotator's columns removed, "
                        "so this one can judge independently.")
    p.add_argument("--merge-blind", metavar="CSV", default=None,
                   help="Merge a completed blind template back into this one.")
    args = p.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"[ERROR] {csv_path} not found", file=sys.stderr)
        sys.exit(1)

    rows = _load(csv_path)
    out_dir = csv_path.parent

    if args.progress:
        progress(rows)
    elif args.make_blind:
        fill = args.make_blind
        hide = "annotator1" if fill == "annotator2" else "annotator2"
        make_blind(rows, csv_path, hide, fill)
    elif args.merge_blind:
        merge_blind(rows, csv_path, Path(args.merge_blind))
    elif args.single_annotator:
        analyse_single(rows, out_dir, f"annotator{args.single_annotator}",
                       args.provenance)
    else:
        mode = args.provenance
        if mode not in ("two_human", "ai_plus_human"):
            mode = "two_human"
        analyse(rows, out_dir, mode)


if __name__ == "__main__":
    main()
