"""
benchmarks/merge_ground_truth.py — Combine ground truth from several targets.

Each target is annotated on its own, then merged here so the ranking
experiment can run over more than one application. A finding's identity is
(source, canonical_id, rule_id): canonical_id is file+line+CWE, so two
distinct rules at one location share it and keying on it alone silently
drops one of them.

Usage:
    python -m benchmarks.merge_ground_truth
    python -m benchmarks.merge_ground_truth --source flask=results/flask-vulnerable/ground_truth.json
    python -m benchmarks.merge_ground_truth --out results/combined_ground_truth.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_RESULTS = _ROOT / "results"

# Targets merged when no --source is given.
_DEFAULT_SOURCES = [
    ("flask-vulnerable", _RESULTS / "flask-vulnerable" / "ground_truth.json"),
    ("fastapi-vulnerable", _RESULTS / "fastapi-vulnerable" / "ground_truth.json"),
    ("juice-shop", _RESULTS / "ground_truth.json"),
    ("nodegoat", _RESULTS / "nodegoat" / "ground_truth.json"),
    ("express-clean", _RESULTS / "express-clean" / "ground_truth.json"),
]


def _parse_sources(raw: list[str] | None) -> list[tuple[str, Path]]:
    if not raw:
        return _DEFAULT_SOURCES
    out = []
    for item in raw:
        if "=" not in item:
            print(f"[ERROR] --source expects NAME=PATH, got {item!r}", file=sys.stderr)
            sys.exit(1)
        name, path = item.split("=", 1)
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = _ROOT / candidate
        out.append((name, candidate))
    return out


def main() -> None:
    p = argparse.ArgumentParser(description="Merge per-target ground truth files")
    p.add_argument("--source", action="append", metavar="NAME=PATH",
                   help="A target to merge; repeatable. Defaults to all known targets.")
    p.add_argument("--out", default=str(_RESULTS / "combined_ground_truth.json"))
    args = p.parse_args()

    combined: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    per_source: dict[str, Counter] = {}
    modes: Counter = Counter()

    for source, path in _parse_sources(args.source):
        if not path.exists():
            print(f"[skip] {source}: {path} not found")
            continue
        records = json.loads(path.read_text(encoding="utf-8"))
        counts: Counter = Counter()
        for record in records:
            key = (source, record["canonical_id"], record.get("rule_id", ""))
            if key in seen:
                continue
            seen.add(key)
            record["source_app"] = source
            combined.append(record)
            counts[record["consensus_label"]] += 1
            modes[record.get("annotation_mode", "unspecified")] += 1
        per_source[source] = counts
        print(f"[ok]   {source}: {sum(counts.values())} findings "
              f"(tp={counts['tp']} fp={counts['fp']} skip={counts['skip']})")

    if not combined:
        print("[ERROR] nothing merged", file=sys.stderr)
        sys.exit(1)

    labels = Counter(r["consensus_label"] for r in combined)
    usable = labels["tp"] + labels["fp"]
    print()
    print(f"Combined: {len(combined)} findings from {len(per_source)} target(s)")
    print(f"  tp={labels['tp']}  fp={labels['fp']}  skip={labels['skip']}")
    if usable:
        base = max(labels["tp"], labels["fp"]) / usable
        print(f"  base rate: {base:.3f}")
        if base >= 0.9:
            print("  [WARN] Precision@K has little headroom at this base rate.")
    routed = sum(1 for r in combined if r.get("route_path"))
    print(f"  with route context: {routed}")

    # Provenance does not survive on its own — a merged file that mixes
    # AI-drafted and human labels has to say so.
    print(f"  annotation modes: {dict(modes)}")
    if len(modes) > 1:
        print("  [NOTE] Targets were annotated differently; report the mix,")
        print("         not a single provenance for the combined dataset.")

    out = Path(args.out)
    if not out.is_absolute():
        out = _ROOT / out
    out.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    print(f"\nSaved → {out}")


if __name__ == "__main__":
    main()
