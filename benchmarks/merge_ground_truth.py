"""
benchmarks/merge_ground_truth.py — Merge ground truth JSONs from multiple benchmark apps.

Merges:
  benchmarks/results/ground_truth.json          (Juice Shop, Week 17-18)
  benchmarks/results/nodegoat/ground_truth.json (OWASP NodeGoat, Week 19-21)
  benchmarks/results/express-clean/ground_truth.json (clean reference app)

Output: benchmarks/results/combined_ground_truth.json

Usage:
    python -m benchmarks.merge_ground_truth
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

_ROOT = Path(__file__).resolve().parent


def main() -> None:
    results = _ROOT / "results"
    sources = [
        ("juice-shop",    results / "ground_truth.json"),
        ("nodegoat",      results / "nodegoat" / "ground_truth.json"),
        ("express-clean", results / "express-clean" / "ground_truth.json"),
    ]

    combined: list[dict] = []
    seen: set[str] = set()

    for source, p in sources:
        if not p.exists():
            print(f"[WARN] {p} not found — skipped", file=sys.stderr)
            continue
        records = json.loads(p.read_text(encoding="utf-8"))
        for r in records:
            cid = r["canonical_id"]
            key = f"{source}:{cid}"
            if key not in seen:
                r["source_app"] = source
                combined.append(r)
                seen.add(key)

    labels = Counter(r["consensus_label"] for r in combined)
    print(f"Combined: {len(combined)} findings")
    print(f"  TP={labels['tp']}  FP={labels['fp']}  skip={labels['skip']}")
    print(f"  FP rate: {labels['fp'] / max(len(combined), 1) * 100:.1f}%")

    out = results / "combined_ground_truth.json"
    out.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    print(f"Saved -> {out}")


if __name__ == "__main__":
    main()
