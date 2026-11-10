"""
Build the v3 training dataset by adding ivitopow/SecuCoder to the existing
training_pairs_final.jsonl, then saving as training_pairs_v3.jsonl.

Usage:
  uv run python -m benchmarks.training_data.build_v3_dataset

Outputs:
  benchmarks/results/training_pairs_v3.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

EXISTING = Path("benchmarks/results/training_pairs_final.jsonl")
OUT      = Path("benchmarks/results/training_pairs_v3.jsonl")
SECURECODER = "ivitopow/SecuCoder"


def _load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def main() -> None:
    from benchmarks.training_data.extract import load_from_huggingface
    from benchmarks.training_data.format_dataset import format_cve_pair, write_jsonl

    print(f"Loading existing pairs from {EXISTING} …")
    existing = _load_jsonl(EXISTING)
    existing_ids = {r["id"] for r in existing}
    print(f"  {len(existing)} existing pairs, {len(existing_ids)} unique IDs")

    print(f"\nLoading {SECURECODER} …")
    new_examples: list[dict] = []
    skipped = 0
    for rec in load_from_huggingface(SECURECODER, split="train"):
        ex = format_cve_pair(rec)
        if ex is None:
            skipped += 1
            continue
        if ex["id"] in existing_ids:
            skipped += 1
            continue
        new_examples.append(ex)
        existing_ids.add(ex["id"])
        if len(new_examples) % 100 == 0:
            print(f"  … {len(new_examples)} new pairs extracted", end="\r", flush=True)

    print(f"\n  {len(new_examples)} new pairs from SecuCoder  ({skipped} skipped)")

    combined = existing + new_examples
    print(f"\nWriting {len(combined)} total pairs to {OUT} …")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(combined, OUT)

    size_mb = OUT.stat().st_size / 1024 / 1024
    print(f"Done. {OUT}  ({size_mb:.1f} MB)")
    print(f"\nTo train v3 run:")
    print(f"  uv run python -m benchmarks.training_data.train_qlora \\")
    print(f"    --data {OUT} \\")
    print(f"    --output models/sentinel-coder-v3 \\")
    print(f"    --epochs 3 --max-seq 768")


if __name__ == "__main__":
    main()
