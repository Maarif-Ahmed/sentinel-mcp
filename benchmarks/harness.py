"""
benchmarks/harness.py — Sentinel evaluation harness.

Runs the Sentinel scan pipeline against a target repository (default: OWASP
Juice Shop), records every finding and its metadata to JSON, and writes a
CSV annotation template ready for two annotators to fill in TP/FP labels.

Usage:
    python -m benchmarks.harness
    python -m benchmarks.harness --repo "C:\\path\\to\\juice-shop"
    python -m benchmarks.harness --repo ... --out benchmarks/results --scanners trivy
    python -m benchmarks.harness --scanners bandit trivy   # explicit scanner list
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Resolve the src/ package without installing in editable mode every time
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sentinel.orchestrator import ScanOrchestrator
from sentinel.scanners.bandit import BanditAdapter
from sentinel.scanners.trivy import TrivyAdapter

_DEFAULT_REPO = Path(r"C:\Development Work\juice-shop")
_DEFAULT_OUT  = Path(__file__).parent / "results"

_SCANNER_MAP = {
    "bandit": BanditAdapter,
    "trivy":  TrivyAdapter,
}


def _build_scanners(names: list[str]):
    out = []
    for name in names:
        cls = _SCANNER_MAP.get(name)
        if cls is None:
            print(f"[WARN] unknown scanner {name!r} — skipped", file=sys.stderr)
            continue
        adapter = cls()
        if not adapter.is_available():
            print(f"[WARN] scanner {name!r} not available on PATH — skipped", file=sys.stderr)
            continue
        out.append(adapter)
    return out


def run(repo: Path, out_dir: Path, scanner_names: list[str]) -> Path:
    """Run the pipeline and write results. Returns path to the JSON results file."""
    repo = repo.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Repository : {repo}")
    print(f"Scanners   : {scanner_names}")
    print(f"Output dir : {out_dir}")
    print()

    scanners = _build_scanners(scanner_names)
    if not scanners:
        print("[ERROR] no scanners available — aborting.", file=sys.stderr)
        sys.exit(1)

    orchestrator = ScanOrchestrator(scanners=scanners)

    print("Scanning …", flush=True)
    t0 = time.time()
    enriched = orchestrator.scan(repo)
    elapsed = time.time() - t0
    print(f"Done in {elapsed:.1f}s — {len(enriched)} findings\n")

    # ------------------------------------------------------------------ #
    # Build results document                                               #
    # ------------------------------------------------------------------ #
    timestamp = datetime.now(timezone.utc).isoformat()
    results_doc = {
        "meta": {
            "timestamp": timestamp,
            "repo": str(repo),
            "scanners": scanner_names,
            "elapsed_seconds": round(elapsed, 2),
            "finding_count": len(enriched),
        },
        "findings": [ef.to_dict() for ef in enriched],
    }

    json_path = out_dir / "scan_results.json"
    json_path.write_text(json.dumps(results_doc, indent=2), encoding="utf-8")
    print(f"Results saved → {json_path}")

    # ------------------------------------------------------------------ #
    # Write annotation template CSV                                        #
    # ------------------------------------------------------------------ #
    csv_path = out_dir / "annotation_template.csv"
    _FIELDS = [
        "canonical_id", "scanner", "rule_id", "cwe_id",
        "file_path", "line_start", "line_end",
        "severity", "confidence", "ranked_severity", "score",
        "route_path", "http_methods", "middleware_names",
        "message",
        # Annotator 1 (e.g. M4 / Shaheer)
        "annotator1_label",   # tp | fp | skip
        "annotator1_notes",
        # Annotator 2 (e.g. M3 / Marif)
        "annotator2_label",   # tp | fp | skip
        "annotator2_notes",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_FIELDS)
        w.writeheader()
        for ef in enriched:
            fi = ef.finding
            ri = ef.risk
            ct = ef.context
            w.writerow({
                "canonical_id":     fi.canonical_id,
                "scanner":          fi.scanner,
                "rule_id":          fi.rule_id,
                "cwe_id":           fi.cwe_id or "",
                "file_path":        fi.file_path,
                "line_start":       fi.line_start,
                "line_end":         fi.line_end,
                "severity":         fi.severity,
                "confidence":       fi.confidence,
                "ranked_severity":  ri.ranked_severity,
                "score":            round(ri.score, 4),
                "route_path":       ct.route_path or "",
                "http_methods":     "|".join(ct.http_methods),
                "middleware_names":  "|".join(ct.middleware_names),
                "message":          fi.message,
                "annotator1_label":  "",
                "annotator1_notes":  "",
                "annotator2_label":  "",
                "annotator2_notes":  "",
            })

    print(f"Annotation template → {csv_path}")

    # ------------------------------------------------------------------ #
    # Summary by scanner / severity                                        #
    # ------------------------------------------------------------------ #
    print()
    print("─" * 60)
    print(f"{'SEVERITY':<12} {'COUNT':>6}  {'TOP RULE'}")
    print("─" * 60)
    from collections import Counter
    sev_counts: Counter = Counter()
    sev_rules: dict[str, Counter] = {}
    for ef in enriched:
        sev = ef.risk.ranked_severity
        sev_counts[sev] += 1
        sev_rules.setdefault(sev, Counter())[ef.finding.rule_id] += 1
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in sev_counts:
            top = sev_rules[sev].most_common(1)[0][0]
            print(f"{sev:<12} {sev_counts[sev]:>6}  {top}")
    print("─" * 60)
    print(f"{'TOTAL':<12} {len(enriched):>6}")

    return json_path


def main() -> None:
    p = argparse.ArgumentParser(description="Sentinel evaluation harness")
    p.add_argument("--repo", default=str(_DEFAULT_REPO),
                   help="Absolute path to the target repository")
    p.add_argument("--out", default=str(_DEFAULT_OUT),
                   help="Output directory for results and annotation CSV")
    p.add_argument("--scanners", nargs="+", default=["bandit", "trivy"],
                   choices=list(_SCANNER_MAP),
                   help="Scanners to run (default: bandit trivy)")
    args = p.parse_args()

    run(Path(args.repo), Path(args.out), args.scanners)


if __name__ == "__main__":
    main()
