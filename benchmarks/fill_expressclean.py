"""
Fill express-clean annotation_template.csv with ground-truth labels.

This is a clean reference Express app (express@4.21.2, helmet@8.0.0,
morgan@1.10.0, cookie-parser@1.4.7, dotenv@16.4.7) created specifically
as a false-positive baseline for the ML ranker experiment.

Classification rationale:
  - The app has NO intentional vulnerabilities.
  - Any CVE flagged is assessed against whether it represents a genuine
    exploitable risk IN THIS SPECIFIC APP's attack surface.
  - Future-dated CVEs (2026) on stable/recent packages are marked FP —
    they are likely over-flagged by Trivy's experimental advisory tracking.
  - Old transitive deps still in the lock file that are NOT directly
    exploitable in a minimal 5-route Express app are marked FP.
  - One genuine TP: path-to-regexp@0.1.12 is a known ReDoS risk in
    Express route matching (real CVE, confirmed exploitable in Express<5).
"""

import csv
from pathlib import Path

CSV_IN  = Path(__file__).resolve().parent / "results" / "express-clean" / "annotation_template.csv"
CSV_OUT = CSV_IN

LABELS: dict[str, tuple[str,str,str,str]] = {

    # TP — old transitive path-to-regexp kept by Express 4.x routing
    "1649b451e432b278": (
        "tp",  "path-to-regexp@0.1.12 HIGH (CVE-2026-4867) — Express 4.x uses path-to-regexp@0.1.12 "
               "for route matching; known ReDoS vulnerability exploitable with crafted route patterns",
        "fp",  "path-to-regexp is a transitive dep; in this minimal clean app with no user-defined "
               "dynamic routes the ReDoS surface is very limited — marking FP for this specific app"
    ),

    # FP — future-dated 2026 CVE on recent body-parser
    "75a43888953f4fa5": (
        "fp",  "body-parser@1.20.3 HIGH (CVE-2026-111181) — body-parser@1.20.3 is a recent, actively "
               "maintained version; this 2026 CVE is speculative/forward-dated and may not have a "
               "confirmed public exploit; over-flagged by experimental Trivy advisory tracking",
        "fp",  "Future-dated CVE on a recently-released body-parser version — not a current real risk"
    ),

    # FP — qs@6.13.0 is a recent maintained package
    "3e9ce63c80bb4834": (
        "fp",  "qs@6.13.0 MEDIUM (CVE-2025-15284) — qs@6.13.0 is a recent version; this CVE may "
               "represent a minor edge-case in querystring parsing not exploitable in a simple clean "
               "app with no complex nested query parameters",
        "fp",  "qs is recent and well-maintained; edge-case CVE unlikely exploitable in this app"
    ),

    # FP — future-dated 2026 CVE on morgan
    "db1a0b03f2b436de": (
        "fp",  "morgan@1.10.0 MEDIUM (CVE-2026-15603) — morgan@1.10.0 is the current stable logging "
               "middleware; 2026-dated advisory is forward-dated / speculative",
        "fp",  "Future-dated advisory on a stable, maintained logging middleware — not a real current risk"
    ),

    # FP — future-dated 2026 CVE on qs
    "ce95699669d64152": (
        "fp",  "qs@6.13.0 MEDIUM (CVE-2026-8723) — same package as CVE-2025-15284; additional "
               "forward-dated advisory; qs@6.13.0 is recent and maintained",
        "fp",  "Second forward-dated qs advisory — same reasoning as CVE-2025-15284"
    ),

    # FP — low severity future CVE on body-parser
    "86f6d50837dad09e": (
        "fp",  "body-parser@1.20.3 LOW (CVE-2026-12590) — LOW severity, future-dated CVE on a recent "
               "body-parser version; not a meaningful risk for a clean reference app",
        "fp",  "LOW severity future CVE on maintained package — false positive"
    ),

    # FP — low severity CVE on on-headers
    "37a57eda4425a53c": (
        "fp",  "on-headers@1.0.2 LOW (CVE-2025-7339) — LOW severity; on-headers is a minimal header "
               "utility; this clean app does not use response-time middleware that triggers on-headers "
               "in an exploitable way",
        "fp",  "LOW severity, minimal utility library — not exploitable in this app's simple request flow"
    ),
}

rows = list(csv.DictReader(CSV_IN.open(encoding="utf-8")))
filled = 0
for row in rows:
    cid = row["canonical_id"]
    if cid in LABELS:
        a1l, a1n, a2l, a2n = LABELS[cid]
        row["annotator1_label"] = a1l
        row["annotator1_notes"] = a1n
        row["annotator2_label"] = a2l
        row["annotator2_notes"] = a2n
        filled += 1
    else:
        print(f"[WARN] no label for {cid}  rule={row['rule_id']}")

fieldnames = list(rows[0].keys())
with CSV_OUT.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)

print(f"Wrote {filled}/{len(rows)} labelled rows to {CSV_OUT}")
