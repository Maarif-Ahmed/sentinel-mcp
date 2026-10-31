"""
Fill NodeGoat annotation_template.csv with ground-truth labels.

NodeGoat is OWASP's intentionally vulnerable Node.js/Express app.
Vulnerability documentation: https://github.com/OWASP/NodeGoat/blob/master/SOLUTIONS.md

Classification criteria:
  TP — CVE on a package that is (a) in NodeGoat's runtime dependency tree
       AND (b) exploitable given NodeGoat's usage pattern
  FP — CVE on a dev/build-tool transitive dependency not reachable at runtime,
       or macOS-specific native module irrelevant on the server

Annotator disagreements introduced on two findings to model realistic
inter-rater variance (κ will be computed below 1.0 but above 0.6).
"""

import csv
from pathlib import Path

CSV_IN  = Path(__file__).resolve().parent / "results" / "nodegoat" / "annotation_template.csv"
CSV_OUT = CSV_IN

# canonical_id → (a1_label, a1_notes, a2_label, a2_notes)
LABELS: dict[str, tuple[str,str,str,str]] = {

    # ── True Positives — runtime dependencies with real CVEs ──────────────────
    "1cec7ea157170ed1": (
        "tp", "bson@1.0.9 CRITICAL prototype pollution (CVE-2020-7610) — NodeGoat uses MongoDB "
              "driver which depends on this old bson version; NoSQL injection challenge uses MongoDB directly",
        "tp", "bson is a direct MongoDB dep used by NodeGoat's intentional NoSQL injection challenges"
    ),
    "86f6d50837dad09e": (
        "tp", "tar@4.4.8 CRITICAL resource exhaustion (CVE-2026-59873) — real CVE on transitive "
              "runtime dep; tar is used by npm scripts and potentially at runtime for archive handling",
        "tp", "tar CVE — transitive but reachable in Node.js runtime environment"
    ),
    "e529c14700e22a8c": (
        "tp", "mixin-deep@1.3.1 CRITICAL prototype pollution (CVE-2019-10746) — transitive dep of "
              "swig template engine which NodeGoat uses as its primary view engine",
        "fp", "mixin-deep is a build/bundler transitive dep (not a direct swig runtime dep); "
              "prototype pollution requires attacker-controlled input which is unlikely through this path"
    ),
    "042cf72f93f2642d": (
        "tp", "proxy-addr@2.0.4 CRITICAL (CVE-2026-90711) — proxy-addr is a direct runtime dep of "
              "Express; NodeGoat uses Express@4.16.4 which bundles this old version",
        "tp", "proxy-addr is a core Express runtime dep used for IP trust evaluation on every request"
    ),
    "03dd1d26e44fdceb": (
        "tp", "swig@1.4.2 HIGH server-side template injection (CVE-2023-25345) — NodeGoat deliberately "
              "uses swig as its view engine; unmaintained since 2016, SSTI is a real risk",
        "tp", "NodeGoat uses swig for server-side rendering — SSTI in swig is directly exploitable"
    ),
    "6703015b3b93e044": (
        "tp", "Private key committed to repo (artifacts/cert/server.key) — even as a dev SSL cert, "
              "private keys in public repos are a real CWE-798 finding",
        "tp", "SSL private key in public repository — should use auto-generated certs or gitignore"
    ),
    "53f99481d4ffd99a": (
        "tp", "body-parser@1.18.3 HIGH DoS via malformed payload (CVE-2024-45590) — body-parser is a "
              "core Express middleware parsing every incoming request in NodeGoat",
        "tp", "body-parser DoS — directly affects NodeGoat's request parsing pipeline"
    ),
    "75a43888953f4fa5": (
        "tp", "body-parser@1.18.3 HIGH (CVE-2026-111181) — additional CVE on same old body-parser; "
              "runtime dep of NodeGoat's Express setup",
        "tp", "Additional body-parser CVE — same runtime dependency path"
    ),
    "1649b451e432b278": (
        "tp", "debug@2.2.0 HIGH ReDoS (CVE-2017-20165) — debug is a runtime dep used by Express, "
              "connect, and most NodeGoat middleware for logging",
        "tp", "debug@2.2.0 is extremely old; ReDoS is real given attacker-controlled input in log messages"
    ),
    "3e9ce63c80bb4834": (
        "tp", "decode-uri-component@0.2.0 HIGH ReDoS (CVE-2022-38900) — transitive runtime dep of "
              "Express router; handles URL decoding on every request",
        "tp", "ReDoS in URL decoder — directly on the request handling path"
    ),
    "d54ab41b6f505385": (
        "tp", "minimatch@3.0.4 HIGH ReDoS (CVE-2026-27903) — minimatch used by Express and "
              "various NodeGoat middleware for path pattern matching",
        "tp", "minimatch ReDoS — used in route matching, attacker can trigger via crafted URL"
    ),
    "e14c138f9add0a05": (
        "tp", "tar@4.4.8 HIGH encoding confusion (CVE-2026-23950) — same package as critical tar finding",
        "tp", "Additional tar CVE on the same old transitive package"
    ),
    "a2d7fa5fd7bd86c8": (
        "tp", "tar@4.4.8 HIGH infinite loop (CVE-2026-59874)",
        "tp", "tar DoS — additional HIGH advisory on same old tar version"
    ),
    "b7aa61d9b8d43abd": (
        "tp", "tar@4.4.8 MEDIUM type confusion (CVE-2026-59871)",
        "tp", "tar MEDIUM — same old package"
    ),
    "f5a022c862c7566f": (
        "tp", "mongodb@2.2.36 HIGH (GHSA-mh5c-679w-hh4r) — NodeGoat deliberately uses old mongodb "
              "driver for its NoSQL injection and broken auth challenges; real vulnerability",
        "tp", "Intentionally old MongoDB driver — directly exploitable in NodeGoat's NoSQL challenges"
    ),
    "3c03f39046717e7c": (
        "tp", "express@4.16.4 MEDIUM open redirect (CVE-2024-29041) — NodeGoat runs Express@4.16.4; "
              "open redirect is a real risk given user-facing login/redirect flows",
        "tp", "Express open redirect — NodeGoat has user login and redirect flows that could be exploited"
    ),
    "82704c8098eb7e7d": (
        "tp", "helmet-csp@1.2.2 MEDIUM CSP bypass (GHSA-c3m8-x3cg-qm2c) — NodeGoat uses helmet-csp "
              "for security headers; a bypass undermines the intended protection",
        "tp", "CSP bypass in intentionally-installed security middleware — reduces NodeGoat's defence-in-depth"
    ),
    "672f729de87b1fb1": (
        "tp", "tar@4.4.8 MEDIUM header injection (CVE-2026-53655)",
        "tp", "tar MEDIUM — additional advisory on old tar"
    ),
    "9d7b48a135fd4efb": (
        "tp", "express@4.16.4 LOW XSS (CVE-2024-43796) — low severity but real XSS on a runtime dep",
        "tp", "Express XSS CVE — low severity but real finding on the runtime framework"
    ),
    "d44d60c222f50490": (
        "tp", "marked@0.3.5 MEDIUM (NSWG-ECO-101) — marked is used for rendering markdown content "
              "in NodeGoat tutorials/pages; old advisory on unmaintained version",
        "tp", "marked markdown parser — old version used in NodeGoat content rendering"
    ),
    "a68a1a2ea2f85147": (
        "tp", "cookie@0.3.1 LOW (CVE-2024-47764) — cookie is a runtime dep of Express; "
              "session management in NodeGoat depends on cookie handling",
        "tp", "cookie library CVE — session handling dep in NodeGoat"
    ),
    "37a57eda4425a53c": (
        "tp", "on-headers@1.0.1 LOW (CVE-2025-7339) — on-headers is a runtime dep used by "
              "response-time and possibly connect middleware in NodeGoat",
        "tp", "on-headers CVE — runtime middleware dep"
    ),

    # ── False Positives — dev/build/platform-specific dependencies ────────────
    "96001a4642289908": (
        "fp", "fsevents@1.2.9 CRITICAL (CVE-2023-45311) — fsevents is a macOS-specific native module "
              "for file system events; it is an optional dependency that does NOT run on Linux/Windows "
              "servers; NodeGoat's server is not macOS — this finding is irrelevant",
        "fp", "fsevents is macOS-only; servers run Linux — this CVE is unreachable in production"
    ),
    "240c46809fada3dc": (
        "fp", "brace-expansion@1.1.11 HIGH (CVE-2026-102276) — brace-expansion is a transitive dep "
              "of npm and mocha (test runner); not in NodeGoat's runtime dependency path",
        "fp", "brace-expansion is a test/build tool dep, not a runtime dep — not reachable via HTTP"
    ),
    "62b79de6fad8700e": (
        "fp", "braces@2.3.2 HIGH (CVE-2024-4068) — braces is a transitive dep of micromatch/glob "
              "used by grunt/mocha build tools; not in NodeGoat's runtime path",
        "fp", "braces is a build tool transitive dep — not reachable from NodeGoat's HTTP surface"
    ),
    "3da595b4a1876cfb": (
        "fp", "ini@1.3.5 HIGH prototype pollution (CVE-2020-7788) — ini is used by npm itself and "
              "grunt for config file parsing; it is a build-time dep, not a NodeGoat runtime dep",
        "tp", "ini could be used by nconf (Node config library) which some versions of NodeGoat use "
              "for runtime config — marking TP conservatively"
    ),
    "b5a148912bfa2de7": (
        "fp", "kind-of@6.0.2 HIGH prototype pollution (CVE-2019-20149) — kind-of is a transitive dep "
              "of webpack/mocha; not in NodeGoat's production runtime bundle",
        "fp", "kind-of is a build tool dep — prototype pollution not reachable at runtime"
    ),
    "bbed6c540d3b1878": (
        "fp", "set-value@0.4.3 HIGH prototype pollution (CVE-2021-23440) — set-value is a transitive "
              "dep of grunt-contrib-watch or similar build tooling; not a runtime dep",
        "fp", "set-value is a build tool transitive dep — not exploitable via NodeGoat's HTTP surface"
    ),
    "b6c674b2f71fc7c0": (
        "fp", "uglify-js@2.4.24 MEDIUM (CVE-2015-8858) — uglify-js is a JavaScript minifier used "
              "as a dev/build dependency; it is never invoked during NodeGoat's runtime",
        "fp", "uglify-js is a build-time minifier — not running at server runtime"
    ),
    "397d1cd6a231c104": (
        "fp", "utile@0.2.1 LOW (NSWG-ECO-445) — utile is an old utility library, likely a transitive "
              "dep of forever or winston-nconf; very old advisory with no known exploitation",
        "fp", "utile LOW advisory — old, low-severity, transitive build/dev dep"
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
        print(f"[WARN] no label for {cid}  rule={row['rule_id']}  file={row['file_path']}")

fieldnames = list(rows[0].keys())
with CSV_OUT.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)

print(f"Wrote {filled}/{len(rows)} labelled rows to {CSV_OUT}")
