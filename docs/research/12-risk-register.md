# 12 — Risk Register

## 1. Risk Scoring

Each risk is scored on two dimensions:
- **Probability:** 1 (unlikely) – 3 (likely)
- **Impact:** 1 (minor) – 3 (major)
- **Risk score:** Probability × Impact

Risks with score ≥ 6 are high priority.

---

## 2. Technical Risks

### T1 — LLM Patch Quality (3B Model)

| Property | Value |
|---|---|
| Probability | 3 (likely — 3B models are known to struggle with diff formatting) |
| Impact | 2 (moderate — patch generation degrades, but scan and explain still work) |
| Score | **6 (High)** |
| Status | **Mitigated** |

**Description:** The Qwen2.5-Coder 3B model produces incorrectly-formatted unified diffs. Failure modes observed: numbered context block used as diff body; wrong line numbers in hunk headers; model outputs the full context instead of only the changed lines.

**Mitigation implemented:**
- Two-phase prompting: Phase 1 (plain English) + Phase 2 (OLD/NEW lines only)
- `difflib.unified_diff` reconstruction from OLD/NEW lines — Python generates the diff, not the model
- `_hunk_lines_valid()` rejects diffs where hunk lines don't start with ` `, `-`, `+`, or `\`
- `_patch_covers_finding()` rejects diffs that don't cover the finding's line
- Retry mechanism with explicit line number reminder
- nosec fast path for B311 patterns — no LLM call at all

**Residual risk:** Multi-line findings still require full LLM diff generation. The fallback may return `patch_diff: null` for complex findings.

---

### T2 — tree-sitter Windows Build Failure

| Property | Value |
|---|---|
| Probability | 2 (moderate — MSVC build tools required, often missing) |
| Impact | 2 (moderate — context graph disabled, scan still works) |
| Score | **4 (Medium)** |
| Status | **Resolved** |

**Description:** tree-sitter language grammars require a C compiler to build on Windows. Developers without MSVC Build Tools installed see build failures during `pip install`.

**Resolution:** MSVC Build Tools documented as a prerequisite. The project now uses pre-built wheel distributions from PyPI where available (tree-sitter-javascript, tree-sitter-python). Build-from-source is only required for grammars not on PyPI.

---

### T3 — Trivy Database Staleness

| Property | Value |
|---|---|
| Probability | 2 (moderate — database update requires internet access) |
| Impact | 1 (minor — stale DB misses recent CVEs but doesn't fail) |
| Score | **2 (Low)** |
| Status | **Accepted** |

**Description:** Trivy uses a local vulnerability database that must be updated periodically. A stale database returns fewer findings without indication.

**Mitigation:** Trivy's scan output includes the database age. Documented in README: run `trivy image --download-db-only` to refresh. Trivy itself shows a warning when the database is more than 24 hours old.

---

### T4 — Context Graph Scope Limitation

| Property | Value |
|---|---|
| Probability | 3 (certain — by design) |
| Impact | 1 (minor — clearly documented) |
| Score | **3 (Low)** |
| Status | **Accepted** |

**Description:** The context graph only parses Express.js route patterns. Python Flask/FastAPI routes, Koa.js, Hapi, and other frameworks are not attributed. Findings in those files show `route_path: null`.

**Mitigation:** Limitation documented. Scope boundary is consistent with the FYP research questions, which use OWASP Juice Shop (Express.js) as the benchmark.

---

### T5 — Ollama Memory Pressure

| Property | Value |
|---|---|
| Probability | 2 (moderate on low-RAM machines) |
| Impact | 2 (moderate — Ollama crashes, LLM tools fail) |
| Score | **4 (Medium)** |
| Status | **Mitigated** |

**Description:** Running Bandit, Trivy, and Ollama simultaneously on a machine with 8 GB RAM may cause memory pressure, leading to OOM or slow response times.

**Mitigation:** Recommended minimum is 16 GB RAM. The scanner subprocesses complete before the LLM is invoked (sequential pipeline, not parallel). `_CONTEXT_RADIUS = 10` limits LLM prompt size.

---

## 3. Research Risks

### R1 — Small Dataset (N=79)

| Property | Value |
|---|---|
| Probability | 3 (certain — dataset is fixed at N=79) |
| Impact | 2 (moderate — ML results are indicative, not statistically robust) |
| Score | **6 (High)** |
| Status | **Accepted** |

**Description:** N=79 annotated findings is small for training machine learning models. The ML ranker experiment may produce unstable results across cross-validation folds.

**Mitigation:** 5-fold stratified cross-validation is appropriate for small datasets. Results are explicitly scoped as "indicative on the OWASP Juice Shop benchmark." A negative result (ML ≤ rule-based) is treated as a valid research finding, not a failure. The dataset may be supplemented with DVWA (Damn Vulnerable Web Application) findings if time permits.

---

### R2 — Inter-Rater Disagreement

| Property | Value |
|---|---|
| Probability | 2 (moderate) |
| Impact | 2 (moderate — affects ground truth quality) |
| Score | **4 (Medium)** |
| Status | **Mitigated** |

**Description:** Two annotators may disagree on whether a finding is a true positive or false positive, particularly for medium-confidence findings or context-dependent vulnerabilities.

**Mitigation:** Annotation criteria documented before annotation begins. Cohen's κ computed as a check. Disagreements resolved by discussion; a third annotator breaks ties. All disputed findings are documented.

---

### R3 — Benchmark Applicability

| Property | Value |
|---|---|
| Probability | 3 (certain — Juice Shop is a specific benchmark) |
| Impact | 1 (minor — clearly scoped) |
| Score | **3 (Low)** |
| Status | **Accepted** |

**Description:** All evaluation results are specific to the OWASP Juice Shop benchmark. They may not generalise to production codebases, different languages, or different vulnerability distributions.

**Mitigation:** All research questions and results explicitly state "on the OWASP Juice Shop benchmark." No generalisation claims are made in the dissertation.

---

## 4. Schedule Risks

### S1 — FYP-I Gate Delay

| Property | Value |
|---|---|
| Probability | 1 (resolved — gates passed) |
| Impact | 3 (major — gates block downstream work) |
| Score | **3 (Low)** |
| Status | **Resolved** |

**Description:** Each milestone gate (ping, scan, explain, propose, verify) must pass before the next phase begins. A late gate shifts all downstream milestones.

**Resolution:** All FYP-I gates (Weeks 1–16) passed on schedule. The tree-sitter Windows build risk (T2) was the most likely gate blocker and was resolved in Week 9.

---

### S2 — Dissertation Writing Scope

| Property | Value |
|---|---|
| Probability | 2 (moderate) |
| Impact | 2 (moderate — late submission, reduced quality) |
| Score | **4 (Medium)** |
| Status | **Active** |

**Description:** Weeks 29–30 are allocated for dissertation writing. The research document set (this `docs/research/` directory) is intended to make that writing faster by having all key decisions, methods, and results already documented. If experiments run late, writing time is compressed.

**Mitigation:** Research documents written during Weeks 27–28 (current milestone) to serve as first-draft dissertation material. All RQ experiments designed to be runnable in a single day.
