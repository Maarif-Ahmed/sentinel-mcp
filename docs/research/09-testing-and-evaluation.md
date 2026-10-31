# 09 — Testing and Evaluation

## 1. Research Questions

Sentinel addresses four research questions (RQs), each with a measurable metric and a reproducible method. No RQ relies on human relevance ratings.

| RQ | Question | Metric | Benchmark |
|---|---|---|---|
| RQ1 | Does context annotation change finding ranking vs severity-only? | Spearman ρ between severity-only rank and context-enriched rank | OWASP Juice Shop |
| RQ2 | Does the verification loop correctly identify when a patch removes a finding? | TP rate (rescan clear after correct patch) + FP rate (rescan clear after incorrect patch) | Fixture files + Juice Shop |
| RQ3 | Does the ML ranker improve Precision@5 over rule-based? | Precision@5, 5-fold CV | N=79 annotated findings |
| RQ4 | What is the end-to-end latency and VRAM for a complete scan cycle? | Median wall-clock (s), peak VRAM (MB), peak RAM (MB) | 10 runs on fixed Juice Shop snapshot |

---

## 2. Benchmark: OWASP Juice Shop

OWASP Juice Shop is a deliberately insecure Node.js + Angular web application with a documented list of vulnerabilities across SQL injection, XSS, broken authentication, sensitive data exposure, and more. It is used as the primary benchmark because:

- Vulnerabilities are **documented**: known file paths and line numbers, not inferred.
- It contains **both true positives** (scanner findings that correspond to real vulnerabilities) and **false positives** (scanner findings on safe code).
- The codebase is **polyglot** (Node.js + Python utilities), exercising both Bandit and Trivy.
- It is **publicly available** (MIT licence), making the benchmark reproducible.

A **fixed snapshot** (specific commit hash) is used for all benchmarks to ensure reproducibility.

---

## 3. Ground Truth Construction

### 3.1 Process

1. Run `sentinel.scan_repository` on the fixed Juice Shop snapshot.
2. Export all findings as a structured CSV: `finding_id, rule_id, file_path, line_start, message, snippet`.
3. Two team members (Marif Ahmed, Shaheer ul Ibrahim) independently annotate each finding as:
   - `true_positive` — corresponds to a vulnerability documented in Juice Shop's challenge list.
   - `false_positive` — scanner flags code that is not actually vulnerable.
4. Compute inter-rater agreement using **Cohen's κ**.
5. Resolve disagreements: team members discuss each disputed finding and reach consensus. A third annotator breaks ties if consensus is not reached.

### 3.2 Inter-Rater Agreement

**Target:** κ ≥ 0.6 (substantial agreement).

Cohen's κ formula:
```
κ = (P_o - P_e) / (1 - P_e)
```
Where `P_o` is observed agreement and `P_e` is expected agreement by chance.

A κ < 0.6 would indicate the annotation task is ambiguous; the annotation criteria would be refined and the process repeated before using labels for model training.

### 3.3 Dataset Statistics

| Property | Value |
|---|---|
| Total annotated findings | 79 |
| True positives | ~45 (estimated ~57%) |
| False positives | ~34 (estimated ~43%) |
| Benchmark applications | 3 (Juice Shop + 2 team-built vulnerable apps) |
| Annotators | 2 (+ 1 arbiter) |

---

## 4. RQ1: Context Annotation vs Severity-Only Ranking

### Method

1. For each finding in the Juice Shop benchmark, record:
   - `severity_rank`: rank by scanner severity (high=1, medium=2, low=3) with ties broken by rule_id.
   - `context_rank`: rank by `RiskAssessment.score` (includes route exposure + middleware factors).
2. Compute Spearman's ρ between the two rank orderings.
3. Report the rank correlation and identify the findings with the largest rank changes.

### Expected Result

ρ close to 1.0 would indicate context adds no information (route exposure and authentication are uncorrelated with scanner severity). ρ significantly below 1.0 indicates context is informative — some findings are promoted (exposed routes) and some demoted (authenticated middleware).

### Interpretation

A finding promoted by context enrichment is a candidate for the "would be missed by severity-only triage" category, which is the core value proposition of the context graph.

---

## 5. RQ2: Verification Loop Accuracy

### Method

Two test sets:

**Set A — Known-good patches (should be rescan-clear):**
- Take 10 findings from the fixture apps.
- Manually write a correct, minimal patch for each.
- Apply the patch, run `sentinel.verify_proposal`.
- Expected: `rescan_clear: True` for all 10.

**Set B — Known-bad patches (should still be detected):**
- Take the same 10 findings.
- Apply a patch that changes the code but does not fix the vulnerability (e.g., rename variable, add comment).
- Run `sentinel.verify_proposal`.
- Expected: `rescan_clear: False` for all 10.

### Metrics

- **True Positive Rate** (TPR): correct patches that are rescan-clear / total correct patches.
- **False Negative Rate** (FNR): incorrect patches that are incorrectly marked rescan-clear / total incorrect patches.

A high FNR would indicate the rescan is unreliable — it clears findings that were not actually fixed. This is reported as a limitation if observed.

---

## 6. RQ3: ML Ranker Precision@5

### Method

**Feature extraction:** For each of the 79 annotated findings, extract the 13-dimensional feature vector.

**Models:**

| Model | Configuration |
|---|---|
| Severity-only baseline | Sort by severity (high > medium > low) |
| Rule-based ranker | Weighted sum (fixed weights) |
| Logistic Regression | sklearn, L2, C=1.0, max_iter=1000 |
| Random Forest | sklearn, n_estimators=100, max_depth=5, random_state=42 |

**Evaluation:** 5-fold stratified cross-validation. In each fold:
1. Train on 80% of findings.
2. Rank the held-out 20%.
3. Compute Precision@5: fraction of top-5 ranked findings that are true positives.
4. Average Precision@5 across all 5 folds.

**Statistical test:** Wilcoxon signed-rank test between ML ranker Precision@5 scores and rule-based scores across folds. p < 0.05 considered significant.

### Expected Results

If context features (`has_authenticated_middleware`, `is_publicly_exposed_route`) are informative, the ML ranker should outperform severity-only. Whether it outperforms the rule-based ranker is a genuine research question — the rule-based ranker is already context-aware.

A negative result (ML ≤ rule-based) is valid and reported honestly. It may indicate: dataset too small, features not sufficiently discriminative, or the rule-based weights are already well-calibrated.

---

## 7. RQ4: End-to-End Latency and VRAM

### Method

**Benchmark task:** Complete scan cycle on the fixed Juice Shop snapshot:
1. `sentinel.scan_repository`
2. `sentinel.explain_finding` for the top-ranked finding
3. `sentinel.propose_fix` for the top-ranked finding

**Hardware:** RTX 4050 Laptop GPU (6 GB VRAM), 16 GB RAM, Windows 11.

**Models compared:** Qwen2.5-Coder 3B Q4_K_M vs Qwen2.5-Coder 7B Q4_K_M.

**Measurement:**
- Wall-clock time: `time.perf_counter()` around each tool call.
- VRAM: `nvidia-smi --query-gpu=memory.used --format=csv` before and after each phase.
- RAM: `psutil.Process().memory_info().rss` sampled at 1s intervals.
- **10 runs** per model; report median and interquartile range (IQR).

### Metrics Table

| Phase | 3B Median (s) | 3B IQR | 7B Median (s) | 7B IQR |
|---|---|---|---|---|
| scan_repository | TBD | TBD | TBD | TBD |
| explain_finding | TBD | TBD | TBD | TBD |
| propose_fix (Phase 1) | TBD | TBD | TBD | TBD |
| propose_fix (Phase 2a) | TBD | TBD | TBD | TBD |
| propose_fix (Phase 2b) | TBD | TBD | TBD | TBD |
| **Total cycle** | TBD | TBD | TBD | TBD |
| Peak VRAM (MB) | TBD | TBD | TBD | TBD |
| Peak RAM (MB) | TBD | TBD | TBD | TBD |

*Values to be filled from benchmark runs.*

---

## 8. Limitations

| Limitation | Mitigation |
|---|---|
| N=79 is small for ML | Report as limitation; 5-fold CV is appropriate for small datasets; supplement with DVWA if time permits |
| Ground truth is Juice Shop-specific | Explicitly scope all claims to Juice Shop; do not claim generalisation |
| Rescan verification is scanner-limited | If Bandit is updated between patch and rescan, findings may change; pin Bandit version in benchmark |
| 3B model patch quality | RQ4 benchmark explicitly measures this; nosec fast path and difflib reconstruction reduce the failure rate for common patterns |
| Single hardware configuration | Report hardware specs; results may differ on different GPU configurations |
