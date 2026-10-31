# 06 — AI/ML Strategy

## 1. LLM Choice Rationale

### 1.1 Hardware Constraints

The target hardware (RTX 4050, 6 GB VRAM) sets a hard ceiling on model size. Key thresholds:

| Model | Quantization | VRAM | Fits RTX 4050? |
|---|---|---|---|
| Qwen2.5-Coder 1.5B | Q4_K_M | ~1.0 GB | ✅ Yes |
| Qwen2.5-Coder 3B | Q4_K_M | ~2.0 GB | ✅ Yes (chosen) |
| Qwen2.5-Coder 7B | Q4_K_M | ~4.5 GB | ✅ Yes (marginal) |
| Qwen2.5-Coder 7B | Q8 | ~7.2 GB | ❌ Exceeds |
| Qwen2.5-Coder 14B | Q4_K_M | ~8.5 GB | ❌ Exceeds |
| GPT-4 | Cloud | N/A | ❌ Privacy |

The 3B model was chosen as the primary model because it:
- Fits entirely on-GPU (no CPU offloading → consistent latency).
- Leaves ~4 GB VRAM headroom for OS and scanner processes.
- Produces acceptable code completions for single-line changes.
- Apache 2.0 licence — no redistribution concerns.

The 7B model is used in the RQ4 benchmark only.

### 1.2 Why Qwen2.5-Coder Specifically

| Criterion | Qwen2.5-Coder 3B | CodeLlama 7B | DeepSeek-Coder 1.3B |
|---|---|---|---|
| Code quality (HumanEval) | ~75% | ~71% | ~65% |
| VRAM at Q4_K_M | ~2 GB | ~4 GB | ~0.8 GB |
| Licence | Apache 2.0 | Llama 2 Community | Apache 2.0 |
| Context window | 32K tokens | 16K tokens | 16K tokens |
| Fine-tuned for code edits | ✅ Yes | ⚠️ Partial | ✅ Yes |

Qwen2.5-Coder provides the best code quality per VRAM unit at the 3B scale, with a permissive licence and large context window.

---

## 2. Prompt Engineering

Generating correct unified diffs from a 3B model is non-trivial. Several techniques were developed and tested iteratively:

### 2.1 Two-Phase Prompting

**Problem:** Asking the model to simultaneously understand the vulnerability AND format a diff is too complex for a 3B model.

**Solution:** Split into two calls:
- **Phase 1:** "What is wrong with the marked line? What should the fix be?" → plain English description.
- **Phase 2:** "Given this fix description, generate the diff." → model only formats what it already understands.

Each call is narrow and well-defined. The Phase 1 description serves as chain-of-thought context for Phase 2.

### 2.2 `>>>` Vulnerable Line Marker

**Problem:** With ±30 lines of context, the 3B model drifted to nearby code rather than the flagged line.

**Solution:** Mark the exact vulnerable line with `>>>` in the context listing:
```
  85    def jitter_sleep():
  86 >>>     time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
  87
```

The marker is included in the system prompt description ("The line marked with `>>>` is the EXACT vulnerable line").

### 2.3 Reduced Context Radius (30 → 10 lines)

**Problem:** A 3B model has limited attention capacity. 60+ lines of context overwhelmed the model — it lost focus on the `>>>` marker.

**Solution:** Reduce `_CONTEXT_RADIUS` from 30 to 10 lines. The model sees only 20 lines total, keeping the vulnerable line near the centre of the context window.

### 2.4 Few-Shot Example

**Problem:** Zero-shot diff generation produces inconsistent formatting even with detailed instructions.

**Solution:** A concrete example (B105 hardcoded token → environment variable lookup) in the patch system prompt anchors the model to the exact format expected. One example is sufficient; more examples consume tokens that could be used for context.

### 2.5 OLD→NEW Line Reconstruction via difflib

**Problem:** Even when the model correctly identifies the fix, it often formats the diff incorrectly (wrong line numbers, missing context lines, numbered context block instead of diff lines).

**Solution:** Ask the model for only two lines:
```
OLD: <exact vulnerable line verbatim>
NEW: <replacement line>
```
Python then:
1. Verifies `OLD` matches the actual file line (strip-compare).
2. Preserves original indentation from the file.
3. Constructs a valid diff with `difflib.unified_diff`.

The model never touches diff syntax. This eliminates the entire formatting failure mode for single-line findings.

### 2.6 Inference Parameter Tuning

| Parameter | Value | Rationale |
|---|---|---|
| `temperature` | 0.1 | Low temperature → deterministic, conservative code output |
| `top_p` | 0.9 | Nucleus sampling → avoids degenerate low-probability tokens |
| `repeat_penalty` | 1.1 | Discourages repetitive output in long generations |
| `max_tokens` | 1024 | Sufficient for single-file patches; prevents runaway generation |

### 2.7 nosec Fast Path

**Problem:** B311 flagging `random.uniform()` in jitter sleep functions is a systematic false positive. Asking the LLM to fix it produces hallucinated patches (e.g., replacing the sleep with cryptographic random, or unrelated changes).

**Solution:** Pattern-match B311 findings against known non-cryptographic uses (sleep/jitter context). Return a `# nosec B311` comment diff without any LLM call. Zero latency, correct output.

### 2.8 Hunk Line Validation

**Problem:** The model sometimes returned the numbered context listing (with `>>>` markers) as the diff body. The `--- / +++` header check passed, but the content was invalid.

**Solution:** `_hunk_lines_valid()` verifies every line inside a `@@` hunk starts with ` `, `-`, `+`, or `\`. Lines starting with digits (numbered context) are rejected immediately.

---

## 3. ML Ranker Experiment

### 3.1 Research Question

> RQ3: Does adding structural route context features to the ranker improve Precision@5 on annotated Juice Shop findings, compared to severity-only and rule-based baselines?

### 3.2 Feature Set (13 Dimensions)

| Feature | Type | Source |
|---|---|---|
| `severity_score` | Ordinal (1–4) | Scanner severity |
| `confidence_score` | Ordinal (1–3) | Scanner confidence |
| `cwe_is_injection` | Binary | CWE-89, CWE-79, CWE-78 |
| `cwe_is_auth` | Binary | CWE-287, CWE-306, CWE-798 |
| `cwe_is_crypto` | Binary | CWE-326, CWE-327, CWE-330 |
| `cwe_is_misconfig` | Binary | CWE-16, CWE-693 |
| `cwe_is_error_handling` | Binary | CWE-391 |
| `has_authenticated_middleware` | Binary | Context graph |
| `is_publicly_exposed_route` | Binary | Context graph |
| `is_dependency_finding` | Binary | Trivy vs Bandit |
| `is_dev_dependency` | Binary | Trivy metadata |
| `file_is_route_handler` | Binary | Context graph |
| `snippet_length` | Integer | len(snippet) |

### 3.3 Ground Truth Construction

**Dataset:** OWASP Juice Shop — an intentionally vulnerable Node.js + Python application with documented vulnerabilities.

**Annotation process:**
1. Run `sentinel.scan_repository` on a fixed Juice Shop snapshot.
2. Two team members independently annotate each finding as `true_positive` (corresponds to a documented Juice Shop vulnerability) or `false_positive`.
3. Compute Cohen's κ for inter-rater agreement. Target: κ ≥ 0.6.
4. Resolve disagreements by discussion. Final label used.

**Dataset size:** N = 79 annotated findings across three benchmark applications.

### 3.4 Models and Evaluation

| Model | Description |
|---|---|
| Severity-only baseline | Rank by scanner severity (high > medium > low) |
| Rule-based ranker | Weighted sum of all 13 features |
| Logistic Regression | sklearn, L2 regularisation, C=1.0 |
| Random Forest | sklearn, 100 estimators, max_depth=5 |

**Evaluation protocol:** 5-fold stratified cross-validation. Metric: **Precision@5** (fraction of top-5 ranked findings that are true positives).

**Expected finding:** If the context features (`has_authenticated_middleware`, `is_publicly_exposed_route`) are informative, the ML ranker should outperform the severity-only baseline on Precision@5. If not, the result is reported honestly as a negative finding — still a valid research contribution.

### 3.5 Limitations

- N=79 is small for machine learning. Results should be treated as indicative, not definitive.
- The ground truth is specific to Juice Shop; generalisation to other codebases is not claimed.
- The context graph covers Express.js only; Python Flask/FastAPI routes are not attributed.
- Inter-rater agreement is computed but annotation is not triple-blind.
