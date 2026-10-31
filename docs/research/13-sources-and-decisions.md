# 13 — Sources and Decisions

## 1. Architecture Decision Records (ADRs)

### ADR-001: Local MCP over Cloud API

**Decision:** Use a local MCP server with Ollama and local scanners. Reject cloud LLM APIs.

**Date:** Week 1 (project initiation)

**Status:** Accepted — implemented.

**Context:** Three architectures were evaluated (see doc 03). Cloud GPT-4 was rejected due to privacy concerns (source code sent externally). Auto-apply was rejected as an unsafe default. Local MCP was chosen.

**Rationale:**
- Source code stays on the developer's machine — no privacy risk.
- Zero ongoing cost — no API keys, no per-token billing.
- Works offline — no internet dependency for analysis.
- MCP protocol is AI-client-agnostic — works with Claude Code, Cursor, and any future MCP client.

**Consequences:**
- LLM quality is bounded by what runs on local hardware.
- The 3B model requires prompt engineering effort to compensate for reduced capability.
- See ADR-002 for how this constraint was handled in patch generation.

---

### ADR-002: Patch Generation via OLD/NEW + difflib

**Decision:** For single-line findings, ask the LLM only for OLD/NEW lines. Python generates the unified diff using `difflib.unified_diff`.

**Date:** Week 22 (during patch quality improvement work)

**Status:** Accepted — implemented.

**Context:** The 3B model was asked to produce complete unified diffs. Several failure modes were observed: numbered context block output as diff body, wrong hunk line numbers, missing `--- / +++` header. Multiple mitigation strategies were implemented progressively (see doc 06, section 2).

**Rationale:**
- Diff formatting is a separate skill from understanding the fix. Separating the tasks reduces the model's cognitive load.
- `difflib.unified_diff` produces guaranteed-valid diffs — no diff formatting errors possible.
- Asking only for two lines (`OLD:` / `NEW:`) is a simpler and more constrained task than full diff generation.
- Strip-comparison of OLD against the actual file catches model hallucination.

**Consequences:**
- Only applicable to single-line findings (`line_start == line_end`).
- Multi-line findings still require full LLM diff generation (Path 3 fallback).
- The `generated_by` field distinguishes `model+difflib` (this path) from `model` (fallback).

---

### ADR-003: nosec Fast Path for B311

**Decision:** For B311 findings matching known non-cryptographic patterns (`random.uniform/randint/random/choice` in jitter/sleep context), return a `# nosec B311` comment diff without any LLM call.

**Date:** Week 23

**Status:** Accepted — implemented.

**Context:** B311 fires on all uses of `random.*` for cryptographic security reasons. In rate-limit jitter and sleep functions, `random.uniform` is not a security issue — it's intentional non-cryptographic randomness. The LLM was generating incorrect patches for these (e.g., replacing the sleep with `secrets.token_bytes()`).

**Rationale:**
- The correct fix (nosec comment) is deterministic — no model judgment needed.
- Zero latency — no Ollama call.
- The `# nosec B311` comment suppresses the finding in future Bandit scans, which is the correct resolution for this pattern.

**Consequences:**
- Only applies to the specific regex pattern in `_NOSEC_PATTERNS`. Other B311 uses go through the normal LLM path.
- Developers should review the nosec comment is appropriate for their context.

---

### ADR-004: Two-Phase Prompting

**Decision:** Split patch generation into Phase 1 (describe fix in plain English) + Phase 2 (generate patch from description).

**Date:** Week 22

**Status:** Accepted — implemented.

**Context:** Zero-shot diff generation with a single prompt produced inconsistent results. The model struggled to simultaneously understand the vulnerability and format a diff correctly.

**Rationale:**
- Phase 1 produces a plain-English description that serves as chain-of-thought context.
- Phase 2 receives the description as input — the model formats something it already understands.
- Each call is narrower and better-defined than the combined task.

**Consequences:**
- Two LLM calls per patch proposal (plus one optional retry).
- Total latency increases. This is acceptable — the additional call adds ~5–10 seconds.

---

### ADR-005: Context Radius 10 (not 30)

**Decision:** Set `_CONTEXT_RADIUS = 10`, giving the model ±10 lines around the finding.

**Date:** Week 23

**Status:** Accepted — implemented.

**Context:** Initial implementation used ±30 lines. The model frequently referenced code from lines 25–30 away from the finding, producing patches for the wrong location.

**Rationale:**
- A 3B model has limited attention capacity. With 60+ lines of context, the `>>>` marker on the vulnerable line receives proportionally less attention.
- 20 lines total keeps the vulnerable line near the centre of the context window.
- If the fix genuinely requires understanding code 20+ lines away, it likely also requires multi-line patch generation, which is already flagged as a limitation.

**Consequences:**
- For findings that require broader context (e.g., a function parameter defined 15 lines away), the model may produce incomplete patches. These fall through to the LLM full diff path, which may also fail. Reported as a limitation.

---

## 2. Source Register

### Standards and Specifications

| Source | Used For |
|---|---|
| OWASP Top 10 (2021) | Vulnerability categorisation; CWE weighting in ranker |
| CWE (MITRE) | `cwe_id` values in `SecurityFinding`; feature extraction for ML ranker |
| CVSS v3.1 (NIST NVD) | Severity scoring context (Trivy uses CVSS scores) |
| Model Context Protocol v1.0 (Anthropic, 2024) | MCP server implementation; tool schema definitions |
| Unified Diff Format (GNU patch) | Patch format specification |

### Libraries and Tools

| Library | Version | Licence | Used For |
|---|---|---|---|
| Python | 3.12 | PSF | Runtime |
| mcp | 2.x | MIT | MCP server + tool dispatch |
| Pydantic | 2.x | MIT | Data models and validation |
| Bandit | 1.7.x | Apache 2.0 | Python SAST scanner |
| Trivy | latest | Apache 2.0 | Dependency and secret scanner |
| tree-sitter | 0.23.x | MIT | Syntax tree parsing |
| tree-sitter-javascript | 0.23.x | MIT | JS grammar |
| NetworkX | 3.x | BSD | Context graph |
| scikit-learn | 1.x | BSD | ML ranker (LogReg, RF) |
| Qwen2.5-Coder 3B Q4_K_M | — | Apache 2.0 | Local LLM |
| Ollama | latest | MIT | LLM inference server |
| uv | 0.x | MIT | Package manager |
| difflib | stdlib | PSF | Unified diff generation |
| sqlite3 | stdlib | PSF | Audit log |

### Benchmark Datasets

| Dataset | Source | Used For |
|---|---|---|
| OWASP Juice Shop | github.com/juice-shop/juice-shop (MIT) | Primary benchmark, ground truth |
| DVWA | github.com/digininja/DVWA (GPL-3.0) | Supplementary benchmark (if time permits) |

### Prior Work Referenced

| Reference | Relevance |
|---|---|
| Bandit documentation (PyCQA) | Scanner rule reference, severity/confidence scale |
| Trivy documentation (Aqua Security) | Scanner output schema, secrets detection |
| HumanEval benchmark (OpenAI, 2021) | Basis for model selection comparison (table in doc 06) |
| Cohen (1960), "A coefficient of agreement for nominal scales" | Cohen's κ formula for inter-rater agreement |
| Unified diff format documentation (GNU) | Patch format specification |
