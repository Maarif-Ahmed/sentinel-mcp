# 08 — 30-Week Roadmap

## 1. Team Ownership

| Member | ID | Primary Areas |
|---|---|---|
| Ammar Ahmed Abbasi | 63199 | MCP server, tool dispatch, orchestrator, protocol compliance |
| Muhammad Alam | 64759 | Scanner adapters, normalizer, context graph (tree-sitter + NetworkX) |
| Marif Ahmed | 61208 | LLM adapter, rule-based ranker, ML ranker, patch generator |
| Shaheer ul Ibrahim | 58512 | Verification, audit log, report generator, evaluation harness |

---

## 2. Milestone Table

| Weeks | Milestone | Owner(s) | Status |
|---|---|---|---|
| 1–2 | Environment PoC: `sentinel.ping` gate | All | ✅ Complete |
| 3–5 | BanditAdapter + FindingNormalizer | M2, M1 | ✅ Complete |
| 6–7 | TrivyAdapter + deduplication | M2 | ✅ Complete |
| 8–10 | Context graph (Express.js routes + middleware) | M2, M1 | ✅ Complete |
| 11–12 | RuleBasedRanker + OllamaProvider + explain_finding | M3, M1 | ✅ Complete |
| 13–14 | PatchGenerator + SyntaxChecker + verify_proposal | M3, M4 | ✅ Complete |
| 15–16 | AuditLog + get_audit_history + FYP-I demo | M4, M1 | ✅ Complete |
| 17–18 | Evaluation harness + ground truth annotation | M4, M3 | ✅ Complete |
| 19–21 | ML ranker (features, LR, RF, 5-fold CV) | M3 | ✅ Complete |
| 22–23 | RQ4: LLM latency + VRAM benchmark | M3, M4 | ✅ Complete |
| 24 | Semgrep adapter (optional) | M2 | ⬜ Skipped (deferred) |
| 25–26 | `sentinel report` CLI + HTML severity breakdown | M4 | ✅ Complete |
| 27–28 | 13 research documents in `docs/research/` | All | 🔄 In progress |
| 29–30 | Final report + submission | All | ⬜ Pending |

---

## 3. FYP-I Detail (Weeks 1–16)

### Weeks 1–2: Environment Proof-of-Concept
**Goal:** Every team member can call `sentinel.ping` from their Windows 11 machine.

Tasks:
- Install Python 3.11, `mcp` v2, `bandit`, `trivy` binary, Ollama on each machine.
- Verify tree-sitter builds with MSVC or mingw64 — document exact steps.
- Implement `sentinel.ping` MCP tool, test via MCP Inspector (`npx @modelcontextprotocol/inspector`).

**Gate:** `sentinel.ping` returns `{"status": "ok"}` on all four team machines. Nothing proceeds until this passes.

### Weeks 3–5: First Scanner + Normalizer
Tasks:
- `BanditAdapter`: `subprocess.run(["bandit", "-r", "-f", "json", repo_path])`, parse JSON.
- `FindingNormalizer`: map `RawFinding → SecurityFinding`, compute `canonical_id`.
- `sentinel.scan_repository` (Bandit only) over MCP.
- Test fixture: vulnerable Flask file with 3 known issues.

**Gate:** `sentinel.scan_repository` returns ≥1 `SecurityFinding` with correct `canonical_id`.

### Weeks 6–7: Trivy Adapter
Tasks:
- `TrivyAdapter`: subprocess + JSON parse, secrets truncation.
- Deduplication by `canonical_id` in normalizer.
- Both scanners in pipeline.

**Gate:** Single scan returns findings from both Bandit and Trivy without duplicates.

### Weeks 8–10: Context Graph
Tasks:
- tree-sitter S-expression queries for Express.js route and middleware extraction.
- `ContextGraphBuilder` with NetworkX; two-claim scope.
- Enrich `SecurityFinding` with `ContextAnnotation`.

**Gate:** A finding for a vulnerable JS file shows `route_path` populated.

### Weeks 11–12: Ranker + LLM Explanation
Tasks:
- `RuleBasedRanker` with explicit feature table and weights.
- `OllamaProvider` with `localhost:11434` endpoint.
- `sentinel.explain_finding` tool.

**Gate:** `sentinel.explain_finding` returns a coherent paragraph within 30 seconds.

### Weeks 13–14: Patch Proposal + Verification
Tasks:
- `PatchGenerator` with initial LLM diff approach.
- `sentinel.propose_fix` tool (no apply logic).
- `SyntaxChecker` (Python: `ast.parse`; JS: `node --check`).
- `sentinel.verify_proposal` (syntax + rescan).

**Gate:** `sentinel.propose_fix` returns a diff; `sentinel.verify_proposal` correctly identifies rescan-clear outcome on fixture.

### Weeks 15–16: Integration + Audit + Demo
Tasks:
- `AuditEvent` + SQLite logger; wired into all tool handlers.
- `sentinel.get_audit_history`.
- Integration test on OWASP Juice Shop clone.
- FYP-I report + demo.

**Gate:** Full pipeline (scan → explain → propose → verify → history) working on Juice Shop.

---

## 4. FYP-II Detail (Weeks 17–30)

### Weeks 17–18: Evaluation Harness + Ground Truth
Tasks:
- Build `benchmarks/` harness: runs Sentinel on fixed Juice Shop snapshot, records findings + metadata.
- Two-member independent annotation of all findings as TP/FP.
- Compute Cohen's κ; resolve disagreements.

**Gate:** N ≥ 50 annotated findings, κ ≥ 0.6.

### Weeks 19–21: ML Ranker
Tasks:
- 13-dimensional feature extraction pipeline from `SecurityFinding` + `ContextAnnotation`.
- `is_dev_dependency` feature from Trivy metadata.
- Logistic Regression + Random Forest with 5-fold stratified CV.
- Precision@5 vs rule-based and severity-only baselines.
- `MLRanker` as alternative `RankerProvider`.

**Gate:** Precision@5 reported for all four ranker variants.

### Weeks 22–23: RQ4 LLM Benchmark
Tasks:
- Benchmark Qwen2.5-Coder 3B vs 7B on explanation quality and patch generation.
- Measure median wall-clock time (10 runs), peak VRAM (MB), peak RAM (MB).
- Use `psutil` and Ollama metrics endpoint.

**Gate:** Latency + VRAM table produced for both models.

### Weeks 25–26: Report Generator
Tasks:
- `sentinel report` CLI command.
- JSON output (full structured data).
- Single-file HTML report with severity breakdown chart.
- Complete all RQ1–RQ4 experiments.

**Gate:** `sentinel report` produces valid HTML on Juice Shop findings.

### Weeks 27–28: Documentation
Tasks:
- 13 research documents in `docs/research/`.
- Installation guide + README.

### Weeks 29–30: Final Report + Submission
Tasks:
- Dissertation writing.
- Final code cleanup.
- Submission packaging.

---

## 5. Critical Path

The critical path runs through the MCP server infrastructure:

```
ping gate (W2) → scan_repository (W5) → context graph (W10) → ranker (W12)
    → propose_fix (W14) → FYP-I demo (W16) → evaluation harness (W18)
    → ML ranker results (W21) → report generator (W26) → final report (W30)
```

Every stage depends on the previous gate passing. The context graph (W8–10) was identified as the highest-risk item due to tree-sitter Windows build complexity — it was completed successfully.

---

## 6. Completed vs Planned

| Item | Planned | Actual |
|---|---|---|
| Primary LLM | Qwen2.5-Coder 3B Q4_K_M | ✅ As planned |
| Semgrep adapter | FYP-II Week 24 | ⬜ Deferred — stability work on Bandit+Trivy took priority |
| Context graph | Express.js only | ✅ As planned |
| ML dataset size | 50–80 findings | ✅ N=79 |
| Patch generation approach | Single LLM diff call | Evolved: nosec fast path + OLD/NEW difflib + retry |
| Web dashboard | Removed (replaced with CLI) | ✅ As planned |
| Auto-apply | Out of scope | ✅ Never built |
