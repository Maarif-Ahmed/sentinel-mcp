# Sentinel MCP

A context-aware AI agent for automated web application security analysis and verified remediation.

Sentinel integrates with compatible AI development clients via the [Model Context Protocol](https://modelcontextprotocol.io/). It runs security scanners locally, attributes findings to the HTTP routes they sit behind, explains them with a local LLM, and proposes patch diffs for developer review.

**Source code never leaves your machine.** No cloud API calls. No automatic patches.

## Status

✅ Week 1–2: Foundation — `sentinel.ping` gate  
✅ Week 3–7: Scanner adapters (Bandit + Trivy) + normalizer  
✅ Week 8–10: Context graph — Express.js (tree-sitter) and Flask/FastAPI (`ast`)  
✅ Week 11–12: LLM explanation (Ollama / Qwen2.5-Coder 3B)  
✅ Week 13–14: Patch proposal + verification  
✅ Week 15–16: Audit log + `sentinel report` CLI  
✅ Week 17–18: Evaluation harness + ground truth annotation  
✅ Week 19–21: ML ranker (Logistic Regression + Random Forest)  
✅ Week 22–23: RQ4 LLM latency + VRAM benchmarks  
✅ Week 24: QLoRA fine-tuning of Qwen2.5-Coder-3B (see *Fine-tuning*)  
✅ Week 25–26: Report generator CLI + HTML severity breakdown  
🔄 Week 27–28: Research documents (`docs/research/`)  
⬜ Week 29–30: Final report + submission

## Quick Start

**Prerequisites:** Python 3.11+, [Ollama](https://ollama.com/) with `qwen2.5-coder:3b` pulled, [Bandit](https://bandit.readthedocs.io/), [Trivy](https://trivy.dev/).

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
sentinel ping     # must return {"status": "ok"} before proceeding
pytest tests/ -v
```

### Register with Claude Code

```bash
claude mcp add sentinel -s user -- .venv/Scripts/python.exe -m sentinel.server
```

Then restart Claude Code. Sentinel's tools load automatically when you ask Claude to scan a repository.

## MCP Tools

| Tool | Status | Description |
|------|--------|-------------|
| `sentinel.ping` | ✅ Ready | Environment health check |
| `sentinel.scan_repository` | ✅ Ready | Scan with Bandit + Trivy; returns findings with context annotations and risk scores |
| `sentinel.explain_finding` | ✅ Ready | LLM-generated explanation for a finding |
| `sentinel.propose_fix` | ✅ Ready | Unified diff patch proposal (display only — never auto-applied) |
| `sentinel.verify_proposal` | ✅ Ready | Syntax check + rescan after developer manually applies a patch |
| `sentinel.get_audit_history` | ✅ Ready | SQLite audit log for a repository |
| `sentinel.report` | ✅ Ready | Generate JSON + static HTML report |
| `sentinel.watch_repository` | ✅ Ready | Start continuous rescanning on file save |
| `sentinel.get_watch_status` | ✅ Ready | Drain findings discovered since the last poll |
| `sentinel.stop_watch` | ✅ Ready | Stop the watcher for a repository |

## Architecture

```
sentinel-mcp/
├── src/sentinel/
│   ├── server.py           # MCP server, tool registration
│   ├── orchestrator.py     # Pipeline: scan → normalize → enrich → rank → explain
│   ├── scanners/           # Bandit + Trivy subprocess adapters
│   ├── normalizer.py       # RawFinding → SecurityFinding, deduplication
│   ├── context/            # route + middleware extraction
│   │   ├── extractor.py        #   Express.js via tree-sitter (regex fallback)
│   │   ├── python_extractor.py #   Flask decorators + FastAPI Depends() via ast
│   │   └── graph.py            #   NetworkX import graph, route attribution
│   ├── ranker.py           # Rule-based severity ranker
│   ├── ml/                 # ML ranker (Logistic Regression / Random Forest)
│   ├── llm/                # Ollama provider (Qwen2.5-Coder 3B)
│   ├── remediation.py      # PatchGenerator → unified diff (no apply logic)
│   ├── verification.py     # Syntax check + rescan
│   ├── audit.py            # SQLite append-only audit log
│   ├── report.py           # JSON + HTML report generator
│   ├── watcher.py          # watchdog file watcher for continuous scanning
│   └── cli.py              # `sentinel` CLI entry point
├── benchmarks/
│   ├── harness.py          # run the pipeline, emit an annotation template
│   ├── label.py            # interactive TP/FP labelling with source context
│   ├── annotate.py         # Cohen's κ, blind templates, provenance stamping
│   ├── evaluate.py         # ranker comparison + RQ1 context ablation
│   ├── compare_adapters.py # base vs fine-tuned adapter comparison
│   └── training_data/      # dataset construction + QLoRA training
├── vulnerable-apps/        # Intentionally vulnerable targets (Flask, FastAPI)
└── docs/research/          # 13 research documents (in progress)
```

**LLM:** Qwen2.5-Coder 3B Q4_K_M via Ollama (~2 GB VRAM). All inference runs locally.  
**Scanners:** Bandit (Python SAST) + Trivy (dependency CVEs + secrets).  
**Context:** structural analysis only — route attribution and middleware names, no taint tracking. A finding is attributed to the handler whose body encloses it; where it is reached only through an import, the least-guarded reachable route is reported, since that is the actual exposure.

## Fine-tuning

Two QLoRA adapters were trained on Qwen2.5-Coder-3B-Instruct (4-bit NF4, LoRA rank 16 / alpha 32, 7 target modules, 29.9M trainable parameters). The v3 dataset is 4,878 security fix pairs drawn from CVEfixes, CrossVul and SecuCoder.

Adapters are **not** in this repository — `adapter_model.safetensors` is 120 MB, past GitHub's file limit. They are distributed via the Hugging Face Hub.

**Result: neither adapter beat the un-finetuned base model.** Measured across 5 vulnerability classes and 2 prompt shapes with `benchmarks/compare_adapters.py`:

| model | structural score | invented identifiers per patch |
|---|---|---|
| base | **1.000** | **1.5** |
| v2 | 0.850 | 5.7 |
| v3 | 0.950 | 7.9 |

The cause is distributional. Only 20.5% of the training pairs are minimal fixes (one hunk, ≤2 added lines); the median target diff adds 5 lines and the mean 8.1, because CVEfixes contains real commits with refactors and tests alongside the fix. The model learned that shape and hallucinates surrounding code when asked for a one-line patch.

This also shows the structural score is inadequate as a quality gate: all three models scored 1.00 on the same SQL injection case, while only the base model produced a usable patch. The confidence threshold in `llm/router.py` checks diff *syntax*, not whether the vulnerability is fixed.

## Evaluation

Ground truth is annotated by two independent annotators, with Cohen's κ gating acceptance at ≥ 0.6. `annotate.py --make-blind` produces a template with the other annotator's columns stripped, so agreement is measured between genuinely independent judgements, and every ground-truth row records how it was produced (`annotation_mode`) — a claim of human review is refused unless the per-row review markers are present.

Known limitations, stated rather than worked around:

- The dataset contains only findings a scanner **reported**, so it measures precision, not recall. Two real path traversals in the Flask target went unflagged by Bandit.
- There is no JavaScript SAST. JS targets therefore produce findings only from dependency manifests, which carry no route context. Semgrep would close this.
- Precision@K saturates at the base rates reached so far; AUC-ROC is the usable metric, and at these sample sizes a single label change can invert which ranker leads.

## Security Constraints

- Tree-sitter parses source files; no `eval()` or `exec()` on repo code
- File snippets passed to the LLM are wrapped in explicit delimiters with an untrusted-content notice
- `repo_path` must resolve under an allowed root before any file read. Roots come from `SENTINEL_ALLOWED_ROOTS` (os-pathsep separated) and default to the user's home directory; `resolve()` collapses symlinks and `..`, so confinement cannot be escaped by a crafted path
- Scanner output parsed as JSON; never `eval()`d
- Trivy secrets stored as type + location only — no raw secret values
- Patches are proposals only; `requires_developer_action` is always `True`

## Team

| Member | Areas |
|--------|-------|
| Ammar Ahmed Abbasi | MCP server, orchestration |
| Muhammad Alam | Scanners, context graph |
| Marif Ahmed | LLM adapter, ranker, ML experiment |
| Shaheer ul Ibrahim | Verification, audit, evaluation harness |

**Supervisor:** Dr. Lubna Aziz  
**Institution:** Iqra University — FYP-II, 2025–26
