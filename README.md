# Sentinel MCP

A context-aware AI agent for automated web application security analysis and verified remediation.

Sentinel integrates with compatible AI development clients via the [Model Context Protocol](https://modelcontextprotocol.io/). It runs security scanners locally, extracts structural context from Express.js routes, explains findings with a local LLM, and proposes patch diffs for developer review.

**Source code never leaves your machine.** No cloud API calls. No automatic patches.

## Status

✅ Week 1–2: Foundation — `sentinel.ping` gate  
✅ Week 3–7: Scanner adapters (Bandit + Trivy) + normalizer  
✅ Week 8–10: Express.js context graph (tree-sitter)  
✅ Week 11–12: LLM explanation (Ollama / Qwen2.5-Coder 3B)  
✅ Week 13–14: Patch proposal + verification  
✅ Week 15–16: Audit log + `sentinel report` CLI  
✅ Week 17–18: Evaluation harness + ground truth annotation  
✅ Week 19–21: ML ranker (Logistic Regression + Random Forest, N=79)  
✅ Week 22–23: RQ4 LLM latency + VRAM benchmarks  
✅ Week 25–26: Report generator CLI + HTML severity breakdown  
⬜ Week 27–28: Research documents (`docs/research/`)  
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

## Architecture

```
sentinel-mcp/
├── src/sentinel/
│   ├── server.py           # MCP server, tool registration
│   ├── orchestrator.py     # Pipeline: scan → normalize → enrich → rank → explain
│   ├── scanners/           # Bandit + Trivy subprocess adapters
│   ├── normalizer.py       # RawFinding → SecurityFinding, deduplication
│   ├── context/            # tree-sitter Express.js route + middleware extraction
│   ├── ranker.py           # Rule-based severity ranker
│   ├── ml/                 # ML ranker (Logistic Regression / Random Forest)
│   ├── llm/                # Ollama provider (Qwen2.5-Coder 3B)
│   ├── remediation.py      # PatchGenerator → unified diff (no apply logic)
│   ├── verification.py     # Syntax check + rescan
│   ├── audit.py            # SQLite append-only audit log
│   ├── report.py           # JSON + HTML report generator
│   └── cli.py              # `sentinel` CLI entry point
├── benchmarks/             # Evaluation harness (Juice Shop ground truth, N=79)
├── vulnerable-apps/        # Intentionally vulnerable test apps
└── docs/research/          # 13 research documents (in progress)
```

**LLM:** Qwen2.5-Coder 3B Q4_K_M via Ollama (~2 GB VRAM). All inference runs locally.  
**Scanners:** Bandit (Python SAST) + Trivy (dependency CVEs + secrets).  
**Context:** tree-sitter parses Express.js routes — structural analysis only, no taint tracking.

## Security Constraints

- Tree-sitter parses source files; no `eval()` or `exec()` on repo code
- File snippets passed to the LLM are wrapped in explicit delimiters with an untrusted-content notice
- All `repo_path` values validated before any file read
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
**Institution:** FYP-II, 2025–26
