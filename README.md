# Sentinel MCP

A context-aware AI agent for automated web application security analysis and verified remediation.

Sentinel integrates with compatible AI development clients via the [Model Context Protocol](https://modelcontextprotocol.io/). It runs security scanners locally, extracts structural context from Express.js routes, explains findings with a local LLM, and proposes patch diffs for developer review.

**Source code never leaves your machine.** No cloud API calls. No automatic patches.

## Status

🔴 Week 1–2: Foundation — `sentinel.ping` gate  
⬜ Week 3–7: Scanner adapters (Bandit + Trivy)  
⬜ Week 8–10: Express.js context graph  
⬜ Week 11–12: LLM explanation (Ollama)  
⬜ Week 13–14: Patch proposal + verification  
⬜ Week 15–16: FYP-I demo

## Quick Start

See [docs/setup-windows.md](docs/setup-windows.md) for the complete Week 1–2 setup checklist.

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
sentinel ping     # must return {"status": "ok"} before proceeding
pytest tests/ -v
```

## MCP Tools

| Tool | Status | Description |
|------|--------|-------------|
| `sentinel.ping` | ✅ Ready | Environment health check |
| `sentinel.scan_repository` | 🔴 Stub | Scan with Bandit + Trivy |
| `sentinel.explain_finding` | 🔴 Stub | LLM-generated explanation |
| `sentinel.propose_fix` | 🔴 Stub | Patch diff proposal (display only) |
| `sentinel.verify_proposal` | 🔴 Stub | Syntax check + rescan |
| `sentinel.get_audit_history` | 🔴 Stub | SQLite audit log |
| `sentinel.report` | 🔴 Stub | Static HTML report |

## Team

| Member | Areas |
|--------|-------|
| Ammar Ahmed Abbasi | MCP server, orchestration |
| Muhammad Alam | Scanners, context graph |
| Marif Ahmed | LLM adapter, ranker |
| Shaheer ul Ibrahim | Verification, audit, evaluation |

**Supervisor:** Dr. Lubna Aziz

## Documentation

Research documents will be created in `docs/research/` after the Week 2 environment gate is confirmed.
