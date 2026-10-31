# Sentinel MCP — Research Documents

This directory contains the research document set for the Sentinel MCP FYP project. These documents cover the full arc from project motivation to implementation decisions and evaluation methodology.

---

## Document Index

| # | Document | Summary |
|---|---|---|
| 01 | [Project Overview](01-project-overview.md) | What Sentinel is, what problem it solves, and who it is for |
| 02 | [Literature and Tools Review](02-literature-and-tools-review.md) | SAST landscape, MCP protocol, local LLM options, prior work |
| 03 | [Architecture Options](03-architecture-options.md) | Three candidate architectures evaluated; Cloud GPT-4 and auto-apply rejected |
| 04 | [Recommended Architecture](04-recommended-architecture.md) | Component inventory, data models, MCP tool contracts, sequence diagram |
| 05 | [End-to-End Workflow](05-end-to-end-workflow.md) | Seven-stage pipeline from scan to report; state machine; data flow |
| 06 | [AI/ML Strategy](06-ai-ml-strategy.md) | LLM selection, prompt engineering techniques, ML ranker design |
| 07 | [Security and Threat Model](07-security-and-threat-model.md) | STRIDE analysis, trust boundaries, controls implemented |
| 08 | [30-Week Roadmap](08-30-week-roadmap.md) | Milestone table, team ownership, critical path, completed vs planned |
| 09 | [Testing and Evaluation](09-testing-and-evaluation.md) | RQ1–RQ4 methods, OWASP Juice Shop benchmark, ground truth construction |
| 10 | [Cost and Deployment](10-cost-and-deployment.md) | Zero cloud cost, hardware requirements, installation steps, Windows notes |
| 11 | [MVP Specification](11-mvp-specification.md) | Seven MCP tool contracts, input/output schemas, acceptance criteria |
| 12 | [Risk Register](12-risk-register.md) | Technical, research, and schedule risks with mitigations and status |
| 13 | [Sources and Decisions](13-sources-and-decisions.md) | Architecture decision records (ADRs 001–005), source register |

---

## Quick Navigation

**Starting from scratch?** Read [01](01-project-overview.md) → [03](03-architecture-options.md) → [04](04-recommended-architecture.md).

**Evaluating the project?** Read [09](09-testing-and-evaluation.md) (RQ methods) → [06](06-ai-ml-strategy.md) (ML ranker) → [08](08-30-week-roadmap.md) (milestone status).

**Setting up the system?** Read [10](10-cost-and-deployment.md) (installation) → [11](11-mvp-specification.md) (tool contracts).

**Understanding security decisions?** Read [07](07-security-and-threat-model.md) → [13](13-sources-and-decisions.md) (ADRs).

**Writing the dissertation?** All documents are structured to serve as first-draft material. Start with the document whose section corresponds to your dissertation chapter.

---

## Key Facts

- **Language:** Python 3.12
- **LLM:** Qwen2.5-Coder 3B Q4_K_M via Ollama (local, no cloud)
- **Scanners:** Bandit (Python SAST) + Trivy (dependencies + secrets)
- **Context graph:** Express.js routes and middleware via tree-sitter
- **ML dataset:** N=79 annotated findings (OWASP Juice Shop)
- **Patch auto-apply:** Out of scope (by design)
- **Cloud cost:** Zero

---

## Team

| Member | ID | Areas |
|---|---|---|
| Ammar Ahmed Abbasi | 63199 | MCP server, orchestrator |
| Muhammad Alam | 64759 | Scanner adapters, context graph |
| Marif Ahmed | 61208 | LLM adapter, ranker, patch generator |
| Shaheer ul Ibrahim | 58512 | Verification, audit log, evaluation |
