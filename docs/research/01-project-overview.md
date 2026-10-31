# 01 — Project Overview

## 1. What Is Sentinel MCP?

Sentinel MCP is a local, privacy-preserving security analysis agent for web application repositories. It integrates with AI-assisted development environments (Claude Code, Cursor, any Model Context Protocol-compatible client) to run security scanners, extract structural code context, explain findings in plain language, propose patch diffs, and verify that a manually-applied patch removes the flagged vulnerability.

The system is implemented as a **Model Context Protocol (MCP) server** — a lightweight stdio-transport process that exposes seven tools to a connected AI client. The developer never leaves their editor; they ask their AI assistant to scan a repository, and Sentinel handles the rest.

**Source code never leaves the developer's machine.** All LLM inference runs against a locally-hosted model via Ollama. No network calls are made to external services unless the developer explicitly copies output into a cloud AI client.

---

## 2. The Problem Being Solved

### 2.1 The Developer Security Tooling Gap

Modern web applications are routinely deployed with known vulnerabilities — not because developers are careless, but because the feedback loop between writing code and receiving security guidance is broken:

- **SAST tools** (Bandit, Semgrep) run in CI, far from the moment of writing. Findings arrive as line items in a report with no explanation and no fix.
- **Dependency scanners** (Trivy, Snyk) produce CVE lists that developers cannot act on without understanding which route exposes the vulnerable package.
- **LLM coding assistants** (GitHub Copilot, Cursor) provide general-purpose code suggestions but have no awareness of security scanner output or the structural context of findings.

The result: a security finding sits in a JIRA ticket for weeks, the developer who sees it lacks the domain knowledge to fix it quickly, and the window of exposure grows.

### 2.2 What Sentinel Does Differently

Sentinel closes this loop by:

1. Running security scanners programmatically against the repository.
2. Enriching each finding with **structural context** — which Express.js route exposes the vulnerable code, what middleware is declared before the handler.
3. Ranking findings by combined severity + context risk score.
4. Providing an **LLM-generated explanation** of why the finding is dangerous and what a fix looks like.
5. Proposing a **unified diff patch** for the developer to review and apply manually.
6. Verifying that the applied patch removes the finding from a subsequent scan.

Every step runs locally. Every patch is advisory. The developer retains full control.

---

## 3. Scope Boundaries

### 3.1 What Sentinel Does

| Capability | Detail |
|---|---|
| Python SAST | Bandit — AST-based static analysis |
| Dependency + secrets scanning | Trivy — CVE database + secret patterns |
| Express.js route context | tree-sitter CST parsing, route + middleware extraction |
| Risk ranking | Rule-based weighted scorer + ML ranker (Logistic Regression / Random Forest) |
| LLM explanation | Qwen2.5-Coder 3B Q4_K_M via Ollama |
| Patch proposal | Unified diff (display only, never auto-applied) |
| Patch verification | Syntax check + Bandit rescan on patched file copy |
| Audit log | SQLite append-only event log |
| Report generation | JSON + static single-file HTML |

### 3.2 What Sentinel Does NOT Do

| Out of Scope | Reason |
|---|---|
| Auto-apply patches | Safety — developer must review every change |
| Run project test suite | Scope — verification is rescan only |
| Web dashboard / React frontend | Replaced with `sentinel report` CLI |
| Cloud LLM API calls | Privacy — source code stays local |
| CodeQL integration | Licensing complexity |
| Training an LLM from scratch | Hardware and time infeasible |
| Multi-project hosted SaaS | Out of FYP scope |
| Flask/FastAPI context graph | FYP-II extension only |
| Semgrep CE adapter | Deferred to FYP-II (licensing + time) |

---

## 4. Team and Supervision

| Role | Name | Student ID | Primary Areas |
|---|---|---|---|
| Team Member | Ammar Ahmed Abbasi | 63199 | MCP server, tool dispatch, orchestrator, MCP protocol compliance |
| Team Member | Muhammad Alam | 64759 | Scanner adapters, normalizer, context graph (tree-sitter + NetworkX) |
| Team Member | Marif Ahmed | 61208 | LLM adapter, rule-based ranker, ML ranker experiment, patch generator |
| Team Member | Shaheer ul Ibrahim | 58512 | Verification, audit log, report generator, evaluation harness |
| Supervisor | Dr. Lubna Aziz | — | Academic supervision |

---

## 5. Hardware Environment

| Component | Specification |
|---|---|
| GPU | NVIDIA RTX 4050 Laptop GPU, 6 GB VRAM |
| RAM | 16 GB |
| OS | Windows 11 Home 10.0.26300 |
| Python | 3.12.12 |
| Ollama | 0.40.13 |
| Primary LLM | Qwen2.5-Coder 3B Q4_K_M (~2 GB VRAM) |

The 3B model was chosen specifically because it fits entirely on-GPU within the 6 GB constraint, leaving headroom for the OS and scanner processes. The 7B variant (~6.7 GB) partially offloads to CPU and is used only for the RQ4 latency/VRAM benchmark.

---

## 6. Timeline Summary

| Phase | Weeks | Status |
|---|---|---|
| FYP-I: Foundation + Scanner + Context | 1–10 | ✅ Complete |
| FYP-I: Ranker + LLM + Patch + Verify | 11–14 | ✅ Complete |
| FYP-I: Integration + Audit + Demo | 15–16 | ✅ Complete |
| FYP-II: Evaluation harness + Ground truth | 17–18 | ✅ Complete |
| FYP-II: ML ranker experiment | 19–21 | ✅ Complete |
| FYP-II: RQ4 LLM benchmark | 22–23 | ✅ Complete |
| FYP-II: Report generator CLI | 25–26 | ✅ Complete |
| FYP-II: Research documents | 27–28 | 🔄 In progress |
| FYP-II: Final report + submission | 29–30 | ⬜ Pending |

---

## 7. Key Design Principles

**Local-first.** Every component runs on the developer's machine. No source code is transmitted externally.

**Advisory only.** Patches are diffs for human review. `requires_developer_action` is enforced as always `True` in the data model.

**Transparent ranking.** The rule-based ranker exposes every feature and weight. The ML ranker reports `feature_breakdown` on every assessment.

**Honest claims.** The context graph makes two structural claims (file attribution, middleware names declared before handler) and explicitly disclaims everything else in every `ContextAnnotation`.

**Reproducible evaluation.** All research questions are answered with objective metrics against a known ground truth (OWASP Juice Shop documented vulnerabilities), not human relevance ratings.
