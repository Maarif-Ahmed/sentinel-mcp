# 03 — Architecture Options

## 1. Overview

Three candidate architectures were evaluated before settling on the final design. Each was assessed against five criteria: **privacy**, **cost**, **safety**, **FYP scope fit**, and **hardware fit**. This document records the options and the decision rationale.

---

## 2. Option A — Cloud-Based Agent with GPT-4

### Description

A cloud-hosted web service that accepts a repository URL, clones it, runs scanners, and sends findings + code snippets to the OpenAI GPT-4 API for explanation and patch generation. Results are returned via a REST endpoint or webhook.

```
Developer → REST API → Clone repo → Bandit/Trivy → GPT-4 API → Patch diff
```

### Claimed Advantages

- GPT-4 produces significantly higher-quality patches than a 3B local model.
- No GPU hardware required on the developer's machine.
- Easier to scale (stateless request handler).

### Rejection Reasons

| Criterion | Assessment |
|---|---|
| **Privacy** | ❌ Source code uploaded to OpenAI servers. Unacceptable for any proprietary or sensitive codebase. |
| **Cost** | ❌ GPT-4 API: ~$0.03/1K tokens. A typical scan of 1000 findings × 2000 tokens each = ~$60 per scan. Unsustainable for a free tool. |
| **Safety** | ⚠️ Auto-apply was proposed for this option but creates unacceptable risk. |
| **FYP scope fit** | ❌ Building a cloud service introduces infrastructure, auth, rate-limiting, and billing concerns far outside the research scope. |
| **Hardware fit** | ✅ No local GPU needed — but irrelevant given the privacy rejection. |

**Decision: Rejected.** Privacy and cost are non-negotiable disqualifiers.

---

## 3. Option B — Full Autonomous Agent with Auto-Apply and Test Runner

### Description

A local agent (similar to Devin or SWE-agent) that scans the repository, generates patches, automatically applies them, runs the project's test suite to validate, and commits passing fixes.

```
Scan → Generate patch → git apply → npm test / pytest → git commit (if tests pass)
```

### Claimed Advantages

- Fully automated: developer reviews only the final diff, not intermediate steps.
- Test runner provides a stronger confidence signal than rescan-only verification.
- Closer to the "AI developer" vision in the literature.

### Rejection Reasons

| Criterion | Assessment |
|---|---|
| **Privacy** | ✅ Can be local. |
| **Cost** | ✅ Local LLM, no API cost. |
| **Safety** | ❌ Auto-applying patches from a 3B LLM to production code is dangerous. The model produces plausible-looking but incorrect patches (e.g., adding `verify=False` to requests, observed in testing). An automated commit of such a patch could introduce new vulnerabilities. |
| **FYP scope fit** | ❌ Implementing a reliable test runner integration requires: sandboxed subprocess management, dependency installation, timeout handling, output parsing for every test framework (pytest, Jest, Mocha, unittest). This is a project in itself. |
| **Hardware fit** | ⚠️ Running tests adds significant latency to every patch attempt — 30+ seconds for a typical test suite on a laptop. |

**Decision: Rejected.** Auto-apply from a small LLM is unsafe. Test runner integration is out of scope.

---

## 4. Option C — Local MCP Server, Proposals Only (Chosen)

### Description

A local stdio MCP server that exposes security analysis as tools to any MCP-compatible AI client. Scanners run as subprocesses. Context extraction uses tree-sitter. LLM inference runs via Ollama. Patches are unified diffs displayed to the developer for manual review and application.

```
AI Client (Claude Code / Cursor)
    │  MCP stdio
    ▼
sentinel.scan_repository → Bandit + Trivy (subprocess) → Normalize → Context → Rank
sentinel.explain_finding → Ollama (Qwen 3B) → Explanation
sentinel.propose_fix     → Ollama (Qwen 3B) → Unified diff (display only)
sentinel.verify_proposal → Syntax check + Bandit rescan
```

### Why This Architecture Was Chosen

| Criterion | Assessment |
|---|---|
| **Privacy** | ✅ All processing local. Source code never leaves the machine. |
| **Cost** | ✅ Zero ongoing cost. Open-source components, local inference. |
| **Safety** | ✅ No auto-apply. `requires_developer_action` enforced in the data model. Developer reviews every diff before `git apply`. |
| **FYP scope fit** | ✅ MCP server + 7 tools is well-scoped for a 4-person team over 30 weeks. Research questions are answerable within the architecture. |
| **Hardware fit** | ✅ Qwen2.5-Coder 3B Q4_K_M: ~2 GB VRAM, fits RTX 4050 with headroom. |

---

## 5. Decision Matrix

| Criterion | Weight | Option A (Cloud/GPT-4) | Option B (Auto-apply) | Option C (Local MCP) |
|---|---|---|---|---|
| Privacy | 30% | 0 | 3 | 3 |
| Cost | 20% | 0 | 3 | 3 |
| Safety | 25% | 1 | 0 | 3 |
| FYP scope fit | 15% | 0 | 1 | 3 |
| Hardware fit | 10% | 3 | 1 | 3 |
| **Weighted total** | | **0.55** | **1.75** | **3.00** |

*Scores: 0 = fails criterion, 1 = partial, 3 = fully satisfies.*

Option C scores perfectly on all criteria relevant to the project constraints.

---

## 6. Key Architectural Decisions Within Option C

Having selected Option C, several further decisions were made:

| Decision | Choice | Alternative Considered | Reason |
|---|---|---|---|
| Transport | stdio | HTTP/SSE | stdio requires no port, no daemon, simpler Windows setup |
| LLM runtime | Ollama | llama.cpp directly | Ollama provides OpenAI-compatible API, easier to swap models |
| Scanner output | JSON | SARIF | JSON is simpler to parse; SARIF is richer but adds a dependency |
| Context graph | NetworkX (in-memory) | Neo4j | No infrastructure; file-level graphs are small enough |
| Patch format | Unified diff | JSON patch / AST diff | Unified diff is human-readable, `patch` tool applies it directly |
| Verification | Syntax + rescan | Full test suite | Test runner is out of scope; rescan is reproducible and sufficient |
| Storage | SQLite stdlib | PostgreSQL / Redis | Zero infrastructure; audit log is append-only, single-writer |
