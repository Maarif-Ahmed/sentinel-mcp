# 02 — Literature and Tools Review

## 1. Static Application Security Testing (SAST) Tools

### 1.1 Bandit

Bandit is an open-source Python SAST tool developed by the OpenStack Security Project and now maintained by PyCQA. It performs AST-based analysis using a plugin architecture where each plugin tests for a specific weakness (e.g., B301 for pickle usage, B311 for non-cryptographic random, B501 for weak TLS).

**Strengths relevant to Sentinel:**
- JSON output (`bandit -r -f json`) is stable and well-documented.
- Apache 2.0 licence — no redistribution concerns.
- Fast: scans thousands of lines in under a second.
- No taint tracking — findings are local and do not require inter-procedural analysis, making them easier to explain with a small LLM.

**Limitations:**
- High false-positive rate for B311 (flags all `random` usage regardless of context).
- No cross-file data flow — cannot detect SQL injection through function call chains.
- Python only.

### 1.2 Semgrep Community Edition

Semgrep uses pattern-matching rules written in a YAML DSL with support for cross-file taint tracking via dataflow analysis. The community edition (CE) includes a large rule registry covering Python, JavaScript, Java, Go, and more.

**Why deferred to FYP-II:**
- The CE rule registry licence requires careful handling when the repository is published publicly (some rules carry non-commercial restrictions).
- Taint-tracking results are harder for a 3B LLM to explain accurately — the attack path spans multiple files.
- Adding a third scanner in FYP-I would crowd out context graph work during the critical weeks 8–10.

### 1.3 CodeQL

CodeQL is GitHub's semantic code analysis engine. It compiles source code into a queryable database and supports custom queries in QL.

**Why excluded:**
- The CodeQL licence (GitHub CodeQL Terms of Service) restricts use to open-source projects or paid GitHub Advanced Security subscriptions. Publishing Sentinel's findings output could constitute a derivative work in a legally ambiguous way.
- Requires a full compilation step — incompatible with rapid scan-on-demand use.

---

## 2. Dependency and Secrets Scanners

### 2.1 Trivy

Trivy (Aqua Security, Apache 2.0) is a comprehensive scanner covering OS packages, language dependencies (pip, npm, Maven), IaC misconfigurations, and secrets. It operates against a local vulnerability database that self-updates.

**Strengths:**
- Single binary, no external service calls after database download.
- `--format json` output is machine-readable and detailed.
- Detects secrets (API keys, tokens) by pattern matching — stored in findings as type + location only (no raw secret values, per Sentinel's threat model).

**Limitations:**
- CVE severity comes from NVD/OSV — not context-aware. A critical CVE in a development dependency that never ships is ranked the same as a runtime one.
- Sentinel addresses this partially with the `is_dev_dependency` feature in the ML ranker.

### 2.2 Snyk

Snyk is a commercial SaaS dependency scanner with a free tier. It offers deeper fix suggestions and a large proprietary vulnerability database.

**Why not used:**
- Requires source code upload to Snyk's servers — incompatible with Sentinel's local-only principle.
- Free tier rate limits make automated scanning impractical.

### 2.3 pip-audit / Safety

`pip-audit` (PyPA) and `Safety` (pyup.io) both check Python dependencies against PyPI advisory databases.

**Why not used:**
- Both are Python-only; Sentinel targets polyglot repositories.
- Trivy's Python coverage is equivalent for the FYP scope.

---

## 3. LLM-Assisted Security Tools

### 3.1 GitHub Copilot

GitHub Copilot provides inline code completions and, in its chat interface, can answer security questions about selected code. It does not integrate with SAST scanner output and has no structured finding or patch proposal format.

**Key difference from Sentinel:** Copilot is reactive (developer asks) and has no scanner-grounded findings. Sentinel is proactive (scans autonomously) and grounds all LLM output in structured scanner data.

### 3.2 Cursor

Cursor is an AI-first code editor that exposes codebase context to an LLM. It can be configured with MCP servers — this is Sentinel's primary integration target. Cursor does not run security scanners by default.

### 3.3 Snyk DeepCode AI

Snyk's DeepCode AI uses LLMs to generate fix suggestions for Snyk findings. It requires a Snyk account and sends code to Snyk's servers.

**Key difference from Sentinel:** DeepCode is cloud-based, tied to the Snyk ecosystem, and not accessible through MCP. Sentinel is local, scanner-agnostic (Bandit + Trivy today, extensible), and natively MCP-native.

---

## 4. The Model Context Protocol (MCP)

MCP (Anthropic, 2024) is an open protocol for connecting AI clients to tool servers. It uses a client–server architecture over stdio or HTTP with Server-Sent Events (SSE). The server exposes **tools** (callable functions with JSON schema), **resources** (readable data), and **prompts** (templated text). The client is any MCP-compatible AI application.

**Why MCP for Sentinel:**
- Decouples the security analysis engine from any specific AI client.
- The same Sentinel server works with Claude Code, Cursor, and any future MCP client without code changes.
- The Python `mcp` SDK v2 handles protocol framing, JSON-RPC dispatch, and schema generation from Pydantic models automatically.
- stdio transport requires no daemon management or port configuration.

---

## 5. Local LLM Infrastructure

### 5.1 Ollama

Ollama is a local LLM runtime (MIT licence) that exposes an OpenAI-compatible REST API at `localhost:11434`. It handles model quantization loading, GPU memory management, and request queuing. Sentinel uses the `/v1/chat/completions` endpoint with `stream: false`.

**Key inference parameters tuned in Sentinel:**
- `temperature: 0.1` — low for deterministic, conservative code output.
- `top_p: 0.9` — nucleus sampling to avoid degenerate tokens.
- `repeat_penalty: 1.1` — discourages repetitive output.

### 5.2 Qwen2.5-Coder 3B Q4_K_M

Qwen2.5-Coder (Alibaba Cloud, Apache 2.0) is a family of code-specialized LLMs fine-tuned from Qwen2.5 on a large corpus of code, commit messages, and documentation. The 3B parameter variant quantized to Q4_K_M (~2 GB) fits entirely on the RTX 4050's 6 GB VRAM.

**Capability profile for patch generation:**
- Strong at single-line code changes when given precise context.
- Weak at multi-line refactors or cross-file changes.
- Tends to drift to nearby code when the exact vulnerable line is not clearly marked.
- Mitigated in Sentinel via `>>>` line markers, two-phase prompting, and OLD→NEW + difflib reconstruction.

---

## 6. Competitor Matrix

The following matrix compares Sentinel against three established tools on criteria relevant to the FYP research questions.

| Criterion | Sentinel MCP | GitHub Advanced Security | Snyk | SonarQube CE |
|---|---|---|---|---|
| **Runs fully locally** | ✅ Yes | ❌ Cloud (GitHub.com) | ❌ Cloud SaaS | ✅ Self-hosted |
| **MCP integration** | ✅ Native | ❌ No | ❌ No | ❌ No |
| **Patch proposals** | ✅ Unified diff | ✅ Autofix (limited) | ✅ Fix PRs | ❌ Suggestions only |
| **Auto-applies patches** | ❌ No (by design) | ✅ Yes (Autofix) | ✅ Yes (Fix PRs) | ❌ No |
| **Context-aware ranking** | ✅ Route + middleware | ❌ No | ❌ No | ❌ No |
| **LLM explanation** | ✅ Local Qwen 3B | ✅ Copilot (cloud) | ✅ DeepCode (cloud) | ❌ No |
| **Python SAST** | ✅ Bandit | ✅ CodeQL | ✅ Semgrep | ✅ Rules-based |
| **Dependency CVEs** | ✅ Trivy | ✅ Dependabot | ✅ Yes | ✅ Via plugins |
| **Secrets detection** | ✅ Trivy | ✅ Secret scanning | ✅ Yes | ✅ Via plugins |
| **Source privacy** | ✅ Local only | ❌ GitHub servers | ❌ Snyk servers | ✅ Self-hosted |
| **Cost** | ✅ Free / open source | 💰 Paid (private repos) | 💰 Free tier limited | ✅ Free CE |
| **Cross-file taint** | ❌ No | ✅ CodeQL | ✅ Semgrep | ✅ Dataflow rules |
| **JavaScript SAST** | ❌ Context only | ✅ Yes | ✅ Yes | ✅ Yes |

**Where Sentinel is stronger:** Local privacy, MCP-native integration, context-aware route ranking, no auto-apply (safety by design).

**Where Sentinel is weaker:** No cross-file taint tracking, Python SAST only (Bandit), no JavaScript SAST (only route context extraction), smaller rule set than CodeQL/Semgrep.

---

## 7. Related Academic Work

| Work | Relevance |
|---|---|
| Li et al. (2023) — *Large Language Models for Code Security* | Establishes that LLMs can suggest patches for simple CWEs but struggle with multi-step vulnerabilities; motivates the 3B scope limitation. |
| Pearce et al. (2022) — *Examining Zero-Shot Vulnerability Repair with LLMs* | Shows GPT-4 repairs ~65% of simple buffer overflows zero-shot; 3B models significantly lower. Motivates the nosec fast path and OLD→NEW reconstruction. |
| Chakraborty et al. (2022) — *Deep Learning Based Vulnerability Detection* | Graph neural network approaches require compilation; motivates AST-only (Bandit) for FYP scope. |
| OWASP Top 10 (2021) | Defines the CWE categories used in Sentinel's rule-based ranker and ground truth annotation. |
| Joh & Malaiya (2010) — *Incorporating Vulnerability Discovery Models* | Background on vulnerability severity scoring; motivates going beyond CVSS for context-sensitive ranking. |
