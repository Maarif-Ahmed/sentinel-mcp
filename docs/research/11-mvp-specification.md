# 11 — MVP Specification

## 1. Scope

The Sentinel MVP is a locally-running MCP server that provides security analysis assistance via seven tools. It integrates with Claude Code (and any MCP-compatible AI client) to deliver a scan → explain → propose → verify workflow on Python and JavaScript repositories.

**In scope:** The seven tools listed below, their inputs, outputs, and acceptance criteria.

**Out of scope (explicitly not built):**
- Patch auto-apply
- Web UI or web dashboard
- Cloud deployment
- Multi-user or multi-machine deployment
- CI/CD pipeline integration
- Language support beyond Python (Bandit) and Node.js (context graph)
- Semgrep adapter

---

## 2. Tool Contracts

### 2.1 `sentinel.ping`

**Purpose:** Health check. Confirms the server is running and reachable.

**Input:** None.

**Output:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

**Acceptance criteria:**
- Returns `status: "ok"` within 1 second.
- Returns `status: "error"` with a message if any dependency check fails (optional).

---

### 2.2 `sentinel.scan_repository`

**Purpose:** Run Bandit and Trivy on a local repository. Return ranked security findings.

**Input:**
```json
{
  "repo_path": "C:/path/to/repository"
}
```

**Output:**
```json
{
  "scan_id": "<uuid>",
  "findings": [
    {
      "finding_id": "<uuid>",
      "canonical_id": "<sha256>",
      "rule_id": "B105",
      "scanner": "bandit",
      "severity": "medium",
      "confidence": "high",
      "file_path": "app/auth.py",
      "line_start": 42,
      "line_end": 42,
      "message": "Possible hardcoded password",
      "snippet": "SECRET_KEY = 'dev-secret'",
      "cwe_id": "CWE-259",
      "context": {
        "route_path": null,
        "http_methods": [],
        "has_authenticated_middleware": false,
        "is_publicly_exposed_route": false
      },
      "risk_score": 3.2
    }
  ],
  "summary": {
    "total": 12,
    "by_severity": {"high": 2, "medium": 7, "low": 3},
    "by_scanner": {"bandit": 10, "trivy": 2}
  }
}
```

**Acceptance criteria:**
- Completes within 300 seconds (timeout enforced on scanner subprocesses).
- Returns at least one finding for a repository containing `tests/fixtures/vulnerable_flask.py`.
- Findings are sorted by `risk_score` descending.
- `canonical_id` is stable across runs for the same file/line/CWE combination.
- No duplicate `canonical_id` values in a single scan.

---

### 2.3 `sentinel.explain_finding`

**Purpose:** Generate a plain-English explanation of a finding using the local LLM.

**Input:**
```json
{
  "finding_id": "<uuid>",
  "repo_path": "C:/path/to/repository"
}
```

**Output:**
```json
{
  "finding_id": "<uuid>",
  "explanation": "This finding flags a hardcoded password string...",
  "model": "qwen2.5-coder:3b"
}
```

**Acceptance criteria:**
- Returns an explanation within 60 seconds.
- Explanation references the specific rule ID and file.
- Returns a clear error if Ollama is unreachable.

---

### 2.4 `sentinel.propose_fix`

**Purpose:** Generate a unified diff patch for a finding using the local LLM.

**Input:**
```json
{
  "finding_id": "<uuid>",
  "repo_path": "C:/path/to/repository"
}
```

**Output:**
```json
{
  "proposal_id": "<uuid>",
  "finding_id": "<uuid>",
  "patch_diff": "--- a/app/auth.py\n+++ b/app/auth.py\n@@ -42,1 +42,1 @@\n-SECRET_KEY = 'dev-secret'\n+SECRET_KEY = os.environ.get('SECRET_KEY')\n",
  "generated_by": "qwen2.5-coder:3b+difflib",
  "requires_developer_action": true,
  "warning": "This patch is LLM-generated and must be reviewed before application."
}
```

**Acceptance criteria:**
- `requires_developer_action` is always `true`. Cannot be overridden.
- `patch_diff` is a valid unified diff (parseable by `patch -p1`).
- Diff covers the finding's line number (within 5 lines).
- If no valid diff can be generated, returns `patch_diff: null` with a `reason` field.
- `generated_by` field indicates the generation path (rule_based / model+difflib / model).

---

### 2.5 `sentinel.verify_proposal`

**Purpose:** Syntax-check and rescan a proposed patch to assess whether the finding is cleared.

**Input:**
```json
{
  "proposal_id": "<uuid>",
  "repo_path": "C:/path/to/repository"
}
```

**Output:**
```json
{
  "proposal_id": "<uuid>",
  "syntax_ok": true,
  "rescan_clear": true,
  "overall": "undetected_by_rescan",
  "disclaimer": "Rescan clear does not prove the vulnerability is fixed. Manual review required."
}
```

`overall` values: `"undetected_by_rescan"` | `"still_detected"` | `"syntax_error"` | `"inconclusive"`.

**Acceptance criteria:**
- `disclaimer` is always present and non-empty. Cannot be removed.
- `syntax_ok: false` when a Python patch introduces invalid syntax.
- `rescan_clear: true` when a correct patch is applied to a fixture file.
- `rescan_clear: false` when an incorrect patch is applied.

---

### 2.6 `sentinel.get_audit_history`

**Purpose:** Retrieve recent audit events for a repository.

**Input:**
```json
{
  "repo_path": "C:/path/to/repository",
  "limit": 20
}
```

**Output:**
```json
{
  "events": [
    {
      "event_id": "<uuid>",
      "timestamp": "2024-10-31T12:00:00Z",
      "event_type": "scan",
      "repo_path": "C:/path/to/repository",
      "finding_canonical_id": null,
      "action": "scan_repository",
      "outcome": "ok",
      "metadata": {"total_findings": 12}
    }
  ]
}
```

**Acceptance criteria:**
- Returns events in reverse-chronological order.
- Events include `scan`, `explain`, `propose`, and `verify` event types.
- Respects `limit` parameter (default 20, maximum 100).

---

### 2.7 `sentinel.report`

**Purpose:** Generate a JSON and HTML report of the last scan.

**Input:**
```json
{
  "repo_path": "C:/path/to/repository",
  "output_path": "C:/path/to/output"
}
```

**Output:**
```json
{
  "json_path": "C:/path/to/output/report.json",
  "html_path": "C:/path/to/output/report.html",
  "finding_count": 12
}
```

**Acceptance criteria:**
- `report.html` is a valid single-file HTML document (no external dependencies).
- HTML includes a severity breakdown section and a findings table.
- Both files are written to `output_path`.

---

## 3. Scope Classifications

For each feature, the scope classification records whether it was in, out, or deferred.

| Feature | Classification | Reason |
|---|---|---|
| `sentinel.ping` | In scope | Gate for environment verification |
| `sentinel.scan_repository` (Bandit) | In scope | Core MVP requirement |
| `sentinel.scan_repository` (Trivy) | In scope | Core MVP requirement |
| Context graph (Express.js) | In scope | Core differentiator |
| `sentinel.explain_finding` | In scope | Core MVP requirement |
| `sentinel.propose_fix` | In scope | Core MVP requirement |
| `sentinel.verify_proposal` | In scope | Core MVP requirement |
| `sentinel.get_audit_history` | In scope | Core MVP requirement |
| `sentinel.report` | In scope | FYP-II deliverable |
| Patch auto-apply | **Out of scope** | Security risk; hard constraint |
| Web dashboard | **Out of scope** | Replaced by CLI + HTML report |
| Cloud LLM integration | **Out of scope** | Privacy constraint |
| Semgrep adapter | **Deferred** | Stability work on Bandit+Trivy took priority |
| Flask/FastAPI context graph | **Deferred** | Express.js scope sufficient for benchmark |
| Multi-file patch support | **Deferred** | Single-file diffs sufficient for known findings |
