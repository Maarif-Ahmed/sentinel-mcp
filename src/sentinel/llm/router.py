"""
ModelRouter — task-to-model dispatch for the multi-model framework.

Assigns specialist small LLMs to each pipeline task based on documented
benchmark strengths. All models run locally via Ollama; only one model is
hot in VRAM at a time (RTX 4050, 6 GB).

Model assignments:
  classify_severity  → phi4-mini         (3.8B, ~4.5 GB) — best reasoning sub-4B
  explain_finding    → llama3.2:3b       (3B,   ~3.5 GB) — natural prose + structured output
  generate_patch     → qwen2.5-coder:3b  (3B,   ~3.5 GB) — 84.1% HumanEval, purpose-built
  validate_diff      → qwen2.5-coder:1.5b(1.5B, ~2.0 GB) — fast structural check
  fallback_patch     → qwen2.5-coder:7b  (7B,   ~8.7 GB) — partial offload, cascade only

Confidence scoring (patch proposals only):
  score = 0.6 × structural_score + 0.4 × self_rating
  threshold = 0.7 — below this, the router cascades to the fallback model.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sentinel.llm.base import LLMProviderError
from sentinel.llm.ollama import DEFAULT_BASE_URL, DEFAULT_TIMEOUT, OllamaProvider

if TYPE_CHECKING:
    from sentinel.schemas import SecurityFinding

# ---------------------------------------------------------------------------
# Task constants
# ---------------------------------------------------------------------------

TASK_CLASSIFY = "classify_severity"
TASK_EXPLAIN  = "explain_finding"
TASK_PATCH    = "generate_patch"
TASK_VALIDATE = "validate_diff"
TASK_FALLBACK = "fallback_patch"

CONFIDENCE_THRESHOLD = 0.7

# ---------------------------------------------------------------------------
# Model assignments and per-task inference parameters
# ---------------------------------------------------------------------------

_TASK_MODELS: dict[str, str] = {
    TASK_CLASSIFY: "phi4-mini",
    TASK_EXPLAIN:  "llama3.2:3b",
    TASK_PATCH:    "qwen2.5-coder:3b",
    TASK_VALIDATE: "qwen2.5-coder:1.5b",
    TASK_FALLBACK: "qwen2.5-coder:7b",
}

_TASK_PARAMS: dict[str, dict] = {
    TASK_CLASSIFY: {"temperature": 0.0, "max_tokens": 64},
    TASK_EXPLAIN:  {"temperature": 0.2, "max_tokens": 512},
    TASK_PATCH:    {"temperature": 0.1, "max_tokens": 1024},
    TASK_VALIDATE: {"temperature": 0.0, "max_tokens": 128},
    TASK_FALLBACK: {"temperature": 0.1, "max_tokens": 1024},
}

# ---------------------------------------------------------------------------
# Self-rating prompt
# ---------------------------------------------------------------------------

_SYSTEM_RATE = """\
You generated the following security patch. Rate its quality on a scale of 1 to 10.
Consider:
1. Does the patch directly fix the stated vulnerability?
2. Is the unified diff syntax valid (correct headers and hunk)?
3. Is the change minimal — no unnecessary modifications?
Reply with ONLY a single integer from 1 to 10. No other text.
"""

# Diff validity patterns (mirrors remediation.py — no cross-import)
_DIFF_HEADER_RE = re.compile(r"^--- .+\n\+\+\+ .+", re.MULTILINE)
_HUNK_LINE_RE   = re.compile(r"^@@ -(\d+)", re.MULTILINE)


# ---------------------------------------------------------------------------
# ModelRouter
# ---------------------------------------------------------------------------


class ModelRouter:
    """
    Dispatches pipeline tasks to specialist LLMs and scores confidence for
    patch proposals.

    One OllamaProvider is created per distinct model ID and reused. Ollama
    loads and evicts models from VRAM on demand; the router does not manage
    GPU memory directly.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._base_url   = base_url
        self._timeout    = timeout
        self._providers: dict[str, OllamaProvider] = {}

    # ------------------------------------------------------------------
    # Task routing
    # ------------------------------------------------------------------

    def for_task(self, task: str) -> OllamaProvider:
        """Return (or create) the OllamaProvider assigned to *task*."""
        model_id = _TASK_MODELS.get(task)
        if model_id is None:
            raise ValueError(
                f"Unknown task {task!r}. Valid tasks: {list(_TASK_MODELS)}"
            )
        if model_id not in self._providers:
            params = _TASK_PARAMS.get(task, {})
            self._providers[model_id] = OllamaProvider(
                model=model_id,
                base_url=self._base_url,
                timeout=self._timeout,
                **params,
            )
        return self._providers[model_id]

    def model_for(self, task: str) -> str:
        """Return the model ID string for a task (no network call)."""
        return _TASK_MODELS.get(task, "unknown")

    def available_tasks(self) -> dict[str, bool]:
        """Check which tasks have their assigned model available in Ollama."""
        return {task: self.for_task(task).is_available() for task in _TASK_MODELS}

    # ------------------------------------------------------------------
    # Confidence scoring
    # ------------------------------------------------------------------

    def confidence_score(
        self,
        diff: str,
        finding: "SecurityFinding",
        llm: OllamaProvider,
    ) -> float:
        """
        Compute a [0, 1] confidence score for a generated patch.

        Formula: 0.6 × structural_score + 0.4 × self_rating

        structural_score — four automated diff-validity checks.
        self_rating      — the patch model rates its own output 1–10.

        The weights are research parameters; they are intentionally surfaced
        here rather than buried in the model output.
        """
        structural = self._structural_score(diff, finding)
        self_rating = self._self_rate(llm, diff, finding)
        return round(0.6 * structural + 0.4 * self_rating, 4)

    def _structural_score(
        self, diff: str, finding: "SecurityFinding"
    ) -> float:
        """Score 0–1 from four binary diff-validity checks."""
        checks = [
            bool(_DIFF_HEADER_RE.search(diff)),        # valid --- / +++ header
            bool(_HUNK_LINE_RE.search(diff)),           # at least one @@ hunk
            self._hunk_lines_valid(diff),               # no raw numbered context in hunk
            self._patch_covers_finding(diff, finding),  # hunk within 5 lines of finding
        ]
        return sum(checks) / len(checks)

    def _self_rate(
        self,
        llm: OllamaProvider,
        diff: str,
        finding: "SecurityFinding",
    ) -> float:
        """Ask the patch model to rate its own output. Returns 0–1 (0.5 on failure)."""
        user_prompt = (
            f"Finding: {finding.rule_id} ({finding.cwe_id or 'no CWE'}) "
            f"at {finding.file_path}:{finding.line_start}\n"
            f"Message: {finding.message}\n\n"
            f"Generated patch:\n{diff}"
        )
        try:
            raw = llm.complete(_SYSTEM_RATE, user_prompt).strip()
            m = re.search(r"\b([1-9]|10)\b", raw)
            if m:
                return float(m.group(1)) / 10.0
        except LLMProviderError:
            pass
        return 0.5  # neutral fallback

    # ------------------------------------------------------------------
    # Static diff-validity helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hunk_lines_valid(diff: str) -> bool:
        """Return True if every hunk line starts with ' ', '-', '+', '@', or '\\'."""
        in_hunk = False
        for line in diff.splitlines():
            if line.startswith("@@"):
                in_hunk = True
                continue
            if line.startswith(("--- ", "+++ ")):
                continue
            if in_hunk:
                if not line:
                    continue
                if line[0] not in (" ", "-", "+", "\\"):
                    return False
        return True

    @staticmethod
    def _patch_covers_finding(diff: str, finding: "SecurityFinding") -> bool:
        """Return True if any hunk is within 5 lines of the finding."""
        for m in _HUNK_LINE_RE.finditer(diff):
            if abs(int(m.group(1)) - finding.line_start) <= 5:
                return True
        return False
