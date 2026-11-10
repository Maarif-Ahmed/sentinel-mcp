"""
PatchGenerator — produces unified diff patch proposals via the local LLM.

The patch is NEVER applied automatically. It is returned as a string diff
for the developer to review and apply manually.

Three-phase approach for single-line findings:
  Phase 1 — describe the fix in plain English (short, focused call).
  Phase 2a — ask for OLD line / NEW line only; reconstruct the diff with
              Python's difflib. The model only thinks about the code change,
              not diff syntax, so output quality is much higher.
  Phase 2b — fallback: ask the model to generate the full diff directly
              (used when Phase 2a fails or for multi-line findings).
  Retry     — if the Phase 2b diff misses the finding's line, retry once.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from sentinel.llm.base import LLMProvider, LLMProviderError
from sentinel.llm.router import CONFIDENCE_THRESHOLD, TASK_FALLBACK, TASK_PATCH, ModelRouter
from sentinel.schemas import ContextAnnotation, RemediationProposal, SecurityFinding

# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

_SYSTEM_DESCRIBE = """\
You are a security engineer reviewing code for vulnerabilities.
Given a security finding and the affected code, respond with exactly two lines:
Line 1: What is wrong with the line marked >>>.
Line 2: What the minimal fix should be (plain English, no code).
Be specific. Do not add any other text.
"""

_SYSTEM_PATCH = """\
You are a security engineer generating minimal, targeted code patches.

Rules:
- Return ONLY a unified diff in standard format:
    --- a/filename
    +++ b/filename
    @@ -line,count +line,count @@
     context line
    -removed line
    +added line
- The line marked with ">>>" is the EXACT vulnerable line. Only modify that line.
- Do NOT include any explanation, markdown code fences, or prose.
- Make the smallest change that addresses the vulnerability.
- If you truly cannot produce a safe patch, output: # CANNOT_PATCH: <reason>

Example
-------
Finding: B105 hardcoded password  File: app.py  Line: 12
Fix: Replace the hardcoded string with an environment variable lookup.
   10     def get_token():
   11
   12 >>>     token = "abc123"
   13
   14         return token

--- a/app.py
+++ b/app.py
@@ -12,1 +12,1 @@
-    token = "abc123"
+    token = os.environ["APP_TOKEN"]
"""

_SYSTEM_LINES = """\
You are fixing a single vulnerable line of code.
Respond with EXACTLY two lines and nothing else:
OLD: <the exact vulnerable line as it appears in the file, verbatim>
NEW: <the replacement line that fixes the vulnerability>

Do not add explanations, comments, diffs, or any other text.
"""

_SYSTEM_RETRY = """\
You are a security engineer generating minimal, targeted code patches.
Your previous attempt did not modify the correct line. Try again.

Rules:
- Return ONLY a unified diff. No prose, no markdown fences.
- ONLY change the line explicitly shown as the vulnerable line.
- The hunk header @@ must reference that exact line number.
- If you truly cannot patch it safely: # CANNOT_PATCH: <reason>
"""

_DIFF_HEADER_RE = re.compile(r"^--- .+\n\+\+\+ .+", re.MULTILINE)
_HUNK_LINE_RE = re.compile(r"^@@ -(\d+)", re.MULTILINE)

# Rule IDs whose flagged pattern is safer to suppress with # nosec than to patch.
_NOSEC_PATTERNS: dict[str, tuple[re.Pattern[str], str]] = {
    "B311": (
        re.compile(r"random\.(uniform|randint|random|choice)\b", re.I),
        "# nosec B311  # non-cryptographic use (rate-limit jitter / randomness)",
    ),
}

_CONTEXT_RADIUS = 10  # lines each side — tight enough for 3B attention


class PatchGenerator:
    def __init__(
        self,
        llm: LLMProvider,
        repo_root: Path,
        router: ModelRouter | None = None,
    ) -> None:
        self._llm = llm
        self._repo_root = repo_root
        self._router = router

    def generate(
        self,
        finding: SecurityFinding,
        context: ContextAnnotation | None,
    ) -> RemediationProposal:
        # Fast path: known low-risk patterns better suppressed than patched
        nosec_diff = self._nosec_suppression(finding)
        if nosec_diff:
            return RemediationProposal(
                finding_id=finding.id,
                patch_diff=nosec_diff,
                rationale=(
                    f"Pattern-matched suppression: {finding.rule_id} flagged a "
                    f"non-cryptographic use of randomness. Added # nosec comment."
                ),
                generated_by="rule_based",
                confidence_score=1.0,
            )

        file_context = self._read_file_context(finding)
        context_block = self._format_context_block(finding, context, file_context)

        # Pick the specialist patch model when a router is available
        patch_llm = self._router.for_task(TASK_PATCH) if self._router else self._llm

        # Phase 1 — describe the fix in plain English
        fix_description = self._describe_fix(finding, context_block, patch_llm)

        # Phase 2 — generate the diff given the description
        patch_diff, generated_by = self._generate_diff(
            finding, context_block, fix_description, patch_llm
        )

        # Confidence scoring + cascade (router path only)
        confidence = 0.0
        if self._router and not patch_diff.startswith("#"):
            confidence = self._router.confidence_score(patch_diff, finding, patch_llm)
            if confidence < CONFIDENCE_THRESHOLD:
                fallback_llm = self._router.for_task(TASK_FALLBACK)
                fb_desc = self._describe_fix(finding, context_block, fallback_llm)
                fb_diff, fb_model = self._generate_diff(
                    finding, context_block, fb_desc, fallback_llm
                )
                if not fb_diff.startswith("#"):
                    # Score the fallback the same way as the primary. Comparing
                    # a structural-only score against a blended one lets a
                    # weaker patch win on scale difference alone.
                    fb_conf = self._router.confidence_score(
                        fb_diff, finding, fallback_llm
                    )
                    if fb_conf > confidence:
                        patch_diff, generated_by, confidence = fb_diff, fb_model, fb_conf

        method = "reconstructed via difflib" if "+difflib" in generated_by else "generated"
        rationale = (
            f"Patch {method} by {generated_by} for {finding.rule_id} "
            f"({finding.cwe_id or 'no CWE'}) at {finding.file_path}:{finding.line_start}"
        )
        return RemediationProposal(
            finding_id=finding.id,
            patch_diff=patch_diff,
            rationale=rationale,
            generated_by=generated_by,
            confidence_score=round(confidence, 4),
        )

    # ------------------------------------------------------------------
    # Phase 1
    # ------------------------------------------------------------------

    def _describe_fix(
        self,
        finding: SecurityFinding,
        context_block: str,
        llm: LLMProvider | None = None,
    ) -> str:
        """Ask the model to describe the fix in plain English (short focused call)."""
        _llm = llm or self._llm
        user_prompt = (
            f"Finding: {finding.rule_id}  CWE: {finding.cwe_id or 'unknown'}\n"
            f"Description: {finding.message}\n"
            f"File: {finding.file_path}  Line: {finding.line_start}\n\n"
            f"{context_block}"
        )
        try:
            return _llm.complete(_SYSTEM_DESCRIBE, user_prompt).strip()
        except LLMProviderError:
            return ""

    # ------------------------------------------------------------------
    # Phase 2 + retry
    # ------------------------------------------------------------------

    def _generate_diff(
        self,
        finding: SecurityFinding,
        context_block: str,
        fix_description: str,
        llm: LLMProvider | None = None,
    ) -> tuple[str, str]:
        """Return (patch_diff, model_id).

        For single-line findings tries OLD→NEW reconstruction first (Phase 2a),
        which offloads all diff formatting to Python. Falls back to asking the
        model to produce a full diff (Phase 2b) with one retry on miss.
        """
        _llm = llm or self._llm

        # Phase 2a — OLD/NEW lines + difflib reconstruction (single-line only)
        if finding.line_start == finding.line_end:
            old_text, new_text = self._ask_old_new(finding, fix_description, context_block, _llm)
            if old_text and new_text:
                reconstructed = self._reconstruct_diff(finding, old_text, new_text)
                if reconstructed:
                    return reconstructed, f"{_llm.model_id}+difflib"

        # Phase 2b — ask the model to produce the full diff
        user_prompt = self._build_patch_prompt(finding, context_block, fix_description)
        try:
            raw = _llm.complete(_SYSTEM_PATCH, user_prompt)
        except LLMProviderError as e:
            return f"# LLM error: {e}", _llm.model_id

        if raw.strip().startswith("# CANNOT_PATCH"):
            reason = raw.strip().removeprefix("# CANNOT_PATCH:").strip()
            return f"# CANNOT_PATCH: {reason or 'no reason given'}", _llm.model_id

        diff = self._extract_diff(raw, finding)
        if diff.startswith("# WARNING: patch does not address"):
            diff = self._retry_diff(finding, context_block, fix_description, raw, _llm)

        return diff, _llm.model_id

    def _ask_old_new(
        self,
        finding: SecurityFinding,
        fix_description: str,
        context_block: str,
        llm: LLMProvider | None = None,
    ) -> tuple[str, str]:
        """Ask the model for the exact old line and its replacement. Returns ('', '') on failure."""
        _llm = llm or self._llm
        user_prompt = (
            f"Finding: {finding.rule_id}  CWE: {finding.cwe_id or 'unknown'}\n"
            f"Description: {finding.message}\n"
            f"Fix: {fix_description}\n"
            f"File: {finding.file_path}  Vulnerable line number: {finding.line_start}\n\n"
            f"{context_block}"
        )
        try:
            raw = _llm.complete(_SYSTEM_LINES, user_prompt).strip()
            return self._parse_old_new(raw)
        except LLMProviderError:
            return "", ""

    def _parse_old_new(self, raw: str) -> tuple[str, str]:
        """Parse 'OLD: ...' and 'NEW: ...' lines from the model's response."""
        old = new = ""
        for line in raw.splitlines():
            if line.startswith("OLD:"):
                old = line[4:].strip()
            elif line.startswith("NEW:"):
                new = line[4:].strip()
        return old, new

    def _reconstruct_diff(
        self, finding: SecurityFinding, old_text: str, new_text: str
    ) -> str:
        """Build a valid unified diff using difflib after verifying OLD matches the file.

        Preserves the original line's indentation: if the model stripped leading
        whitespace from NEW, it is re-applied from the actual file line.
        Returns '' if OLD does not match or any I/O error occurs.
        """
        try:
            full_path = self._repo_root / finding.file_path
            all_lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines(
                keepends=True
            )
            actual = all_lines[finding.line_start - 1]
            # Strip-compare so minor whitespace differences don't block a match
            if actual.strip() != old_text.strip():
                return ""
            # Preserve original indentation
            indent = len(actual) - len(actual.lstrip())
            replacement = " " * indent + new_text.lstrip() + "\n"
            patched = all_lines.copy()
            patched[finding.line_start - 1] = replacement
            diff_lines = list(
                difflib.unified_diff(
                    all_lines,
                    patched,
                    fromfile=f"a/{finding.file_path}",
                    tofile=f"b/{finding.file_path}",
                    n=3,
                )
            )
            return "".join(diff_lines).strip()
        except Exception:
            return ""

    def _retry_diff(
        self,
        finding: SecurityFinding,
        context_block: str,
        fix_description: str,
        previous_output: str,
        llm: LLMProvider | None = None,
    ) -> str:
        _llm = llm or self._llm
        retry_prompt = (
            f"Your previous output did not modify line {finding.line_start}.\n"
            f"Previous output:\n{previous_output}\n\n"
            f"Fix description: {fix_description}\n\n"
            f"Try again. The hunk @@ must reference line {finding.line_start}.\n"
            f"The diff header must be:\n"
            f"--- a/{finding.file_path}\n"
            f"+++ b/{finding.file_path}\n\n"
            f"{context_block}"
        )
        try:
            raw = _llm.complete(_SYSTEM_RETRY, retry_prompt)
        except LLMProviderError as e:
            return f"# LLM error on retry: {e}"
        return self._extract_diff(raw, finding)

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _build_patch_prompt(
        self,
        finding: SecurityFinding,
        context_block: str,
        fix_description: str,
    ) -> str:
        parts = [
            f"Finding: {finding.rule_id}",
            f"File: {finding.file_path}  Line: {finding.line_start}",
            f"CWE: {finding.cwe_id or 'unknown'}",
            f"Description: {finding.message}",
        ]
        if fix_description:
            parts.append(f"Fix: {fix_description}")
        parts.append(f"\n{context_block}")
        parts.append(
            f"\nGenerate the unified diff.\n"
            f"The diff header must be:\n"
            f"--- a/{finding.file_path}\n"
            f"+++ b/{finding.file_path}"
        )
        return "\n".join(parts)

    def _format_context_block(
        self,
        finding: SecurityFinding,
        context: ContextAnnotation | None,
        file_context: str,
    ) -> str:
        lines: list[str] = []
        if context and context.route_path:
            lines.append(f"Route: {context.route_path} {context.http_methods}")
            if context.middleware_names:
                lines.append(f"Middleware: {context.middleware_names}")
        if file_context:
            lines.append("Affected code (>>> marks the vulnerable line):")
            lines.append(file_context)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _nosec_suppression(self, finding: SecurityFinding) -> str:
        """Return a # nosec diff if the finding matches a known safe-to-suppress pattern."""
        entry = _NOSEC_PATTERNS.get(finding.rule_id)
        if not entry:
            return ""
        pattern, nosec_comment = entry
        snippet = finding.snippet or ""
        if not pattern.search(snippet):
            return ""
        try:
            full_path = self._repo_root / finding.file_path
            all_lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
            original = all_lines[finding.line_start - 1]
            patched = original.rstrip() + "  " + nosec_comment
            return (
                f"--- a/{finding.file_path}\n"
                f"+++ b/{finding.file_path}\n"
                f"@@ -{finding.line_start},1 +{finding.line_start},1 @@\n"
                f"-{original}\n"
                f"+{patched}\n"
            )
        except Exception:
            return ""

    def _read_file_context(self, finding: SecurityFinding) -> str:
        """Read ±CONTEXT_RADIUS lines around the finding, marking the vulnerable line(s)."""
        try:
            full_path = self._repo_root / finding.file_path
            if not full_path.exists():
                return ""
            all_lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(0, finding.line_start - 1 - _CONTEXT_RADIUS)
            end = min(len(all_lines), finding.line_end + _CONTEXT_RADIUS)
            numbered_lines = []
            for i, line in enumerate(all_lines[start:end], start=start):
                lineno = i + 1
                marker = ">>>" if finding.line_start <= lineno <= finding.line_end else "   "
                numbered_lines.append(f"{lineno:4d} {marker} {line}")
            return "\n".join(numbered_lines)
        except Exception:
            return ""

    def _extract_diff(self, raw: str, finding: SecurityFinding | None = None) -> str:
        """Validate the LLM output is a unified diff covering the finding's line."""
        cleaned = re.sub(r"```(?:diff|patch)?\n?", "", raw).strip()
        if not _DIFF_HEADER_RE.search(cleaned):
            return f"# WARNING: LLM did not return a valid unified diff. Raw output:\n{cleaned}"
        if not self._hunk_lines_valid(cleaned):
            return (
                f"# WARNING: diff header present but hunk lines are malformed "
                f"(model returned context block instead of diff lines). Raw output:\n{cleaned}"
            )
        if finding and not self._patch_covers_finding(cleaned, finding):
            return (
                f"# WARNING: patch does not address the flagged line "
                f"({finding.file_path}:{finding.line_start}). Review carefully.\n{cleaned}"
            )
        return cleaned

    @staticmethod
    def _hunk_lines_valid(diff: str) -> bool:
        """Return True if every line inside a hunk starts with ' ', '-', '+', '@', or '\\'.

        Rejects output where the model returned the numbered context block
        (lines like '  123 >>> content' or '  123     content') instead of
        actual diff lines.
        """
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

    def _patch_covers_finding(self, diff: str, finding: SecurityFinding) -> bool:
        """Return True if any hunk is within 5 lines of the finding."""
        for m in _HUNK_LINE_RE.finditer(diff):
            if abs(int(m.group(1)) - finding.line_start) <= 5:
                return True
        return False
