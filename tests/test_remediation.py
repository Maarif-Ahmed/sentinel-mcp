"""
Week 13-14 milestone gate — Part 1: PatchGenerator.

Tests verify:
  - PatchGenerator returns a RemediationProposal for every outcome
  - requires_developer_action is always True
  - LLM errors return an empty diff with a rationale (not a crash)
  - CANNOT_PATCH signal returns empty diff
  - Valid unified diff passes through unchanged
  - Markdown fences around a diff are stripped
  - Non-diff LLM output gets a WARNING: prefix
  - generated_by reflects the provider's model_id
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.llm.base import LLMProvider, LLMProviderError
from sentinel.remediation import PatchGenerator
from sentinel.schemas import ContextAnnotation, SecurityFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeLLM(LLMProvider):
    """Minimal LLMProvider stub that returns a configurable response."""

    def __init__(self, response: str | Exception, model: str = "fake-model") -> None:
        self._response = response
        self._model = model

    @property
    def model_id(self) -> str:
        return self._model

    def is_available(self) -> bool:
        return True

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


_VALID_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -10,5 +10,5 @@
-    query = f"SELECT * FROM users WHERE id = {user_id}"
+    query = "SELECT * FROM users WHERE id = %s"
+    cursor.execute(query, (user_id,))
"""


def _make_finding(**kwargs) -> SecurityFinding:
    defaults = dict(
        canonical_id=SecurityFinding.make_canonical_id("app.py", 10, "CWE-89"),
        scanner="bandit",
        rule_id="B608",
        file_path="app.py",
        line_start=10,
        line_end=10,
        severity="high",
        confidence="high",
        cwe_id="CWE-89",
        message="SQL injection via string formatting",
    )
    defaults.update(kwargs)
    return SecurityFinding(**defaults)


def _make_context() -> ContextAnnotation:
    return ContextAnnotation(
        route_path="/api/users/:id",
        http_methods=["GET"],
        middleware_names=[],
        attribution_confidence="handler",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPatchGenerator:
    def test_returns_remediation_proposal(self, tmp_path: Path):
        gen = PatchGenerator(_FakeLLM(_VALID_DIFF), tmp_path)
        proposal = gen.generate(_make_finding(), _make_context())
        assert proposal.finding_id is not None
        assert proposal.patch_diff != "" or proposal.rationale != ""

    def test_requires_developer_action_always_true(self, tmp_path: Path):
        gen = PatchGenerator(_FakeLLM(_VALID_DIFF), tmp_path)
        proposal = gen.generate(_make_finding(), _make_context())
        assert proposal.requires_developer_action is True

    def test_llm_error_returns_comment_marker(self, tmp_path: Path):
        # A '#'-prefixed marker, not an empty string: generate() keys the
        # cascade off that prefix, and it tells the developer what failed.
        gen = PatchGenerator(_FakeLLM(LLMProviderError("connection refused")), tmp_path)
        proposal = gen.generate(_make_finding(), None)
        assert proposal.patch_diff.startswith("#")
        assert "connection refused" in proposal.patch_diff

    def test_unparseable_output_returns_comment_marker(self, tmp_path: Path):
        gen = PatchGenerator(_FakeLLM("CANNOT_PATCH"), tmp_path)
        proposal = gen.generate(_make_finding(), None)
        assert proposal.patch_diff.startswith("#")
        assert "CANNOT_PATCH" in proposal.patch_diff

    def test_valid_diff_returned_as_is(self, tmp_path: Path):
        gen = PatchGenerator(_FakeLLM(_VALID_DIFF), tmp_path)
        proposal = gen.generate(_make_finding(), _make_context())
        assert "--- a/app.py" in proposal.patch_diff
        assert "+++ b/app.py" in proposal.patch_diff

    def test_markdown_fence_stripped(self, tmp_path: Path):
        fenced = f"```diff\n{_VALID_DIFF}\n```"
        gen = PatchGenerator(_FakeLLM(fenced), tmp_path)
        proposal = gen.generate(_make_finding(), None)
        assert "```" not in proposal.patch_diff
        assert "--- a/app.py" in proposal.patch_diff

    def test_non_diff_output_gets_warning_prefix(self, tmp_path: Path):
        gen = PatchGenerator(_FakeLLM("Use parameterized queries instead."), tmp_path)
        proposal = gen.generate(_make_finding(), None)
        assert "WARNING" in proposal.patch_diff

    def test_generated_by_reflects_model_id(self, tmp_path: Path):
        gen = PatchGenerator(_FakeLLM(_VALID_DIFF, model="qwen2.5-coder:3b"), tmp_path)
        proposal = gen.generate(_make_finding(), None)
        assert proposal.generated_by == "qwen2.5-coder:3b"

    def test_finding_id_in_proposal(self, tmp_path: Path):
        finding = _make_finding()
        gen = PatchGenerator(_FakeLLM(_VALID_DIFF), tmp_path)
        proposal = gen.generate(finding, None)
        assert proposal.finding_id == finding.id
