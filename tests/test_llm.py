"""
Week 11-12 milestone gate — Part 2: OllamaProvider.

These tests do NOT require Ollama to be running. They verify:
  - OllamaProvider.is_available() returns False gracefully when Ollama is down
  - OllamaProvider.complete() raises LLMProviderError (not crash) when unavailable
  - The model_id property returns the configured model name
  - The provider can be instantiated with custom parameters

Integration tests (requiring live Ollama) are skipped automatically.
"""

from __future__ import annotations

import pytest

from sentinel.llm.base import LLMProviderError
from sentinel.llm.ollama import DEFAULT_MODEL, OllamaProvider


def _ollama_running() -> bool:
    provider = OllamaProvider()
    return provider.is_available()


ollama_down = not _ollama_running()


class TestOllamaProviderUnit:
    """Unit tests — no Ollama required."""

    def test_model_id_default(self):
        provider = OllamaProvider()
        assert provider.model_id == DEFAULT_MODEL

    def test_model_id_custom(self):
        provider = OllamaProvider(model="qwen2.5-coder:7b")
        assert provider.model_id == "qwen2.5-coder:7b"

    def test_is_available_returns_false_gracefully_when_down(self):
        """is_available() must return False (not raise) when Ollama is unreachable."""
        provider = OllamaProvider(base_url="http://localhost:19999")  # nothing there
        result = provider.is_available()
        assert result is False

    def test_complete_raises_llm_provider_error_when_down(self):
        """complete() raises LLMProviderError when Ollama is unreachable — not a crash."""
        provider = OllamaProvider(base_url="http://localhost:19999", timeout=2)
        with pytest.raises(LLMProviderError):
            provider.complete("system", "user")

    def test_custom_timeout_accepted(self):
        provider = OllamaProvider(timeout=30)
        assert provider._timeout == 30

    def test_custom_temperature_accepted(self):
        provider = OllamaProvider(temperature=0.5)
        assert provider._temperature == 0.5


@pytest.mark.skipif(ollama_down, reason="Ollama not running or model not loaded")
class TestOllamaProviderIntegration:
    """Integration tests — require live Ollama with qwen2.5-coder:3b loaded."""

    def test_complete_returns_non_empty_string(self):
        provider = OllamaProvider()
        result = provider.complete(
            system_prompt="You are a security assistant. Be very brief.",
            user_prompt="In one sentence, what is SQL injection?",
        )
        assert isinstance(result, str)
        assert len(result) > 10

    def test_complete_mentions_sql(self):
        provider = OllamaProvider()
        result = provider.complete(
            system_prompt="You are a security assistant. Be very brief.",
            user_prompt="In one sentence, what is SQL injection?",
        )
        assert "sql" in result.lower() or "inject" in result.lower(), (
            f"Expected 'sql' or 'inject' in response, got: {result[:200]}"
        )
