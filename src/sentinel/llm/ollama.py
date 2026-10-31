"""
OllamaProvider — local LLM via Ollama's OpenAI-compatible REST API.

Default endpoint: http://localhost:11434/v1
Default model:    qwen2.5-coder:3b  (Q4_K_M, ~2 GB VRAM)

Source code snippets are processed entirely locally. Nothing is sent to
external services unless the caller explicitly configures a remote endpoint.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from sentinel.llm.base import LLMProvider, LLMProviderError

DEFAULT_MODEL = "qwen2.5-coder:3b"
DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_TIMEOUT = 120  # seconds


class OllamaProvider(LLMProvider):
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
        max_tokens: int = 1024,
        temperature: float = 0.1,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._temperature = temperature

    @property
    def model_id(self) -> str:
        return self._model

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """
        Send a chat completion request to the local Ollama server.
        Uses the OpenAI-compatible /v1/chat/completions endpoint.
        """
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
            "stream": False,
        }

        url = f"{self._base_url}/chat/completions"
        body = json.dumps(payload).encode()

        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as e:
            raise LLMProviderError(
                f"Cannot connect to Ollama at {self._base_url}. "
                f"Is 'ollama serve' running? Error: {e}"
            ) from e
        except json.JSONDecodeError as e:
            raise LLMProviderError(f"Ollama returned invalid JSON: {e}") from e

        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMProviderError(
                f"Unexpected Ollama response shape: {e}. Response: {data!r:.200}"
            ) from e

    def is_available(self) -> bool:
        """Return True if Ollama is running and the model is loaded."""
        try:
            url = f"{self._base_url}/models"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            model_ids = [m.get("id", "") for m in data.get("data", [])]
            return any(self._model in mid for mid in model_ids)
        except Exception:
            return False
