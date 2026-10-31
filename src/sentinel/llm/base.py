"""LLMProvider abstract base class."""

from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """
        Send a completion request and return the response text.

        Raises:
            LLMProviderError: on connection failure or malformed response
        """

    @property
    @abstractmethod
    def model_id(self) -> str:
        """Return the model identifier, e.g. 'qwen2.5-coder:3b'."""


class LLMProviderError(RuntimeError):
    """Raised on LLM connection or response errors."""
