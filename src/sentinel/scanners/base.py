"""
ScannerAdapter abstract base class.

Every scanner implementation must:
- Run as a subprocess (never eval/exec scanner output)
- Return list[RawFinding] — not parsed directly to SecurityFinding
- Handle scanner-not-found gracefully with a clear error message
- Use pathlib.Path for all file operations
- Not modify the target repository in any way
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sentinel.schemas import RawFinding


class ScannerAdapter(ABC):
    """Base class for all security scanner adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner identifier, e.g. 'bandit' or 'trivy'."""

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if the scanner binary/package is installed and callable.
        Must not raise — return False if unavailable.
        """

    @abstractmethod
    def run(self, repo_path: Path) -> list[RawFinding]:
        """
        Run the scanner against repo_path and return raw findings.

        Raises:
            ScannerNotAvailableError: if is_available() would return False
            ScannerExecutionError: if the scanner process fails unexpectedly
        """


class ScannerNotAvailableError(RuntimeError):
    """Raised when a scanner is not installed or not callable."""


class ScannerExecutionError(RuntimeError):
    """Raised when a scanner process exits with an unexpected error."""
