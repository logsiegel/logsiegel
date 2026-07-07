"""Logsiegel: tamper-evident, privacy-preserving event logs for AI systems."""

from .core import EVENT_TYPES, Logsiegel, VerifyReport

__version__ = "0.1.0"
__all__ = ["Logsiegel", "VerifyReport", "EVENT_TYPES", "__version__"]
