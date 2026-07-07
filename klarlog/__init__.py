"""Klarlog: tamper-evident, privacy-preserving event logs for AI systems."""

from .core import EVENT_TYPES, Klarlog, VerifyReport

__version__ = "0.1.0"
__all__ = ["Klarlog", "VerifyReport", "EVENT_TYPES", "__version__"]
