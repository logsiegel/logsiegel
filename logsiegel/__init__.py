"""Logsiegel: tamper-evident, privacy-preserving event logs for AI systems."""

from .core import EVENT_TYPES, Logsiegel, VerifyReport, verify_receipt

__version__ = "0.1.0"
__all__ = ["Logsiegel", "VerifyReport", "EVENT_TYPES", "verify_receipt", "__version__"]
