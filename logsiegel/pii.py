"""PII detection and scrubbing for stored payloads.

The log line itself never contains raw payloads (only salted hashes), so it
is PII-free by construction. This module closes the remaining gap: the
optional encrypted payload. With a detector configured on the writer, the
payload stores a *masked* copy — placeholders instead of identifiers — while
the salted hashes keep committing to the original text. Whoever holds the
original (user, provider log) can still prove or disprove a match against the
committed hash; the log operator holds no identifiers at all.

Each entry additionally records what was masked (counts per kind and the
detector id), never the values.

Detectors are pluggable. ``RegexDetector`` works offline with no
dependencies; ``HttpDetector`` delegates to an NER service over HTTP
(e.g. an on-prem PII container).
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class Detection:
    kind: str
    start: int
    end: int


class RegexDetector:
    """Offline detector for machine-readable identifiers (email, phone, IBAN).

    Deliberately conservative: patterns favor precision over recall — this is
    the zero-dependency default, not a substitute for an NER model.
    """

    PATTERNS = {
        "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "iban": r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b",
        "phone": r"(?:\+\d{1,3}[\s\-/]?|\b0)\d{2,4}[\s\-/]?\d{3,}(?:[\s\-/]?\d{2,})*",
    }

    def __init__(self, extra_patterns: dict[str, str] | None = None):
        self.id = "regex-v0"
        patterns = {**self.PATTERNS, **(extra_patterns or {})}
        self._compiled = {kind: re.compile(p) for kind, p in patterns.items()}

    def detect(self, text: str) -> list[Detection]:
        found = []
        for kind, rx in self._compiled.items():
            for m in rx.finditer(text):
                found.append(Detection(kind, m.start(), m.end()))
        return found


class HttpDetector:
    """Delegate detection to an NER service (e.g. an on-prem PII container).

    Wire format: POST ``{"text": ...}`` as JSON, expects
    ``{"entities": [{"label": ..., "start": ..., "end": ...}, ...]}``.
    """

    def __init__(self, url: str, timeout: float = 5.0, detector_id: str | None = None):
        self.url = url
        self.timeout = timeout
        self.id = detector_id or f"http:{url}"

    def detect(self, text: str) -> list[Detection]:
        req = urllib.request.Request(
            self.url,
            data=json.dumps({"text": text}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read())
        return [
            Detection(str(e["label"]).lower(), int(e["start"]), int(e["end"]))
            for e in body.get("entities", [])
        ]


def scrub(text: str, detections: list[Detection]) -> tuple[str, dict[str, int]]:
    """Replace detected spans with ``[KIND]`` placeholders.

    Overlapping detections are resolved longest-span-first so one span is
    masked exactly once. Returns the masked text and counts per kind.
    """
    kept: list[Detection] = []
    for d in sorted(detections, key=lambda d: (d.end - d.start), reverse=True):
        if all(d.end <= k.start or d.start >= k.end for k in kept):
            kept.append(d)

    counts: dict[str, int] = {}
    out = text
    for d in sorted(kept, key=lambda d: d.start, reverse=True):
        out = out[: d.start] + f"[{d.kind.upper()}]" + out[d.end :]
        counts[d.kind] = counts.get(d.kind, 0) + 1
    return out, counts
