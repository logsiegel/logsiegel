"""Logsiegel core: an append-only, tamper-evident event log for AI systems.

Design:
- Entries are canonical-JSON lines in ``log.jsonl``; each entry carries the
  hash of its predecessor (hash chain).
- Checkpoints (``checkpoints.jsonl``) commit to a Merkle root (RFC 6962) over
  the first N entries and are signed with Ed25519. Any later modification,
  reordering, or truncation of committed entries is detectable offline.
- Privacy by design: the log itself stores only event metadata and salted
  hashes of payloads. Raw payloads (prompt/output) are optional, stored
  separately, encrypted with a per-entry key. Deleting that key
  ("crypto-shredding") destroys the content *and* the linkability of the
  salted hash, while the log remains fully verifiable.

This is a proof of concept: local filesystem, one log directory per writer.
Appends are serialized with an exclusive file lock and fsynced before they
are acknowledged — an event counts as recorded only once it is durable.
"""

from __future__ import annotations

import json
import os
import secrets
import hashlib

try:
    import fcntl
except ImportError:  # non-POSIX platform: no advisory locking
    fcntl = None
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

from .merkle import inclusion_proof, leaf_hash, merkle_root, verify_inclusion
from .pii import scrub

LOG_FILE = "log.jsonl"
CHECKPOINT_FILE = "checkpoints.jsonl"
KEY_FILE = "keys/signing_key.pem"
PUB_FILE = "keys/signing_key.pub"
PAYLOAD_DIR = "payloads"
PAYLOAD_KEYS_FILE = "keys/payload_keys.json"

GENESIS = "sha256:" + hashlib.sha256(b"logsiegel-genesis").hexdigest()

# Minimal v0 event taxonomy for the AI system lifecycle (Art. 12 orientation).
EVENT_TYPES = (
    "system_start",
    "system_stop",
    "inference",
    "model_change",
    "config_change",
    "human_override",
    "data_input",
    "anomaly",
)


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _salted_hash(salt: bytes, text: str) -> str:
    return "sha256:" + hashlib.sha256(salt + text.encode()).hexdigest()


@dataclass
class VerifyReport:
    ok: bool
    entries: int
    checkpoints: int
    problems: list[str] = field(default_factory=list)
    first_ts: str | None = None
    last_ts: str | None = None

    def fail(self, msg: str) -> None:
        self.ok = False
        self.problems.append(msg)


def verify_receipt(receipt: dict, public_key: Ed25519PublicKey) -> VerifyReport:
    """Verify a standalone receipt (see :meth:`Logsiegel.receipt`) offline.

    Needs only the receipt and the log's public key — obtain the key
    out-of-band, not from whoever produced the receipt."""
    report = VerifyReport(ok=True, entries=1, checkpoints=1)
    cp = receipt.get("checkpoint") or {}
    try:
        body = {k: cp[k] for k in ("origin", "size", "root", "ts")}
        public_key.verify(bytes.fromhex(cp["sig"]), canonical(body))
    except (InvalidSignature, KeyError, ValueError):
        report.fail("checkpoint signature invalid")
        return report
    if cp["origin"] != receipt.get("origin"):
        report.fail("origin mismatch between receipt and checkpoint")
    entry = receipt.get("entry")
    seq = receipt.get("seq")
    if not isinstance(entry, dict) or entry.get("seq") != seq:
        report.fail("entry/seq mismatch in receipt")
        return report
    try:
        proof = [bytes.fromhex(p) for p in receipt.get("inclusion_proof", [])]
        included = verify_inclusion(
            leaf_hash(canonical(entry)), seq, cp["size"], proof, bytes.fromhex(cp["root"])
        )
    except (KeyError, ValueError, TypeError):
        included = False
    if not included:
        report.fail(f"inclusion proof invalid for entry {seq}")
    report.first_ts = report.last_ts = entry.get("ts")
    return report


class Logsiegel:
    def __init__(
        self,
        directory: str | Path,
        event_types: tuple[str, ...] = EVENT_TYPES,
        pii_detector=None,
    ):
        """`event_types` lets domain-specific writers bring their own taxonomy
        (default: the AI lifecycle taxonomy above). `pii_detector` (see
        ``logsiegel.pii``) masks identifiers in stored payloads; the salted
        hashes keep committing to the original text."""
        self.dir = Path(directory)
        self.event_types = event_types
        self.pii_detector = pii_detector
        self._tail: tuple[int, int, str] | None = None  # (byte size, entries, last hash)

    # -- setup -----------------------------------------------------------

    @classmethod
    def init(cls, directory: str | Path, origin: str = "logsiegel-poc") -> "Logsiegel":
        lb = cls(directory)
        if (lb.dir / LOG_FILE).exists():
            raise FileExistsError(f"{lb.dir} already contains a log")
        (lb.dir / "keys").mkdir(parents=True, exist_ok=True)
        (lb.dir / PAYLOAD_DIR).mkdir(exist_ok=True)

        key = Ed25519PrivateKey.generate()
        (lb.dir / KEY_FILE).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(lb.dir / KEY_FILE, 0o600)
        (lb.dir / PUB_FILE).write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        (lb.dir / PAYLOAD_KEYS_FILE).write_text("{}")
        (lb.dir / "origin").write_text(origin)
        (lb.dir / LOG_FILE).touch()
        (lb.dir / CHECKPOINT_FILE).touch()
        return lb

    @property
    def origin(self) -> str:
        return (self.dir / "origin").read_text().strip()

    def _private_key(self) -> Ed25519PrivateKey:
        return serialization.load_pem_private_key((self.dir / KEY_FILE).read_bytes(), password=None)

    def public_key(self) -> Ed25519PublicKey:
        return serialization.load_pem_public_key((self.dir / PUB_FILE).read_bytes())

    def public_key_fingerprint(self) -> str:
        raw = self.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]

    # -- entries ---------------------------------------------------------

    def _read_lines(self, name: str) -> list[bytes]:
        raw = (self.dir / name).read_bytes()
        return [ln for ln in raw.split(b"\n") if ln.strip()]

    def entries(self) -> list[dict]:
        return [json.loads(ln) for ln in self._read_lines(LOG_FILE)]

    def _tail_state(self) -> tuple[int, int, str]:
        """(byte size, entry count, last entry hash) — O(1) while the file is
        unchanged; re-read from disk when another writer grew it."""
        size = (self.dir / LOG_FILE).stat().st_size
        if self._tail is not None and self._tail[0] == size:
            return self._tail
        lines = self._read_lines(LOG_FILE)
        last = "sha256:" + hashlib.sha256(lines[-1]).hexdigest() if lines else GENESIS
        self._tail = (size, len(lines), last)
        return self._tail

    def _write_keys(self, keys: dict) -> None:
        tmp = self.dir / (PAYLOAD_KEYS_FILE + ".tmp")
        tmp.write_text(json.dumps(keys, indent=1))
        os.replace(tmp, self.dir / PAYLOAD_KEYS_FILE)

    def append(
        self,
        event: str,
        attrs: dict | None = None,
        input_text: str | None = None,
        output_text: str | None = None,
        store_payload: bool = False,
    ) -> dict:
        """Append one event. Only metadata and salted hashes enter the log.

        The append is serialized under an exclusive lock on the log file and
        fsynced before returning: evidence is either durable or the caller
        sees the failure — never silently lost to a crash.
        """
        if event not in self.event_types:
            raise ValueError(f"unknown event type {event!r}; expected one of {self.event_types}")
        salt = secrets.token_bytes(16)

        with (self.dir / LOG_FILE).open("a+b") as f:
            if fcntl is not None:
                fcntl.flock(f, fcntl.LOCK_EX)
            size, seq, prev = self._tail_state()

            entry: dict = {
                "v": 0,
                "seq": seq,
                "ts": _now(),
                "event": event,
                "attrs": attrs or {},
                "prev": prev,
            }
            # Hashes commit to the ORIGINAL text (evidential value); with a
            # detector configured, only the masked copy is ever persisted.
            stored_input, stored_output = input_text, output_text
            if input_text is not None:
                entry["input_hash"] = _salted_hash(salt, input_text)
            if output_text is not None:
                entry["output_hash"] = _salted_hash(salt, output_text)
            if self.pii_detector is not None and (input_text is not None or output_text is not None):
                pii: dict = {"detector": getattr(self.pii_detector, "id", "custom")}
                if input_text is not None:
                    stored_input, counts = scrub(input_text, self.pii_detector.detect(input_text))
                    pii["input"] = counts
                if output_text is not None:
                    stored_output, counts = scrub(output_text, self.pii_detector.detect(output_text))
                    pii["output"] = counts
                entry["pii"] = pii

            needs_key = input_text is not None or output_text is not None
            if needs_key:
                payload_key = AESGCM.generate_key(bit_length=256)
                keys = json.loads((self.dir / PAYLOAD_KEYS_FILE).read_text())
                keys[str(seq)] = {"salt": salt.hex(), "key": payload_key.hex()}
                self._write_keys(keys)
                if store_payload:
                    nonce = secrets.token_bytes(12)
                    blob = canonical({"input": stored_input, "output": stored_output})
                    enc = AESGCM(payload_key).encrypt(nonce, blob, None)
                    ref = f"{PAYLOAD_DIR}/{seq:08d}.enc"
                    (self.dir / ref).write_bytes(nonce + enc)
                    entry["payload_ref"] = ref

            data = canonical(entry) + b"\n"
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            self._tail = (size + len(data), seq + 1,
                          "sha256:" + hashlib.sha256(data[:-1]).hexdigest())
        return entry

    # -- checkpoints -----------------------------------------------------

    def _root_over(self, lines: list[bytes]) -> str:
        return merkle_root([leaf_hash(ln) for ln in lines]).hex()

    def checkpoint(self) -> dict:
        lines = self._read_lines(LOG_FILE)
        body = {
            "origin": self.origin,
            "size": len(lines),
            "root": self._root_over(lines),
            "ts": _now(),
        }
        sig = self._private_key().sign(canonical(body))
        cp = {**body, "sig": sig.hex()}
        with (self.dir / CHECKPOINT_FILE).open("ab") as f:
            if fcntl is not None:
                fcntl.flock(f, fcntl.LOCK_EX)
            f.write(canonical(cp) + b"\n")
            f.flush()
            os.fsync(f.fileno())
        return cp

    def checkpoints(self) -> list[dict]:
        return [json.loads(ln) for ln in self._read_lines(CHECKPOINT_FILE)]

    # -- verification ----------------------------------------------------

    def verify(self, public_key: Ed25519PublicKey | None = None) -> VerifyReport:
        """Offline verification: hash chain, Merkle roots, signatures.

        Pass ``public_key`` to verify against an out-of-band copy of the
        log's key (trust anchor) instead of the one stored next to the log —
        the stored copy proves nothing against whoever controls the log
        directory.
        """
        lines = self._read_lines(LOG_FILE)
        report = VerifyReport(ok=True, entries=len(lines), checkpoints=0)

        # 1. hash chain + sequence
        prev = GENESIS
        for i, ln in enumerate(lines):
            try:
                e = json.loads(ln)
            except json.JSONDecodeError:
                report.fail(f"entry {i}: not valid JSON")
                continue
            if e.get("seq") != i:
                report.fail(f"entry {i}: sequence mismatch (claims seq={e.get('seq')})")
            if e.get("prev") != prev:
                report.fail(f"entry {i}: hash chain broken")
            if canonical(e) != ln:
                report.fail(f"entry {i}: not in canonical form")
            prev = "sha256:" + hashlib.sha256(ln).hexdigest()
        if lines:
            report.first_ts = json.loads(lines[0]).get("ts")
            report.last_ts = json.loads(lines[-1]).get("ts")

        # 2. checkpoints: signature + committed root + monotonic size
        pub = public_key or self.public_key()
        last_size = 0
        for j, cp in enumerate(self.checkpoints()):
            report.checkpoints += 1
            body = {k: cp[k] for k in ("origin", "size", "root", "ts")}
            try:
                pub.verify(bytes.fromhex(cp["sig"]), canonical(body))
            except InvalidSignature:
                report.fail(f"checkpoint {j}: signature invalid")
                continue
            if cp["origin"] != self.origin:
                report.fail(f"checkpoint {j}: origin mismatch")
            if cp["size"] < last_size:
                report.fail(f"checkpoint {j}: size shrank ({last_size} -> {cp['size']})")
            last_size = cp["size"]
            if cp["size"] > len(lines):
                report.fail(
                    f"checkpoint {j}: commits to {cp['size']} entries, "
                    f"but log has only {len(lines)} (truncation)"
                )
                continue
            if self._root_over(lines[: cp["size"]]) != cp["root"]:
                report.fail(f"checkpoint {j}: Merkle root mismatch (entries modified)")

        return report

    # -- receipts --------------------------------------------------------

    def receipt(self, seq: int) -> dict:
        """Standalone proof for one entry: the entry itself, an RFC 6962
        inclusion proof, and the latest signed checkpoint covering it.

        Verifiable with :func:`verify_receipt` and the log's public key
        alone — the verifier needs no access to the full log or the
        operator's infrastructure."""
        lines = self._read_lines(LOG_FILE)
        if not 0 <= seq < len(lines):
            raise IndexError(f"no entry {seq} (log has {len(lines)})")
        covering = [cp for cp in self.checkpoints() if cp["size"] > seq]
        if not covering:
            raise ValueError(f"no checkpoint covers entry {seq} yet — run checkpoint first")
        cp = covering[-1]
        leaves = [leaf_hash(ln) for ln in lines[: cp["size"]]]
        return {
            "v": 0,
            "origin": self.origin,
            "seq": seq,
            "entry": json.loads(lines[seq]),
            "inclusion_proof": [p.hex() for p in inclusion_proof(leaves, seq)],
            "checkpoint": cp,
        }

    # -- privacy ---------------------------------------------------------

    def read_payload(self, seq: int) -> dict:
        keys = json.loads((self.dir / PAYLOAD_KEYS_FILE).read_text())
        meta = keys.get(str(seq))
        if meta is None:
            raise KeyError(f"payload key for entry {seq} not available (shredded or never stored)")
        entry = self.entries()[seq]
        ref = entry.get("payload_ref")
        if not ref:
            raise KeyError(f"entry {seq} has no stored payload")
        raw = (self.dir / ref).read_bytes()
        blob = AESGCM(bytes.fromhex(meta["key"])).decrypt(raw[:12], raw[12:], None)
        return json.loads(blob)

    def shred(self, seq: int) -> None:
        """Crypto-shred entry payload: content and hash linkability are gone,
        the log itself stays byte-identical and verifiable."""
        keys = json.loads((self.dir / PAYLOAD_KEYS_FILE).read_text())
        if str(seq) not in keys:
            raise KeyError(f"no payload key for entry {seq}")
        del keys[str(seq)]
        self._write_keys(keys)
        ref = self.entries()[seq].get("payload_ref")
        if ref and (self.dir / ref).exists():
            os.remove(self.dir / ref)

    # -- export ----------------------------------------------------------

    def export_dossier(self) -> str:
        """Auditor-readable summary (Annex-IV-oriented record-keeping section)."""
        entries = self.entries()
        report = self.verify()
        keys = json.loads((self.dir / PAYLOAD_KEYS_FILE).read_text())

        by_event: dict[str, int] = {}
        models: set[str] = set()
        for e in entries:
            by_event[e["event"]] = by_event.get(e["event"], 0) + 1
            m = e["attrs"].get("gen_ai.request.model") or e["attrs"].get("model")
            if m:
                models.add(str(m))
        shredded = sum(
            1 for e in entries
            if ("input_hash" in e or "output_hash" in e) and str(e["seq"]) not in keys
        )

        lines = [
            "# Logsiegel record-keeping dossier",
            "",
            f"- Origin: `{self.origin}`",
            f"- Signing key: `{self.public_key_fingerprint()}`",
            f"- Entries: {report.entries}  |  Checkpoints: {report.checkpoints}",
            f"- Period covered: {report.first_ts} — {report.last_ts}",
            f"- Integrity verification: {'PASS' if report.ok else 'FAIL'}",
        ]
        for p in report.problems:
            lines.append(f"  - problem: {p}")
        lines += [
            "",
            "## Events",
            "",
            "| event | count |",
            "|---|---|",
        ]
        known = [ev for ev in self.event_types if ev in by_event]
        extra = sorted(ev for ev in by_event if ev not in self.event_types)
        for ev in known + extra:
            lines.append(f"| {ev} | {by_event[ev]} |")
        lines += [
            "",
            "## Models observed",
            "",
            ", ".join(sorted(models)) if models else "(none recorded)",
            "",
            "## Data protection",
            "",
            "The log contains event metadata and salted payload hashes only; "
            "raw contents are stored separately under per-entry keys "
            f"(crypto-shredding). Shredded entries: {shredded}.",
        ]

        pii_counts: dict[str, int] = {}
        pii_detectors: set[str] = set()
        pii_entries = 0
        for e in entries:
            p = e.get("pii")
            if not p:
                continue
            pii_entries += 1
            pii_detectors.add(p.get("detector", "custom"))
            for side in ("input", "output"):
                for kind, n in p.get(side, {}).items():
                    pii_counts[kind] = pii_counts.get(kind, 0) + n
        if pii_entries:
            lines += [
                "",
                "## PII scrubbing",
                "",
                f"Detector(s): {', '.join(sorted(pii_detectors))} — active on "
                f"{pii_entries} entries. Stored payloads hold masked copies; "
                "salted hashes commit to the original text.",
                "",
                "| identifier kind | masked |",
                "|---|---|",
            ]
            for kind in sorted(pii_counts):
                lines.append(f"| {kind} | {pii_counts[kind]} |")

        lines += [
            "",
            "## Retention",
            "",
            "Checkpoints commit to log size and content over time; "
            "premature deletion or truncation is detectable by re-verification "
            "against any retained checkpoint.",
        ]
        return "\n".join(lines) + "\n"
