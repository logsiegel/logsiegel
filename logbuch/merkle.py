"""RFC 6962-style Merkle tree over log entries.

Leaf and node hashing follow Certificate Transparency (RFC 6962, section 2.1)
so that roots are comparable with standard transparency-log tooling.
"""

from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    """Hash of a single log entry (leaf), domain-separated per RFC 6962."""
    return _sha256(LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(NODE_PREFIX + left + right)


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Root over already leaf-hashed entries (RFC 6962 MTH)."""
    n = len(leaf_hashes)
    if n == 0:
        return _sha256(b"")
    if n == 1:
        return leaf_hashes[0]
    # largest power of two strictly smaller than n
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(merkle_root(leaf_hashes[:k]), merkle_root(leaf_hashes[k:]))
