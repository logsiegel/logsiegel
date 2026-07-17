"""RFC 6962-style Merkle tree over log entries.

Leaf/node hashing and the proof constructions follow Certificate Transparency
(RFC 6962 section 2.1; verification algorithms as restated in RFC 9162
sections 2.1.3.2 and 2.1.4.2) so that roots and proofs are comparable with
standard transparency-log tooling.

- ``inclusion_proof``/``verify_inclusion``: one entry is committed by a root
  (the basis for standalone receipts).
- ``consistency_proof``/``verify_consistency``: a log of size n is an
  append-only extension of an earlier log of size m (the check a witness
  performs before co-signing a new checkpoint).
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


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Root over already leaf-hashed entries (RFC 6962 MTH)."""
    n = len(leaf_hashes)
    if n == 0:
        return _sha256(b"")
    if n == 1:
        return leaf_hashes[0]
    k = _split(n)
    return node_hash(merkle_root(leaf_hashes[:k]), merkle_root(leaf_hashes[k:]))


# -- inclusion proofs (RFC 6962 §2.1.1 / RFC 9162 §2.1.3) -------------------

def inclusion_proof(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    """Audit path PATH(index, D[n]) proving one leaf against the root."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise IndexError(f"index {index} out of range for tree of size {n}")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaf_hashes[:k], index) + [merkle_root(leaf_hashes[k:])]
    return inclusion_proof(leaf_hashes[k:], index - k) + [merkle_root(leaf_hashes[:k])]


def verify_inclusion(
    leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes
) -> bool:
    """Check an inclusion proof (RFC 9162 §2.1.3.2)."""
    if index >= size:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# -- consistency proofs (RFC 6962 §2.1.2 / RFC 9162 §2.1.4) -----------------

def consistency_proof(leaf_hashes: list[bytes], m: int) -> list[bytes]:
    """PROOF(m, D[n]): the log of size n extends its prefix of size m."""
    n = len(leaf_hashes)
    if not 0 < m <= n:
        raise IndexError(f"prefix size {m} out of range for tree of size {n}")
    if m == n:
        return []
    return _subproof(m, leaf_hashes, True)


def _subproof(m: int, leaf_hashes: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaf_hashes)
    if m == n:
        return [] if complete else [merkle_root(leaf_hashes)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaf_hashes[:k], complete) + [merkle_root(leaf_hashes[k:])]
    return _subproof(m - k, leaf_hashes[k:], False) + [merkle_root(leaf_hashes[:k])]


def verify_consistency(
    first: int, second: int, proof: list[bytes], first_root: bytes, second_root: bytes
) -> bool:
    """Check a consistency proof (RFC 9162 §2.1.4.2); requires 0 < first <= second."""
    if first == second:
        return not proof and first_root == second_root
    if first == 0 or first > second:
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two: old root is implicit
        path = [first_root] + path
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn != 0 and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
