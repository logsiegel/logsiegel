import hashlib

import pytest

from logsiegel.merkle import (
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)


def leaves(n):
    return [leaf_hash(f"entry-{i}".encode()) for i in range(n)]


def test_rfc6962_known_answers():
    # MTH({}) = SHA-256 of the empty string; leaf hash of "" per RFC 6962 §2.1
    assert merkle_root([]) == hashlib.sha256(b"").digest()
    assert leaf_hash(b"").hex() == (
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    )
    assert merkle_root([leaf_hash(b"x")]) == leaf_hash(b"x")


@pytest.mark.parametrize("n", range(1, 17))
def test_inclusion_proofs_verify_for_all_indexes(n):
    ls = leaves(n)
    root = merkle_root(ls)
    for i in range(n):
        assert verify_inclusion(ls[i], i, n, inclusion_proof(ls, i), root)


def test_inclusion_rejects_forgery():
    ls = leaves(8)
    root = merkle_root(ls)
    proof = inclusion_proof(ls, 3)
    assert not verify_inclusion(leaf_hash(b"forged"), 3, 8, proof, root)
    assert not verify_inclusion(ls[3], 4, 8, proof, root)  # wrong index
    assert not verify_inclusion(ls[3], 3, 9, proof, root)  # wrong size


@pytest.mark.parametrize("n", range(1, 17))
def test_consistency_proofs_verify_for_all_prefixes(n):
    ls = leaves(n)
    root_n = merkle_root(ls)
    for m in range(1, n + 1):
        proof = consistency_proof(ls, m)
        assert verify_consistency(m, n, proof, merkle_root(ls[:m]), root_n)


def test_consistency_rejects_rewritten_history():
    ls = leaves(10)
    forged = list(ls)
    forged[2] = leaf_hash(b"rewritten")  # entry inside the old prefix changed
    proof = consistency_proof(forged, 6)
    assert not verify_consistency(6, 10, proof, merkle_root(ls[:6]), merkle_root(forged))


def test_consistency_edge_cases():
    ls = leaves(5)
    assert verify_consistency(5, 5, [], merkle_root(ls), merkle_root(ls))
    assert not verify_consistency(5, 5, [], merkle_root(ls), merkle_root(leaves(4)))
    assert not verify_consistency(0, 5, [], merkle_root([]), merkle_root(ls))
    with pytest.raises(IndexError):
        consistency_proof(ls, 6)
    with pytest.raises(IndexError):
        inclusion_proof(ls, 5)
