"""Merkle roots and the proofs that make one invoice line checkable on its own."""

import hashlib

import pytest

from hashguard.canonical import record_hash
from hashguard.merkle import (
    InclusionProof,
    SealHeader,
    build_proof,
    merkle_root,
    verify_proof,
)


def leaves(count: int) -> list[bytes]:
    return [record_hash({"seq": i}) for i in range(count)]


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 7, 8, 17, 40, 100, 1441])
def test_every_leaf_proves_into_the_root(count):
    tree = leaves(count)
    root = merkle_root(tree)
    for index in {0, count // 2, count - 1}:
        assert verify_proof(tree[index], build_proof(tree, index), root)


def test_a_different_leaf_does_not_prove():
    tree = leaves(16)
    root = merkle_root(tree)
    assert not verify_proof(record_hash({"seq": 999}), build_proof(tree, 3), root)


def test_changing_one_leaf_changes_the_root():
    tree = leaves(32)
    before = merkle_root(tree)
    tree[7] = record_hash({"seq": 7, "tampered": True})
    assert merkle_root(tree) != before


def test_proof_declaring_the_wrong_tree_size_is_refused():
    """Bitcoin's odd-node duplication (CVE-2012-2459) is why leaf_count is committed."""
    tree = leaves(9)
    root = merkle_root(tree)
    proof = build_proof(tree, 0)
    forged = InclusionProof(proof.index, proof.leaf_count + 1, proof.path)
    assert not verify_proof(tree[0], forged, root)


def test_truncated_path_is_refused():
    tree = leaves(16)
    root = merkle_root(tree)
    proof = build_proof(tree, 5)
    assert not verify_proof(tree[5], InclusionProof(5, 16, proof.path[:-1]), root)


def test_index_outside_the_tree_is_refused():
    tree = leaves(8)
    root = merkle_root(tree)
    proof = build_proof(tree, 0)
    assert not verify_proof(tree[0], InclusionProof(99, 8, proof.path), root)


def test_proof_survives_a_json_round_trip():
    tree = leaves(21)
    root = merkle_root(tree)
    proof = build_proof(tree, 13)
    assert verify_proof(tree[13], InclusionProof.from_json(proof.to_json()), root)


def test_empty_tree_has_no_root():
    with pytest.raises(ValueError):
        merkle_root([])


def test_leaves_must_be_digests():
    with pytest.raises(ValueError):
        merkle_root([b"short"])


def test_seal_header_matches_the_bbu_block_header_construction():
    """SealHeader is bbu.merkle.LedgerBlockHeader: SHA256d(prev || merkle)."""
    prev = b"\x01" * 32
    root = b"\x02" * 32
    expected = hashlib.sha256(hashlib.sha256(prev + root).digest()).digest()
    assert SealHeader(prev, root).seal_hash == expected
