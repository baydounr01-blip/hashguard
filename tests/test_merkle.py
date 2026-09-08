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


def test_a_proof_claiming_a_differently_shaped_tree_is_refused():
    """A 9-leaf tree is four levels deep. Claim a size that is not, and the
    audit path is the wrong length for it."""
    tree = leaves(9)
    root = merkle_root(tree)
    proof = build_proof(tree, 0)
    for wrong_size in (8, 17):  # three levels deep, and five
        forged = InclusionProof(proof.index, wrong_size, proof.path)
        assert not verify_proof(tree[0], forged, root)


def test_leaf_count_alone_does_not_pin_the_exact_tree_size():
    """CVE-2012-2459, stated honestly rather than claimed away.

    A 10-leaf tree whose last leaf repeats the ninth has *exactly* the root of
    the 9-leaf tree, so a proof reshaped from 9 to 10 still validates: both are
    four levels deep and the roots genuinely coincide. This is a property of
    the Bitcoin tree shape, not a defect here.

    What closes it is elsewhere, and is tested elsewhere: the seal commits the
    record count and ``verify_seal`` re-counts the records against it
    (``test_ledger.py::test_appending_an_invented_record_is_detected``), and the
    verifiers check a proof's declared count against the sealed one
    (``test_verifier.py::test_a_proof_declaring_the_wrong_leaf_count_is_refused``).
    """
    tree = leaves(9)
    root = merkle_root(tree)
    proof = build_proof(tree, 0)

    assert verify_proof(tree[0], InclusionProof(0, 10, proof.path), root)
    assert merkle_root(tree + [tree[-1]]) == root, (
        "the duplicated-last-leaf tree really does share the root; that is the whole collision"
    )


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
