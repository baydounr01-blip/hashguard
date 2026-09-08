"""The encoding both parties hash. If this drifts, every signature drifts."""

import hashlib

import pytest

from hashguard.canonical import (
    CanonicalError,
    canonical_bytes,
    record_hash,
    sha256d,
    tagged_hash,
    unhexlify,
)


def test_key_order_does_not_change_the_hash():
    assert record_hash({"a": 1, "b": 2}) == record_hash({"b": 2, "a": 1})


def test_any_content_change_changes_the_hash():
    base = {"seq": 1, "claimed_wh": 18300}
    assert record_hash(base) != record_hash({**base, "claimed_wh": 18301})


def test_floats_are_refused_rather_than_hashed():
    """A ledger whose numbers are floats is a ledger with two readings."""
    with pytest.raises(CanonicalError, match="minor unit"):
        canonical_bytes({"eur": 1.5})


@pytest.mark.parametrize("value", [{"k": {1, 2}}, {"k": b"bytes"}, {1: "int key"}])
def test_unencodable_values_are_refused(value):
    with pytest.raises(CanonicalError):
        canonical_bytes(value)


def test_nested_floats_are_found():
    with pytest.raises(CanonicalError):
        canonical_bytes({"a": {"b": [1, 2, 3.5]}})


def test_tags_separate_domains():
    """A leaf hash must never be presentable as an inner node."""
    assert tagged_hash("leaf", b"x") != tagged_hash("node", b"x")


def test_sha256d_matches_the_bitcoin_construction():
    assert sha256d(b"abc") == hashlib.sha256(hashlib.sha256(b"abc").digest()).digest()


def test_sha256d_matches_the_bbu_implementation():
    """The construction is carried over verbatim from universal-timeline's
    ``bbu.merkle.sha256d``; if it ever diverges, the port has broken."""

    def bbu_sha256d(data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    assert sha256d(b"branching block universe") == bbu_sha256d(b"branching block universe")


def test_canonical_form_is_compact_and_sorted():
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


@pytest.mark.parametrize("bad", ["", "zz", "ab" * 31, "ab" * 33, "not hex at all"])
def test_short_or_malformed_digests_are_refused(bad):
    with pytest.raises(CanonicalError):
        unhexlify(bad)
