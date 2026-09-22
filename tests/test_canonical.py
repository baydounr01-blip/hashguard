"""The encoding both parties hash. If this drifts, every signature drifts."""

import hashlib

import pytest

from hashguard.canonical import (
    MAX_SAFE_INT,
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


def test_integers_beyond_2_53_are_refused():
    """The bound exists for the *other* implementation. JavaScript parses
    9007199254740993 as 9007199254740992, so a record holding it would hash
    differently in the console and the client could never verify their own
    invoice. Refusing it here makes agreement a property of the format.

    It is four orders of magnitude above anything HashGuard measures: 2^53
    watt-hours is 9 PWh, 2^53 micro-euro is nine billion euro. A value that
    reaches it is a bug, and failing on a bug beats signing it.
    """
    assert MAX_SAFE_INT == 2**53 - 1
    assert canonical_bytes({"wh": MAX_SAFE_INT}) == b'{"wh":9007199254740991}'
    assert canonical_bytes({"wh": -MAX_SAFE_INT}) == b'{"wh":-9007199254740991}'
    for value in (2**53, -(2**53), 2**53 + 1, 2**64, -(2**70)):
        with pytest.raises(CanonicalError) as caught:
            canonical_bytes({"wh": value})
        assert "2**53" in str(caught.value)
    with pytest.raises(CanonicalError) as caught:
        canonical_bytes({"day": {"records": [{"claimed_wh": 2**53}]}})
    assert "$.day.records[0].claimed_wh" in str(caught.value), "the path must name the value"


def test_booleans_are_not_measured_against_the_integer_bound():
    """``isinstance(True, int)`` is True in Python. An implementation that
    range-checks before it type-checks breaks every record in the ledger."""
    assert canonical_bytes({"executed": True, "paused": False}) == (
        b'{"executed":true,"paused":false}'
    )
