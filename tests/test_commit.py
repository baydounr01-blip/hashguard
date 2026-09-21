"""Commit and reveal: the rules that make the ordering checkable.

Ported from RAMI-Chain's commitment layer, which refuses a reveal of a commit
that does not exist, a reveal in the same block as its commit or earlier, a
wrong height, a double reveal, and a signal that does not reproduce its
commitment. The shapes differ -- a farm ledger has records, not blocks -- but
every refusal has a counterpart here.
"""

import pytest

from hashguard.commit import (
    LEGACY,
    MISMATCHED,
    REVEALED,
    UNREVEALED,
    CommitError,
    commit_hash,
    decision_snapshot,
    new_nonce,
    price_curve_hash,
    reveal_state,
    tally,
)


def pair(nonce=None, action="PAUSE", opened="2026-09-20T09:00:00Z", seq=41):
    """A predecessor carrying a commitment, and the record that reveals it."""
    nonce = nonce or new_nonce()
    revealing = {
        "seq": seq + 1,
        "action": action,
        "price_ppm_per_kwh": 310_000,
        "breakeven_ppm_per_kwh": 98_000,
        "opened": opened,
        "price_curve_hash": None,
        "reveal": {"commit_seq": seq, "nonce": nonce},
        "commit": None,
    }
    predecessor = {
        "seq": seq,
        "action": "MINE",
        "price_ppm_per_kwh": 60_000,
        "breakeven_ppm_per_kwh": 98_000,
        "opened": "2026-09-20T08:30:00Z",
        "price_curve_hash": None,
        "reveal": None,
        "commit": commit_hash(decision_snapshot(revealing), nonce),
    }
    return predecessor, revealing


# -- the commitment itself -------------------------------------------------


def test_a_reveal_reproduces_its_commit():
    predecessor, revealing = pair()
    assert reveal_state(revealing, predecessor) == REVEALED


@pytest.mark.parametrize(
    "field,value",
    [
        ("action", "MINE"),
        ("price_ppm_per_kwh", 310_001),
        ("breakeven_ppm_per_kwh", 98_001),
        ("opened", "2026-09-20T09:00:01Z"),
        ("price_curve_hash", "ab" * 32),
    ],
)
def test_a_changed_decision_does_not_reproduce_the_commit(field, value):
    """Every field of the committed decision is covered, so none of them can
    be adjusted after the interval ran."""
    predecessor, revealing = pair()
    revealing[field] = value
    assert reveal_state(revealing, predecessor) == MISMATCHED


def test_the_commitment_is_domain_separated_and_nonce_bound():
    snapshot = {"action": "PAUSE", "price_ppm_per_kwh": 1, "breakeven_ppm_per_kwh": 2,
                "opened": "2026-09-20T09:00:00Z", "price_curve_hash": None}
    first, second = new_nonce(), new_nonce()
    assert commit_hash(snapshot, first) != commit_hash(snapshot, second), (
        "without the nonce a two-valued decision would be guessable before it is revealed"
    )
    assert commit_hash(snapshot, first) == commit_hash(snapshot, first)


@pytest.mark.parametrize("bad", ["", "ab", "zz" * 32, "ab" * 31, None, 42])
def test_a_nonce_that_is_not_32_bytes_of_hex_is_refused(bad):
    with pytest.raises(CommitError):
        commit_hash({"action": "MINE"}, bad)


# -- the ordering rules ----------------------------------------------------


def test_a_reveal_in_the_same_record_is_refused():
    """A decision revealed by the record that committed it was committed in
    advance of nothing at all."""
    predecessor, revealing = pair()
    revealing["reveal"] = {**revealing["reveal"], "commit_seq": revealing["seq"]}
    assert reveal_state(revealing, predecessor) == MISMATCHED


@pytest.mark.parametrize("offset", [-2, -3, 1, 5])
def test_a_reveal_naming_any_record_but_its_predecessor_is_refused(offset):
    predecessor, revealing = pair()
    revealing["reveal"] = {**revealing["reveal"], "commit_seq": revealing["seq"] + offset}
    assert reveal_state(revealing, predecessor) == MISMATCHED


def test_a_reveal_of_a_commit_that_does_not_exist_is_refused():
    predecessor, revealing = pair()
    predecessor["commit"] = None
    assert reveal_state(revealing, predecessor) == MISMATCHED
    assert reveal_state(revealing, None) == MISMATCHED


def test_a_malformed_reveal_is_refused_rather_than_raising():
    predecessor, revealing = pair()
    for broken in ("not a dict", {"nonce": "ab"}, {"commit_seq": "x", "nonce": new_nonce()}, {}):
        revealing["reveal"] = broken
        assert reveal_state(revealing, predecessor) == MISMATCHED


# -- the states that are not accusations -----------------------------------


def test_an_unrevealed_commit_is_counted_not_refused():
    """The ordinary cause is the agent restarting. Refusing it would let a
    restart corrupt a ledger; it is simply not billable."""
    predecessor, revealing = pair()
    revealing["reveal"] = None
    assert reveal_state(revealing, predecessor) == UNREVEALED


def test_a_record_that_predates_the_rule_is_named_legacy():
    """Exactly what v2.0.0 wrote: no commit, no reveal, anywhere."""
    legacy = {"seq": 3, "action": "PAUSE", "commit": None, "reveal": None}
    assert reveal_state(legacy, None) == LEGACY
    assert reveal_state(legacy, {"seq": 2, "commit": None, "reveal": None}) == LEGACY


def test_the_first_record_of_a_session_reveals_nothing_and_is_not_a_mismatch():
    first = {"seq": 0, "action": "MINE", "commit": "ab" * 32, "reveal": None}
    assert reveal_state(first, None) == UNREVEALED


def test_the_upgrade_boundary_is_not_a_mismatch():
    """The first committed record after an upgrade follows a legacy one."""
    legacy = {"seq": 9, "action": "MINE", "commit": None, "reveal": None}
    fresh = {"seq": 10, "action": "MINE", "commit": "cd" * 32, "reveal": None}
    assert reveal_state(fresh, legacy) == UNREVEALED


# -- the summary -----------------------------------------------------------


def test_the_tally_is_integers_only_and_therefore_hashable():
    from hashguard.canonical import canonical_bytes

    counts = tally([REVEALED, REVEALED, UNREVEALED, MISMATCHED, LEGACY])
    assert counts == {"revealed": 2, "unrevealed": 1, "mismatched": 1, "legacy": 1}
    canonical_bytes(counts)  # raises if anything in here is not canonical


def test_the_price_curve_digest_distinguishes_curves_and_admits_having_none():
    assert price_curve_hash(None) is None
    assert price_curve_hash({}) is None
    first = price_curve_hash({0: 60_000, 1: 61_000})
    assert first == price_curve_hash({1: 61_000, 0: 60_000}), "key order must not matter"
    assert first != price_curve_hash({0: 60_000, 1: 61_001})
