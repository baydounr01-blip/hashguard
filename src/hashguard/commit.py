"""Commit and reveal: the decision is fixed before the evidence is seen.

Ported from the commitment layer of RAMI-Chain
(``chain/crates/rami-core/src/ledger.rs``, itself a faithful port of
``reference/rami_ledger.py``). There the rule is stated in one line: publish
``sha256(canon(signal) || nonce)`` *before* the fact and reveal the signal in a
**strictly later** block, so that a track record cannot be adjusted after the
outcome is known. ``verify_ledger`` refuses a reveal of a commit that does not
exist, a reveal in the same block as its commit or earlier, a wrong height, a
double reveal, and a revealed signal that does not reproduce its commit.

What the same rule is worth here
--------------------------------

HashGuard bills for pauses, and a pause is corroborated by the farm going dark
in hashrate telemetry. Up to v2.0.0 a record was written at the *start* of an
interval carrying the decision, the energy claimed for the interval to come,
and the hashrate read *now*. Nothing in the ledger established that the
decision had been fixed before the telemetry that corroborates it was seen.

That gap has a concrete exploit. A farm goes dark for a reason that is nothing
to do with curtailment -- an outage, maintenance, a tripped breaker -- and the
operator writes a record claiming the pause was a decision. The corroboration
cap waves it through, because the telemetry genuinely does show a dark farm.
The claim is unfalsifiable after the fact precisely because it was written
after the fact.

Commit/reveal fixes the order and makes it checkable:

    decide -> commit -> the interval elapses -> measure -> reveal

Record ``k-1`` carries ``commit``, the hash of the decision that will govern
interval ``k`` together with a 32-byte nonce. Record ``k`` publishes that
decision in clear and carries ``reveal = {commit_seq: k-1, nonce}``. Anyone
holding the two records can recompute the commitment from the *revealed*
decision and check it against the commitment written a poll earlier -- and a
commitment written a poll earlier is on disk, hashed into the chain, and (once
the day closes) under a Merkle seal, before the telemetry it will be matched
against was ever read.

The snapshot that is committed is a projection of record ``k`` itself, so a
reveal needs nothing but the two records to check:

    {action, price_ppm_per_kwh, breakeven_ppm_per_kwh, opened, price_curve_hash}

Rules, all of which both verifiers apply
----------------------------------------

* A reveal names **exactly its predecessor**: ``commit_seq == seq - 1``. Any
  other target, and in particular the same record, is refused -- a decision
  revealed in the record that committed it was never committed in advance of
  anything.
* A commit with no reveal in the next record is *unrevealed*. That is allowed
  and counted, not refused: the agent restarting is the ordinary cause, and
  refusing it would let a restart corrupt a ledger. It is not billable either.
* A record with no ``commit`` at all is *legacy* -- exactly what v2.0.0 wrote.
* Billing fails closed. From the activation day, an executed PAUSE is billable
  only if its reveal reproduces its commit.

Mining is untouched by any of this. The decision is made and acted on exactly
as before; the commitment is a hash written to disk afterwards, and a failure
to write it is a logged cycle failure, not a stopped farm.
"""

from __future__ import annotations

import secrets

from .canonical import SPEC, canonical_bytes, tagged_hash

#: The fields of a record that make up the committed decision. Nothing about
#: the telemetry is in here: the point is that the decision is fixed before the
#: telemetry exists.
DECISION_FIELDS = (
    "action",
    "price_ppm_per_kwh",
    "breakeven_ppm_per_kwh",
    "opened",
    "price_curve_hash",
)

COMMIT_TAG = SPEC + "/commit"
CURVE_TAG = SPEC + "/price-curve"

#: How a record's commit/reveal state is described, in the statement and in the
#: verifiers' output.
REVEALED = "revealed"
UNREVEALED = "unrevealed"
MISMATCHED = "mismatched"
LEGACY = "legacy"


class CommitError(ValueError):
    """A commitment or a reveal is malformed."""


def new_nonce() -> str:
    """32 bytes from the OS. The nonce is what stops a committed decision from
    being guessed before it is revealed: without it, there are two possible
    decisions and the hash of each is trivial to compute."""
    return secrets.token_bytes(32).hex()


def decision_snapshot(record_or_decision: dict) -> dict:
    """The committed projection of a record (or of a decision about to become
    one). Missing fields are carried as ``None`` rather than omitted, so that a
    decision which had no price curve commits to *having had none*."""
    return {field: record_or_decision.get(field) for field in DECISION_FIELDS}


def commit_hash(snapshot: dict, nonce: str) -> str:
    """``tagged_hash(SPEC/commit, canonical(snapshot) || nonce)``, hex.

    Domain-separated like every other digest here, so a commitment can never be
    replayed as a record leaf or a Merkle node.
    """
    try:
        raw_nonce = bytes.fromhex(nonce)
    except (TypeError, ValueError) as exc:
        raise CommitError(f"nonce is not hex: {nonce!r}") from exc
    if len(raw_nonce) != 32:
        raise CommitError(f"nonce must be 32 bytes, got {len(raw_nonce)}")
    return tagged_hash(COMMIT_TAG, canonical_bytes(snapshot) + raw_nonce).hex()


def price_curve_hash(curve: dict[int, int] | None) -> str | None:
    """A digest of the hourly price curve the decision was taken from.

    ``None`` when there was no curve, which is the fail-open case: no price
    data means mine, and a record that claims nothing needs to commit to
    nothing. Hours are stringified because the canonical encoder takes string
    keys only, and sorted by the encoder itself.
    """
    if not curve:
        return None
    return tagged_hash(
        CURVE_TAG, canonical_bytes({str(hour): int(price) for hour, price in curve.items()})
    ).hex()


def reveal_state(record: dict, predecessor: dict | None) -> str:
    """How record ``record`` stands with respect to its predecessor's commit.

    ``predecessor`` of ``None`` means it could not be read -- the first record
    a reader holds, or a day boundary whose previous file is missing. That is
    ``UNREVEALED``: not an accusation, and not billable either.
    """
    reveal = record.get("reveal")
    if reveal is None:
        # No reveal at all. Legacy if this record predates commit/reveal;
        # otherwise the predecessor committed something nobody opened.
        if predecessor is None or predecessor.get("commit") is None:
            return LEGACY if record.get("commit") is None else UNREVEALED
        return UNREVEALED
    if predecessor is None or predecessor.get("commit") is None:
        return MISMATCHED
    if not isinstance(reveal, dict):
        return MISMATCHED
    try:
        if int(reveal.get("commit_seq", -1)) != int(record["seq"]) - 1:
            # A reveal that names anything but its immediate predecessor -- the
            # same record included -- is how the ordering would be undone.
            return MISMATCHED
        if int(predecessor["seq"]) != int(record["seq"]) - 1:
            return MISMATCHED
        computed = commit_hash(decision_snapshot(record), reveal.get("nonce"))
    except (CommitError, KeyError, TypeError, ValueError):
        return MISMATCHED
    return REVEALED if computed == predecessor["commit"] else MISMATCHED


def tally(states) -> dict:
    """Canonical, integer-only counts, safe to hash into a statement."""
    counts = {REVEALED: 0, UNREVEALED: 0, MISMATCHED: 0, LEGACY: 0}
    for state in states:
        counts[state] = counts.get(state, 0) + 1
    return {
        "revealed": counts[REVEALED],
        "unrevealed": counts[UNREVEALED],
        "mismatched": counts[MISMATCHED],
        "legacy": counts[LEGACY],
    }
