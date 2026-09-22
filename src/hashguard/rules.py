"""Signature rules: what a seal, an activation and a statement are signed over,
and which rule governs a given day.

Ported from RAMI-Chain's first consensus change (v0.8.0, ``docs/CONSENSO-V2.md``
in the RAMI-Ledger repository). Until then a RAMI transaction was signed over
``"RAMI-CHAIN/tx/v1" || body``; a transaction signed for one network verified
on every other network with the same key. The fix put the network's identity
inside the signed message -- ``"RAMI-CHAIN/tx/v2" || network_id || body`` --
and made the rule a pure function of the block's date against an activation
date: before it, v1 and only v1; from it, v2 and only v2; never both for one
block, and the rule never regresses within a branch.

HashGuard has the same hole in a different coat. A v2.0.0 seal is signed over
``canonical(body)`` and the body names no farm, so one key file installed on
two farms signs seals that are interchangeable between them. From the
activation day a seal is signed over

    b"hashguard-ledger/2/seal-sig/2" || farm_id (32 bytes) || canonical(body)

where the body itself also carries ``farm_id`` and ``rule: 2``. A seal signed
for farm A cannot be presented as farm B's, because the message differs in 32
bytes and the verifier reconstructs the message from the farm it was handed.

Three things deliberately do **not** change, following RAMI's own restraint:

* ``SPEC`` stays ``hashguard-ledger/2``. A rule changed, not the format's name.
* ``seal_hash = SHA256d(prev_seal || merkle_root)`` keeps its formula, as the
  txid did. The rule decides which *signature* is valid, not how a seal is
  identified.
* The whole body stays under the signature. ``leaf_count`` is a committed fact
  (see the CVE-2012-2459 note in :mod:`hashguard.merkle`) and must not fall
  out of it.

The rule for a day is decided here, once, as a pure function, so that the
ledger that writes a seal, the module that verifies one, the standalone
verifier and the console all reach the same verdict for the same day.
"""

from __future__ import annotations

from datetime import date

from .canonical import SPEC, canonical_bytes

#: v2.0.0: ``Sign(canonical(body))``, no farm in the message. Byte-identical
#: to what v2.0.0 writes, so a day sealed before activation is sealed the same
#: way by every version.
SEAL_RULE_LEGACY = 1
#: v2.1: ``Sign(tag || farm_id || canonical(body))``, body carries the farm.
SEAL_RULE_FARM_BOUND = 2

#: The activation entry written once into ``ledger/activation.json``.
ACTIVATION_KIND = "activation/1"

SEAL_SIG_TAG_V2 = b"hashguard-ledger/2/seal-sig/2"
ACTIVATION_SIG_TAG = b"hashguard-ledger/2/activation-sig/1"
STATEMENT_SIG_TAG = b"hashguard-ledger/2/statement-sig/1"

#: Keys of a statement that are presentation, not evidence, and are left out
#: of the signed message. Anything not on this list is covered.
STATEMENT_UNSIGNED_KEYS = ("signature", "algorithm", "how_to_verify", "mode", "note")

#: Keys of a seal that are not part of the signed body.
SEAL_UNSIGNED_KEYS = ("signature", "algorithm")


class RuleError(ValueError):
    """A rule, a day or a farm identifier is not what it has to be."""


def check_day(day: str) -> str:
    """``YYYY-MM-DD`` and nothing else; the rule compares days as strings."""
    if not isinstance(day, str) or len(day) != 10:
        raise RuleError(f"a day is written YYYY-MM-DD, got {day!r}")
    try:
        date.fromisoformat(day)
    except ValueError as exc:
        raise RuleError(f"a day is written YYYY-MM-DD, got {day!r}") from exc
    return day


def farm_id_bytes(farm_id: str) -> bytes:
    """A farm id is 32 bytes of hex. Anything else is refused, not coerced."""
    if not isinstance(farm_id, str):
        raise RuleError("farm_id must be a hex string")
    try:
        raw = bytes.fromhex(farm_id)
    except ValueError as exc:
        raise RuleError(f"farm_id is not hex: {farm_id!r}") from exc
    if len(raw) != 32:
        raise RuleError(f"farm_id must be 32 bytes, got {len(raw)}")
    return raw


def seal_rule_for(day: str, from_day: str | None) -> int:
    """Which rule a seal for ``day`` must carry.

    Pure: two readers holding the same activation day reach the same verdict
    for the same day, which is what keeps the ledger from having two valid
    readings. ``from_day`` of ``None`` is a ledger that was never activated
    (v2.0.0): every day is legacy.
    """
    check_day(day)
    if from_day is None:
        return SEAL_RULE_LEGACY
    check_day(from_day)
    return SEAL_RULE_FARM_BOUND if day >= from_day else SEAL_RULE_LEGACY


def declared_rule(seal: dict) -> int:
    """The rule a seal says it was signed under. A seal with no ``rule`` field
    is a v2.0.0 seal, which is rule 1 by definition."""
    rule = seal.get("rule", SEAL_RULE_LEGACY)
    if rule not in (SEAL_RULE_LEGACY, SEAL_RULE_FARM_BOUND):
        raise RuleError(f"unknown seal rule {rule!r}")
    return int(rule)


def seal_body_for_signing(seal: dict) -> dict:
    return {k: v for k, v in seal.items() if k not in SEAL_UNSIGNED_KEYS}


def seal_message(rule: int, farm_id: str | None, body: dict) -> bytes:
    """The bytes a seal signature is made over, under ``rule``."""
    if rule == SEAL_RULE_LEGACY:
        return canonical_bytes(body)
    if rule == SEAL_RULE_FARM_BOUND:
        if farm_id is None:
            raise RuleError("a farm-bound seal needs a farm_id")
        if body.get("farm_id") != farm_id:
            raise RuleError("the seal body names a different farm than the message")
        if body.get("rule") != SEAL_RULE_FARM_BOUND:
            raise RuleError("a farm-bound seal body must declare rule 2")
        return SEAL_SIG_TAG_V2 + farm_id_bytes(farm_id) + canonical_bytes(body)
    raise RuleError(f"unknown seal rule {rule!r}")


def activation_body(farm_id: str, device_id: str, from_day: str, activated_at: str) -> dict:
    return {
        "spec": SPEC,
        "kind": ACTIVATION_KIND,
        "rule": SEAL_RULE_FARM_BOUND,
        "from_day": check_day(from_day),
        "farm_id": farm_id,
        "device_id": device_id,
        "activated_at": activated_at,
    }


def activation_message(farm_id: str, body: dict) -> bytes:
    if body.get("farm_id") != farm_id:
        raise RuleError("the activation body names a different farm than the message")
    return ACTIVATION_SIG_TAG + farm_id_bytes(farm_id) + canonical_bytes(body)


def statement_message(farm_id: str, statement: dict) -> bytes:
    """Everything in the statement except presentation is signed."""
    if statement.get("farm_id") != farm_id:
        raise RuleError("the statement names a different farm than the message")
    body = {k: v for k, v in statement.items() if k not in STATEMENT_UNSIGNED_KEYS}
    return STATEMENT_SIG_TAG + farm_id_bytes(farm_id) + canonical_bytes(body)
