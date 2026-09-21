"""The signature rule: which one governs a day, and what each one signs.

Ported from RAMI-Chain's first consensus change. Two properties carry the
whole thing, and both are tested here rather than argued for:

* the rule for a day is a *pure function* of the day and the activation day,
  so two readers never disagree about which format a seal should be in;
* a seal signed for one farm does not verify as another farm's, with the same
  key, which is what makes a device key an identity for a *farm* rather than
  a licence to seal anything.
"""

import pytest

from hashguard.canonical import canonical_bytes
from hashguard.identity import DeviceIdentity, is_farm_id, mint_farm_id, verify_signature
from hashguard.rules import (
    SEAL_RULE_FARM_BOUND,
    SEAL_RULE_LEGACY,
    RuleError,
    activation_body,
    activation_message,
    declared_rule,
    seal_message,
    seal_rule_for,
    statement_message,
)


def legacy_body(day="2026-09-20"):
    """The exact shape v2.0.0 seals: no rule, no farm."""
    return {
        "spec": "hashguard-ledger/2",
        "day": day,
        "device_id": "d" * 32,
        "prev_seal": "a" * 64,
        "merkle_root": "b" * 64,
        "leaf_count": 48,
        "first_seq": 0,
        "last_seq": 47,
        "seal_hash": "c" * 64,
        "corroboration": {"verdict": "CORROBORATED", "claimed_wh": 0},
    }


# -- the rule --------------------------------------------------------------


def test_the_rule_is_a_pure_function_of_the_day_and_the_activation():
    """Before, rule 1 and only rule 1. From the day, rule 2 and only rule 2.
    No mixed period, and the same answer every time it is asked."""
    assert seal_rule_for("2026-09-19", "2026-09-20") == SEAL_RULE_LEGACY
    assert seal_rule_for("2026-09-20", "2026-09-20") == SEAL_RULE_FARM_BOUND
    assert seal_rule_for("2026-09-21", "2026-09-20") == SEAL_RULE_FARM_BOUND
    # A ledger that was never activated is entirely legacy: that is every
    # v2.0.0 ledger, and it must keep exactly one reading too.
    for day in ("2020-01-01", "2026-09-20", "2099-12-31"):
        assert seal_rule_for(day, None) == SEAL_RULE_LEGACY
    assert seal_rule_for("2026-09-20", "2026-09-20") == seal_rule_for("2026-09-20", "2026-09-20")


@pytest.mark.parametrize("bad", ["2026-9-20", "20260920", "", "not a day", None, 20260920])
def test_a_day_that_is_not_a_day_is_refused(bad):
    with pytest.raises(RuleError):
        seal_rule_for(bad, "2026-09-20")


def test_an_unknown_declared_rule_is_refused():
    with pytest.raises(RuleError):
        declared_rule({"rule": 3})


def test_a_seal_with_no_rule_field_is_the_legacy_rule():
    """v2.0.0 wrote no rule field. That absence has exactly one meaning."""
    assert declared_rule(legacy_body()) == SEAL_RULE_LEGACY


# -- what each rule signs --------------------------------------------------


def test_legacy_seals_are_byte_identical_to_v2_0_0():
    """A day before activation must be signed over exactly the bytes v2.0.0
    signed, or upgrading would silently invalidate every past seal."""
    body = legacy_body()
    assert seal_message(SEAL_RULE_LEGACY, mint_farm_id(), body) == canonical_bytes(body)


def test_a_farm_bound_message_carries_the_farm_before_the_body():
    farm = mint_farm_id()
    body = {**legacy_body(), "rule": SEAL_RULE_FARM_BOUND, "farm_id": farm}
    message = seal_message(SEAL_RULE_FARM_BOUND, farm, body)
    assert message.startswith(b"hashguard-ledger/2/seal-sig/2")
    assert bytes.fromhex(farm) in message
    assert message.endswith(canonical_bytes(body)), "the whole body stays under the signature"


def test_a_seal_signed_for_farm_a_does_not_verify_as_farm_b():
    """The point of the whole change: one key file installed on two farms
    stops producing interchangeable seals."""
    identity = DeviceIdentity.generate()
    farm_a, farm_b = mint_farm_id(), mint_farm_id()
    body_a = {**legacy_body(), "rule": SEAL_RULE_FARM_BOUND, "farm_id": farm_a}
    signature = identity.sign(seal_message(SEAL_RULE_FARM_BOUND, farm_a, body_a))

    assert verify_signature(identity.public(), seal_message(SEAL_RULE_FARM_BOUND, farm_a, body_a), signature)
    body_b = {**body_a, "farm_id": farm_b}
    assert not verify_signature(
        identity.public(), seal_message(SEAL_RULE_FARM_BOUND, farm_b, body_b), signature
    )


def test_a_farm_bound_body_must_agree_with_its_message():
    """Refuse to sign bytes that say one farm while the body says another;
    a signature over a self-contradicting message proves nothing useful."""
    farm = mint_farm_id()
    with pytest.raises(RuleError):
        seal_message(SEAL_RULE_FARM_BOUND, farm, legacy_body())
    with pytest.raises(RuleError):
        seal_message(SEAL_RULE_FARM_BOUND, farm, {**legacy_body(), "farm_id": mint_farm_id(), "rule": 2})
    with pytest.raises(RuleError):
        seal_message(SEAL_RULE_FARM_BOUND, None, legacy_body())


@pytest.mark.parametrize("bad", ["", "ab", "zz" * 32, "ab" * 31, 42, None])
def test_a_farm_id_that_is_not_32_bytes_of_hex_is_refused(bad):
    body = {**legacy_body(), "rule": SEAL_RULE_FARM_BOUND, "farm_id": bad}
    with pytest.raises(RuleError):
        seal_message(SEAL_RULE_FARM_BOUND, bad, body)


# -- the other two signed documents ---------------------------------------


def test_the_activation_entry_is_signed_and_names_its_farm():
    identity = DeviceIdentity.generate()
    farm = identity.farm_id
    body = activation_body(farm, identity.device_id, "2026-09-20", "2026-09-20T00:00:00Z")
    signature = identity.sign(activation_message(farm, body))
    assert verify_signature(identity.public(), activation_message(farm, body), signature)
    moved = {**body, "from_day": "2026-10-01"}
    assert not verify_signature(identity.public(), activation_message(farm, moved), signature), (
        "moving the activation day must not survive its own signature"
    )


def test_the_statement_message_covers_the_totals_but_not_the_presentation():
    farm = mint_farm_id()
    statement = {
        "spec": "hashguard-ledger/2",
        "month": "2026-09",
        "farm_id": farm,
        "totals": {"fee_micro_eur": 1000},
        "how_to_verify": "run the verifier",
    }
    base = statement_message(farm, statement)
    # Presentation may change without breaking the signature...
    assert statement_message(farm, {**statement, "how_to_verify": "anything", "mode": "advisory"}) == base
    # ...and the money may not.
    assert statement_message(farm, {**statement, "totals": {"fee_micro_eur": 0}}) != base


def test_identities_carry_a_farm_id_and_publish_it():
    identity = DeviceIdentity.generate()
    assert is_farm_id(identity.farm_id)
    assert identity.public()["farm_id"] == identity.farm_id
    assert DeviceIdentity.generate().farm_id != identity.farm_id, "each farm gets its own"
