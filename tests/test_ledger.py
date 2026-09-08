"""The guarded ledger: the part of HashGuard that has to survive a hostile reader.

These tests are written from the position of someone who does not trust either
party. Can the operator inflate an invoice? Can the client deny a pause that
happened? Can either of them edit last week? The answer has to be no, and it has
to be no for arithmetic reasons rather than procedural ones.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from hashguard.canonical import record_hash
from hashguard.identity import DeviceIdentity
from hashguard.ledger import (
    GuardedLedger,
    Interval,
    LedgerError,
    verify_chain,
    verify_seal,
)
from hashguard.merkle import build_proof, merkle_root, verify_proof
from hashguard.money import to_micro, to_ppm, to_wh

FULL_FARM_GH = 630_000
POLL_SECONDS = 1200
MACHINES = 6


def build_ledger(tmp_path, days=3, honest=True):
    """A ledger holding `days` sealed days of a farm that pauses in peak hours."""
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(identity, base_dir=str(tmp_path / "ledger"))
    for back in range(days, 0, -1):
        day = datetime.now(timezone.utc) - timedelta(days=back)
        for slot in range(72):
            hour = slot // 3
            when = day.replace(hour=hour, minute=(slot % 3) * 20, second=0, microsecond=0)
            peak = 8 <= hour < 12 or 19 <= hour < 23
            ledger.record(
                Interval(
                    action="PAUSE" if peak else "MINE",
                    executed=True,
                    n_miners=MACHINES,
                    seconds=POLL_SECONDS,
                    price_ppm_per_kwh=to_ppm("0.31" if peak else "0.06"),
                    breakeven_ppm_per_kwh=to_ppm("0.098"),
                    claimed_wh=to_wh("3.05", POLL_SECONDS, MACHINES) if peak else 0,
                    claimed_mining_lost_micro_eur=to_micro("0.63") if peak else 0,
                    baseline_gh=FULL_FARM_GH,
                    # A dishonest farm claims the pause but never stops hashing.
                    observed_gh=(350 if honest else FULL_FARM_GH) if peak else FULL_FARM_GH,
                ),
                when=when,
            )
        ledger.seal_day(day.date().isoformat())
    return identity, ledger


def months_in(ledger):
    """Every month the ledger has sealed days in.

    Built as "the last three days", which straddles a month boundary roughly one
    run in ten. Summing across the months present keeps these tests from failing
    on the 1st and 2nd of each month for reasons that have nothing to do with
    the code under test.
    """
    return sorted({seal["day"][:7] for seal in ledger.seals()})


def combined_totals(ledger):
    totals = {
        "gross_net_saving_micro_eur": 0,
        "billable_net_saving_micro_eur": 0,
        "advisory_net_saving_micro_eur": 0,
        "fee_micro_eur": 0,
        "client_keeps_micro_eur": 0,
    }
    for month in months_in(ledger):
        for key, value in ledger.statement(month)["totals"].items():
            totals[key] += value
    return totals


# -- the happy path --------------------------------------------------------


def test_a_fresh_ledger_chains_and_seals(tmp_path):
    identity, ledger = build_ledger(tmp_path)
    for day in ledger.days():
        records = ledger.day_records(day)
        ok, reason = verify_chain(records)
        assert ok, reason
    for seal in ledger.seals():
        ok, reason = verify_seal(seal, ledger.day_records(seal["day"]), identity.public())
        assert ok, reason


def test_seals_chain_to_each_other(tmp_path):
    _, ledger = build_ledger(tmp_path)
    seals = ledger.seals()
    for previous, current in zip(seals, seals[1:]):
        assert current["prev_seal"] == previous["seal_hash"]


def test_statement_arithmetic_closes(tmp_path):
    _, ledger = build_ledger(tmp_path)
    for month in months_in(ledger):
        totals = ledger.statement(month)["totals"]
        billable = totals["billable_net_saving_micro_eur"]
        assert totals["fee_micro_eur"] + totals["client_keeps_micro_eur"] == billable
        assert totals["fee_micro_eur"] == (billable * 2500) // 10_000
    combined = combined_totals(ledger)
    assert combined["billable_net_saving_micro_eur"] > 0, (
        "peak-hour pausing at 0.31 EUR/kWh should be worth money"
    )


def test_statement_proofs_verify(tmp_path):
    from hashguard.merkle import InclusionProof

    _, ledger = build_ledger(tmp_path)
    checked = 0
    for month in months_in(ledger):
        statement = ledger.statement(month)
        roots = {d["day"]: bytes.fromhex(d["merkle_root"]) for d in statement["days"]}
        for item in statement["proofs"]:
            leaf = record_hash(item["record"])
            assert leaf.hex() == item["leaf"]
            assert verify_proof(leaf, InclusionProof.from_json(item["proof"]), roots[item["day"]])
            checked += 1
    assert checked, "a month with billable pauses must carry inclusion proofs"


# -- adversarial -----------------------------------------------------------


def rewrite_record(ledger, day, index, mutate):
    path = os.path.join(ledger.records_dir, f"{day}.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[index])
    mutate(record)
    lines[index] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")


def test_inflating_a_past_record_breaks_the_chain_and_the_seal(tmp_path):
    identity, ledger = build_ledger(tmp_path)
    day = ledger.days()[0]
    seal = next(s for s in ledger.seals() if s["day"] == day)
    rewrite_record(ledger, day, 30, lambda r: r.update(claimed_wh=r["claimed_wh"] * 4))

    records = ledger.day_records(day)
    chain_ok, _ = verify_chain(records)
    seal_ok, reason = verify_seal(seal, records, identity.public())
    assert not chain_ok, "editing a record must break the hash chain"
    assert not seal_ok and "altered" in reason


def test_deleting_a_record_is_detected(tmp_path):
    identity, ledger = build_ledger(tmp_path)
    day = ledger.days()[0]
    seal = next(s for s in ledger.seals() if s["day"] == day)
    path = os.path.join(ledger.records_dir, f"{day}.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    del lines[40]
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    records = ledger.day_records(day)
    ok, reason = verify_chain(records)
    assert not ok and "missing" in reason
    assert not verify_seal(seal, records, identity.public())[0]


def test_appending_an_invented_record_is_detected(tmp_path):
    identity, ledger = build_ledger(tmp_path)
    day = ledger.days()[0]
    seal = next(s for s in ledger.seals() if s["day"] == day)
    records = ledger.day_records(day)
    forged = dict(records[-1])
    forged["seq"] = forged["seq"] + 1
    forged["claimed_wh"] = 999_999
    with open(os.path.join(ledger.records_dir, f"{day}.jsonl"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
    assert not verify_seal(seal, ledger.day_records(day), identity.public())[0]


def test_a_forged_seal_does_not_pass_signature_check(tmp_path):
    """An attacker who rewrites records *and* recomputes the root still cannot sign."""
    identity, ledger = build_ledger(tmp_path)
    day = ledger.days()[0]
    seal = dict(next(s for s in ledger.seals() if s["day"] == day))
    rewrite_record(ledger, day, 30, lambda r: r.update(claimed_wh=r["claimed_wh"] * 4))

    records = ledger.day_records(day)
    # Recompute honestly-shaped seal fields over the tampered records.
    leaves = [record_hash(r) for r in records]
    from hashguard.merkle import SealHeader

    root = merkle_root(leaves)
    header = SealHeader(bytes.fromhex(seal["prev_seal"]), root)
    seal["merkle_root"] = root.hex()
    seal["seal_hash"] = header.seal_hash.hex()

    ok, reason = verify_seal(seal, records, identity.public())
    assert not ok and "signature" in reason


def test_another_devices_key_cannot_sign_for_this_one(tmp_path):
    identity, ledger = build_ledger(tmp_path, days=1)
    stranger = DeviceIdentity.generate()
    seal = ledger.seals()[0]
    assert verify_seal(seal, ledger.day_records(seal["day"]), identity.public())[0]
    assert not verify_seal(seal, ledger.day_records(seal["day"]), stranger.public())[0]


def test_fabricated_savings_are_not_billable(tmp_path):
    """The corroboration cap, end to end: a farm that never stopped bills zero."""
    _, honest = build_ledger(tmp_path / "honest", honest=True)
    _, liar = build_ledger(tmp_path / "liar", honest=False)

    assert combined_totals(honest)["billable_net_saving_micro_eur"] > 0
    liar_totals = combined_totals(liar)
    assert liar_totals["billable_net_saving_micro_eur"] == 0
    assert liar_totals["fee_micro_eur"] == 0
    for month in months_in(liar):
        assert liar.statement(month)["corroboration"]["verdict"] == "UNCORROBORATED"


# -- invariants ------------------------------------------------------------


def test_a_day_still_running_cannot_be_sealed(tmp_path):
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(identity, base_dir=str(tmp_path / "ledger"))
    ledger.record(
        Interval("MINE", True, 1, 60, 0, 0, 0, 0, None, None),
        when=datetime.now(timezone.utc),
    )
    with pytest.raises(LedgerError, match="not over yet"):
        ledger.seal_day(datetime.now(timezone.utc).date().isoformat())


def test_sealing_twice_does_not_fork_the_chain(tmp_path):
    _, ledger = build_ledger(tmp_path, days=1)
    day = ledger.days()[0]
    before = len(ledger.seals())
    assert ledger.seal_day(day) == ledger.seal_day(day)
    assert len(ledger.seals()) == before


def test_the_ledger_resumes_where_it_stopped(tmp_path):
    identity, ledger = build_ledger(tmp_path, days=1)
    last = ledger.day_records(ledger.days()[-1])[-1]
    reopened = GuardedLedger(identity, base_dir=str(tmp_path / "ledger"))
    fresh = reopened.record(Interval("MINE", True, 1, 60, 0, 0, 0, 0, None, None))
    assert fresh["seq"] == last["seq"] + 1
    assert fresh["prev"] == record_hash(last).hex()


def test_records_cannot_hold_unhashable_values(tmp_path):
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(identity, base_dir=str(tmp_path / "ledger"))
    record = ledger.record(Interval("MINE", True, 1, 60, 0, 0, 0, 0, None, None))
    from hashguard.canonical import canonical_bytes

    canonical_bytes(record)  # raises if the ledger ever stored a float


def test_advisory_intervals_are_never_billed(tmp_path):
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(identity, base_dir=str(tmp_path / "ledger"))
    day = datetime.now(timezone.utc) - timedelta(days=1)
    for slot in range(6):
        ledger.record(
            Interval(
                "PAUSE", False, MACHINES, POLL_SECONDS, to_ppm("0.31"), to_ppm("0.098"),
                to_wh("3.05", POLL_SECONDS, MACHINES), to_micro("0.63"), FULL_FARM_GH, 350,
            ),
            when=day.replace(hour=slot, minute=0, second=0, microsecond=0),
        )
    ledger.seal_day(day.date().isoformat())
    totals = ledger.statement(day.strftime("%Y-%m"))["totals"]
    assert totals["billable_net_saving_micro_eur"] == 0
    assert totals["fee_micro_eur"] == 0
    assert totals["advisory_net_saving_micro_eur"] > 0, (
        "advisory savings are still measured and shown, they are simply not charged"
    )
