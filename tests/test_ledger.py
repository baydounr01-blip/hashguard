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


# -- the signature rule and its activation ---------------------------------


def activated_ledger(tmp_path, activate_from, days=4):
    """A ledger whose activation day falls in the middle of the days it seals."""
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(
        identity, base_dir=str(tmp_path / "ledger"), activate_from=activate_from
    )
    for back in range(days, 0, -1):
        day = datetime.now(timezone.utc) - timedelta(days=back)
        for hour in (9, 20):
            ledger.record(
                Interval(
                    "PAUSE", True, MACHINES, POLL_SECONDS, to_ppm("0.31"), to_ppm("0.098"),
                    to_wh("3.05", POLL_SECONDS, MACHINES), to_micro("0.63"), FULL_FARM_GH, 350,
                ),
                when=day.replace(hour=hour, minute=0, second=0, microsecond=0),
            )
        ledger.seal_day(day.date().isoformat())
    return identity, ledger


def test_a_ledger_crossing_the_activation_date_seals_each_day_under_exactly_one_rule(tmp_path):
    """The property that keeps a day from having two readings: before the
    activation day, the v2.0.0 format and only that; from it, the farm-bound
    format and only that."""
    from datetime import date as _date

    from hashguard.rules import declared_rule

    activate = (_date.today() - timedelta(days=2)).isoformat()
    identity, ledger = activated_ledger(tmp_path, activate, days=4)

    seals = {seal["day"]: seal for seal in ledger.seals()}
    assert len(seals) == 4
    for day, seal in seals.items():
        expected = 2 if day >= activate else 1
        assert declared_rule(seal) == expected, f"{day} should be rule {expected}"
        if expected == 2:
            assert seal["farm_id"] == identity.farm_id
        else:
            assert "farm_id" not in seal, "a legacy seal must be byte-identical to v2.0.0's"
            assert "rule" not in seal
        ok, reason = verify_seal(seal, ledger.day_records(day), identity.public(), activate)
        assert ok, f"{day}: {reason}"
    assert {declared_rule(s) for s in seals.values()} == {1, 2}, (
        "this test is only meaningful if the activation day is actually crossed"
    )


def test_a_seal_under_the_wrong_rule_for_its_date_is_refused(tmp_path):
    from datetime import date as _date

    activate = (_date.today() - timedelta(days=2)).isoformat()
    identity, ledger = activated_ledger(tmp_path, activate, days=4)
    seals = {seal["day"]: seal for seal in ledger.seals()}
    after = max(day for day in seals if day >= activate)
    before = min(day for day in seals if day < activate)

    # The same seals, judged against an activation day that moved.
    ok, reason = verify_seal(seals[after], ledger.day_records(after), identity.public(), "2099-01-01")
    assert not ok and "must be rule 1" in reason
    ok, reason = verify_seal(seals[before], ledger.day_records(before), identity.public(), "2000-01-01")
    assert not ok and "must be rule 2" in reason


def test_activation_cannot_rewrite_the_rule_of_a_sealed_day(tmp_path):
    """RAMI's "the rule never regresses within a branch", in one farm's ledger:
    once a day is sealed, no later activation can change which format it
    should have been sealed in."""
    identity, ledger = build_ledger(tmp_path, days=2)
    sealed = max(ledger.days())

    with pytest.raises(LedgerError, match="already activated"):
        GuardedLedger(identity, base_dir=ledger.base_dir, activate_from="2099-01-01")

    os.remove(ledger.activation_path)
    with pytest.raises(LedgerError, match="already sealed"):
        GuardedLedger(identity, base_dir=ledger.base_dir, activate_from=sealed)


def test_a_ledger_activated_for_another_farm_is_refused(tmp_path):
    """A device that is not this farm's does not get to append to its ledger,
    even though its key would produce perfectly valid-looking signatures."""
    _, ledger = build_ledger(tmp_path, days=1)
    stranger = DeviceIdentity.generate()
    with pytest.raises(LedgerError, match="another farm's ledger"):
        GuardedLedger(stranger, base_dir=ledger.base_dir)


# -- commit and reveal: the decision predates its own corroboration --------


def write_committed_day(ledger, day, hours, observed=350, sabotage=None):
    """Write a day the way the agent writes it.

    An opening record carrying the first commitment, then one closing record
    per interval, each revealing its own decision and committing the next.
    With ``sabotage`` set to an index, that record reveals a nonce that does
    not match the commitment written before it -- a chain that is perfectly
    consistent, correctly sealed and correctly signed, in which one decision
    was nevertheless written after the fact.
    """
    from hashguard.commit import commit_hash, decision_snapshot, new_nonce

    plan = []
    for hour in hours:
        opened = day.replace(hour=hour, minute=0, second=0, microsecond=0)
        plan.append(
            {
                "opened": opened.isoformat().replace("+00:00", "Z"),
                "closed": opened + timedelta(seconds=POLL_SECONDS),
                "action": "PAUSE",
                "price": to_ppm("0.31"),
                "breakeven": to_ppm("0.098"),
            }
        )
    nonces = [new_nonce() for _ in plan]
    commits = [
        commit_hash(
            decision_snapshot(
                {
                    "action": entry["action"],
                    "price_ppm_per_kwh": entry["price"],
                    "breakeven_ppm_per_kwh": entry["breakeven"],
                    "opened": entry["opened"],
                    "price_curve_hash": None,
                }
            ),
            nonce,
        )
        for entry, nonce in zip(plan, nonces)
    ]

    opening = ledger.record(
        Interval(
            "MINE", True, MACHINES, 0, 0, 0, 0, 0, FULL_FARM_GH, FULL_FARM_GH,
            opened=plan[0]["opened"], commit=commits[0],
        ),
        when=day.replace(hour=hours[0], minute=0, second=0, microsecond=0),
    )
    previous_seq = opening["seq"]
    for index, entry in enumerate(plan):
        nonce = nonces[index]
        if sabotage == index:
            nonce = new_nonce()   # reveals something that was never committed
        stored = ledger.record(
            Interval(
                entry["action"], True, MACHINES, POLL_SECONDS,
                entry["price"], entry["breakeven"],
                to_wh("3.05", POLL_SECONDS, MACHINES), to_micro("0.63"),
                FULL_FARM_GH, observed,
                opened=entry["opened"],
                commit=commits[index + 1] if index + 1 < len(plan) else None,
                reveal={"commit_seq": previous_seq, "nonce": nonce},
            ),
            when=entry["closed"],
        )
        previous_seq = stored["seq"]
    return ledger


def committed_ledger(tmp_path, activate_from, name="ledger", hours=(9, 10, 11), sabotage=None):
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(
        identity, base_dir=str(tmp_path / name), activate_from=activate_from
    )
    day = datetime.now(timezone.utc) - timedelta(days=1)
    write_committed_day(ledger, day, hours, sabotage=sabotage)
    ledger.seal_day(day.date().isoformat())
    return identity, ledger, day.strftime("%Y-%m")


def test_records_carry_the_commit_of_the_interval_they_open_and_the_reveal_of_the_one_they_close(
    tmp_path,
):
    from datetime import date as _date

    from hashguard.commit import REVEALED, UNREVEALED, reveal_state

    activate = (_date.today() - timedelta(days=2)).isoformat()
    _, ledger, _ = committed_ledger(tmp_path, activate)
    records = ledger.day_records(ledger.days()[0])

    previous = None
    states = []
    for record in records:
        states.append(reveal_state(record, previous))
        previous = record
    assert states == [UNREVEALED, REVEALED, REVEALED, REVEALED]
    for record in records[1:]:
        assert record["reveal"]["commit_seq"] == record["seq"] - 1


def test_a_pause_claimed_without_a_matching_reveal_is_not_billed(tmp_path):
    """Same farm, same telemetry, same claimed energy. The difference is
    whether the decision can be shown to predate the measurement."""
    from datetime import date as _date

    activate = (_date.today() - timedelta(days=2)).isoformat()
    _, honest_ledger, month = committed_ledger(tmp_path, activate, name="honest")
    honest = honest_ledger.statement(month)
    assert honest["totals"]["billable_net_saving_micro_eur"] > 0
    assert honest["commit_reveal"]["pause_claims_not_billed_for_lack_of_a_reveal"] == 0
    assert honest["commit_reveal"]["revealed"] == 3

    identity = DeviceIdentity.generate()
    bare = GuardedLedger(identity, base_dir=str(tmp_path / "bare"), activate_from=activate)
    day = datetime.now(timezone.utc) - timedelta(days=1)
    for hour in (9, 10, 11):
        bare.record(
            Interval(
                "PAUSE", True, MACHINES, POLL_SECONDS, to_ppm("0.31"), to_ppm("0.098"),
                to_wh("3.05", POLL_SECONDS, MACHINES), to_micro("0.63"), FULL_FARM_GH, 350,
            ),
            when=day.replace(hour=hour, minute=0, second=0, microsecond=0),
        )
    bare.seal_day(day.date().isoformat())
    uncommitted = bare.statement(month)

    assert (
        uncommitted["totals"]["gross_net_saving_micro_eur"]
        == honest["totals"]["gross_net_saving_micro_eur"]
    ), "the measurement is the same; only its standing changed"
    assert uncommitted["totals"]["billable_net_saving_micro_eur"] == 0
    assert uncommitted["totals"]["fee_micro_eur"] == 0
    assert uncommitted["commit_reveal"]["pause_claims_not_billed_for_lack_of_a_reveal"] == 3


def test_a_reveal_that_does_not_match_its_commit_is_not_billed(tmp_path):
    from datetime import date as _date

    from hashguard.commit import MISMATCHED, reveal_state

    activate = (_date.today() - timedelta(days=2)).isoformat()
    _, ledger, month = committed_ledger(tmp_path, activate, sabotage=1)
    statement = ledger.statement(month)

    records = ledger.day_records(ledger.days()[0])
    previous = None
    states = []
    for record in records:
        states.append(reveal_state(record, previous))
        previous = record
    assert states.count(MISMATCHED) == 1
    assert statement["commit_reveal"]["mismatched"] == 1
    assert statement["commit_reveal"]["pause_claims_not_billed_for_lack_of_a_reveal"] == 1


def test_legacy_records_before_activation_still_bill(tmp_path):
    """Records written before the rule existed carry no commitment, and have
    to keep billing exactly as v2.0.0 billed them."""
    _, ledger = build_ledger(tmp_path, days=1)          # activation is today
    assert combined_totals(ledger)["billable_net_saving_micro_eur"] > 0
    for month in months_in(ledger):
        statement = ledger.statement(month)
        assert statement["commit_reveal"]["legacy"] > 0
        assert statement["commit_reveal"]["mismatched"] == 0
        assert statement["commit_reveal"]["pause_claims_not_billed_for_lack_of_a_reveal"] == 0


def test_a_reveal_across_a_day_boundary_is_followed_into_the_previous_file(tmp_path):
    """The first record of a day reveals a commitment written in the last
    record of the day before. A reader that stops at the file boundary would
    call one interval a day unrevealed -- and stop billing it."""
    from datetime import date as _date

    from hashguard.commit import REVEALED, commit_hash, decision_snapshot, new_nonce, reveal_state

    activate = (_date.today() - timedelta(days=3)).isoformat()
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(identity, base_dir=str(tmp_path / "ledger"), activate_from=activate)
    first = datetime.now(timezone.utc) - timedelta(days=2)
    second = datetime.now(timezone.utc) - timedelta(days=1)

    opened = second.replace(hour=0, minute=0, second=0, microsecond=0)
    snapshot = {
        "action": "PAUSE",
        "price_ppm_per_kwh": to_ppm("0.31"),
        "breakeven_ppm_per_kwh": to_ppm("0.098"),
        "opened": opened.isoformat().replace("+00:00", "Z"),
        "price_curve_hash": None,
    }
    nonce = new_nonce()
    last_of_first_day = ledger.record(
        Interval(
            "MINE", True, MACHINES, 0, 0, 0, 0, 0, FULL_FARM_GH, FULL_FARM_GH,
            opened=first.replace(hour=23, minute=0, second=0, microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            commit=commit_hash(decision_snapshot(snapshot), nonce),
        ),
        when=first.replace(hour=23, minute=30, second=0, microsecond=0),
    )
    ledger.record(
        Interval(
            "PAUSE", True, MACHINES, POLL_SECONDS, snapshot["price_ppm_per_kwh"],
            snapshot["breakeven_ppm_per_kwh"], to_wh("3.05", POLL_SECONDS, MACHINES),
            to_micro("0.63"), FULL_FARM_GH, 350,
            opened=snapshot["opened"],
            reveal={"commit_seq": last_of_first_day["seq"], "nonce": nonce},
        ),
        when=opened + timedelta(seconds=POLL_SECONDS),
    )
    for day in ledger.days():
        ledger.seal_day(day)

    day_two = second.date().isoformat()
    crossing = ledger.day_records(day_two)[0]
    assert reveal_state(crossing, ledger.record_before(day_two)) == REVEALED
    statement = ledger.statement(second.strftime("%Y-%m"))
    if any(entry["day"] == day_two for entry in statement["days"]):
        assert statement["commit_reveal"]["pause_claims_not_billed_for_lack_of_a_reveal"] == 0


def test_the_statement_is_signed_over_its_own_totals(tmp_path):
    """v2.0.0 signed the seals but not the document around them, so the fee and
    the totals a client was handed were unattested."""
    from hashguard.identity import verify_signature
    from hashguard.rules import statement_message

    identity, ledger = build_ledger(tmp_path, days=1)
    for month in months_in(ledger):
        statement = ledger.statement(month)
        farm = identity.farm_id
        assert verify_signature(
            identity.public(), statement_message(farm, statement), statement["signature"]
        )
        inflated = {
            **statement,
            "totals": {**statement["totals"], "billable_net_saving_micro_eur": 999_999_999},
        }
        assert not verify_signature(
            identity.public(), statement_message(farm, inflated), statement["signature"]
        ), "re-totalling a statement must not survive its own signature"
