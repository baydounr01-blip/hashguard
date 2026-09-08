"""The standalone verifier must agree with the package -- and stay independent.

``tools/hashguard_verify.py`` deliberately reimplements the hashing rather than
importing it, so that a client can check an invoice without running our code.
Independence is the point and drift is the risk, so these tests pin the two
implementations to each other on generated data.
"""

import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from hashguard.canonical import canonical_bytes, record_hash, sha256d
from hashguard.identity import DeviceIdentity
from hashguard.ledger import GuardedLedger, Interval
from hashguard.merkle import GENESIS_SEAL, build_proof, merkle_root
from hashguard.money import to_micro, to_ppm, to_wh

VERIFIER_PATH = os.path.join(os.path.dirname(__file__), "..", "tools", "hashguard_verify.py")


@pytest.fixture(scope="module")
def verifier():
    spec = importlib.util.spec_from_file_location("hashguard_verify", VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_verifier_imports_nothing_from_the_package():
    """If it ever imports hashguard, it stops being independent evidence."""
    source = open(VERIFIER_PATH, encoding="utf-8").read()
    assert "import hashguard" not in source
    assert "from hashguard" not in source


# -- the two implementations must agree ------------------------------------


def test_canonical_encoding_agrees(verifier):
    for value in (
        {"a": 1, "b": "two"},
        {"z": [1, 2, {"n": None}], "a": True},
        {"unicode": "café · 30 °C"},
        {},
    ):
        assert verifier.canonical(value) == canonical_bytes(value)


def test_hashes_agree(verifier):
    assert verifier.sha256d(b"x") == sha256d(b"x")
    record = {"seq": 3, "claimed_wh": 18300, "prev": "ab" * 32}
    assert verifier.record_hash(record) == record_hash(record)


def test_merkle_roots_agree(verifier):
    for count in (1, 2, 3, 9, 40):
        leaves = [record_hash({"seq": i}) for i in range(count)]
        assert verifier.merkle_root(leaves) == merkle_root(leaves)


def test_proof_verification_agrees(verifier):
    leaves = [record_hash({"seq": i}) for i in range(23)]
    root = merkle_root(leaves)
    for index in (0, 11, 22):
        proof = build_proof(leaves, index).to_json()
        assert verifier.verify_proof(leaves[index], proof, root)
        assert not verifier.verify_proof(record_hash({"seq": 999}), proof, root)


def test_the_genesis_seal_agrees(verifier):
    assert verifier.GENESIS_SEAL == GENESIS_SEAL


def test_the_verifier_refuses_floats_too(verifier):
    with pytest.raises(ValueError):
        verifier.canonical({"eur": 1.5})


# -- end to end ------------------------------------------------------------


def build_month(tmp_path, honest=True):
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(identity, base_dir=str(tmp_path / "ledger"))
    for back in (3, 2, 1):
        day = datetime.now(timezone.utc) - timedelta(days=back)
        for slot in range(48):
            hour = slot // 2
            peak = 8 <= hour < 12 or 19 <= hour < 23
            ledger.record(
                Interval(
                    action="PAUSE" if peak else "MINE",
                    executed=True,
                    n_miners=6,
                    seconds=1800,
                    price_ppm_per_kwh=to_ppm("0.31" if peak else "0.06"),
                    breakeven_ppm_per_kwh=to_ppm("0.098"),
                    claimed_wh=to_wh("3.05", 1800, 6) if peak else 0,
                    claimed_mining_lost_micro_eur=to_micro("0.95") if peak else 0,
                    baseline_gh=630_000,
                    observed_gh=(350 if honest else 630_000) if peak else 630_000,
                ),
                when=day.replace(hour=hour, minute=(slot % 2) * 30, second=0, microsecond=0),
            )
        ledger.seal_day(day.date().isoformat())
    return identity, ledger


def write_statement(tmp_path, identity, ledger, month):
    statement = ledger.statement(month)
    statement_path = tmp_path / "statement.json"
    key_path = tmp_path / "device_public.json"
    statement_path.write_text(json.dumps(statement, indent=2))
    key_path.write_text(json.dumps(identity.public(), indent=2))
    return str(statement_path), str(key_path)


def run_verifier(verifier, monkeypatch, statement_path, records_dir, key_path):
    monkeypatch.setattr(
        "sys.argv",
        ["hashguard_verify", statement_path, "--records", records_dir, "--pubkey", key_path],
    )
    return verifier.main()


def months_of(ledger):
    return sorted({seal["day"][:7] for seal in ledger.seals()})


def test_an_honest_statement_passes_every_check(tmp_path, verifier, monkeypatch):
    identity, ledger = build_month(tmp_path)
    for month in months_of(ledger):
        statement_path, key_path = write_statement(tmp_path, identity, ledger, month)
        assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) == 0


def test_a_tampered_record_fails_the_verifier(tmp_path, verifier, monkeypatch):
    identity, ledger = build_month(tmp_path)
    month = months_of(ledger)[0]
    statement_path, key_path = write_statement(tmp_path, identity, ledger, month)

    day = json.loads(open(statement_path).read())["days"][0]["day"]
    path = os.path.join(ledger.records_dir, f"{day}.jsonl")
    lines = open(path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[20])
    record["claimed_wh"] = record["claimed_wh"] * 4
    lines[20] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) != 0


def test_a_fabricated_month_is_billed_at_zero(tmp_path, verifier, monkeypatch):
    """The corroboration cap survives the round trip into the statement."""
    identity, ledger = build_month(tmp_path, honest=False)
    for month in months_of(ledger):
        statement = ledger.statement(month)
        assert statement["totals"]["fee_micro_eur"] == 0
        statement_path, key_path = write_statement(tmp_path, identity, ledger, month)
        # It still verifies: nothing was tampered with. It simply bills nothing.
        assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) == 0


def test_a_later_month_verifies_even_though_it_does_not_start_at_genesis(
    tmp_path, verifier, monkeypatch
):
    """Regression: only the very first statement a farm ever produces begins at
    the genesis seal. Every later month opens with a day chaining to a seal from
    the month before -- a real link, but not one this document can check."""
    from datetime import date

    today = date.today()
    first_this_month = today.replace(day=1)
    last_prev = first_this_month - timedelta(days=1)
    first_prev = last_prev.replace(day=1)
    last_prev_prev = first_prev - timedelta(days=1)
    # Two days either side of a month boundary, all comfortably in the past.
    days = [
        last_prev_prev - timedelta(days=1),
        last_prev_prev,
        first_prev,
        first_prev + timedelta(days=1),
    ]

    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(identity, base_dir=str(tmp_path / "ledger"))
    for day in days:
        for hour in (9, 10, 20):
            ledger.record(
                Interval(
                    action="PAUSE",
                    executed=True,
                    n_miners=6,
                    seconds=1800,
                    price_ppm_per_kwh=to_ppm("0.31"),
                    breakeven_ppm_per_kwh=to_ppm("0.098"),
                    claimed_wh=to_wh("3.05", 1800, 6),
                    claimed_mining_lost_micro_eur=to_micro("0.95"),
                    baseline_gh=630_000,
                    observed_gh=350,
                ),
                when=datetime(day.year, day.month, day.day, hour, tzinfo=timezone.utc),
            )
        ledger.seal_day(day.isoformat())

    months = months_of(ledger)
    assert len(months) == 2, "this test needs a month boundary to be meaningful"
    later = months[1]
    statement = ledger.statement(later)
    assert statement["days"][0]["prev_seal"] != GENESIS_SEAL.hex(), (
        "the later month must not start at genesis, or the regression is not exercised"
    )
    statement_path, key_path = write_statement(tmp_path, identity, ledger, later)
    assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) == 0


def test_missing_records_fail_the_verifier(tmp_path, verifier, monkeypatch):
    """An invoice you cannot check against raw records is not an invoice."""
    identity, ledger = build_month(tmp_path)
    month = months_of(ledger)[0]
    statement_path, key_path = write_statement(tmp_path, identity, ledger, month)
    empty = tmp_path / "no_records"
    empty.mkdir()
    assert run_verifier(verifier, monkeypatch, statement_path, str(empty), key_path) != 0
