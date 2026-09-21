"""The standalone verifier must agree with the package -- and stay independent.

``tools/hashguard_verify.py`` deliberately reimplements the hashing rather than
importing it, so that a client can check an invoice without running our code.
Independence is the point and drift is the risk, so these tests pin the two
implementations to each other on generated data.
"""

import importlib.util
import json
import os
from datetime import date, datetime, timedelta, timezone

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


def build_month(tmp_path, honest=True, activate_from=None):
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(
        identity, base_dir=str(tmp_path / "ledger"), activate_from=activate_from
    )
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


def test_a_proof_declaring_the_wrong_leaf_count_is_refused(tmp_path, verifier, monkeypatch):
    """The other half of the CVE-2012-2459 defence.

    A Merkle root does not pin how many leaves produced it -- a tree whose last
    leaf is duplicated shares its parent's root. The seal commits the record
    count, so a proof describing a differently sized tree has to be refused even
    when its path happens to reach the sealed root.
    """
    identity, ledger = build_month(tmp_path)
    month = months_of(ledger)[0]
    statement = ledger.statement(month)
    assert statement["proofs"], "this test needs a proof to tamper with"
    statement["proofs"][0]["proof"]["leaf_count"] += 1

    statement_path = tmp_path / "statement.json"
    key_path = tmp_path / "device_public.json"
    statement_path.write_text(json.dumps(statement, indent=2))
    key_path.write_text(json.dumps(identity.public(), indent=2))

    assert (
        run_verifier(verifier, monkeypatch, str(statement_path), ledger.records_dir, str(key_path))
        != 0
    )


def test_missing_records_fail_the_verifier(tmp_path, verifier, monkeypatch):
    """An invoice you cannot check against raw records is not an invoice."""
    identity, ledger = build_month(tmp_path)
    month = months_of(ledger)[0]
    statement_path, key_path = write_statement(tmp_path, identity, ledger, month)
    empty = tmp_path / "no_records"
    empty.mkdir()
    assert run_verifier(verifier, monkeypatch, statement_path, str(empty), key_path) != 0


# -- the signature rule, seen from outside the package ---------------------


def write_docs(tmp_path, statement, public):
    statement_path = tmp_path / "statement.json"
    key_path = tmp_path / "device_public.json"
    statement_path.write_text(json.dumps(statement, indent=2))
    key_path.write_text(json.dumps(public, indent=2))
    return str(statement_path), str(key_path)


def activated_statement(ledger, activate):
    """The month that actually straddles or follows the activation day."""
    for month in months_of(ledger):
        statement = ledger.statement(month)
        if any(day["day"] >= activate for day in statement["days"]):
            return statement
    raise AssertionError("no sealed month carries a day on or after the activation day")


def test_a_v2_0_0_statement_verifies_unchanged(tmp_path, verifier, monkeypatch, capsys):
    """The compatibility promise: a statement written before this version
    still passes, and the two checks that cannot be made are reported as not
    made rather than quietly skipped."""
    identity, ledger = build_month(tmp_path)
    statement = ledger.statement(months_of(ledger)[0])
    for key in ("farm_id", "activation", "signature", "algorithm"):
        statement.pop(key, None)
    for day in statement["days"]:
        day.pop("rule", None)
    statement["device"].pop("farm_id", None)
    public = {k: v for k, v in identity.public().items() if k != "farm_id"}

    statement_path, key_path = write_docs(tmp_path, statement, public)
    assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) == 0
    output = capsys.readouterr().out
    assert "predates farm-bound signatures" in output
    assert "not signed as a whole" in output


def test_a_rule_1_seal_after_activation_is_refused(tmp_path, verifier, monkeypatch, capsys):
    """Going back to the format that names no farm is how the whole change
    would be undone. The date decides, not the seal."""
    activate = (date.today() - timedelta(days=2)).isoformat()
    identity, ledger = build_month(tmp_path, activate_from=activate)
    statement = activated_statement(ledger, activate)
    target = next(day for day in statement["days"] if day["day"] >= activate)
    target["rule"] = 1

    statement_path, key_path = write_docs(tmp_path, statement, identity.public())
    assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) != 0
    output = capsys.readouterr().out
    assert f"{target['day']}: sealed under the signature rule its date requires" in output


def test_a_rule_2_seal_before_activation_is_refused(tmp_path, verifier, monkeypatch, capsys):
    """And the mirror image, so that no day can be read under either rule."""
    activate = (date.today() - timedelta(days=2)).isoformat()
    identity, ledger = build_month(tmp_path, activate_from=activate)
    statement = activated_statement(ledger, activate)
    moved = "2099-01-01"
    statement["activation"] = {**statement["activation"], "from_day": moved}
    farm_bound = [day for day in statement["days"] if day["day"] >= activate]
    assert farm_bound, "this test needs at least one farm-bound day"

    statement_path, key_path = write_docs(tmp_path, statement, identity.public())
    assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) != 0
    output = capsys.readouterr().out
    for day in farm_bound:
        assert f"{day['day']}: sealed under the signature rule its date requires" in output


def test_a_statement_for_another_farm_is_refused(tmp_path, verifier, monkeypatch, capsys):
    """Same device key, same valid signatures, different farm. The client who
    was handed a key for farm A must not be billed for farm B's ledger."""
    identity, ledger = build_month(tmp_path)
    statement = ledger.statement(months_of(ledger)[0])
    public = dict(identity.public())
    public["farm_id"] = DeviceIdentity.generate().farm_id

    statement_path, key_path = write_docs(tmp_path, statement, public)
    assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) != 0
    assert "for the farm whose key you were given" in capsys.readouterr().out


def test_the_statement_signature_is_checked(tmp_path, verifier, monkeypatch, capsys):
    """A field the arithmetic checks would not notice, changed after signing."""
    identity, ledger = build_month(tmp_path)
    statement = ledger.statement(months_of(ledger)[0])
    statement["margin_ppm"] = statement["margin_ppm"] + 1

    statement_path, key_path = write_docs(tmp_path, statement, identity.public())
    assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) != 0
    assert "signed by the device key, totals included" in capsys.readouterr().out


def test_the_activation_entry_cannot_be_moved_without_breaking_its_signature(
    tmp_path, verifier, monkeypatch, capsys
):
    identity, ledger = build_month(tmp_path)
    statement = ledger.statement(months_of(ledger)[0])
    statement["activation"] = {**statement["activation"], "from_day": "2099-01-01"}

    statement_path, key_path = write_docs(tmp_path, statement, identity.public())
    assert run_verifier(verifier, monkeypatch, statement_path, ledger.records_dir, key_path) != 0
    assert "activation entry is signed by the device key" in capsys.readouterr().out
