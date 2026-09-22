#!/usr/bin/env python3
"""hashguard_verify -- check a HashGuard invoice without trusting HashGuard.

This file imports nothing from the HashGuard package. It is deliberately one
short, dependency-free file so that a client, an auditor, or a sceptical
accountant can read the whole thing in ten minutes and satisfy themselves that
it does what it says: recompute every hash in the statement from the raw
records, and report where -- if anywhere -- the arithmetic stops agreeing.

    python3 hashguard_verify.py statement.json --records ledger/records
    python3 hashguard_verify.py statement.json --records ledger/records --pubkey device_public.json

Exit code 0 means every check passed. Any other exit code means do not pay the
invoice until someone explains why.

What it checks
--------------
1. Each record is canonically encodable and its ``prev`` matches the hash of
   the record before it -- history has not been edited.
2. Sequence numbers are contiguous -- no record has been removed.
3. Each day's records reproduce the sealed Merkle root, and
   seal_hash == SHA256d(prev_seal || merkle_root).
4. The seals chain: each day's ``prev_seal`` is the previous day's seal hash.
5. Every inclusion proof validates against its root, and describes a tree of
   the size the seal committed to.
6. Signatures verify against the device public key (ed25519, if provided).
7. The money adds up: fee + client_keeps == billable, fee == billable * fee_bp
   // 10000, and no line bills more energy than the telemetry corroborated.
8. Each day is sealed under exactly the signature rule its date requires. From
   the activation day written into the ledger, a seal's signed message carries
   the farm's identifier, so a seal cannot be moved between farms; before it,
   seals are signed the way v2.0.0 signed them. A day sealed under the wrong
   rule for its date is refused -- never both, for any day.
9. The statement itself is signed, so the document around the seals cannot be
   re-typed between the farm and the invoice.
10. **The bill is recomputed from the records**, not merely checked against
   itself. Every figure in check 7 is one the statement supplied; this walks
   the raw records and works out what those figures should have been, with the
   published formulas, in integers. A statement whose totals the records do not
   support fails here even when its own arithmetic closes perfectly.
11. Every reveal reproduces the commitment written a record earlier. From the
   activation day a claimed pause is only billable if the decision behind it
   was committed before the interval ran -- so a farm that went dark for an
   unrelated reason cannot have the pause written around it afterwards.

A statement written by v2.0.0 carries no activation and no farm identifier.
It still verifies here, and this file says so rather than passing quietly:
checks 8 and 9 are reported as not performed, and its records are named
*legacy* rather than treated as broken commitments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import date, timedelta

SPEC = "hashguard-ledger/2"
GENESIS_SEAL = hashlib.sha256(hashlib.sha256(b"hashguard/v2/genesis").digest()).digest()
PPM = 1_000_000
MIN_DARK_FRACTION_PPM = 50_000

# The two signature rules. 1 is what v2.0.0 wrote: Sign(canonical(body)), with
# no farm named anywhere in the message. 2 puts the farm inside it.
RULE_LEGACY = 1
RULE_FARM_BOUND = 2
SEAL_SIG_TAG_V2 = b"hashguard-ledger/2/seal-sig/2"
ACTIVATION_SIG_TAG = b"hashguard-ledger/2/activation-sig/1"
STATEMENT_SIG_TAG = b"hashguard-ledger/2/statement-sig/1"
ACTIVATION_KIND = "activation/1"
STATEMENT_UNSIGNED_KEYS = ("signature", "algorithm", "how_to_verify", "mode", "note")


def farm_id_bytes(farm_id):
    """32 bytes of hex, or an exception. Never coerced into something else."""
    if not isinstance(farm_id, str):
        raise ValueError("farm_id must be a hex string")
    raw = bytes.fromhex(farm_id)
    if len(raw) != 32:
        raise ValueError(f"farm_id must be 32 bytes, got {len(raw)}")
    return raw


def rule_for(day, from_day):
    """Which rule a day must be sealed under. Pure, so every reader agrees."""
    if not from_day:
        return RULE_LEGACY
    return RULE_FARM_BOUND if day >= from_day else RULE_LEGACY


def seal_message(rule, farm_id, body):
    if rule == RULE_LEGACY:
        return canonical(body)
    if body.get("farm_id") != farm_id:
        raise ValueError("the seal body names a different farm than the message")
    return SEAL_SIG_TAG_V2 + farm_id_bytes(farm_id) + canonical(body)


# ------------------------------------------------- commit and reveal
# A record carries the commitment of the decision that governs the interval it
# opens; the next record reveals it. The commitment is therefore on disk, and
# under the day's seal, before the telemetry that corroborates the claim was
# ever read -- which is what stops a pause being written around a farm that
# went dark for an unrelated reason.

DECISION_FIELDS = ("action", "price_ppm_per_kwh", "breakeven_ppm_per_kwh", "opened", "price_curve_hash")
COMMIT_TAG = SPEC + "/commit"
REVEALED = "revealed"
UNREVEALED = "unrevealed"
MISMATCHED = "mismatched"
LEGACY = "legacy"


def decision_snapshot(record):
    return {field: record.get(field) for field in DECISION_FIELDS}


def commit_hash(snapshot, nonce):
    raw = bytes.fromhex(nonce)
    if len(raw) != 32:
        raise ValueError(f"nonce must be 32 bytes, got {len(raw)}")
    return tagged(COMMIT_TAG, canonical(snapshot) + raw).hex()


def reveal_state(record, predecessor):
    """How this record stands with respect to its predecessor's commitment.

    ``unrevealed`` and ``legacy`` are not accusations: the first means the
    agent restarted, the second that the record predates the rule. Neither is
    billable. ``mismatched`` is the one that means something was changed.
    """
    reveal = record.get("reveal")
    if reveal is None:
        if predecessor is None or predecessor.get("commit") is None:
            return LEGACY if record.get("commit") is None else UNREVEALED
        return UNREVEALED
    if predecessor is None or predecessor.get("commit") is None or not isinstance(reveal, dict):
        return MISMATCHED
    try:
        # Exactly its predecessor, never itself and never a record further
        # back: that ordering is the whole guarantee.
        if int(reveal.get("commit_seq", -1)) != int(record["seq"]) - 1:
            return MISMATCHED
        if int(predecessor["seq"]) != int(record["seq"]) - 1:
            return MISMATCHED
        computed = commit_hash(decision_snapshot(record), reveal.get("nonce"))
    except (KeyError, TypeError, ValueError):
        return MISMATCHED
    return REVEALED if computed == predecessor["commit"] else MISMATCHED


# ------------------------------------------------- the money, from scratch


def _half_even(numerator, denominator):
    """Round half to even, in integers.

    The agent rounds with ``decimal.ROUND_HALF_EVEN``. Both sides of an invoice
    have to round the same way, or the last micro-euro is an argument nobody
    can settle -- which is the argument this whole file exists to prevent.
    """
    whole, remainder = divmod(numerator, denominator)
    twice = 2 * remainder
    if twice > denominator or (twice == denominator and whole % 2):
        whole += 1
    return whole


def energy_cost_micro_eur(wh, price_ppm_per_kwh):
    return _half_even(int(wh) * int(price_ppm_per_kwh), 1000)


def corroborated_wh(record):
    """What the hashrate telemetry witnessed, in watt-hours. Never more than
    was claimed, and zero when there is no usable baseline."""
    baseline = record.get("baseline_gh")
    observed = record.get("observed_gh")
    if baseline is None or observed is None or int(baseline) <= 0:
        return 0
    fraction = max(0, min(PPM, (int(baseline) - int(observed)) * PPM // int(baseline)))
    if fraction < MIN_DARK_FRACTION_PPM:
        return 0
    return int(record["claimed_wh"]) * fraction // PPM


def previous_record(records_dir, day):
    """The record before this day's first one. A reveal at a day boundary
    names a commitment that lives in the previous day's file."""
    try:
        previous = (date.fromisoformat(day) - timedelta(days=1)).isoformat()
    except (TypeError, ValueError):
        return None
    records = read_records(records_dir, previous)
    return records[-1] if records else None


# ---------------------------------------------------------------- hashing


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


#: The largest integer JavaScript and Python still agree about. A ledger is
#: meant to be checkable in a browser, so a value past this point is one the
#: two readers would hash differently -- and it is refused here as it is in the
#: agent, rather than hashed into a digest only one of them can reproduce.
MAX_SAFE_INT = 2**53 - 1


def canonical(value) -> bytes:
    _reject_unhashable(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _reject_unhashable(value, path="$"):
    if isinstance(value, float):
        raise ValueError(f"{path}: the canonical form admits no floats")
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if value > MAX_SAFE_INT or value < -MAX_SAFE_INT:
            raise ValueError(
                f"{path}: {value} is outside ±(2**53 - 1); JavaScript cannot tell it "
                "from its neighbour, so it has no single canonical reading"
            )
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            _reject_unhashable(v, f"{path}[{i}]")
    elif isinstance(value, dict):
        for k, v in value.items():
            _reject_unhashable(v, f"{path}.{k}")


def tagged(tag: str, data: bytes) -> bytes:
    return sha256d(hashlib.sha256(tag.encode()).digest() + data)


def record_hash(record: dict) -> bytes:
    return tagged(SPEC + "/record", canonical(record))


def node(left: bytes, right: bytes) -> bytes:
    return tagged(SPEC + "/node", left + right)


def merkle_root(leaves):
    if not leaves:
        raise ValueError("empty tree")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def verify_proof(leaf: bytes, proof: dict, root: bytes) -> bool:
    index, count = int(proof["index"]), int(proof["leaf_count"])
    if not 0 <= index < count:
        return False
    depth, width = 0, count
    while width > 1:
        width = (width + 1) // 2
        depth += 1
    if len(proof["path"]) != depth:
        return False
    cur = leaf
    for step in proof["path"]:
        sibling = bytes.fromhex(step["hash"])
        if len(sibling) != 32:
            return False
        cur = node(sibling, cur) if step["side"] == "L" else node(cur, sibling)
    return cur == root


# ---------------------------------------------------------------- checks


class Report:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.notes: list[str] = []

    def check(self, ok: bool, label: str, detail: str = "") -> bool:
        if ok:
            print(f"  \033[32mPASS\033[0m  {label}")
        else:
            print(f"  \033[31mFAIL\033[0m  {label}" + (f"\n        {detail}" if detail else ""))
            self.failures.append(label)
        return ok

    def note(self, text: str) -> None:
        print(f"  \033[33mNOTE\033[0m  {text}")
        self.notes.append(text)


def read_records(records_dir: str, day: str) -> list[dict]:
    path = os.path.join(records_dir, f"{day}.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def check_chain(records: list[dict], report: Report, day: str) -> None:
    prev_hash = None
    prev_seq = None
    for r in records:
        if prev_seq is not None and int(r["seq"]) != prev_seq + 1:
            report.check(False, f"{day}: contiguous sequence", f"jumps {prev_seq} -> {r['seq']}")
            return
        if prev_hash is not None and r["prev"] != prev_hash:
            report.check(False, f"{day}: hash chain", f"seq {r['seq']} points at the wrong predecessor")
            return
        prev_seq, prev_hash = int(r["seq"]), record_hash(r).hex()
    report.check(True, f"{day}: {len(records)} records, chain unbroken")


def verify_signature(public: dict, message: bytes, signature_b64: str, report: Report) -> bool | None:
    import base64
    import binascii

    algorithm = public.get("algorithm")
    try:
        signature = base64.b64decode(signature_b64 or "", validate=True)
    except (binascii.Error, ValueError, TypeError):
        # A malformed signature is a failed check, not a traceback: this file
        # is read by people who need an answer, not a stack.
        return False
    if algorithm == "ed25519":
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except Exception:  # noqa: BLE001
            report.note("ed25519 signatures not checked: install 'cryptography' to check them")
            return None
        try:
            Ed25519PublicKey.from_public_bytes(
                base64.b64decode(public["public_key_b64"])
            ).verify(signature, message)
            return True
        except (InvalidSignature, ValueError, KeyError):
            return False
    if algorithm == "hmac-sha256":
        secret = public.get("secret_b64")
        if not secret:
            report.note(
                "seals are HMAC-signed: only a holder of the shared secret can check them. "
                "Ask for an ed25519 device key if you want third-party auditability."
            )
            return None
        import hmac

        expected = hmac.new(base64.b64decode(secret), message, "sha256").digest()
        return hmac.compare_digest(expected, signature)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("statement", help="the statement JSON handed to you")
    parser.add_argument("--records", required=True, help="directory of daily .jsonl record files")
    parser.add_argument("--pubkey", help="device public key JSON (for signature checks)")
    args = parser.parse_args()

    with open(args.statement, encoding="utf-8") as handle:
        statement = json.load(handle)
    public = statement.get("device", {})
    if args.pubkey:
        with open(args.pubkey, encoding="utf-8") as handle:
            public = json.load(handle)

    report = Report()
    print(f"\nHashGuard statement · {statement.get('month')} · spec {statement.get('spec')}")
    report.check(statement.get("spec") == SPEC, "statement uses a known spec version")

    # -- which farm, and from which day the seals say so ------------------
    # A seal signed over a message that names no farm is a seal that can be
    # presented as any farm's, by anyone holding the key. From the activation
    # day written into the ledger, the farm is inside the signed bytes.
    print("\nThe farm this statement is for")
    activation = statement.get("activation")
    farm_id = statement.get("farm_id")
    from_day = None
    if not activation:
        report.note(
            "this statement predates farm-bound signatures. Its seals are signed over a "
            "message that names no farm, so a seal produced for another farm with the same "
            "key would verify here. Ask for a statement from HashGuard 2.1 or later."
        )
    else:
        known = activation.get("kind") == ACTIVATION_KIND
        report.check(known, "the activation entry is of a kind this file knows", f"kind {activation.get('kind')!r}")
        if known:
            from_day = activation.get("from_day")
            report.check(
                isinstance(from_day, str) and len(from_day) == 10,
                "the activation entry names the day farm-bound seals begin",
                f"got {from_day!r}",
            )
            report.check(
                bool(farm_id) and activation.get("farm_id") == farm_id,
                "the statement and its activation entry name the same farm",
            )
            body = {k: v for k, v in activation.items() if k not in ("signature", "algorithm")}
            message = None
            try:
                message = ACTIVATION_SIG_TAG + farm_id_bytes(activation.get("farm_id")) + canonical(body)
            except ValueError as exc:
                report.check(False, "the activation entry names a well-formed farm", str(exc))
            if message is not None:
                verdict = verify_signature(public, message, activation.get("signature"), report)
                if verdict is not None:
                    report.check(verdict, "the activation entry is signed by the device key")
            print(f"  farm {farm_id}")
            print(f"  seals name this farm from {from_day} onward; days before it are signed as v2.0.0 signed them")
    if args.pubkey and public.get("farm_id") and farm_id:
        report.check(
            public["farm_id"] == farm_id,
            "this statement is for the farm whose key you were given",
            f"the key names {str(public.get('farm_id'))[:16]}..., the statement names {str(farm_id)[:16]}...",
        )
    elif args.pubkey and public.get("farm_id"):
        # The key names a farm and the statement names none. That is what a
        # pre-2.1 statement looks like once the farm has upgraded, and it is
        # not a mismatch: the statement makes no claim about which farm it is
        # for, so there is nothing here to disagree with. Failing it would
        # teach an operator that a red line is normal, which is how a verifier
        # stops being read. Say what is missing instead.
        report.note(
            f"the key you were given names farm {str(public.get('farm_id'))[:16]}..., and this "
            "statement names no farm at all. It predates farm binding, so it cannot be tied to "
            "that key beyond the signature itself -- which any ledger signed by this device "
            "would also satisfy."
        )
    elif args.pubkey and activation:
        report.note(
            "the device key file you were given predates farm identifiers. Ask for a fresh "
            "device_public.json and compare its farm id with the one above, out of band."
        )

    print("\nRecords and seals")
    # A statement covers one month, so its first day usually chains to a seal
    # from the month before rather than to genesis. That link is real but not
    # checkable from this document alone; the rest of the days chain here.
    expected_prev = None
    seen_days = []
    for day_entry in statement.get("days", []):
        day = day_entry["day"]
        seen_days.append(day)
        records = read_records(args.records, day)
        if not records:
            report.check(False, f"{day}: records present", f"no {day}.jsonl under {args.records}")
            continue
        check_chain(records, report, day)
        leaves = [record_hash(r) for r in records]
        report.check(
            len(leaves) == day_entry["leaf_count"],
            f"{day}: record count matches the seal",
            f"seal says {day_entry['leaf_count']}, found {len(leaves)}",
        )
        root = merkle_root(leaves)
        report.check(
            root.hex() == day_entry["merkle_root"],
            f"{day}: records reproduce the sealed Merkle root",
            "the content of at least one record differs from what was sealed",
        )
        computed = sha256d(bytes.fromhex(day_entry["prev_seal"]) + root).hex()
        report.check(computed == day_entry["seal_hash"], f"{day}: seal_hash = SHA256d(prev_seal || root)")
        if expected_prev is None:
            if day_entry["prev_seal"] == GENESIS_SEAL.hex():
                report.check(True, f"{day}: chains to the genesis seal")
            else:
                report.note(
                    f"{day} chains to seal {day_entry['prev_seal'][:16]}..., which was sealed "
                    "before this statement begins. Check it against the previous month's "
                    "statement to follow the chain back further."
                )
        else:
            report.check(
                day_entry["prev_seal"] == expected_prev,
                f"{day}: seal chains to the previous sealed day",
                f"expected prev_seal {expected_prev[:16]}..., got {day_entry['prev_seal'][:16]}...",
            )
        expected_prev = day_entry["seal_hash"]

        # Exactly one rule governs a day, and which one is a function of the
        # date against the activation entry -- not of what the seal prefers to
        # claim. A legacy seal dated after activation is how someone would go
        # back to the format that names no farm; it is refused here.
        declared = int(day_entry.get("rule", RULE_LEGACY))
        required = rule_for(day, from_day)
        if not report.check(
            declared == required,
            f"{day}: sealed under the signature rule its date requires",
            f"the seal declares rule {declared}, and farm-bound signatures were activated "
            f"from {from_day or 'never'}, so this day must be rule {required}",
        ):
            continue
        body = {
            "spec": SPEC,
            "day": day,
            "device_id": public.get("device_id"),
            "prev_seal": day_entry["prev_seal"],
            "merkle_root": day_entry["merkle_root"],
            "leaf_count": day_entry["leaf_count"],
            "first_seq": int(records[0]["seq"]),
            "last_seq": int(records[-1]["seq"]),
            "seal_hash": day_entry["seal_hash"],
            "corroboration": day_entry["corroboration"],
        }
        if declared == RULE_FARM_BOUND:
            body["rule"] = RULE_FARM_BOUND
            body["farm_id"] = farm_id
        try:
            message = seal_message(declared, farm_id, body)
        except ValueError as exc:
            report.check(False, f"{day}: the seal names a well-formed farm", str(exc))
            continue
        verdict = verify_signature(public, message, day_entry["signature"], report)
        if verdict is not None:
            report.check(verdict, f"{day}: seal signed by the device key")

    print("\nInclusion proofs")
    if not statement.get("proofs"):
        report.note("the statement carries no inclusion proofs to sample")
    roots = {d["day"]: bytes.fromhex(d["merkle_root"]) for d in statement.get("days", [])}
    counts = {d["day"]: int(d["leaf_count"]) for d in statement.get("days", [])}
    for item in statement.get("proofs", []):
        leaf = record_hash(item["record"])
        # The proof has to describe the tree the seal committed to, not merely a
        # tree of the same depth. A Bitcoin-shaped tree whose last leaf is
        # duplicated shares its root (CVE-2012-2459), so the leaf count is what
        # says which tree this is -- and the seal is where that count is fixed.
        sized = int(item["proof"].get("leaf_count", -1)) == counts.get(item["day"])
        ok_leaf = leaf.hex() == item["leaf"]
        ok_path = sized and ok_leaf and verify_proof(leaf, item["proof"], roots.get(item["day"], b""))
        report.check(
            ok_path,
            f"seq {item['record']['seq']} ({item['day']}) is in the sealed tree",
            "the proof does not lead to the sealed root, or describes a tree of a "
            "different size than the seal committed to",
        )

    print("\nBilling arithmetic")
    totals = statement.get("totals", {})
    fee_bp = int(statement.get("fee_bp", 0))
    billable = int(totals.get("billable_net_saving_micro_eur", 0))
    fee = int(totals.get("fee_micro_eur", 0))
    keeps = int(totals.get("client_keeps_micro_eur", 0))
    expected_fee = (billable * fee_bp) // 10_000 if billable > 0 else 0
    report.check(fee == expected_fee, f"fee is exactly {fee_bp/100:.2f}% of billable savings, rounded down")
    report.check(fee + keeps == billable, "fee + what you keep == billable savings, to the micro-euro")
    report.check(billable >= 0 or fee == 0, "a month that lost money is not billed")
    report.check(
        billable <= int(totals.get("gross_net_saving_micro_eur", 0)) or billable <= 0,
        "billable never exceeds gross: the corroboration cap was applied",
    )

    # -- and now the same bill, derived again from the raw records ---------
    # Everything above this point checks the statement against itself. These
    # figures come from walking the records with the published formulas, so a
    # total the measurements do not support fails here even when the
    # arithmetic around it closes perfectly.
    print("\nThe bill, recomputed from the records")
    gross_again = billable_again = advisory_again = 0
    claimed_wh_again = corroborated_again = billable_wh_again = 0
    uncommitted = 0
    states = {REVEALED: 0, UNREVEALED: 0, MISMATCHED: 0, LEGACY: 0}

    for day_entry in statement.get("days", []):
        day = day_entry["day"]
        records = read_records(args.records, day)
        if not records:
            continue
        previous = previous_record(args.records, day)
        require_reveal = rule_for(day, from_day) == RULE_FARM_BOUND
        for r in records:
            state = reveal_state(r, previous)
            states[state] = states.get(state, 0) + 1
            previous = r
            if r.get("action") != "PAUSE":
                continue
            claimed = int(r["claimed_wh"])
            lost_claim = int(r["claimed_mining_lost_micro_eur"])
            net = energy_cost_micro_eur(claimed, r["price_ppm_per_kwh"]) - lost_claim
            if not r.get("executed"):
                advisory_again += net
                continue
            gross_again += net
            if require_reveal and state != REVEALED:
                # Billing fails closed: a claim whose decision cannot be shown
                # to predate its own corroboration is the operator's loss.
                uncommitted += 1
                continue
            claimed_wh_again += claimed
            witnessed = corroborated_wh(r)
            corroborated_again += witnessed
            payable = min(claimed, witnessed)
            billable_wh_again += payable
            if payable <= 0:
                continue
            lost = lost_claim * payable // max(claimed, 1)
            billable_again += energy_cost_micro_eur(payable, r["price_ppm_per_kwh"]) - lost

    for label, mine, theirs in (
        ("gross measured savings", gross_again, totals.get("gross_net_saving_micro_eur", 0)),
        ("billable savings", billable_again, totals.get("billable_net_saving_micro_eur", 0)),
        ("advisory savings", advisory_again, totals.get("advisory_net_saving_micro_eur", 0)),
    ):
        report.check(
            mine == int(theirs or 0),
            f"the records reproduce the statement's {label}",
            f"the records give {mine}, the statement says {int(theirs or 0)} (micro-EUR)",
        )
    report.check(
        billable_again * fee_bp // 10_000 == fee if billable_again > 0 else fee == 0,
        "the fee follows from the savings the records support, not from the stated total",
    )

    corroboration = statement.get("corroboration", {})
    for label, mine, theirs in (
        ("claimed", claimed_wh_again, corroboration.get("claimed_wh", 0)),
        ("corroborated", corroborated_again, corroboration.get("corroborated_wh", 0)),
        ("billable", billable_wh_again, corroboration.get("billable_wh", 0)),
    ):
        report.check(
            mine == int(theirs or 0),
            f"the records reproduce the statement's {label} energy",
            f"the records give {mine} Wh, the statement says {int(theirs or 0)} Wh",
        )

    print("\nCommitments")
    declared = statement.get("commit_reveal") or {}
    if not declared and states[LEGACY] == sum(states.values()):
        report.note(
            "these records predate commit/reveal: nothing in them shows that a decision was "
            "fixed before the telemetry that corroborates it was read. Ask for a ledger from "
            "HashGuard 2.1 or later."
        )
    else:
        report.check(
            states[MISMATCHED] == 0,
            "every reveal reproduces the commitment written a record earlier",
            f"{states[MISMATCHED]} record(s) reveal a decision that does not match what was "
            "committed before the interval ran",
        )
        print(
            f"  {states[REVEALED]} revealed · {states[UNREVEALED]} unrevealed (restarts and "
            f"day boundaries) · {states[LEGACY]} pre-2.1"
        )
        if declared:
            report.check(
                uncommitted == int(declared.get("pause_claims_not_billed_for_lack_of_a_reveal", 0)),
                "the statement counts the same uncommitted claims this file found",
                f"the records give {uncommitted}, the statement says "
                f"{declared.get('pause_claims_not_billed_for_lack_of_a_reveal')}",
            )
        if uncommitted:
            report.note(
                f"{uncommitted} claimed pause(s) were measured but not billed, because the "
                "decision behind them cannot be shown to predate the telemetry. That is the "
                "operator's loss, not yours."
            )

    report.check(
        int(corroboration.get("billable_wh", 0)) <= int(corroboration.get("corroborated_wh", 0)),
        "no line bills more energy than the telemetry witnessed",
    )
    if corroboration.get("verdict") in ("OVERCLAIMED", "UNCORROBORATED"):
        report.note(
            f"corroboration verdict is {corroboration['verdict']}: the ledger claimed savings the "
            "telemetry does not support. The cap was applied, but ask what happened."
        )

    # -- the document, not just the seals inside it -----------------------
    print("\nThe statement as a document")
    if "signature" not in statement:
        report.note(
            "this statement is not signed as a whole (HashGuard before 2.1). Its seals are "
            "signed, so the measurements behind it are attested, but the totals, the fee and "
            "the proofs around them could have been re-typed after the farm produced them."
        )
    elif not farm_id:
        report.check(False, "a signed statement names the farm it is signed for")
    else:
        body = {k: v for k, v in statement.items() if k not in STATEMENT_UNSIGNED_KEYS}
        message = None
        try:
            message = STATEMENT_SIG_TAG + farm_id_bytes(farm_id) + canonical(body)
        except ValueError as exc:
            report.check(False, "the statement names a well-formed farm", str(exc))
        if message is not None:
            verdict = verify_signature(public, message, statement.get("signature"), report)
            if verdict is not None:
                report.check(verdict, "the statement is signed by the device key, totals included")

    print()
    if report.failures:
        print(f"\033[31m{len(report.failures)} check(s) FAILED.\033[0m Do not pay this statement until they are explained.")
        for failure in report.failures:
            print(f"  - {failure}")
        return 2
    euros = billable / 1_000_000
    fee_eur = fee / 1_000_000
    print(f"\033[32mAll checks passed.\033[0m {len(seen_days)} sealed day(s).")
    print(f"Billable net savings EUR {euros:.2f} · fee EUR {fee_eur:.2f} · you keep EUR {keeps/1_000_000:.2f}")
    if report.notes:
        print(f"({len(report.notes)} note(s) above — passed, but worth reading.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
