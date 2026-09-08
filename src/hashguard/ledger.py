"""The guarded ledger: an append-only, hash-chained, Merkle-sealed record of
every interval the agent measured, and the invoice derived from it.

The design separates two things that HashGuard v1 mixed together in a mutable
``savings.json``:

* **Records are facts.** One per poll interval. What the price was, how many
  machines there were, what the telemetry saw. Written once, chained to its
  predecessor, never rewritten.
* **Statements are policy applied to facts.** The fee percentage, the
  corroboration cap, the rounding rule. Recomputable by anyone holding the
  records, which means the invoice is a *derivation* the client can repeat, not
  an assertion the client must accept.

Three layers of protection, each answering a different attack:

1. **Hash chain** (``prev`` inside every record) -- catches editing history.
   Change one field of one record from three weeks ago and every subsequent
   record's hash no longer matches its successor's ``prev``.
2. **Merkle seal per day** (``bbu.merkle.LedgerBlockHeader``, verbatim
   construction) -- lets the client verify one invoice line against a 32-byte
   root and a ~15-hash path, without shipping 40 000 records.
3. **Device signature over each seal** -- catches fabrication. A consistent
   chain of invented numbers is easy; a consistent chain of invented numbers
   signed by a key that lives only on the client's own machine is not.

Nothing here trusts the operator, and nothing here trusts the client. That is
the point: the arrangement is *checkable*, so neither party has to be trusted.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date, datetime, timezone

from .attest import DEFAULT_MARGIN_PPM, Claim, SavingsAuditor
from .canonical import (
    SPEC,
    CanonicalError,
    canonical_bytes,
    hexlify,
    record_hash,
    unhexlify,
)
from .identity import DeviceIdentity
from .merkle import GENESIS_SEAL, SealHeader, build_proof, merkle_root
from .money import (
    DEFAULT_FEE_BP,
    client_keeps_micro_eur,
    energy_cost_micro_eur,
    fee_micro_eur,
)

#: The fields of a record, in the order this module writes them. Documented
#: rather than enforced: the canonical encoder sorts keys anyway, so this is
#: here to be read alongside ``tools/hashguard_verify.py``.
RECORD_FIELDS = (
    "spec", "seq", "day", "ts", "prev", "device_id", "action", "executed",
    "n_miners", "seconds", "price_ppm_per_kwh", "breakeven_ppm_per_kwh",
    "claimed_wh", "claimed_mining_lost_micro_eur", "baseline_gh", "observed_gh",
)


class LedgerError(RuntimeError):
    """The ledger on disk is inconsistent with itself."""


def _append_line(path: str, payload: dict) -> None:
    """Append one JSON line and get it onto the disk before returning.

    A savings ledger that loses its last hour to a power cut is a ledger with a
    hole in the chain, and a hole in the chain is indistinguishable from
    tampering. fsync is cheap at one write per minute.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _read_lines(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    out: list[dict] = []
    with open(path, encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise LedgerError(f"{path}:{lineno} is not valid JSON: {exc}") from exc
    return out


@dataclass
class Interval:
    """One measured poll interval, in the units the ledger stores."""

    action: str                       # "MINE" | "PAUSE"
    executed: bool
    n_miners: int
    seconds: int
    price_ppm_per_kwh: int
    breakeven_ppm_per_kwh: int
    claimed_wh: int
    claimed_mining_lost_micro_eur: int
    baseline_gh: int | None
    observed_gh: int | None


class GuardedLedger:
    """Append-only ledger rooted at ``base_dir``."""

    def __init__(
        self,
        identity: DeviceIdentity,
        base_dir: str = "ledger",
        fee_bp: int = DEFAULT_FEE_BP,
        margin_ppm: int = DEFAULT_MARGIN_PPM,
    ) -> None:
        self.identity = identity
        self.base_dir = base_dir
        self.fee_bp = fee_bp
        self.margin_ppm = margin_ppm
        self.records_dir = os.path.join(base_dir, "records")
        self.seals_path = os.path.join(base_dir, "seals.jsonl")
        os.makedirs(self.records_dir, exist_ok=True)
        self._seq, self._prev = self._resume()

    # -- writing ---------------------------------------------------------

    def _resume(self) -> tuple[int, str]:
        """Pick up where the last run stopped, verifying as we go."""
        days = sorted(f for f in os.listdir(self.records_dir) if f.endswith(".jsonl"))
        if not days:
            return 0, hexlify(GENESIS_SEAL)
        last = _read_lines(os.path.join(self.records_dir, days[-1]))
        if not last:
            raise LedgerError(f"{days[-1]} exists but is empty; refusing to guess the chain head")
        head = last[-1]
        return int(head["seq"]) + 1, hexlify(record_hash(head))

    def record(self, interval: Interval, when: datetime | None = None) -> dict:
        """Append one interval and return the stored record."""
        moment = when or datetime.now(timezone.utc)
        record = {
            "spec": SPEC,
            "seq": self._seq,
            "day": moment.date().isoformat(),
            "ts": moment.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "prev": self._prev,
            "device_id": self.identity.device_id,
            "action": interval.action,
            "executed": bool(interval.executed),
            "n_miners": int(interval.n_miners),
            "seconds": int(interval.seconds),
            "price_ppm_per_kwh": int(interval.price_ppm_per_kwh),
            "breakeven_ppm_per_kwh": int(interval.breakeven_ppm_per_kwh),
            "claimed_wh": int(interval.claimed_wh),
            "claimed_mining_lost_micro_eur": int(interval.claimed_mining_lost_micro_eur),
            "baseline_gh": None if interval.baseline_gh is None else int(interval.baseline_gh),
            "observed_gh": None if interval.observed_gh is None else int(interval.observed_gh),
        }
        canonical_bytes(record)  # refuses to store anything it cannot hash
        _append_line(os.path.join(self.records_dir, f"{record['day']}.jsonl"), record)
        self._seq += 1
        self._prev = hexlify(record_hash(record))
        return record

    # -- reading ---------------------------------------------------------

    def day_records(self, day: str) -> list[dict]:
        return _read_lines(os.path.join(self.records_dir, f"{day}.jsonl"))

    def days(self) -> list[str]:
        return sorted(
            f[: -len(".jsonl")]
            for f in os.listdir(self.records_dir)
            if f.endswith(".jsonl")
        )

    def seals(self) -> list[dict]:
        return _read_lines(self.seals_path)

    # -- sealing ---------------------------------------------------------

    def seal_day(self, day: str) -> dict:
        """Close a day: Merkle-root its records, chain the seal, sign it.

        Idempotent -- re-sealing a day returns the existing seal rather than
        forking the chain. Sealing today is refused; a day still receiving
        records cannot be closed without the seal becoming a lie the moment the
        next record lands.
        """
        existing = {s["day"]: s for s in self.seals()}
        if day in existing:
            return existing[day]
        if day >= date.today().isoformat():
            raise LedgerError(f"{day} is not over yet; a day is sealed once it can no longer change")
        records = self.day_records(day)
        if not records:
            raise LedgerError(f"no records for {day}")
        leaves = [record_hash(r) for r in records]
        root = merkle_root(leaves)
        seals = self.seals()
        prev = unhexlify(seals[-1]["seal_hash"]) if seals else GENESIS_SEAL
        header = SealHeader(prev_seal=prev, merkle_root=root)
        auditor = SavingsAuditor(margin_ppm=self.margin_ppm)
        for r in records:
            if r["action"] == "PAUSE" and r["executed"]:
                auditor.submit(Claim(r["seq"], r["claimed_wh"], r["baseline_gh"], r["observed_gh"]))
        body = {
            "spec": SPEC,
            "day": day,
            "device_id": self.identity.device_id,
            "prev_seal": hexlify(prev),
            "merkle_root": hexlify(root),
            "leaf_count": len(leaves),
            "first_seq": int(records[0]["seq"]),
            "last_seq": int(records[-1]["seq"]),
            "seal_hash": hexlify(header.seal_hash),
            "corroboration": auditor.report(),
        }
        body["signature"] = self.identity.sign(canonical_bytes(body))
        body["algorithm"] = self.identity.algorithm
        _append_line(self.seals_path, body)
        return body

    def seal_pending(self) -> list[dict]:
        """Seal every finished day that has no seal yet."""
        sealed = {s["day"] for s in self.seals()}
        today = date.today().isoformat()
        return [self.seal_day(d) for d in self.days() if d < today and d not in sealed]

    # -- billing ---------------------------------------------------------

    def statement(self, month: str, max_proofs: int = 8) -> dict:
        """The month's invoice, with everything needed to check it.

        Only *sealed* days are billed. An unsealed day is still measurable and
        still visible in the console, but it is not chargeable until it is
        closed and signed -- billing fails closed.
        """
        auditor = SavingsAuditor(margin_ppm=self.margin_ppm)
        days: list[dict] = []
        gross_micro = 0
        billable_micro = 0
        advisory_micro = 0
        proof_targets: list[tuple[str, int]] = []

        for seal in self.seals():
            if not seal["day"].startswith(month):
                continue
            records = self.day_records(seal["day"])
            day_billable = 0
            day_gross = 0
            for index, r in enumerate(records):
                if r["action"] != "PAUSE":
                    continue
                claimed_energy = energy_cost_micro_eur(r["claimed_wh"], r["price_ppm_per_kwh"])
                claimed_net = claimed_energy - r["claimed_mining_lost_micro_eur"]
                if not r["executed"]:
                    advisory_micro += claimed_net
                    continue
                day_gross += claimed_net
                claim = Claim(r["seq"], r["claimed_wh"], r["baseline_gh"], r["observed_gh"])
                billable_wh = auditor.submit(claim)
                if billable_wh <= 0:
                    continue
                # The revenue forgone scales with the same fraction of the farm
                # that actually went dark: you only lose the hashrate you stopped.
                share_num, share_den = billable_wh, max(r["claimed_wh"], 1)
                energy = energy_cost_micro_eur(billable_wh, r["price_ppm_per_kwh"])
                lost = r["claimed_mining_lost_micro_eur"] * share_num // share_den
                day_billable += energy - lost
                if len(proof_targets) < max_proofs:
                    proof_targets.append((seal["day"], index))
            gross_micro += day_gross
            billable_micro += day_billable
            days.append(
                {
                    "day": seal["day"],
                    "seal_hash": seal["seal_hash"],
                    "prev_seal": seal["prev_seal"],
                    "merkle_root": seal["merkle_root"],
                    "leaf_count": seal["leaf_count"],
                    "signature": seal["signature"],
                    "algorithm": seal["algorithm"],
                    "corroboration": seal["corroboration"],
                    "gross_net_saving_micro_eur": day_gross,
                    "billable_net_saving_micro_eur": day_billable,
                }
            )

        proofs = []
        for day, index in proof_targets:
            records = self.day_records(day)
            leaves = [record_hash(r) for r in records]
            proofs.append(
                {
                    "day": day,
                    "record": records[index],
                    "leaf": hexlify(leaves[index]),
                    "proof": build_proof(leaves, index).to_json(),
                }
            )

        fee = fee_micro_eur(billable_micro, self.fee_bp)
        return {
            "spec": SPEC,
            "month": month,
            "device": self.identity.public(),
            "fee_bp": self.fee_bp,
            "margin_ppm": self.margin_ppm,
            "days": days,
            "corroboration": auditor.report(),
            "totals": {
                "gross_net_saving_micro_eur": gross_micro,
                "billable_net_saving_micro_eur": billable_micro,
                "advisory_net_saving_micro_eur": advisory_micro,
                "fee_micro_eur": fee,
                "client_keeps_micro_eur": client_keeps_micro_eur(billable_micro, self.fee_bp),
            },
            "proofs": proofs,
            "how_to_verify": (
                "python3 tools/hashguard_verify.py statement.json --records ledger/records "
                "-- recomputes every hash in this document from the raw records. "
                "It imports nothing from HashGuard; read it, it is one file."
            ),
        }


# -- verification, usable without ever having written a record -------------


def verify_chain(records: list[dict]) -> tuple[bool, str]:
    """Is this a contiguous, unbroken hash chain?

    Returns ``(ok, reason)``. The reason names the first record that breaks, so
    a failure is a place to look and not just a red light.
    """
    if not records:
        return True, "empty"
    prev_hash: str | None = None
    prev_seq: int | None = None
    for r in records:
        try:
            canonical_bytes(r)
        except CanonicalError as exc:
            return False, f"seq {r.get('seq')} is not canonically encodable: {exc}"
        if prev_seq is not None and int(r["seq"]) != prev_seq + 1:
            return False, f"sequence jumps from {prev_seq} to {r['seq']}: a record is missing"
        if prev_hash is not None and r["prev"] != prev_hash:
            return False, f"seq {r['seq']} points at {r['prev'][:16]}..., expected {prev_hash[:16]}..."
        prev_seq = int(r["seq"])
        prev_hash = hexlify(record_hash(r))
    return True, f"{len(records)} records chained"


def verify_seal(seal: dict, records: list[dict], public: dict | None = None) -> tuple[bool, str]:
    """Does this seal actually seal these records, and was it signed?"""
    from .identity import verify_signature

    leaves = [record_hash(r) for r in records]
    if len(leaves) != seal["leaf_count"]:
        return False, f"seal claims {seal['leaf_count']} records, found {len(leaves)}"
    root = merkle_root(leaves)
    if hexlify(root) != seal["merkle_root"]:
        return False, "the records do not produce the sealed Merkle root: content was altered"
    header = SealHeader(prev_seal=unhexlify(seal["prev_seal"]), merkle_root=root)
    if hexlify(header.seal_hash) != seal["seal_hash"]:
        return False, "seal_hash is not SHA256d(prev_seal || merkle_root)"
    if public is not None:
        body = {k: v for k, v in seal.items() if k not in ("signature", "algorithm")}
        if not verify_signature(public, canonical_bytes(body), seal["signature"]):
            return False, "signature does not verify against the device key"
    return True, "sealed and signed"
