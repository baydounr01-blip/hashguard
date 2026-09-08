#!/usr/bin/env python3
"""Build a month of measurements, verify the invoice, then break it on purpose.

Run it to see the whole argument in about two seconds:

    python3 scripts/demo_verification.py

It generates three days of a simulated farm, seals them, writes a statement,
runs the standalone verifier over it, then edits one record on disk to inflate
a claim and runs the verifier again. The first run passes; the second names the
day, the check and the reason. CI runs this and fails if either half stops
behaving.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from hashguard.identity import DeviceIdentity  # noqa: E402
from hashguard.ledger import GuardedLedger, Interval  # noqa: E402
from hashguard.money import from_micro, to_micro, to_ppm, to_wh  # noqa: E402

VERIFIER = os.path.join(ROOT, "tools", "hashguard_verify.py")
MACHINES = 6
POLL = 1800


def build(base: str) -> tuple[DeviceIdentity, GuardedLedger, list[str]]:
    identity = DeviceIdentity.generate()
    ledger = GuardedLedger(identity, base_dir=os.path.join(base, "ledger"))
    for back in (3, 2, 1):
        day = datetime.now(timezone.utc) - timedelta(days=back)
        for slot in range(48):
            hour = slot // 2
            peak = 8 <= hour < 12 or 19 <= hour < 23
            ledger.record(
                Interval(
                    action="PAUSE" if peak else "MINE",
                    executed=True,
                    n_miners=MACHINES,
                    seconds=POLL,
                    price_ppm_per_kwh=to_ppm("0.31" if peak else "0.06"),
                    breakeven_ppm_per_kwh=to_ppm("0.098"),
                    claimed_wh=to_wh("3.05", POLL, MACHINES) if peak else 0,
                    claimed_mining_lost_micro_eur=to_micro("0.95") if peak else 0,
                    baseline_gh=630_000,
                    observed_gh=350 if peak else 630_000,
                ),
                when=day.replace(hour=hour, minute=(slot % 2) * 30, second=0, microsecond=0),
            )
        ledger.seal_day(day.date().isoformat())
    months = sorted({seal["day"][:7] for seal in ledger.seals()})
    return identity, ledger, months


def run_verifier(statement: str, records: str, pubkey: str) -> int:
    return subprocess.call(
        [sys.executable, VERIFIER, statement, "--records", records, "--pubkey", pubkey]
    )


def main() -> int:
    base = tempfile.mkdtemp(prefix="hashguard-demo-")
    try:
        identity, ledger, months = build(base)
        pubkey = os.path.join(base, "device_public.json")
        with open(pubkey, "w", encoding="utf-8") as handle:
            json.dump(identity.public(), handle, indent=2)

        failures = 0
        for month in months:
            statement = ledger.statement(month)
            path = os.path.join(base, f"statement-{month}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(statement, handle, indent=2)
            totals = statement["totals"]
            print("=" * 72)
            print(f"HONEST STATEMENT {month}")
            print(
                f"  billable EUR {from_micro(totals['billable_net_saving_micro_eur'])} · "
                f"fee EUR {from_micro(totals['fee_micro_eur'])} · "
                f"client keeps EUR {from_micro(totals['client_keeps_micro_eur'])} · "
                f"corroboration {statement['corroboration']['verdict']}"
            )
            print("=" * 72)
            if run_verifier(path, ledger.records_dir, pubkey) != 0:
                print("!! an untouched statement failed verification", file=sys.stderr)
                failures += 1

        # Now inflate one record on disk, as a dishonest operator would.
        month = months[0]
        path = os.path.join(base, f"statement-{month}.json")
        day = json.load(open(path, encoding="utf-8"))["days"][0]["day"]
        records_path = os.path.join(ledger.records_dir, f"{day}.jsonl")
        lines = open(records_path, encoding="utf-8").read().splitlines()
        record = json.loads(lines[20])
        record["claimed_wh"] = record["claimed_wh"] * 4
        lines[20] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        open(records_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

        print("\n" + "=" * 72)
        print(f"TAMPERED: seq {record['seq']} on {day} had its claimed energy multiplied by four")
        print("=" * 72)
        if run_verifier(path, ledger.records_dir, pubkey) == 0:
            print("!! the verifier accepted a tampered ledger", file=sys.stderr)
            failures += 1
        else:
            print("\nThe verifier caught it, as it must.")

        return 1 if failures else 0
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
