#!/usr/bin/env python3
"""Drive a HashGuard ledger through its public API -- under either version.

``tools/compat/roundtrip.sh`` runs *this same file* against the published
version and against the working tree, so that the two ledgers being compared
were produced by the same instructions and differ only in the code that
executed them. That is also why it uses nothing but the documented surface:
``DeviceIdentity``, ``GuardedLedger``, ``Interval``, ``record``, ``seal_day``
and ``statement``. If a release breaks this script, it has broken the surface
an integrator was told to build on, and the round trip says so before the
release does.

Where the versions genuinely differ, the difference is *detected*, never
assumed. ``Interval`` grew commit/reveal fields in 2.1; this script asks the
dataclass whether they exist rather than testing a version string, because a
version string is a claim and a field list is a fact.

    build_days.py capabilities
    build_days.py write   --ledger DIR --key FILE --days 30 --end 2026-09-10
    build_days.py seal    --ledger DIR --key FILE
    build_days.py statement --ledger DIR --key FILE --month 2026-09 --out s.json
    build_days.py pubkey  --key FILE --out device_public.json
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from datetime import date, datetime, timedelta, timezone

from hashguard.identity import DeviceIdentity
from hashguard.ledger import GuardedLedger, Interval

#: Six records a day: a four-hour poll. Enough for a Merkle tree with real
#: inclusion proofs, few enough that a month builds in seconds.
RECORDS_PER_DAY = 6
POWER_KW_PER_MACHINE = 3
MACHINES = 4


def interval_fields() -> set:
    return {field.name for field in dataclasses.fields(Interval)}


def supports_commit_reveal() -> bool:
    return {"commit", "reveal", "opened"} <= interval_fields()


def version() -> str:
    try:
        from hashguard import __version__

        return __version__
    except ImportError:  # pragma: no cover - every version ships one
        return "unknown"


# ---------------------------------------------------------------------------


def decision_for(day: date, tick: int) -> dict:
    """A deterministic mine/pause pattern.

    Deterministic on purpose: both versions must be able to write the *same*
    month, so that a difference between the two ledgers is a difference in the
    code and never in the dice.
    """
    hour = tick * (24 // RECORDS_PER_DAY)
    expensive = (day.toordinal() + tick) % 3 == 0
    price = 210_000 if expensive else 41_000
    return {
        "action": "PAUSE" if expensive else "MINE",
        "price_ppm_per_kwh": price,
        "breakeven_ppm_per_kwh": 57_000,
        "hour": hour,
        "curve": {h: 40_000 + 10_000 * ((day.toordinal() + h) % 12) for h in range(24)},
    }


def iso(moment: datetime) -> str:
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write(args) -> int:
    identity = DeviceIdentity.load_or_create(args.key)
    ledger = GuardedLedger(identity, base_dir=args.ledger)
    end = date.fromisoformat(args.end)
    start = end - timedelta(days=args.days - 1)
    seconds = 86400 // RECORDS_PER_DAY

    commits = supports_commit_reveal() and not args.no_commit
    if commits:
        from hashguard.commit import commit_hash, decision_snapshot, new_nonce, price_curve_hash

    open_interval = None
    written = 0
    for offset in range(args.days):
        day = start + timedelta(days=offset)
        for tick in range(RECORDS_PER_DAY):
            decision = decision_for(day, tick)
            when = datetime(
                day.year, day.month, day.day, decision["hour"], 0, 0, tzinfo=timezone.utc
            )
            common = {
                "n_miners": MACHINES,
                "baseline_gh": 400_000,
                "executed": True,
            }
            if open_interval is None:
                # The first record of a session closes nothing. Under 2.1 it
                # still carries a commitment, because the commitment needs
                # somewhere to go; under 2.0.0 it is simply a zero-second row.
                fields = dict(
                    common,
                    action="MINE",
                    seconds=0,
                    price_ppm_per_kwh=0,
                    breakeven_ppm_per_kwh=0,
                    claimed_wh=0,
                    claimed_mining_lost_micro_eur=0,
                    observed_gh=400_000,
                )
            else:
                paused = open_interval["action"] == "PAUSE"
                fields = dict(
                    common,
                    action=open_interval["action"],
                    seconds=seconds,
                    price_ppm_per_kwh=open_interval["price_ppm_per_kwh"],
                    breakeven_ppm_per_kwh=open_interval["breakeven_ppm_per_kwh"],
                    claimed_wh=(POWER_KW_PER_MACHINE * 1000 * seconds * MACHINES) // 3600
                    if paused
                    else 0,
                    claimed_mining_lost_micro_eur=(43 * seconds * MACHINES) if paused else 0,
                    # A pause has to be visible in the physics or it is not
                    # billable: dark while paused, at baseline while mining.
                    observed_gh=0 if paused else 400_000,
                )

            if commits:
                opening = {
                    "action": decision["action"],
                    "price_ppm_per_kwh": decision["price_ppm_per_kwh"],
                    "breakeven_ppm_per_kwh": decision["breakeven_ppm_per_kwh"],
                    "opened": iso(when),
                    "price_curve_hash": price_curve_hash(decision["curve"]),
                }
                nonce = new_nonce()
                commitment = commit_hash(decision_snapshot(opening), nonce)
                fields["commit"] = commitment
                if open_interval is None:
                    fields["opened"] = iso(when)
                    fields["reveal"] = None
                    fields["price_curve_hash"] = None
                else:
                    fields["opened"] = open_interval["opened"]
                    fields["reveal"] = {
                        "commit_seq": ledger.next_seq - 1,
                        "nonce": open_interval["nonce"],
                    }
                    fields["price_curve_hash"] = open_interval["price_curve_hash"]
                ledger.record(Interval(**fields), when=when)
                open_interval = {**opening, "nonce": nonce}
            else:
                ledger.record(Interval(**fields), when=when)
                open_interval = {
                    "action": decision["action"],
                    "price_ppm_per_kwh": decision["price_ppm_per_kwh"],
                    "breakeven_ppm_per_kwh": decision["breakeven_ppm_per_kwh"],
                }
            written += 1

    print(
        f"wrote {written} records over {args.days} days ending {args.end} "
        f"(commit/reveal: {'yes' if commits else 'no'})"
    )
    return 0


def seal(args) -> int:
    identity = DeviceIdentity.load_or_create(args.key)
    ledger = GuardedLedger(identity, base_dir=args.ledger)
    sealed = []
    for day in ledger.days():
        if args.through and day > args.through:
            continue
        existing = {s["day"] for s in ledger.seals()}
        if day in existing:
            continue
        entry = ledger.seal_day(day)
        sealed.append(entry["day"])
    print(f"sealed {len(sealed)} days" + (f": {sealed[0]}..{sealed[-1]}" if sealed else ""))
    return 0


def statement(args) -> int:
    identity = DeviceIdentity.load_or_create(args.key)
    ledger = GuardedLedger(identity, base_dir=args.ledger)
    document = ledger.statement(args.month)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    print(
        f"statement {args.month} -> {args.out} "
        f"({len(document.get('days', []))} days, {document.get('total_eur', '?')})"
    )
    return 0


def pubkey(args) -> int:
    identity = DeviceIdentity.load_or_create(args.key)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(identity.public(), handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"public key -> {args.out}")
    return 0


def capabilities(args) -> int:
    print(
        json.dumps(
            {
                "version": version(),
                "interval_fields": sorted(interval_fields()),
                "commit_reveal": supports_commit_reveal(),
                "activation": "activate_from" in GuardedLedger.__init__.__code__.co_varnames,
                "python": sys.version.split()[0],
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_days", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    write_parser = sub.add_parser("write", help="append days of records")
    write_parser.add_argument("--ledger", required=True)
    write_parser.add_argument("--key", required=True)
    write_parser.add_argument("--days", type=int, required=True)
    write_parser.add_argument("--end", required=True, help="last day, YYYY-MM-DD")
    write_parser.add_argument(
        "--no-commit",
        action="store_true",
        help="write 2.0.0-shaped records even on a version that supports commit/reveal",
    )
    write_parser.set_defaults(handler=write)

    seal_parser = sub.add_parser("seal", help="seal every unsealed day")
    seal_parser.add_argument("--ledger", required=True)
    seal_parser.add_argument("--key", required=True)
    seal_parser.add_argument("--through", help="do not seal past this day")
    seal_parser.set_defaults(handler=seal)

    statement_parser = sub.add_parser("statement", help="write a monthly statement")
    statement_parser.add_argument("--ledger", required=True)
    statement_parser.add_argument("--key", required=True)
    statement_parser.add_argument("--month", required=True)
    statement_parser.add_argument("--out", required=True)
    statement_parser.set_defaults(handler=statement)

    pubkey_parser = sub.add_parser("pubkey", help="write the device public key")
    pubkey_parser.add_argument("--key", required=True)
    pubkey_parser.add_argument("--out", required=True)
    pubkey_parser.set_defaults(handler=pubkey)

    cap_parser = sub.add_parser("capabilities", help="what this installed version supports")
    cap_parser.set_defaults(handler=capabilities)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
