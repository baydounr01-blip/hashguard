"""The HashGuard agent: poll, judge, decide, record, serve.

One process, one loop, no dependencies outside the standard library. It reads
the miners, compares each board against its siblings, decides whether this hour
pays for itself, and writes what it measured into a ledger that neither party
can quietly edit afterwards.

    python3 -m hashguard --demo          simulated farm, nothing to install
    python3 -m hashguard                 read config.json and run for real
    python3 -m hashguard --check         validate the configuration and exit
    python3 -m hashguard --statement 2026-09 > statement.json

Every failure in the loop is contained. A miner that will not answer is a gap
in the data. A price feed that will not load means mine. A relay that refuses
leaves the machine where it is. The one thing the agent will not do is stop
measuring, because the measurement is what the client is billed on.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import date, datetime, timezone

from . import logs
from .adaptive import Adaptive
from .api import AgentState, serve
from .attest import dark_fraction_ppm
from .collector import SimulatedFarm, cgminer_command, parse_stats
from .commit import commit_hash, decision_snapshot, new_nonce, price_curve_hash
from .config import ConfigError, load, validate
from .identity import DeviceIdentity
from .ledger import GuardedLedger, Interval
from .money import to_micro, to_wh
from .pricing import Curtailment
from .qtmp import HashrateBaseline, QTMPEngine

BANNER = r"""
  _  _         _      ___                     _
 | || |__ _ __| |_   / __|_  _ __ _ _ _ __ _ | |
 | __ / _` (_-<  ' \| (_ | || / _` | '_/ _` || |
 |_||_\__,_/__/_||_|\___|\_,_\__,_|_| \__,_||_|   v2
"""


def _iso(moment: datetime) -> str:
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def poll_once(state: AgentState, simulated: SimulatedFarm | None, baseline: HashrateBaseline) -> None:
    """One full cycle, in the order that makes a claim checkable.

    Read the miners, close the interval that was opened at the previous poll
    with the telemetry just read, decide the interval that starts now, commit
    that decision, and write both into one record. The commitment for an
    interval is therefore on disk a whole poll before the hashrate that will
    corroborate it is measured -- which is the entire point, and is what
    :mod:`hashguard.commit` exists to let anyone check afterwards.

    Holds the lock only while mutating shared state.
    """
    snapshot: dict = {}
    if simulated is not None:
        for index in range(simulated.miners):
            snapshot[f"SIM-{index:02d}"] = simulated.read(index)
    else:
        for miner in state.config["miners"]:
            raw = cgminer_command(miner["host"], int(miner.get("port", 4028)), "stats")
            parsed = parse_stats(raw)
            if parsed is None:
                print(f"[poll] {miner['name']} did not answer")
            snapshot[miner["name"]] = parsed

    live = {name: data for name, data in snapshot.items() if data is not None}
    total_gh = int(sum(b["hashrate_gh"] for d in live.values() for b in d["boards"]))

    with state.lock:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        state.snapshot = live
        state.last_poll = _iso(now)
        fresh_alerts = state.engine.update(live)

        # 1. The interval that just closed, and the telemetry that judges it.
        #    Its decision was committed one poll ago and is revealed below.
        closing = state.open_interval
        # The baseline only learns from intervals we believe were mining, so a
        # long curtailment cannot slowly redefine what "running" looks like.
        baseline.observe(total_gh, (closing or {}).get("action", "MINE") == "MINE")
        state.baseline_gh = baseline.value()
        state.observed_gh = total_gh

        curtailment = state.config["curtailment"]
        poll_seconds = int(state.config["poll_seconds"])
        machines = len(state.config["miners"]) or len(live)

        # 2. Decide the interval that starts now, act on it, and commit it --
        #    before a single byte of the telemetry that will corroborate it
        #    has been read. Acting comes first: a failure to hash must never
        #    be able to delay a relay.
        decision = state.curtailment.decide()
        notes = state.curtailment.act()
        if notes:
            state.notes.extend(notes)
            del state.notes[:-50]
        executed = curtailment["mode"] != "advisory"
        opening = {
            "action": decision["action"],
            "price_ppm_per_kwh": int(decision.get("price_ppm_per_kwh", 0)),
            "breakeven_ppm_per_kwh": int(decision.get("breakeven_ppm_per_kwh", 0)),
            "opened": _iso(now),
            "price_curve_hash": price_curve_hash(state.curtailment.prices_ppm),
        }
        nonce = new_nonce()
        commitment = commit_hash(decision_snapshot(opening), nonce)

        # 3. One record: the closed interval in clear, revealing its own
        #    decision, carrying the commitment of the one now running.
        if closing is None:
            # The first poll of a session closes nothing. A zero-second record
            # that claims nothing, so that the commitment has somewhere to go.
            interval = Interval(
                action="MINE", executed=executed, n_miners=machines, seconds=0,
                price_ppm_per_kwh=0, breakeven_ppm_per_kwh=0,
                claimed_wh=0, claimed_mining_lost_micro_eur=0,
                baseline_gh=state.baseline_gh, observed_gh=total_gh,
                opened=_iso(now), commit=commitment, reveal=None, price_curve_hash=None,
            )
        else:
            # Never claim more time than the poll interval, whatever the clock
            # says: an agent that stalled under-claims rather than over-claims.
            elapsed = min(poll_seconds, max(0, int((now - closing["at"]).total_seconds())))
            was_paused = closing["action"] == "PAUSE"
            revenue_per_second = (
                float(curtailment["hashrate_th"])
                * float(curtailment["hashprice_usd_th_day"])
                / float(curtailment["eur_usd"])
                / 86400.0
            )
            interval = Interval(
                action=closing["action"],
                executed=closing["executed"],
                n_miners=machines,
                seconds=elapsed,
                price_ppm_per_kwh=closing["price_ppm_per_kwh"],
                breakeven_ppm_per_kwh=closing["breakeven_ppm_per_kwh"],
                claimed_wh=to_wh(curtailment["power_kw"], elapsed, machines) if was_paused else 0,
                claimed_mining_lost_micro_eur=(
                    to_micro(revenue_per_second * elapsed * machines, "mining_lost")
                    if was_paused
                    else 0
                ),
                baseline_gh=state.baseline_gh,
                observed_gh=total_gh,
                opened=closing["opened"],
                commit=commitment,
                reveal={"commit_seq": state.ledger.next_seq - 1, "nonce": closing["nonce"]},
                price_curve_hash=closing["price_curve_hash"],
            )

        state.ledger.record(interval, when=now)
        state.open_interval = {**opening, "at": now, "executed": executed, "nonce": nonce,
                               "commit": commitment}
        paused = decision["action"] == "PAUSE"
        state.history.append(
            {
                "ts": state.last_poll,
                "total_th": round(total_gh / 1000.0, 1),
                "action": decision["action"],
                "open_alerts": sum(1 for a in state.engine.alerts if a.get("open")),
            }
        )
        del state.history[:-288]
        paths = state.config["paths"]
        logs.append(
            paths["log_dir"],
            {"type": "snapshot", "ts": state.last_poll, "miners": live, "curtailment": decision},
            int(paths.get("max_log_mb", 256)),
        )

    for alert in fresh_alerts:
        print(f"[{alert['severity']}] {alert['target']}: {alert['message']}")
    fraction = dark_fraction_ppm(state.baseline_gh, total_gh)
    corroboration = f" · {fraction / 10000:.0f}% dark" if fraction is not None and paused else ""
    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] {total_gh / 1000:.0f} TH/s · "
        f"{decision['action']} ({decision['reason']}){corroboration}"
    )


def poll_loop(state: AgentState, simulated: SimulatedFarm | None) -> None:
    baseline = HashrateBaseline()
    last_seal_day = date.today().isoformat()
    while True:
        try:
            poll_once(state, simulated, baseline)
            today = date.today().isoformat()
            if today != last_seal_day:
                with state.lock:
                    for seal in state.ledger.seal_pending():
                        print(f"[ledger] sealed {seal['day']}: {seal['leaf_count']} records, "
                              f"root {seal['merkle_root'][:16]}...")
                last_seal_day = today
        except Exception as exc:  # noqa: BLE001 - the loop outliving a bug is the point
            print(f"[poll] cycle failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        time.sleep(int(state.config["poll_seconds"]))


def build_state(config: dict, identity: DeviceIdentity) -> AgentState:
    paths = config["paths"]
    return AgentState(
        config=config,
        engine=QTMPEngine(config),
        curtailment=Curtailment(config),
        ledger=GuardedLedger(
            identity,
            base_dir=paths["ledger_dir"],
            fee_bp=int(config["billing"]["fee_bp"]),
            margin_ppm=int(config["billing"]["corroboration_margin_ppm"]),
        ),
        adaptive=Adaptive(config, paths["state"]),
        identity=identity,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hashguard", description=__doc__)
    parser.add_argument("--demo", action="store_true", help="run against a simulated farm")
    parser.add_argument("--check", action="store_true", help="validate the configuration and exit")
    parser.add_argument("--statement", metavar="YYYY-MM", help="print a signed statement and exit")
    parser.add_argument("--seal", action="store_true", help="seal every finished day and exit")
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args(argv)

    try:
        config = load(args.config)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.check:
        problems = validate(config)
        print("configuration is valid" if not problems else "\n".join(f"  - {p}" for p in problems))
        return 0 if not problems else 2

    identity = DeviceIdentity.load_or_create(config["paths"]["device_key"])
    state = build_state(config, identity)

    if args.statement:
        with state.lock:
            state.ledger.seal_pending()
            print(json.dumps(state.ledger.statement(args.statement), indent=2, ensure_ascii=False))
        return 0

    if args.seal:
        for seal in state.ledger.seal_pending():
            print(f"sealed {seal['day']}: root {seal['merkle_root']}")
        return 0

    api = config["api"]
    print(BANNER)
    print(f"  farm         {config['farm_name']}")
    print(f"  api          http://{api['bind_host']}:{api['api_port']}  (header X-HashGuard-Token)")
    print(f"  mode         {'DEMO (simulated farm)' if args.demo else 'PRODUCTION'}")
    print(f"  curtailment  {config['curtailment']['mode']}")
    print(f"  break-even   {state.curtailment.breakeven_ppm() / 1e6:.4f} EUR/kWh")
    print(f"  device       {identity.device_id}  ({identity.algorithm})")
    print(f"  farm id      {identity.farm_id or 'none (pre-2.1 key file)'}")
    print(f"  ledger       {config['paths']['ledger_dir']}/")
    if state.ledger.activated_from:
        print(f"  seals        name this farm from {state.ledger.activated_from} onward")
    else:
        print("  seals        name no farm: signatures are not bound to this installation")
    if identity.algorithm != "ed25519":
        print("  note         seals are HMAC-signed; install 'cryptography' for third-party auditable ed25519")
    if not api.get("cors_origins"):
        print("  note         no CORS origins listed: use the console from this machine, or list its origin")
    print()

    simulated = SimulatedFarm() if args.demo else None
    threading.Thread(target=poll_loop, args=(state, simulated), daemon=True).start()
    server = serve(state)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[exit] agent stopped. Your miners keep running on their own firmware.")
        with state.lock:
            state.ledger.seal_pending()
    return 0
