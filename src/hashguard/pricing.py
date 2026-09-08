"""Curtailment: mine only in the hours that pay for themselves.

Break-even is the electricity price at which an hour of mining earns exactly
what it costs::

    revenue_per_day = hashrate_TH * hashprice_USD_per_TH_day / EURUSD
    energy_per_day  = power_kW * 24
    breakeven       = revenue_per_day / energy_per_day        [EUR/kWh]

Above it, the hour costs more than it makes and pausing is worth money. Below
it, mining is worth money. That is the entire model, and it is stated in full
so a client can check it against their own bill.

Two things are load-bearing:

* **Prices are integers.** Micro-EUR per kWh, converted once at the edge. The
  price that goes into a decision is the same integer that goes into the sealed
  ledger record, so a billing dispute cannot begin with two different readings
  of the same hour.
* **Missing data means mine.** No price feed, a malformed response, a network
  outage -- the decision is MINE. The failure mode of a curtailment system that
  guesses is a farm stopped for a reason nobody can reconstruct, and the client
  loses real revenue to our uncertainty. Billing fails closed; mining fails open.
"""

from __future__ import annotations

from datetime import date, datetime

from .money import to_ppm
from .netguard import NetGuardError, fetch_public_json


class Curtailment:
    """Holds today's price curve and the current mine/pause decision."""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.prices_ppm: dict[int, int] = {}
        self.prices_date: str | None = None
        self.decision: dict = {"action": "MINE", "reason": "starting up", "source": "init"}
        self.last_error: str | None = None

    # -- the model -------------------------------------------------------

    def breakeven_ppm(self) -> int:
        """Break-even in micro-EUR per kWh."""
        curtailment = self.config["curtailment"]
        revenue_eur_day = (
            float(curtailment["hashrate_th"])
            * float(curtailment["hashprice_usd_th_day"])
            / float(curtailment["eur_usd"])
        )
        kwh_day = float(curtailment["power_kw"]) * 24.0
        if kwh_day <= 0:
            return 0
        return to_ppm(revenue_eur_day / kwh_day, "breakeven")

    # -- prices ----------------------------------------------------------

    def fetch_prices(self, today: str | None = None) -> None:
        """Refresh the day's curve. Any failure leaves the curve empty."""
        curtailment = self.config["curtailment"]
        today = today or date.today().isoformat()
        if self.prices_date == today and self.prices_ppm:
            return
        try:
            if curtailment["price_source"] == "url" and curtailment["price_url"]:
                payload = fetch_public_json(
                    curtailment["price_url"], headers=curtailment.get("price_headers") or {}
                )
                self.prices_ppm = _parse_price_curve(payload)
                if not self.prices_ppm:
                    raise NetGuardError("the price feed returned no usable hours")
            else:
                fixed = to_ppm(curtailment["fixed_price_eur_kwh"], "fixed_price_eur_kwh")
                self.prices_ppm = {hour: fixed for hour in range(24)}
            self.prices_date = today
            self.last_error = None
        except (NetGuardError, ValueError, KeyError, TypeError) as exc:
            self.prices_ppm = {}
            self.prices_date = None
            self.last_error = str(exc)
            print(f"[curtail] no prices ({exc}) - failing open: MINE")

    # -- the decision ----------------------------------------------------

    def decide(self, now: datetime | None = None) -> dict:
        curtailment = self.config["curtailment"]
        if not curtailment["enabled"]:
            self.decision = {
                "action": "MINE", "reason": "curtailment is switched off", "source": "config",
            }
            return self.decision
        self.fetch_prices()
        hour = (now or datetime.now().astimezone()).hour
        if hour not in self.prices_ppm:
            self.decision = {
                "action": "MINE",
                "reason": "no price for this hour - failing open",
                "source": "fail-safe",
                "error": self.last_error,
            }
            return self.decision
        total_ppm = self.prices_ppm[hour] + to_ppm(
            curtailment["network_cost_eur_kwh"], "network_cost_eur_kwh"
        )
        breakeven = self.breakeven_ppm()
        margin = float(curtailment["margin"])
        threshold = int(breakeven * (1 - margin))
        paused = total_ppm > threshold
        self.decision = {
            "action": "PAUSE" if paused else "MINE",
            "reason": (
                f"{total_ppm / 1e6:.3f} EUR/kWh {'above' if paused else 'at or below'} "
                f"break-even {breakeven / 1e6:.3f} (margin {margin * 100:.0f}%)"
            ),
            "source": curtailment["price_source"],
            "price_ppm_per_kwh": total_ppm,
            "breakeven_ppm_per_kwh": breakeven,
            "hour": hour,
        }
        return self.decision

    # -- acting on it ----------------------------------------------------

    def act(self) -> list[str]:
        """Execute the decision. Returns human-readable notes about what happened.

        Advisory mode never touches anything. A webhook that fails leaves the
        machine in whatever state it is already in, because the failure mode of
        a relay call is never allowed to be a farm that stops.
        """
        from .netguard import call_local_webhook

        curtailment = self.config["curtailment"]
        notes: list[str] = []
        if curtailment["mode"] != "webhook":
            return notes
        allowlist = curtailment.get("webhook_allowlist", [])
        suffix = "0" if self.decision["action"] == "PAUSE" else "1"
        for name, url in (curtailment.get("webhooks") or {}).items():
            try:
                status = call_local_webhook(url + suffix, allowlist)
                notes.append(f"{name}: relay answered {status}")
            except NetGuardError as exc:
                notes.append(f"{name}: relay call refused or failed ({exc}); machine left as it is")
        return notes


def _parse_price_curve(payload) -> dict[int, int]:
    """Read ``[{"hour": 0, "price_eur_kwh": 0.09}, ...]`` defensively.

    Hours outside 0..23 and non-finite prices are dropped rather than allowed to
    produce a decision. A price feed is untrusted input like any other.
    """
    curve: dict[int, int] = {}
    if not isinstance(payload, list):
        return curve
    for entry in payload[:64]:
        if not isinstance(entry, dict):
            continue
        try:
            hour = int(entry["hour"])
            price = float(entry["price_eur_kwh"])
        except (KeyError, TypeError, ValueError):
            continue
        if not 0 <= hour <= 23 or not 0 <= price < 100:
            continue
        curve[hour] = to_ppm(price, f"hour {hour}")
    return curve
