"""Integer units. Every quantity that can end up on an invoice lives here.

HashGuard bills a percentage of measured savings, which means the measurement
*is* the invoice. Doing that arithmetic in floating point invites the one
argument neither party can win: two correct programs disagreeing in the sixth
decimal. So the ledger carries integers in declared minor units, and the fee is
computed with integer division and a stated rounding rule.

Units
-----
``micro_eur``   10^-6 EUR      -- money
``wh``          watt-hours     -- energy
``gh``          GH/s           -- hashrate
``seconds``     seconds        -- time
``ppm``         parts per million -- ratios (prices per kWh, fractions)

Conversion from the analogue world (a price scraped off an API, a hashrate read
off a miner) happens once, at the edge, through the ``from_*`` helpers below,
and never again.
"""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

MICRO = 1_000_000

#: The fee, in basis points. 2500 bp = 25%.
DEFAULT_FEE_BP = 2500


class MoneyError(ValueError):
    """A quantity could not be converted into its integer unit."""


def _to_decimal(value: float | int | str, what: str) -> Decimal:
    try:
        dec = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise MoneyError(f"{what}: {value!r} is not a number") from exc
    if not dec.is_finite():
        raise MoneyError(f"{what}: {value!r} is not finite")
    return dec


def to_micro(value: float | int | str, what: str = "amount") -> int:
    """EUR -> micro-EUR, rounded half to even."""
    dec = _to_decimal(value, what) * MICRO
    return int(dec.quantize(Decimal(1), rounding=ROUND_HALF_EVEN))


def from_micro(micro: int) -> str:
    """micro-EUR -> a EUR string with two decimals, for display only."""
    sign = "-" if micro < 0 else ""
    cents = (abs(int(micro)) + 5000) // 10000
    return f"{sign}{cents // 100}.{cents % 100:02d}"


def to_ppm(value: float | int | str, what: str = "ratio") -> int:
    """A ratio or a per-unit price -> parts per million."""
    dec = _to_decimal(value, what) * MICRO
    return int(dec.quantize(Decimal(1), rounding=ROUND_HALF_EVEN))


def to_wh(kw: float | int | str, seconds: int, machines: int) -> int:
    """kW drawn by ``machines`` for ``seconds`` -> watt-hours, half-even."""
    if seconds < 0 or machines < 0:
        raise MoneyError("seconds and machines must not be negative")
    dec = _to_decimal(kw, "power_kw") * 1000 * Decimal(seconds) / Decimal(3600) * machines
    return int(dec.quantize(Decimal(1), rounding=ROUND_HALF_EVEN))


def energy_cost_micro_eur(wh: int, price_ppm_per_kwh: int) -> int:
    """Cost of ``wh`` watt-hours at a price given in micro-EUR per kWh.

    Exact: ``wh * price / 1000``, rounded half to even, no float anywhere.
    """
    num = int(wh) * int(price_ppm_per_kwh)
    dec = Decimal(num) / Decimal(1000)
    return int(dec.quantize(Decimal(1), rounding=ROUND_HALF_EVEN))


def fee_micro_eur(net_saving_micro: int, fee_bp: int = DEFAULT_FEE_BP) -> int:
    """The operator's cut, rounded **down**, and never charged on a loss.

    Rounding down is deliberate and one-directional: every fraction of a
    micro-euro that rounding creates goes to the client, so the rounding rule
    itself cannot be a source of overbilling.
    """
    if not 0 <= fee_bp <= 10_000:
        raise MoneyError(f"fee_bp must be within 0..10000, got {fee_bp}")
    if net_saving_micro <= 0:
        return 0
    return (int(net_saving_micro) * int(fee_bp)) // 10_000


def client_keeps_micro_eur(net_saving_micro: int, fee_bp: int = DEFAULT_FEE_BP) -> int:
    """What is left for the client. Always exactly ``net - fee``."""
    if net_saving_micro <= 0:
        return int(net_saving_micro)
    return int(net_saving_micro) - fee_micro_eur(net_saving_micro, fee_bp)
