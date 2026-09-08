"""Integer money. The invoice is the measurement, so the arithmetic is exact."""

import pytest

from hashguard.money import (
    MoneyError,
    client_keeps_micro_eur,
    energy_cost_micro_eur,
    fee_micro_eur,
    from_micro,
    to_micro,
    to_ppm,
    to_wh,
)


def test_conversion_is_exact_for_ordinary_prices():
    assert to_micro("0.12") == 120_000
    assert to_ppm("0.098") == 98_000
    assert to_micro(0.1) == 100_000  # binary 0.1 must still land on the decimal


def test_watt_hours_from_power_and_time():
    # 3.05 kW x 6 machines x 1 h = 18.3 kWh
    assert to_wh("3.05", 3600, 6) == 18_300
    assert to_wh("3.05", 1200, 6) == 6_100


def test_energy_cost_is_exact():
    # 18.3 kWh at 0.21 EUR/kWh = 3.843 EUR
    assert energy_cost_micro_eur(18_300, to_ppm("0.21")) == 3_843_000


def test_fee_and_remainder_always_reconstruct_the_total():
    """No euro may be lost or invented between the two halves of the split."""
    for amount in (0, 1, 7, 999, 100_000_000, 123_456_789):
        assert fee_micro_eur(amount) + client_keeps_micro_eur(amount) == amount


def test_rounding_always_favours_the_client():
    """Fee rounds down, so the rounding rule can never be a source of overbilling."""
    for amount in range(1, 400):
        assert fee_micro_eur(amount) <= amount * 0.25


def test_a_losing_month_is_not_billed():
    assert fee_micro_eur(-5_000_000) == 0
    assert client_keeps_micro_eur(-5_000_000) == -5_000_000


def test_fee_basis_points_are_bounded():
    with pytest.raises(MoneyError):
        fee_micro_eur(1_000_000, fee_bp=10_001)
    with pytest.raises(MoneyError):
        fee_micro_eur(1_000_000, fee_bp=-1)


@pytest.mark.parametrize("bad", ["nonsense", float("nan"), float("inf")])
def test_non_numbers_are_refused(bad):
    with pytest.raises(MoneyError):
        to_micro(bad)


def test_display_formatting():
    assert from_micro(1_234_567) == "1.23"
    assert from_micro(0) == "0.00"
    assert from_micro(-2_500_000) == "-2.50"
