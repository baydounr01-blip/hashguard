"""Curtailment: the model, and the direction each failure falls in."""

from datetime import datetime

from hashguard.config import default_config
from hashguard.pricing import Curtailment, _parse_price_curve
from hashguard.money import to_ppm


def test_breakeven_matches_the_published_formula():
    """100 TH/s at $0.045/TH/day, EURUSD 1.08, drawing 3.05 kW."""
    curtailment = Curtailment(default_config())
    expected = (100.0 * 0.045 / 1.08) / (3.05 * 24)
    assert abs(curtailment.breakeven_ppm() / 1e6 - expected) < 1e-6


def test_an_expensive_hour_pauses():
    config = default_config()
    config["curtailment"]["fixed_price_eur_kwh"] = 0.31
    assert Curtailment(config).decide(datetime(2026, 9, 8, 10))["action"] == "PAUSE"


def test_a_cheap_hour_mines():
    config = default_config()
    config["curtailment"]["fixed_price_eur_kwh"] = 0.01
    config["curtailment"]["network_cost_eur_kwh"] = 0.0
    assert Curtailment(config).decide(datetime(2026, 9, 8, 3))["action"] == "MINE"


def test_curtailment_can_be_switched_off():
    config = default_config()
    config["curtailment"]["enabled"] = False
    config["curtailment"]["fixed_price_eur_kwh"] = 9.99
    assert Curtailment(config).decide()["action"] == "MINE"


def test_an_unreachable_price_feed_fails_open_to_mining():
    """Mining fails open. A farm stopped for a reason nobody can reconstruct
    costs the client real revenue, so uncertainty never pauses anything."""
    config = default_config()
    config["curtailment"]["price_source"] = "url"
    config["curtailment"]["price_url"] = "https://169.254.169.254/prices"
    curtailment = Curtailment(config)
    decision = curtailment.decide()
    assert decision["action"] == "MINE"
    assert decision["source"] == "fail-safe"
    assert curtailment.last_error


def test_the_decision_carries_the_integer_price_it_used():
    """The number in the decision is the number sealed into the ledger, so a
    dispute cannot start from two readings of the same hour."""
    config = default_config()
    config["curtailment"]["fixed_price_eur_kwh"] = 0.31
    config["curtailment"]["network_cost_eur_kwh"] = 0.04
    decision = Curtailment(config).decide(datetime(2026, 9, 8, 10))
    assert decision["price_ppm_per_kwh"] == to_ppm("0.31") + to_ppm("0.04")
    assert isinstance(decision["price_ppm_per_kwh"], int)


def test_a_price_feed_is_untrusted_input():
    curve = _parse_price_curve(
        [
            {"hour": 0, "price_eur_kwh": 0.09},
            {"hour": 99, "price_eur_kwh": 0.10},      # out of range
            {"hour": 2, "price_eur_kwh": "text"},      # not a number
            {"hour": 3, "price_eur_kwh": -5},          # negative
            {"hour": 4, "price_eur_kwh": 1e9},         # absurd
            "not even an object",
            {"missing": "fields"},
        ]
    )
    assert curve == {0: 90_000}


def test_a_non_list_feed_yields_no_curve():
    assert _parse_price_curve({"unexpected": "shape"}) == {}
    assert _parse_price_curve(None) == {}


def test_advisory_mode_never_touches_a_relay():
    config = default_config()
    config["curtailment"]["mode"] = "advisory"
    config["curtailment"]["webhooks"] = {"S19-01": "http://192.168.1.50/relay?on="}
    curtailment = Curtailment(config)
    curtailment.decide()
    assert curtailment.act() == []


def test_a_relay_outside_the_allowlist_is_refused_and_the_machine_is_left_alone():
    config = default_config()
    config["curtailment"]["mode"] = "webhook"
    config["curtailment"]["webhooks"] = {"S19-01": "http://192.168.1.50/relay?on="}
    config["curtailment"]["webhook_allowlist"] = []
    curtailment = Curtailment(config)
    curtailment.decide()
    notes = curtailment.act()
    assert notes and "left as it is" in notes[0]
