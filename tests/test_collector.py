"""Reading miners without trusting them.

Anything that can reach TCP 4028 can answer for a miner, and vendor firmware is
inconsistent even when it is honest. Parsing has to be forgiving about shape and
unforgiving about size.
"""

import pytest

from hashguard.collector import MAX_BOARDS, MAX_FANS, SimulatedFarm, parse_stats


def test_a_normal_reply_parses():
    parsed = parse_stats(
        {"STATS": [{"chain_rate1": "35000", "temp1": "62-70", "fan1": "4200", "Hardware Errors": 3}]}
    )
    assert parsed["boards"][0]["hashrate_gh"] == 35000.0
    assert parsed["boards"][0]["temp_max"] == 70.0
    assert parsed["boards"][0]["temp_spread"] == 8.0
    assert parsed["fans"] == [4200.0]
    assert parsed["hw_errors"] == 3


def test_alternative_firmware_field_names_are_tolerated():
    assert parse_stats({"STATS": [{"chain_rate1": 35000, "temp_chip1": "71", "hw_errors": 9}]})[
        "hw_errors"
    ] == 9


def test_a_reply_claiming_thousands_of_boards_is_capped():
    """Not a large farm: a malformed or hostile reply."""
    hostile = {"STATS": [{f"chain_rate{i}": "100" for i in range(1, 500)}]}
    assert len(parse_stats(hostile)["boards"]) <= MAX_BOARDS


def test_fans_are_capped_too():
    hostile = {"STATS": [{"chain_rate1": "100", **{f"fan{i}": "4000" for i in range(1, 500)}}]}
    assert len(parse_stats(hostile)["fans"]) <= MAX_FANS


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {},
        {"STATS": "not a list"},
        {"STATS": [None, 42, "text"]},
        {"STATS": [{"chain_rate1": "NaN"}]},
        {"STATS": [{"chain_rate1": "not a number"}]},
        {"STATS": [{"chain_rate1": 0}]},
        {"STATS": [{"no_useful_fields": True}]},
    ],
)
def test_garbage_yields_no_reading_rather_than_an_exception(raw):
    """A silent or lying miner is a data gap to report, not a crash to propagate."""
    assert parse_stats(raw) is None


def test_absurd_temperatures_are_discarded():
    parsed = parse_stats({"STATS": [{"chain_rate1": "35000", "temp1": "9999"}]})
    assert parsed["boards"][0]["temp_max"] is None


def test_absurd_fan_speeds_are_discarded():
    parsed = parse_stats({"STATS": [{"chain_rate1": "35000", "fan1": "999999"}]})
    assert parsed["fans"] == []


def test_the_simulated_farm_degrades_one_board_over_time():
    """The demo has to show the engine finding something, not a wall of green."""
    farm = SimulatedFarm()
    first = farm.read(4)["boards"][2]["hashrate_gh"]
    for _ in range(400):
        farm.read(4)
    later = farm.read(4)["boards"][2]["hashrate_gh"]
    assert later < first * 0.98
