"""The detection engine, and the measurement behind the claim in its docstring."""

import random

import pytest

from hashguard.config import default_config
from hashguard.qtmp import (
    HashrateBaseline,
    QTMPEngine,
    linear_slope,
    median,
    n_eff,
    robust_z,
    sidak_threshold,
)


# -- the statistics --------------------------------------------------------


def test_median_handles_both_parities():
    assert median([3.0, 1.0, 2.0]) == 2.0
    assert median([4.0, 1.0, 3.0, 2.0]) == 2.5


def test_robust_z_is_not_poisoned_by_a_broken_peer():
    """The point of MAD: one already-dead board must not hide the next one."""
    healthy = [100.0] * 8
    with_a_corpse = healthy + [1.0]
    assert robust_z(90.0, with_a_corpse) < -1.0


def test_a_degenerate_reference_yields_no_evidence():
    """Identical peers give a zero spread; inventing a huge z from that is how
    monitoring systems earn the right to be ignored."""
    assert robust_z(50.0, [100.0] * 6) == 0.0
    assert robust_z(50.0, [100.0]) == 0.0


def test_autocorrelation_shrinks_the_effective_sample():
    independent = [random.Random(1).gauss(0, 1) for _ in range(60)]
    walk, value = [], 0.0
    generator = random.Random(2)
    for _ in range(60):
        value += generator.gauss(0, 0.05)
        walk.append(value)
    assert n_eff(walk) < n_eff(independent)
    assert n_eff(walk) >= 2.0


def test_linear_slope_recovers_a_known_trend():
    slope, residual = linear_slope([3.0 + 2.0 * i for i in range(20)])
    assert slope == pytest.approx(2.0)
    assert residual == pytest.approx(0.0, abs=1e-9)


def test_sidak_tightens_the_threshold_as_the_farm_grows():
    assert sidak_threshold(2.5, 1) == 2.5
    assert sidak_threshold(2.5, 18) > 2.5
    assert sidak_threshold(2.5, 200) > sidak_threshold(2.5, 18)


# -- the engine ------------------------------------------------------------


def simulate(config, seed, degrade=False, polls=40, miners=6, boards=3):
    """A farm of `miners` machines; optionally one board fading slowly."""
    generator = random.Random(seed)
    engine = QTMPEngine(config)
    raised = []
    for tick in range(polls):
        snapshot = {}
        for machine in range(miners):
            rack = []
            for board in range(boards):
                hashrate = 35000 * (1 + generator.gauss(0, 0.012))
                if degrade and machine == 4 and board == 2:
                    hashrate *= 1 - 0.0009 * tick
                rack.append(
                    {"idx": board + 1, "hashrate_gh": hashrate, "temp_max": 62 + generator.gauss(0, 1.5)}
                )
            snapshot[f"S19-{machine:02d}"] = {
                "boards": rack,
                "fans": [4200 + generator.gauss(0, 80) for _ in range(4)],
                "hw_errors": 2,
            }
        raised += [a for a in engine.update(snapshot) if a["metric"] == "hashrate"]
    return raised


def v1_rule():
    """v1's thresholding: per-board rate, no persistence, judge immediately."""
    config = default_config()
    config["qtmp"].update({"family_wise": False, "persistence": 1, "min_samples": 1})
    return config


def test_v2_rule_cuts_false_alarms():
    """The measurement quoted in hashguard.qtmp's docstring.

    Loose bounds on purpose: the claim is a large, robust reduction, not a
    specific number that a change of Python's RNG would invalidate.
    """
    trials = 40
    v1_false = sum(len(simulate(v1_rule(), seed)) for seed in range(trials)) / trials
    v2_false = sum(len(simulate(default_config(), seed)) for seed in range(trials)) / trials
    assert v1_false > 3.0, f"v1's rule should be noisy on healthy hardware, saw {v1_false}"
    assert v2_false < 1.0, f"v2's rule should be quiet on healthy hardware, saw {v2_false}"
    assert v2_false < v1_false / 4


def test_v2_still_catches_a_degrading_board():
    """Quieter must not mean blinder."""
    trials = 40
    caught = sum(
        1
        for seed in range(trials)
        if any(a["target"] == "S19-04 board 3" for a in simulate(default_config(), seed, degrade=True))
    )
    assert caught >= trials - 2, f"caught only {caught}/{trials}"


def test_a_small_farm_raises_nothing_before_it_has_samples():
    config = default_config()
    engine = QTMPEngine(config)
    snapshot = {
        "S19-00": {
            "boards": [{"idx": 1, "hashrate_gh": 35000, "temp_max": 60}],
            "fans": [4200],
            "hw_errors": 0,
        }
    }
    assert engine.update(snapshot) == []


def test_an_open_alert_is_not_raised_twice():
    alerts = simulate(v1_rule(), 3, degrade=True, polls=60)
    targets = [a["target"] for a in alerts]
    assert len(targets) == len(set(targets)), "one open alert per target at a time"


# -- the baseline ----------------------------------------------------------


def test_the_baseline_only_learns_from_mining_intervals():
    """A long curtailment must not redefine what a running farm looks like."""
    baseline = HashrateBaseline()
    for value in (630_000, 631_000, 629_000, 628_000):
        baseline.observe(value, mining=True)
    for _ in range(50):
        baseline.observe(400, mining=False)
    assert baseline.value() > 600_000


def test_the_baseline_admits_it_does_not_know_yet():
    baseline = HashrateBaseline()
    assert baseline.value() is None
    baseline.observe(630_000, mining=True)
    assert baseline.value() is None
