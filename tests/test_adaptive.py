"""The feedback controller, including the recovery failure it was written to fix."""

import random

from hashguard.adaptive import Adaptive
from hashguard.config import default_config


def controller(tmp_path, name="state.json"):
    config = default_config()
    return config, Adaptive(config, str(tmp_path / name))


def feed(adaptive, labels):
    for real in labels:
        adaptive.feedback("hashrate", real)


def test_false_alarms_raise_the_bar(tmp_path):
    config, adaptive = controller(tmp_path)
    start = config["qtmp"]["z_alert"]
    feed(adaptive, [False] * 8)
    assert config["qtmp"]["z_alert"] > start


def test_it_can_come_back_down_again(tmp_path):
    """The failure this controller was rewritten to fix.

    v1's loop, fed eight false alarms and then a run of confirmed catches,
    walked the threshold to its 6.0 ceiling and crawled back only to 4.9 --
    recovering 31% of its own excursion, having switched most of the detector
    off in the meantime. Recovery has to be substantial, not cosmetic.
    """
    config, adaptive = controller(tmp_path)
    start = config["qtmp"]["z_alert"]
    feed(adaptive, [False] * 8)
    raised = config["qtmp"]["z_alert"]
    assert raised > start, "eight false alarms should raise the bar at all"

    feed(adaptive, [True] * 40)
    recovered = (raised - config["qtmp"]["z_alert"]) / (raised - start)
    assert recovered > 0.6, f"only {recovered:.0%} of the excursion was undone (v1 managed 31%)"


def test_thresholds_never_leave_their_clamps(tmp_path):
    """An adaptive loop with no floor will quietly switch the detector off."""
    config, adaptive = controller(tmp_path)
    feed(adaptive, [False] * 200)
    assert config["qtmp"]["z_alert"] <= config["adaptive"]["z_max"]
    config2, adaptive2 = controller(tmp_path, "state2.json")
    feed(adaptive2, [True] * 200)
    assert config2["qtmp"]["z_alert"] >= config2["adaptive"]["z_min"]


def test_it_holds_still_until_it_has_evidence(tmp_path):
    config, adaptive = controller(tmp_path)
    start = config["qtmp"]["z_alert"]
    result = adaptive.feedback("hashrate", False)
    assert config["qtmp"]["z_alert"] == start
    assert result["action"] == "gathering labels"


def test_closed_loop_converges(tmp_path):
    """The measurement quoted in hashguard.adaptive's docstring.

    A farm where raising the threshold genuinely does raise precision. Target
    precision 0.60 is reached at z = 2.045 under this model, and the controller
    has to find it from a start of 2.5 without parking in a clamp.
    """

    def run(seed, labels=300):
        config = default_config()
        adaptive = Adaptive(config, str(tmp_path / f"s{seed}.json"))
        generator = random.Random(seed)
        for _ in range(labels):
            z = config["qtmp"]["z_alert"]
            true_precision = min(0.98, max(0.02, 0.15 + 0.22 * z))
            adaptive.feedback("hashrate", generator.random() < true_precision)
        return config["qtmp"]["z_alert"]

    settled = [run(seed) for seed in range(12)]
    mean = sum(settled) / len(settled)
    assert 1.7 < mean < 2.4, f"should settle near the ideal 2.045, got {mean:.2f}"
    assert sum(1 for z in settled if z in (1.5, 6.0)) <= 2, "should rarely park in a clamp"


def test_each_metric_moves_its_own_threshold(tmp_path):
    config, adaptive = controller(tmp_path)
    fan_before = config["qtmp"]["fan_temp_alert"]
    z_before = config["qtmp"]["z_alert"]
    for _ in range(10):
        adaptive.feedback("fan", False)
    assert config["qtmp"]["fan_temp_alert"] > fan_before
    assert config["qtmp"]["z_alert"] == z_before


def test_a_disabled_loop_changes_nothing(tmp_path):
    config, adaptive = controller(tmp_path)
    config["adaptive"]["enabled"] = False
    start = config["qtmp"]["z_alert"]
    feed(adaptive, [False] * 20)
    assert config["qtmp"]["z_alert"] == start


def test_state_survives_a_restart(tmp_path):
    config, adaptive = controller(tmp_path)
    feed(adaptive, [False] * 10)
    reloaded = Adaptive(default_config(), str(tmp_path / "state.json"))
    assert reloaded.state["hashrate"]["fp"] > 0


def test_a_corrupt_state_file_resets_instead_of_crashing(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json at all")
    adaptive = Adaptive(default_config(), str(path))
    assert adaptive.state["hashrate"] == {"tp": 0.0, "fp": 0.0}


def test_an_unknown_metric_is_ignored(tmp_path):
    _, adaptive = controller(tmp_path)
    assert adaptive.feedback("not_a_metric", True) is None
