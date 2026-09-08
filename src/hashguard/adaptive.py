"""Thresholds that learn from the operator, within bounds they cannot leave.

Every alert the console resolves is labelled real or false. Those labels are
the only ground truth the system will ever have about this particular farm, so
they move the thresholds: too many false alarms on a metric and its threshold
rises; a run of confirmed catches and it comes back down.

Two things here are corrections to v1's version of this loop, and both were
found by watching it run rather than by reading it.

**Recent feedback has to dominate.** v1 divided lifetime true positives by
lifetime alerts. After a few hundred labels that ratio is a fossil: a genuinely
noisy month cannot move it, and a noisy first week biases it forever. v2 decays
the counts geometrically, giving an effective memory of roughly thirty labels,
so the threshold tracks the farm the operator has *now*.

**The step has to be proportional to the error, and it has to stop.** v1 moved
a fixed 0.15 in whichever direction precision was wrong. Fed eight false alarms
and then thirty real catches, it walked the threshold from 2.5 up to its 6.0
ceiling and only crawled back to 4.9 -- it had switched most of the detector off
and could not undo it. v2 moves proportionally to the error, does nothing until
it has seen enough labels to have an opinion, and does nothing while precision
is already within :data:`TOLERANCE` of target. Far from target it moves
decisively; on target it holds still.

The dead band is not a fixed number, because the quantity it guards is an
estimate. Precision measured over an effective thirty labels has a standard
error near nine points, so a loop that moves whenever precision differs from
target by five points is mostly responding to its own sampling noise, and will
random-walk a threshold into its clamp given long enough. v2 requires the gap to
be larger than the noise -- ``1.5`` standard errors, alongside the flat
tolerance -- so the threshold moves on evidence and holds on noise.

Measured against a simulated farm where raising the threshold genuinely raises
precision (``tests/test_adaptive.py::test_closed_loop_converges``), 300 labels
settle the threshold at a mean of **2.02** sigma against an ideal of **2.045**.
Worth stating plainly: in the degenerate case where the threshold has *no*
effect on precision, no setting is correct and the loop random-walks inside its
clamps. That is a property of the question, not a defect in the answer, and the
clamps are what keeps it survivable.

The clamps stay, and they are not decoration. An adaptive loop with no floor
will walk a threshold to infinity given a long enough run of dismissals, and a
monitoring system that has quietly turned itself off is worse than one that was
never installed.
"""

from __future__ import annotations

import json
import math
import os

METRIC_TO_THRESHOLD = {
    "hashrate": "z_alert",
    "fan": "fan_temp_alert",
    "hw_errors": "hw_err_slope_alert",
}

#: Geometric decay per label. 0.97 gives an effective memory of ~33 labels.
DECAY = 0.97
#: Sigmas of threshold movement per unit of precision error.
GAIN = 2.0
#: Precision within this much of target counts as on target: hold still.
TOLERANCE = 0.05
#: ...and the gap must also exceed this many standard errors of the estimate.
SIGNIFICANCE = 1.5
#: Effective labels required before the loop has any opinion at all.
MIN_SAMPLES = 5.0


class Adaptive:
    def __init__(self, config: dict, state_path: str = "adaptive_state.json") -> None:
        self.config = config
        self.state_path = state_path
        self.state: dict[str, dict[str, float]] = {
            metric: {"tp": 0.0, "fp": 0.0} for metric in METRIC_TO_THRESHOLD
        }
        if os.path.exists(state_path):
            try:
                with open(state_path, encoding="utf-8") as handle:
                    stored = json.load(handle)
                for metric, counts in stored.items():
                    if metric in self.state and isinstance(counts, dict):
                        self.state[metric] = {
                            "tp": max(0.0, float(counts.get("tp", 0.0))),
                            "fp": max(0.0, float(counts.get("fp", 0.0))),
                        }
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                pass  # a corrupt state file resets to the prior; it does not stop the agent

    @staticmethod
    def precision(counts: dict[str, float]) -> float:
        """Laplace-smoothed at read time, so one label cannot swing it to 0 or 1."""
        return (counts["tp"] + 1.0) / (counts["tp"] + counts["fp"] + 2.0)

    def feedback(self, metric: str, real: bool) -> dict | None:
        settings = self.config["adaptive"]
        if not settings["enabled"] or metric not in self.state:
            return None
        counts = self.state[metric]
        counts["tp"] *= DECAY
        counts["fp"] *= DECAY
        counts["tp" if real else "fp"] += 1.0

        precision = self.precision(counts)
        target = float(settings["target_precision"])
        step = float(settings["step"])
        key = METRIC_TO_THRESHOLD[metric]
        thresholds = self.config["qtmp"]
        effective = counts["tp"] + counts["fp"]

        # Proportional control with a dead band. Below target -> too many false
        # alarms -> raise the bar. Above target -> too conservative -> lower it.
        # Within the band, or before there is enough evidence, do nothing.
        error = target - precision
        # Standard error of a proportion over the effective sample. The gap has
        # to beat both the flat tolerance and the noise floor to count.
        standard_error = math.sqrt(
            max(precision * (1.0 - precision), 1e-6) / max(effective, 1.0)
        )
        band = max(TOLERANCE, SIGNIFICANCE * standard_error)
        if effective < MIN_SAMPLES or abs(error) <= band:
            delta = 0.0
            verdict = "holding" if effective >= MIN_SAMPLES else "gathering labels"
        else:
            delta = max(-step, min(step, GAIN * error))
            verdict = "raising the bar" if delta > 0 else "lowering the bar"
        thresholds[key] = round(
            max(float(settings["z_min"]), min(float(settings["z_max"]), thresholds[key] + delta)),
            4,
        )
        self._save()
        return {
            "metric": metric,
            "precision": round(precision, 3),
            "threshold": thresholds[key],
            "action": verdict,
            "dead_band": round(band, 3),
            "effective_samples": round(effective, 1),
        }

    def _save(self) -> None:
        try:
            with open(self.state_path, "w", encoding="utf-8") as handle:
                json.dump(self.state, handle, indent=2, sort_keys=True)
        except OSError as exc:  # pragma: no cover
            print(f"[adaptive] could not persist state: {exc}")
