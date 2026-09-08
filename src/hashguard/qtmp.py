"""The QTMP engine: every board judged against its own siblings.

Carried over from the v1 agent and from the QTMP core in the quantumbot547
repository, with the numpy dependency removed. The statistics involved are a
median, a median absolute deviation and a least-squares slope over at most a
few hundred points; importing a 15 MB numerical stack to compute them was a
supply-chain cost with no benefit. The agent now runs on the standard library
alone, which is also the strongest thing that can be said about its
dependencies: there are none.

The idea is unchanged, because it is the right one. A board's control group is
the other boards in the same rack. Comparing against siblings cancels ambient
temperature, grid voltage and difficulty drift in one stroke, because all of
them move every sibling together. What is left when you subtract the siblings
is the board's own health.

Four refinements matter. Two survive from v1; two are new, and they are the
difference between a detector and an alarm generator.

* **MAD, not standard deviation.** A board that is already failing would inflate
  a standard deviation and hide itself inside its own noise. The median absolute
  deviation is unmoved by a minority of broken members.
* **Effective sample size.** Hashrate is strongly autocorrelated -- consecutive
  samples are nearly the same reading. Treating 30 correlated samples as 30
  independent ones inflates every z-score until the alert list is noise.
* **Family-wise correction (new in v2).** A farm with 18 boards runs 18
  hypothesis tests every poll. At the v1 threshold of 2.5 sigma that is a false
  alarm roughly every twenty minutes on perfectly healthy hardware, which is
  how an operator learns to ignore the panel. v2 reads ``z_alert`` as the false
  alarm rate for the *farm per poll* and applies a Sidak correction across the
  boards actually being compared, so the threshold tightens as the farm grows
  and the configured number keeps meaning what the operator thought it meant.
* **Persistence (new in v2).** Noise does not persist; degradation does. A
  board must breach on ``persistence`` consecutive polls before it raises. This
  costs a few minutes of latency on a failure that takes weeks to arrive, and
  removes the entire tail of one-poll flukes that the correction does not.

Measured over 40 seeded runs of a simulated 18-board farm, 40 polls each
(``tests/test_qtmp.py::test_v2_rule_cuts_false_alarms``): v1's rule averages
**4.67 false hashrate alerts per healthy run**, v2's averages **0.25** -- an
18-fold reduction -- while both catch a board losing 0.09% of its hashrate per
poll in **40 of 40** runs. The noise went away; the signal did not.
"""

from __future__ import annotations

import math
import secrets
from collections import deque
from datetime import datetime, timezone
from statistics import NormalDist

SEVERITY_ALERT = "ALERT"
SEVERITY_CRITICAL = "CRITICAL"


def median(values: list[float]) -> float:
    if not values:
        raise ValueError("median of an empty sample")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def robust_z(value: float, peers: list[float]) -> float:
    """Deviation from the peer median, in MAD-derived sigmas.

    Returns 0.0 rather than infinity when the peers are identical: a sample with
    no spread carries no evidence, and inventing an enormous z-score from a
    degenerate reference is how monitoring systems earn the right to be ignored.
    """
    if len(peers) < 2:
        return 0.0
    med = median(peers)
    mad = median([abs(p - med) for p in peers])
    sigma = 1.4826 * mad
    if sigma <= 1e-9:
        return 0.0
    return (value - med) / sigma


def n_eff(series: list[float]) -> float:
    """Effective sample size after lag-1 autocorrelation.

    ``n_eff = n * (1 - rho) / (1 + rho)``. For rho -> 1 (a series that barely
    moves between samples) this collapses towards 2: thirty readings of a
    slow-moving quantity are worth about two independent ones.
    """
    n = len(series)
    if n < 5:
        return float(max(n, 1))
    mean = sum(series) / n
    centred = [x - mean for x in series]
    denominator = sum(x * x for x in centred)
    if denominator <= 1e-12:
        return float(n)
    rho = sum(centred[i] * centred[i + 1] for i in range(n - 1)) / denominator
    rho = max(-0.99, min(rho, 0.99))
    return max(2.0, n * (1 - rho) / (1 + rho))


def linear_slope(values: list[float]) -> tuple[float, float]:
    """Least-squares slope over ``0..n-1`` and the residual standard deviation.

    v1 called ``numpy.polyfit`` twice per metric per poll to get these two
    numbers. One pass gets both.
    """
    n = len(values)
    if n < 3:
        return 0.0, 0.0
    mean_x = (n - 1) / 2.0
    mean_y = sum(values) / n
    sxx = sum((i - mean_x) ** 2 for i in range(n))
    if sxx <= 1e-12:
        return 0.0, 0.0
    sxy = sum((i - mean_x) * (values[i] - mean_y) for i in range(n))
    slope = sxy / sxx
    intercept = mean_y - slope * mean_x
    residuals = [values[i] - (slope * i + intercept) for i in range(n)]
    variance = sum(r * r for r in residuals) / n
    return slope, math.sqrt(variance)


def sidak_threshold(z_alert: float, n_tests: int) -> float:
    """Raise ``z_alert`` so it bounds the false alarm rate across ``n_tests``.

    The operator sets one number and means "how often should this farm cry wolf".
    Applied naively to each board, that number instead means "how often should
    *each board* cry wolf", and the farm's rate is the per-board rate times the
    number of boards. The Sidak correction restores the intended reading:
    per-test alpha becomes ``1 - (1 - alpha)**(1/n)``.
    """
    if n_tests <= 1:
        return z_alert
    normal = NormalDist()
    alpha = 1.0 - normal.cdf(z_alert)
    if alpha <= 0.0:
        return z_alert
    per_test = 1.0 - (1.0 - alpha) ** (1.0 / n_tests)
    per_test = min(max(per_test, 1e-12), 0.5 - 1e-12)
    return normal.inv_cdf(1.0 - per_test)


class HashrateBaseline:
    """What the farm hashes when it is mining.

    This is the reference the ledger's corroboration check needs: to say that a
    pause happened, you need to know what not-pausing looks like. Only intervals
    the agent believes were mining feed the baseline, so a long curtailment
    cannot slowly redefine "normal" downwards.
    """

    def __init__(self, window: int = 60) -> None:
        self.samples: deque[int] = deque(maxlen=window)

    def observe(self, total_gh: int, mining: bool) -> None:
        if mining and total_gh > 0:
            self.samples.append(int(total_gh))

    def value(self) -> int | None:
        if len(self.samples) < 3:
            return None
        return int(median([float(s) for s in self.samples]))


class QTMPEngine:
    """Rolling per-board statistics and the alerts they justify."""

    def __init__(self, config: dict) -> None:
        self.config = config
        window = int(config["qtmp"]["window"])
        self.hashrate: dict[tuple[str, int], deque[float]] = {}
        self.fan_residual: dict[str, deque[float]] = {}
        self.hardware_errors: dict[str, deque[float]] = {}
        self.alerts: deque[dict] = deque(maxlen=200)
        self._window = window
        #: consecutive polls each board has been below threshold
        self._breaches: dict[tuple[str, int], int] = {}

    def _series(self, store: dict, key) -> deque:
        series = store.get(key)
        if series is None:
            series = deque(maxlen=self._window)
            store[key] = series
        return series

    def update(self, snapshot: dict) -> list[dict]:
        """Fold one poll into the rolling state and return newly raised alerts."""
        thresholds = self.config["qtmp"]
        raised: list[dict] = []
        board_means: dict[tuple[str, int], float] = {}

        for miner, data in snapshot.items():
            if not data:
                continue
            for board in data["boards"]:
                key = (miner, board["idx"])
                series = self._series(self.hashrate, key)
                series.append(float(board["hashrate_gh"]))
                board_means[key] = sum(series) / len(series)
            temperatures = [b["temp_max"] for b in data["boards"] if b.get("temp_max")]
            if data.get("fans") and temperatures:
                mean_temp = sum(temperatures) / len(temperatures)
                for rpm in data["fans"]:
                    self._series(self.fan_residual, miner).append(rpm / max(mean_temp, 1.0))
            self._series(self.hardware_errors, miner).append(float(data.get("hw_errors", 0)))

        min_samples = int(thresholds.get("min_samples", 10))
        persistence = int(thresholds.get("persistence", 3))
        judged = {
            key: mean
            for key, mean in board_means.items()
            if len(self.hashrate[key]) >= min_samples
        }
        if len(judged) >= int(thresholds["min_siblings"]):
            alert_z = float(thresholds["z_alert"])
            critical_z = float(thresholds["z_critical"])
            if thresholds.get("family_wise", True):
                alert_z = sidak_threshold(alert_z, len(judged))
                critical_z = sidak_threshold(critical_z, len(judged))
            for key, mean_hashrate in judged.items():
                peers = [v for k, v in judged.items() if k != key]
                z = robust_z(mean_hashrate, peers)
                series = list(self.hashrate[key])
                z_adjusted = z * math.sqrt(min(1.0, n_eff(series) / max(len(series), 1)))
                if z_adjusted >= -alert_z:
                    self._breaches[key] = 0
                    continue
                self._breaches[key] = self._breaches.get(key, 0) + 1
                if self._breaches[key] < persistence:
                    continue
                severity = SEVERITY_CRITICAL if z_adjusted < -critical_z else SEVERITY_ALERT
                raised.append(
                    self._alert(
                        severity, "hashrate", f"{key[0]} board {key[1]}", z_adjusted,
                        f"{abs(z_adjusted):.1f} sigma below its siblings for "
                        f"{self._breaches[key]} consecutive polls "
                        f"({mean_hashrate / 1000:.1f} TH/s)",
                    )
                )

        for miner, series in self.fan_residual.items():
            if len(series) < 10:
                continue
            values = list(series)
            z = robust_z(sum(values[-3:]) / 3.0, values[:-3])
            if z > float(thresholds["fan_temp_alert"]):
                raised.append(
                    self._alert(
                        SEVERITY_ALERT, "fan", miner, z,
                        f"fans working {z:.1f} sigma harder for the same temperature "
                        "- check dust or a bearing",
                    )
                )

        for miner, series in self.hardware_errors.items():
            if len(series) < 10:
                continue
            values = list(series)
            slope, residual_sd = linear_slope(values)
            standard_error = residual_sd / math.sqrt(max(n_eff(values), 2.0))
            z = slope / standard_error if standard_error > 1e-9 else 0.0
            if z > float(thresholds["hw_err_slope_alert"]):
                raised.append(
                    self._alert(
                        SEVERITY_ALERT, "hw_errors", miner, z,
                        f"hardware errors trending up ({z:.1f} sigma)",
                    )
                )

        open_alerts = {(a["metric"], a["target"]) for a in self.alerts if a.get("open", True)}
        fresh = [a for a in raised if (a["metric"], a["target"]) not in open_alerts]
        self.alerts.extend(fresh)
        return fresh

    def _alert(self, severity: str, metric: str, target: str, z: float, message: str) -> dict:
        return {
            "id": secrets.token_hex(8),
            "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "severity": severity,
            "metric": metric,
            "target": target,
            "z": round(float(z), 2),
            "message": message,
            "open": True,
            "feedback": None,
        }
