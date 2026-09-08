"""Corroboration: an invoice line has to be visible in the physics.

This module is a port of ``bbu.signature`` from the Universo de Bloques
Ramificados repository, where it implements postulate P12 -- the only
falsifiable prediction of that framework. There, the ``ComputeAuditor``
compares the compute an agent *credits itself with* against the compute its
branch could physically have supplied, and declares a signature when the first
exceeds the second by a margin the variance cannot explain::

    excess_ratio = accredited_cost / branch_budget
    signature    = excess_ratio > margin

HashGuard bills a share of measured savings, which puts it in the same shape of
trouble: the party issuing the bill is the party doing the measuring. So the
same detector is pointed at the invoice.

    claimed savings  <-> accredited compute  (what the ledger asserts)
    dark machine-hrs <-> branch budget       (what the telemetry witnessed)

A pause claims that machines stopped drawing power. If they stopped, their
hashrate went to the floor, and the hashrate is measured by a different code
path, from a different source (the miners' own API), than the price and power
figures that produce the claim. Two independent readings of one physical event.
When they disagree, the disagreement is the finding.

Two rules follow, and they point in opposite directions on purpose:

* **Mining fails open.** No price data, no telemetry, agent dead -> keep mining.
  The client's operation is never held hostage by our uncertainty.
* **Billing fails closed.** Savings the telemetry cannot corroborate are not
  billable, and a claim is capped at its corroborated value. Our uncertainty is
  charged to us, not to the client.

The asymmetry is the whole product. It is cheaper for the operator to measure
honestly than to argue.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PPM = 1_000_000

#: How far a claim may exceed its corroboration before it is called out.
#: Telemetry is noisy and a miner can take a poll cycle to actually go dark, so
#: a small excess is expected; 1.25x is not.
DEFAULT_MARGIN_PPM = 1_250_000

#: Below this share of the farm going dark, a pause is treated as not having
#: happened at all rather than as a partial one.
MIN_DARK_FRACTION_PPM = 50_000  # 5%

CORROBORATED = "CORROBORATED"
PARTIAL = "PARTIAL"
OVERCLAIMED = "OVERCLAIMED"
UNCORROBORATED = "UNCORROBORATED"


def dark_fraction_ppm(baseline_gh: int, observed_gh: int) -> int | None:
    """How much of the farm actually went dark, in parts per million.

    ``None`` when there is no usable baseline: the honest answer to "we cannot
    tell", which the caller must treat as not billable rather than as zero
    savings or as full savings.
    """
    if baseline_gh is None or observed_gh is None or baseline_gh <= 0:
        return None
    fraction = (baseline_gh - observed_gh) * PPM // baseline_gh
    return max(0, min(PPM, fraction))


@dataclass
class Claim:
    """One interval's assertion, and the telemetry standing behind it."""

    seq: int
    claimed_wh: int
    baseline_gh: int | None
    observed_gh: int | None

    @property
    def corroborated_wh(self) -> int:
        fraction = dark_fraction_ppm(self.baseline_gh, self.observed_gh)
        if fraction is None or fraction < MIN_DARK_FRACTION_PPM:
            return 0
        return self.claimed_wh * fraction // PPM

    @property
    def billable_wh(self) -> int:
        """Never more than the telemetry witnessed. This is the cap."""
        return min(self.claimed_wh, self.corroborated_wh)


@dataclass
class SavingsAuditor:
    """Accumulates claims over a period and returns a verdict, not an opinion.

    Deliberately mirrors ``bbu.signature.ComputeAuditor``: ``submit`` to feed it,
    ``excess_ratio_ppm`` for the raw number, ``overclaim_detected`` for the
    thresholded call.
    """

    margin_ppm: int = DEFAULT_MARGIN_PPM
    claimed_wh: int = 0
    corroborated_wh: int = 0
    billable_wh: int = 0
    n_claims: int = 0
    n_uncorroborated: int = 0
    flagged: list[int] = field(default_factory=list)

    def submit(self, claim: Claim) -> int:
        """Register a claim. Returns the watt-hours that became billable."""
        self.n_claims += 1
        self.claimed_wh += claim.claimed_wh
        corroborated = claim.corroborated_wh
        self.corroborated_wh += corroborated
        billable = claim.billable_wh
        self.billable_wh += billable
        if claim.claimed_wh > 0 and corroborated == 0:
            self.n_uncorroborated += 1
            self.flagged.append(claim.seq)
        elif corroborated > 0 and claim.claimed_wh * PPM // corroborated > self.margin_ppm:
            self.flagged.append(claim.seq)
        return billable

    @property
    def excess_ratio_ppm(self) -> int | None:
        """claimed / corroborated, in ppm. ``None`` when nothing was claimed."""
        if self.claimed_wh == 0:
            return None
        if self.corroborated_wh == 0:
            return None  # unbounded: claimed something, witnessed nothing
        return self.claimed_wh * PPM // self.corroborated_wh

    @property
    def overclaim_detected(self) -> bool:
        if self.claimed_wh == 0:
            return False
        ratio = self.excess_ratio_ppm
        if ratio is None:
            return True  # claimed savings with zero corroboration anywhere
        return ratio > self.margin_ppm

    def verdict(self) -> str:
        if self.claimed_wh == 0:
            return CORROBORATED
        if self.corroborated_wh == 0:
            return UNCORROBORATED
        if self.overclaim_detected:
            return OVERCLAIMED
        if self.billable_wh < self.claimed_wh:
            return PARTIAL
        return CORROBORATED

    def report(self) -> dict:
        """Canonical, integer-only, safe to hash into a seal."""
        return {
            "verdict": self.verdict(),
            "margin_ppm": self.margin_ppm,
            "claimed_wh": self.claimed_wh,
            "corroborated_wh": self.corroborated_wh,
            "billable_wh": self.billable_wh,
            "excess_ratio_ppm": self.excess_ratio_ppm,
            "n_claims": self.n_claims,
            "n_uncorroborated": self.n_uncorroborated,
            "flagged_seq": sorted(self.flagged)[:64],
        }
