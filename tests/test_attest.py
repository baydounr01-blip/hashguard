"""The corroboration auditor: an invoice line has to be visible in the physics.

Ported from ``bbu.signature.ComputeAuditor`` (postulate P12 of the Universo de
Bloques Ramificados). There, credited compute exceeding a branch's budget is a
signature. Here, claimed savings exceeding what the telemetry witnessed is one.
"""

from hashguard.attest import (
    CORROBORATED,
    OVERCLAIMED,
    PARTIAL,
    UNCORROBORATED,
    Claim,
    SavingsAuditor,
    dark_fraction_ppm,
)

FULL_FARM_GH = 630_000
ONE_INTERVAL_WH = 18_300


def test_dark_fraction_is_zero_when_nothing_stopped():
    assert dark_fraction_ppm(FULL_FARM_GH, FULL_FARM_GH) == 0


def test_dark_fraction_is_total_when_everything_stopped():
    assert dark_fraction_ppm(FULL_FARM_GH, 0) == 1_000_000


def test_dark_fraction_is_unknown_without_a_baseline():
    assert dark_fraction_ppm(None, 100) is None
    assert dark_fraction_ppm(0, 100) is None


def test_an_honest_pause_is_billable_in_full():
    auditor = SavingsAuditor()
    for seq in range(10):
        auditor.submit(Claim(seq, ONE_INTERVAL_WH, FULL_FARM_GH, 200))
    assert auditor.verdict() in (CORROBORATED, PARTIAL)
    assert auditor.billable_wh > 0.99 * auditor.claimed_wh
    assert not auditor.flagged


def test_a_fabricated_pause_is_worth_nothing():
    """Claiming savings while the farm hashes at full tilt bills zero."""
    auditor = SavingsAuditor()
    for seq in range(10):
        auditor.submit(Claim(seq, ONE_INTERVAL_WH, FULL_FARM_GH, FULL_FARM_GH - 1_000))
    assert auditor.verdict() == UNCORROBORATED
    assert auditor.billable_wh == 0
    assert auditor.overclaim_detected
    assert len(auditor.flagged) == 10


def test_a_half_executed_pause_bills_half():
    """Claiming six machines stopped when three did is capped at three."""
    auditor = SavingsAuditor()
    auditor.submit(Claim(0, ONE_INTERVAL_WH, FULL_FARM_GH, FULL_FARM_GH // 2))
    assert auditor.billable_wh == ONE_INTERVAL_WH // 2
    assert auditor.verdict() == OVERCLAIMED


def test_savings_without_a_baseline_are_never_billed():
    """Billing fails closed: what we cannot corroborate, we do not charge for."""
    auditor = SavingsAuditor()
    auditor.submit(Claim(0, ONE_INTERVAL_WH, None, None))
    assert auditor.billable_wh == 0
    assert auditor.verdict() == UNCORROBORATED


def test_billable_never_exceeds_corroborated():
    """The cap is the whole safety property. It must hold for any input."""
    auditor = SavingsAuditor()
    for seq, observed in enumerate([0, 100, 300_000, 600_000, FULL_FARM_GH]):
        auditor.submit(Claim(seq, ONE_INTERVAL_WH, FULL_FARM_GH, observed))
    assert auditor.billable_wh <= auditor.corroborated_wh
    assert auditor.billable_wh <= auditor.claimed_wh


def test_a_month_of_only_mining_is_corroborated_trivially():
    auditor = SavingsAuditor()
    for seq in range(5):
        auditor.submit(Claim(seq, 0, FULL_FARM_GH, FULL_FARM_GH))
    assert auditor.verdict() == CORROBORATED
    assert not auditor.overclaim_detected


def test_report_is_integer_only_and_therefore_hashable():
    from hashguard.canonical import canonical_bytes

    auditor = SavingsAuditor()
    auditor.submit(Claim(0, ONE_INTERVAL_WH, FULL_FARM_GH, 500))
    canonical_bytes(auditor.report())  # raises if any float sneaked in
