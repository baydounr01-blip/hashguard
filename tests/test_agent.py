"""The poll loop, and the order it keeps.

The security property is an *ordering*: the decision that governs an interval
is committed to disk before the telemetry that will corroborate it is read.
Reading the code is not evidence of that. Running the loop and checking that
every record's reveal reproduces the commitment written a poll earlier is.
"""

from hashguard.adaptive import Adaptive
from hashguard.agent import poll_once
from hashguard.api import AgentState
from hashguard.collector import SimulatedFarm
from hashguard.commit import MISMATCHED, REVEALED, UNREVEALED, reveal_state
from hashguard.config import default_config
from hashguard.identity import DeviceIdentity
from hashguard.ledger import GuardedLedger
from hashguard.pricing import Curtailment
from hashguard.qtmp import HashrateBaseline, QTMPEngine


def build(tmp_path):
    config = default_config()
    config["farm_name"] = "Test farm"
    config["poll_seconds"] = 60
    config["paths"]["ledger_dir"] = str(tmp_path / "ledger")
    config["paths"]["log_dir"] = str(tmp_path / "logs")
    identity = DeviceIdentity.generate()
    state = AgentState(
        config=config,
        engine=QTMPEngine(config),
        curtailment=Curtailment(config),
        ledger=GuardedLedger(identity, base_dir=config["paths"]["ledger_dir"]),
        adaptive=Adaptive(config, str(tmp_path / "adaptive.json")),
        identity=identity,
    )
    return state, identity


def states_of(ledger):
    records = []
    for day in ledger.days():
        records.extend(ledger.day_records(day))
    out = []
    previous = None
    for record in records:
        out.append(reveal_state(record, previous))
        previous = record
    return records, out


def test_the_poll_loop_commits_before_it_measures(tmp_path):
    state, _ = build(tmp_path)
    farm = SimulatedFarm()
    baseline = HashrateBaseline()
    for _ in range(4):
        poll_once(state, farm, baseline)

    records, states = states_of(state.ledger)
    assert len(records) == 4

    # The first poll of a session closes nothing, claims nothing, and still
    # commits the interval it opens -- the commitment needs somewhere to go.
    assert records[0]["seconds"] == 0
    assert records[0]["claimed_wh"] == 0
    assert records[0]["reveal"] is None
    assert records[0]["commit"]

    assert states[0] == UNREVEALED
    assert states[1:] == [REVEALED, REVEALED, REVEALED], (
        "every closed interval must reveal the decision committed a poll earlier"
    )
    # The commitment now outstanding is the one the last record carries, so it
    # is on disk before the next poll reads a single hashrate.
    assert state.open_interval["commit"] == records[-1]["commit"]


def test_every_record_reveals_exactly_its_predecessor(tmp_path):
    state, _ = build(tmp_path)
    farm = SimulatedFarm()
    baseline = HashrateBaseline()
    for _ in range(5):
        poll_once(state, farm, baseline)

    records, _ = states_of(state.ledger)
    for record in records[1:]:
        assert record["reveal"]["commit_seq"] == record["seq"] - 1


def test_a_restart_leaves_one_unrevealed_commitment_and_no_mismatch(tmp_path):
    """The agent restarting is the ordinary cause of an unrevealed commitment.
    It must not look like tampering, and it must not bill."""
    state, identity = build(tmp_path)
    farm = SimulatedFarm()
    baseline = HashrateBaseline()
    for _ in range(3):
        poll_once(state, farm, baseline)

    # A new process over the same ledger: nothing in memory, everything on disk.
    state.open_interval = None
    state.ledger = GuardedLedger(identity, base_dir=state.config["paths"]["ledger_dir"])
    for _ in range(2):
        poll_once(state, farm, baseline)

    records, states = states_of(state.ledger)
    assert len(records) == 5
    assert MISMATCHED not in states
    assert states.count(UNREVEALED) == 2, "the session start and the restart, and nothing else"


def test_a_claim_never_covers_more_time_than_the_poll_interval(tmp_path):
    """A stalled agent under-claims rather than over-claims: whatever the wall
    clock says, an interval is capped at the configured poll."""
    state, _ = build(tmp_path)
    farm = SimulatedFarm()
    baseline = HashrateBaseline()
    for _ in range(3):
        poll_once(state, farm, baseline)

    records, _ = states_of(state.ledger)
    for record in records:
        assert 0 <= record["seconds"] <= state.config["poll_seconds"]


def test_nothing_is_committed_before_the_first_poll(tmp_path):
    """There is no open interval until the loop has run once, and the console
    is told that rather than shown a commitment that does not exist."""
    state, _ = build(tmp_path)
    assert state.open_interval is None
    poll_once(state, SimulatedFarm(), HashrateBaseline())
    assert state.open_interval is not None
    assert state.open_interval["opened"]
