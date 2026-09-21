"""The audit that audits the audit.

``docs/AUDIT_v1.md`` says what each defence does. ``hashguard --self-audit``
re-runs those findings against a live agent. The risk with any self-check is
that it becomes decorative -- a function that returns PASS regardless, which
nobody notices because PASS is what everyone expected to see.

So every test here does the same thing from a different angle: it *reopens* a
closed finding and requires the audit to go red on exactly that line, and not
on the others. A green audit is only evidence if a broken build turns it red.
"""

import json
import os
import secrets
import stat

import pytest

from hashguard.adaptive import Adaptive
from hashguard.api import AgentState
from hashguard.config import CONSOLE_WRITABLE, Field, default_config
from hashguard.config import save as save_config
from hashguard.identity import DeviceIdentity
from hashguard.ledger import GuardedLedger, Interval
from hashguard.pricing import Curtailment
from hashguard.qtmp import QTMPEngine
from hashguard.selfaudit import (
    FAIL,
    NOT_CHECKED,
    PASS,
    exit_code,
    format_report,
    package_digest,
    report_json,
    run,
)


def build_state(tmp_path, records: int = 3):
    """A real agent state on disk: config 0600, key 0600, a short ledger."""
    config = default_config()
    config["farm_name"] = "Audit farm"
    config["paths"]["ledger_dir"] = str(tmp_path / "ledger")
    config["paths"]["log_dir"] = str(tmp_path / "logs")
    config["paths"]["device_key"] = str(tmp_path / "device_key.json")
    config["paths"]["state"] = str(tmp_path / "adaptive.json")
    # load() mints one; these tests build the config directly, so mint it here
    # rather than handing the audit an agent whose door has no lock at all.
    config["api"]["api_token"] = secrets.token_urlsafe(32)
    config_path = str(tmp_path / "config.json")
    save_config(config, config_path)

    identity = DeviceIdentity.generate()
    identity.save(config["paths"]["device_key"])
    ledger = GuardedLedger(identity, base_dir=config["paths"]["ledger_dir"])
    for index in range(records):
        ledger.record(
            Interval(
                action="PAUSE" if index % 2 else "MINE",
                executed=False,
                n_miners=4,
                seconds=60,
                price_ppm_per_kwh=180_000,
                breakeven_ppm_per_kwh=60_000,
                claimed_wh=1000 if index % 2 else 0,
                claimed_mining_lost_micro_eur=900 if index % 2 else 0,
                baseline_gh=400_000,
                observed_gh=0 if index % 2 else 400_000,
            )
        )
    state = AgentState(
        config=config,
        engine=QTMPEngine(config),
        curtailment=Curtailment(config),
        ledger=ledger,
        adaptive=Adaptive(config, config["paths"]["state"]),
        identity=identity,
    )
    return state, config_path


def verdicts(checks) -> dict:
    return {check.finding: check.verdict for check in checks}


def observed(checks, finding: str) -> str:
    return next(check.observed for check in checks if check.finding == finding)


def reds(checks) -> list:
    return [check.finding for check in checks if check.verdict == FAIL]


@pytest.fixture
def audit_cwd(tmp_path, monkeypatch):
    """Run from a scratch directory.

    Not tidiness: a probe aimed at the console write surface would, if that
    surface ever reopened, cause the API to persist the patched configuration
    to ``config.json`` in the working directory. These tests deliberately
    reopen that surface, so the working directory must not be the repository.
    """
    monkeypatch.chdir(tmp_path)
    return tmp_path


# -- the audit is green, and says what it could not check -------------------


def test_the_self_audit_is_green_on_this_build(audit_cwd):
    state, config_path = build_state(audit_cwd)
    checks = run(state, config_path=config_path)
    assert reds(checks) == [], "a defence documented in AUDIT_v1.md is no longer standing"
    for finding in (
        "AUDIT-01", "AUDIT-02", "AUDIT-03", "AUDIT-04", "AUDIT-05", "AUDIT-06",
        "AUDIT-07", "AUDIT-08", "AUDIT-09", "AUDIT-10", "AUDIT-11", "AUDIT-12",
        "AUDIT-14", "token", "signing",
    ):
        assert verdicts(checks)[finding] == PASS, f"{finding}: {observed(checks, finding)}"
    assert exit_code(checks) == 0


def test_the_report_states_what_it_did_not_check(audit_cwd):
    """No release publishes a digest for this version yet. The audit has to say
    so in amber rather than quietly counting it as a defence that held."""
    state, config_path = build_state(audit_cwd)
    checks = run(state, config_path=config_path)

    assert verdicts(checks)["build"] == NOT_CHECKED
    assert "no published digest" in observed(checks, "build")
    # It is not a failure by default -- there is nothing wrong with this build,
    # only something missing from the world -- but --strict refuses to ship on it.
    assert exit_code(checks, strict=False) == 0
    assert exit_code(checks, strict=True) == 1

    text = format_report(checks, strict=False)
    assert "NOT CHECKED" in text
    assert "not counted as passing" in text
    report = report_json(checks, strict=True)
    assert report["summary"]["not_checked"] >= 1
    assert report["exit_code"] == 1


def test_the_audit_writes_nothing(audit_cwd):
    """It probes a running agent. It must not leave a mark on one."""
    state, config_path = build_state(audit_cwd)
    before_config = open(config_path, encoding="utf-8").read()
    before_records = [
        r for day in state.ledger.days() for r in state.ledger.day_records(day)
    ]
    before_seals = state.ledger.seals()
    listing = sorted(os.listdir(audit_cwd))

    run(state, config_path=config_path)

    assert open(config_path, encoding="utf-8").read() == before_config
    after_records = [
        r for day in state.ledger.days() for r in state.ledger.day_records(day)
    ]
    assert after_records == before_records, "the audit appended to the ledger it was auditing"
    assert state.ledger.seals() == before_seals, "the audit sealed a day"
    assert sorted(os.listdir(audit_cwd)) == listing, "the audit left a file behind"


# -- reopen a finding, and the right line must go red ----------------------


def test_reopening_the_config_write_surface_turns_audit_04_red(audit_cwd, monkeypatch):
    """AUDIT-04 was that ``POST /config`` merged anything. Make the fee
    console-writable again -- exactly the regression a careless patch would
    introduce -- and the audit must name it."""
    monkeypatch.setitem(
        CONSOLE_WRITABLE, "billing.fee_bp", Field("int", 2500, 0, 10_000, doc="reopened")
    )
    state, config_path = build_state(audit_cwd)
    checks = run(state, config_path=config_path)

    assert "AUDIT-04" in reds(checks)
    assert "billing.fee_bp" in observed(checks, "AUDIT-04")
    assert reds(checks) == ["AUDIT-04"], (
        f"reopening one finding must redden one line; saw {reds(checks)}"
    )
    assert exit_code(checks) == 1


def test_a_loosened_key_file_turns_audit_14_red(audit_cwd):
    """AUDIT-14 was secrets written world-readable. A ``chmod 644`` on the
    signing key is how that comes back -- usually by a backup script, not by a
    code change, which is exactly why reading the code would not find it."""
    state, config_path = build_state(audit_cwd)
    key_path = state.config["paths"]["device_key"]
    os.chmod(key_path, 0o644)
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o644

    checks = run(state, config_path=config_path)
    assert "AUDIT-14" in reds(checks)
    assert "readable beyond its owner" in observed(checks, "AUDIT-14")
    assert "chmod 600" in observed(checks, "AUDIT-14"), "a red line must say what to do"
    assert reds(checks) == ["AUDIT-14"]


@pytest.mark.parametrize(
    "token, because",
    [
        # 25 characters, so config.validate() lets it through, and long enough
        # that a character-count rule alone would call it fine.
        ("hunter2hunter2hunter2hunt", "distinct characters"),
        # 32 characters, 16 distinct, ~150 bits by alphabet -- and one half
        # typed twice. Length and alphabet both say yes; the period says no.
        ("abcdefghijklmnopabcdefghijklmnop", "repeated"),
        ("shortish-token-abc12", "at least"),
    ],
)
def test_a_token_that_is_guessable_by_shape_turns_the_entropy_check_red(
    audit_cwd, token, because
):
    """The one thing this check must not do is measure only length. Each of
    these clears a length rule and is still a string somebody would guess."""
    state, config_path = build_state(audit_cwd)
    state.config["api"]["api_token"] = token
    checks = run(state, config_path=config_path)

    assert "token" in reds(checks)
    assert because in observed(checks, "token")
    assert "let the agent mint one" in observed(checks, "token"), "a red line must say what to do"
    assert reds(checks) == ["token"]


def test_a_minted_token_passes_the_shape_check(audit_cwd):
    """The bar has to be one the agent's own token clears, every time, or the
    audit is a warning nobody can act on."""
    state, config_path = build_state(audit_cwd)
    for _ in range(25):
        state.config["api"]["api_token"] = secrets.token_urlsafe(32)
        checks = run(state, config_path=config_path)
        assert verdicts(checks)["token"] == PASS, observed(checks, "token")


def test_a_console_page_that_allows_inline_script_turns_audit_11_red(audit_cwd):
    """The console's defence against stored XSS is a CSP plus a page that never
    builds HTML from a string. Relax the CSP and the audit must notice, because
    this one is checked by reading the files the browser will actually be given."""
    web = audit_cwd / "web"
    web.mkdir()
    (web / "console.js").write_text("const x = 1;\n", encoding="utf-8")
    (web / "console.html").write_text(
        '<meta http-equiv="Content-Security-Policy" content="\n'
        "  default-src 'none';\n"
        "  script-src 'self' 'unsafe-inline';\n"
        '">\n<script src="console.js"></script>\n',
        encoding="utf-8",
    )
    state, config_path = build_state(audit_cwd)
    checks = run(state, config_path=config_path)

    assert "AUDIT-11" in reds(checks)
    assert "unsafe-inline" in observed(checks, "AUDIT-11")


def test_a_console_page_that_writes_html_from_a_string_turns_audit_11_red(audit_cwd):
    web = audit_cwd / "web"
    web.mkdir()
    (web / "console.js").write_text(
        "function render(row) {\n  panel.innerHTML = `<b>${row.name}</b>`;\n}\n", encoding="utf-8"
    )
    (web / "console.html").write_text(
        '<meta http-equiv="Content-Security-Policy" content="script-src \'self\';">\n'
        '<script src="console.js"></script>\n',
        encoding="utf-8",
    )
    state, config_path = build_state(audit_cwd)
    checks = run(state, config_path=config_path)

    assert "AUDIT-11" in reds(checks)
    assert "innerHTML" in observed(checks, "AUDIT-11")


def test_a_ledger_with_nothing_in_it_is_not_checked_rather_than_passed(audit_cwd):
    """A fresh install has no records. AUDIT-05 cannot be replayed against an
    empty ledger, and saying PASS there would be the most flattering lie the
    audit could tell: every later statement rests on that check."""
    state, config_path = build_state(audit_cwd, records=0)
    checks = run(state, config_path=config_path)

    assert verdicts(checks)["AUDIT-05"] == NOT_CHECKED
    assert "no records yet" in observed(checks, "AUDIT-05")
    assert reds(checks) == []
    assert exit_code(checks, strict=True) == 1


def test_a_non_loopback_bind_is_not_checked_rather_than_passed(audit_cwd):
    """The operator may bind the LAN deliberately; AUDIT-12's default still
    holds and validate() still refuses it unacknowledged. What the audit must
    not do is print PASS next to a machine that is listening to its network."""
    state, config_path = build_state(audit_cwd)
    state.config["api"]["bind_host"] = "10.0.0.5"
    state.config["api"]["i_understand_non_loopback_bind"] = True
    checks = run(state, config_path=config_path)

    assert verdicts(checks)["AUDIT-12"] == NOT_CHECKED
    assert "10.0.0.5" in observed(checks, "AUDIT-12")
    assert reds(checks) == []


# -- the digest that lets someone else check this build --------------------


def test_the_package_digest_moves_when_the_package_does(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    (package / "core.py").write_text("y = 2\n", encoding="utf-8")
    first, count = package_digest(str(package))
    assert count == 2

    (package / "core.py").write_text("y = 3\n", encoding="utf-8")
    second, _ = package_digest(str(package))
    assert second != first, "a changed byte must change the digest"

    # A rename alone changes it too: the path is part of what is hashed, so
    # shuffling code between modules cannot keep the same answer.
    (package / "core.py").rename(package / "engine.py")
    third, _ = package_digest(str(package))
    assert third != second


def test_the_digest_ignores_bytecode_caches(tmp_path):
    """Two machines that ran the code a different number of times must agree."""
    package = tmp_path / "pkg"
    (package / "__pycache__").mkdir(parents=True)
    (package / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    before, count = package_digest(str(package))
    (package / "__pycache__" / "__init__.cpython-311.py").write_text("noise\n", encoding="utf-8")
    after, after_count = package_digest(str(package))
    assert (before, count) == (after, after_count)


def test_the_json_report_is_a_document_not_a_screen(audit_cwd):
    state, config_path = build_state(audit_cwd)
    report = report_json(run(state, config_path=config_path))
    assert json.loads(json.dumps(report)) == report
    assert {"finding", "claim", "verdict", "observed", "ms"} <= set(report["checks"][0])
    assert report["summary"]["passed"] + report["summary"]["failed"] + report["summary"][
        "not_checked"
    ] == len(report["checks"])
