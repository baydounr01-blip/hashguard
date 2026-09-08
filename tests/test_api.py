"""The HTTP surface, exercised against a live server on loopback.

Every test here is an attack that worked, or would have worked, against v1.
"""

import json
import threading
import urllib.error
import urllib.request

import pytest

from hashguard.adaptive import Adaptive
from hashguard.api import AgentState, serve
from hashguard.config import default_config
from hashguard.identity import DeviceIdentity
from hashguard.ledger import GuardedLedger
from hashguard.pricing import Curtailment
from hashguard.qtmp import QTMPEngine

TOKEN = "a-token-that-is-comfortably-long-enough"


@pytest.fixture
def agent(tmp_path):
    config = default_config()
    config["farm_name"] = "Test farm"
    config["api"]["api_token"] = TOKEN
    config["api"]["api_port"] = 0  # let the OS pick a free port
    config["api"]["cors_origins"] = ["https://console.example"]
    config["api"]["rate_limit"]["failure_threshold"] = 3
    config["api"]["rate_limit"]["base_block_s"] = 30
    config["paths"]["ledger_dir"] = str(tmp_path / "ledger")

    identity = DeviceIdentity.generate()
    state = AgentState(
        config=config,
        engine=QTMPEngine(config),
        curtailment=Curtailment(config),
        ledger=GuardedLedger(identity, base_dir=config["paths"]["ledger_dir"]),
        adaptive=Adaptive(config, str(tmp_path / "adaptive.json")),
        identity=identity,
    )
    server = serve(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    yield state
    server.shutdown()
    server.server_close()


def call(agent, path, token=TOKEN, method="GET", body=None, origin=None):
    """Returns (status, headers, parsed body)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(agent.base_url + path, data=data, method=method)
    if token is not None:
        request.add_header("X-HashGuard-Token", token)
    if origin:
        request.add_header("Origin", origin)
    if data:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, dict(response.headers), json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), json.loads(error.read() or b"{}")


# -- authentication (AUDIT-06) --------------------------------------------


def test_no_token_is_rejected(agent):
    status, _, _ = call(agent, "/status", token=None)
    assert status == 401


def test_a_wrong_token_is_rejected(agent):
    status, _, payload = call(agent, "/status", token="wrong")
    assert status == 401 and payload["error"] == "invalid token"


def test_the_right_token_works(agent):
    status, _, payload = call(agent, "/status")
    assert status == 200 and payload["farm"] == "Test farm"


def test_repeated_guessing_gets_blocked_with_a_retry_after(agent):
    """v1 attached no cost at all to being wrong."""
    for _ in range(5):
        call(agent, "/status", token="wrong")
    status, headers, _ = call(agent, "/status", token="wrong")
    assert status == 429
    assert int(headers["Retry-After"]) > 0


def test_guessing_is_blocked_per_presented_token_as_well_as_per_source(agent):
    """Two keys are counted, so rotating one dimension does not escape the other.

    Note the deliberate trade-off documented in docs/THREAT_MODEL.md: on a
    loopback-only bind the source key is shared with the legitimate console, so
    a local attacker can cause a temporary self-denial. Anyone who can reach
    loopback can already read config.json, so this buys them nothing.
    """
    for _ in range(5):
        call(agent, "/status", token="wrong-guess")
    status, _, _ = call(agent, "/status", token="wrong-guess")
    assert status == 429


# -- CORS (AUDIT-01) ------------------------------------------------------


def test_a_listed_origin_is_echoed(agent):
    _, headers, _ = call(agent, "/status", origin="https://console.example")
    assert headers.get("Access-Control-Allow-Origin") == "https://console.example"
    assert headers.get("Vary") == "Origin"


def test_an_unlisted_origin_gets_nothing(agent):
    """v1 shipped Access-Control-Allow-Origin: * by default."""
    _, headers, _ = call(agent, "/status", origin="https://evil.example")
    assert "Access-Control-Allow-Origin" not in headers


def test_an_unlisted_origin_cannot_write(agent):
    status, _, _ = call(
        agent, "/config", method="POST", body={"qtmp": {"z_alert": 3.0}}, origin="https://evil.example"
    )
    assert status == 403


# -- headers --------------------------------------------------------------


def test_security_headers_are_present(agent):
    _, headers, _ = call(agent, "/status")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["Cache-Control"] == "no-store"


def test_the_python_version_is_not_advertised(agent):
    _, headers, _ = call(agent, "/status")
    assert "Python" not in headers.get("Server", "")


# -- the write surface (AUDIT-04) -----------------------------------------


def test_the_console_can_calibrate(agent):
    status, _, payload = call(agent, "/config", method="POST", body={"qtmp": {"z_alert": 3.1}})
    assert status == 200 and payload["applied"] == ["qtmp.z_alert"]
    assert agent.config["qtmp"]["z_alert"] == 3.1


def test_the_console_cannot_change_the_fee_or_the_price_source(agent):
    """v1 deep-merged anything posted here into the live configuration."""
    status, _, payload = call(
        agent,
        "/config",
        method="POST",
        body={
            "billing": {"fee_bp": 0},
            "curtailment": {"price_url": "http://169.254.169.254/latest/"},
            "paths": {"log_dir": "../../etc"},
        },
    )
    assert status == 207
    assert len(payload["rejected"]) == 3 and not payload["applied"]
    assert agent.config["billing"]["fee_bp"] == 2500
    assert agent.config["curtailment"]["price_url"] == ""
    assert agent.config["paths"]["log_dir"] == "logs"


def test_out_of_range_calibration_is_refused(agent):
    status, _, payload = call(agent, "/config", method="POST", body={"qtmp": {"z_alert": 99}})
    assert status == 207 and not payload["applied"]
    assert agent.config["qtmp"]["z_alert"] == 2.5


# -- bounded input (AUDIT-09) ---------------------------------------------


def test_an_oversized_body_is_refused(agent):
    status, _, _ = call(agent, "/config", method="POST", body={"pad": "x" * 200_000})
    assert status == 413


def test_a_non_json_body_is_refused(agent):
    request = urllib.request.Request(
        agent.base_url + "/config", data=b"not json", method="POST"
    )
    request.add_header("X-HashGuard-Token", TOKEN)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    assert status == 400


def test_a_json_array_body_is_refused(agent):
    status, _, _ = call(agent, "/config", method="POST", body=[1, 2, 3])
    assert status == 400


# -- secrets and routes ---------------------------------------------------


def test_the_token_is_never_echoed(agent):
    _, _, payload = call(agent, "/config")
    assert payload["api"]["api_token"] == "***"
    assert TOKEN not in json.dumps(payload)


def test_the_writable_surface_is_advertised(agent):
    _, _, payload = call(agent, "/config")
    assert "qtmp.z_alert" in payload["_writable_from_console"]
    assert "billing.fee_bp" not in payload["_writable_from_console"]


def test_unknown_routes_are_404_not_a_file_read(agent):
    status, _, _ = call(agent, "/../../etc/passwd")
    assert status == 404


def test_feedback_needs_a_real_alert(agent):
    status, _, _ = call(agent, "/feedback", method="POST", body={"alert_id": "nope", "real": True})
    assert status == 404


def test_feedback_rejects_an_absurd_alert_id(agent):
    status, _, _ = call(agent, "/feedback", method="POST", body={"alert_id": "x" * 5000})
    assert status == 400


def test_status_exposes_the_device_identity_but_no_secret(agent):
    _, _, payload = call(agent, "/status")
    assert payload["device"]["device_id"]
    assert "secret_b64" not in json.dumps(payload["device"])
