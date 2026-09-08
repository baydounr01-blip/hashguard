"""The hardening layer: identity, SSRF policy, rate limiting, config surface.

Each test here corresponds to a finding in ``docs/AUDIT_v1.md``. If one of them
starts failing, a vulnerability that was closed has been reopened.
"""

import base64
import os
import stat

import pytest

from hashguard.config import (
    ConfigError,
    apply_console_patch,
    default_config,
    validate,
)
from hashguard.identity import DeviceIdentity, IdentityError, verify_signature
from hashguard.netguard import NetGuardError, fetch_public_json, is_public, validate_webhook
from hashguard.ratelimit import RateLimiter


# -- identity (AUDIT-05, AUDIT-14) ----------------------------------------


def test_a_signature_verifies_and_a_tampered_message_does_not():
    identity = DeviceIdentity.generate()
    signature = identity.sign(b"sealed")
    assert verify_signature(identity.public(), b"sealed", signature)
    assert not verify_signature(identity.public(), b"sea1ed", signature)


def test_public_material_carries_no_secret():
    identity = DeviceIdentity.generate()
    public = identity.public()
    assert "secret_b64" not in public
    assert base64.b64encode(identity._secret).decode() not in str(public)


def test_key_files_are_written_owner_only(tmp_path):
    path = str(tmp_path / "device_key.json")
    DeviceIdentity.generate().save(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_world_readable_key_is_refused_not_warned_about(tmp_path):
    path = str(tmp_path / "device_key.json")
    DeviceIdentity.generate().save(path)
    os.chmod(path, 0o644)
    with pytest.raises(IdentityError, match="readable beyond its owner"):
        DeviceIdentity.load_or_create(path)


def test_hmac_identity_admits_it_is_not_third_party_verifiable():
    identity = DeviceIdentity.generate(prefer_ed25519=False)
    assert identity.public()["verifiable_by_third_party"] is False
    with pytest.raises(IdentityError, match="third-party audit"):
        verify_signature(identity.public(), b"x", identity.sign(b"x"))


# -- SSRF (AUDIT-02, AUDIT-03) --------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/prices",          # plaintext
        "https://127.0.0.1/prices",           # loopback
        "https://localhost/prices",           # loopback by name
        "https://169.254.169.254/latest/",    # cloud metadata
        "https://10.0.0.1/prices",            # private
        "https://192.168.1.1/prices",         # the farm's own router
        "file:///etc/passwd",                 # not even http
        "https:///no-host",                   # malformed
    ],
)
def test_price_feeds_cannot_be_aimed_inside_the_network(url):
    with pytest.raises(NetGuardError):
        fetch_public_json(url)


@pytest.mark.parametrize(
    "address,expected",
    [
        ("8.8.8.8", True),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("192.168.0.5", False),
        ("172.16.0.1", False),
        ("169.254.169.254", False),
        ("::1", False),
        ("0.0.0.0", False),
    ],
)
def test_address_classification(address, expected):
    import ipaddress

    assert is_public(ipaddress.ip_address(address)) is expected


def test_a_webhook_host_must_be_on_the_allowlist():
    with pytest.raises(NetGuardError, match="webhook_allowlist"):
        validate_webhook("http://192.168.1.50/relay?on=", [])


def test_an_allowlisted_private_webhook_is_accepted():
    assert validate_webhook("http://192.168.1.50/relay?on=", ["192.168.1.50"]) == (
        "192.168.1.50",
        80,
        "/relay?on=",
    )


def test_a_webhook_may_not_point_at_the_public_internet():
    with pytest.raises(NetGuardError, match="public address"):
        validate_webhook("http://example.com/relay", ["example.com"])


# -- rate limiting (AUDIT-06) ---------------------------------------------


def test_a_burst_is_capped():
    clock = [1000.0]
    limiter = RateLimiter(window_s=10, max_attempts=3, clock=lambda: clock[0])
    assert [limiter.consume(["ip:a"]).allowed for _ in range(5)] == [True, True, True, False, False]
    clock[0] += 11
    assert limiter.consume(["ip:a"]).allowed


def test_repeated_wrong_tokens_are_blocked_for_exponentially_longer():
    clock = [1000.0]
    limiter = RateLimiter(failure_threshold=2, base_block_s=2, max_block_s=60, clock=lambda: clock[0])
    assert limiter.failed(["ip:a"]) == 0        # first failure is free
    blocks = [limiter.failed(["ip:a"]) for _ in range(3)]
    assert blocks == [2, 4, 8]
    decision = limiter.consume(["ip:a"])
    assert not decision.allowed and decision.retry_after > 0


def test_a_valid_credential_clears_the_suspicion():
    limiter = RateLimiter(failure_threshold=2, base_block_s=5)
    for _ in range(4):
        limiter.failed(["ip:a"])
    assert not limiter.consume(["ip:a"]).allowed
    limiter.succeeded(["ip:a"])
    assert limiter.consume(["ip:a"]).allowed


def test_the_strictest_key_wins():
    """Rotating the source address does not escape a block on the token."""
    limiter = RateLimiter(failure_threshold=1, base_block_s=30)
    limiter.failed(["tok:deadbeef"])
    assert not limiter.consume(["ip:fresh", "tok:deadbeef"]).allowed


# -- the config write surface (AUDIT-01, AUDIT-04, AUDIT-08) --------------


def test_the_console_can_only_turn_the_calibration_knobs():
    config = default_config()
    applied, rejected = apply_console_patch(
        config,
        {
            "qtmp": {"z_alert": 3.1},
            "billing": {"fee_bp": 0},
            "curtailment": {"price_url": "http://169.254.169.254/", "power_kw": 3.4},
            "paths": {"log_dir": "../../etc"},
            "api": {"api_token": "stolen"},
        },
    )
    assert set(applied) == {"qtmp.z_alert", "curtailment.power_kw"}
    assert config["qtmp"]["z_alert"] == 3.1
    assert config["billing"]["fee_bp"] == 2500, "the fee is not settable over the network"
    assert config["api"]["api_token"] == "", "the token is not settable over the network"
    assert config["paths"]["log_dir"] == "logs"
    assert len(rejected) == 4


def test_rejections_are_named_rather_than_dropped_silently():
    _, rejected = apply_console_patch(default_config(), {"billing": {"fee_bp": 0}})
    assert any("billing.fee_bp" in message for message in rejected)


def test_out_of_range_values_are_refused():
    config = default_config()
    applied, rejected = apply_console_patch(config, {"qtmp": {"z_alert": 99}})
    assert not applied
    assert any("above the maximum" in message for message in rejected)
    assert config["qtmp"]["z_alert"] == 2.5


@pytest.mark.parametrize("value", ["not a number", None, [1], {"a": 1}])
def test_non_numeric_values_are_refused(value):
    applied, rejected = apply_console_patch(default_config(), {"qtmp": {"z_alert": value}})
    assert not applied and rejected


def test_defaults_are_valid():
    assert validate(default_config()) == []


def test_wildcard_cors_is_refused():
    config = default_config()
    config["api"]["cors_origins"] = ["*"]
    assert any("'*' is refused" in problem for problem in validate(config))


def test_binding_beyond_loopback_requires_saying_so():
    config = default_config()
    config["api"]["bind_host"] = "0.0.0.0"
    assert any("bind_host" in problem for problem in validate(config))
    config["api"]["i_understand_non_loopback_bind"] = True
    assert not any("bind_host" in problem for problem in validate(config))


def test_paths_cannot_escape_the_working_directory():
    config = default_config()
    config["paths"]["log_dir"] = "../../etc"
    assert any("outside the working directory" in problem for problem in validate(config))


def test_webhook_mode_without_an_allowlist_is_refused():
    config = default_config()
    config["curtailment"]["mode"] = "webhook"
    assert any("webhook_allowlist is empty" in problem for problem in validate(config))


def test_a_plaintext_price_url_is_refused():
    config = default_config()
    config["curtailment"]["price_source"] = "url"
    config["curtailment"]["price_url"] = "http://prices.example/feed"
    assert any("https" in problem for problem in validate(config))


def test_duplicate_miner_names_are_refused():
    config = default_config()
    config["miners"] = [
        {"name": "S19-01", "host": "192.168.1.101"},
        {"name": "S19-01", "host": "192.168.1.102"},
    ]
    assert any("duplicate name" in problem for problem in validate(config))


def test_loading_an_invalid_config_refuses_to_start(tmp_path):
    import json

    path = tmp_path / "config.json"
    path.write_text(json.dumps({"poll_seconds": 0}))
    with pytest.raises(ConfigError, match="poll_seconds"):
        from hashguard.config import load

        load(str(path))


# -- secrets never leave (AUDIT-07) ---------------------------------------


def test_the_config_endpoint_redacts_every_secret():
    from hashguard.api import redacted_config

    config = default_config()
    config["api"]["api_token"] = "a-real-token-value-32-chars-long"
    config["curtailment"]["price_headers"] = {"x-api-key": "a-real-price-feed-key"}
    config["curtailment"]["webhooks"] = {"S19-01": "http://192.168.1.50/relay?on="}

    view = redacted_config(config)
    serialised = str(view)
    assert "a-real-token-value" not in serialised
    assert "a-real-price-feed-key" not in serialised
    assert "192.168.1.50" not in serialised, "webhook URLs describe the internal network"
    assert config["api"]["api_token"] == "a-real-token-value-32-chars-long", "the view must be a copy"
