"""Configuration: a typed, bounded schema, and a deliberately narrow write surface.

HashGuard v1 accepted ``POST /config`` and deep-merged whatever arrived into
the live configuration. Everything except the API token was writable that way:
the URL the agent fetches prices from, the webhook URLs it calls, the directory
it writes logs into, the billing percentage. A console session was therefore
enough to point the agent at an internal address, to redirect its writes through
``../../``, or to quietly change the fee.

v2 splits configuration in two:

* **Console-writable** -- the calibration knobs, and nothing else. Each one is
  typed and bounded, and a value outside its bounds is rejected with a message,
  not clamped in silence.
* **Operator-only** -- tokens, bind address, price sources, webhook allowlist,
  paths, fee. These change by editing ``config.json`` on the machine, which
  means changing them requires the thing the whole design already assumes an
  attacker does not have: a shell on the farm's own hardware.

The rule of thumb behind the split: if a setting can make the agent talk to
something new, write somewhere new, or bill differently, the network cannot set it.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from typing import Any

CONFIG_PATH = "config.json"


@dataclass(frozen=True)
class Field:
    kind: str                       # "int" | "num" | "str" | "bool" | "list" | "dict"
    default: Any
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple[str, ...] | None = None
    doc: str = ""


#: The knobs the console may turn. Everything here is numeric and bounded.
CONSOLE_WRITABLE: dict[str, Field] = {
    "qtmp.z_alert": Field("num", 2.5, 1.5, 6.0, doc="board vs. siblings, alert threshold in sigma"),
    "qtmp.z_critical": Field("num", 4.0, 2.0, 8.0, doc="critical threshold in sigma"),
    "qtmp.epsilon": Field("num", 0.15, 0.05, 0.5, doc="weak/strong split"),
    "qtmp.fan_temp_alert": Field("num", 2.0, 1.0, 5.0, doc="fan effort vs. temperature, in sigma"),
    "qtmp.hw_err_slope_alert": Field("num", 2.0, 1.0, 6.0, doc="hardware-error trend, in sigma"),
    "qtmp.window": Field("int", 30, 10, 240, doc="samples kept per series"),
    "qtmp.min_siblings": Field("int", 3, 2, 64, doc="boards needed before comparing"),
    "qtmp.min_samples": Field("int", 10, 3, 240, doc="samples a board needs before it is judged"),
    "qtmp.persistence": Field("int", 3, 1, 20, doc="consecutive breaching polls before an alert"),
    "qtmp.family_wise": Field("bool", True, doc="read z_alert as a farm-wide, not per-board, rate"),
    "curtailment.hashrate_th": Field("num", 100.0, 1.0, 1000.0, doc="TH/s per machine"),
    "curtailment.power_kw": Field("num", 3.05, 0.1, 20.0, doc="kW per machine"),
    "curtailment.hashprice_usd_th_day": Field("num", 0.045, 0.001, 1.0, doc="$/TH/day"),
    "curtailment.eur_usd": Field("num", 1.08, 0.5, 3.0, doc="EUR per USD"),
    "curtailment.margin": Field("num", 0.05, 0.0, 0.5, doc="margin required over break-even"),
    "curtailment.fixed_price_eur_kwh": Field("num", 0.12, 0.0, 2.0, doc="EUR/kWh when the source is fixed"),
    "curtailment.network_cost_eur_kwh": Field("num", 0.04, 0.0, 1.0, doc="grid fees, EUR/kWh"),
    "adaptive.target_precision": Field("num", 0.60, 0.3, 0.95, doc="alert precision to aim for"),
    "adaptive.enabled": Field("bool", True, doc="let feedback move the thresholds"),
}


def default_config() -> dict:
    return {
        "farm_name": "Unnamed farm",

        # -- API surface. Operator-only, all of it. ---------------------
        # Loopback by default: v1 bound 0.0.0.0 and handed the whole LAN a
        # login prompt. Remote access is a VPN's job, not a bind address's.
        "api": {
            "bind_host": "127.0.0.1",
            "api_port": 8787,
            "api_token": "",
            "cors_origins": [],           # exact origins; no wildcard is accepted
            "rate_limit": {
                "window_s": 60,
                "max_attempts": 120,
                "failure_threshold": 5,
                "base_block_s": 2,
                "max_block_s": 900,
            },
        },

        "miners": [],
        "poll_seconds": 60,

        "qtmp": {
            "window": 30, "epsilon": 0.15, "z_alert": 2.5, "z_critical": 4.0,
            "min_siblings": 3, "min_samples": 10, "persistence": 3,
            "family_wise": True, "fan_temp_alert": 2.0, "hw_err_slope_alert": 2.0,
        },

        "curtailment": {
            "enabled": True,
            "mode": "advisory",                  # advisory | webhook
            "hashrate_th": 100.0,
            "power_kw": 3.05,
            "hashprice_usd_th_day": 0.045,
            "eur_usd": 1.08,
            "margin": 0.05,
            "price_source": "fixed",             # fixed | url
            "price_url": "",                     # https, public address, operator-set
            "price_headers": {},
            "fixed_price_eur_kwh": 0.12,
            "network_cost_eur_kwh": 0.04,
            "webhooks": {},                      # {"S19-01": "http://192.168.1.50/relay?on="}
            "webhook_allowlist": [],             # hosts the agent may ever call
        },

        "billing": {
            "fee_bp": 2500,                      # basis points; 2500 = 25%
            "operator": "HashGuard",
            "payment_reference": "",
            "corroboration_margin_ppm": 1_250_000,
        },

        "adaptive": {
            "enabled": True, "target_precision": 0.60, "step": 0.15,
            "z_min": 1.5, "z_max": 6.0,
        },

        "paths": {
            "ledger_dir": "ledger",
            "log_dir": "logs",
            "device_key": "device_key.json",
            "state": "adaptive_state.json",
            "max_log_mb": 256,
        },
    }


class ConfigError(ValueError):
    """The configuration is not usable as given."""


def _get(config: dict, path: str) -> Any:
    node: Any = config
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _set(config: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    node = config
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _coerce(field: Field, value: Any, path: str) -> Any:
    if field.kind == "bool":
        if not isinstance(value, bool):
            raise ConfigError(f"{path}: expected true or false, got {value!r}")
        return value
    if field.kind in ("int", "num"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{path}: expected a number, got {value!r}")
        number = int(value) if field.kind == "int" else float(value)
        if number != number or number in (float("inf"), float("-inf")):
            raise ConfigError(f"{path}: must be finite")
        if field.minimum is not None and number < field.minimum:
            raise ConfigError(f"{path}: {number} is below the minimum {field.minimum}")
        if field.maximum is not None and number > field.maximum:
            raise ConfigError(f"{path}: {number} is above the maximum {field.maximum}")
        return number
    raise ConfigError(f"{path}: no coercion rule for {field.kind}")


def apply_console_patch(config: dict, patch: dict) -> tuple[list[str], list[str]]:
    """Apply the console-writable subset of ``patch`` to ``config`` in place.

    Returns ``(applied, rejected)``. Anything outside :data:`CONSOLE_WRITABLE` is
    rejected by name -- silently dropping it would leave the operator believing
    a setting took effect.
    """
    applied: list[str] = []
    rejected: list[str] = []
    for path, value in _flatten(patch):
        field = CONSOLE_WRITABLE.get(path)
        if field is None:
            rejected.append(f"{path}: not settable from the console (operator-only or unknown)")
            continue
        try:
            _set(config, path, _coerce(field, value, path))
            applied.append(path)
        except ConfigError as exc:
            rejected.append(str(exc))
    return applied, rejected


def _flatten(node: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                continue
            out.extend(_flatten(value, f"{prefix}.{key}" if prefix else key))
    else:
        out.append((prefix, node))
    return out


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _safe_relpath(path: str, label: str) -> str:
    """Refuse a path that escapes the working directory.

    ``log_dir: "../../etc"`` was a valid v1 configuration.
    """
    root = os.path.abspath(os.getcwd())
    resolved = os.path.abspath(os.path.join(root, path))
    if os.path.commonpath([root, resolved]) != root:
        raise ConfigError(f"{label}: {path!r} resolves outside the working directory")
    return path


def validate(config: dict) -> list[str]:
    """Return the list of problems. Empty means the config is safe to run."""
    problems: list[str] = []

    for path, field in CONSOLE_WRITABLE.items():
        value = _get(config, path)
        if value is None:
            continue
        try:
            _coerce(field, value, path)
        except ConfigError as exc:
            problems.append(str(exc))

    api = config.get("api", {})
    port = api.get("api_port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        problems.append(f"api.api_port: {port!r} is not a valid port")
    token = api.get("api_token", "")
    if token and len(token) < 24:
        problems.append("api.api_token: shorter than 24 characters; leave it empty to have one generated")
    origins = api.get("cors_origins", [])
    if not isinstance(origins, list):
        problems.append("api.cors_origins: must be a list of exact origins")
    elif "*" in origins:
        problems.append(
            "api.cors_origins: '*' is refused. v1 shipped a wildcard by default, which lets any "
            "page a browser loads reach the agent. List the exact console origin instead."
        )
    if api.get("bind_host") not in (None, "127.0.0.1", "::1", "localhost") and not config.get(
        "api", {}
    ).get("i_understand_non_loopback_bind"):
        problems.append(
            f"api.bind_host: binding {api.get('bind_host')!r} exposes the agent beyond this machine. "
            "Use a VPN and keep the bind on loopback, or set api.i_understand_non_loopback_bind: true "
            "to state that you meant it."
        )

    curtailment = config.get("curtailment", {})
    if curtailment.get("mode") not in ("advisory", "webhook"):
        problems.append(f"curtailment.mode: {curtailment.get('mode')!r} is not advisory or webhook")
    if curtailment.get("price_source") not in ("fixed", "url"):
        problems.append(f"curtailment.price_source: {curtailment.get('price_source')!r} is not fixed or url")
    if curtailment.get("price_source") == "url" and not str(curtailment.get("price_url", "")).startswith("https://"):
        problems.append("curtailment.price_url: must be an https:// URL when price_source is 'url'")
    allowlist = curtailment.get("webhook_allowlist", [])
    if not isinstance(allowlist, list):
        problems.append("curtailment.webhook_allowlist: must be a list of hostnames")
    if curtailment.get("mode") == "webhook" and not allowlist:
        problems.append(
            "curtailment.mode is 'webhook' but webhook_allowlist is empty: the agent will refuse "
            "every relay call. List the hosts it is allowed to reach."
        )

    fee_bp = config.get("billing", {}).get("fee_bp")
    if not isinstance(fee_bp, int) or not 0 <= fee_bp <= 10_000:
        problems.append(f"billing.fee_bp: {fee_bp!r} is not basis points within 0..10000")

    poll = config.get("poll_seconds")
    if not isinstance(poll, int) or not 5 <= poll <= 3600:
        problems.append(f"poll_seconds: {poll!r} is outside 5..3600")

    for key, label in (("ledger_dir", "paths.ledger_dir"), ("log_dir", "paths.log_dir")):
        value = config.get("paths", {}).get(key)
        if not isinstance(value, str) or not value:
            problems.append(f"{label}: must be a non-empty relative path")
            continue
        try:
            _safe_relpath(value, label)
        except ConfigError as exc:
            problems.append(str(exc))

    seen = set()
    for miner in config.get("miners", []):
        if not isinstance(miner, dict) or not miner.get("name") or not miner.get("host"):
            problems.append(f"miners: every entry needs a name and a host, got {miner!r}")
            continue
        if miner["name"] in seen:
            problems.append(f"miners: duplicate name {miner['name']!r}; names index the ledger and must be unique")
        seen.add(miner["name"])
        miner_port = miner.get("port", 4028)
        if not isinstance(miner_port, int) or not 1 <= miner_port <= 65535:
            problems.append(f"miners[{miner['name']}].port: {miner_port!r} is not a valid port")

    return problems


def save(config: dict, path: str = CONFIG_PATH) -> None:
    """Write ``0600``: the file holds the API token."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, ensure_ascii=False, sort_keys=True)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover
        pass


def load(path: str = CONFIG_PATH) -> dict:
    """Load, merge over defaults, mint a token if needed, and refuse to run
    on an invalid configuration rather than starting in a state nobody meant."""
    config = default_config()
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as handle:
                config = _deep_merge(config, json.load(handle))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc
    minted = False
    if not config["api"]["api_token"]:
        config["api"]["api_token"] = secrets.token_urlsafe(32)
        minted = True
    problems = validate(config)
    if problems:
        raise ConfigError(
            "configuration refused:\n  - " + "\n  - ".join(problems)
        )
    if minted:
        save(config, path)
        print("[security] A new API token was generated and stored in", path)
        print("[security] Paste it into the console once:")
        print("           " + config["api"]["api_token"])
    return config
