"""The agent's HTTP API. Small surface, and every edge of it defended.

The threat model is stated plainly: this server sits on a machine inside the
farm, listening on loopback by default, and everything that reaches it is
untrusted until a token says otherwise. The console is a static page that could
be served from anywhere, so it gets no more trust than any other origin.

What changed from v1, and why:

* **Loopback bind by default.** v1 bound ``0.0.0.0`` and offered the whole LAN
  a login prompt. Remote access is a VPN's job.
* **No wildcard CORS.** v1 shipped ``Access-Control-Allow-Origin: *``, so any
  page in the operator's browser could reach the agent and start guessing
  tokens from inside the network. v2 echoes an origin only if it is on an
  explicit list, and refuses to start with ``*`` on that list.
* **Rate limiting with progressive blocking.** v1 attached no cost to a wrong
  token. v2 makes the tenth wrong guess wait, and the twentieth wait a lot longer.
* **Bounded bodies.** v1 did ``self.rfile.read(int(Content-Length))`` with no
  cap and no error handling, so a header was enough to allocate arbitrary memory
  or crash the handler.
* **A narrow, typed write surface.** ``POST /config`` used to deep-merge
  anything into the live config. Now it accepts only the calibration knobs, in
  their declared ranges, and names whatever it rejected.
* **Secrets never leave.** ``GET /config`` redacts the token, the price-feed
  headers and the webhook URLs -- v1 redacted only the token and handed out the
  rest to anyone holding it.
"""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import CONSOLE_WRITABLE, apply_console_patch, save as save_config
from .ratelimit import RateLimiter

#: A config patch is a handful of numbers. Nothing legitimate is bigger.
MAX_BODY_BYTES = 64 * 1024

SECURITY_HEADERS = {
    # The API returns JSON only. These make a stray HTML response inert.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class AgentState:
    """Everything the request handlers are allowed to see."""

    def __init__(self, config: dict, engine, curtailment, ledger, adaptive, identity) -> None:
        self.config = config
        self.engine = engine
        self.curtailment = curtailment
        self.ledger = ledger
        self.adaptive = adaptive
        self.identity = identity
        self.snapshot: dict = {}
        self.last_poll: str | None = None
        self.history: list[dict] = []
        self.baseline_gh: int | None = None
        self.observed_gh: int | None = None
        self.notes: list[str] = []
        self.lock = threading.RLock()
        limits = config["api"]["rate_limit"]
        self.limiter = RateLimiter(
            window_s=float(limits["window_s"]),
            max_attempts=int(limits["max_attempts"]),
            failure_threshold=int(limits["failure_threshold"]),
            base_block_s=float(limits["base_block_s"]),
            max_block_s=float(limits["max_block_s"]),
        )


def redacted_config(config: dict) -> dict:
    """The configuration as the console is allowed to see it.

    A token holder is not automatically entitled to the *other* secrets on the
    machine: the price-feed API key lives in ``price_headers`` and the webhook
    URLs describe the farm's internal topology.
    """
    import copy

    view = copy.deepcopy(config)
    view["api"]["api_token"] = "***"
    view["curtailment"]["price_headers"] = {
        key: "***" for key in view["curtailment"].get("price_headers", {})
    }
    view["curtailment"]["webhooks"] = {
        name: "***" for name in view["curtailment"].get("webhooks", {})
    }
    view["_writable_from_console"] = sorted(CONSOLE_WRITABLE)
    return view


def make_handler(state: AgentState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "HashGuard"
        sys_version = ""            # do not advertise the Python version
        timeout = 15                # a stalled connection is not a free thread

        # -- plumbing ---------------------------------------------------

        @property
        def _origins(self) -> list[str]:
            return state.config["api"].get("cors_origins", []) or []

        def _client_key(self) -> str:
            return f"ip:{self.client_address[0]}"

        def _token_key(self) -> str:
            from .canonical import sha256d

            presented = self.headers.get("X-HashGuard-Token", "")
            return "tok:" + sha256d(presented.encode("utf-8", "replace")).hex()[:16]

        def _send(self, code: int, payload: dict, extra_headers: dict | None = None) -> None:
            # 204 means "no content", and under HTTP/1.1 a body here desynchronises
            # the connection for every request that follows on it.
            body = b"" if code == 204 else json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            if code != 204:
                # A 204 carries neither a body nor a Content-Length.
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
            if self.close_connection:
                # Say so, rather than dropping a socket the client still thinks
                # it can reuse. Set before the refusals that never read a body.
                self.send_header("Connection", "close")
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            origin = self.headers.get("Origin")
            if origin and origin in self._origins:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Headers", "X-HashGuard-Token, Content-Type")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Max-Age", "600")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

        def _authorized(self) -> bool:
            """Rate limit first, then compare in constant time.

            Order matters: checking the token first and rate limiting after
            would let an attacker measure the difference.
            """
            keys = [self._client_key(), self._token_key()]
            # Refusing a POST leaves its body unread, so the connection cannot be
            # reused for the next request on it.
            if self.command == "POST":
                self.close_connection = True
            decision = state.limiter.consume(keys)
            if not decision.allowed:
                self._send(
                    429,
                    {"error": "too many requests", "detail": decision.reason},
                    {"Retry-After": str(decision.retry_after)},
                )
                return False
            presented = self.headers.get("X-HashGuard-Token", "")
            expected = state.config["api"]["api_token"]
            if not secrets.compare_digest(presented, expected):
                blocked = state.limiter.failed(keys)
                self._send(
                    401,
                    {
                        "error": "invalid token",
                        "detail": (
                            f"repeated failures are now blocked for {blocked:.0f}s"
                            if blocked
                            else "check the token the agent printed at startup"
                        ),
                    },
                )
                return False
            state.limiter.succeeded(keys)
            self.close_connection = False
            return True

        def _origin_allowed_for_write(self) -> bool:
            """A cross-origin write needs a listed origin.

            The custom token header already forces a preflight, so a form post
            from a hostile page cannot reach here. This is the second lock.
            """
            origin = self.headers.get("Origin")
            return origin is None or origin in self._origins

        def _read_body(self) -> dict | None:
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                # The body is never read in this branch, so the connection can no
                # longer be reused: close it rather than desynchronise it.
                self.close_connection = True
                self._send(400, {"error": "Content-Length is not a number"})
                return None
            if length < 0 or length > MAX_BODY_BYTES:
                self.close_connection = True
                self._send(413, {"error": f"body must be 0..{MAX_BODY_BYTES} bytes"})
                return None
            try:
                raw = self.rfile.read(length) if length else b"{}"
                data = json.loads(raw or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                self._send(400, {"error": "body is not valid JSON"})
                return None
            if not isinstance(data, dict):
                self._send(400, {"error": "body must be a JSON object"})
                return None
            return data

        def _route(self) -> str:
            return self.path.split("?", 1)[0].rstrip("/") or "/"

        # -- methods ----------------------------------------------------

        def do_OPTIONS(self) -> None:
            self._send(204, {})

        def do_GET(self) -> None:
            if not self._authorized():
                return
            route = self._route()
            with state.lock:
                if route == "/status":
                    return self._send(200, self._status())
                if route == "/config":
                    return self._send(200, redacted_config(state.config))
                if route == "/history":
                    return self._send(200, {"history": state.history[-288:]})
                if route == "/savings":
                    return self._send(200, self._savings())
                if route == "/ledger/seals":
                    return self._send(200, {"seals": state.ledger.seals()[-62:]})
                if route == "/identity":
                    return self._send(200, state.identity.public())
            self._send(404, {"error": "unknown route"})

        def do_POST(self) -> None:
            if not self._authorized():
                return
            if not self._origin_allowed_for_write():
                return self._send(403, {"error": "origin not allowed to write"})
            data = self._read_body()
            if data is None:
                return
            route = self._route()
            with state.lock:
                if route == "/config":
                    applied, rejected = apply_console_patch(state.config, data)
                    if applied:
                        save_config(state.config)
                    return self._send(
                        200 if not rejected else 207,
                        {"applied": applied, "rejected": rejected},
                    )
                if route == "/feedback":
                    return self._send(*self._feedback(data))
                if route == "/ledger/seal":
                    sealed = state.ledger.seal_pending()
                    return self._send(200, {"sealed": [s["day"] for s in sealed]})
            self._send(404, {"error": "unknown route"})

        # -- payloads ---------------------------------------------------

        def _status(self) -> dict:
            return {
                "farm": state.config["farm_name"],
                "ts": state.last_poll,
                "curtailment": state.curtailment.decision,
                "breakeven_ppm_per_kwh": state.curtailment.breakeven_ppm(),
                "prices_ppm": state.curtailment.prices_ppm,
                "miners": state.snapshot,
                "alerts": list(state.engine.alerts),
                "thresholds": state.config["qtmp"],
                "adaptive": state.adaptive.state,
                "telemetry": {
                    "baseline_gh": state.baseline_gh,
                    "observed_gh": state.observed_gh,
                },
                "notes": state.notes[-10:],
                "device": state.identity.public(),
                "mode": state.config["curtailment"]["mode"],
            }

        def _savings(self) -> dict:
            from datetime import date

            month = self.path.split("month=", 1)[1][:7] if "month=" in self.path else date.today().strftime("%Y-%m")
            if len(month) != 7 or month[4] != "-" or not month.replace("-", "").isdigit():
                month = date.today().strftime("%Y-%m")
            statement = state.ledger.statement(month)
            statement["mode"] = state.config["curtailment"]["mode"]
            statement["note"] = (
                "advisory mode: these savings are potential and are not billed"
                if state.config["curtailment"]["mode"] == "advisory"
                else "executed pauses, capped at what the telemetry corroborates"
            )
            return statement

        def _feedback(self, data: dict) -> tuple[int, dict]:
            alert_id = data.get("alert_id")
            real = bool(data.get("real"))
            if not isinstance(alert_id, str) or len(alert_id) > 64:
                return 400, {"error": "alert_id must be a short string"}
            for alert in state.engine.alerts:
                if alert["id"] == alert_id:
                    if not alert.get("open", True):
                        return 409, {"error": "this alert was already resolved"}
                    alert["feedback"] = "real" if real else "false"
                    alert["open"] = False
                    result = state.adaptive.feedback(alert["metric"], real)
                    return 200, {"ok": True, "adaptive": result}
            return 404, {"error": "alert not found"}

        def log_message(self, fmt: str, *args) -> None:
            """One line per request, with no token and no request body in it."""
            print(f"[api] {self.client_address[0]} {self.command} {self._route()} {fmt % args}")

    return Handler


def serve(state: AgentState) -> ThreadingHTTPServer:
    api = state.config["api"]
    server = ThreadingHTTPServer((api["bind_host"], int(api["api_port"])), make_handler(state))
    server.daemon_threads = True
    return server
