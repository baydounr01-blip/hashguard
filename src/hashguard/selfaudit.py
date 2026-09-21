"""The audit, run against the running thing rather than read off the page.

``docs/AUDIT_v1.md`` lists what HashGuard v1 got wrong and what v2 does instead.
A document is a claim. A test suite is better, but it runs against fixtures the
same people wrote. Neither answers the question an operator actually has six
months after installation: *is this defence still standing on this machine, in
this configuration, in this build?*

So this module re-runs the audit. It starts the agent's own API in-process on
``127.0.0.1:0``, attacks it the way the v1 findings were found -- a hostile
Origin, a metadata-service URL, a config patch aimed at the fee, a lie in
``Content-Length``, wrong tokens until the door shuts -- and reports one verdict
per finding. It also checks the things that are not requests: file permissions,
token entropy, what the console page is allowed to execute, and whether this
build matches a published digest.

Three verdicts, and the third is the point:

* ``PASS``   -- the probe ran and the defence held.
* ``FAIL``   -- the probe ran and the defence did not hold.
* ``NOT CHECKED`` -- the probe could not run here. Printed in amber, never
  folded into PASS, and counted as a failure under ``--strict``. A comparison
  that could not be made is not a comparison that passed; RAMI-Chain's panel
  makes the same distinction for its binary digests and it is the honest one.

What this never does: touch a relay, seal a day, write to the ledger, or read a
miner. Its one outbound request is the release-digest lookup, and that goes
through :mod:`hashguard.netguard` under exactly the rules a price feed gets.
Mining is not in its path and neither is billing.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from http.server import ThreadingHTTPServer

from .api import AgentState, make_handler

PASS = "PASS"
FAIL = "FAIL"
NOT_CHECKED = "NOT CHECKED"

#: Anything under these and the token is guessable in a way a rate limiter only
#: slows down. ``secrets.token_urlsafe(32)`` -- 43 characters over 64 symbols --
#: clears all three by a wide margin.
MIN_TOKEN_BITS = 128
MIN_TOKEN_LENGTH = 24
MIN_TOKEN_DISTINCT = 16


class NotChecked(Exception):
    """This probe could not run here, and says so rather than guessing.

    Raised for a *gap in the environment* -- no ledger yet, no ``web/``
    directory in an installed wheel, no published digest for this version.
    Never for a defence that answered wrongly: that is a :data:`FAIL`.
    """


@dataclass(frozen=True)
class Check:
    """One line of the report: a judgement, and the fact behind it."""

    finding: str
    claim: str
    verdict: str
    observed: str
    ms: int

    def as_dict(self) -> dict:
        return {
            "finding": self.finding,
            "claim": self.claim,
            "verdict": self.verdict,
            "observed": self.observed,
            "ms": self.ms,
        }


# ---------------------------------------------------------------------------
# The probe harness
# ---------------------------------------------------------------------------


class _Target:
    """A throwaway copy of the agent, served on loopback, port zero.

    It shares the identity and the ledger with the real agent -- those are read
    only here -- and gets a *deep copy* of the configuration, so that a probe
    aimed at the write surface cannot reach the live settings even if the write
    surface is the thing that has regressed.

    Its rate limiter is its own. That matters: the last probe deliberately
    trips the limiter against the audit's own source address, and doing that to
    the running agent would lock the operator out of their own console.
    """

    def __init__(self, state: AgentState) -> None:
        self.config = copy.deepcopy(state.config)
        self.token = self.config["api"]["api_token"]
        self.state = AgentState(
            config=self.config,
            engine=state.engine,
            curtailment=state.curtailment,
            ledger=state.ledger,
            adaptive=state.adaptive,
            identity=state.identity,
        )
        self.state.snapshot = state.snapshot
        self.state.open_interval = state.open_interval
        base = make_handler(self.state)

        class Quiet(base):  # type: ignore[valid-type,misc]
            """The report is the output. A probe's own access log is not."""

            def log_message(self, fmt: str, *args) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        self.server.daemon_threads = True
        self.host, self.port = self.server.server_address[0], self.server.server_address[1]
        self._thread = None

    def __enter__(self) -> "_Target":
        import threading

        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    # -- requests -------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        token: str | None = None,
        origin: str | None = None,
    ) -> tuple[int, dict, dict]:
        """One request. Returns ``(status, headers, parsed body)``."""
        import http.client

        payload = b"" if body is None else json.dumps(body).encode("utf-8")
        headers = {"X-HashGuard-Token": self.token if token is None else token}
        if origin is not None:
            headers["Origin"] = origin
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(payload))
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            connection.request(method, path, body=payload or None, headers=headers)
            response = connection.getresponse()
            raw = response.read(1024 * 1024)
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {}
            return response.status, dict(response.getheaders()), parsed
        finally:
            connection.close()

    def raw(self, request_bytes: bytes) -> str:
        """Send bytes that no HTTP client would produce, and read the status line."""
        sock = socket.create_connection((self.host, self.port), timeout=10)
        try:
            sock.sendall(request_bytes)
            sock.settimeout(10)
            head = b""
            while b"\r\n" not in head and len(head) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                head += chunk
            return head.split(b"\r\n", 1)[0].decode("latin-1")
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# The probes, one per finding
# ---------------------------------------------------------------------------


def _audit_01_cors(target: _Target) -> str:
    from .config import default_config, validate

    status, headers, _ = target.request("GET", "/status", origin="https://evil.example")
    echoed = headers.get("Access-Control-Allow-Origin")
    if echoed is not None:
        raise AssertionError(f"an unlisted origin was echoed back as {echoed!r}")
    wildcard = default_config()
    wildcard["api"]["cors_origins"] = ["*"]
    problems = [p for p in validate(wildcard) if p.startswith("api.cors_origins")]
    if not problems:
        raise AssertionError("a configuration listing '*' as an origin was accepted")
    return (
        f"Origin https://evil.example got HTTP {status} with no Access-Control-Allow-Origin; "
        "a config listing '*' is refused by validate()"
    )


def _audit_02_ssrf(target: _Target) -> str:
    from .netguard import NetGuardError, fetch_public_json

    status, _, body = target.request(
        "POST", "/config", {"curtailment": {"price_url": "http://169.254.169.254/latest/meta-data/"}}
    )
    rejected = " ".join(body.get("rejected", []))
    if body.get("applied") or "curtailment.price_url" not in rejected:
        raise AssertionError(f"the console was able to set a price URL: {body!r}")
    try:
        fetch_public_json("https://169.254.169.254/latest/meta-data/")
    except NetGuardError as exc:
        refusal = str(exc)
    else:
        raise AssertionError("the guard fetched the cloud metadata service")
    return (
        f"POST /config answered {status} and named curtailment.price_url; "
        f"the guard refused the metadata address itself: {refusal[:90]}"
    )


def _audit_03_relays(target: _Target) -> str:
    from .netguard import NetGuardError, validate_webhook

    status, _, body = target.request(
        "POST", "/config", {"curtailment": {"webhooks": {"S19-01": "http://192.168.1.1/admin"}}}
    )
    rejected = " ".join(body.get("rejected", []))
    if body.get("applied") or "curtailment.webhooks" not in rejected:
        raise AssertionError(f"the console was able to set a webhook: {body!r}")
    try:
        validate_webhook("http://8.8.8.8/relay", ["8.8.8.8"])
    except NetGuardError as exc:
        refusal = str(exc)
    else:
        raise AssertionError("an allowlisted *public* address was accepted as a relay")
    return (
        f"POST /config answered {status} and named curtailment.webhooks; an allowlisted "
        f"public address is still refused: {refusal[:90]}"
    )


def _audit_04_write_surface(target: _Target) -> str:
    before = copy.deepcopy(target.config)
    status, _, body = target.request(
        "POST",
        "/config",
        {
            "billing": {"fee_bp": 9_000},
            "api": {"api_token": "attacker-chosen-token-000000000000"},
            "paths": {"log_dir": "/tmp/anywhere"},
        },
    )
    rejected = " ".join(body.get("rejected", []))
    missing = [
        path
        for path in ("billing.fee_bp", "api.api_token", "paths.log_dir")
        if path not in rejected
    ]
    if missing:
        raise AssertionError(f"the console write surface now accepts {missing}: {body!r}")
    if body.get("applied"):
        raise AssertionError(f"something in that patch was applied: {body['applied']}")
    if target.config != before:
        raise AssertionError("the configuration changed under a patch that was reported rejected")
    return (
        f"HTTP {status}; billing.fee_bp, api.api_token and paths.log_dir each rejected by name, "
        "nothing applied, configuration unchanged"
    )


def _audit_05_ledger(target: _Target) -> str:
    from .ledger import verify_chain, verify_seal

    ledger = target.state.ledger
    days = ledger.days()
    records = [r for day in days for r in ledger.day_records(day)]
    if not records:
        raise NotChecked("this ledger holds no records yet; there is nothing to verify or break")
    ok, reason = verify_chain(records)
    if not ok:
        raise AssertionError(f"the real ledger does not verify: {reason}")

    public = target.state.identity.public()
    seals = ledger.seals()
    for seal in seals:
        sealed_ok, sealed_reason = verify_seal(
            seal, ledger.day_records(seal["day"]), public, ledger.activated_from
        )
        if not sealed_ok:
            raise AssertionError(f"seal {seal['day']} does not verify: {sealed_reason}")

    # Now break a copy and require the same code to notice. Verifying a good
    # ledger proves nothing on its own -- a function that returns True always
    # would pass that half.
    if seals:
        seal = seals[0]
        tampered = copy.deepcopy(ledger.day_records(seal["day"]))
        tampered[0]["claimed_wh"] = int(tampered[0].get("claimed_wh", 0)) + 1
        broke, why = verify_seal(seal, tampered, public, ledger.activated_from)
        where = f"seal {seal['day']}"
    elif len(records) >= 2:
        tampered = copy.deepcopy(records)
        tampered[0]["claimed_wh"] = int(tampered[0].get("claimed_wh", 0)) + 1
        broke, why = verify_chain(tampered)
        where = f"the chain of {len(records)} records"
    else:
        raise NotChecked(
            f"this ledger holds {len(records)} record and no seal; there is nothing to break yet"
        )
    if broke:
        raise AssertionError(f"one Wh was added to a record and {where} still verified")
    return (
        f"{len(records)} records over {len(days)} days chain and {len(seals)} seals verify; "
        f"adding one Wh to a record breaks {where}: {why[:70]}"
    )


def _audit_07_redaction(target: _Target) -> str:
    status, _, body = target.request("GET", "/config")
    blob = json.dumps(body)
    if target.token and target.token in blob:
        raise AssertionError("GET /config returned the API token in clear")
    if body.get("api", {}).get("api_token") != "***":
        raise AssertionError("api.api_token is not redacted")
    for key, value in body.get("curtailment", {}).get("price_headers", {}).items():
        if value != "***":
            raise AssertionError(f"curtailment.price_headers[{key}] is not redacted")
    for name, value in body.get("curtailment", {}).get("webhooks", {}).items():
        if value != "***":
            raise AssertionError(f"curtailment.webhooks[{name}] is not redacted")
    return (
        f"HTTP {status}; the token does not appear in the response, and the price headers "
        f"({len(body.get('curtailment', {}).get('price_headers', {}))}) and webhook URLs "
        f"({len(body.get('curtailment', {}).get('webhooks', {}))}) come back as '***'"
    )


def _audit_08_traversal(target: _Target) -> str:
    from .config import default_config, validate

    status, _, body = target.request("POST", "/config", {"paths": {"log_dir": "../../etc"}})
    if body.get("applied") or "paths.log_dir" not in " ".join(body.get("rejected", [])):
        raise AssertionError(f"the console was able to move the log directory: {body!r}")
    escaping = default_config()
    escaping["paths"]["log_dir"] = "../../etc"
    problems = [p for p in validate(escaping) if p.startswith("paths.log_dir")]
    if not problems:
        raise AssertionError("a config whose log_dir escapes the working directory was accepted")
    return (
        f"HTTP {status}; paths.log_dir rejected by name, and validate() refuses it on disk too: "
        f"{problems[0][:80]}"
    )


def _audit_09_bounded_body(target: _Target) -> str:
    from .api import MAX_BODY_BYTES

    oversized = target.raw(
        f"POST /config HTTP/1.1\r\nHost: {target.host}\r\n"
        f"X-HashGuard-Token: {target.token}\r\n"
        f"Content-Length: {MAX_BODY_BYTES * 2}\r\n\r\n".encode("ascii")
    )
    if " 413" not in oversized:
        raise AssertionError(f"a body of {MAX_BODY_BYTES * 2} bytes was not refused: {oversized!r}")
    nonsense = target.raw(
        f"POST /config HTTP/1.1\r\nHost: {target.host}\r\n"
        f"X-HashGuard-Token: {target.token}\r\n"
        "Content-Length: abc\r\n\r\n".encode("ascii")
    )
    if " 400" not in nonsense:
        raise AssertionError(f"a non-numeric Content-Length was not refused: {nonsense!r}")
    return (
        f"Content-Length {MAX_BODY_BYTES * 2} -> {oversized.strip()}; "
        f"Content-Length 'abc' -> {nonsense.strip()}; neither body was ever read"
    )


def _audit_10_miner_socket(target: _Target) -> str:
    import threading

    from .collector import MAX_BOARDS, MAX_RESPONSE_BYTES, cgminer_command, parse_stats

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    flood = MAX_RESPONSE_BYTES + 64 * 1024

    def talk_forever() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            conn.recv(4096)
            sent = 0
            while sent < flood:
                conn.sendall(b"x" * 8192)
                sent += 8192
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    thread = threading.Thread(target=talk_forever, daemon=True)
    thread.start()
    try:
        answer = cgminer_command("127.0.0.1", listener.getsockname()[1], "stats", timeout=5.0)
    finally:
        try:
            listener.close()
        except OSError:
            pass
        thread.join(timeout=5)
    if answer is not None:
        raise AssertionError("a miner that sent more than the cap was still parsed")

    many = {"STATS": [{f"chain_rate{i}": "100.0" for i in range(1, 501)}]}
    parsed = parse_stats(many)
    boards = len((parsed or {}).get("boards", []))
    if boards > MAX_BOARDS:
        raise AssertionError(f"a response declaring 500 boards produced {boards}")
    return (
        f"a listener streaming {flood // 1024} KB was read as None (cap "
        f"{MAX_RESPONSE_BYTES // 1024} KB); a response declaring 500 boards produced {boards} "
        f"(cap {MAX_BOARDS})"
    )


def _audit_11_xss(target: _Target) -> str:
    root = _repo_root()
    script = os.path.join(root, "web", "console.js") if root else None
    page = os.path.join(root, "web", "console.html") if root else None
    if not script or not os.path.exists(script) or not os.path.exists(page):
        raise NotChecked(
            "the web/ directory is not next to this installation, so the console page "
            "this agent is actually served with could not be read"
        )
    js = _read_text(script)
    offenders = [
        line.strip()[:60]
        for line in js.splitlines()
        if re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write", line)
    ]
    if offenders:
        raise AssertionError(f"console.js writes HTML from a string: {offenders[0]}")
    html = _read_text(page)
    # The policy is written across several lines and its own directives contain
    # single quotes ('self'), so the closing quote is the one that opened the
    # attribute and nothing else: match it back, do not guess.
    policy = re.search(
        r'http-equiv=(["\'])Content-Security-Policy\1[^>]*?content=(["\'])(.*?)\2',
        html,
        re.IGNORECASE | re.DOTALL,
    )
    if not policy:
        raise AssertionError("console.html carries no Content-Security-Policy")
    directives = " ".join(policy.group(3).split())
    if "script-src 'self'" not in directives:
        raise AssertionError(f"the CSP does not restrict scripts to 'self': {directives}")
    if "'unsafe-inline'" in directives or "'unsafe-eval'" in directives:
        raise AssertionError(f"the CSP allows inline or eval'd script: {directives}")
    inline = [
        block
        for block in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.DOTALL)
        if block.strip()
    ]
    if inline:
        raise AssertionError(f"console.html carries {len(inline)} inline script block(s)")
    return (
        f"console.js ({len(js.splitlines())} lines) never assigns HTML from a string; "
        "console.html restricts script-src to 'self' with no inline block"
    )


def _audit_12_bind(target: _Target) -> str:
    from .config import default_config, validate

    exposed = default_config()
    exposed["api"]["bind_host"] = "0.0.0.0"
    problems = [p for p in validate(exposed) if p.startswith("api.bind_host")]
    if not problems:
        raise AssertionError("binding 0.0.0.0 was accepted with no acknowledgement")
    bind = target.config["api"].get("bind_host")
    if bind not in ("127.0.0.1", "::1", "localhost"):
        raise NotChecked(
            f"this agent is configured to bind {bind!r} with "
            "api.i_understand_non_loopback_bind set. The default holds, but the operator "
            "has turned this defence off deliberately, so it is not being checked here"
        )
    return (
        f"this agent binds {bind}; the audit's own server answered on {target.host}; "
        f"validate() refuses 0.0.0.0 without an explicit acknowledgement: {problems[0][:70]}"
    )


def _audit_14_permissions(target: _Target, config_path: str) -> str:
    paths = [(config_path, "the configuration")]
    key_path = target.config.get("paths", {}).get("device_key")
    if key_path:
        paths.append((key_path, "the device key"))
    seen = []
    for path, label in paths:
        if not os.path.exists(path):
            raise NotChecked(f"{label} is not at {path!r} on this machine, so it was not stat'ed")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            raise AssertionError(
                f"{label} at {path} is {oct(mode)}: readable beyond its owner. "
                f"Run: chmod 600 {path}"
            )
        seen.append(f"{path} {oct(mode)}")
    return "; ".join(seen) + " -- owner only"


def _token_entropy(target: _Target) -> str:
    """What can honestly be measured about a token: its shape.

    Nothing here can tell how a token was *chosen*. What it can tell is that a
    string is too short, drawn from too small an alphabet, built of too few
    distinct characters, or a short pattern repeated -- and each of those is a
    token an attacker guesses rather than brute-forces. A passphrase that reads
    like a password but clears all four would pass, and the report says so
    instead of implying a strength measurement that was never taken.
    """
    token = target.config["api"].get("api_token", "")
    if not token:
        raise AssertionError("no API token is configured: the API would accept an empty header")
    advice = "Delete api.api_token from config.json and let the agent mint one."
    if len(token) < MIN_TOKEN_LENGTH:
        raise AssertionError(
            f"the token is {len(token)} characters; this design assumes at least "
            f"{MIN_TOKEN_LENGTH}. {advice}"
        )
    alphabet = 0
    for pattern, size in ((r"[a-z]", 26), (r"[A-Z]", 26), (r"[0-9]", 10), (r"[-_]", 2)):
        if re.search(pattern, token):
            alphabet += size
    alphabet += len(set(re.sub(r"[A-Za-z0-9_\-]", "", token)))
    bits = int(len(token) * math.log2(alphabet)) if alphabet > 1 else 0
    if bits < MIN_TOKEN_BITS:
        raise AssertionError(
            f"{len(token)} characters over an alphabet of {alphabet} is about {bits} bits, "
            f"below the {MIN_TOKEN_BITS} this design assumes. {advice}"
        )
    distinct = len(set(token))
    if distinct < MIN_TOKEN_DISTINCT:
        raise AssertionError(
            f"the token uses {distinct} distinct characters across {len(token)}: that is a "
            f"pattern, not a random string, whatever its length. {advice}"
        )
    for period in range(1, len(token) // 2 + 1):
        if token == (token[:period] * (len(token) // period + 1))[: len(token)]:
            raise AssertionError(
                f"the token is {token[:period]!r} repeated: its real strength is "
                f"{period} characters, not {len(token)}. {advice}"
            )
    return (
        f"{len(token)} characters over an alphabet of {alphabet} (about {bits} bits by shape), "
        f"{distinct} distinct, no repeating period. Shape is all this can measure: how the "
        "token was chosen is not visible from here"
    )


_DEGRADED_BANNER_PROBE = r"""
import os, sys, tempfile

class _NoCryptography:
    def find_spec(self, name, path=None, target=None):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("blocked by hashguard --self-audit")
        return None

sys.meta_path.insert(0, _NoCryptography())

from hashguard.agent import banner_lines, build_state
from hashguard.config import default_config
from hashguard.identity import HAVE_ED25519, DeviceIdentity

if HAVE_ED25519:
    print("BLOCKER-FAILED: hashguard.identity still found ed25519")
    raise SystemExit(1)

scratch = tempfile.mkdtemp(prefix="hashguard-selfaudit-")
config = default_config()
config["paths"]["ledger_dir"] = os.path.join(scratch, "ledger")
config["paths"]["state"] = os.path.join(scratch, "adaptive.json")
identity = DeviceIdentity.generate()
state = build_state(config, identity)
print("\n".join(banner_lines(config, identity, state)))
print("ALGORITHM:" + identity.algorithm)
"""


def _degradation_is_announced(target: _Target) -> str:
    """With ``cryptography`` gone, does the agent still *say* what it lost?

    The fallback itself is covered by the test suite. What is checked here is
    the sentence: an agent that quietly signs with HMAC and prints the same
    banner as an ed25519 one is a degradation in disguise, which is the single
    thing this project has said it will not do.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-c", _DEGRADED_BANNER_PROBE],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NotChecked(f"could not start a second interpreter to check this: {exc}") from exc
    output = result.stdout + result.stderr
    if "BLOCKER-FAILED" in output:
        raise NotChecked("cryptography could not be hidden from the child interpreter")
    if result.returncode != 0:
        raise AssertionError(
            f"the agent could not build its banner without cryptography (exit "
            f"{result.returncode}): {output.strip()[-200:]}"
        )
    if "ALGORITHM:hmac-sha256" not in output:
        raise AssertionError(f"the fallback did not select hmac-sha256: {output.strip()[-200:]}")
    missing = [
        phrase
        for phrase in ("hmac-sha256", "install 'cryptography'")
        if phrase not in output
    ]
    if missing:
        raise AssertionError(
            f"the startup banner does not mention {missing} when signatures are downgraded"
        )
    return (
        "with cryptography blocked, a second interpreter selected hmac-sha256 and its banner "
        "says so and names what to install"
    )


# ---------------------------------------------------------------------------
# This build against a published digest
# ---------------------------------------------------------------------------


def package_digest(package_dir: str | None = None) -> tuple[str, int]:
    """SHA-256 over the installed package's source, and the file count.

    Every ``.py`` file under the package directory, in sorted relative-path
    order, each fed in as ``path`` ``NUL`` ``length`` ``NUL`` ``bytes`` so that
    renaming a file or moving a byte across a boundary changes the digest.
    """
    import hashlib

    root = package_dir or os.path.dirname(os.path.abspath(__file__))
    files = []
    for directory, _, names in os.walk(root):
        if "__pycache__" in directory:
            continue
        for name in names:
            if name.endswith(".py"):
                full = os.path.join(directory, name)
                files.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    digest = hashlib.sha256()
    for relative, full in sorted(files):
        with open(full, "rb") as handle:
            blob = handle.read()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(len(blob)).encode("ascii"))
        digest.update(b"\x00")
        digest.update(blob)
    return digest.hexdigest(), len(files)


def digest_line(version: str, package_dir: str | None = None) -> str:
    """The line a release publishes, in the shape ``sha256sum`` writes."""
    value, _ = package_digest(package_dir)
    return f"{value}  hashguard-{version}-package"


def _build_matches_published(target: _Target, sums_url: str | None) -> str:
    from . import __version__
    from .netguard import NetGuardError, fetch_public_bytes

    value, count = package_digest()
    expected_name = f"hashguard-{__version__}-package"
    if not sums_url:
        raise NotChecked(
            f"this build is {value[:16]}... over {count} files, and nothing was compared with "
            "it: no published digest was given (--release-sums URL). Until a release publishes "
            "SHA256SUMS, an operator cannot tell this build from a modified one"
        )
    try:
        body = fetch_public_bytes(sums_url, accept="text/plain")
    except NetGuardError as exc:
        raise NotChecked(f"the published digest could not be fetched: {exc}") from exc
    published = None
    for line in body.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1] == expected_name:
            published = parts[0]
            break
    if published is None:
        raise NotChecked(
            f"{sums_url} publishes no line for {expected_name}, so this version was not "
            "compared with anything"
        )
    if published != value:
        raise AssertionError(
            f"this build hashes to {value[:16]}... over {count} files; the release publishes "
            f"{published[:16]}... for {expected_name}. The code running here is not the code "
            "that was published"
        )
    return f"{value[:16]}... over {count} files, matching {expected_name} at {sums_url}"


def _audit_06_rate_limit(target: _Target) -> str:
    """Deliberately last: it blocks the audit's own address on this server."""
    limits = target.config["api"]["rate_limit"]
    threshold = int(limits["failure_threshold"])
    statuses = []
    blocked = None
    for attempt in range(threshold + 4):
        status, headers, _ = target.request("GET", "/status", token="wrong-token")
        statuses.append(status)
        if status == 429:
            blocked = (attempt + 1, headers.get("Retry-After"))
            break
    if blocked is None:
        raise AssertionError(
            f"{len(statuses)} wrong tokens in a row cost nothing: statuses {statuses}"
        )
    attempts, retry_after = blocked
    if not retry_after or not str(retry_after).isdigit() or int(retry_after) < 1:
        raise AssertionError(f"the 429 carried Retry-After {retry_after!r}")
    return (
        f"wrong token #{attempts} was answered 429 with Retry-After {retry_after}s "
        f"(threshold {threshold}); every earlier one got 401"
    )


# ---------------------------------------------------------------------------
# Running them
# ---------------------------------------------------------------------------


def _repo_root() -> str | None:
    """Where ``web/`` lives, if this is a checkout rather than an installed wheel."""
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (os.getcwd(), os.path.abspath(os.path.join(here, "..", ".."))):
        if os.path.isdir(os.path.join(candidate, "web")):
            return candidate
    return None


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _run_probe(finding: str, claim: str, probe) -> Check:
    started = time.monotonic()
    try:
        observed = probe()
        verdict = PASS
    except NotChecked as exc:
        verdict, observed = NOT_CHECKED, str(exc)
    except Exception as exc:  # noqa: BLE001 - a probe that cannot conclude is not a pass
        verdict = FAIL
        observed = f"{exc.__class__.__name__}: {exc}" if not isinstance(exc, AssertionError) else str(exc)
    return Check(
        finding=finding,
        claim=claim,
        verdict=verdict,
        observed=observed,
        ms=int((time.monotonic() - started) * 1000),
    )


def run(state: AgentState, config_path: str = "config.json", sums_url: str | None = None) -> list[Check]:
    """Replay the audit against this agent, and return one check per finding.

    The rate-limit probe is last on purpose: it ends with the audit's own
    address blocked on the audit's own server, and anything after it would be
    measuring that block rather than the defence it meant to test.
    """
    checks: list[Check] = []
    with _Target(state) as target:
        plan = [
            ("AUDIT-01", "an unlisted origin is never echoed, and '*' is refused outright",
             lambda: _audit_01_cors(target)),
            ("AUDIT-02", "the console cannot aim the agent at an internal address",
             lambda: _audit_02_ssrf(target)),
            ("AUDIT-03", "the console cannot add a relay, and no relay is on the internet",
             lambda: _audit_03_relays(target)),
            ("AUDIT-04", "the fee, the token and the paths are not console-writable",
             lambda: _audit_04_write_surface(target)),
            ("AUDIT-05", "the billing basis verifies, and one altered Wh breaks it",
             lambda: _audit_05_ledger(target)),
            ("AUDIT-07", "a token holder is not handed the other secrets",
             lambda: _audit_07_redaction(target)),
            ("AUDIT-08", "no path escapes the working directory",
             lambda: _audit_08_traversal(target)),
            ("AUDIT-09", "a lie in Content-Length allocates nothing",
             lambda: _audit_09_bounded_body(target)),
            ("AUDIT-10", "a miner that will not stop talking cannot exhaust the agent",
             lambda: _audit_10_miner_socket(target)),
            ("AUDIT-11", "the console executes only its own script",
             lambda: _audit_11_xss(target)),
            ("AUDIT-12", "the agent listens on loopback and says so if it does not",
             lambda: _audit_12_bind(target)),
            ("AUDIT-14", "the secrets on disk are readable only by their owner",
             lambda: _audit_14_permissions(target, config_path)),
            ("token", "the API token is not guessable from its shape",
             lambda: _token_entropy(target)),
            ("build", "this build is the build that was published",
             lambda: _build_matches_published(target, sums_url)),
            ("signing", "a downgraded signature is announced, not hidden",
             lambda: _degradation_is_announced(target)),
            ("AUDIT-06", "a wrong token costs something, and the cost compounds",
             lambda: _audit_06_rate_limit(target)),
        ]
        for finding, claim, probe in plan:
            checks.append(_run_probe(finding, claim, probe))
    return checks


def exit_code(checks: list[Check], strict: bool = False) -> int:
    if any(check.verdict == FAIL for check in checks):
        return 1
    if strict and any(check.verdict == NOT_CHECKED for check in checks):
        return 1
    return 0


def format_report(checks: list[Check], colour: bool = False, strict: bool = False) -> str:
    """The report a person reads: a judgement, then the fact behind it."""
    tints = {
        PASS: "\033[32m",
        FAIL: "\033[31m",
        NOT_CHECKED: "\033[33m",   # amber: it did not pass, it did not run
    }
    reset = "\033[0m"

    def tint(verdict: str) -> str:
        label = f"{verdict:<11}"
        return f"{tints[verdict]}{label}{reset}" if colour else label

    lines = ["", "  HashGuard self-audit -- docs/AUDIT_v1.md, replayed against this agent", ""]
    for check in checks:
        lines.append(f"  {tint(check.verdict)} {check.finding:<9} {check.claim}")
        for piece in _wrap(check.observed, 88):
            lines.append(f"              {'':<9} · {piece}")
        lines[-1] += f"  ({check.ms} ms)"
    failed = sum(1 for c in checks if c.verdict == FAIL)
    skipped = sum(1 for c in checks if c.verdict == NOT_CHECKED)
    passed = len(checks) - failed - skipped
    lines += ["", f"  {passed} passed · {failed} failed · {skipped} not checked"]
    if skipped and not strict:
        lines.append("  What could not be checked is not counted as passing. --strict makes it fail.")
    lines.append("")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, line, out = text.split(), "", []
    for word in words:
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out or [""]


def report_json(checks: list[Check], strict: bool = False) -> dict:
    from . import __version__

    return {
        "tool": "hashguard --self-audit",
        "version": __version__,
        "strict": strict,
        "checks": [check.as_dict() for check in checks],
        "summary": {
            "passed": sum(1 for c in checks if c.verdict == PASS),
            "failed": sum(1 for c in checks if c.verdict == FAIL),
            "not_checked": sum(1 for c in checks if c.verdict == NOT_CHECKED),
        },
        "exit_code": exit_code(checks, strict),
    }
