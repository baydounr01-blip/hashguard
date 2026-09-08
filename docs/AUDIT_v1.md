# Security audit of HashGuard v1

v1 was a single 74 KB `index-2.html`: a landing page, a client console, and a
Python farm agent embedded in a `<script type="text/x-python">` block that the
download button assembled into a file in the browser.

It was a good sketch of a product. It was not a product you should run on a
network that has money on it. This document is the review, finding by finding,
and what v2 does about each one. Every finding here has a test in `tests/` that
fails if it is reopened — the test file and function are named in the last
column.

Severity is stated against v1's own stated threat model, which is the honest
place to judge it from: *the agent runs inside the farm network, the console is
a static page, and the token is the security boundary.*

## Summary

| ID | Severity | Finding | Status in v2 |
|---|---|---|---|
| AUDIT-01 | High | `Access-Control-Allow-Origin: *` by default | Fixed — exact origin allowlist, `*` refused at startup |
| AUDIT-02 | High | Server-side request forgery via `price_url` | Fixed — HTTPS + public-address-only, DNS-pinned |
| AUDIT-03 | High | Request forgery / lateral movement via `webhooks` | Fixed — private-address-only + explicit host allowlist |
| AUDIT-04 | High | `POST /config` deep-merged anything into the live config | Fixed — typed, bounded, console-writable subset only |
| AUDIT-05 | High | The billing basis had no integrity at all | Fixed — hash-chained, Merkle-sealed, signed ledger |
| AUDIT-06 | High | No rate limiting on token authentication | Fixed — progressive blocking on source and token |
| AUDIT-08 | High | Path traversal via `log_dir` | Fixed — paths must resolve inside the working directory |
| AUDIT-11 | High | Stored XSS in the console via agent-supplied strings | Fixed — console builds DOM nodes, never `innerHTML` |
| AUDIT-07 | Medium | `GET /config` leaked the price-feed key and webhook URLs | Fixed — every secret redacted, not just the token |
| AUDIT-09 | Medium | Unbounded request body from `Content-Length` | Fixed — 64 KB cap, malformed length handled |
| AUDIT-10 | Medium | Unbounded read from the miner socket | Fixed — 256 KB cap and a wall-clock deadline |
| AUDIT-12 | Medium | Bound `0.0.0.0` by default | Fixed — loopback by default, opt out explicitly |
| AUDIT-13 | Medium | Token in `localStorage`; no CSP on the page | Fixed — `sessionStorage`, and a strict CSP |
| AUDIT-14 | Medium | `config.json` written world-readable with the token in it | Fixed — `0600`, and refused if looser |
| AUDIT-15 | Low | Console gate: unsalted SHA-256 of a documented password | Fixed — gate removed; it was never security |
| AUDIT-16 | Low | Logs grew without limit | Fixed — daily rotation under a size ceiling |
| AUDIT-17 | Low | Float arithmetic in the billing basis | Fixed — integers in declared minor units |
| AUDIT-18 | Quality | ~4.7 false alerts per healthy run | Fixed — family-wise correction and persistence |
| AUDIT-19 | Quality | Adaptive thresholds could not recover | Fixed — proportional control with a dead band |
| AUDIT-20 | Quality | numpy imported to compute medians | Fixed — no runtime dependencies at all |

---

## The findings

### AUDIT-01 · High · Wildcard CORS

```python
"cors_origin": "*",   # DEFAULT_CONFIG
self.send_header("Access-Control-Allow-Origin", STATE.cfg["cors_origin"])
```

Any page loaded in any browser on the operator's machine could issue requests to
the agent and read the responses. The token still gated the data, but the
wildcard turned every website the operator visited into a position from which to
guess it — at LAN speed, against an endpoint with no rate limiting (AUDIT-06).

**v2.** `api.cors_origins` is a list of exact origins, empty by default. An
origin is echoed only if it is on the list. `*` on that list is rejected at
startup with an explanation, rather than accepted.
*Tests: `test_security.py::test_wildcard_cors_is_refused`,
`test_api.py::test_an_unlisted_origin_gets_nothing`.*

### AUDIT-02 · High · Server-side request forgery via the price feed

```python
r = requests.get(c["price_url"], timeout=10)
```

`price_url` was a console-writable string (AUDIT-04) fetched by a process
sitting inside the farm's network. That is a request-forgery primitive pointed
at the most sensitive place available: the miners' own management interfaces,
the router's admin page, and `169.254.169.254` on any cloud host.

**v2.** Price feeds go through `netguard.fetch_public_json`, which requires
HTTPS, resolves the hostname, refuses any answer in private, loopback,
link-local, reserved or multicast space, connects to the address it vetted
(so DNS rebinding does not get a second answer), never follows redirects, and
caps the response at 512 KB. `price_url` is operator-only.
*Tests: `test_security.py::test_price_feeds_cannot_be_aimed_inside_the_network`.*

### AUDIT-03 · High · Lateral movement via webhooks

```python
requests.get(url + ("0" if d["action"] == "PAUSE" else "1"), timeout=5)
```

The webhook map was arbitrary URLs, console-writable, called on a schedule.
Beyond forgery, it is an exfiltration channel: the agent will fetch a URL of the
attacker's choosing, on a timer, from inside the farm.

**v2.** Relay control is the mirror-image policy: the host must be on
`curtailment.webhook_allowlist` *and* must resolve to a private address. A relay
that resolves to the public internet is refused — controlling a farm's power is a
local-network action. The allowlist is operator-only, and `webhook` mode with
an empty allowlist is refused at startup rather than silently doing nothing.
*Tests: `test_security.py::test_a_webhook_host_must_be_on_the_allowlist`,
`::test_a_webhook_may_not_point_at_the_public_internet`.*

### AUDIT-04 · High · The config endpoint accepted anything

```python
data.pop("api_token", None)          # the only thing protected
STATE.cfg.update(deep_merge(STATE.cfg, data))
save_config(STATE.cfg)
```

Everything except the token was writable over the network: the price source, the
webhook URLs, the log directory, the miner list — and `billing.fee_pct`. A
console session could change what the client is charged.

**v2.** `config.CONSOLE_WRITABLE` is an explicit map of sixteen calibration
knobs, each with a type and a range. Anything else is rejected *by name*, so an
operator is never left believing a setting took effect. Tokens, bind address,
price sources, webhooks, paths and the fee are operator-only: they change by
editing `config.json` on the machine, which requires the one thing the threat
model already assumes an attacker lacks.
*Tests: `test_security.py::test_the_console_can_only_turn_the_calibration_knobs`,
`test_api.py::test_the_console_cannot_change_the_fee_or_the_price_source`.*

### AUDIT-05 · High · The billing basis had no integrity

```python
class SavingsLedger:
    PATH = "savings.json"
    ...
    with open(self.PATH, "w") as f:
        json.dump(self.data, f, indent=2)
```

This is the finding that matters most, because it is not really a bug — it is
the product's central claim left unimplemented. v1 charged 25% of measured
savings and stored the measurement in a mutable JSON file with running totals
and no history. The client could edit it to reduce the bill. The operator could
edit it to raise one. Neither could prove anything, and the FAQ's answer — "the
ledger lives on your own machine, the formula is public" — answers a different
question than the one a sceptical client is asking.

**v2.** The ledger is append-only and hashed three ways over: each record
carries the hash of its predecessor, each day is Merkle-rooted and the root
chained into a seal built exactly like a Bitcoin block header
(`SHA256d(prev_seal || merkle_root)`), and each seal is signed by a device key
that never leaves the farm machine. The monthly statement ships with inclusion
proofs, and `tools/hashguard_verify.py` re-derives every hash in it from the raw
records without importing any HashGuard code.
*Tests: all of `test_ledger.py`, `test_verifier.py`.*

### AUDIT-06 · High · Token authentication had no cost attached

```python
def _auth(self):
    tok = self.headers.get("X-QTMP-Token", "")
    return secrets.compare_digest(tok, STATE.cfg["api_token"])
```

The comparison is constant-time, which is correct and beside the point: nothing
limited how many times an attacker could make it. On a LAN that carries tens of
thousands of requests a second, and combined with wildcard CORS (AUDIT-01), a
24-byte token is only as strong as the attacker's patience.

**v2.** Every request is counted against both the source address and a hash of
the presented token, with a window cap and a failure counter whose block
doubles: 2s, 4s, 8s, up to fifteen minutes. The limiter runs *before* the token
comparison, so the two cannot be told apart by timing. A valid credential clears
the counters. The design is ported from `PersistentAccessLimiter` in the
quantumbot547 repository, which guards that project's client access endpoint.
*Tests: `test_security.py` rate-limiting section,
`test_api.py::test_repeated_guessing_gets_blocked_with_a_retry_after`.*

### AUDIT-07 · Medium · Only the token was redacted

```python
cfg = dict(STATE.cfg)
cfg["api_token"] = "***"      # never echo the token
```

`esios_token` — a live API credential — and the webhook URLs, which describe the
internal network layout, were returned in full to any token holder. The comment
says the right thing about one secret and overlooks the others. The dict copy is
also shallow, so nested mutations would have escaped.

**v2.** `api.redacted_config` deep-copies and redacts the token, every
price-feed header value, and every webhook URL.
*Test: `test_security.py::test_the_config_endpoint_redacts_every_secret`.*

### AUDIT-08 · High · Path traversal in `log_dir`

```python
os.makedirs(cfg["log_dir"], exist_ok=True)
path = os.path.join(cfg["log_dir"], f"{date.today().isoformat()}.jsonl")
```

`log_dir` was console-writable (AUDIT-04) and used unvalidated. `"../../etc"`
was a valid configuration, giving an attacker with a token an arbitrary
directory-creation and file-append primitive with the agent's privileges.

**v2.** Paths are operator-only, and `config.validate` refuses any that resolves
outside the working directory.
*Test: `test_security.py::test_paths_cannot_escape_the_working_directory`.*

### AUDIT-09 · Medium · Unbounded request body

```python
n = int(self.headers.get("Content-Length", 0))
data = json.loads(self.rfile.read(n) or b"{}")
```

`int()` on a non-numeric header raises `ValueError`, which nothing caught. `n`
had no ceiling, so an attacker who got past the token could ask the agent to
allocate arbitrary memory with a single header.

**v2.** A 64 KB cap, an explicit 413, a 400 for a malformed length, a 400 for a
body that is not a JSON object — and the connection is closed on the paths where
the body is never read, so a refusal cannot desynchronise a keep-alive
connection.
*Tests: `test_api.py::test_an_oversized_body_is_refused`, `::test_a_non_json_body_is_refused`.*

### AUDIT-10 · Medium · Unbounded read from the miner socket

```python
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    buf += chunk
```

Bounded only by the miner's willingness to stop talking. Anything that can reach
TCP 4028 can answer for a miner, and that port has no authentication of any
kind. An agent that dies to memory exhaustion stops measuring the savings the
client is billed for, which makes this a billing problem as much as a
reliability one.

**v2.** 256 KB cap, a wall-clock deadline across the whole exchange, at most 16
boards and 16 fans parsed from a reply, and implausible temperatures and fan
speeds discarded.
*Tests: `test_collector.py`.*

### AUDIT-11 · High · Stored XSS in the console

```javascript
d.innerHTML =
  '<div class="ahead"><span>'+a.severity+' · '+a.metric+' · z='+a.z+'σ</span>'+
  '<div class="amsg"><b>'+a.target+'</b> — '+a.message+'</div>';
```

`a.target` is built from miner names, which come from `config.json`, which was
network-writable (AUDIT-04). `m.payment_address` was interpolated the same way.
So: write a miner named `<img src=x onerror=...>`, wait for an alert, and the
payload executes in the console — where the agent token is sitting in
`localStorage` (AUDIT-13). That is a full chain from config write to token
exfiltration.

**v2.** The console never assigns `innerHTML` from agent data. Every value goes
through `textContent` on a node built with `createElement`. A strict CSP is the
backstop.
*Enforced by `web/console.html`; see also the CSP notes in `docs/THREAT_MODEL.md`.*

### AUDIT-12 · Medium · Bound to `0.0.0.0` by default

```python
srv = ThreadingHTTPServer(("0.0.0.0", cfg["api_port"]), Handler)
```

The documentation said "the agent is never exposed to the internet" while the
default handed a login prompt to every device on the network — and to the
internet directly if the machine had a public address or the router forwarded a
port.

**v2.** Default `127.0.0.1`. Remote access is a VPN's job, which is what v1's
own settings dialog already recommended. Binding wider requires setting
`api.i_understand_non_loopback_bind`, so it is a decision rather than a default.
*Test: `test_security.py::test_binding_beyond_loopback_requires_saying_so`.*

### AUDIT-13 · Medium · Token in `localStorage`, no CSP

`localStorage` persists indefinitely and is readable by any script in the
origin, which makes AUDIT-11 far more valuable to an attacker. The page also
shipped no Content-Security-Policy.

**v2.** The token lives in `sessionStorage` and is gone when the tab closes. The
console page carries a strict CSP with no `unsafe-inline`, no remote scripts and
`frame-ancestors 'none'`.

### AUDIT-14 · Medium · Secrets written world-readable

```python
with open(CONFIG_PATH, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
```

Default umask, so typically `0644`. On a shared box or a Raspberry Pi image with
extra accounts, every local user could read the API token and the price-feed
credential.

**v2.** `config.json` and `device_key.json` are created `0600` from the first
byte via `os.open` with an explicit mode, never chmodded after the fact. The
device key's permissions are re-checked on load and a loosened key is refused
outright rather than used with a warning.
*Tests: `test_security.py::test_key_files_are_written_owner_only`,
`::test_a_world_readable_key_is_refused_not_warned_about`.*

### AUDIT-15 · Low · The console gate

```javascript
const PASS_HASH = "6b1e1fd0...";   // Default: "qtmp2026"
```

An unsalted single-round SHA-256, in a static file, of a password written in the
comment above it. v1's own comment was honest about this — "this is visual
access control, not security" — and that honesty is the right instinct.

**v2.** Removed. A control that provides no security and looks like it does is
worse than no control, because someone eventually relies on it. The console asks
for the agent token, which is the actual boundary, and says so.

### AUDIT-16 · Low · Logs grew without limit

A minute-resolution JSONL log, written forever, on hardware that is often a
Raspberry Pi with an SD card. When the card fills, the agent stops — and the
agent stopping is the measurement stopping.

**v2.** Daily files under a configurable ceiling (256 MB default); the oldest
day is dropped when the ceiling is passed. The ledger is never touched by
rotation.

### AUDIT-17 · Low · Floating point in the billing basis

```python
mb["net_saving_eur"] = round(mb["net_saving_eur"] + net, 4)
```

Repeated float addition with rounding, over tens of thousands of intervals, for
a number that gets multiplied by 0.25 and put on an invoice. It is unlikely to
be wrong by much. It is guaranteed to be irreproducible in another language,
which matters when the whole proposition is that the client can check the sum.

**v2.** Integers in declared minor units — micro-EUR, watt-hours, ppm — from the
edge conversion onward. The canonical encoder *refuses* to hash a float, so an
accidental reintroduction is a loud failure rather than a slow drift. The fee is
integer arithmetic with a stated rounding rule, and it rounds down, so rounding
always favours the client.
*Tests: `test_money.py`, `test_canonical.py::test_floats_are_refused_rather_than_hashed`.*

### AUDIT-18 · Quality · The detector cried wolf

Eighteen boards are eighteen hypothesis tests per poll. At v1's 2.5σ threshold
that is a false alarm every twenty minutes on healthy hardware — measured at
**4.67 per 40-poll run** over 40 seeded simulations. An operator learns to
ignore that panel within a week, at which point the real alert arrives and is
also ignored.

**v2.** `z_alert` is read as a farm-wide false-alarm rate and Šidák-corrected
across the boards being compared, so the number keeps meaning what the operator
thought it meant as the farm grows. A board must also breach on three
consecutive polls. Measured: **0.25 false alerts per run**, with the degrading
board still caught in **40 of 40** runs.
*Test: `test_qtmp.py::test_v2_rule_cuts_false_alarms`, `::test_v2_still_catches_a_degrading_board`.*

### AUDIT-19 · Quality · The adaptive loop could not recover

v1 moved thresholds a fixed step based on *lifetime* precision. Fed eight false
alarms and then thirty confirmed catches, it walked `z_alert` from 2.5 to its
6.0 ceiling and crawled back only to 4.9 — recovering 31% of its own excursion,
having switched most of the detector off in the meantime. A monitoring system
that has quietly turned itself off is worse than one that was never installed.

**v2.** Geometrically decayed counts (effective memory ~33 labels),
proportional steps, an evidence floor, and a dead band that widens with the
standard error of the estimate so the loop moves on evidence and holds on noise.
Closed-loop against a farm where the threshold genuinely affects precision, it
settles at a mean of 2.02σ against an ideal of 2.045.
*Test: `test_adaptive.py::test_it_can_come_back_down_again`, `::test_closed_loop_converges`.*

### AUDIT-20 · Quality · numpy for a median

v1 required `requests` and `numpy` to compute medians, a MAD, and a
least-squares slope over at most a few hundred points — and called
`numpy.polyfit` twice per metric per poll to get a slope and its residuals
separately. Two large transitive dependency trees, on a machine with power
control over a mining farm, for arithmetic the standard library does fine.

**v2.** No runtime dependencies. `cryptography` is optional and only for
ed25519 device keys; without it the agent falls back to HMAC and says so, in the
startup banner and in every statement it signs. CI asserts that installing
HashGuard pulls in nothing third-party.
*Enforced by the `zero-dependency-check` job in `.github/workflows/ci.yml`.*

---

## What v1 got right

Worth recording, because v2 keeps all of it:

* **The engine's core idea.** Comparing each board against its rack siblings
  cancels ambient temperature, grid voltage and difficulty drift in one stroke.
  Using MAD rather than standard deviation so a dying board cannot hide inside
  its own noise is the right call, and so is correcting for autocorrelation.
* **Fail-safe curtailment.** No price data means mine. The agent dying means the
  miners keep running on their own firmware. v2 keeps this exactly, and adds its
  mirror image: billing fails *closed*, so uncertainty costs the operator rather
  than the client.
* **Netting the revenue you lose against the electricity you avoid.** Many
  curtailment pitches quietly bill on gross energy saved.
* **Not billing advisory mode.** If the software only recommended, it charges
  nothing.
* **Saying out loud that the console gate was not security.** That instinct, of
  naming the weak part rather than dressing it up, is the one this whole
  document is built on.
