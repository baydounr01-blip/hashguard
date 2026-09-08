# HashGuard v2

**Curtailment and hardware-failure detection for Bitcoin mining farms, with a
savings ledger that neither the operator nor the client can quietly rewrite.**

```bash
pip install -e ".[sign]"
python3 -m hashguard --demo          # a simulated farm; no hardware, no account
python3 scripts/demo_verification.py # build a month, verify it, break it, watch it get caught
```

The agent runs on your hardware, inside your network, on the standard library
alone. It reads your miners, compares every hashboard against its rack siblings,
decides each hour whether mining pays for itself, and records what it measured.

HashGuard charges 25% of the savings it produces. That business model has an
obvious problem — *the party sending the bill is the party doing the
measuring* — and v2 exists mostly to solve it properly.

---

## The problem this version is about

v1 charged a share of measured savings and stored the measurement in a mutable
`savings.json` holding running totals and no history. The client could edit it
to shrink the bill. The operator could edit it to grow one. Neither could prove
anything to the other. The FAQ's answer — *"the ledger lives on your own
machine, the formula is public"* — answered a different question than the one a
sceptical client was actually asking.

You cannot fix that with a promise. You fix it by making the invoice a
**derivation the client can repeat**, rather than an assertion the client has to
accept. Four mechanisms do that, and they close four different doors.

### 1. History cannot be edited — a hash chain

Every record carries the hash of the record before it. Change one field of one
interval from three weeks ago and every subsequent record stops matching its
predecessor. The break is arithmetic, and the verifier names the record.

### 2. One line can be checked alone — a Merkle seal per day

Each day is Merkle-rooted, and the root is sealed exactly as a Bitcoin block
header is:

```
seal_hash = SHA256d(prev_seal ‖ merkle_root)
```

The monthly statement ships with inclusion proofs, so a single invoice line is
checkable against a 32-byte root and about fifteen hashes — no one has to send
you forty thousand records to prove one of them.

The construction is carried over verbatim from `bbu.merkle.LedgerBlockHeader` in
[universal-timeline](https://github.com/baydounr01-blip/universal-timeline),
where it demonstrates postulate P8: any alteration of an ancestor breaks every
link that follows it, detectably.

### 3. Numbers cannot be invented — a device signature

A consistent chain of fabricated figures is easy to produce in a text editor. A
consistent chain signed by an ed25519 key that exists only on the farm machine
is not. Seals are signed there; the public half is all anyone needs to check
them. Without `cryptography` installed the agent falls back to HMAC and *says
so* — in the startup banner, in the statement, and in the console — because an
HMAC seal is only checkable by someone who could also forge one, and that
difference should never be papered over.

### 4. A pause has to be visible in the physics — corroboration

This is the part we think is genuinely new.

A claimed pause asserts that machines stopped drawing power. If they stopped,
their hashrate went to the floor — and the hashrate is measured by a different
code path, from a different source (the miners' own API), than the price and
power figures that generate the claim. Two independent readings of one physical
event.

```
dark_fraction  = (baseline_hashrate − observed_hashrate) / baseline_hashrate
corroborated   = claimed_energy × dark_fraction
billable       = min(claimed_energy, corroborated)
```

Savings the telemetry cannot see are not billable, and every claim is capped at
its corroborated value. The cap is one-directional: it can only ever reduce an
invoice.

`hashguard/attest.py` is a port of `bbu.signature.ComputeAuditor` from the same
repository — postulate P12, the only falsifiable prediction of that framework —
which compares the computation an agent credits itself with against the
computation its branch could physically have supplied, and declares a signature
when the first exceeds the second beyond what variance explains. Same structure,
same conclusion: when two independent readings of one event disagree, the
disagreement is the finding.

### The asymmetry that ties it together

> **Mining fails open. Billing fails closed.**

No price data, a dead agent, a refused relay — the farm keeps mining. Your
operation is never held hostage to our uncertainty. But any interval the
telemetry cannot corroborate is simply not billable. Our uncertainty is charged
to us.

It is cheaper for the operator to measure honestly than to argue.

---

## Checking an invoice

```bash
python3 -m hashguard --statement 2026-09 > statement.json

python3 tools/hashguard_verify.py statement.json \
    --records ledger/records \
    --pubkey device_public.json
```

`tools/hashguard_verify.py` imports **nothing** from HashGuard. That is
deliberate and it is enforced by a test. It is one short, dependency-free file
so an auditor can read the whole thing in ten minutes and satisfy themselves
that it does what it claims: recompute every hash in the statement from the raw
records, and report exactly where the arithmetic stops agreeing.

It checks that the records chain, that none are missing, that each day's records
reproduce the sealed root, that `seal_hash = SHA256d(prev_seal ‖ merkle_root)`,
that the seals chain day to day, that every inclusion proof validates, that the
signatures verify, and that the money adds up — including that no line bills
more energy than the telemetry witnessed.

The console does a subset of the same work **in your browser**, with WebCrypto,
using none of the operator's code. That is possible only because the ledger
holds no floating point: integers and strings serialise identically in Python
and JavaScript, so both sides hash the same bytes.

### Everything is integers

Money is micro-EUR, energy is watt-hours, ratios are parts per million, all as
integers converted once at the edge. The canonical encoder **refuses to hash a
float** rather than hashing one that another implementation might render
differently. The fee is integer arithmetic with a stated rounding rule, and it
rounds *down*, so every fraction of a micro-euro that rounding creates goes to
the client.

---

## Security

v1's single-file agent had ten findings at High severity, including a wildcard
CORS default, server-side request forgery through a network-writable
`price_url`, arbitrary configuration writes over the API, a path traversal in
`log_dir`, and a stored XSS in the console that chained to token theft.

Every one of them is in **[`docs/AUDIT_v1.md`](docs/AUDIT_v1.md)**, with the
code that was wrong, why it mattered, what v2 does instead, and the name of the
test that fails if it is ever reopened. The threat model is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md); reporting is in
[`SECURITY.md`](SECURITY.md).

Highlights of the posture:

| | |
|---|---|
| **Bind** | loopback by default; going wider takes an explicit `i_understand_non_loopback_bind` |
| **CORS** | exact origin allowlist; `*` is refused at startup |
| **Auth** | constant-time compare *behind* a rate limiter with progressive blocking on source and token |
| **Write surface** | sixteen typed, bounded calibration knobs. Tokens, price sources, relays, paths and the fee are not settable over the network at all |
| **Outbound** | price feeds must be HTTPS to a public address; relays must be allowlisted *and* private. Both DNS-pinned, no redirects, size-capped |
| **Input** | every read bounded — request bodies, miner sockets, price responses, board counts |
| **Secrets** | key and config files created `0600`; a loosened key file is refused, not warned about |
| **Console** | strict CSP, no `innerHTML` from agent data, token in `sessionStorage` |
| **Dependencies** | none. `cryptography` is optional, for ed25519 |

### No runtime dependencies

v1 pulled in `requests` and `numpy` to compute medians and a least-squares
slope, on a machine with power control over a mining farm. v2 has none: there is
no third-party code in the path between a miner's socket and a signed ledger
record. CI asserts it.

---

## What it detects, and how loudly

A board's control group is the other boards in its rack. Comparing against
siblings cancels ambient temperature, grid voltage and difficulty drift at a
stroke, because all of them move every sibling together.

Three refinements matter:

- **MAD, not standard deviation** — a board already failing would inflate a
  standard deviation and hide inside its own noise.
- **Effective sample size** — hashrate is strongly autocorrelated; treating 30
  correlated samples as 30 independent ones inflates every z-score.
- **Family-wise correction and persistence** *(new in v2)* — eighteen boards are
  eighteen hypothesis tests per poll. At v1's threshold that is a false alarm
  every twenty minutes on healthy hardware, and an operator learns to ignore the
  panel within a week.

Measured over 40 seeded runs of a simulated 18-board farm
(`tests/test_qtmp.py`):

| | false alerts per healthy run | degrading board caught |
|---|---|---|
| v1's rule | **4.67** | 40 / 40 |
| v2's rule | **0.25** | 40 / 40 |

The noise went away. The signal did not.

The adaptive layer had a matching problem: driven by *lifetime* precision with a
fixed step, it walked `z_alert` to its ceiling on a run of dismissals and
recovered only 31% of its own excursion — a monitoring system that had quietly
switched itself off. v2 uses decayed counts, proportional steps, an evidence
floor, and a dead band that widens with the standard error of the estimate.
Closed-loop it settles at 2.02σ against an ideal of 2.045.

---

## Layout

```
src/hashguard/
  canonical.py   the one encoding both parties hash; refuses floats
  merkle.py      Merkle roots, inclusion proofs, the bbu-style seal header
  ledger.py      append-only records, daily seals, the monthly statement
  attest.py      the corroboration auditor (ported from bbu.signature, P12)
  identity.py    ed25519 / HMAC device keys, 0600 and checked
  money.py       integer units and the fee arithmetic
  qtmp.py        the detection engine
  adaptive.py    the feedback controller
  collector.py   bounded reads from the miner API
  pricing.py     break-even and the mine/pause decision
  netguard.py    outbound request policy (SSRF)
  ratelimit.py   progressive blocking, ported from quantumbot547
  config.py      typed schema and the narrow console-writable surface
  api.py         the HTTP surface
  agent.py       the loop and the CLI

tools/hashguard_verify.py   the independent verifier (imports no HashGuard)
web/                        console (strict CSP, in-browser verification)
docs/AUDIT_v1.md            every v1 finding and its fix
docs/THREAT_MODEL.md        what this defends against, and what it does not
```

## Where this comes from

Three repositories of the same author, joined here:

- **[universal-timeline](https://github.com/baydounr01-blip/universal-timeline)** —
  the Universo de Bloques Ramificados. `bbu.merkle` supplies the SHA-256d
  Merkle tree and the block-header chaining; `bbu.signature` (P12) supplies the
  structure of the corroboration auditor. Its governing idea — *a verdict is
  computed, not declared* — is the one this repository is built on.
- **[quantumbot547](https://github.com/baydounr01-blip/quantumbot547)** — the
  QTMP engine and the progressive access limiter behind `ratelimit.py`.
- **hashguard v1** — the product, the fail-safe curtailment design, and the
  sibling-comparison engine. All of it survives into v2; see the closing section
  of `docs/AUDIT_v1.md` for what it got right.

## Licence

MIT. See [LICENSE](LICENSE).
