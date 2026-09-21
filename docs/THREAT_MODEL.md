# Threat model

What HashGuard defends against, what it does not, and where the honest limits
are. Written so that someone deciding whether to run this on a farm with money
on it can tell the difference between a designed property and a hope.

## What is being protected

1. **The farm's continued operation.** Mining is the client's revenue. Nothing
   in this software may stop it for a reason that cannot be reconstructed.
2. **The integrity of the billing basis.** HashGuard charges a share of measured
   savings. The measurement is the invoice.
3. **The farm's internal network.** The agent sits inside it, with credentials
   to talk to the miners and, optionally, power control over them. That position
   is worth stealing.
4. **The secrets on the agent machine.** The API token, the device signing key,
   and any price-feed credential.

## The parties, and what each is assumed to want

| Party | Assumed capability | Assumed motive |
|---|---|---|
| **Client** (farm operator) | Full control of the machine, the config, and the ledger files | Pay less than they owe |
| **Operator** (HashGuard) | Ships the software; may see statements | Bill more than is owed |
| **Network attacker** | Can reach the agent's port; can answer for a miner on TCP 4028 | Pivot into the farm, steal the token, control power |
| **Browser attacker** | Can get the operator to load a hostile page | Reach the agent through the browser; steal the token |

Neither the client nor the operator is assumed honest. That is the whole design
constraint: the arrangement has to be *checkable*, because then neither party has
to be trusted.

## Designed properties

### The ledger

- **Editing history is detectable.** Each record carries its predecessor's hash.
  Editing, deleting or reordering any record breaks every link after it, and the
  verifier names the first record that fails.
- **Fabricating history is detectable.** Seals are signed by a device key. An
  attacker who rewrites records *and* recomputes the Merkle root still cannot
  produce a valid signature without the key.
- **A seal cannot be moved between farms.** Every installation mints a
  `farm_id`: 32 random bytes, public, stored beside the device key and printed
  at startup. From the activation day written into `ledger/activation.json`,
  the farm id is *inside* the bytes a seal signature covers, so one key file
  installed on two farms no longer produces interchangeable seals. Which rule
  governs a day is a pure function of the day and the activation day, so a day
  never has two valid readings, and a day already sealed can never have its
  rule changed by a later activation.
  *Tests: `test_rules.py::test_a_seal_signed_for_farm_a_does_not_verify_as_farm_b`,
  `test_ledger.py::test_a_ledger_crossing_the_activation_date_seals_each_day_under_exactly_one_rule`,
  `::test_activation_cannot_rewrite_the_rule_of_a_sealed_day`.*
- **The invoice document is signed, not just the seals inside it.** v2.0.0
  signed each day's seal but nothing around it, so the totals, the fee and the
  inclusion proofs a client was handed could be re-typed in transit while every
  seal still verified. The statement now carries its own signature over
  everything except its presentational fields.
  *Test: `test_ledger.py::test_the_statement_is_signed_over_its_own_totals`,
  `test_verifier.py::test_the_statement_signature_is_checked`.*
- **A single line is checkable in isolation.** Inclusion proofs mean verifying
  one invoice line needs a 32-byte root and ~15 hashes, not the whole month.
- **The arithmetic is reproducible.** Integers in declared minor units, and a
  canonical encoding that refuses to hash a float. Two correct implementations
  in two languages produce the same bytes.
- **Overbilling is capped by physics.** A claimed pause must show up as the farm
  going dark in hashrate telemetry, which is collected by a different code path
  from a different source. The cap is one-directional: it can only reduce.
- **Billing fails closed.** No baseline, no telemetry, no seal — not billable.

### The agent

- **Loopback by default.** Widening it requires an explicit config flag whose
  name says what it means.
- **Authentication has a cost.** Rate limiting runs *before* the constant-time
  token comparison, with progressive blocking on both the source address and a
  hash of the presented token.
- **The network write surface is small and typed.** Sixteen bounded calibration
  knobs. Tokens, bind address, price sources, relay URLs, file paths and the fee
  are operator-only, changed by editing `config.json` on the machine.
- **Outbound requests are policed in both directions.** Price feeds: HTTPS,
  public addresses only. Relays: allowlisted hosts, private addresses only. Both
  DNS-pinned to the address that was vetted, no redirects followed, responses
  size-capped.
- **Every read is bounded.** Request bodies, miner sockets, price responses,
  board and fan counts, log directory size.
- **Secrets are `0600` from the first byte**, and a device key whose permissions
  have loosened is refused rather than used with a warning.
- **The defences can be re-tested on the machine they are running on.**
  `hashguard --self-audit` replays every finding in `docs/AUDIT_v1.md` against a
  throwaway copy of the live API, and separates *held* from *could not be
  checked*. This matters because most of the properties above degrade through
  configuration and operations, not through code: a `chmod` from a backup
  script, an origin added to get a demo working, a token pasted in by hand.
  A test suite in a repository cannot see any of that.
  *Tests: `test_selfaudit.py::test_the_self_audit_is_green_on_this_build`,
  `::test_reopening_the_config_write_surface_turns_audit_04_red`,
  `::test_a_loosened_key_file_turns_audit_14_red`,
  `::test_the_report_states_what_it_did_not_check`.*
- **A degraded signature backend is announced, not hidden.** Without
  `cryptography` the agent signs with HMAC-SHA256 and says so in the startup
  banner and in the statement. The self-audit runs the banner in a second
  interpreter with `cryptography` blocked and requires the sentence to be there.
  *Test: `test_selfaudit.py::test_the_self_audit_is_green_on_this_build`
  (the `signing` line).*

### The console

- Strict CSP with no `unsafe-inline` for scripts and no remote script sources.
- No agent-supplied string is ever assigned to `innerHTML`.
- The token lives in `sessionStorage`, not `localStorage`.
- Verification runs client-side, so a compromised operator backend cannot make
  a bad statement look good in the client's own browser.

## Explicitly out of scope

These are real risks. HashGuard does not address them, and saying so is more
useful than implying otherwise.

- **Root on the agent machine.** Anyone with root can read the device key and
  sign anything they like. The ledger's guarantee is "this was produced by the
  key on that machine", not "this is true". If the machine is owned, so is the
  ledger. Ed25519 with the key on the *client's* hardware is what makes this a
  meaningful boundary against the operator specifically.
- **Lying miners.** If a miner's firmware is compromised and reports a hashrate
  it is not producing, corroboration is corroborating a lie. The telemetry is
  independent of the *pricing* path, not independent of the hardware.
- **Physical energy metering.** HashGuard infers energy from configured power
  draw and elapsed time. It does not read a meter. A machine whose real draw
  differs from `power_kw` produces a proportionally wrong figure — honestly
  measured and consistently wrong. A metering integration is the obvious next
  step and does not exist yet.
- **Transport encryption to the agent.** The API speaks plain HTTP. The token
  crosses the network in a header. This is safe on loopback and inside a VPN,
  and it is *not* safe on an untrusted LAN. Use a VPN; the software tells you so
  at startup when no CORS origin is configured.
- **Denial of service by a local attacker.** Rate limiting keys on the source
  address, and on a loopback-only bind every local process shares that address,
  so a local attacker can trigger a temporary self-denial by guessing wrong
  repeatedly. Anyone who can reach loopback can already read `config.json`, so
  this buys them nothing they did not have.
- **Supply chain of the Python runtime itself.** Runtime dependencies are zero,
  which removes the third-party layer, but not CPython or the OS.
- **Key rotation and revocation.** There is currently one device key with no
  rotation ceremony. Rotating it today means the seals before and after are
  signed by different keys, and a verifier must be given both. This should be a
  first-class operation and is not yet.
- **A key file copied *after* activation carries the farm id with it.** Farm
  binding stops a seal being presented as another farm's; it does not stop
  someone duplicating a whole installation. What the client gets is a visible
  symptom rather than a silent one: the same farm id and the same device
  fingerprint appearing on two farms. Comparing that fingerprint out of band,
  once, is what makes it a symptom at all.
- **Days sealed before the activation day stay in the old format.** They must:
  re-signing them would mean rewriting signed history, which is the one thing
  this design exists to prevent. A ledger that predates HashGuard 2.1
  therefore has a prefix of seals that name no farm, and the verifier says so.
- **Price feed integrity beyond TLS.** A feed that is authentic but wrong
  produces authentic, wrong decisions. The price used is sealed into the record,
  so the error is at least *attributable* after the fact.
- **The self-audit runs inside the process it is auditing.** It is a check
  against regression and misconfiguration, not against a hostile build: code
  that has been modified to lie can modify the audit too. The only defence
  against that is comparing the running package with a digest published
  elsewhere, which is why `--self-audit` reports that comparison as **NOT
  CHECKED** until a release publishes one, instead of leaving it out.
- **What the token check measures is shape, not secrecy.** Length, alphabet,
  distinct characters and repetition are all that can be read off a string. A
  memorable passphrase that clears all four still passes, and the report says
  so on the line rather than implying a strength measurement nobody took.

## Known trade-offs

**The corroboration cap can under-bill.** A farm that pauses via a mechanism
which leaves hashboards reporting (a pool-side throttle, say, rather than a power
cut) will show a smaller dark fraction than it earned, and be billed less than it
should. This is deliberate: the error direction favours the client, and an
operator arguing for *more* than the telemetry shows is in a much better position
than a client arguing against a number they cannot check.

**HMAC fallback is weaker and is not hidden.** Without `cryptography`, seals are
HMAC-signed and only a holder of the shared secret can verify them — the same
secret that could forge them. The agent says so at startup, the statement carries
`verifiable_by_third_party: false`, and the console and CLI verifier both say it
plainly rather than reporting a check they did not perform.

**Sealing is daily.** A day in progress is measured, visible and unsealed, and an
unsealed day is not billable. Records written since the last seal are chained but
not yet Merkle-committed, so a compromise before the daily seal could edit them
without breaking a seal — the chain would still break, which is what makes it
detectable, but the signed commitment is what makes it *provable*. Sealing more
frequently is a straightforward change if the exposure matters to you.

## Reporting

See [SECURITY.md](../SECURITY.md).
