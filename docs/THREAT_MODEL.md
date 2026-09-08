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
- **Price feed integrity beyond TLS.** A feed that is authentic but wrong
  produces authentic, wrong decisions. The price used is sealed into the record,
  so the error is at least *attributable* after the fact.

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
