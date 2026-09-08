# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/baydounr01-blip/hashguard/security/advisories/new)
on this repository. Please do not open a public issue for anything that would
let someone bill a farm incorrectly, reach a farm's internal network, or read a
device key.

Useful reports include: what an attacker can do, the position they need to start
from, and — if you have one — a failing test. There is no bounty; there is a
credit in the advisory and in the changelog unless you would rather not have one.

## Scope

**In scope**

- The agent (`src/hashguard/`), especially: the HTTP API, the config write
  surface, the outbound request guard, and anything reachable from a miner's
  socket.
- The ledger and its verification (`ledger.py`, `merkle.py`, `canonical.py`,
  `attest.py`, `tools/hashguard_verify.py`) — in particular any way to make a
  tampered ledger verify, or an honest one fail.
- The console (`web/`) — anything that gets script execution, exfiltrates the
  token, or makes an invalid statement display as valid.

**Out of scope** — these are documented limits, not oversights. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md):

- Attacks requiring root on the agent machine.
- Miners whose firmware reports hashrate they are not producing.
- The absence of physical energy metering.
- Plaintext HTTP on the agent API; it is loopback-bound by design and the
  documented deployment is a VPN.
- Denial of service from a local process against a loopback-bound agent.

## Supported versions

| Version | Supported |
|---|---|
| 2.x | yes |
| 1.x (`index-2.html`) | **no** — see [docs/AUDIT_v1.md](docs/AUDIT_v1.md) |

v1 is not patched and should not be run. Its findings are published in full
because the software was distributed and anyone still running it should know
precisely what they are running.

## Running it safely

1. **Keep the bind on loopback.** `api.bind_host` defaults to `127.0.0.1`.
   Reach it remotely over a VPN rather than by widening the bind.
2. **Install `cryptography`.** `pip install -e ".[sign]"`. Without it, seals are
   HMAC-signed and cannot be audited by a third party.
3. **Back up `device_key.json`, and keep it `0600`.** Lose it and past seals stay
   verifiable but no new ones can be signed by that identity. Leak it and anyone
   can mint seals in your farm's name.
4. **List your console's exact origin** in `api.cors_origins` if you serve the
   console from anywhere other than the agent's own machine. `*` is refused.
5. **Keep `curtailment.mode` on `advisory`** until you have watched the decisions
   for a while. Advisory mode never touches a relay and never bills anything.
6. **List relay hosts explicitly** in `curtailment.webhook_allowlist`. The agent
   will not call a host nobody listed, and will not call a public address at all.
7. **Verify your first statement by hand**, with `tools/hashguard_verify.py`. If
   the checking mechanism only ever gets used by the party that wrote it, it is
   decoration.

## What we commit to

- Any finding that lets a bill be wrong, a network be pivoted into, or a key be
  read gets a fix and a public advisory.
- Fixes ship with a regression test named in the advisory.
- The audit of v1 stays published, in full, including the parts that are
  embarrassing. A vendor's security posture is better judged by what they
  disclose about their own past code than by what they claim about their current
  code.
