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
  `attest.py`, `rules.py`, `tools/hashguard_verify.py`) — in particular any way
  to make a tampered ledger verify, or an honest one fail.
- The console (`web/`) — anything that gets script execution, exfiltrates the
  token, or makes an invalid statement display as valid.
- The self-audit (`selfaudit.py`) — in particular any way to make a probe report
  PASS while the defence it names is not standing. A self-check that can be
  made to lie is worse than no self-check, because someone will trust it.

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
4. **Write down the farm id the agent prints at startup, and compare it once,
   out of band.** It is public material — 32 bytes of hex, stored beside the
   device key — and from the activation day recorded in
   `ledger/activation.json` it is inside every signed seal. Comparing it once
   is what turns "a seal signed by some HashGuard installation" into "a seal
   signed by *this* farm". The verifier checks it for you when the
   `device_public.json` you were given carries one.
5. **List your console's exact origin** in `api.cors_origins` if you serve the
   console from anywhere other than the agent's own machine. `*` is refused.
6. **Keep `curtailment.mode` on `advisory`** until you have watched the decisions
   for a while. Advisory mode never touches a relay and never bills anything.
7. **List relay hosts explicitly** in `curtailment.webhook_allowlist`. The agent
   will not call a host nobody listed, and will not call a public address at all.
8. **Verify your first statement by hand**, with `tools/hashguard_verify.py`. If
   the checking mechanism only ever gets used by the party that wrote it, it is
   decoration.
9. **Run `python3 -m hashguard --self-audit` after installing, and after every
   upgrade.** It replays every finding in `docs/AUDIT_v1.md` against the agent
   running on *your* machine, in *your* configuration, and reports one verdict
   per finding. Read the amber lines: **NOT CHECKED** means a probe could not
   run here, and it is deliberately not counted as a pass. Use `--json` to keep
   it in a monitor and `--strict` to make an unrunnable check fail.

   The audit starts a throwaway copy of the API on `127.0.0.1:0` with its own
   rate limiter, so nothing it does can lock you out of the console, and it
   writes nothing: no ledger record, no seal, no config change, no relay call.

## What we commit to

- Any finding that lets a bill be wrong, a network be pivoted into, or a key be
  read gets a fix and a public advisory.
- Fixes ship with a regression test named in the advisory, and where the fix is
  a defence rather than a correction, with a `--self-audit` line that goes red
  if it is ever reopened.
- The audit of v1 stays published, in full, including the parts that are
  embarrassing. A vendor's security posture is better judged by what they
  disclose about their own past code than by what they claim about their current
  code.
