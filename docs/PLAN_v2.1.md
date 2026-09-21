# HashGuard v2.1 — plan

What is ported from RAMI-Chain, how it lands in a Python standard-library
agent, which test protects each piece, and what each piece risks against the
two rules that govern this product. Written before the code, so the code can
be checked against it.

Source of the solutions: the sibling repository
[RAMI-Ledger](https://github.com/baydounr01-blip/RAMI-Ledger) (RAMI-Chain, a
Rust blockchain with a desktop wallet). Nothing here copies Rust. What is
ported is the *solution*: the rule, the rejection, the test discipline. Where
a RAMI solution collides with a HashGuard rule, the HashGuard rule wins and the
collision is written down in `PENDING-v2.1.0.md`.

## The rules that win

These do not move, and every section below is judged against them.

1. **No third-party code in the core.** What needs cryptography the standard
   library lacks lives behind an optional extra (`[sign]` today) and, when it
   is missing, the agent degrades *out loud* — banner, statement, console.
2. **Integers only.** The canonical encoder refuses floats. Nothing new puts a
   float into anything hashed or signed.
3. **Mining fails open. Billing fails closed.** No new feature can stop a miner
   because of *our* uncertainty; no uncorroborated interval is billed; a new
   cap can only reduce an invoice.
4. **Loopback bind by default; the network-writable surface does not grow.**
   Key and config files stay `0600`; a loosened file is refused.
5. **`tools/hashguard_verify.py` imports nothing from HashGuard**, and if the
   ledger format changes it reads the old and the new format without
   ambiguity.
6. **English in code, docs and console. Every change ships with its test, and
   the test is named in the documentation**, as `docs/AUDIT_v1.md` does.

## What the ledger looks like today (v2.0.0), so the changes are checkable

`SPEC = "hashguard-ledger/2"`. It does **not** change in v2.1. RAMI kept
`PROTO_VERSION` and the txid formula through its first consensus change; the
rule changed, not the identifier. Same here: a v2.0.0 verifier keeps reading a
v2.1 statement as far as it can, and the point where it stops is a rule it
does not know, not a spec string it refuses.

| Object | Fields today | Hashed / signed how |
|---|---|---|
| **record** (`ledger/records/DAY.jsonl`) | `spec, seq, day, ts, prev, device_id, action, executed, n_miners, seconds, price_ppm_per_kwh, breakeven_ppm_per_kwh, claimed_wh, claimed_mining_lost_micro_eur, baseline_gh, observed_gh` | leaf = `tagged_hash(SPEC/record, canonical(record))`; `prev` = hex of the previous leaf |
| **seal** (`ledger/seals.jsonl`) | `spec, day, device_id, prev_seal, merkle_root, leaf_count, first_seq, last_seq, seal_hash, corroboration` + `signature, algorithm` | `seal_hash = SHA256d(prev_seal ‖ merkle_root)`; `signature = Sign(canonical(body))` — **no domain tag, no farm identifier** |
| **statement** | `spec, month, device, fee_bp, margin_ppm, days[], corroboration, totals, proofs[], how_to_verify` | **not signed** |
| **identity** (`device_key.json`, `device_public.json`) | `algorithm, device_id, public_key_b64` (+ secret) | `device_id` = fingerprint of the public key |

Two facts found while reading, both of which shape the plan:

* The seal signature covers a body with no farm identifier, so the same key
  file installed on two farms signs interchangeable seals. That is the RAMI
  v0.7.x problem ("a regtest transaction is valid byte for byte on testnet")
  in HashGuard's clothes. Solution 1.
* **`tools/hashguard_verify.py` does not recompute the bill from the records.**
  It checks the chain, the roots, the seals, the proofs, the fee arithmetic
  and that `billable_wh ≤ corroborated_wh` — but every one of those money
  figures is read from the statement. A statement could carry a billable total
  that the records do not support and the arithmetic would still "close". The
  README's claim that the verifier makes the invoice *a derivation the client
  can repeat* is therefore half true today. This is fixed in solution 2 (the
  verifier has to walk the records for commit/reveal anyway) and named in
  `docs/AUDIT_v1.md` as a finding against v2.0.0, with its test.

## Sequencing

The five deliveries of this session touch overlapping files, so the order is
fixed by format dependencies, not by preference:

```
1 farm-bound signature + activation   -> ledger.py, identity.py, rules.py, verifier, console
2 commit/reveal (+ verifier recomputes the bill) -> ledger.py, agent.py, commit.py, verifier, console
6 parity corpus                        -> canonical.py, web/canonical.js (split out of console.js), tests
3 --self-audit                         -> selfaudit.py, agent.py, netguard.py, CI
5 cross-version round trip             -> tools/compat/, CI   (last: it needs the final formats of 1 and 2)
```

Solution 2 depends on 1's activation entry (the same activation day governs
both rules). Solution 6 moves the console's canonical encoder into its own
file, which 3's static checks then point at. Solution 5 runs the real v2.0.0
code against the real v2.1 code and is the last thing to write, because it
pins the formats the other four produce.

Every change is one commit per solution on one branch, and every commit runs
the whole suite plus the five CI jobs (tests ×3 Pythons, zero-dependency,
end-to-end, and the new `parity`, `self-audit`, `compat` jobs) before review.

---

## 1 · The signature bound to the farm, with an activation date

**What it solves in RAMI-Chain.** Until v0.7.3 the signed message was
`"RAMI-CHAIN/tx/v1" ‖ body`; a transaction signed for regtest verified on
testnet with the same key and nonce. v0.8.0 signs
`"RAMI-CHAIN/tx/v2" ‖ network_id ‖ body`
(`chain/crates/rami-core/src/tx.rs`: `DS_TAG_V2`, `signing_message_v2`,
`regla_para`, `FirmaCtx`). The rule is fixed by the block's timestamp against
`Params.firma_v2_desde` — before the date v1 and only v1, from the date v2 and
only v2, no mixed period — and **the rule never regresses within a branch**
(`BlockNode.firma_v2`), so nobody can back-date a block to slip an old-format
signature in after activation (`docs/CONSENSO-V2.md` §3). Nodes that do not
upgrade open all their files and simply stop following the chain at the first
block they cannot judge, without breaking (§6).

**HashGuard design.**

* **`farm_id`** — 32 random bytes, hex, minted once by the agent and stored in
  `device_key.json` next to the key; exported by `identity.public()` and
  therefore in `device_public.json`, `GET /identity`, the startup banner and
  the console header. It is public material, like RAMI's network-id, and the
  client is told to compare it out of band. A v2.0.0 key file without one is
  rewritten `0600` with a fresh `farm_id` on first load; two farms provisioned
  from one copied key file before the upgrade therefore diverge, which is the
  point.
* **Activation entry** — `ledger/activation.json`, written the first time a
  v2.1 agent opens a ledger, signed by the device key:
  `{spec, kind: "activation/1", rule: 2, from_day, farm_id, device_id,
  activated_at, signature, algorithm}`. `from_day` is the UTC day of
  activation. The rule for any sealed day is a pure function of
  `(day, from_day)` in a new module `hashguard/rules.py`:
  `day < from_day → rule 1` (byte-identical to v2.0.0), `day ≥ from_day →
  rule 2`. A day already sealed under rule 1 cannot be re-signed: `seal_day`
  is idempotent and `activate(from_day)` refuses any `from_day` at or before a
  sealed day ("the rule never regresses"). Forcing an earlier activation for a
  fresh ledger — RAMI's `--firma-v2-desde` for regtest — is
  `GuardedLedger(..., activate_from=DAY)` / `HASHGUARD_ACTIVATE_FROM`, refused
  if it would rewrite a sealed day.
* **Rule 2 seal.** The body gains `rule: 2` and `farm_id`; the signed message
  becomes `b"hashguard-ledger/2/seal-sig/2" ‖ farm_id(32 bytes) ‖
  canonical(body)`. The body — which carries `seal_hash`, and with it every
  record of the day — stays entirely under the signature: `leaf_count` is a
  committed fact (`merkle.py`, the CVE-2012-2459 note) and must not fall out of
  it. `seal_hash` keeps its formula, as the txid did in RAMI.
* **Statement signature** (new; statements were unsigned). Message
  `b"hashguard-ledger/2/statement-sig/1" ‖ farm_id ‖ canonical(statement
  minus the presentational keys signature/algorithm/how_to_verify/mode/note)`.
  The statement carries `farm_id`, the `activation` entry, `version`, and a
  `rule` per day.
* **Verifier.** Reads `activation` from the statement (absent → every day is
  rule 1, and it says so in a NOTE: *this statement predates farm-bound
  signatures*). For each day it computes the rule from `from_day`, requires
  the day's declared rule to equal it — a rule-1 seal on or after `from_day`
  and a rule-2 seal before it are both FAIL, never both accepted for one day —
  reconstructs the body for that rule and checks the signature under the
  matching message. It pins `farm_id` from `--pubkey` when the key file has
  one, requires the statement's and the activation's to match, and checks the
  activation entry's own signature. A v2.0.0 `device_public.json` (no
  `farm_id`) gets a NOTE telling the client to re-export it and compare the
  farm id out of band.
* **Console.** Shows `farm_id`, the rule per day, and applies the same
  never-both check; signatures stay a NOTE in the browser as today.

**Files.** `src/hashguard/rules.py` (new), `identity.py`, `ledger.py`,
`agent.py` (banner, `HASHGUARD_ACTIVATE_FROM`), `api.py` (`/identity`
already exports `public()`), `tools/hashguard_verify.py`, `web/console.js`,
`docs/THREAT_MODEL.md`, `SECURITY.md`, `README.md`.

**Protecting tests.**

| Claim | Test |
|---|---|
| The rule is a pure function of `(day, from_day)`; `None` means rule 1 everywhere | `test_rules.py::test_the_rule_is_a_pure_function_of_the_day_and_the_activation` |
| A seal signed for farm A does not verify as farm B, same key | `test_rules.py::test_a_seal_signed_for_farm_a_does_not_verify_as_farm_b` |
| Rule-1 seals produced by v2.1 are byte-identical to v2.0.0's | `test_rules.py::test_legacy_seals_are_byte_identical_to_v2_0_0` |
| A ledger crossing the activation day seals each day under exactly one rule | `test_ledger.py::test_a_ledger_crossing_the_activation_date_seals_each_day_under_exactly_one_rule` |
| Activation cannot move earlier than a sealed day | `test_ledger.py::test_activation_cannot_rewrite_the_rule_of_a_sealed_day` |
| A ledger activated for another farm is refused at open | `test_ledger.py::test_a_ledger_activated_for_another_farm_is_refused` |
| A v2.0.0 statement verifies unchanged | `test_verifier.py::test_a_v2_0_0_statement_verifies_unchanged` |
| A rule-1 seal after activation is refused; a rule-2 seal before it is refused | `test_verifier.py::test_a_rule_1_seal_after_activation_is_refused`, `::test_a_rule_2_seal_before_activation_is_refused` |
| A statement presented for another farm is refused | `test_verifier.py::test_a_statement_for_another_farm_is_refused` |
| The statement signature is checked, and a re-totalled statement fails it | `test_verifier.py::test_the_statement_signature_is_checked` |
| `farm_id` is public material and survives rewriting a v2.0.0 key file | `test_security.py::test_the_farm_id_is_public_material_and_survives_a_key_file_rewrite` |
| The real v2.0.0 verifier stops exactly at the first rule-2 day | `tools/compat/roundtrip.sh` (solution 5, CI job `compat`) |

**Fails open / fails closed.** Mining: untouched — nothing here is in the poll
path except one more banner line. Billing: a seal whose rule does not match
its day is refused, so the month it belongs to is not payable until explained;
that is the closed direction. Risk: an operator who copies a key file *after*
activation carries the farm id with it; the client sees one fingerprint on two
farms and the threat model says so. No new cap; no invoice can grow.

**Estimate.** ~10 h: rules module and identity 2 h, ledger and activation 3 h,
verifier 2 h, console 1 h, tests and docs 2 h.

**Done when** the tests above pass on three Pythons, the zero-dependency job
still finds `hmac-sha256` in the banner (HMAC identities are bound the same
way), and the `compat` job shows the v2.0.0 verifier failing *only* the
signature check of days on or after `from_day`.

---

## 2 · Commit/reveal of the decision

**What it solves in RAMI-Chain.** The commitment layer
(`chain/crates/rami-core/src/ledger.rs`, a faithful port of
`reference/rami_ledger.py`) publishes `sha256(canon(signal) ‖ nonce)` before
a fact and reveals `{commit, height, nonce, signal}` in a *strictly later*
block. `verify_ledger` rejects: a reveal of a commit that does not exist, a
reveal before or in the same block as its commit, a wrong height, a double
reveal, a revealed signal that does not reproduce the commit, and a malformed
reveal. An unrevealed commit is allowed; it is simply counted.

**What the same rule prevents here.** Today a record is written at the *start*
of an interval with the decision, the claimed energy for the interval to come,
and the hashrate read *now* — the corroboration is one interval behind the
claim, and the ledger does not prove that the decision was fixed before the
telemetry that corroborates it was seen. The look-ahead attack that follows
is concrete: claim a "pause" exactly when the farm is dark for another reason
(an outage, maintenance) and let the corroboration cap wave it through.
Commit/reveal fixes the order: **decide → commit → interval elapses →
measure → reveal**.

**HashGuard design.**

* A record now describes **the interval that just closed** and carries the
  **commit of the interval that just opened**. Poll `k` reads the miners,
  closes interval `k−1` (writes its record: the decision revealed in clear,
  `seconds` = elapsed capped at `poll_seconds` — never more than configured —,
  `claimed_wh` for those seconds, `observed_gh` and `baseline_gh` **at
  close**), decides interval `k` from the price now, mints a 32-byte nonce
  (`secrets.token_bytes`) and writes `commit` for it into that same record.
* New record fields: `opened` (ISO time the interval opened), `commit` (hex),
  `reveal` (`{commit_seq, nonce}` or `null`), `price_curve_hash` (hex of the
  day's price curve as fetched, or `null` on fail-open). The decision snapshot
  that is committed is the projection
  `{action, price_ppm_per_kwh, breakeven_ppm_per_kwh, opened,
  price_curve_hash}` of the record that later reveals it, so the reveal is
  checkable from the record's own clear text plus the predecessor's `commit`:
  `commit == tagged_hash(SPEC/commit, canonical(decision) ‖ nonce)`.
* **Rules the ledger, the verifier and the console all apply.** A reveal must
  name exactly its predecessor (`commit_seq == seq − 1`; any other target, and
  in particular the same record, is refused). A predecessor's `commit` with no
  reveal in the next record is *unrevealed* — allowed, counted (the agent
  restarted, or the interval never closed). A record with no `commit` at all
  is *legacy* (v2.0.0). The first record of a session is a zero-second MINE
  record that carries the first commit and reveals nothing.
* **Billing fails closed.** From the activation day (the same `from_day` as
  solution 1; commit/reveal is "rule 2" of the records), an executed PAUSE is
  billable only if its reveal reproduces its commit. Unrevealed or mismatched
  pause claims are counted in `statement.commit_reveal` and billed at zero.
  Before `from_day`, legacy records bill as in v2.0.0. Mining is untouched:
  a commit is a hash written to disk after the decision is already made.
* **The statement shows both.** Each sampled proof of a revealing record
  carries its `predecessor` (record, leaf, proof) so a reader with only the
  statement can check the commit and the reveal against the sealed root;
  `commit_reveal` summarises per day and per month: revealed, unrevealed,
  legacy, mismatched, and pause claims not billed for lack of a reveal.
* **The verifier recomputes the bill.** Walking every record of the month it
  already reads, it re-derives gross, corroborated, billable, fee and
  what-you-keep with the published integer formulas, applies the reveal rule
  and the corroboration cap itself, and compares the result to the statement.
  A billable total the records do not support is a FAIL, whatever the fee
  arithmetic says. This closes the gap named above.

**Files.** `src/hashguard/commit.py` (new), `ledger.py`, `agent.py`
(`poll_once` restructured around an open interval held in `AgentState`),
`api.py` (status shows the open commitment), `tools/hashguard_verify.py`,
`web/console.js`, `docs/AUDIT_v1.md` (new finding: the verifier trusted the
statement's totals), `README.md`, `docs/THREAT_MODEL.md`.

**Protecting tests.**

| Claim | Test |
|---|---|
| A reveal reproduces its commit; a changed decision does not | `test_commit.py::test_a_reveal_reproduces_its_commit`, `::test_a_changed_decision_does_not_reproduce_the_commit` |
| A reveal in the same record, or naming any record but the predecessor, is refused | `test_commit.py::test_a_reveal_in_the_same_record_is_refused`, `::test_a_reveal_naming_any_record_but_its_predecessor_is_refused` |
| Records carry the commit of the interval they open and the reveal of the one they close | `test_ledger.py::test_records_carry_the_commit_of_the_interval_they_open_and_the_reveal_of_the_one_they_close` |
| A pause claimed without a matching reveal is not billed | `test_ledger.py::test_a_pause_claimed_without_a_matching_reveal_is_not_billed` |
| Legacy records before activation still bill | `test_ledger.py::test_legacy_records_before_activation_still_bill` |
| The poll loop commits before it measures | `test_agent.py::test_the_poll_loop_commits_before_it_measures` |
| The verifier fails a reveal that does not match its commit | `test_verifier.py::test_a_reveal_that_does_not_match_its_commit_fails_the_verifier` |
| The verifier recomputes the bill from the records | `test_verifier.py::test_the_verifier_recomputes_the_bill_from_the_records` |
| An inflated billable total is caught even when the fee arithmetic closes | `test_verifier.py::test_an_inflated_billable_total_is_caught_even_when_the_arithmetic_closes` |

**Fails open / fails closed.** Mining: the decision is made exactly as before
and acted on before anything is hashed; a failure to write the commit is a
logged cycle failure and the miners keep running. Billing: three new ways for
a claim to be unbillable (unrevealed, mismatched, legacy-after-activation) and
none for it to grow; `seconds` is capped at the configured poll interval, so a
stalled agent under-claims rather than over-claims. Risk worth stating: the
first interval after every restart is never billed (its record is the session
start); that is a cost to the operator, not to the client.

**Estimate.** ~14 h: commit module 2 h, ledger and agent 4 h, verifier
recomputation 4 h, console 2 h, tests and docs 2 h.

**Done when** a month built by the tests bills the same figure in `ledger.py`
and in the verifier's recomputation, a tampered total is caught with the
arithmetic intact, and the `compat` job shows the v2.0.0 verifier still
passing the chain and root checks on records that carry commits and reveals.

---

## 3 · Self-audit: `hashguard --self-audit`

**What it solves in RAMI-Chain.** `rami_net::selftest`
(`chain/crates/rami-net/src/selftest.rs`) connects to the node's own P2P port
as a malicious peer — old plaintext hello, old protocol version, another
network, identity without proof of work, tampered handshake signature,
unauthenticated frame, oversized frame, avalanche of 256 fake tips — and
requires each to be rejected. `rami-gui` adds local checks
(`local_security_checks`, `main.rs`): `0600` on keystore, node key and panel
token; loopback-only panel; SHA-256 of the running executable against
`BINARIES-SHA256.txt` of the published release, with three honest outcomes
(matches / differs / could not compare). Each check is shown as *judgement*
(name, ✓/✗) and *fact* (what was observed, how long it took).

**HashGuard design.** `src/hashguard/selfaudit.py`, run by
`hashguard --self-audit [--json] [--strict]`. It builds the agent state from
the real `config.json` and ledger, starts the API in-process on
`127.0.0.1:0` (no poll loop, no miner is read), and replays every High finding
of `docs/AUDIT_v1.md` against it, live:

| Finding | Probe | Expected |
|---|---|---|
| AUDIT-01 CORS | `GET /status` with `Origin: https://evil.example`; `validate()` with `["*"]` | no `Access-Control-Allow-Origin`; `*` refused |
| AUDIT-02 SSRF | `POST /config {"curtailment":{"price_url":"http://169.254.169.254/"}}`; `fetch_public_json("https://169.254.169.254/")` | rejected by name; refused before a packet leaves |
| AUDIT-03 relays | `POST /config {"curtailment":{"webhooks":…}}`; `validate_webhook("http://8.8.8.8/relay", ["8.8.8.8"])` | rejected by name; public address refused |
| AUDIT-04 write surface | `POST /config` with `billing.fee_bp`, `api.api_token`, `paths.log_dir` | all three rejected by name, config unchanged |
| AUDIT-05 ledger | `verify_chain`/`verify_seal` over the real ledger; a tampered copy in a temp dir | real ledger passes; the copy fails at the edited record |
| AUDIT-06 rate limit | wrong tokens until blocked (run **last**: the block is on the audit's own address) | `429` with `Retry-After` |
| AUDIT-07 redaction | `GET /config` | token, price headers, webhook URLs absent |
| AUDIT-08 traversal | `POST /config {"paths":{"log_dir":"../../etc"}}`; `validate()` | rejected; refused |
| AUDIT-09 bounded body | raw request with `Content-Length: 100000`; with `Content-Length: abc` | `413`; `400`, connection closed |
| AUDIT-10 miner socket | a loopback listener that streams 300 KB; `parse_stats` with 500 boards | reader returns `None`; boards capped |
| AUDIT-11 XSS | static: `web/console.js` has no `innerHTML`; `console.html` has a CSP with `script-src 'self'` and no inline script | — (stated as a static check, not a replay) |
| AUDIT-12 bind | the audit server's own address; `validate()` with `0.0.0.0` | loopback; refused without the flag |
| AUDIT-14 permissions | `stat` of the real `config.json` and `device_key.json` | `0600` |
| token entropy | length and alphabet of the configured token | ≥ 128 bits |
| installed package vs published digest | SHA-256 over the installed package files against `SHA256SUMS.txt` fetched (through `netguard`, HTTPS + public address, no redirects) for this version | PASS / FAIL / **NOT CHECKED** (no sums published for this version, or offline) |
| degradation without `cryptography` | a subprocess with `cryptography` blocked prints the banner | contains `hmac-sha256` and `install 'cryptography'` |

The report is one line per check — verdict, finding, what was observed, ms —
and an exit code that is 0 only if nothing FAILED; `--strict` makes NOT
CHECKED count. NOT CHECKED is printed in amber and never hidden: a comparison
that could not be made is not a comparison that passed. A CI job runs the
audit against a demo configuration.

**Files.** `src/hashguard/selfaudit.py` (new), `agent.py` (flag, banner
lines factored into a function the audit can call), `netguard.py`
(`fetch_public_bytes`, the JSON fetch built on it), `tools/package_digest.py`
(new; prints the digest lines a release publishes), `.github/workflows/ci.yml`,
`README.md`, `SECURITY.md`.

**Protecting tests.**

| Claim | Test |
|---|---|
| The audit is green on this build | `test_selfaudit.py::test_the_self_audit_is_green_on_this_build` |
| Reopening AUDIT-04 (the fee becomes console-writable) turns the audit red | `test_selfaudit.py::test_reopening_the_config_write_surface_turns_audit_04_red` |
| A loosened key file turns AUDIT-14 red | `test_selfaudit.py::test_a_loosened_key_file_turns_audit_14_red` |
| What could not be checked is reported as such, not as passed | `test_selfaudit.py::test_the_report_states_what_it_did_not_check` |
| Green in CI | job `self-audit` |

**Fails open / fails closed.** The audit never touches a relay, never seals,
and never writes to the real ledger; its only outbound request is the digest
lookup, through the same guard as a price feed. Mining is not in the path.
Billing is not touched. Risk: the rate-limit probe blocks the audit's own
source address on the audit's own server instance — a separate limiter from
the running agent's, and the last probe by construction.

**Estimate.** ~8 h: probes 4 h, package digest and the degraded-banner
subprocess 2 h, tests and CI 2 h.

**Done when** `hashguard --self-audit` prints one verdict per finding, CI is
green on it, and both reopening tests turn the right line red.

---

## 5 · Round trip with the published version

**What it solves in RAMI-Chain.** `tools/compat/roundtrip.sh` builds the
published tag and the working tree, then: the old version writes; the new
opens, verifies and writes on top; the old reopens what the new wrote; and
(step 4) the new forces the signature-rule activation and the old reopens the
directory, *says which blocks it does not re-admit*, keeps working and does
not fall over. It runs in CI with the real binaries (`security.yml`, job
`compat`), because the format that matters is the one the binaries actually
write, not the one anyone remembers.

**HashGuard design.** `tools/compat/roundtrip.sh [OLD_REF]`, default
`v2.0.0`. The repository has no tag yet, so the script resolves `v2.0.0` to
the merge commit of v2 (`2ea210c`) when the tag is absent and says so; a tag
should be created (noted in PENDING). Two virtual environments: OLD from a git
worktree at the ref, NEW from this tree. `--demo` is a live loop in both
versions, so a month is generated through the public ledger API with one
driver, `tools/compat/build_days.py`, that runs unchanged under both packages
— which also pins that `GuardedLedger`, `Interval` and `DeviceIdentity` stay
source-compatible.

1. **OLD writes** thirty sealed days ending eleven days ago, the statement for
   each month touched, and `device_public.json`.
2. **NEW verifies OLD's statement** — must pass, with the NOTE that it
   predates farm binding. *If this fails, a new format broke an old ledger
   without an activation, and the script fails here.*
3. **NEW opens OLD's ledger** with activation forced to ten days ago (the
   regtest-style `HASHGUARD_ACTIVATE_FROM`; refused if it would touch a
   sealed day — asserted), appends ten days of records with commits and
   reveals, seals them under rule 2, writes its statement (signed, with
   `farm_id` and `activation`). The rewritten key file is checked to be
   `0600` and to still hold the OLD key.
4. **NEW verifies** its own statement and OLD's original: both pass.
5. **OLD verifies NEW's statement**: the script requires that the *only* FAIL
   lines are `seal signed by the device key` for days on or after the
   activation day — exactly the rule-2 days, nothing else — and that the
   chain, root, seal-hash and proof checks still pass on records that carry
   commits and reveals. That is "the old version says exactly where it stops
   understanding".
6. **OLD produces a statement from NEW's ledger** (a downgrade), and NEW's
   verifier fails it only on the rule-2 days with a message that names the
   cause. OLD then seals one more day under rule 1 on the activated ledger,
   and NEW's verifier refuses that seal as rule 1 after activation.
7. **Both verifiers cross their statements**: OLD→OLD pass, NEW→OLD pass,
   NEW→NEW pass, OLD→NEW fails only where step 5 says.

**Files.** `tools/compat/roundtrip.sh`, `tools/compat/build_days.py` (new),
`.github/workflows/ci.yml` (job `compat`, `fetch-depth: 0`).

**Protecting tests.** The script is the test; CI job `compat`. The unit
suite's `test_verifier.py::test_a_v2_0_0_statement_verifies_unchanged` pins
the same property with a v2.0.0-shaped statement built in-process.

**Fails open / fails closed.** No runtime code; the risk is the reverse — a
script that passes without exercising the boundary. Each step asserts a
specific line, not an exit code alone.

**Estimate.** ~5 h.

**Done when** the job is green and step 5's assertion is visibly the
interesting one in the log.

---

## 6 · Byte-for-byte parity between the two canonical encoders

**What it solves in RAMI-Chain.** `rami-core/src/canon.rs` reimplements the
Python reference's `canon()` and is tested against captured reference values
(`ledger.rs`, `commit_hash_matches_python_reference`,
`reveal_leaf_matches_python_reference`), with the rules written where both
implementations can read them: keys sorted, no spaces, integer-valued floats
as integers, `|x| < 2^53`, NaN/Infinity refused.

**HashGuard design.** Two implementations exist: `canonical.py` and the
console's `canonical()` in `web/console.js`. Three things are made explicit
before the corpus can be honest:

* **Safe integers only, on both sides.** JavaScript parses `9007199254740993`
  as `9007199254740992`; a record holding such a value would hash differently
  in the browser and the console could never verify it. No HashGuard unit
  reaches 2^53 (that is 9 PWh, or 9 billion euro in micro-EUR), so
  `canonical.py`, the verifier and the console all **refuse** integers outside
  `±(2^53 − 1)`, exactly as they refuse floats. Parity becomes a guaranteed
  property rather than a hope.
* **Keys sort by code point, on both sides.** Python sorts `str` by code
  point; `Array.prototype.sort` sorts by UTF-16 code unit, which disagrees for
  a key above U+FFFF against one in U+E000–U+FFFF. The console sorts by code
  point from now on.
* **The encoder moves out of the console** into `web/canonical.js`, loaded by
  `console.html` before `console.js` (still `script-src 'self'`) and loadable
  by Node through `vm` with WebCrypto, so the *same* file that runs in the
  browser is the one the test hashes.

The corpus, `tests/vectors/canonical.json`: empty containers; nested
objects; `null`/`true`/`false`; `0`, `-0`, `±(2^53 − 1)`; key order including
integer-like keys (`"10"` before `"9"`), unicode keys, and the code-point
trap above; strings with every JSON escape, DEL, U+2028, non-BMP characters,
and strings that look like numbers; a real record and a real seal body. Each
entry carries the expected canonical bytes and the expected record hash.
`tests/test_parity.py` hashes every entry in Python and, via
`tools/canonical_parity_node.js`, in Node, and requires (a) both to equal each
other and (b) both to equal the pinned digest; a serialization change on
either side fails (a), and one that changes both identically fails (b).
`tools/canonical_vectors.py --print` regenerates the pins, deliberately.

**Files.** `src/hashguard/canonical.py`, `web/canonical.js` (new),
`web/console.js`, `web/console.html`, `tools/hashguard_verify.py`,
`tools/canonical_parity_node.js` (new), `tools/canonical_vectors.py` (new),
`tests/vectors/canonical.json` (new), `tests/test_parity.py` (new),
`.github/workflows/ci.yml` (job `parity`, with Node).

**Protecting tests.**

| Claim | Test |
|---|---|
| Python and Node hash the corpus identically | `test_parity.py::test_python_and_node_hash_the_corpus_identically` |
| The pinned digests have not moved | `test_parity.py::test_the_pinned_digests_have_not_moved` |
| Integers beyond 2^53 are refused on both sides | `test_canonical.py::test_integers_beyond_2_53_are_refused`, `test_parity.py::test_node_refuses_unsafe_integers_too` |
| Keys sort by code point on both sides | `test_parity.py::test_keys_sort_by_code_point_on_both_sides` |
| Floats are refused on both sides | `test_parity.py::test_node_refuses_floats_too` |

**Fails open / fails closed.** Refusing large integers is a new failure in the
write path: a record that cannot be canonically encoded is not stored, and the
cycle is logged as failed (mining unaffected, the interval unbilled). The bound
is four orders of magnitude above any real quantity; the test that pins it
says which.

**Estimate.** ~4 h.

**Done when** the `parity` job is green and the vectors file carries pinned
digests for every entry.

---

## Later deliveries (planned here, built after the five above)

### 4 · Network and process inventory with an approved list

RAMI: `tools/security/inventory.py` scans the Rust sources (without comments
and tests) for URLs, host literals, `Command::new`, `env::var` and `bind(`,
prints a fixed-format list, and `--check` diffs it against
`SECURITY-INVENTORY.txt`; CI fails on any difference. HashGuard:
`tools/security/inventory.py` over `src/hashguard` for `http(s)://` literals
and host names, `subprocess`/`os.system`/`os.exec*`, `os.environ`/`getenv`,
`socket.create_connection`/`bind`, `ThreadingHTTPServer`, and every
`open(`/`os.open(` write target expressed as a config path key; plus a
*runtime* section produced by starting the agent on loopback and reading
`/proc/net/tcp` for its listening sockets. Approved list
`SECURITY-INVENTORY.txt`, CI job `inventory`; a new socket or destination
breaks CI until someone approves it. Protecting: the job, and
`test_inventory.py::test_an_unapproved_listener_breaks_the_check`. ~3 h.

### 7 · Graded sources and the exact word

RAMI: an Admiralty code per peer — letter for history, number for the
session, computed from what the node verified, descriptive only
(`docs/PALABRA-EXACTA.md` §1); a seven-term scale for predictions carried
inside the payload (§3); `tools/panel/lexico.py` failing CI on hedging
vocabulary in everything a person reads (§4). HashGuard: each miner gets a
letter (share of polls answered over its history, hard cap `C` on a changed
board count) and a number (this session: answered, fresh, corroborated by a
sibling rack); each price source gets the same pair (fetch history; this
session's freshness and whether the curve changed mid-day); both shown in
the console and carried in the statement **without effect on billing**.
The corroboration verdict is expressed with one term of the scale, from the
integer ratio, never a loose percentage. `tools/lexicon_check.py` scans
README, docs, `web/`, the statement strings in `ledger.py` and the console
texts; CI job `lexicon`. A first pass over today's copy finds hedging words
in `docs/THREAT_MODEL.md` and `README.md` that will have to be rewritten as
facts or as scale terms. Protecting: `test_grades.py` (the letter and number
tables), `test_lexicon.py::test_the_patterns_bite_and_the_scale_is_allowed`,
job `lexicon`. ~6 h.

### 10 · Console check and generated i18n

RAMI: `tools/panel/check.py` runs `node --check` over every script and
requires every `getElementById("x")` to have an `id="x"`; `gen_i18n.py`
generates `i18n.js` from `i18n-src/` and CI fails if the generated file
differs. HashGuard: `tools/console_check.py` over `web/console.html`,
`web/canonical.js`, `web/console.js`, `web/landing.js`; `web/i18n-src/`
(`en.json`, `es.json`) → generated `web/i18n.js`; every user-visible string in
the console goes through `t("…")`. Two CI jobs, `console` and `i18n`. ~4 h.

### 11 · The discipline of each version

`RELEASE_NOTES.md` with three fixed sections per version — **What it costs**
(measured), **How it was checked** (numbers and test names), **What is still
missing** — and `PENDING-v2.1.0.md` on the branch: the table of what was
verified, *how it is built, for whoever touches it next*, and what remains.
RAMI's lesson from `PENDIENTE-v0.10.16.md`
(`oversized_frame_disconnects_peer`, which read a peer count once, right after
an event that a later refresh updated, and took down the v0.10.7 release under
load): **no test reads once a state that a thread updates later; it waits with
a deadline.** Applied to this suite: `test_api.py` starts a server thread but
every request blocks on its response, so nothing there reads stale state; the
new `test_agent.py` and `test_selfaudit.py` follow the same rule, and a
`wait_until(predicate, deadline)` helper is the only way to observe a thread.
~3 h.

### 8 · Verified updater and a release with sums

RAMI: `release.yml` builds one installer per platform, publishes
`SHA256SUMS.txt` and `BINARIES-SHA256.txt`, signs the sums with an Ed25519
release key when `RAMI_RELEASE_SEED` exists, and uses `RELEASE_NOTES.md` as
the body; `rami-node/src/update.rs` fetches the sums from GitHub only, refuses
any asset whose hash differs, never downgrades, and (`local_security_checks`)
compares its own binary. HashGuard: `release.yml` on `workflow_dispatch` with
the tag as input, building wheel, sdist and a single-file zipapp
(`hashguard.pyz`), publishing `SHA256SUMS.txt` and `SHA256SUMS.sig`
(Ed25519, `HASHGUARD_RELEASE_SEED`), notes from `RELEASE_NOTES.md`;
`hashguard --check-update` reports only; `hashguard --apply-update` verifies
sum and signature before touching anything and **refuses to run while a
curtailment order is active** (a relay told to pause must be told to resume
by the same process that told it to pause — fails open). The release public
key is compiled in once generated. Outbound: one more public HTTPS
destination through `netguard`, in the inventory. ~10 h.

### 9 · Authenticated, encrypted tunnel for statement delivery

RAMI's `chain/crates/rami-net/PROTOCOL.md`: Ed25519 identity with proof of
work, three-message handshake signed by both parties over a fixed 203-byte
transcript, X25519 ephemeral keys, HKDF-SHA256, ChaCha20-Poly1305 with a
64-bit counter nonce, `len ‖ ciphertext` frames with the length checked before
allocation, bounded queues, TOFU. HashGuard does **not** put this between a
miner socket and a signed record; it is an optional `[tunnel]` extra
(`cryptography` supplies X25519, HKDF and ChaCha20-Poly1305 — the standard
library has none of the three) that carries a signed statement from the farm
to the operator without a VPN, degrading out loud when absent. First a
`docs/PROTOCOL.md` at RAMI's level of rigour — frames, byte layouts, size
bounds, what is rejected and why, who initiates, how the operator's key is
pinned, how the farm identity ties to the device key, replay protection —
then the code. If the code does not fit a delivery, the protocol ships and
the rest goes to PENDING. ~20 h (4 h protocol, 16 h implementation).

## What is not ported

The multiverse of branches, the Collatz tie-break and the advisory neural
network are distributed-consensus solutions; a single-farm ledger has no
branches to choose between. `adaptive.py` stays the only adaptive layer and
still never touches billing.

## Definition of done for v2.1.0

* Solutions 1, 2, 3, 5 and 6 merged, each with its tests named above, the
  suite green on Python 3.10–3.12, and the eight CI jobs green.
* `pyproject.toml` at 2.1.0; `RELEASE_NOTES.md` with its three sections;
  `docs/AUDIT_v1.md` updated where a defence changed its test and with the
  verifier finding; `SECURITY.md` with the new surface (activation entry,
  farm id, self-audit's one outbound lookup); `PENDING-v2.1.0.md` on the
  branch.
