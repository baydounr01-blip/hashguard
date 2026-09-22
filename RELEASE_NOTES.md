# Release notes

Every version gets the same three sections, in the same order, and none of them
is allowed to be empty.

**What it costs** is measured, not estimated: bytes, milliseconds, and the
things that got slower or bigger. A release that only lists what it gained is a
sales page.

**How it was checked** names the tests. A claim with no test name behind it is
an opinion, and an opinion is not what anyone should pay an invoice on.

**What is still missing** is the section that makes the other two believable. It
is written before the release, not after somebody finds the gap.

---

## 2.1.0 — the disciplines from RAMI-Chain

HashGuard 2.0.0 could prove that a ledger had not been edited. It could not
prove *whose* ledger it was, and it could not prove that a decision had been
taken before the measurement that justified it. Both gaps are closed here, with
the solutions already proven in [RAMI-Chain](https://github.com/baydounr01-blip/RAMI-Ledger),
adapted to a single-farm ledger with no third-party dependencies.

### The two findings this release answers

**A seal named no farm.** A 2.0.0 seal is signed over a message containing the
day, the Merkle root and the previous seal — and nothing that says which
installation produced it. A key holder with two farms could present either
farm's seals as the other's, and every check would pass. From an **activation
day written into the ledger and signed**, the farm id is inside the signed
bytes. Days before that day keep their old signatures byte for byte, because
re-signing history is the one thing this design exists to prevent.

**A decision could be written to fit a measurement.** 2.0.0 recorded the
mine/pause decision and the telemetry in the same record, written at the same
moment. Nothing in the file showed which came first, so a farm that went dark
for an unrelated reason could have a pause written around the gap afterwards.
Now each poll publishes `sha256(canonical(decision) ‖ nonce)` for the interval
it is *opening*, and reveals the nonce one record later. The commitment is on
disk — and under the day's seal — a full poll before the hashrate that
corroborates it is read.

A third finding surfaced while building the round trip and is fixed here: the
verifier used to fail a pre-2.1 statement for "not being for the farm whose key
you were given" whenever the key file had since gained a farm id. A statement
that names no farm makes no claim to disagree with. It is a NOTE now, because
teaching an operator that a red line on an old invoice is normal is how a
verifier stops being read.

### What it costs

| | 2.0.0 | 2.1.0 | |
|---|---|---|---|
| A paused-interval record, canonical bytes | 373 | 669 | **+79%** |
| A year of 60-second polls, one farm | 196 MB | 352 MB | **+156 MB** |
| Commit computed per poll | — | 8 µs | against a 60 s poll |
| Startup, per ledger | — | one `activation.json` read | written once, on first start after upgrade |
| `--self-audit`, demo installation | — | ~0.8 s | 16 checks, one of them a subprocess |
| `parity` test suite | — | ~0.8 s | 16 vectors, Python and Node |
| `compat` round trip, CI | — | ~2 min | two virtualenvs, 22 sealed days |
| Test suite | 199 tests, ~14 s | 316 tests, ~40 s | +117 tests |
| Runtime dependencies | 0 | 0 | unchanged, and asserted in CI |

The record growth is the honest price of commit/reveal: a 64-character
commitment, a 64-character nonce, an opening timestamp and a price-curve
digest, on every record. A farm that does not want it can keep running 2.0.0
records — they still bill exactly as they did, under the rule marked `legacy`.
Nothing in this release is faster, larger-capacity or cheaper. It buys one
thing: claims that can be checked by someone who does not trust the farm.

**A new refusal in the write path.** The canonical encoder now rejects any
integer outside ±(2⁵³ − 1), in the agent, the verifier and the console alike. A
record it cannot encode is not stored and the poll cycle is logged as failed —
mining continues, and the interval is simply unbilled, which is the direction
this project fails in. The bound is about JavaScript, not the physics: 2⁵³
watt-hours is 9 PWh and 2⁵³ micro-euro is nine billion euro, four orders of
magnitude above anything a farm produces.

**Nothing new can raise an invoice.** The corroboration cap still only reduces.
An unrevealed or mismatched commitment makes an interval *unbillable*; it never
makes one billable that was not. A ledger with no commitments at all bills
exactly as 2.0.0 billed it.

### How it was checked

**Farm-bound signatures.**
`test_rules.py::test_the_rule_is_a_pure_function_of_the_day_and_the_activation`,
`::test_legacy_seals_are_byte_identical_to_v2_0_0`,
`::test_a_seal_signed_for_farm_a_does_not_verify_as_farm_b`,
`test_ledger.py::test_a_ledger_crossing_the_activation_date_seals_each_day_under_exactly_one_rule`,
`::test_activation_cannot_rewrite_the_rule_of_a_sealed_day`,
`::test_a_ledger_activated_for_another_farm_is_refused`,
`::test_legacy_records_before_activation_still_bill`,
`test_verifier.py::test_a_rule_1_seal_after_activation_is_refused`,
`::test_a_rule_2_seal_before_activation_is_refused`,
`::test_a_statement_for_another_farm_is_refused`,
`::test_the_activation_entry_cannot_be_moved_without_breaking_its_signature`.

**Commit/reveal.** `test_commit.py` (the state machine, including a reveal
whose nonce is wrong and one that points at the wrong sequence),
`test_agent.py::test_the_poll_loop_commits_before_it_measures` — which runs the
real loop and checks the *ordering*, not the code —
`::test_a_restart_leaves_one_unrevealed_commitment_and_no_mismatch`,
`test_ledger.py`'s billing tests (same farm, same telemetry, same claimed
energy: the ledger with commitments bills, the one without bills zero), and
`test_verifier.py::test_a_reveal_that_does_not_match_its_commit_fails_the_verifier`,
which asserts that the commitment check is the *only* thing that catches a
ledger whose chain, root, seal and signature all verify.

**The bill, recomputed.** `test_verifier.py::test_an_inflated_billable_total_is_caught_even_when_the_arithmetic_closes`.
Inflate the totals consistently and every check under "Billing arithmetic"
still passes, because they compare the statement with itself. Only re-deriving
the bill from the raw records catches it.

**The self-audit.** `test_selfaudit.py::test_the_self_audit_is_green_on_this_build`,
and four tests that reopen a closed finding — a console-writable fee, `chmod
644` on the signing key, a CSP that allows inline script, a token that is one
half typed twice — and require the audit to redden *that* line and no other.
`::test_the_report_states_what_it_did_not_check` pins the amber verdict, and
`::test_the_audit_writes_nothing` pins that it leaves no record, no seal and no
file behind. CI job `self-audit`, which fails on any amber line other than the
one release digest that is known not to exist yet.

**Cross-version compatibility.** `tools/compat/roundtrip.sh`, CI job `compat`.
Two virtualenvs, the published version and this tree, one ledger passed back
and forth. The assertion that matters is the reverse direction: the old
verifier on the new ledger must fail on exactly `seal signed by the device key`
for the days at or after the activation day, while chain, record count, Merkle
root, seal chaining, seal hash and inclusion proofs all still pass on records
carrying fields it has never seen. Each of those labels is asserted by name, as
the old verifier writes them — an assertion on an exit code would pass equally
against a script that checked nothing.

**The two canonical encoders.** `test_parity.py`, CI job `parity`. Sixteen
pinned vectors, hashed in Python and in Node running `web/canonical.js` itself,
required to agree with each other *and* with the pin. Reverting the JavaScript
key comparator to `Array.prototype.sort` turns the corpus red on the
code-point entry by name, with both encodings printed; that was checked before
the change was committed. `test_canonical.py::test_integers_beyond_2_53_are_refused`
and `test_parity.py::test_node_refuses_the_same_things` pin the new bound on
both sides, and `::test_booleans_are_not_measured_against_the_integer_bound`
pins the mistake that would have refused every record in the ledger.

316 tests, green on Python 3.10, 3.11 and 3.12. Eight CI jobs: three test
matrices, `zero-dependency-check`, `parity`, `compat`, `self-audit`,
`end-to-end-verification`.

### What is still missing

- **No `v2.0.0` tag exists**, so `tools/compat/roundtrip.sh` resolves it to the
  v2 merge commit and says so loudly every run. Tag the release; a comparison
  that names a commit instead of a version is one nobody can repeat from the
  notes alone.
- **No published `SHA256SUMS`**, so the self-audit's build-digest check is
  permanently **NOT CHECKED**. `tools/package_digest.py` prints the line a
  release would publish. Until it is published, an operator cannot tell this
  build from a modified one, and the audit says exactly that rather than
  leaving the line out.
- **The self-audit runs inside the process it audits.** It catches regression
  and misconfiguration, not a hostile build. The published digest above is the
  only defence against that, which is why its absence is reported and not
  hidden.
- **Key rotation has no ceremony.** One device key, no rotation, no revocation.
  Rotating today means seals before and after are signed by different keys and
  a verifier must be handed both.
- **A duplicated installation carries its farm id with it.** Farm binding stops
  a seal being presented as another farm's; it does not stop someone copying a
  whole installation. What the client gets is a visible symptom — the same farm
  id and fingerprint on two farms — rather than a silent one, and only if they
  compared the fingerprint out of band once.
- **The token check measures shape, not secrecy.** Length, alphabet, distinct
  characters and repetition are all that can be read off a string.
- **Solutions 4, 7, 8, 9, 10 and 11 of `docs/PLAN_v2.1.md` are not built.**
  Network and process inventory, graded sources, the verified updater, the
  encrypted delivery tunnel, the console check with generated i18n, and this
  file's own automation. They are planned there with files, tests and estimates.

See [`PENDING-v2.1.0.md`](PENDING-v2.1.0.md) for what was verified on this
branch and how each piece is built, for whoever touches it next.

---

## 2.0.0 — the rewrite

The v1 agent was a single file with ten findings at High severity. All of them,
with the code that was wrong and the test that fails if it is reopened, are in
[`docs/AUDIT_v1.md`](docs/AUDIT_v1.md).

### What it costs

Everything the ledger records is now an integer in a declared minor unit, and
the canonical encoder refuses to hash a float — so v1 ledgers do not carry
forward and there is no migration. `numpy` and `requests` were removed, which
means the median and the least-squares slope are hand-written and slightly
slower on a very large farm, in exchange for no third-party code between a
miner's socket and a signed record.

### How it was checked

199 tests. The detection rule was measured over 40 seeded runs of a simulated
18-board farm (`tests/test_qtmp.py`): false alerts per healthy run fell from
4.67 to 0.25 with the degrading board still caught 40 times out of 40. The
adaptive loop settles at 2.02σ against an ideal of 2.045.
`scripts/demo_verification.py` builds a month, verifies it, breaks it and
requires the verifier to catch it, in CI.

### What is still missing

Everything listed under 2.1.0's own missing section, plus the two findings
2.1.0 answers: seals named no farm, and a decision could be written to fit a
measurement.
