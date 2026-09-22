# PENDING — v2.1.0

What was verified on this branch, how each piece is built for whoever touches
it next, and what is left. Kept in the repository rather than in a tracker
because the person who needs it most is the one reading this code in a year
with no access to the conversation that produced it.

---

## What was verified, and by what

| Claim | Verified by | Where it runs |
|---|---|---|
| A seal names its farm from the activation day, and never before | `test_rules.py`, `test_ledger.py::test_a_ledger_crossing_the_activation_date_seals_each_day_under_exactly_one_rule` | `tests` |
| A sealed day's rule never moves | `test_ledger.py::test_activation_cannot_rewrite_the_rule_of_a_sealed_day`, and step 3 of `roundtrip.sh` | `tests`, `compat` |
| A pre-activation day is signed byte for byte as 2.0.0 signed it | `test_rules.py::test_legacy_seals_are_byte_identical_to_v2_0_0` | `tests` |
| The decision is committed before the telemetry is read | `test_agent.py::test_the_poll_loop_commits_before_it_measures` | `tests` |
| An unrevealed or broken commitment is unbillable, never billable | `test_ledger.py` billing tests | `tests` |
| A legacy ledger bills exactly as 2.0.0 billed it | `test_ledger.py::test_legacy_records_before_activation_still_bill` | `tests` |
| The bill is re-derivable from the raw records | `test_verifier.py::test_an_inflated_billable_total_is_caught_even_when_the_arithmetic_closes` | `tests` |
| Every v1 finding still holds on a live agent | `test_selfaudit.py`, `hashguard --self-audit` | `tests`, `self-audit` |
| Reopening a finding turns exactly one audit line red | four tests in `test_selfaudit.py` | `tests` |
| 2.0.0 keeps working on a 2.1 ledger and says where it stops | `tools/compat/roundtrip.sh` step 5 | `compat` |
| Python and the browser hash identically | `test_parity.py` | `tests`, `parity` |
| The agent runs on the standard library alone | `pip list` assertion + a demo run with no extras | `zero-dependency-check` |

Eight CI jobs: `tests` on 3.10/3.11/3.12, `zero-dependency-check`, `parity`,
`compat`, `self-audit`, `end-to-end-verification`.

---

## How each piece is built

### `rules.py` — which rule governs a day

`seal_rule_for(day, from_day)` is a **pure function**, and everything derives
the rule through it: the ledger when sealing, both verifiers when checking, the
console when displaying. Nothing anywhere reads the rule off the seal and
believes it when an activation day is available. That is the whole design: a
seal's own claim about its rule is not evidence, because a forger would make
the same claim.

`from_day is None` means the legacy rule for every day — which is exactly a
2.0.0 ledger, and exactly what a reader holding no activation entry can
honestly conclude.

### `commit.py` — commit/reveal

Record *N* carries `commit`, the commitment for the interval that *opens* at
record *N*. Record *N+1* carries `reveal` with the nonce and `commit_seq: N`.
So a reveal is always read against its **predecessor**, and `reveal_state`
takes both.

The trap to know about: at a day boundary the predecessor lives in the previous
day's file. `GuardedLedger.record_before(day)` crosses it. A reader that stops
at the file boundary silently stops billing one interval per day, which is the
kind of bug that looks like rounding.

Four states, and the difference matters: `revealed` bills; `unrevealed` is the
ordinary result of a restart and does not bill and does not accuse;
`mismatched` does not bill and *does* accuse; `legacy` is a pre-2.1 record and
bills as 2.0.0 billed it.

### `selfaudit.py` — the v1 findings, replayed

Each probe is a function returning a sentence describing what it *observed*, or
raising. A raised `NotChecked` is amber; any other exception is red. That
asymmetry is deliberate: a probe that cannot conclude must not print PASS, but
a gap in the environment must not print FAIL either.

Two things to preserve if you touch it:

- **`AUDIT-06` runs last.** It ends with the audit's own address blocked on the
  audit's own server. Anything after it measures that block.
- **Every probe must break something.** `_audit_05_ledger` verifies the real
  ledger *and then tampers with a copy and requires the same function to
  notice*. A check that only confirms the good case would pass against a
  function that returns `True` unconditionally, which is how a self-check
  becomes decorative.

The audit serves a **deep copy** of the config on its own `AgentState` with its
own rate limiter, so a probe aimed at the write surface cannot reach live
settings even if the write surface is what regressed.

### `tools/compat/roundtrip.sh` — the cross-version test

Two virtualenvs, one ledger. `build_days.py` runs unchanged under both versions
and detects capability from `dataclasses.fields(Interval)` rather than from a
version string — a version string is a claim, a field list is a fact.

Two arrangements exist only to make step 5 mean something:

- The new version seals **through `today-2`**, leaving `today-1` finished and
  unsealed, so the old version has a day it can legitimately seal for itself.
  Without that gap, step 6 would be refusing a broken Merkle root and calling
  it a refused signature rule.
- Step 5 asserts the old verifier's **labels by name**, as the old verifier
  writes them. An assertion on an exit code would pass just as happily against
  a script that checked nothing.

There is no `v2.0.0` tag, so the script falls back to the v2 merge commit
`2ea210c` and prints a note every run. **Tag the release.**

### `web/canonical.js` and the parity corpus

The encoder lives in its own file so the file the browser loads is the file the
test hashes. A copy kept beside the test would agree with the test and drift
from the page. `test_parity.py::test_the_console_loads_the_same_encoder_the_test_hashes`
fails if `console.js` grows its own `canonical()` again.

Three assertions, not two: Python matches the pin, Node matches the pin, and
the two match each other. Two of the three would each miss a real failure mode.
Regenerating the pin is `tools/canonical_vectors.py --write`, and CI diffs the
corpus against what the generator builds, so a pin edited by hand fails.

---

## The load-flakiness rule, from RAMI's `PENDIENTE-v0.10.16.md`

RAMI's `oversized_frame_disconnects_peer` read a peer count **once**, right
after an event that a later refresh updated. It passed on a quiet machine and
took down the v0.10.7 release under load.

The rule that came out of it: **no test reads once a state that another thread
updates later. It waits, with a deadline.**

Where this suite stands against it today:

- `test_api.py` starts a server thread, but every request blocks on its own
  response, so nothing reads a state a thread is still writing.
- `test_selfaudit.py` is the same shape: the audit's probes are synchronous
  request/response against a server whose only job is to answer them.
- `test_agent.py` calls `poll_once` directly rather than starting `poll_loop`,
  so the ordering it asserts is the ordering in the file, with no scheduler in
  between.

**No `wait_until(predicate, deadline)` helper exists yet**, because nothing in
the suite needs one. Add it the first time a test wants to observe a thread,
and do not add a `sleep` instead.

---

## What is left

### Before tagging 2.1.0

1. **Create the `v2.0.0` tag** on `2ea210c`, and `v2.1.0` on this merge.
   `roundtrip.sh` then names versions instead of commits.
2. **Publish `SHA256SUMS`** for the release, with the line
   `tools/package_digest.py` prints. Until then `--self-audit` reports the
   build-digest check as NOT CHECKED, permanently and by design.
3. **The founder photograph** at `web/founder.jpg`. It was requested in the
   pull request that added the "Who's behind it" section and never arrived;
   the CSS layer that paints over the `RB` initials is already in place, so the
   file is the only thing needed. No code change.

### Planned, not built (`docs/PLAN_v2.1.md` has files, tests and estimates)

| | | Estimate |
|---|---|---|
| 4 | Network and process inventory with an approved list | ~6 h |
| 7 | Graded sources and the exact word (Admiralty / ICD 203) | ~5 h |
| 10 | Console check and generated i18n | ~4 h |
| 11 | The discipline of each version, automated | ~3 h |
| 8 | Verified updater and a release with sums | ~7 h |
| 9 | Authenticated, encrypted tunnel for statement delivery | ~10 h |

### Deliberately not ported from RAMI-Chain

The multiverse of branches, the Collatz tie-break and the advisory neural
network. All three solve **distributed consensus** — which fork wins when
honest nodes disagree. A single-farm ledger has one writer and no fork, so
porting them would add machinery with nothing to decide. `adaptive.py` remains
the only adaptive layer here, and it still never touches billing.

### Known limits, carried forward

Listed in full under "What is still missing" in
[`RELEASE_NOTES.md`](RELEASE_NOTES.md) and in the out-of-scope section of
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). The two worth repeating here
because they bound what any of the above can promise:

- **The self-audit runs inside the process it audits.** It catches regression
  and misconfiguration, not a hostile build. Only the published digest answers
  that, which is why its absence is item 2 above.
- **A key file copied after activation carries the farm id with it.** Farm
  binding gives the client a visible symptom — one farm id on two farms —
  rather than a silent one. It is not a defence against a duplicated
  installation.
