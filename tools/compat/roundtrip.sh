#!/usr/bin/env bash
#
# Cross-version round trip: the published version and this one, over one ledger.
#
# A format is not what the specification says. It is what the released binaries
# actually write and actually accept. So this script installs the published
# version and the working tree side by side, in two virtual environments, and
# makes them hand a single ledger back and forth:
#
#   1. OLD writes a month, seals it, and states it.
#   2. NEW verifies OLD's statement.               -- a new release must not
#                                                     break an old ledger.
#   3. NEW opens OLD's ledger, activates farm-bound signatures from a day after
#      the last sealed one, appends its own days with commit/reveal, seals and
#      states them.
#   4. NEW verifies both statements.
#   5. OLD verifies NEW's statement, and the ONLY thing it may fail on is the
#      signature of the days sealed under the new rule. Chain, roots, seal
#      hashes and inclusion proofs must all still pass, on records carrying
#      fields OLD has never heard of.
#   6. OLD, on NEW's ledger, refuses to seal a day under the old rule after the
#      activation day -- and when it does write one anyway, NEW refuses it.
#
# Step 5 is the interesting one. "The old version keeps working and says exactly
# where it stops understanding" is a property that cannot be tested inside one
# version's test suite, because both halves of the comparison would be the same
# code. Ported from RAMI-Chain's tools/compat/roundtrip.sh.
#
# Usage:  tools/compat/roundtrip.sh [OLD_REF]      (default: v2.0.0)

set -euo pipefail

OLD_REF="${1:-v2.0.0}"
# The v2.0.0 tree exists as the merge commit of the v2 pull request; the tag
# itself has not been created yet. Resolve the tag when it is there and fall
# back with a loud note when it is not, rather than silently comparing the
# working tree with itself -- which would make this script pass by testing
# nothing at all. Noted in PENDING-v2.1.0.md: create the tag.
FALLBACK_V2_0_0="2ea210c"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'cd "$REPO_ROOT" && git worktree remove --force "$WORK/old" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fact() { printf '   %s\n' "$*"; }
die()  { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$REPO_ROOT"

if git rev-parse -q --verify "${OLD_REF}^{commit}" >/dev/null; then
  OLD_SHA="$(git rev-parse "${OLD_REF}^{commit}")"
  fact "old version: ${OLD_REF} (${OLD_SHA:0:10})"
elif [ "$OLD_REF" = "v2.0.0" ] && git rev-parse -q --verify "${FALLBACK_V2_0_0}^{commit}" >/dev/null; then
  OLD_SHA="$(git rev-parse "${FALLBACK_V2_0_0}^{commit}")"
  printf '\033[33mNOTE\033[0m  there is no v2.0.0 tag in this repository; using the v2 merge\n'
  printf '      commit %s instead. Create the tag so this comparison names a release.\n' "${OLD_SHA:0:10}"
else
  die "cannot resolve '${OLD_REF}' to a commit, and there is no fallback for it"
fi

if [ "$OLD_SHA" = "$(git rev-parse HEAD)" ]; then
  die "the old ref and HEAD are the same commit; this would compare the tree with itself"
fi

# -- two trees, two environments -------------------------------------------

say "Installing both versions"
git worktree add --detach "$WORK/old" "$OLD_SHA" >/dev/null 2>&1
python3 -m venv "$WORK/venv-old"
python3 -m venv "$WORK/venv-new"
OLD_PY="$WORK/venv-old/bin/python"
NEW_PY="$WORK/venv-new/bin/python"
"$WORK/venv-old/bin/pip" install -q --disable-pip-version-check -e "$WORK/old" >/dev/null
"$WORK/venv-new/bin/pip" install -q --disable-pip-version-check -e "$REPO_ROOT" >/dev/null

# Both must sign the same way, or step 5 would be comparing signature backends
# rather than signature *rules*. Install cryptography in both, or in neither.
if "$NEW_PY" -c "import cryptography" 2>/dev/null; then
  BACKEND="ed25519 (cryptography already present)"
elif "$WORK/venv-new/bin/pip" install -q --disable-pip-version-check "cryptography>=41" >/dev/null 2>&1 \
  && "$WORK/venv-old/bin/pip" install -q --disable-pip-version-check "cryptography>=41" >/dev/null 2>&1; then
  BACKEND="ed25519 (cryptography installed into both)"
else
  BACKEND="hmac-sha256 (cryptography unavailable; both versions degrade alike)"
fi
fact "signature backend: $BACKEND"

DRIVER="$REPO_ROOT/tools/compat/build_days.py"
OLD_VERIFY="$WORK/old/tools/hashguard_verify.py"
NEW_VERIFY="$REPO_ROOT/tools/hashguard_verify.py"
LEDGER="$WORK/ledger"
KEY="$WORK/device_key.json"
PUB="$WORK/device_public.json"

fact "old capabilities: $("$OLD_PY" "$DRIVER" capabilities | tr -d '\n ' )"
fact "new capabilities: $("$NEW_PY" "$DRIVER" capabilities | tr -d '\n ' )"

# Dates are relative to today so the script never needs a clock that agrees
# with a fixture, and never seals a day that has not finished.
day_before() { "$NEW_PY" -c "import datetime,sys;print((datetime.date.today()-datetime.timedelta(days=int(sys.argv[1]))).isoformat())" "$1"; }
LAST_OLD_DAY="$(day_before 11)"     # the old version seals up to here
ACTIVATE_FROM="$(day_before 10)"    # farm-bound signatures begin here
LAST_NEW_DAY="$(day_before 2)"      # the new version seals up to here
DOWNGRADE_DAY="$(day_before 1)"     # finished, unsealed: step 6 works here
OLD_MONTH="${LAST_OLD_DAY:0:7}"
NEW_MONTH="${LAST_NEW_DAY:0:7}"
DOWNGRADE_MONTH="${DOWNGRADE_DAY:0:7}"

# -- helpers ----------------------------------------------------------------

# Run a verifier and keep its output; never let set -e swallow the exit code.
verify() {   # verify <python> <verifier> <statement> <label-file>
  local py="$1" tool="$2" statement="$3" out="$4"
  set +e
  "$py" "$tool" "$statement" --records "$LEDGER/records" --pubkey "$PUB" \
    2>&1 | sed -e 's/\x1b\[[0-9;]*m//g' > "$out"
  local code=${PIPESTATUS[0]}
  set -e
  echo "$code"
}

failures_in() { grep -E '^  FAIL ' "$1" | sed -e 's/^  FAIL  //' || true; }

# -- 1. OLD writes ----------------------------------------------------------

say "1. The published version writes a month and seals it"
"$OLD_PY" "$DRIVER" write --ledger "$LEDGER" --key "$KEY" --days 12 --end "$LAST_OLD_DAY"
"$OLD_PY" "$DRIVER" seal --ledger "$LEDGER" --key "$KEY"
"$OLD_PY" "$DRIVER" pubkey --key "$KEY" --out "$PUB"
"$OLD_PY" "$DRIVER" statement --ledger "$LEDGER" --key "$KEY" \
  --month "$OLD_MONTH" --out "$WORK/old-statement.json"
[ -f "$LEDGER/activation.json" ] && die "the old version wrote an activation entry it does not know about"
fact "no activation.json: the old ledger is exactly what 2.0.0 writes"

# -- 2. NEW verifies OLD ----------------------------------------------------

say "2. This version verifies the published version's statement"
code="$(verify "$NEW_PY" "$NEW_VERIFY" "$WORK/old-statement.json" "$WORK/new-on-old.txt")"
[ "$code" = "0" ] || { cat "$WORK/new-on-old.txt"; die "a new release broke an old ledger"; }
grep -q 'predates farm-bound signatures' "$WORK/new-on-old.txt" \
  || die "the new verifier passed an unbound statement without saying it was unbound"
grep -q 'pre-2.1\|not signed as a whole' "$WORK/new-on-old.txt" \
  || die "the new verifier did not say which checks it could not make"
fact "passed, with the notes that name what it could not check"

# -- 3. NEW appends, activating from a day after the last sealed one --------

say "3. This version opens that ledger, activates farm binding, and appends"
# Refused if it would change the rule of a day that is already sealed. Assert
# that first: the whole design rests on a sealed day's rule never moving.
set +e
HASHGUARD_ACTIVATE_FROM="$LAST_OLD_DAY" "$NEW_PY" "$DRIVER" \
  write --ledger "$LEDGER" --key "$KEY" --days 1 --end "$LAST_NEW_DAY" \
  > "$WORK/backdate.txt" 2>&1
backdate=$?
set -e
[ "$backdate" -eq 0 ] && { cat "$WORK/backdate.txt"; die "activation was accepted on an already-sealed day"; }
grep -q 'already sealed' "$WORK/backdate.txt" \
  || { cat "$WORK/backdate.txt"; die "activation was refused, but not for the sealed-day reason"; }
fact "back-dating the activation onto a sealed day is refused, and says why"

HASHGUARD_ACTIVATE_FROM="$ACTIVATE_FROM" "$NEW_PY" "$DRIVER" \
  write --ledger "$LEDGER" --key "$KEY" --days 9 --end "$LAST_NEW_DAY"
# Seal only through $LAST_NEW_DAY, leaving $DOWNGRADE_DAY finished and
# unsealed. Step 6 needs a day the old version can still seal for itself, or
# it would be refusing a broken Merkle root rather than the signature rule.
"$NEW_PY" "$DRIVER" seal --ledger "$LEDGER" --key "$KEY" --through "$LAST_NEW_DAY"
"$NEW_PY" "$DRIVER" statement --ledger "$LEDGER" --key "$KEY" \
  --month "$NEW_MONTH" --out "$WORK/new-statement.json"
"$NEW_PY" "$DRIVER" pubkey --key "$KEY" --out "$PUB"

perms="$(stat -c '%a' "$KEY")"
[ "$perms" = "600" ] || die "the key file came back $perms after the new version rewrote it"
fact "key file still 0600 after being given a farm id"
"$NEW_PY" - "$KEY" <<'PY'
import json, sys
key = json.load(open(sys.argv[1]))
assert key.get("farm_id"), "the new version did not write a farm id"
assert len(key["farm_id"]) == 64, key["farm_id"]
print(f"   farm id {key['farm_id'][:16]}... added to the key the old version made")
PY

# -- 4. NEW verifies both ---------------------------------------------------

say "4. This version verifies both statements"
code="$(verify "$NEW_PY" "$NEW_VERIFY" "$WORK/new-statement.json" "$WORK/new-on-new.txt")"
[ "$code" = "0" ] || { cat "$WORK/new-on-new.txt"; die "the new version cannot verify its own statement"; }
code="$(verify "$NEW_PY" "$NEW_VERIFY" "$WORK/old-statement.json" "$WORK/new-on-old-2.txt")"
[ "$code" = "0" ] || { cat "$WORK/new-on-old-2.txt"; die "appending broke the month the old version sealed"; }
fact "both pass, and the old month still passes after being appended to"

# -- 5. OLD verifies NEW, and must fail on exactly one thing ----------------

say "5. The published version verifies this version's statement"
code="$(verify "$OLD_PY" "$OLD_VERIFY" "$WORK/new-statement.json" "$WORK/old-on-new.txt")"
mapfile -t fails < <(failures_in "$WORK/old-on-new.txt")
printf '   the old verifier reported %d failure(s)\n' "${#fails[@]}"
[ "${#fails[@]}" -gt 0 ] || die "the old version verified rule-2 signatures it cannot compute"

unexpected=()
for line in "${fails[@]}"; do
  day="${line%%:*}"
  rest="${line#*: }"
  if [ "$rest" = "seal signed by the device key" ] && [[ "$day" > "$ACTIVATE_FROM" || "$day" == "$ACTIVATE_FROM" ]]; then
    continue
  fi
  unexpected+=("$line")
done
if [ "${#unexpected[@]}" -ne 0 ]; then
  printf '   unexpected failure: %s\n' "${unexpected[@]}"
  cat "$WORK/old-on-new.txt"
  die "the old version stops understanding more than the signature rule"
fi
# Labels as the OLD verifier writes them -- this is the point of running it
# rather than reimplementing it. If a label moved, this loop says so instead of
# silently checking nothing.
for check in 'chain unbroken' 'record count matches the seal' \
             'records reproduce the sealed Merkle root' \
             'seal chains to the previous sealed day' \
             'seal_hash = SHA256d(prev_seal || root)' \
             'is in the sealed tree'; do
  grep -qF "$check" "$WORK/old-on-new.txt" \
    || die "the old verifier ran no '$check' check; its output shape has changed"
  if grep -F "$check" "$WORK/old-on-new.txt" | grep -q '^  FAIL'; then
    die "'$check' failed on records carrying fields the old version has never seen"
  fi
  printf '   old verifier still passes: %s\n' "$check"
done
fact "every failure is 'seal signed by the device key' on a day at or after $ACTIVATE_FROM"
fact "chain, Merkle root, seal hash and inclusion proofs all still pass"

# -- 6. the downgrade, and the rule that does not regress -------------------

say "6. The published version seals a day under the old rule; this one refuses it"
# The regression that would undo the whole change: after activation, go on
# sealing days in the format that names no farm. The old version does it
# without knowing it is doing anything, which is exactly why the *date* has to
# decide and not the seal. $DOWNGRADE_DAY is finished and unsealed, so what is
# being refused below is the rule and not a broken Merkle root.
"$OLD_PY" "$DRIVER" write --ledger "$LEDGER" --key "$KEY" --days 1 --end "$DOWNGRADE_DAY" >/dev/null
"$OLD_PY" "$DRIVER" seal --ledger "$LEDGER" --key "$KEY" --through "$DOWNGRADE_DAY"
fact "the old version sealed $DOWNGRADE_DAY under rule 1, on a ledger activated from $ACTIVATE_FROM"

# 6a. The farm's own 2.1 statement carries the activation entry, so the rule
#     for every day in it is derived, not taken on the seal's word.
"$NEW_PY" "$DRIVER" statement --ledger "$LEDGER" --key "$KEY" \
  --month "$DOWNGRADE_MONTH" --out "$WORK/rule1-after-activation.json"
code="$(verify "$NEW_PY" "$NEW_VERIFY" "$WORK/rule1-after-activation.json" "$WORK/new-on-rule1.txt")"
[ "$code" = "0" ] && { cat "$WORK/new-on-rule1.txt"; die "the new verifier accepted a rule-1 seal written after activation"; }
mapfile -t rule1_fails < <(failures_in "$WORK/new-on-rule1.txt")
rule_line="${DOWNGRADE_DAY}: sealed under the signature rule its date requires"
found=0
for line in "${rule1_fails[@]}"; do
  [ "$line" = "$rule_line" ] && found=1
done
[ "$found" -eq 1 ] || {
  printf '   failures were: %s\n' "${rule1_fails[@]}"
  cat "$WORK/new-on-rule1.txt"
  die "the new verifier refused it, but not by name: no '$rule_line'"
}
grep -q "must be rule 2" "$WORK/new-on-rule1.txt" \
  || die "the refusal does not say which rule that day required"
fact "refused by name: '$rule_line', and the message says which rule that day required"

# 6b. The full downgrade: a statement written by the old version, which drops
#     the activation entry along with everything else it does not know about.
#     It must not verify -- and the reader must be told that the document
#     itself is what stopped carrying the binding, not the ledger.
"$OLD_PY" "$DRIVER" statement --ledger "$LEDGER" --key "$KEY" \
  --month "$DOWNGRADE_MONTH" --out "$WORK/downgraded.json"
code="$(verify "$NEW_PY" "$NEW_VERIFY" "$WORK/downgraded.json" "$WORK/new-on-downgraded.txt")"
[ "$code" = "0" ] && { cat "$WORK/new-on-downgraded.txt"; die "the new verifier accepted a statement that dropped the farm binding"; }
mapfile -t downgrade_fails < <(failures_in "$WORK/new-on-downgraded.txt")
for line in "${downgrade_fails[@]}"; do
  case "$line" in
    *": seal signed by the device key") ;;
    *) printf '   failures were: %s\n' "${downgrade_fails[@]}"
       cat "$WORK/new-on-downgraded.txt"
       die "the downgraded statement failed on something other than the seal signatures: $line" ;;
  esac
done
grep -q 'predates farm-bound signatures' "$WORK/new-on-downgraded.txt" \
  || die "the new verifier did not say the downgraded statement carries no activation entry"
fact "refused on the rule-2 days' signatures, and told plainly that the document names no farm"

say "Round trip complete"
fact "old: ${OLD_SHA:0:10}   new: $(git rev-parse --short HEAD)"
fact "the old version keeps working on a new ledger, and says exactly where it stops"
