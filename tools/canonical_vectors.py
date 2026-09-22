#!/usr/bin/env python3
"""Build (and pin) the corpus the two canonical encoders are compared on.

``tests/vectors/canonical.json`` holds, for every entry, the value, the exact
canonical bytes it must encode to, and the record hash of those bytes. The
parity test then requires three things at once:

* Python reproduces the pin,
* Node, running ``web/canonical.js``, reproduces the pin,
* and the two agree with each other.

Three, not two, on purpose. Checking only that Python and Node agree would
pass happily on the day both are changed in the same wrong way -- a rename of
a field, a different escape, a sort that moved. The pin is what makes such a
change visible, and regenerating the pin is a deliberate act with this script
and a commit message that says why.

    python3 tools/canonical_vectors.py --print     # show what would be written
    python3 tools/canonical_vectors.py --write     # rewrite the pins

Anything JavaScript cannot represent has no place in the corpus, because it has
no place in the ledger either: floats, integers past 2^53, lone surrogates.
Those are covered by the refusal tests instead, which is the honest home for a
value whose *correct* behaviour is an error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from hashguard.canonical import MAX_SAFE_INT, canonical_bytes, record_hash  # noqa: E402

VECTORS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "tests", "vectors", "canonical.json"
)


def cases() -> list[dict]:
    """Every case is here because something could plausibly differ between the two.

    Each carries a one-line reason, so that a failure names the property that
    broke rather than an opaque index into a list.
    """
    return [
        {
            "name": "empty object",
            "why": "the degenerate case both encoders have to get right",
            "value": {},
        },
        {
            "name": "empty array",
            "why": "an empty list is not null and not an empty object",
            "value": [],
        },
        {
            "name": "scalars",
            "why": "null, true and false must not be quoted or capitalised differently",
            "value": {"n": None, "t": True, "f": False},
        },
        {
            "name": "zero and negative zero",
            "why": "JavaScript has -0 and Python does not; both must write 0",
            "value": {"zero": 0, "neg": -0, "one": 1, "minus": -1},
        },
        {
            "name": "the safe integer bound",
            "why": "the last integers the two languages still agree about",
            "value": {"high": MAX_SAFE_INT, "low": -MAX_SAFE_INT},
        },
        {
            "name": "nesting",
            "why": "arrays inside objects inside arrays, with no whitespace anywhere",
            "value": {"a": [{"b": [1, {"c": []}]}, []], "d": {"e": {"f": {}}}},
        },
        {
            "name": "numeric-looking keys sort as strings",
            "why": "\"10\" sorts before \"9\"; an encoder that sorts numerically disagrees",
            "value": {"9": 9, "10": 10, "1": 1, "100": 100, "2": 2},
        },
        {
            "name": "ascii key order",
            "why": "uppercase sorts before lowercase, and '_' before lowercase letters",
            "value": {"b": 1, "A": 2, "a": 3, "_": 4, "B": 5, "-": 6, "0": 7},
        },
        {
            "name": "unicode key order",
            "why": "accented and non-latin keys sort by code point, not by locale",
            "value": {"\u00e9": 1, "e": 2, "z": 3, "\u00e4": 4, "Z": 5, "\u65e5": 6, "\u0436": 7},
        },
        {
            "name": "the code-point trap",
            "why": (
                "U+1F600 is above U+FFFF and sorts *after* U+E000 by code point, but its "
                "UTF-16 lead unit 0xD83D sorts *before* it. A JavaScript sort() that "
                "compares code units puts these two keys the other way round"
            ),
            "value": {"\U0001F600": "astral", "\ue000": "private use", "\uffff": "bmp end"},
        },
        {
            "name": "every json escape",
            "why": "\\b \\t \\n \\f \\r get short forms; other controls get \\u00xx",
            "value": {
                "quote": '"',
                "backslash": "\\",
                "solidus": "/",
                "backspace": "\b",
                "formfeed": "\f",
                "newline": "\n",
                "carriage": "\r",
                "tab": "\t",
                "null byte": "\u0000",
                "unit separator": "\u001f",
            },
        },
        {
            "name": "characters that are not escaped",
            "why": (
                "DEL, U+2028 and U+2029 are written raw by both encoders. They look like "
                "they ought to be escaped and are not, which is exactly why they are pinned"
            ),
            "value": {"del": "\u007f", "ls": "\u2028", "ps": "\u2029", "nbsp": "\u00a0"},
        },
        {
            "name": "non-bmp text",
            "why": "a character outside the BMP is one code point and two UTF-16 units",
            "value": {"emoji": "\U0001F510 \U0001F600", "cjk ext": "\U00020000"},
        },
        {
            "name": "strings that look like other types",
            "why": "a quoted number must stay quoted on both sides",
            "value": {"a": "1", "b": "true", "c": "null", "d": "0.1", "e": "1e5", "f": "-0"},
        },
        {
            "name": "a ledger record",
            "why": "the shape actually hashed into a Merkle leaf, with commit and reveal",
            "value": {
                "action": "PAUSE",
                "at": "2026-09-14T08:00:00Z",
                "baseline_gh": 400000,
                "breakeven_ppm_per_kwh": 57000,
                "claimed_mining_lost_micro_eur": 619200,
                "claimed_wh": 48000,
                "commit": "7f" * 32,
                "day": "2026-09-14",
                "executed": True,
                "n_miners": 4,
                "observed_gh": 0,
                "opened": "2026-09-14T04:00:00Z",
                "prev": "00" * 32,
                "price_curve_hash": "3c" * 32,
                "price_ppm_per_kwh": 210000,
                "reveal": {"commit_seq": 41, "nonce": "ab" * 32},
                "seconds": 14400,
                "seq": 42,
                "spec": "hashguard-ledger/2",
            },
        },
        {
            "name": "a seal body",
            "why": "what the device signature is computed over",
            "value": {
                "day": "2026-09-14",
                "farm_id": "5e" * 32,
                "leaf_count": 6,
                "merkle_root": "11" * 32,
                "prev_seal": "22" * 32,
                "rule": 2,
                "seal_hash": "33" * 32,
                "sealed_at": "2026-09-15T00:00:12Z",
                "spec": "hashguard-ledger/2",
            },
        },
    ]


def build() -> dict:
    entries = []
    for case in cases():
        encoded = canonical_bytes(case["value"])
        entries.append(
            {
                "name": case["name"],
                "why": case["why"],
                "value": case["value"],
                "canonical": encoded.decode("utf-8"),
                "record_hash": record_hash(case["value"]).hex(),
            }
        )
    return {
        "note": (
            "Pinned by tools/canonical_vectors.py. Every entry must encode to exactly "
            "these bytes and hash to exactly this digest, in hashguard/canonical.py and "
            "in web/canonical.js alike. Regenerate only on purpose: a moved pin is a "
            "change to the format every existing ledger was written in."
        ),
        "max_safe_int": MAX_SAFE_INT,
        "entries": entries,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="canonical_vectors", description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--print", dest="show", action="store_true", help="print, do not write")
    group.add_argument("--write", action="store_true", help="rewrite tests/vectors/canonical.json")
    args = parser.parse_args(argv)

    document = json.dumps(build(), indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    if args.show:
        sys.stdout.write(document)
        return 0
    os.makedirs(os.path.dirname(VECTORS_PATH), exist_ok=True)
    with open(VECTORS_PATH, "w", encoding="utf-8") as handle:
        handle.write(document)
    print(f"wrote {len(build()['entries'])} vectors to {os.path.relpath(VECTORS_PATH)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
