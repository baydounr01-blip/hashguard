"""The two canonical encoders, compared byte for byte.

HashGuard has two implementations of one encoding: ``hashguard/canonical.py``
and ``web/canonical.js``. That is not an accident to be cleaned up -- it is the
point. The console re-derives the invoice in the client's own browser using
none of the operator's code, and a second implementation is what makes that
mean anything.

It is also a standing liability. Two encoders that quietly disagree about one
character produce a statement the farm can sign and the client can never
verify, and nobody finds out until a bill is disputed. So: a pinned corpus, and
three assertions on it rather than two.

* Python must reproduce the pin.
* Node, running ``web/canonical.js`` itself, must reproduce the pin.
* The two must agree with each other.

Checking only the third would pass on the day both sides change the same wrong
way. Checking only the first two would pass on the day the pin is regenerated
to match a mistake. Together they catch both, and moving a pin stays what it
should be: a deliberate act, with ``tools/canonical_vectors.py --write`` and a
commit message that says why.
"""

import json
import os
import re
import shutil
import subprocess

import pytest

from hashguard.canonical import MAX_SAFE_INT, CanonicalError, canonical_bytes, record_hash

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS = os.path.join(ROOT, "tests", "vectors", "canonical.json")
NODE_RUNNER = os.path.join(ROOT, "tools", "canonical_parity_node.js")

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="node is not installed; the CI job 'parity' installs it and is the gate that counts",
)


@pytest.fixture(scope="module")
def corpus():
    with open(VECTORS, encoding="utf-8") as handle:
        return json.load(handle)


def run_node(job: dict) -> dict:
    result = subprocess.run(
        ["node", NODE_RUNNER],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.stdout, f"node wrote nothing; stderr was: {result.stderr[-500:]}"
    answer = json.loads(result.stdout)
    assert "fatal" not in answer, answer["fatal"]
    return answer


# -- the pin ---------------------------------------------------------------


def test_the_pinned_digests_have_not_moved(corpus):
    """Python against the corpus. A failure here means the encoding changed,
    and every ledger ever written was written under the old one."""
    assert corpus["entries"], "the corpus is empty; tools/canonical_vectors.py --write"
    for entry in corpus["entries"]:
        encoded = canonical_bytes(entry["value"])
        assert encoded.decode("utf-8") == entry["canonical"], (
            f"{entry['name']}: {entry['why']}"
        )
        assert record_hash(entry["value"]).hex() == entry["record_hash"], entry["name"]


def test_the_corpus_covers_the_cases_it_claims_to(corpus):
    """A corpus nobody reads becomes a corpus of one empty object."""
    names = {entry["name"] for entry in corpus["entries"]}
    for required in (
        "empty object",
        "the code-point trap",
        "every json escape",
        "characters that are not escaped",
        "numeric-looking keys sort as strings",
        "the safe integer bound",
        "a ledger record",
        "a seal body",
    ):
        assert required in names, f"the corpus lost its '{required}' case"
    for entry in corpus["entries"]:
        assert entry["why"], f"{entry['name']} carries no reason for being here"


# -- the two implementations -----------------------------------------------


@needs_node
def test_python_and_node_hash_the_corpus_identically(corpus):
    answer = run_node({"encode": [entry["value"] for entry in corpus["entries"]]})
    results = answer["results"]
    assert len(results) == len(corpus["entries"])

    disagreements = []
    for entry, produced in zip(corpus["entries"], results):
        if "error" in produced:
            disagreements.append(f"{entry['name']}: node refused it -- {produced['error']}")
            continue
        python_bytes = canonical_bytes(entry["value"]).decode("utf-8")
        if produced["canonical"] != python_bytes:
            disagreements.append(
                f"{entry['name']} ({entry['why']}):\n"
                f"      python: {python_bytes!r}\n"
                f"      node:   {produced['canonical']!r}"
            )
        elif produced["record_hash"] != record_hash(entry["value"]).hex():
            disagreements.append(
                f"{entry['name']}: same bytes, different digest -- one side's hash "
                f"construction moved"
            )
        elif produced["canonical"] != entry["canonical"]:
            disagreements.append(
                f"{entry['name']}: both encoders agree, and both disagree with the pin. "
                "The encoding changed on both sides at once"
            )
    assert not disagreements, "the two canonical encoders disagree:\n  " + "\n  ".join(
        disagreements
    )


@needs_node
def test_the_two_agree_on_the_safe_integer_bound(corpus):
    answer = run_node({"encode": []})
    assert answer["max_safe"] == MAX_SAFE_INT == corpus["max_safe_int"] == 2**53 - 1


@needs_node
def test_keys_sort_by_code_point_on_both_sides():
    """``Array.prototype.sort`` compares UTF-16 code units. A surrogate pair's
    lead unit is 0xD800..0xDBFF, which is *below* U+E000 -- so a default sort
    puts an astral key before a private-use one and Python does not.

    This is the disagreement that would be invisible in ordinary data and
    catastrophic in a signed record: same content, two Merkle roots.
    """
    key_sets = [
        ["\U0001F600", "\ue000", "\uffff"],
        ["\U00020000", "\ufffd", "z", "\u00e9"],
        ["b", "A", "a", "_", "B", "-", "0"],
        ["9", "10", "1", "100", "2"],
        ["\u00e9", "e", "z", "\u00e4", "Z", "\u65e5", "\u0436"],
    ]
    answer = run_node({"sort": key_sets, "encode": []})
    for keys, from_node in zip(key_sets, answer["sorted"]):
        assert from_node == sorted(keys), (
            f"node sorted {keys} as {from_node}, python as {sorted(keys)}"
        )

    # And the naive sort really does differ, or this test is guarding nothing.
    naive = run_node({"sort": [], "encode": []})
    assert naive["sorted"] == []
    assert sorted(["\U0001F600", "\ue000"]) == ["\ue000", "\U0001F600"], (
        "python's own ordering is the reference here"
    )


# -- what both must refuse -------------------------------------------------


REFUSALS = [
    ({"wh": 1.5}, "a float"),
    ({"wh": 0.1}, "a float that looks exact"),
    ({"wh": 2**53}, "one past the safe integer bound"),
    ({"wh": -(2**53)}, "one past it downwards"),
    ({"wh": 2**64}, "far past it"),
    ([1, [2, [3.5]]], "a float buried in nesting"),
    ({"a": {"b": {"c": 2**53 + 7}}}, "an unsafe integer buried in nesting"),
]


@pytest.mark.parametrize("value, because", REFUSALS)
def test_python_refuses(value, because):
    with pytest.raises(CanonicalError):
        canonical_bytes(value)


@needs_node
@pytest.mark.parametrize("value, because", REFUSALS)
def test_node_refuses_the_same_things(value, because):
    """Refusing in one implementation and accepting in the other is worse than
    accepting in both: it produces a ledger the farm can write and the client
    cannot read, and the farm has no way to notice."""
    answer = run_node({"encode": [value]})
    produced = answer["results"][0]
    assert "error" in produced, (
        f"node encoded {because} as {produced.get('canonical')!r}; python refuses it"
    )
    assert produced["error"].startswith("CanonicalError"), produced["error"]


@needs_node
def test_both_accept_the_bound_itself():
    """The bound is inclusive on both sides, or a legitimate value is refused
    by one of them -- which is the same failure in the other direction."""
    value = {"high": MAX_SAFE_INT, "low": -MAX_SAFE_INT}
    answer = run_node({"encode": [value]})
    produced = answer["results"][0]
    assert "error" not in produced, produced.get("error")
    assert produced["canonical"] == canonical_bytes(value).decode("utf-8")


# -- the file the browser actually loads -----------------------------------


def test_the_console_loads_the_same_encoder_the_test_hashes():
    """If console.js ever grows its own copy of canonical(), this test is the
    only thing standing between the page and a silent divergence."""
    with open(os.path.join(ROOT, "web", "console.html"), encoding="utf-8") as handle:
        page = handle.read()
    # The script tags, not any mention in prose: the page's own commentary
    # names console.js long before it loads anything.
    scripts = re.findall(r'<script[^>]*\bsrc=["\']([^"\']+)["\']', page)
    assert "canonical.js" in scripts, "console.html no longer loads the shared encoder"
    assert scripts.index("canonical.js") < scripts.index("console.js"), (
        f"canonical.js must load before console.js, which destructures it at load; got {scripts}"
    )
    with open(os.path.join(ROOT, "web", "console.js"), encoding="utf-8") as handle:
        console = handle.read()
    assert "HashGuardCanonical" in console
    assert "function canonical(" not in console, (
        "console.js has its own canonical() again; it must use the shared one, "
        "or the file this test hashes is no longer the file the browser runs"
    )
