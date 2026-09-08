"""Merkle trees with inclusion proofs.

Extends ``bbu.merkle`` from the Universo de Bloques Ramificados repository.
That module proves the claim of postulate P8 -- *any* alteration of a leaf
changes the root, and with it every header that follows. HashGuard needs the
converse direction as well: given one leaf and a short path, convince a
sceptical reader that this leaf is under that root without handing them the
other 40 000 leaves of the month.

The tree is Bitcoin-shaped: pairs are hashed left||right and a level with an
odd number of nodes duplicates its last node. That duplication is the origin
of CVE-2012-2459: a tree of ``n+1`` leaves whose last leaf repeats the ``n``th
has *exactly* the root of the ``n``-leaf tree, so a root alone does not pin how
many leaves produced it.

Stating precisely what closes that here, because it is spread across three
places and it would be easy to overclaim:

* :func:`verify_proof` pins the *depth* of the tree, by requiring the audit
  path to be exactly as long as the declared leaf count implies. That refuses a
  truncated path, and a proof reshaped to a differently-shaped tree. It does
  **not**, on its own, distinguish 9 leaves from 10 -- both are four levels
  deep, and by the collision above they can share a root.
* The **seal** commits ``leaf_count``, and ``ledger.verify_seal`` re-counts the
  records on disk against it. That is what makes the leaf count a fact rather
  than an assertion.
* The **statement** carries both, and the verifiers check that a proof's
  declared ``leaf_count`` equals the sealed one before trusting its path.

Together those pin the tree. Any one of them alone does not.
"""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import SPEC, hexlify, sha256d, tagged_hash, unhexlify

_NODE_TAG = SPEC + "/node"


def _node(left: bytes, right: bytes) -> bytes:
    return tagged_hash(_NODE_TAG, left + right)


def merkle_root(leaves: list[bytes]) -> bytes:
    """Root over already-hashed leaves. An empty tree has no root."""
    if not leaves:
        raise ValueError("a Merkle tree needs at least one leaf")
    for leaf in leaves:
        if len(leaf) != 32:
            raise ValueError("every leaf must be a 32-byte digest")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


@dataclass(frozen=True)
class InclusionProof:
    """The audit path from one leaf to the root.

    ``path`` is a list of ``(side, sibling)`` where ``side`` is ``"L"`` when the
    sibling sits on the left. ``leaf_count`` pins the shape of the tree.
    """

    index: int
    leaf_count: int
    path: list[tuple[str, bytes]]

    def to_json(self) -> dict:
        return {
            "index": self.index,
            "leaf_count": self.leaf_count,
            "path": [{"side": side, "hash": hexlify(h)} for side, h in self.path],
        }

    @classmethod
    def from_json(cls, data: dict) -> "InclusionProof":
        path: list[tuple[str, bytes]] = []
        for step in data["path"]:
            side = step["side"]
            if side not in ("L", "R"):
                raise ValueError(f"proof step side must be 'L' or 'R', got {side!r}")
            path.append((side, unhexlify(step["hash"])))
        return cls(int(data["index"]), int(data["leaf_count"]), path)


def build_proof(leaves: list[bytes], index: int) -> InclusionProof:
    """Audit path for ``leaves[index]``."""
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf {index} outside a tree of {len(leaves)}")
    leaf_count = len(leaves)
    path: list[tuple[str, bytes]] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if idx % 2 == 0:
            path.append(("R", level[idx + 1]))
        else:
            path.append(("L", level[idx - 1]))
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return InclusionProof(index, leaf_count, path)


def verify_proof(leaf: bytes, proof: InclusionProof, root: bytes) -> bool:
    """Does this leaf sit at ``proof.index`` of a ``proof.leaf_count``-leaf tree
    whose root is ``root``?

    The path is checked to be exactly as long as the declared tree size implies,
    which is what refuses a truncated path against a padded tree. See the module
    docstring for what this does *not* establish on its own.
    """
    if len(leaf) != 32 or len(root) != 32:
        return False
    if not 0 <= proof.index < proof.leaf_count:
        return False
    expected_depth = 0
    width = proof.leaf_count
    while width > 1:
        width = (width + 1) // 2
        expected_depth += 1
    if len(proof.path) != expected_depth:
        return False
    node = leaf
    for side, sibling in proof.path:
        if len(sibling) != 32:
            return False
        node = _node(sibling, node) if side == "L" else _node(node, sibling)
    return node == root


@dataclass(frozen=True)
class SealHeader:
    """A sealed day, shaped exactly like ``bbu.merkle.LedgerBlockHeader``.

    ``seal_hash = SHA256d(prev_seal || merkle_root)`` -- the same construction
    that chains block headers, so rewriting any record of any past day breaks
    every seal from that day forward, and the break is arithmetic, not a matter
    of opinion.
    """

    prev_seal: bytes
    merkle_root: bytes

    @property
    def seal_hash(self) -> bytes:
        return sha256d(self.prev_seal + self.merkle_root)


#: The chain's fixed point of origin.
GENESIS_SEAL = sha256d(b"hashguard/v2/genesis")
