"""Canonical serialization: the one representation both parties agree to hash.

A ledger whose numbers are floats is a ledger with two readings. IEEE-754
doubles do not survive a round trip through every JSON encoder in the world
identically, and a billing dispute that turns on the last bit of a mantissa is
a billing dispute nobody can settle. So the canonical form used by HashGuard
admits **no floating point at all**: every physical and monetary quantity is
carried as an integer in a declared minor unit (see :mod:`hashguard.money`).

What remains is a total, deterministic encoding:

* objects with keys sorted by their UTF-8 code points,
* no insignificant whitespace,
* UTF-8 output,
* ``int``, ``str``, ``bool``, ``None``, ``list`` and ``dict`` only.

The hash primitive is SHA-256d (SHA-256 applied twice), the same construction
Bitcoin uses and the one carried over from the ``bbu.merkle`` module of the
Universo de Bloques Ramificados repository, so a HashGuard leaf hash and a
Bitcoin transaction hash are computed by the identical function.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: Domain separator. Prefixing every digest with a tag means a hash produced
#: for one purpose can never be replayed as a hash for another.
SPEC = "hashguard-ledger/2"


class CanonicalError(ValueError):
    """The value cannot be canonically encoded, so it must not be hashed."""


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, str):
        return
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalError(
            f"{path}: floats are not canonical; carry the quantity as an "
            "integer in a declared minor unit (see hashguard.money)"
        )
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object keys must be strings, got {type(key).__name__}")
            _check(item, f"{path}.{key}")
        return
    raise CanonicalError(f"{path}: type {type(value).__name__} has no canonical encoding")


def canonical_bytes(value: Any) -> bytes:
    """Return the single byte string this value hashes as.

    Raises :class:`CanonicalError` rather than silently hashing something whose
    encoding another implementation might not reproduce.
    """
    _check(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256d(data: bytes) -> bytes:
    """SHA-256 applied twice, as in Bitcoin block and transaction hashing."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Domain-separated SHA-256d.

    ``tag`` names what the digest is *for*. A leaf hash cannot be presented as
    an inner node, and a seal hash cannot be presented as a leaf, because the
    tag differs and so does the digest.
    """
    prefix = hashlib.sha256(tag.encode("utf-8")).digest()
    return sha256d(prefix + data)


def record_hash(record: dict) -> bytes:
    """The leaf hash of a ledger record."""
    return tagged_hash(SPEC + "/record", canonical_bytes(record))


def hexlify(digest: bytes) -> str:
    return digest.hex()


def unhexlify(text: str) -> bytes:
    """Parse a hex digest, refusing anything that is not exactly 32 bytes."""
    if not isinstance(text, str):
        raise CanonicalError("digest must be a hex string")
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise CanonicalError(f"not a hex digest: {text!r}") from exc
    if len(raw) != 32:
        raise CanonicalError(f"digest must be 32 bytes, got {len(raw)}")
    return raw
