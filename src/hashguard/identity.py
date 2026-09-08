"""The agent's device identity: what makes a seal *the farm's* seal.

A hash chain proves that a ledger has not been edited after the fact. It does
not prove who wrote it -- anyone can build a perfectly consistent chain of
invented numbers in a text editor. Signing closes that gap: the seals are
produced by a key that never leaves the farm machine, so the operator can tell
a measurement apart from a fabrication, and the client can tell an invoice from
a forgery.

Two backends, one interface:

* **ed25519** (preferred) -- asymmetric, so the client publishes only a public
  key and the operator can verify seals without ever holding anything that
  could produce one. Needs ``cryptography``.
* **hmac-sha256** (fallback) -- a shared secret, so verification requires
  possession of the signing secret. Honest but weaker: it proves a seal came
  from someone holding the secret, not specifically from the device. HashGuard
  says so out loud in the statement rather than letting it pass as equivalent.

The key file is created ``0600`` and its permissions are re-checked on every
load; a key that became world-readable is refused, not used with a warning.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import stat
from dataclasses import dataclass

try:  # pragma: no cover - exercised by whichever backend is installed
    # A bare ImportError is not the only way this fails: a cryptography wheel
    # whose native bindings are missing raises from the Rust layer. Either way
    # the answer is the same -- fall back, do not take the process down.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    HAVE_ED25519 = True
except Exception:  # noqa: BLE001 - a broken build of the wheel must degrade, not crash
    HAVE_ED25519 = False


class IdentityError(RuntimeError):
    """The device key is missing, malformed, or insecurely stored."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same failure
        raise IdentityError("malformed base64 in key material") from exc


def _write_private(path: str, payload: dict) -> None:
    """Write ``0600`` from the first byte -- never world-readable, not even briefly."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(payload, handle, indent=2)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - filesystems without POSIX modes
            pass


def _assert_private(path: str) -> None:
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        raise IdentityError(f"cannot stat {path}: {exc}") from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise IdentityError(
            f"{path} is readable beyond its owner (mode {stat.S_IMODE(mode):04o}). "
            "Run: chmod 600 " + path
        )


@dataclass
class DeviceIdentity:
    """A signing identity plus the public material a verifier needs."""

    algorithm: str          # "ed25519" | "hmac-sha256"
    device_id: str          # public fingerprint, safe to print anywhere
    public_key_b64: str     # ed25519 public key, or "" for hmac
    _secret: bytes

    # -- lifecycle -------------------------------------------------------

    @classmethod
    def generate(cls, prefer_ed25519: bool = True) -> "DeviceIdentity":
        if prefer_ed25519 and HAVE_ED25519:
            private = Ed25519PrivateKey.generate()
            raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return cls("ed25519", _fingerprint(public), _b64(public), raw)
        secret = secrets.token_bytes(32)
        return cls("hmac-sha256", _fingerprint(secret), "", secret)

    @classmethod
    def load_or_create(cls, path: str = "device_key.json") -> "DeviceIdentity":
        if os.path.exists(path):
            _assert_private(path)
            with open(path) as handle:
                data = json.load(handle)
            algorithm = data.get("algorithm")
            if algorithm not in ("ed25519", "hmac-sha256"):
                raise IdentityError(f"unknown signing algorithm {algorithm!r} in {path}")
            if algorithm == "ed25519" and not HAVE_ED25519:
                raise IdentityError(
                    f"{path} holds an ed25519 key but the 'cryptography' package is "
                    "not installed. Install it rather than silently downgrading."
                )
            return cls(
                algorithm,
                data["device_id"],
                data.get("public_key_b64", ""),
                _unb64(data["secret_b64"]),
            )
        identity = cls.generate()
        identity.save(path)
        return identity

    def save(self, path: str) -> None:
        _write_private(
            path,
            {
                "algorithm": self.algorithm,
                "device_id": self.device_id,
                "public_key_b64": self.public_key_b64,
                "secret_b64": _b64(self._secret),
                "note": "Private key material. Never commit, never share, mode 0600.",
            },
        )

    # -- use -------------------------------------------------------------

    def sign(self, message: bytes) -> str:
        if self.algorithm == "ed25519":
            private = Ed25519PrivateKey.from_private_bytes(self._secret)
            return _b64(private.sign(message))
        return _b64(hmac.new(self._secret, message, "sha256").digest())

    def public(self) -> dict:
        """The verifier's half of the identity. Contains no secret."""
        return {
            "algorithm": self.algorithm,
            "device_id": self.device_id,
            "public_key_b64": self.public_key_b64,
            "verifiable_by_third_party": self.algorithm == "ed25519",
        }


def _fingerprint(material: bytes) -> str:
    from .canonical import sha256d

    return sha256d(b"hashguard/v2/device-id" + material).hex()[:32]


def verify_signature(public: dict, message: bytes, signature_b64: str) -> bool:
    """Check a seal signature against published identity material.

    For ``hmac-sha256`` this needs the shared secret in ``public["secret_b64"]``,
    which is precisely why ed25519 is preferred: a third party can verify an
    ed25519 seal with material that gives them no power to mint one.
    """
    try:
        signature = _unb64(signature_b64)
    except IdentityError:
        return False
    algorithm = public.get("algorithm")
    if algorithm == "ed25519":
        if not HAVE_ED25519:
            raise IdentityError("verifying ed25519 requires the 'cryptography' package")
        try:
            key = Ed25519PublicKey.from_public_bytes(_unb64(public["public_key_b64"]))
            key.verify(signature, message)
            return True
        except (InvalidSignature, IdentityError, ValueError, KeyError):
            return False
    if algorithm == "hmac-sha256":
        secret_b64 = public.get("secret_b64")
        if not secret_b64:
            raise IdentityError(
                "hmac-sha256 seals can only be verified by a holder of the shared "
                "secret; ed25519 is the backend that supports third-party audit"
            )
        expected = hmac.new(_unb64(secret_b64), message, "sha256").digest()
        return hmac.compare_digest(expected, signature)
    return False
