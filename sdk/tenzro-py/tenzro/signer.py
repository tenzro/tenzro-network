"""The one way this SDK gets a signing key: the machine's hardware.

The optional native module ``tenzro_device_key`` (``pip install
tenzro[device]``, built from ``sdk/tenzro-py/native``) drives the TPM 2.0
(Linux ``/dev/tpmrm0``, Windows TBS) or the Apple Secure Enclave. It reads the
public key, signs a 32-byte digest, and attests; it cannot import or export a
key. On a machine with neither, :func:`open_hardware_signer` raises
:class:`NoHardwareSigner`. There is no software key.

A passkey signs in a browser; a Python caller holding a passkey assertion
passes it as :class:`tenzro.wallet.WebAuthnAssertion` from its own
:class:`tenzro.wallet.HybridSigner`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any

NO_HARDWARE = (
    "no hardware signer is available: Python needs the tenzro_device_key module "
    "(pip install tenzro[device]) and a TPM 2.0 or Secure Enclave; there is no software key"
)


class NoHardwareSigner(RuntimeError):
    """This machine has no hardware key this SDK can sign with."""


@dataclass(frozen=True)
class HardwareAttestation:
    backend: str
    evidence: bytes
    #: Uncompressed SEC1 public key (65 bytes).
    public_key: bytes


def _native() -> Any:
    try:
        import tenzro_device_key
    except ImportError:
        return None
    return tenzro_device_key


def platform_backend() -> str | None:
    """``"tpm"``, ``"secure-enclave"``, or ``None`` when there is no key hardware (or no native module)."""
    native = _native()
    return native.platform_backend() if native is not None else None


class DeviceKeySigner:
    """A :class:`tenzro.wallet.HybridSigner` whose P-256 key lives in this machine's TPM or Secure Enclave.

    The native binding exposes no ML-DSA-65 key, so the post-quantum leg is
    absent; the node refuses the signature for an account that enrolled one.
    """

    def __init__(self, key: Any):
        self._key = key

    @property
    def backend(self) -> str:
        return self._key.backend

    @property
    def label(self) -> str:
        return self._key.label

    def public_key(self) -> bytes:
        """Uncompressed SEC1 P-256 public key (65 bytes)."""
        return bytes(self._key.public_key())

    def p256_public_key(self) -> bytes:
        """The P-256 public key as ``x || y`` (64 bytes); it names the account."""
        return self.public_key()[1:65]

    def ml_dsa_public_key(self) -> bytes | None:
        return None

    def sign_digest(self, digest: bytes) -> bytes:
        """ECDSA P-256 over a 32-byte digest: raw low-S ``r || s``."""
        if len(digest) != 32:
            raise ValueError(f"expected a 32-byte digest, got {len(digest)} bytes")
        return bytes(self._key.sign_digest(bytes(digest)))

    def sign_composite(self, m_prime: bytes) -> tuple[bytes, bytes | None]:
        """The P-256 leg over ``SHA-256(m_prime)``; no ML-DSA-65 leg."""
        return self.sign_digest(hashlib.sha256(m_prime).digest()), None

    def attest(self) -> HardwareAttestation:
        backend, evidence, public_key = self._key.attest()
        return HardwareAttestation(backend=backend, evidence=bytes(evidence), public_key=bytes(public_key))

    def describe(self) -> dict[str, str]:
        if self.backend == "secure-enclave":
            return {"kind": "tee", "backend": "apple-secure-enclave"}
        return {"kind": "tee", "backend": "windows-tpm" if sys.platform == "win32" else "linux-tpm"}

    def public_key_jwk(self) -> dict[str, str]:
        """The P-256 public key as a JWK, for DPoP and DID documents."""
        pk = self.public_key()
        return {"kty": "EC", "crv": "P-256", "x": _b64url(pk[1:33]), "y": _b64url(pk[33:65])}


def set_key_namespace(namespace: str) -> None:
    """Open every later key under a node's key namespace (its ``hardware_key_namespace``).

    A machine that runs several nodes gives each its own namespace; a process
    that uses one node's keys (an agent runtime beside its serving node) sets
    that node's namespace once, before it opens any key.
    """
    native = _native()
    if native is None or native.platform_backend() is None:
        raise NoHardwareSigner(NO_HARDWARE)
    native.set_key_namespace(namespace)


def open_hardware_signer(label: str) -> DeviceKeySigner:
    """Open the labelled hardware key of this machine, creating it on first use."""
    if not label:
        raise ValueError("a device key needs a non-empty label")
    native = _native()
    if native is None or native.platform_backend() is None:
        raise NoHardwareSigner(NO_HARDWARE)
    try:
        return DeviceKeySigner(native.DeviceKey.open(label))
    except Exception as e:  # the binding raises with the hardware's reason
        raise NoHardwareSigner(str(e)) from e


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 thumbprint of a P-256 JWK."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":"), sort_keys=True
    )
    return _b64url(hashlib.sha256(canonical.encode()).digest())


class HardwareDpopProver:
    """Mints ES256 DPoP proofs (RFC 9449) with a hardware P-256 key."""

    def __init__(self, signer: DeviceKeySigner):
        self._signer = signer
        self._jwk = signer.public_key_jwk()

    def jkt(self) -> str:
        return jwk_thumbprint(self._jwk)

    def proof(self, htm: str, htu: str, access_token: str) -> str:
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self._jwk}
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": htm,
            "htu": htu,
            "iat": int(time.time()),
            "ath": _b64url(hashlib.sha256(access_token.encode()).digest()),
        }
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(payload, separators=(",", ":")).encode())
        )
        signature = self._signer.sign_digest(hashlib.sha256(signing_input.encode()).digest())
        return signing_input + "." + _b64url(signature)
