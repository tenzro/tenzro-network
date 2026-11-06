"""Account addresses and composite signatures.

Every signature an account makes is a composite: a P-256 leg from hardware (a
TPM, the Secure Enclave or a passkey) and, once the account enrolls one, an
ML-DSA-65 leg held in hardware. Both legs sign the composite message
representative of a context and a message
(:func:`composite_message_representative`). The account address commits to
the P-256 key only.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Protocol, Union, runtime_checkable

#: Fixed prefix of every composite message representative.
COMPOSITE_PREFIX = b"CompositeAlgorithmSignatures2025"

#: Composite label for ML-DSA-65 with ECDSA P-256; also the FIPS 204 context
#: string the ML-DSA-65 leg signs under.
COMPOSITE_LABEL_MLDSA65_P256 = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512"

#: Signature context of a ledger transaction.
TRANSACTION_SIGNATURE_CONTEXT = b"tenzro/tx"


@dataclass(frozen=True)
class WebAuthnAssertion:
    """A passkey's assertion, the WebAuthn form of the P-256 leg."""

    authenticator_data: bytes
    #: ``clientDataJSON``, byte-exact.
    client_data_json: bytes
    #: The assertion signature, DER or ``r || s``.
    signature: bytes


#: The P-256 leg: raw ``r || s`` from a TPM or Secure Enclave, or a passkey assertion.
ClassicalLeg = Union[bytes, WebAuthnAssertion]


@runtime_checkable
class HybridSigner(Protocol):
    """A hardware signer of composite signatures.

    ``p256_public_key`` is the hardware P-256 key ``x || y`` (64 bytes); it
    names the account. ``ml_dsa_public_key`` is the hardware ML-DSA-65
    verifying key (1952 bytes) when the hardware holds one, else ``None``.
    ``sign_composite(m_prime)`` returns the P-256 leg over
    ``SHA-256(m_prime)`` and, when the hardware holds an ML-DSA-65 key, the
    ML-DSA-65 leg over ``m_prime`` under ``COMPOSITE_LABEL_MLDSA65_P256``
    (``None`` otherwise). There is no software implementation.
    """

    def p256_public_key(self) -> bytes: ...

    def ml_dsa_public_key(self) -> bytes | None: ...

    def sign_composite(self, m_prime: bytes) -> tuple[ClassicalLeg, bytes | None]: ...


def account_address(p256_public_key: bytes) -> bytes:
    """The 32-byte account slot of a hardware P-256 key.

    ``SHA-256("tenzro/account" || 0x02 || 0x40 || x || y)[:20]`` followed by 12
    zero bytes, identical to the node's ``account_slot``.
    """
    if len(p256_public_key) != 64:
        raise ValueError(f"P-256 public key must be 64 bytes (x || y), got {len(p256_public_key)}")
    digest = hashlib.sha256(b"tenzro/account" + bytes([2, 64]) + bytes(p256_public_key)).digest()
    return digest[:20] + bytes(12)


def composite_message_representative(context: bytes, message: bytes) -> bytes:
    """``Prefix || Label || len(ctx) || ctx || SHA-512(message)``, the bytes both legs sign."""
    if len(context) > 255:
        raise ValueError("a signature context is at most 255 bytes")
    return (
        COMPOSITE_PREFIX
        + COMPOSITE_LABEL_MLDSA65_P256
        + bytes([len(context)])
        + context
        + hashlib.sha512(message).digest()
    )


def webauthn_challenge_of(m_prime: bytes) -> str:
    """The WebAuthn challenge a passkey signs for ``m_prime``: ``base64url(SHA-256(m_prime))``, unpadded."""
    digest = hashlib.sha256(m_prime).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def composite_signature_json(classical: ClassicalLeg, ml_dsa: bytes | None) -> dict:
    """The JSON form of a composite signature, as ``tenzro_sendRawTransaction`` takes it."""
    if isinstance(classical, WebAuthnAssertion):
        leg: dict = {
            "form": "web_authn",
            "authenticator_data": classical.authenticator_data.hex(),
            "client_data_json": classical.client_data_json.hex(),
            "signature": classical.signature.hex(),
        }
    else:
        leg = {"form": "raw", "signature": bytes(classical).hex()}
    out: dict = {"classical": leg}
    if ml_dsa:
        out["pq"] = bytes(ml_dsa).hex()
    return out
