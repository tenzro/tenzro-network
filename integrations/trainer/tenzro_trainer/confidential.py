"""Confidential-tier shard unwrap (HPKE — RFC 9180).

When a Tenzro Train task is registered at the ``Confidential`` trust tier,
the sponsor packages each trainer's data shard as a :class:`SealedShardEnvelope`
inside a :class:`SealedDatasetManifest` and installs the manifest via
``tenzro_training_installSealedManifest``. Every envelope carries:

* ``shard_ciphertext_bytes`` — AES-256-GCM ciphertext over the shard
  payload (nonce ``||`` ct ``||`` tag wire format).
* ``wrapped_data_key`` — the AES key wrapped to the trainer's enclave
  via HPKE base mode (RFC 9180), specifically the suite
  ``DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM``.
* ``wrap_alg`` — algorithm identifier; this module accepts
  ``"hpke-x25519-hkdf-sha256-aes-256-gcm"``.
* ``enclave_pubkey`` — the X25519 public key the AES key was wrapped to.
* ``enclave_measurement_hex`` — the enclave measurement the trainer's
  attestation report must carry.

This module runs **inside the trainer's enclave**: the Rust protocol layer
never sees the cleartext data key or the cleartext shard. At enroll time the
Rust ``validate_confidential_enrollment`` verifies the trainer's attestation
report against a pinned vendor root, refuses simulated reports, requires the
report to commit to ``enclave_pubkey`` in its user data, and requires the
report's measurement to equal ``enclave_measurement_hex``. Both expected
values are read from the sealed manifest, not from the enrolling trainer.
Once enrollment succeeds, the trainer calls :func:`unwrap_shard` with the
matching X25519 secret key (which itself never leaves the enclave) to
recover the shard plaintext.

Architectural note: this is deliberately a thin wrapper over the
``pyhpke`` library — implementing HPKE from raw primitives is a footgun
(KEM/KDF/AEAD label derivation, info-string composition, etc.). If
``pyhpke`` isn't installed, :func:`unwrap_shard` raises a clear
``ImportError`` pointing to the ``confidential`` install extra.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

HPKE_SUITE_ID = "hpke-x25519-hkdf-sha256-aes-256-gcm"

# HPKE base-mode info string. Bind the unwrap context to a Tenzro-specific
# domain so a wrapped key for one purpose can't be replayed in another.
HPKE_INFO = b"tenzro/training/confidential-shard/hpke-base"

# AES-GCM nonce length (NIST SP 800-38D recommendation: 96 bits / 12 bytes).
AES_GCM_NONCE_LEN = 12
AES_GCM_TAG_LEN = 16


# ---------------------------------------------------------------------------
# Envelope view
# ---------------------------------------------------------------------------


@dataclass
class SealedShardEnvelope:
    """Python view of the Rust :rust:`SealedShardEnvelope` struct.

    Constructed from the JSON returned by ``tenzro_training_getSealedManifest``
    (then walked to ``manifest.envelopes[i]``). The byte fields arrive over
    JSON as either ``list[int]`` (matches the Rust ``serde_json`` default
    for ``Vec<u8>``) or base64 strings — :meth:`from_json` accepts both.
    """

    trainer_did: str
    shard_index: int
    shard_ciphertext_hash: list[int]  # 32-int array, matches Rust Hash
    shard_ciphertext_bytes: bytes
    wrapped_data_key: bytes
    wrap_alg: str
    enclave_pubkey: bytes
    enclave_measurement_hex: str
    created_at: int  # Unix ms (matches Rust Timestamp)

    @classmethod
    def from_json(cls, j: dict[str, Any]) -> SealedShardEnvelope:
        return cls(
            trainer_did=j["trainer_did"],
            shard_index=int(j["shard_index"]),
            shard_ciphertext_hash=list(j["shard_ciphertext_hash"]),
            shard_ciphertext_bytes=_decode_bytes_field(j["shard_ciphertext_bytes"]),
            wrapped_data_key=_decode_bytes_field(j["wrapped_data_key"]),
            wrap_alg=j["wrap_alg"],
            enclave_pubkey=_decode_bytes_field(j["enclave_pubkey"]),
            enclave_measurement_hex=j["enclave_measurement_hex"],
            created_at=int(j["created_at"]),
        )


def _decode_bytes_field(v: Any) -> bytes:
    """Accept either Rust-style ``list[int]`` or a base64 string."""
    if isinstance(v, list):
        return bytes(v)
    if isinstance(v, str):
        # base64 is the only sensible string encoding for a Vec<u8>.
        return base64.b64decode(v)
    raise TypeError(f"unsupported byte field type: {type(v).__name__}")


# ---------------------------------------------------------------------------
# Unwrap
# ---------------------------------------------------------------------------


def unwrap_shard(
    envelope: SealedShardEnvelope,
    enclave_secret_key: bytes,
    *,
    info: bytes = HPKE_INFO,
) -> bytes:
    """Recover the shard plaintext.

    Steps inside the enclave:

    1. Verify ``envelope.wrap_alg`` is the supported HPKE suite.
    2. Use HPKE base-mode receiver to derive the AES-256 data key from
       ``envelope.wrapped_data_key`` + ``enclave_secret_key``. The wrapped
       payload is ``enc || ct`` where ``enc`` is the ephemeral X25519
       public key and ``ct`` is the HPKE-AEAD ciphertext over the 32-byte
       data key (HPKE-AEAD output for a 32-byte plaintext is 32 + 16 =
       48 bytes; ``enc`` for X25519 is 32 bytes; so a typical wrapped
       blob is 80 bytes).
    3. Use the recovered data key to AES-256-GCM-decrypt
       ``envelope.shard_ciphertext_bytes`` (wire format:
       ``nonce(12) || ct || tag(16)``).

    The plaintext shard never leaves this function's return value —
    callers must scrub it once consumed.

    Raises :class:`ImportError` if ``pyhpke`` / ``cryptography`` aren't
    installed (install the ``confidential`` extra:
    ``pip install tenzro-trainer[confidential]``).
    """
    if envelope.wrap_alg != HPKE_SUITE_ID:
        raise ValueError(
            f"unsupported wrap_alg {envelope.wrap_alg!r}, "
            f"expected {HPKE_SUITE_ID!r}"
        )
    try:
        from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
    except ImportError as e:
        raise ImportError(
            "Confidential-tier shard unwrap requires the `pyhpke` package "
            "(RFC 9180 implementation). Install with: "
            "`pip install tenzro-trainer[confidential]`"
        ) from e
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise ImportError(
            "Confidential-tier shard unwrap requires `cryptography`. "
            "Install with: `pip install tenzro-trainer[confidential]`"
        ) from e

    # 1. Derive the data key via HPKE base mode.
    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256,
        KDFId.HKDF_SHA256,
        AEADId.AES256_GCM,
    )
    # X25519 keys are 32 bytes; pyhpke's KEMKey wraps raw key material.
    sk = KEMKey.from_pem(_x25519_secret_to_pem(enclave_secret_key))

    # HPKE-base wire format: enc (KEM pubkey, 32 bytes for X25519) || ct.
    enc_len = 32
    if len(envelope.wrapped_data_key) < enc_len + AES_GCM_TAG_LEN:
        raise ValueError(
            f"wrapped_data_key too short: {len(envelope.wrapped_data_key)} bytes, "
            f"need at least {enc_len + AES_GCM_TAG_LEN}"
        )
    enc = envelope.wrapped_data_key[:enc_len]
    wrapped_ct = envelope.wrapped_data_key[enc_len:]

    recipient = suite.create_recipient_context(enc, sk, info=info)
    data_key = recipient.open(wrapped_ct)
    if len(data_key) != 32:
        raise ValueError(
            f"recovered data key has wrong length: {len(data_key)} bytes, expected 32"
        )

    # 2. AES-256-GCM-decrypt the shard payload.
    ct = envelope.shard_ciphertext_bytes
    if len(ct) < AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN:
        raise ValueError(
            f"shard ciphertext too short: {len(ct)} bytes, "
            f"need at least {AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN}"
        )
    nonce = ct[:AES_GCM_NONCE_LEN]
    body = ct[AES_GCM_NONCE_LEN:]
    aead = AESGCM(data_key)
    return aead.decrypt(nonce, body, associated_data=None)


def _x25519_secret_to_pem(sk: bytes) -> bytes:
    """Encode a raw 32-byte X25519 secret key as PEM (PKCS#8).

    ``pyhpke``'s :class:`KEMKey` wants a PEM-encoded key, but enclaves
    expose raw keys. This goes through ``cryptography`` to do the
    PKCS#8 wrap.
    """
    if len(sk) != 32:
        raise ValueError(f"X25519 secret key must be 32 bytes, got {len(sk)}")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv = X25519PrivateKey.from_private_bytes(sk)
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


__all__ = [
    "HPKE_INFO",
    "HPKE_SUITE_ID",
    "SealedShardEnvelope",
    "unwrap_shard",
]
