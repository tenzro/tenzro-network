"""DID envelopes over whole JSON-RPC requests.

Some methods change something that belongs to a DID (registering a machine
under a controller is one), so the request carries ``did_envelope``: the DID's
signature over the method name and a hash of every other parameter. The node
rebuilds the same bytes and checks the signature against the key the DID
resolves to. The signature comes from a :class:`~tenzro.wallet.HybridSigner`
over a passkey, TPM or Secure Enclave key; the SDK never holds a private key.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Any

from .wallet import HybridSigner, composite_message_representative, composite_signature_json

#: Signature context of a DID envelope.
DID_ENVELOPE_CONTEXT = b"tenzro/did-envelope"

_ENVELOPE_DOMAIN = b"tenzro-did-envelope:v1"


def request_binding(params: dict[str, Any]) -> bytes:
    """The bytes a request envelope binds: ``params`` without ``did_envelope``,
    as JSON with object keys sorted at every level and no whitespace."""
    bound = {k: v for k, v in params.items() if k != "did_envelope"}
    return json.dumps(bound, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True)
class DidEnvelopeFields:
    """The fields of an envelope before its signature."""

    did: str
    method: str
    params_hash: bytes
    timestamp_ms: int
    nonce: bytes

    def preimage(self) -> bytes:
        """The bytes the DID signs: the domain tag, ``did`` and ``method``
        length-prefixed (u32 big-endian), ``params_hash``, ``timestamp_ms``
        (u64 big-endian) and ``nonce``."""
        did, method = self.did.encode(), self.method.encode()
        return (
            _ENVELOPE_DOMAIN
            + struct.pack(">I", len(did))
            + did
            + struct.pack(">I", len(method))
            + method
            + self.params_hash
            + struct.pack(">Q", self.timestamp_ms)
            + self.nonce
        )

    def header(self, signature: dict) -> str:
        """The hex header value the node takes as ``did_envelope``."""
        did, method = self.did.encode(), self.method.encode()
        sig = json.dumps(signature, separators=(",", ":")).encode()
        return (
            struct.pack(">I", len(did))
            + did
            + struct.pack(">I", len(method))
            + method
            + self.params_hash
            + struct.pack(">Q", self.timestamp_ms)
            + self.nonce
            + struct.pack(">I", len(sig))
            + sig
        ).hex()


def with_request_envelope(
    signer: HybridSigner,
    did: str,
    method: str,
    params: dict[str, Any],
    *,
    timestamp_ms: int | None = None,
    nonce: bytes | None = None,
) -> dict[str, Any]:
    """``params`` with ``did_envelope`` set: ``did``'s envelope, signed by
    ``signer`` (the key ``did`` resolves to), authorizing ``method`` over every
    other field. ``timestamp_ms`` and ``nonce`` are for reproducing a vector."""
    nonce = os.urandom(16) if nonce is None else nonce
    if len(nonce) != 16:
        raise ValueError("envelope nonce must be 16 bytes")
    fields = DidEnvelopeFields(
        did=did,
        method=method,
        params_hash=hashlib.sha256(request_binding(params)).digest(),
        timestamp_ms=int(time.time() * 1000) if timestamp_ms is None else timestamp_ms,
        nonce=nonce,
    )
    m_prime = composite_message_representative(DID_ENVELOPE_CONTEXT, fields.preimage())
    classical, pq = signer.sign_composite(m_prime)
    return {**params, "did_envelope": fields.header(composite_signature_json(classical, pq))}
