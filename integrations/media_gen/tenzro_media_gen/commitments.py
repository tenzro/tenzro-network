"""Deterministic job identity and signing preimages.

Byte-identical counterpart to ``crates/tenzro-media-gen/src/commitments.rs``.
A digest computed here must equal the one the node computes over the same
values, or the node rejects the worker's signature.

Encoding rules, applied uniformly:

- Integers are big-endian, at their declared width.
- Timestamps are two's-complement i64 milliseconds
  (``to_bytes(8, "big", signed=True)``).
- ``guidance_scale`` is its IEEE-754 big-endian bit pattern.
  :meth:`MediaGenParams.validate_for` rejects non-finite values, so the
  pattern is always canonical.
- Variable-length fields are length-prefixed with a big-endian ``u32`` byte
  count, so no field boundary is ambiguous.
- An optional field is a presence byte (``0x01`` / ``0x00``) followed, when
  present, by the value's encoding.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .types import (
    MediaGenHandoff,
    MediaGenKind,
    MediaGenParams,
    MediaGenReceipt,
    MediaGenTaskSpec,
    Signature,
)

JOB_ID_TAG = b"tenzro/media-gen/job-id"
HANDOFF_TAG = b"tenzro/media-gen/handoff"
RECEIPT_TAG = b"tenzro/media-gen/receipt"


def _len_prefixed(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def _encode_opt_u32(value: int | None) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + value.to_bytes(4, "big")


def _encode_millis(millis: int) -> bytes:
    # Two's-complement encoding of i64 millis to match Rust's i64 timestamp.
    return millis.to_bytes(8, "big", signed=True)


def encode_params(params: MediaGenParams) -> bytes:
    """Encode the sampling parameters.

    ``metadata`` is deliberately excluded: it is opaque pipeline-tuning input
    with no canonical ordering guarantee across the Rust and Python JSON
    encoders, and binding it would make the preimage depend on map iteration
    order.
    """
    buf = bytearray()
    buf.extend(_len_prefixed(params.prompt.encode("utf-8")))
    if params.negative_prompt is None:
        buf.append(0x00)
    else:
        buf.append(0x01)
        buf.extend(_len_prefixed(params.negative_prompt.encode("utf-8")))
    buf.extend(params.width.to_bytes(4, "big"))
    buf.extend(params.height.to_bytes(4, "big"))
    buf.extend(_encode_opt_u32(params.num_frames))
    buf.extend(_encode_opt_u32(params.fps))
    buf.extend(params.steps.to_bytes(4, "big"))
    buf.extend(struct.pack(">f", params.guidance_scale))
    if params.seed is None:
        buf.append(0x00)
    else:
        buf.append(0x01)
        buf.extend(params.seed.to_bytes(8, "big"))
    if params.input_image_hash is None:
        buf.append(0x00)
    else:
        buf.append(0x01)
        buf.extend(_require_hash(params.input_image_hash))
    return bytes(buf)


def encode_task_spec(spec: MediaGenTaskSpec) -> bytes:
    buf = bytearray()
    buf.extend(_len_prefixed(spec.job_id.encode("utf-8")))
    buf.extend(_len_prefixed(spec.requester_did.encode("utf-8")))
    buf.extend(_len_prefixed(_require_address(spec.requester_address)))
    buf.extend(_len_prefixed(spec.model_id.encode("utf-8")))
    buf.extend(_len_prefixed(spec.kind.value.encode("utf-8")))
    buf.extend(encode_params(spec.params))
    buf.extend(spec.max_price.to_bytes(16, "big"))
    buf.extend(_encode_millis(spec.created_at))
    return bytes(buf)


def compute_job_id(
    requester_did: str,
    requester_address: bytes,
    model_id: str,
    kind: MediaGenKind,
    params: MediaGenParams,
    max_price: int,
    created_at: int,
) -> str:
    """Derive the lowercase-hex SHA-256 job id for a posted request.

    The timestamp is what separates two otherwise-identical requests from the
    same requester — reposting the same prompt yields a new job, but a retried
    post carrying the original timestamp is recognised as the same job.
    """
    buf = bytearray(JOB_ID_TAG)
    buf.extend(_len_prefixed(requester_did.encode("utf-8")))
    buf.extend(_len_prefixed(_require_address(requester_address)))
    buf.extend(_len_prefixed(model_id.encode("utf-8")))
    buf.extend(_len_prefixed(kind.value.encode("utf-8")))
    buf.extend(encode_params(params))
    buf.extend(max_price.to_bytes(16, "big"))
    buf.extend(_encode_millis(created_at))
    return hashlib.sha256(bytes(buf)).hexdigest()


def expected_job_id(spec: MediaGenTaskSpec) -> str:
    """Job id a spec should carry, ignoring whatever ``spec.job_id`` holds."""
    return compute_job_id(
        spec.requester_did,
        spec.requester_address,
        spec.model_id,
        spec.kind,
        spec.params,
        spec.max_price,
        spec.created_at,
    )


def handoff_signing_bytes(handoff: MediaGenHandoff) -> bytes:
    """Preimage the high-noise expert signs over an intermediate latent.

    ``steps_completed`` is bound because the payment split is computed from it
    — a worker that overstates its half of the schedule would have to forge
    the signature to do so.
    """
    buf = bytearray(HANDOFF_TAG)
    buf.extend(_len_prefixed(handoff.job_id.encode("utf-8")))
    buf.extend(_len_prefixed(handoff.from_worker_did.encode("utf-8")))
    buf.extend(_len_prefixed(_require_address(handoff.from_worker_address)))
    buf.extend(_require_hash(handoff.latent_hash))
    buf.extend(handoff.latent_bytes.to_bytes(8, "big"))
    buf.extend(handoff.steps_completed.to_bytes(4, "big"))
    buf.extend(_encode_millis(handoff.handed_off_at))
    return bytes(buf)


def handoff_commitment(handoff: MediaGenHandoff) -> bytes:
    """SHA-256 over :func:`handoff_signing_bytes`."""
    return hashlib.sha256(handoff_signing_bytes(handoff)).digest()


def receipt_signing_bytes(receipt: MediaGenReceipt) -> bytes:
    """Preimage the worker signs to attest a completed job.

    The full task spec is folded in, so the parameters the worker executed are
    covered and cannot be swapped after signing.
    """
    buf = bytearray(RECEIPT_TAG)
    buf.extend(_len_prefixed(receipt.job_id.encode("utf-8")))
    buf.extend(encode_task_spec(receipt.task_spec))
    buf.extend(_len_prefixed(receipt.worker_did.encode("utf-8")))
    buf.extend(_len_prefixed(_require_address(receipt.worker_address)))
    buf.extend(_require_hash(receipt.output_hash))
    buf.extend(_len_prefixed(receipt.output_mime.encode("utf-8")))
    buf.extend(receipt.output_bytes.to_bytes(8, "big"))
    buf.extend(receipt.seed_used.to_bytes(8, "big"))
    buf.extend(receipt.generation_time_ms.to_bytes(8, "big"))
    buf.extend(receipt.price_paid.to_bytes(16, "big"))
    buf.extend(_encode_millis(receipt.completed_at))
    return bytes(buf)


def receipt_commitment(receipt: MediaGenReceipt) -> bytes:
    """SHA-256 over :func:`receipt_signing_bytes`."""
    return hashlib.sha256(receipt_signing_bytes(receipt)).digest()


def _require_hash(value: bytes) -> bytes:
    if len(value) != 32:
        raise ValueError(f"hash must be 32 bytes, got {len(value)}")
    return value


def _require_address(value: bytes) -> bytes:
    if len(value) != 32:
        raise ValueError(f"address must be 32 bytes, got {len(value)}")
    return value


@dataclass
class WorkerKey:
    """Ed25519 signing key for a media-gen worker."""

    signing: object

    @classmethod
    def generate(cls) -> WorkerKey:
        import nacl.signing

        return cls(signing=nacl.signing.SigningKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> WorkerKey:
        import nacl.signing

        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return cls(signing=nacl.signing.SigningKey(seed))

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> WorkerKey:
        return cls.from_seed(bytes.fromhex(seed_hex))

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self.signing.verify_key)

    @property
    def seed_bytes(self) -> bytes:
        """The 32-byte seed this key was derived from, for persisting it."""
        return bytes(self.signing)

    def sign(self, msg: bytes) -> bytes:
        return self.signing.sign(msg).signature


def sign_handoff(handoff: MediaGenHandoff, key: WorkerKey) -> Signature:
    """Sign a handoff and return the signature to attach to it."""
    return Signature(
        bytes_=key.sign(handoff_signing_bytes(handoff)),
        public_key=key.public_key_bytes,
    )


def sign_receipt(receipt: MediaGenReceipt, key: WorkerKey) -> Signature:
    """Sign a receipt and return the signature to attach to it."""
    return Signature(
        bytes_=key.sign(receipt_signing_bytes(receipt)),
        public_key=key.public_key_bytes,
    )


def verify_handoff(handoff: MediaGenHandoff) -> bool:
    """Check the attached signature against the handoff preimage."""
    return _verify(
        handoff_signing_bytes(handoff),
        handoff.worker_signature,
    )


def verify_receipt(receipt: MediaGenReceipt) -> bool:
    """Check the attached signature against the receipt preimage."""
    return _verify(
        receipt_signing_bytes(receipt),
        receipt.worker_signature,
    )


def _verify(msg: bytes, signature: Signature) -> bool:
    import nacl.exceptions
    import nacl.signing

    if len(signature.public_key) != 32 or len(signature.bytes_) != 64:
        return False
    try:
        nacl.signing.VerifyKey(signature.public_key).verify(msg, signature.bytes_)
    except nacl.exceptions.BadSignatureError:
        return False
    return True
