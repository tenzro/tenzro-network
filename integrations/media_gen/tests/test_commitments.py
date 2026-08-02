"""Job identity and signing preimages.

Mirrors ``crates/tenzro-media-gen/src/commitments.rs``'s own tests over the
same fixtures. A digest computed here has to equal the one Rust computes, so
the properties asserted below are the ones both sides depend on: which fields
are bound, which are not, and that no field boundary is ambiguous.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import replace

import pytest

from tenzro_media_gen.commitments import (
    HANDOFF_TAG,
    JOB_ID_TAG,
    RECEIPT_TAG,
    compute_job_id,
    encode_params,
    expected_job_id,
    handoff_commitment,
    handoff_signing_bytes,
    receipt_commitment,
    receipt_signing_bytes,
)
from tenzro_media_gen.types import MediaGenKind, MediaGenParams, Signature

ZERO_ADDRESS = bytes(32)


def test_job_id_is_deterministic(spec):
    assert expected_job_id(spec) == expected_job_id(spec)
    assert len(spec.job_id) == 64
    assert spec.job_id == spec.job_id.lower()
    bytes.fromhex(spec.job_id)


def test_job_id_binds_the_prompt(spec):
    other = replace(spec, params=replace(spec.params, prompt="a fox in a steel diorama"))
    assert expected_job_id(other) != expected_job_id(spec)


def test_job_id_binds_the_model(spec):
    assert expected_job_id(replace(spec, model_id="z-image-turbo")) != expected_job_id(spec)


def test_job_id_binds_the_kind(spec):
    other = replace(spec, kind=MediaGenKind.TEXT2VIDEO)
    assert expected_job_id(other) != expected_job_id(spec)


def test_job_id_binds_the_price_ceiling(spec):
    other = replace(spec, max_price=spec.max_price + 1)
    assert expected_job_id(other) != expected_job_id(spec)


def test_job_id_binds_the_timestamp(spec):
    """Reposting the same prompt yields a new job; a retried post does not."""
    other = replace(spec, created_at=spec.created_at + 1)
    assert expected_job_id(other) != expected_job_id(spec)


def test_job_id_ignores_the_carried_id(spec):
    """A spec claiming someone else's id still hashes to its own contents."""
    forged = replace(spec, job_id="0" * 64)
    assert expected_job_id(forged) == spec.job_id


def test_job_id_ignores_opaque_metadata(spec):
    """``metadata`` has no canonical ordering across encoders, so it is excluded."""
    tuned = replace(spec.params, metadata={"scheduler": "unipc", "shift": "3.0"})
    assert expected_job_id(replace(spec, params=tuned)) == spec.job_id


def test_length_prefix_removes_field_boundary_ambiguity():
    """Two field splits of the same concatenation must not collide."""

    def encode(prompt: str, negative: str) -> bytes:
        return encode_params(
            MediaGenParams(
                prompt=prompt,
                negative_prompt=negative,
                width=64,
                height=64,
                steps=1,
                guidance_scale=1.0,
            )
        )

    assert encode("ab", "cd") != encode("a", "bcd")


def test_guidance_scale_is_the_ieee754_big_endian_pattern():
    encoded = encode_params(
        MediaGenParams(prompt="x", width=64, height=64, steps=1, guidance_scale=4.5)
    )
    assert struct.pack(">f", 4.5) in encoded


def test_negative_timestamps_encode_as_signed_i64(spec):
    """Two's-complement i64 millis, matching Rust's ``Timestamp``."""
    other = replace(spec, created_at=-1_000)
    assert len(expected_job_id(other)) == 64
    assert expected_job_id(other) != expected_job_id(replace(spec, created_at=1_000))


def test_job_id_preimage_carries_the_domain_tag(spec):
    """Recomputing the digest by hand pins the tag and the field order."""
    manual = hashlib.sha256(
        JOB_ID_TAG
        + len(spec.requester_did.encode()).to_bytes(4, "big")
        + spec.requester_did.encode()
        + len(ZERO_ADDRESS).to_bytes(4, "big")
        + ZERO_ADDRESS
        + len(spec.model_id.encode()).to_bytes(4, "big")
        + spec.model_id.encode()
        + len(spec.kind.value.encode()).to_bytes(4, "big")
        + spec.kind.value.encode()
        + encode_params(spec.params)
        + spec.max_price.to_bytes(16, "big")
        + spec.created_at.to_bytes(8, "big", signed=True)
    ).hexdigest()
    assert manual == spec.job_id


def test_compute_job_id_rejects_a_short_address(spec):
    with pytest.raises(ValueError, match="32 bytes"):
        compute_job_id(
            spec.requester_did,
            b"\x00" * 20,
            spec.model_id,
            spec.kind,
            spec.params,
            spec.max_price,
            spec.created_at,
        )


def test_receipt_commitment_binds_the_output(receipt):
    base = receipt_commitment(receipt)
    assert receipt_commitment(replace(receipt, output_hash=bytes([8] * 32))) != base
    assert receipt_commitment(replace(receipt, output_mime="image/webp")) != base
    assert receipt_commitment(replace(receipt, output_bytes=4096)) != base
    assert receipt_commitment(replace(receipt, price_paid=1)) != base


def test_receipt_commitment_binds_the_executed_spec(receipt):
    """The parameters the worker ran cannot be swapped after signing."""
    tampered = replace(
        receipt,
        task_spec=replace(receipt.task_spec, params=replace(receipt.task_spec.params, steps=4)),
    )
    assert receipt_commitment(tampered) != receipt_commitment(receipt)


def test_receipt_commitment_ignores_the_signature(receipt):
    signed = replace(
        receipt,
        worker_signature=Signature(bytes_=bytes(64), public_key=bytes(32)),
    )
    assert receipt_commitment(signed) == receipt_commitment(receipt)


def test_receipt_preimage_carries_the_domain_tag(receipt):
    assert receipt_signing_bytes(receipt).startswith(RECEIPT_TAG)
    assert receipt_commitment(receipt) == hashlib.sha256(receipt_signing_bytes(receipt)).digest()


def test_handoff_commitment_binds_the_latent_and_the_step_count(handoff):
    """``steps_completed`` sets the payment split, so it has to be signed over."""
    base = handoff_commitment(handoff)
    assert handoff_commitment(replace(handoff, latent_hash=bytes([6] * 32))) != base
    assert handoff_commitment(replace(handoff, latent_bytes=1)) != base
    assert handoff_commitment(replace(handoff, steps_completed=27)) != base


def test_handoff_commitment_ignores_the_signature(handoff):
    signed = replace(
        handoff,
        worker_signature=Signature(bytes_=bytes(64), public_key=bytes(32)),
    )
    assert handoff_commitment(signed) == handoff_commitment(handoff)


def test_handoff_preimage_carries_the_domain_tag(handoff):
    assert handoff_signing_bytes(handoff).startswith(HANDOFF_TAG)
    assert handoff_commitment(handoff) == hashlib.sha256(handoff_signing_bytes(handoff)).digest()


def test_handoff_and_receipt_digests_do_not_collide(handoff, receipt):
    """Distinct tags keep a handoff signature from being replayed as a receipt."""
    assert handoff_commitment(handoff) != receipt_commitment(receipt)
    assert HANDOFF_TAG != RECEIPT_TAG != JOB_ID_TAG
