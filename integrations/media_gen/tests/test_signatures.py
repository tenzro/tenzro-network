"""Worker keys and the two signatures a worker produces.

A handoff signature attests the intermediate latent and the step count the
payment split is computed from; a receipt signature attests the render and the
parameters it was produced under. Both are Ed25519 over the preimages in
:mod:`tenzro_media_gen.commitments`.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from tenzro_media_gen.commitments import (
    WorkerKey,
    sign_handoff,
    sign_receipt,
    verify_handoff,
    verify_receipt,
)
from tenzro_media_gen.types import Signature


@pytest.fixture
def key() -> WorkerKey:
    return WorkerKey.from_seed(bytes(range(32)))


def test_a_key_round_trips_through_its_seed(key):
    assert len(key.seed_bytes) == 32
    assert len(key.public_key_bytes) == 32
    assert WorkerKey.from_seed_hex(key.seed_bytes.hex()).public_key_bytes == (
        key.public_key_bytes
    )


def test_generated_keys_are_distinct():
    assert WorkerKey.generate().public_key_bytes != WorkerKey.generate().public_key_bytes


def test_a_short_seed_is_rejected():
    with pytest.raises(ValueError, match="32 bytes"):
        WorkerKey.from_seed(b"\x00" * 16)


def test_a_signed_handoff_verifies(handoff, key):
    handoff.worker_signature = sign_handoff(handoff, key)
    assert handoff.worker_signature.public_key == key.public_key_bytes
    assert len(handoff.worker_signature.bytes_) == 64
    assert verify_handoff(handoff)


def test_a_signed_receipt_verifies(receipt, key):
    receipt.worker_signature = sign_receipt(receipt, key)
    assert verify_receipt(receipt)


def test_an_unsigned_handoff_does_not_verify(handoff):
    assert not verify_handoff(handoff)


def test_restating_the_step_count_invalidates_the_handoff(handoff, key):
    """Overstating a half of the schedule would take a forged signature."""
    handoff.worker_signature = sign_handoff(handoff, key)
    assert not verify_handoff(replace(handoff, steps_completed=39))


def test_swapping_the_latent_invalidates_the_handoff(handoff, key):
    handoff.worker_signature = sign_handoff(handoff, key)
    assert not verify_handoff(replace(handoff, latent_hash=bytes([6] * 32)))


def test_swapping_the_output_invalidates_the_receipt(receipt, key):
    receipt.worker_signature = sign_receipt(receipt, key)
    assert not verify_receipt(replace(receipt, output_hash=bytes([8] * 32)))


def test_rewriting_the_executed_spec_invalidates_the_receipt(receipt, key):
    receipt.worker_signature = sign_receipt(receipt, key)
    tampered = replace(
        receipt,
        task_spec=replace(
            receipt.task_spec, params=replace(receipt.task_spec.params, steps=4)
        ),
    )
    assert not verify_receipt(tampered)


def test_another_key_s_signature_does_not_verify(receipt, key):
    receipt.worker_signature = sign_receipt(receipt, key)
    impostor = replace(
        receipt,
        worker_signature=Signature(
            bytes_=receipt.worker_signature.bytes_,
            public_key=WorkerKey.generate().public_key_bytes,
        ),
    )
    assert not verify_receipt(impostor)


def test_a_handoff_signature_is_not_a_valid_receipt_signature(handoff, receipt, key):
    """Distinct domain tags keep one signature from being replayed as the other."""
    signed = sign_handoff(handoff, key)
    assert not verify_receipt(replace(receipt, worker_signature=signed))


@pytest.mark.parametrize(
    "signature",
    [
        Signature(bytes_=bytes(64), public_key=b"short"),
        Signature(bytes_=b"short", public_key=bytes(32)),
        Signature.empty(),
    ],
)
def test_malformed_signature_lengths_are_rejected_without_raising(receipt, signature):
    assert not verify_receipt(replace(receipt, worker_signature=signature))
