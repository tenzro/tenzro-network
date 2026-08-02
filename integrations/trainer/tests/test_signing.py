"""Verify Ed25519 signing and the canonical preimage.

The preimage layout matches the convention documented in ``gradient.py`` —
domain prefix ``tenzro/train/outer-gradient`` + BE-encoded fields. Phase 2
will lift signature verification into the Rust syncer; this test pins the
preimage so the eventual Rust verifier is forwards-compatible.
"""

from __future__ import annotations

import nacl.signing

from tenzro_trainer.gradient import (
    FragmentBlob,
    TrainerKey,
    build_outer_gradient,
    gradient_signing_bytes,
)
from tenzro_trainer.types import GradientQuantization


def test_preimage_layout_is_stable():
    msg = gradient_signing_bytes(
        task_id="task-A",
        round_index=3,
        fragment=2,
        trainer_did="did:tenzro:machine:trainer-7",
        safetensors_hash=bytes([9] * 32),
        payload_bytes=12345,
        quantization=GradientQuantization.none(),
        inner_step_count=64,
        submitted_at=1_745_539_200_000,
    )
    # Header.
    assert msg.startswith(b"tenzro/train/outer-gradient")
    # Round (BE u32).
    rest = msg[len(b"tenzro/train/outer-gradient") :]
    rest = rest[len(b"task-A") :]
    assert rest[:4] == (3).to_bytes(4, "big")
    assert rest[4:8] == (2).to_bytes(4, "big")


def test_signature_is_verifiable_with_public_key():
    key = TrainerKey.generate()
    msg = b"hello tenzro train"
    sig = key.sign(msg)
    # NaCl raises on invalid signature.
    nacl.signing.VerifyKey(key.public_key_bytes).verify(msg, sig)


def test_build_outer_gradient_signs_canonical_preimage():
    seed = bytes([42] * 32)
    key = TrainerKey.from_seed(seed)
    blob = FragmentBlob(fragment=0, payload=b"x" * 100, digest=bytes([1] * 32))
    grad = build_outer_gradient(
        task_id="task-A",
        round_index=0,
        blob=blob,
        trainer_did="did:tenzro:machine:trainer-1",
        trainer_address=bytes(32),
        quantization=GradientQuantization.none(),
        inner_step_count=10,
        key=key,
        submitted_at_ms=1_000_000,
    )
    expected_msg = gradient_signing_bytes(
        task_id="task-A",
        round_index=0,
        fragment=0,
        trainer_did="did:tenzro:machine:trainer-1",
        safetensors_hash=bytes([1] * 32),
        payload_bytes=100,
        quantization=GradientQuantization.none(),
        inner_step_count=10,
        submitted_at=1_000_000,
    )
    nacl.signing.VerifyKey(grad.signature.public_key).verify(
        expected_msg, grad.signature.bytes_
    )
