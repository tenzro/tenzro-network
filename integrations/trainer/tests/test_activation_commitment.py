"""Pin the activation-commitment canonical serialization and probe selection.

The Rust side pins the identical golden vector in
``crates/tenzro-types/src/training.rs`` (``activation_commitment_golden_vector``).
If either side changes the canonical bytes, both tests break — that is the
cross-language contract for the Open-tier TOPLOC-class commitment.
"""

from __future__ import annotations

import numpy as np

from tenzro_trainer.gradient import (
    FragmentBlob,
    TrainerKey,
    build_activation_commitment,
    build_outer_gradient,
    gradient_signing_bytes,
    top_k_delta_probes,
)
from tenzro_trainer.types import (
    MAX_PROBE_K,
    ActivationCommitment,
    DeltaProbe,
    GradientQuantization,
    OuterGradient,
)

GOLDEN_HASH = "87f7d6c68ed78aa893a9186e57676e9cbbff7c58d6e1d1f4510ea71a4d7bbc60"


def golden_commitment() -> ActivationCommitment:
    return ActivationCommitment(
        k=2,
        loss_trajectory=[1.5, 0.75, 0.5],
        probes=[DeltaProbe(index=7, value=-2.5), DeltaProbe(index=3, value=1.25)],
    )


def test_golden_vector_matches_rust():
    commitment = golden_commitment()
    assert len(commitment.canonical_bytes()) == 79
    assert commitment.commitment_hash().hex() == GOLDEN_HASH


def test_top_k_probes_descending_magnitude_ties_ascending_index():
    delta = np.array([0.1, -3.0, 0.0, 3.0, -0.5, float("nan"), 2.0], dtype=np.float32)
    probes = top_k_delta_probes(delta, 4)
    assert [(p.index, p.value) for p in probes] == [
        (1, -3.0),
        (3, 3.0),
        (6, 2.0),
        (4, -0.5),
    ]


def test_top_k_probes_tie_broken_by_index():
    delta = np.array([1.0, -1.0], dtype=np.float32)
    probes = top_k_delta_probes(delta, 2)
    assert [(p.index, p.value) for p in probes] == [(0, 1.0), (1, -1.0)]


def test_build_commitment_clamps_k_to_fragment_size_and_max():
    delta = np.arange(4, dtype=np.float32) + 1.0
    commitment = build_activation_commitment([0.9, 0.8], delta, k=MAX_PROBE_K + 100)
    assert commitment.k == 4
    assert len(commitment.probes) == 4
    assert commitment.loss_trajectory == [0.9, 0.8]


def test_build_commitment_rejects_empty_delta():
    import pytest

    with pytest.raises(ValueError):
        build_activation_commitment([0.5], np.zeros(0, dtype=np.float32))


def test_signing_preimage_binds_commitment_hash():
    kwargs = dict(
        task_id="task-A",
        round_index=1,
        fragment=0,
        trainer_did="did:tenzro:machine:trainer-1",
        safetensors_hash=bytes([1] * 32),
        payload_bytes=64,
        quantization=GradientQuantization.none(),
        inner_step_count=3,
        submitted_at=1_000_000,
    )
    without = gradient_signing_bytes(**kwargs)
    assert without[-1] == 0

    commitment = golden_commitment()
    with_commitment = gradient_signing_bytes(**kwargs, commitment=commitment)
    assert with_commitment[-33] == 1
    assert with_commitment[-32:] == commitment.commitment_hash()
    # Identical prefix up to the tag byte.
    assert with_commitment[: len(without) - 1] == without[:-1]


def test_outer_gradient_json_round_trip_carries_commitment():
    key = TrainerKey.from_seed(bytes([7] * 32))
    blob = FragmentBlob(fragment=2, payload=b"y" * 40, digest=bytes([2] * 32))
    commitment = golden_commitment()
    grad = build_outer_gradient(
        task_id="task-B",
        round_index=5,
        blob=blob,
        trainer_did="did:tenzro:machine:trainer-2",
        trainer_address=bytes(32),
        quantization=GradientQuantization.none(),
        inner_step_count=3,
        key=key,
        submitted_at_ms=2_000_000,
        commitment=commitment,
    )
    restored = OuterGradient.from_json(grad.to_json())
    assert restored.commitment is not None
    assert restored.commitment.commitment_hash().hex() == GOLDEN_HASH
    assert restored.commitment.k == commitment.k
    assert restored.commitment.loss_trajectory == commitment.loss_trajectory
