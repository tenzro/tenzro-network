"""Lock the JSON wire format the Rust syncer expects.

The values here are not arbitrary — they describe the exact shape the Rust
``serde_json::from_value::<OuterGradient>(...)`` call in ``tenzro-node``'s
``handle_training_submit_outer_gradient`` will accept.
"""

from __future__ import annotations

import json

from tenzro_trainer.types import (
    AggregationRule,
    ArchitectureSpec,
    OuterGradient,
    Signature,
    TrainingAttestation,
    TrainingModality,
    address_from_json,
    address_to_json,
    hash_from_json,
    hash_to_json,
)


def test_hash_array_roundtrip():
    h = bytes(range(32))
    arr = hash_to_json(h)
    assert arr == list(range(32))
    assert hash_from_json(arr) == h


def test_address_array_roundtrip():
    a = bytes([1] * 32)
    assert address_to_json(a) == [1] * 32
    assert address_from_json([1] * 32) == a


def test_aggregation_mean_serializes_as_bare_string():
    # serde tags unit enum variants by their plain name.
    assert AggregationRule.mean() == "Mean"


def test_architecture_spec_roundtrip():
    spec = ArchitectureSpec(
        family="timesfm",
        param_count=200_000_000,
        modality=TrainingModality.TIMESERIES,
        fragment_count=4,
        dtype="bf16",
        metadata={"d_model": 1024},
    )
    j = spec.to_json()
    assert j["modality"] == "Timeseries"
    assert ArchitectureSpec.from_json(j) == spec


def test_outer_gradient_roundtrip_open_tier():
    grad = OuterGradient(
        task_id="task-A",
        round=3,
        fragment=2,
        trainer_did="did:tenzro:machine:trainer-7",
        trainer_address=bytes([7] * 32),
        safetensors_hash=bytes([9] * 32),
        payload_bytes=12345,
        inner_step_count=64,
        submitted_at=1_745_539_200_000,
        signature=Signature(bytes_=bytes(range(64)), public_key=bytes(range(32))),
        attestation=None,
    )
    j = grad.to_json()
    # Spot-check wire format precisely.
    assert isinstance(j["trainer_address"], list) and len(j["trainer_address"]) == 32
    assert isinstance(j["safetensors_hash"], list) and len(j["safetensors_hash"]) == 32
    assert j["submitted_at"] == 1_745_539_200_000  # bare integer, not {"0": ...}
    assert j["signature"]["bytes"] == list(range(64))
    assert j["signature"]["public_key"] == list(range(32))
    assert j["attestation"] is None
    # Round-trip.
    j2 = json.loads(json.dumps(j))
    assert OuterGradient.from_json(j2) == grad


def test_outer_gradient_with_attestation():
    att = TrainingAttestation(
        vendor="intel-tdx",
        report_hex="deadbeef",
        program_hash=bytes([0xAA] * 32),
        shard_hash=bytes([0xBB] * 32),
    )
    grad = OuterGradient(
        task_id="t",
        round=0,
        fragment=0,
        trainer_did="did:tenzro:machine:t",
        trainer_address=bytes(32),
        safetensors_hash=bytes(32),
        payload_bytes=0,
        inner_step_count=0,
        submitted_at=0,
        signature=Signature(bytes_=b"", public_key=b""),
        attestation=att,
    )
    j = grad.to_json()
    assert j["attestation"]["vendor"] == "intel-tdx"
    assert j["attestation"]["program_hash"] == [0xAA] * 32
    assert OuterGradient.from_json(j) == grad
