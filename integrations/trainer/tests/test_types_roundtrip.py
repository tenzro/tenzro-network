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
    GradientQuantization,
    OuterGradient,
    PipelineAssignment,
    PipelineConfig,
    Signature,
    SyncStrategy,
    TrainingAttestation,
    TrainingModality,
    TrainingTaskSpec,
    TrainingTier,
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
        quantization=GradientQuantization.none(),
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
    assert j["quantization"] == "None"  # serde unit variant = bare string
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
        quantization=GradientQuantization.int8(64),
        inner_step_count=0,
        submitted_at=0,
        signature=Signature(bytes_=b"", public_key=b""),
        attestation=att,
    )
    j = grad.to_json()
    assert j["attestation"]["vendor"] == "intel-tdx"
    assert j["attestation"]["program_hash"] == [0xAA] * 32
    assert j["quantization"] == {"Int8": {"block_size": 64}}
    assert OuterGradient.from_json(j) == grad


def test_gradient_quantization_wire_format():
    # serde externally-tagged encoding, locked against literal JSON.
    assert GradientQuantization.none().to_json() == "None"
    assert GradientQuantization.int8(64).to_json() == {"Int8": {"block_size": 64}}
    assert GradientQuantization.int4(128).to_json() == {"Int4": {"block_size": 128}}
    for j in ("None", {"Int8": {"block_size": 64}}, {"Int4": {"block_size": 128}}):
        q = GradientQuantization.from_json(j)
        assert q.to_json() == j
    assert GradientQuantization.none().label() == "none"
    assert GradientQuantization.int8(64).label() == "int8/64"
    assert GradientQuantization.int4(128).label() == "int4/128"
    try:
        GradientQuantization.from_json({"Int2": {"block_size": 4}})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_sync_strategy_wire_format_and_math():
    assert SyncStrategy.full().to_json() == "Full"
    assert SyncStrategy.streaming(4).to_json() == {"Streaming": {"num_shards": 4}}
    assert SyncStrategy.from_json("Full") == SyncStrategy.full()
    assert SyncStrategy.from_json({"Streaming": {"num_shards": 4}}) == (
        SyncStrategy.streaming(4)
    )
    # Contiguous shard partition — pins the Rust `shard_of_fragment` math.
    s = SyncStrategy.streaming(4)
    assert [s.shard_of_fragment(f, 8) for f in range(8)] == [0, 0, 1, 1, 2, 2, 3, 3]
    s2 = SyncStrategy.streaming(2)
    assert [s2.shard_of_fragment(f, 5) for f in range(5)] == [0, 0, 0, 1, 1]
    # Rotation: shard `round % num_shards` is the active one.
    assert s.active_shard(0) == 0
    assert s.active_shard(5) == 1
    assert s.fragment_active(2, 8, 1)  # fragment 2 is shard 1, round 1 → shard 1
    assert not s.fragment_active(2, 8, 0)
    # Full: everything syncs every round.
    full = SyncStrategy.full()
    assert all(full.fragment_active(f, 8, r) for f in range(8) for r in range(3))


def test_pipeline_wire_format_and_math():
    cfg = PipelineConfig(num_stages=2)
    assert cfg.to_json() == {"num_stages": 2}
    assert PipelineConfig.from_json({"num_stages": 2}) == cfg
    assert [cfg.stage_of_fragment(f, 4) for f in range(4)] == [0, 0, 1, 1]
    a = PipelineAssignment(group_id=1, stage=0)
    assert a.to_json() == {"group_id": 1, "stage": 0}
    assert PipelineAssignment.from_json({"group_id": 1, "stage": 0}) == a


def test_training_task_spec_roundtrip():
    spec = TrainingTaskSpec(
        task_id="task-B",
        sponsor_did="did:tenzro:human:sponsor",
        sponsor_address=bytes([3] * 32),
        architecture=ArchitectureSpec(
            family="timesfm",
            param_count=200_000_000,
            modality=TrainingModality.TIMESERIES,
            fragment_count=8,
            dtype="bf16",
            metadata={"inner_optimizer": "muon"},
        ),
        tier=TrainingTier.OPEN,
        aggregation=AggregationRule.mean(),
        clip_l2_norm=0.08,
        sync_strategy=SyncStrategy.streaming(4),
        quantization=GradientQuantization.int4(64),
        delayed_apply=True,
        pipeline=PipelineConfig(num_stages=2),
        trainer_count=4,
        quorum=3,
        inner_steps=32,
        max_rounds=10,
        grace_window_ms=30_000,
        reward_pool=10**18,
        dataset_ref="tenzro://shard/abc",
        dataset_hash=bytes([5] * 32),
        min_throughput=None,
        created_at=1_745_539_200_000,
        metadata={"inner_optimizer": "muon"},
    )
    j = json.loads(json.dumps(spec.to_json()))
    assert j["sync_strategy"] == {"Streaming": {"num_shards": 4}}
    assert j["quantization"] == {"Int4": {"block_size": 64}}
    assert j["delayed_apply"] is True
    assert j["pipeline"] == {"num_stages": 2}
    assert j["min_throughput"] is None
    assert j["clip_l2_norm"] == 0.08
    assert TrainingTaskSpec.from_json(j) == spec
    # Full/None/no-pipeline variant.
    spec2 = TrainingTaskSpec.from_json(
        {
            **spec.to_json(),
            "sync_strategy": "Full",
            "quantization": "None",
            "delayed_apply": False,
            "pipeline": None,
        }
    )
    assert spec2.sync_strategy == SyncStrategy.full()
    assert spec2.quantization == GradientQuantization.none()
    assert spec2.pipeline is None
