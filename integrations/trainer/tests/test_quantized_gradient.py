"""Quantized fragment round-trips + OuterGradient quantization on the wire."""

from __future__ import annotations

import hashlib

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from tenzro_trainer.gradient import (
    TrainerKey,
    build_outer_gradient,
    deserialize_fragment_delta,
    flatten_fragment_values,
    serialize_fragment,
)
from tenzro_trainer.quantization import quantize
from tenzro_trainer.types import GradientQuantization


def _delta() -> dict:
    g = torch.Generator().manual_seed(0)
    return {
        "b.bias": torch.randn(4, generator=g),
        "a.weight": torch.randn(3, 4, generator=g),
    }


def test_flatten_uses_sorted_key_order():
    delta = _delta()
    flat = flatten_fragment_values(delta)
    assert flat.dtype == np.float32
    expected = np.concatenate(
        [
            delta["a.weight"].reshape(-1).numpy(),
            delta["b.bias"].reshape(-1).numpy(),
        ]
    )
    assert np.array_equal(flat, expected)


def test_serialize_fragment_int8_payload_and_digest():
    delta = _delta()
    spec = GradientQuantization.int8(8)
    blob = serialize_fragment(0, delta, spec)
    expected_payload = quantize(flatten_fragment_values(delta), spec)
    assert blob.payload == expected_payload
    assert blob.digest == hashlib.sha256(expected_payload).digest()
    assert blob.size_bytes == len(expected_payload)


def test_quantized_fragment_round_trip_error_bounds():
    delta = _delta()
    spec = GradientQuantization.int8(16)
    blob = serialize_fragment(0, delta, spec)
    out = deserialize_fragment_delta(blob.payload, delta, spec)
    assert out.keys() == delta.keys()
    flat = flatten_fragment_values(delta)
    max_abs = float(np.max(np.abs(flat)))
    bound = max_abs / 127.0 * 0.5 * 1.0001
    for k in delta:
        assert out[k].shape == delta[k].shape
        assert torch.max(torch.abs(out[k] - delta[k])).item() <= bound


def test_unquantized_fragment_round_trip_is_exact():
    delta = _delta()
    spec = GradientQuantization.none()
    blob = serialize_fragment(0, delta, spec)
    out = deserialize_fragment_delta(blob.payload, delta, spec)
    for k in delta:
        assert torch.equal(out[k], delta[k])


def test_outer_gradient_carries_quantization_on_wire():
    delta = _delta()
    spec = GradientQuantization.int4(64)
    blob = serialize_fragment(2, delta, spec)
    grad = build_outer_gradient(
        task_id="task-Q",
        round_index=1,
        blob=blob,
        trainer_did="did:tenzro:machine:t",
        trainer_address=bytes(32),
        quantization=spec,
        inner_step_count=8,
        key=TrainerKey.from_seed(bytes([9] * 32)),
        submitted_at_ms=1_000,
    )
    j = grad.to_json()
    assert j["quantization"] == {"Int4": {"block_size": 64}}
    assert j["payload_bytes"] == len(blob.payload)
    assert bytes(j["safetensors_hash"]) == hashlib.sha256(blob.payload).digest()
