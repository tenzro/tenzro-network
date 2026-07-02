"""Lock the quantization codec against the Rust wire format.

The byte vectors below are the exact output of
``crates/tenzro-training/src/quantization.rs`` for the same inputs —
per-block 4-byte LE f32 scale followed by the codes.
"""

from __future__ import annotations

import struct

import numpy as np
import pytest

from tenzro_trainer.quantization import dequantize, encoded_len, quantize
from tenzro_trainer.types import GradientQuantization


def test_none_is_raw_le_f32():
    vals = np.array([0.0, 1.5, -2.25], dtype=np.float32)
    spec = GradientQuantization.none()
    data = quantize(vals, spec)
    assert data == vals.astype("<f4").tobytes()
    assert encoded_len(3, spec) == 12
    out = dequantize(data, spec, 3)
    assert np.array_equal(out, vals)


def test_int8_known_byte_vector():
    # max_abs = 127.0 → scale = 127/127 = exactly 1.0 → codes are the values.
    vals = np.array([0.0, 127.0, -127.0, 63.0], dtype=np.float32)
    spec = GradientQuantization.int8(4)
    data = quantize(vals, spec)
    assert data == struct.pack("<f", 1.0) + bytes([0x00, 0x7F, 0x81, 0x3F])
    out = dequantize(data, spec, 4)
    assert np.array_equal(out, vals)


def test_int8_rounds_half_away_from_zero():
    # Rust f32::round is half-away-from-zero, NOT banker's rounding:
    # 0.5 → 1, -0.5 → -1, 2.5 → 3 (numpy's np.round would give 0, 0, 2).
    vals = np.array([127.0, 0.5, -0.5, 2.5], dtype=np.float32)
    data = quantize(vals, GradientQuantization.int8(4))
    assert data[4:] == bytes([0x7F, 0x01, 0xFF, 0x03])


def test_int8_all_zero_block_encodes_scale_zero():
    spec = GradientQuantization.int8(4)
    data = quantize(np.zeros(3, dtype=np.float32), spec)
    assert data == struct.pack("<f", 0.0) + bytes(3)
    assert np.array_equal(dequantize(data, spec, 3), np.zeros(3, dtype=np.float32))


def test_int8_error_bound_is_half_step():
    rng = np.random.default_rng(7)
    vals = rng.standard_normal(1000).astype(np.float32)
    spec = GradientQuantization.int8(1000)  # single block
    out = dequantize(quantize(vals, spec), spec, 1000)
    scale = np.float32(np.max(np.abs(vals))) / np.float32(127.0)
    assert np.max(np.abs(out - vals)) <= float(scale) * 0.5 * 1.0001


def test_int4_known_byte_vector():
    # max_abs = 7.0 → scale = 7/7 = exactly 1.0. Codes [0, 7, -7, 3];
    # nibbles [0x0, 0x7, 0x9, 0x3] packed low-first → 0x70, 0x39.
    vals = np.array([0.0, 7.0, -7.0, 3.0], dtype=np.float32)
    spec = GradientQuantization.int4(4)
    data = quantize(vals, spec)
    assert data == struct.pack("<f", 1.0) + bytes([0x70, 0x39])
    out = dequantize(data, spec, 4)
    assert np.array_equal(out, vals)


def test_int4_rounds_half_away_from_zero():
    # scale = 1.0; codes [7, 1, -1, 3] → nibbles [0x7, 0x1, 0xF, 0x3]
    # → packed 0x17, 0x3F.
    vals = np.array([7.0, 0.5, -0.5, 2.5], dtype=np.float32)
    data = quantize(vals, GradientQuantization.int4(4))
    assert data[4:] == bytes([0x17, 0x3F])


def test_int4_odd_tail_zero_padded():
    spec = GradientQuantization.int4(4)
    vals = np.array([7.0, -7.0, 3.0, 1.0, 7.0], dtype=np.float32)
    data = quantize(vals, spec)
    # Two blocks: (4 vals → 2 bytes) + (1 val → 1 byte), 4-byte scale each.
    assert len(data) == encoded_len(5, spec) == 4 + 2 + 4 + 1
    # Tail byte's high nibble is the zero pad.
    assert data[-1] & 0xF0 == 0
    assert np.array_equal(dequantize(data, spec, 5), vals)


def test_int4_compression_ratio_exceeds_7_5x():
    n = 100_000
    spec = GradientQuantization.int4(256)
    assert (n * 4) / encoded_len(n, spec) > 7.5


def test_multi_block_boundaries():
    # Block size 2 over 5 values: three blocks with independent scales.
    vals = np.array([1.0, -2.0, 100.0, 50.0, 0.25], dtype=np.float32)
    spec = GradientQuantization.int8(2)
    data = quantize(vals, spec)
    assert len(data) == encoded_len(5, spec) == 5 + 3 * 4
    out = dequantize(data, spec, 5)
    # Per-block half-step bound.
    for start in (0, 2, 4):
        end = min(start + 2, 5)
        scale = np.float32(np.max(np.abs(vals[start:end]))) / np.float32(127.0)
        assert np.max(np.abs(out[start:end] - vals[start:end])) <= float(scale) * 0.5 * 1.0001


def test_dequantize_rejects_wrong_length():
    spec8 = GradientQuantization.int8(64)
    spec4 = GradientQuantization.int4(64)
    data = quantize(np.ones(10, dtype=np.float32), spec8)
    with pytest.raises(ValueError):
        dequantize(data + b"\x00", spec8, 10)
    with pytest.raises(ValueError):
        dequantize(data[:-1], spec8, 10)
    with pytest.raises(ValueError):
        dequantize(b"\x00" * 3, GradientQuantization.none(), 1)
    data4 = quantize(np.ones(10, dtype=np.float32), spec4)
    with pytest.raises(ValueError):
        dequantize(data4 + b"\x00", spec4, 10)


def test_encoded_len_matches_quantize_for_all_specs():
    rng = np.random.default_rng(3)
    vals = rng.standard_normal(37).astype(np.float32)
    for spec in (
        GradientQuantization.none(),
        GradientQuantization.int8(8),
        GradientQuantization.int4(8),
        GradientQuantization.int8(64),
        GradientQuantization.int4(64),
    ):
        assert len(quantize(vals, spec)) == encoded_len(37, spec)
