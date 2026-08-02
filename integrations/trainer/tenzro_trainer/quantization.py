"""Blockwise symmetric gradient quantization — byte-identical to the Rust codec.

Mirrors ``crates/tenzro-training/src/quantization.rs``:

* **None** — raw little-endian ``f32`` values, no compression.
* **Int8** — per-block: 4-byte LE ``f32`` scale (``max_abs / 127``; an
  all-zero block encodes scale ``0.0``) followed by one ``i8`` code per value
  (``round(v / scale)`` clamped to ``[-127, 127]``). 4x smaller than f32.
* **Int4** — per-block: 4-byte LE ``f32`` scale (``max_abs / 7``) followed by
  4-bit two's-complement codes in ``[-7, 7]`` packed two per byte, low nibble
  first, odd tail zero-padded. ~8x smaller than f32.

Byte parity notes (locked by ``tests/test_quantization.py``):

* The scale is an IEEE-754 single-precision division (``f32 / f32``), so we
  compute it with ``numpy.float32`` operands before serializing.
* Rust's ``f32::round`` is round-half-away-from-zero; numpy's ``np.round``
  is banker's rounding, so we round explicitly via
  ``sign(q) * floor(|q| + 0.5)`` in float64 (exact for any f32 input).
"""

from __future__ import annotations

import struct

import numpy as np

from tenzro_trainer.types import GradientQuantization


def _round_half_away_from_zero(q: np.ndarray) -> np.ndarray:
    """Rust ``f32::round`` semantics (half away from zero), exact for f32 input."""
    q64 = q.astype(np.float64)
    return np.sign(q64) * np.floor(np.abs(q64) + 0.5)


def _iter_blocks(n: int, block_size: int) -> list[tuple[int, int]]:
    block = max(block_size, 1)
    return [(start, min(start + block, n)) for start in range(0, n, block)]


def quantize(values: np.ndarray, spec: GradientQuantization) -> bytes:
    """Encode float32 values under ``spec``. Matches Rust ``quantize`` byte-for-byte."""
    vals = np.ascontiguousarray(np.asarray(values, dtype=np.float32).reshape(-1))

    if spec.kind == "None":
        return vals.astype("<f4").tobytes()

    out = bytearray()
    for start, end in _iter_blocks(vals.size, spec.block_size):
        chunk = vals[start:end]
        max_abs = np.float32(np.max(np.abs(chunk))) if chunk.size else np.float32(0.0)
        if spec.kind == "Int8":
            scale = np.float32(max_abs) / np.float32(127.0)
            out += struct.pack("<f", float(scale))
            if scale == np.float32(0.0):
                out += bytes(chunk.size)
            else:
                q = (chunk / scale).astype(np.float32)
                codes = np.clip(_round_half_away_from_zero(q), -127, 127).astype(
                    np.int8
                )
                out += codes.tobytes()
        elif spec.kind == "Int4":
            scale = np.float32(max_abs) / np.float32(7.0)
            out += struct.pack("<f", float(scale))
            if scale == np.float32(0.0):
                codes = np.zeros(chunk.size, dtype=np.int8)
            else:
                q = (chunk / scale).astype(np.float32)
                codes = np.clip(_round_half_away_from_zero(q), -7, 7).astype(np.int8)
            nibbles = codes.astype(np.uint8) & 0x0F
            if nibbles.size % 2 == 1:
                nibbles = np.concatenate([nibbles, np.zeros(1, dtype=np.uint8)])
            packed = nibbles[0::2] | (nibbles[1::2] << np.uint8(4))
            out += packed.astype(np.uint8).tobytes()
        else:
            raise ValueError(f"unrecognized quantization kind: {spec.kind!r}")
    return bytes(out)


def dequantize(
    data: bytes, spec: GradientQuantization, expected_len: int
) -> np.ndarray:
    """Decode ``data`` into ``expected_len`` float32 values.

    Strict length validation mirrors the Rust ``dequantize`` — any byte-count
    mismatch raises :class:`ValueError` before decoding.
    """
    if expected_len < 0:
        raise ValueError("expected_len must be non-negative")

    if spec.kind == "None":
        if len(data) != expected_len * 4:
            raise ValueError(
                f"raw f32 payload must be {expected_len * 4} bytes, got {len(data)}"
            )
        return np.frombuffer(data, dtype="<f4").astype(np.float32)

    blocks = _iter_blocks(expected_len, spec.block_size)

    if spec.kind == "Int8":
        expected_bytes = expected_len + len(blocks) * 4
        if len(data) != expected_bytes:
            raise ValueError(
                f"int8 payload must be {expected_bytes} bytes for "
                f"{expected_len} values, got {len(data)}"
            )
        out = np.empty(expected_len, dtype=np.float32)
        cursor = 0
        for start, end in blocks:
            n = end - start
            scale = np.float32(struct.unpack("<f", data[cursor : cursor + 4])[0])
            cursor += 4
            codes = np.frombuffer(data, dtype=np.int8, count=n, offset=cursor)
            cursor += n
            out[start:end] = codes.astype(np.float32) * scale
        return out

    if spec.kind == "Int4":
        expected_bytes = len(blocks) * 4 + sum(
            (end - start + 1) // 2 for start, end in blocks
        )
        if len(data) != expected_bytes:
            raise ValueError(
                f"int4 payload must be {expected_bytes} bytes for "
                f"{expected_len} values, got {len(data)}"
            )
        out = np.empty(expected_len, dtype=np.float32)
        cursor = 0
        for start, end in blocks:
            n = end - start
            nbytes = (n + 1) // 2
            scale = np.float32(struct.unpack("<f", data[cursor : cursor + 4])[0])
            cursor += 4
            packed = np.frombuffer(data, dtype=np.uint8, count=nbytes, offset=cursor)
            cursor += nbytes
            nibbles = np.empty(nbytes * 2, dtype=np.uint8)
            nibbles[0::2] = packed & 0x0F
            nibbles[1::2] = (packed >> np.uint8(4)) & 0x0F
            nibbles = nibbles[:n]
            # Sign-extend the 4-bit two's-complement codes.
            codes = np.where(
                nibbles & 0x08, nibbles.astype(np.int16) - 16, nibbles.astype(np.int16)
            ).astype(np.int8)
            out[start:end] = codes.astype(np.float32) * scale
        return out

    raise ValueError(f"unrecognized quantization kind: {spec.kind!r}")


def encoded_len(length: int, spec: GradientQuantization) -> int:
    """Encoded byte count for ``length`` values — mirrors Rust ``encoded_len``."""
    if length < 0:
        raise ValueError("length must be non-negative")
    if spec.kind == "None":
        return length * 4
    blocks = _iter_blocks(length, spec.block_size)
    if spec.kind == "Int8":
        return length + len(blocks) * 4
    if spec.kind == "Int4":
        return len(blocks) * 4 + sum((end - start + 1) // 2 for start, end in blocks)
    raise ValueError(f"unrecognized quantization kind: {spec.kind!r}")


__all__ = ["dequantize", "encoded_len", "quantize"]
