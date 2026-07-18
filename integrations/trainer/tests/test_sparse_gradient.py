"""Chunked top-k + 2-bit sparse codec tests.

Byte-identical mirror of the Rust ``tenzro-training::sparse`` test suite, so a
Python trainer and a Rust syncer agree on the wire format coordinate-for-
coordinate. Each test here corresponds to one in
``crates/tenzro-training/src/sparse.rs``.
"""

from __future__ import annotations

import numpy as np
import pytest

from tenzro_trainer.gradient import (
    ErrorFeedback,
    _sparse_top_k_indices,
    select_transmitted,
    sparse_decode,
    sparse_encode,
    sparse_encoded_len,
)
from tenzro_trainer.types import OuterUpdateMode, PayloadKind, SparseTopKParams


def params() -> SparseTopKParams:
    return SparseTopKParams(chunk_size=8, k=2)


def test_encoded_len_matches_bytes() -> None:
    p = params()
    # 20 values → chunks of 8, 8, 4 → kept 2, 2, 2.
    values = np.array([float(i) - 10.0 for i in range(20)], dtype=np.float32)
    data = sparse_encode(values, p)
    assert len(data) == sparse_encoded_len(20, p)


def test_top_k_keeps_largest_magnitude() -> None:
    chunk = np.array([0.1, -5.0, 0.2, 3.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32)
    top = _sparse_top_k_indices(chunk, 2)
    assert list(top) == [1, 3]


def test_decode_recovers_sign_at_scale() -> None:
    p = params()
    values = np.zeros(8, dtype=np.float32)
    values[2] = 8.0
    values[5] = -6.0
    data = sparse_encode(values, p)
    back = sparse_decode(data, p, 8)
    # scale = max_abs = 8.0; +8 → +1*8 = 8; -6 → -1*8 = -8; rest 0.
    assert back[2] == 8.0
    assert back[5] == -8.0
    for i, v in enumerate(back):
        if i not in (2, 5):
            assert v == 0.0


def test_all_zero_chunk_round_trips_to_zeros() -> None:
    p = params()
    values = np.zeros(16, dtype=np.float32)
    back = sparse_decode(sparse_encode(values, p), p, 16)
    assert np.all(back == 0.0)


def test_wrong_length_rejected() -> None:
    p = params()
    values = np.arange(16, dtype=np.float32)
    data = sparse_encode(values, p)
    with pytest.raises(ValueError):
        sparse_decode(data, p, 17)
    with pytest.raises(ValueError):
        sparse_decode(data[:-1], p, 16)


def test_compresses_well_over_100x() -> None:
    p = SparseTopKParams()  # chunk 4096, k 64
    dense = 1_000_000 * 4
    sparse = sparse_encoded_len(1_000_000, p)
    ratio = dense / sparse
    assert ratio > 100.0, f"ratio {ratio}"


def test_select_transmitted_matches_decode() -> None:
    p = params()
    values = np.zeros(8, dtype=np.float32)
    values[1] = 4.0
    values[6] = -3.0
    sent = select_transmitted(values, p)
    back = sparse_decode(sparse_encode(values, p), p, 8)
    for idx, v in sent:
        assert back[idx] == v, f"coord {idx}"


def test_error_feedback_carries_dropped_mass() -> None:
    # decay 0.0 isolates a single round: acc after = transmit with transmitted
    # coords zeroed = the dropped residual.
    ef = ErrorFeedback(8, 0.0)
    grad = np.zeros(8, dtype=np.float32)
    grad[0] = 5.0  # kept
    grad[3] = -4.0  # kept
    grad[7] = 1.0  # dropped
    transmit = ef.prepare_transmit(grad)
    p = params()
    sent = select_transmitted(transmit, p)
    ef.commit_transmitted(transmit, sent)
    # Dropped coordinate survives; transmitted ones are reduced by what was
    # sent.
    assert ef.accumulator[7] == 1.0
    assert abs(ef.accumulator[0]) < 1e-6


def test_error_feedback_accumulates_across_rounds() -> None:
    # A coordinate always just below the top-k threshold accumulates until it
    # crosses it and gets transmitted.
    p = SparseTopKParams(chunk_size=4, k=1)
    ef = ErrorFeedback(4, 0.95)
    grad = np.array([1.0, 0.9, 0.0, 0.0], dtype=np.float32)
    crossed = False
    for _ in range(20):
        t = ef.prepare_transmit(grad)
        sent = select_transmitted(t, p)
        if any(i == 1 for i, _ in sent):
            crossed = True
            break
        ef.commit_transmitted(t, sent)
    assert crossed, "error feedback never surfaced the sub-threshold coord"


def test_dim_mismatch_rejected() -> None:
    ef = ErrorFeedback(8, 0.95)
    with pytest.raises(ValueError):
        ef.prepare_transmit(np.zeros(7, dtype=np.float32))


def test_error_feedback_state_round_trips() -> None:
    ef = ErrorFeedback(4, 0.9)
    ef.commit_transmitted(
        np.array([1.0, 2.0, 3.0, 4.0], dtype=np.float32), [(0, 1.0)]
    )
    restored = ErrorFeedback.load_state_dict(ef.state_dict())
    assert restored.decay == ef.decay
    assert np.array_equal(restored.accumulator, ef.accumulator)


def test_payload_kind_json_round_trip() -> None:
    assert PayloadKind.from_json(PayloadKind.dense().to_json()).is_dense
    sk = PayloadKind.sparse_topk(SparseTopKParams(chunk_size=2048, k=32))
    back = PayloadKind.from_json(sk.to_json())
    assert not back.is_dense
    assert back.sparse.chunk_size == 2048
    assert back.sparse.k == 32


def test_outer_update_mode_json_round_trip() -> None:
    nest = OuterUpdateMode.nesterov(lr=0.7, momentum=0.9)
    back = OuterUpdateMode.from_json(nest.to_json())
    assert back.carries_momentum
    ef = OuterUpdateMode.sparse_ef(lr=0.5)
    back_ef = OuterUpdateMode.from_json(ef.to_json())
    assert not back_ef.carries_momentum
    assert back_ef.lr == 0.5
