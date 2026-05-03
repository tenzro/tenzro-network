"""Deterministic, balanced fragment partitioning is a wire-level invariant.

Both the Python trainer and the Rust syncer must agree on the per-fragment
bucket assignment for parameter names. This test pins the algorithm so a
future refactor doesn't silently break aggregation.
"""

from __future__ import annotations

import pytest

from tenzro_trainer.gradient import fragment_indices


def test_balanced_split_no_remainder():
    spans = fragment_indices(num_params=12, fragment_count=4)
    assert spans == [(0, 3), (3, 6), (6, 9), (9, 12)]


def test_balanced_split_with_remainder_extras_go_first():
    # 13 keys into 4 buckets: first bucket gets the extra.
    spans = fragment_indices(num_params=13, fragment_count=4)
    assert spans == [(0, 4), (4, 7), (7, 10), (10, 13)]
    assert sum((b - a) for a, b in spans) == 13


def test_more_fragments_than_params_rejected():
    with pytest.raises(ValueError):
        fragment_indices(num_params=2, fragment_count=4)


def test_zero_fragments_rejected():
    with pytest.raises(ValueError):
        fragment_indices(num_params=10, fragment_count=0)


def test_single_fragment_is_full_range():
    assert fragment_indices(num_params=10, fragment_count=1) == [(0, 10)]
