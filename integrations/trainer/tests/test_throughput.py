"""Inner-loop throughput measurement over the timeseries reference adapter.

Exercises the same code path a real Phase 1 training round drives —
:func:`run_inner_loop` over :class:`TimeseriesAdapter` on a parquet shard —
and asserts the timing figures the report now carries are internally
consistent. This is the CI anchor for the published throughput number.
"""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
pd = pytest.importorskip("pandas")

from tenzro_trainer.adapters.timeseries import build_adapter  # noqa: E402
from tenzro_trainer.inner_loop import run_inner_loop  # noqa: E402


def _write_series_shard(tmp_path, n_points: int = 8192):
    """A univariate parquet shard the timeseries adapter can patch."""
    t = torch.arange(n_points, dtype=torch.float32)
    series = torch.sin(t * 0.05) + 0.1 * torch.randn(n_points, generator=torch.Generator().manual_seed(0))
    path = tmp_path / "series.parquet"
    pd.DataFrame({"value": series.numpy()}).to_parquet(path)
    return f"file://{path}"


def test_inner_loop_reports_throughput(tmp_path):
    shard_uri = _write_series_shard(tmp_path)
    adapter = build_adapter(
        {"metadata": {"d_model": 128, "num_layers": 2, "num_heads": 4}},
        {"batch_size": 8},
    )
    inner_steps = 20
    _pre, _post, report = run_inner_loop(adapter, shard_uri, inner_steps)

    assert report.steps_completed == inner_steps
    # batch_size 8 × 20 steps = 160 samples.
    assert report.samples_processed == 8 * inner_steps
    assert report.wall_seconds > 0.0
    assert report.samples_per_second > 0.0
    assert report.steps_per_second > 0.0
    # samples/s and steps/s are consistent by construction.
    assert report.samples_per_second == pytest.approx(
        report.steps_per_second * 8, rel=1e-6
    )


def test_zero_wall_seconds_yields_nan_rate():
    from tenzro_trainer.inner_loop import InnerStepReport

    r = InnerStepReport(steps_completed=1, final_loss=0.0, avg_loss=0.0)
    assert r.wall_seconds == 0.0
    assert r.samples_per_second != r.samples_per_second  # nan
    assert r.steps_per_second != r.steps_per_second  # nan
