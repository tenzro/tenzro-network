"""End-to-end proof of one decentralized outer-sync round.

Existing training tests exercise the two halves in isolation: the Rust
syncer's mean aggregator over hand-built arrays, and the state machine over
placeholder-hash gradients. Neither drives real trainers. This test closes
that gap: ``N`` independent trainers each run the real inner loop over a
*distinct* synthetic shard, package a real safetensors outer gradient
(``Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾``), and the syncer-side decode + coordinate-wise mean is
checked against the mean of the independently-trained deltas.

The point is the decentralized property, not a throughput number: each
trainer sees different data (different shard seed), so the ``N`` deltas
genuinely differ, and the aggregate is only correct if the wire format,
fragment partition, decode, and mean all agree across participants. That is
the same computation a syncer performs when it finalizes a round from
``K``-of-``M`` submissions.
"""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")
pd = pytest.importorskip("pandas")

from tenzro_trainer.adapters.timeseries import build_adapter  # noqa: E402
from tenzro_trainer.gradient import (  # noqa: E402
    TrainerKey,
    build_outer_gradient,
    compute_outer_delta,
    deserialize_fragment_delta,
    partition_state_dict,
    serialize_fragment,
)
from tenzro_trainer.inner_loop import (  # noqa: E402
    load_partial_state,
    run_inner_loop,
    snapshot_state,
)
from tenzro_trainer.types import GradientQuantization  # noqa: E402


ARCHITECTURE = {"metadata": {"d_model": 64, "num_layers": 2, "num_heads": 4}}
HYPERPARAMS = {"batch_size": 8}
FRAGMENT_COUNT = 4
INNER_STEPS = 15


def _write_shard(tmp_path, seed: int, n_points: int = 4096) -> str:
    """A univariate parquet shard the timeseries adapter can patch.

    ``seed`` distinguishes trainers: each sees a differently-phased series,
    so the deltas they produce genuinely differ.
    """
    gen = torch.Generator().manual_seed(seed)
    t = torch.arange(n_points, dtype=torch.float32)
    series = torch.sin(t * 0.05 + seed) + 0.1 * torch.randn(n_points, generator=gen)
    path = tmp_path / f"series_{seed}.parquet"
    pd.DataFrame({"value": series.numpy()}).to_parquet(path)
    return f"file://{path}"


def _round_start_state() -> dict[str, "torch.Tensor"]:
    """The θ⁽⁰⁾ the syncer broadcasts to every trainer at round start.

    In decoupled outer aggregation the trainers do not independently re-initialize — they all
    receive the same round-start weights. We model that faithfully: build one
    adapter and snapshot its trainable params as the shared broadcast.
    """
    return snapshot_state(build_adapter(ARCHITECTURE, HYPERPARAMS).model())


def _trainer_delta(
    shard_uri: str, start_state: dict[str, "torch.Tensor"]
) -> dict[str, "torch.Tensor"]:
    """Run one real inner loop from the broadcast θ⁽⁰⁾, return the outer delta.

    Fresh adapter → fresh optimizer state, but its trainable params are first
    overwritten with the shared ``start_state`` so every trainer's ``θ⁽⁰⁾`` is
    identical and the deltas are directly comparable — the outer-round
    contract. The delta is ``Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾`` over that shared start.
    """
    adapter = build_adapter(ARCHITECTURE, HYPERPARAMS)
    load_partial_state(adapter.model(), start_state)
    _pre, post, _report = run_inner_loop(adapter, shard_uri, INNER_STEPS)
    return compute_outer_delta(start_state, post)


def test_round_start_broadcast_is_shared():
    """Loading the broadcast θ⁽⁰⁾ makes every trainer's start bit-identical.

    Outer aggregation is only well-defined when all trainers share the
    round-start weights. The syncer broadcasts one θ⁽⁰⁾; each trainer loads
    it. If that load ever fails to overwrite the fresh init, the aggregate
    below stops meaning anything, so it is asserted first.
    """
    start = _round_start_state()
    a = build_adapter(ARCHITECTURE, HYPERPARAMS)
    b = build_adapter(ARCHITECTURE, HYPERPARAMS)
    load_partial_state(a.model(), start)
    load_partial_state(b.model(), start)
    sa = snapshot_state(a.model())
    sb = snapshot_state(b.model())
    assert sa.keys() == sb.keys() == start.keys()
    for k in start:
        assert torch.equal(sa[k], sb[k]), f"round-start divergence on {k}"
        assert torch.equal(sa[k], start[k]), f"broadcast not applied on {k}"


@pytest.mark.parametrize("n_trainers", [3, 5])
def test_decentralized_round_aggregate_is_mean_of_deltas(tmp_path, n_trainers):
    """N trainers → real safetensors gradients → decode + mean == mean(deltas).

    Drives the full wire path per trainer (inner loop → outer delta →
    fragment partition → safetensors serialize → sign), then the syncer path
    (decode each fragment → coordinate-wise mean), and asserts the aggregate
    equals the coordinate-wise mean of the raw deltas. Unquantized, so the
    round-trip is exact and the assertion is tight.
    """
    # The syncer broadcasts one θ⁽⁰⁾; each trainer trains on its own shard.
    start_state = _round_start_state()
    deltas = [
        _trainer_delta(_write_shard(tmp_path, seed=i), start_state)
        for i in range(n_trainers)
    ]

    # Sanity: the trainers genuinely disagree (distinct data → distinct
    # deltas). A test where every delta is identical would pass the mean
    # check trivially and prove nothing about decentralization.
    ref = next(iter(deltas[0]))
    assert not torch.allclose(deltas[0][ref], deltas[1][ref]), (
        "trainers produced identical deltas — shards are not distinct"
    )

    quant = GradientQuantization.none()
    key = TrainerKey.generate()
    address = key.public_key_bytes

    # The delta already carries only trainable params (compute_outer_delta over
    # the trainable-only start snapshot) — that is exactly what travels the wire.
    #
    # Per trainer: partition the delta into fragments, serialize + sign each,
    # then decode back exactly as the syncer would off the wire.
    decoded_per_trainer: list[dict[str, "torch.Tensor"]] = []
    for t_idx, delta in enumerate(deltas):
        fragments = partition_state_dict(delta, FRAGMENT_COUNT)
        decoded: dict[str, "torch.Tensor"] = {}
        for f_idx, frag in enumerate(fragments):
            blob = serialize_fragment(f_idx, frag, quant)
            gradient = build_outer_gradient(
                task_id="proof-task",
                round_index=0,
                blob=blob,
                trainer_did=f"did:tenzro:machine:t{t_idx}",
                trainer_address=address,
                quantization=quant,
                inner_step_count=INNER_STEPS,
                key=key,
            )
            # The digest the trainer signed must commit to the payload bytes.
            assert gradient.safetensors_hash == blob.digest
            # Syncer-side decode (reference shapes come from the fragment).
            decoded.update(deserialize_fragment_delta(blob.payload, frag, quant))
        decoded_per_trainer.append(decoded)

    # Coordinate-wise mean over the decoded deltas — the MeanAggregator's job.
    keys = decoded_per_trainer[0].keys()
    for d in decoded_per_trainer[1:]:
        assert d.keys() == keys, "fragment key set diverged across trainers"

    aggregate = {
        k: torch.stack([d[k] for d in decoded_per_trainer]).mean(dim=0) for k in keys
    }

    # Reference: coordinate-wise mean of the raw (pre-wire) deltas.
    reference = {
        k: torch.stack([dd[k] for dd in deltas]).mean(dim=0) for k in keys
    }

    for k in keys:
        assert torch.allclose(aggregate[k], reference[k], atol=1e-6), (
            f"aggregate diverged from mean-of-deltas on {k}"
        )
