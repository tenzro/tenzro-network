"""Cross-node proof: N trainers drive a live ``tenzro-node`` over JSON-RPC.

The other training tests run the syncer and the trainers in the same Python
(or Rust) process — no gradient ever crosses a network boundary. This test
boots a real ``tenzro-node`` binary as a subprocess, then drives the full
outer-sync protocol against it purely over JSON-RPC on ``:8545``:

1. post a task     (``tenzro_training_postTask``)
2. enroll trainers (``tenzro_training_enrollTrainer``) until the run reaches
   ``quorum`` and flips to ``Training``
3. run ``R`` rounds — each round, every trainer runs its real inner loop from
   the shared broadcast ``θ⁽⁰⁾``, packages a signed ``OuterGradient`` per
   fragment, and submits it (``tenzro_training_submitOuterGradient``); then a
   coordinator finalizes the round (``tenzro_training_finalizeRound``)
4. assert ``getRun.current_round`` advanced once per round and the run holds
   all ``N`` trainers throughout

This is what proves the RPC transport, the node-side ``SyncerState`` gates
(enroll-before-submit, round match, signature verify), and the idempotent
multi-round ``finalize`` all agree with the Python wire mirrors — the piece
the in-process tests cannot exercise.

The node binary path is taken from ``TENZRO_NODE_BIN``. When it is unset the
test skips (a plain ``pytest`` run on a machine with no compiled binary is a
skip, not a failure); the Cloud Build config builds the binary and sets the
env var so CI runs it for real.
"""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import time

import pytest

torch = pytest.importorskip("torch")
pd = pytest.importorskip("pandas")
requests = pytest.importorskip("requests")

from tenzro_trainer.adapters.timeseries import build_adapter  # noqa: E402
from tenzro_trainer.gradient import (  # noqa: E402
    TrainerKey,
    build_outer_gradient,
    compute_outer_delta,
    partition_state_dict,
    serialize_fragment,
)
from tenzro_trainer.inner_loop import (  # noqa: E402
    load_partial_state,
    run_inner_loop,
    snapshot_state,
)
from tenzro_trainer.rpc_bridge import RpcClient  # noqa: E402
from tenzro_trainer.types import (  # noqa: E402
    AggregationRule,
    ArchitectureSpec,
    GradientQuantization,
    SyncStrategy,
    TrainingModality,
    TrainingTaskSpec,
    TrainingTier,
)


ARCHITECTURE = {"metadata": {"d_model": 64, "num_layers": 2, "num_heads": 4}}
HYPERPARAMS = {"batch_size": 8}
FRAGMENT_COUNT = 4
INNER_STEPS = 12
NUM_TRAINERS = 3
NUM_ROUNDS = 3

NODE_BIN = os.environ.get("TENZRO_NODE_BIN")

pytestmark = pytest.mark.skipif(
    not NODE_BIN,
    reason="TENZRO_NODE_BIN unset — needs a compiled tenzro-node (built in CI)",
)


# ---------------------------------------------------------------------------
# Node lifecycle
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_rpc(
    url: str,
    proc: subprocess.Popen,
    log_path: str,
    timeout_secs: float = 180.0,
):
    """Poll the RPC port until a JSON-RPC call succeeds or the node dies.

    On failure, the node's own stdout/stderr (captured to ``log_path``) is
    appended to the raised error so a CI run is self-diagnosing rather than
    opaque — a bare "RPC did not come up" tells us nothing about *why*.
    """

    def _node_log_tail(n: int = 80) -> str:
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return "<node produced no output>"
        tail = "".join(lines[-n:]).strip()
        return tail or "<node produced no output>"

    deadline = time.time() + timeout_secs
    last_err: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"tenzro-node exited early with code {proc.returncode} "
                f"before RPC came up.\n--- node output ---\n{_node_log_tail()}"
            )
        try:
            resp = requests.post(
                url,
                json={"jsonrpc": "2.0", "method": "tenzro_training_listRuns", "id": 1},
                timeout=2.0,
            )
            if resp.status_code == 200 and "result" in resp.json():
                return
        except Exception as e:  # noqa: BLE001 - connection refused while booting
            last_err = e
        time.sleep(0.5)
    raise RuntimeError(
        f"tenzro-node RPC did not come up within {timeout_secs}s: {last_err}\n"
        f"--- node output ---\n{_node_log_tail()}"
    )


@pytest.fixture()
def running_node():
    """Boot a loopback RPC-only ``tenzro-node`` (``--roles ai``) as a subprocess.

    ``--roles ai`` gives the RPC server + training runtime without requiring a
    validator identity, genesis committee, or consensus — exactly the surface a
    trainer talks to. Everything binds on loopback so nothing leaves the box.
    """
    rpc_port = _free_port()
    rpc_addr = f"127.0.0.1:{rpc_port}"
    url = f"http://{rpc_addr}"

    with tempfile.TemporaryDirectory(prefix="tenzro-node-xnode-") as data_dir:
        cmd = [
            NODE_BIN,
            "--roles",
            "ai",
            "--rpc-addr",
            rpc_addr,
            "--data-dir",
            data_dir,
            # Loopback-only transport; a random high port avoids collisions.
            "--listen-addr",
            f"/ip4/127.0.0.1/tcp/{_free_port()}",
        ]
        # Route the node's stdout+stderr to a file so a failed boot is
        # diagnosable — an in-process PIPE would only be drained after the
        # node answers, which is exactly the path that doesn't happen on
        # failure.
        log_path = os.path.join(data_dir, "tenzro-node.log")
        # Ensure the node emits init-progress logs so a stalled boot is
        # legible in the captured file (the node is otherwise near-silent).
        node_env = {**os.environ, "RUST_LOG": os.environ.get("RUST_LOG", "info")}
        with open(log_path, "w", encoding="utf-8") as log_fh:
            proc = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                text=True,
                env=node_env,
            )
            try:
                _wait_for_rpc(url, proc, log_path)
                yield url
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# Trainer helpers (shared with test_decentralized_round.py in spirit)
# ---------------------------------------------------------------------------


def _write_shard(tmp_path, seed: int, n_points: int = 4096) -> str:
    gen = torch.Generator().manual_seed(seed)
    t = torch.arange(n_points, dtype=torch.float32)
    series = torch.sin(t * 0.05 + seed) + 0.1 * torch.randn(n_points, generator=gen)
    path = tmp_path / f"series_{seed}.parquet"
    pd.DataFrame({"value": series.numpy()}).to_parquet(path)
    return f"file://{path}"


def _round_start_state() -> dict[str, "torch.Tensor"]:
    return snapshot_state(build_adapter(ARCHITECTURE, HYPERPARAMS).model())


def _trainer_delta(
    shard_uri: str, start_state: dict[str, "torch.Tensor"]
) -> dict[str, "torch.Tensor"]:
    adapter = build_adapter(ARCHITECTURE, HYPERPARAMS)
    load_partial_state(adapter.model(), start_state)
    _pre, post, _report = run_inner_loop(adapter, shard_uri, INNER_STEPS)
    return compute_outer_delta(start_state, post)


def _task_spec(task_id: str) -> TrainingTaskSpec:
    """Open-tier, mean-aggregation, unquantized, full-sync timeseries task.

    ``quorum == NUM_TRAINERS`` so the run flips to ``Training`` only once every
    trainer has enrolled; ``max_rounds`` bounds the run.
    """
    architecture = ArchitectureSpec(
        family="timeseries-toy",
        param_count=0,
        modality=TrainingModality.TIMESERIES,
        fragment_count=FRAGMENT_COUNT,
        dtype="f32",
        metadata=ARCHITECTURE["metadata"],
    )
    return TrainingTaskSpec(
        task_id=task_id,
        sponsor_did="did:tenzro:machine:sponsor-xnode",
        sponsor_address=bytes(32),
        architecture=architecture,
        tier=TrainingTier.OPEN,
        aggregation=AggregationRule.mean(),
        clip_l2_norm=None,
        sync_strategy=SyncStrategy.full(),
        quantization=GradientQuantization.none(),
        delayed_apply=False,
        pipeline=None,
        trainer_count=NUM_TRAINERS,
        quorum=NUM_TRAINERS,
        inner_steps=INNER_STEPS,
        max_rounds=NUM_ROUNDS,
        grace_window_ms=60_000,
        reward_pool=0,
        dataset_ref="file://cross-node-proof",
        dataset_hash=bytes(32),
        min_throughput=None,
        created_at=int(time.time() * 1000),
        metadata={},
    )


# ---------------------------------------------------------------------------
# The proof
# ---------------------------------------------------------------------------


def test_cross_node_multi_round_over_rpc(running_node, tmp_path):
    url = running_node
    client = RpcClient(url=url)
    task_id = "cross-node-proof"

    # 1. Sponsor posts the task; the node becomes the syncer for it.
    posted = client.post_task(_task_spec(task_id))
    assert posted["task_id"] == task_id
    assert posted["status"] == "registered"

    # Fresh syncer: no rounds, no trainers, not yet Training.
    run = client.get_run(task_id)
    assert run["current_round"] == 0
    assert run["trainers"] == []
    assert run["status"] in ("Enrolling", "Pending")

    # 2. Enroll N trainers. Each is a distinct Ed25519 key + DID. The run flips
    #    to Training once the quorum-th trainer enrolls.
    keys = [TrainerKey.generate() for _ in range(NUM_TRAINERS)]
    dids = [f"did:tenzro:machine:xnode-t{i}" for i in range(NUM_TRAINERS)]
    for i, did in enumerate(dids):
        res = client.enroll_trainer(task_id, did)
        assert res["trainer_count"] == i + 1
    run = client.get_run(task_id)
    assert len(run["trainers"]) == NUM_TRAINERS
    assert set(run["trainers"]) == set(dids)
    assert run["status"] == "Training", (
        f"run should be Training after quorum enrollment, got {run['status']}"
    )

    quant = GradientQuantization.none()

    # 3. Run R outer rounds. Every round, all N trainers train from the shared
    #    broadcast θ⁽⁰⁾, submit real signed gradients, then the round is
    #    finalized over RPC. Assert current_round advances exactly once/round.
    for round_index in range(NUM_ROUNDS):
        # The syncer broadcasts one θ⁽⁰⁾ per round; each trainer trains its own
        # shard from it. Re-seed shards per round so gradients differ round over
        # round (proves the round advance carries fresh work, not a replay).
        start_state = _round_start_state()
        deltas = [
            _trainer_delta(
                _write_shard(tmp_path, seed=round_index * 100 + t_idx), start_state
            )
            for t_idx in range(NUM_TRAINERS)
        ]

        # Each trainer submits every fragment of its delta over RPC.
        for t_idx, delta in enumerate(deltas):
            fragments = partition_state_dict(delta, FRAGMENT_COUNT)
            for f_idx, frag in enumerate(fragments):
                blob = serialize_fragment(f_idx, frag, quant)
                gradient = build_outer_gradient(
                    task_id=task_id,
                    round_index=round_index,
                    blob=blob,
                    trainer_did=dids[t_idx],
                    trainer_address=keys[t_idx].public_key_bytes,
                    quantization=quant,
                    inner_step_count=INNER_STEPS,
                    key=keys[t_idx],
                )
                # The node accepts the gradient only if enrolled + round matches
                # + signature verifies. A rejected submission raises RpcError.
                accepted = client.submit_outer_gradient(gradient)
                assert accepted["accepted"] is True

        # A gradient for the wrong round must be rejected by the node — the
        # round gate is a real fail-closed check, not advisory.
        stale_blob = serialize_fragment(
            0, partition_state_dict(deltas[0], FRAGMENT_COUNT)[0], quant
        )
        stale = build_outer_gradient(
            task_id=task_id,
            round_index=round_index + 99,
            blob=stale_blob,
            trainer_did=dids[0],
            trainer_address=keys[0].public_key_bytes,
            quantization=quant,
            inner_step_count=INNER_STEPS,
            key=keys[0],
        )
        with pytest.raises(Exception):
            client.submit_outer_gradient(stale)

        # 4. Coordinator finalizes the round. post_step_hashes are the SHA-256
        #    digests of each fragment's post-aggregation blob; here we reuse the
        #    trainer-0 fragment digests as stand-in post-step hashes (the node
        #    only requires 32-byte hashes per fragment to build the SyncRound
        #    state root — the aggregate math is validated in the in-process
        #    test; this test validates the RPC + round-advance protocol).
        frags0 = partition_state_dict(deltas[0], FRAGMENT_COUNT)
        post_hashes = {
            f_idx: serialize_fragment(f_idx, frag, quant).digest
            for f_idx, frag in enumerate(frags0)
        }
        sync_round = client.finalize_round(task_id, round_index, post_hashes)
        assert "state_root" in sync_round

        # current_round advanced to round_index + 1.
        run = client.get_run(task_id)
        assert run["current_round"] == round_index + 1, (
            f"round {round_index} did not advance current_round over RPC"
        )
        # Trainer set is stable across rounds.
        assert set(run["trainers"]) == set(dids)

    # After R rounds the syncer has advanced R times over the wire.
    run = client.get_run(task_id)
    assert run["current_round"] == NUM_ROUNDS


def test_finalize_round_is_idempotent_over_rpc(running_node, tmp_path):
    """Re-finalizing a round with the same state root is a no-op, not an error.

    Two witnesses submitting the same finalize for the same round is the
    expected production shape (k-of-N committee). The node's finalize is
    idempotent on a matching state root; this asserts that property holds
    across the RPC boundary.
    """
    url = running_node
    client = RpcClient(url=url)
    task_id = "cross-node-idempotent"

    client.post_task(_task_spec(task_id))
    keys = [TrainerKey.generate() for _ in range(NUM_TRAINERS)]
    dids = [f"did:tenzro:machine:idem-t{i}" for i in range(NUM_TRAINERS)]
    for did in dids:
        client.enroll_trainer(task_id, did)

    quant = GradientQuantization.none()
    start_state = _round_start_state()
    deltas = [
        _trainer_delta(_write_shard(tmp_path, seed=i), start_state)
        for i in range(NUM_TRAINERS)
    ]
    for t_idx, delta in enumerate(deltas):
        for f_idx, frag in enumerate(partition_state_dict(delta, FRAGMENT_COUNT)):
            blob = serialize_fragment(f_idx, frag, quant)
            client.submit_outer_gradient(
                build_outer_gradient(
                    task_id=task_id,
                    round_index=0,
                    blob=blob,
                    trainer_did=dids[t_idx],
                    trainer_address=keys[t_idx].public_key_bytes,
                    quantization=quant,
                    inner_step_count=INNER_STEPS,
                    key=keys[t_idx],
                )
            )

    frags0 = partition_state_dict(deltas[0], FRAGMENT_COUNT)
    post_hashes = {
        f_idx: serialize_fragment(f_idx, frag, quant).digest
        for f_idx, frag in enumerate(frags0)
    }
    first = client.finalize_round(task_id, 0, post_hashes)
    assert client.get_run(task_id)["current_round"] == 1

    # Same round, same post-step hashes → same state root → idempotent no-op.
    second = client.finalize_round(task_id, 0, post_hashes)
    assert second["state_root"] == first["state_root"]
    # Round did not double-advance.
    assert client.get_run(task_id)["current_round"] == 1
