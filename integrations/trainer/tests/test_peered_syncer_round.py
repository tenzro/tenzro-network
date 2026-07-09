"""Cross-node Level B: a round finalized on one node fans out to a peer.

Level A (``test_cross_node_round.py``) drives ONE node over JSON-RPC: N
trainers submit gradients, a coordinator finalizes, the node's syncer
advances. No second node ever sees the round.

Level B boots TWO ``tenzro-node`` processes that peer over libp2p and both
hold a syncer for the SAME run. Only node A receives trainer gradients and
the finalize RPC. When A finalizes, it broadcasts the ``SyncRound`` on the
``tenzro/training/syncer`` gossip topic; node B — which received no
gradients and no finalize RPC — ingests that broadcast and advances its own
``current_round`` to the same value with the same ``state_root``.

That is the multi-syncer witness-committee shape (Psyche / INTELLECT-2): a
round decided by one witness is observed by the others over gossip, and the
idempotent ``finalize_round`` accepts a matching ``(round, state_root)`` and
rejects a divergent one as a fork. This test proves the gossip transport,
the peer subscription, and the receiving-side apply all agree across a real
libp2p boundary — the piece neither the in-process tests nor Level A cover.

The node binary path is taken from ``TENZRO_NODE_BIN``; unset means skip
(a plain ``pytest`` run without a compiled binary is a skip, not a
failure). The Cloud Build config builds the binary and sets the env var.
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


def _node_log_tail(log_path: str, n: int = 80) -> str:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return "<node produced no output>"
    tail = "".join(lines[-n:]).strip()
    return tail or "<node produced no output>"


def _wait_for_rpc(
    url: str,
    proc: subprocess.Popen,
    log_path: str,
    timeout_secs: float = 180.0,
) -> None:
    """Poll the RPC port until a JSON-RPC call succeeds or the node dies."""
    deadline = time.time() + timeout_secs
    last_err: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"tenzro-node exited early with code {proc.returncode} before "
                f"RPC came up.\n--- node output ---\n{_node_log_tail(log_path)}"
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
        f"--- node output ---\n{_node_log_tail(log_path)}"
    )


def _node_peer_id(url: str, timeout_secs: float = 30.0) -> str:
    """Read the node's libp2p peer id from ``tenzro_nodeInfo``.

    The peer id is derived from the node's p2p keypair (persisted under its
    data dir), so it is not known until the network layer is up. Poll until
    ``self_peer_id`` is populated.
    """
    deadline = time.time() + timeout_secs
    last: str | None = None
    while time.time() < deadline:
        resp = requests.post(
            url,
            json={"jsonrpc": "2.0", "method": "tenzro_nodeInfo", "id": 1},
            timeout=5.0,
        )
        result = resp.json().get("result") or {}
        peer_id = result.get("self_peer_id")
        if peer_id:
            return peer_id
        last = str(result)
        time.sleep(0.5)
    raise RuntimeError(f"node did not report self_peer_id within {timeout_secs}s: {last}")


class _Node:
    def __init__(self, url: str, p2p_port: int, log_path: str, proc: subprocess.Popen):
        self.url = url
        self.p2p_port = p2p_port
        self.log_path = log_path
        self.proc = proc


def _spawn_node(data_dir: str, boot_nodes: str | None = None) -> _Node:
    rpc_port = _free_port()
    p2p_port = _free_port()
    rpc_addr = f"127.0.0.1:{rpc_port}"
    url = f"http://{rpc_addr}"
    # tenzro-node binds a web-verify server, an MCP server, an A2A server, and
    # six ecosystem MCP servers, each on a fixed default port. Two nodes on the
    # same host collide on those defaults, so the second node fails to bind,
    # its server task terminates, and the node triggers graceful shutdown
    # before its RPC ever comes up. Give every server a distinct free port.
    aux_flags = [
        "--web-addr",
        "--mcp-addr",
        "--a2a-addr",
        "--solana-mcp-addr",
        "--ethereum-mcp-addr",
        "--canton-mcp-addr",
        "--layerzero-mcp-addr",
        "--chainlink-mcp-addr",
        "--lifi-mcp-addr",
    ]
    cmd = [
        NODE_BIN,
        "--roles",
        "ai",
        "--rpc-addr",
        rpc_addr,
        "--data-dir",
        data_dir,
        "--listen-addr",
        f"/ip4/127.0.0.1/tcp/{p2p_port}",
    ]
    for flag in aux_flags:
        cmd += [flag, f"127.0.0.1:{_free_port()}"]
    if boot_nodes:
        cmd += ["--boot-nodes", boot_nodes]
    log_path = os.path.join(data_dir, "tenzro-node.log")
    node_env = {**os.environ, "RUST_LOG": os.environ.get("RUST_LOG", "info")}
    log_fh = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        cmd, stdout=log_fh, stderr=subprocess.STDOUT, text=True, env=node_env
    )
    return _Node(url=url, p2p_port=p2p_port, log_path=log_path, proc=proc)


def _terminate(node: _Node) -> None:
    node.proc.terminate()
    try:
        node.proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        node.proc.kill()
        node.proc.wait(timeout=5)


@pytest.fixture()
def peered_nodes():
    """Boot two loopback ``--roles ai`` nodes; node B dials node A as a boot peer.

    Yields ``(url_a, url_b)``. Node A is the coordinator (receives gradients +
    finalize RPC); node B is the observer (peers with A and ingests the round
    over the ``tenzro/training/syncer`` gossip topic).
    """
    with (
        tempfile.TemporaryDirectory(prefix="tenzro-node-b-a-") as dir_a,
        tempfile.TemporaryDirectory(prefix="tenzro-node-b-b-") as dir_b,
    ):
        node_a = _spawn_node(dir_a)
        try:
            _wait_for_rpc(node_a.url, node_a.proc, node_a.log_path)
            peer_a = _node_peer_id(node_a.url)
            boot = f"/ip4/127.0.0.1/tcp/{node_a.p2p_port}/p2p/{peer_a}"
            node_b = _spawn_node(dir_b, boot_nodes=boot)
            try:
                _wait_for_rpc(node_b.url, node_b.proc, node_b.log_path)
                yield node_a.url, node_b.url
            finally:
                _terminate(node_b)
        finally:
            _terminate(node_a)


# ---------------------------------------------------------------------------
# Trainer helpers
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
        sponsor_did="did:tenzro:machine:sponsor-peered",
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
        dataset_ref="file://peered-syncer-proof",
        dataset_hash=bytes(32),
        min_throughput=None,
        created_at=int(time.time() * 1000),
        metadata={},
    )


def _wait_for_round(url: str, task_id: str, target: int, timeout_secs: float = 30.0):
    """Poll a node's ``getRun`` until ``current_round`` reaches ``target``.

    Gossip delivery is asynchronous, so the observer node advances a moment
    after the coordinator finalizes. Return the run once it reaches the
    target, or raise with the last-seen round for a legible failure.
    """
    client = RpcClient(url=url)
    deadline = time.time() + timeout_secs
    last = None
    while time.time() < deadline:
        run = client.get_run(task_id)
        if run["current_round"] >= target:
            return run
        last = run["current_round"]
        time.sleep(0.25)
    raise AssertionError(
        f"node {url} did not reach round {target} within {timeout_secs}s "
        f"(last current_round={last}) — gossip round fan-out did not arrive"
    )


# ---------------------------------------------------------------------------
# The proof
# ---------------------------------------------------------------------------


def test_finalized_round_fans_out_to_peer_syncer(peered_nodes, tmp_path):
    url_a, url_b = peered_nodes
    client_a = RpcClient(url=url_a)
    client_b = RpcClient(url=url_b)
    task_id = "peered-syncer-proof"

    # Both nodes hold a syncer for the same run. Only A will receive gradients
    # and the finalize RPC; B is a pure gossip observer.
    client_a.post_task(_task_spec(task_id))
    client_b.post_task(_task_spec(task_id))
    assert client_a.get_run(task_id)["current_round"] == 0
    assert client_b.get_run(task_id)["current_round"] == 0

    # Enroll trainers on A only. B never sees an enrollment.
    keys = [TrainerKey.generate() for _ in range(NUM_TRAINERS)]
    dids = [f"did:tenzro:machine:peered-t{i}" for i in range(NUM_TRAINERS)]
    for did in dids:
        client_a.enroll_trainer(task_id, did)
    assert client_a.get_run(task_id)["status"] == "Training"
    # B holds no trainers — it only tracks the state-root chain over gossip.
    assert client_b.get_run(task_id)["trainers"] == []

    quant = GradientQuantization.none()

    for round_index in range(NUM_ROUNDS):
        start_state = _round_start_state()
        deltas = [
            _trainer_delta(
                _write_shard(tmp_path, seed=round_index * 100 + t_idx), start_state
            )
            for t_idx in range(NUM_TRAINERS)
        ]

        # All gradients go to node A exclusively.
        for t_idx, delta in enumerate(deltas):
            for f_idx, frag in enumerate(partition_state_dict(delta, FRAGMENT_COUNT)):
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
                assert client_a.submit_outer_gradient(gradient)["accepted"] is True

        # A finalizes — this is the only finalize RPC in the whole test. It
        # broadcasts the SyncRound on tenzro/training/syncer.
        frags0 = partition_state_dict(deltas[0], FRAGMENT_COUNT)
        post_hashes = {
            f_idx: serialize_fragment(f_idx, frag, quant).digest
            for f_idx, frag in enumerate(frags0)
        }
        sync_round = client_a.finalize_round(task_id, round_index, post_hashes)
        root_a = sync_round["state_root"]

        # A advanced synchronously (RPC path).
        run_a = client_a.get_run(task_id)
        assert run_a["current_round"] == round_index + 1

        # B advances only via gossip — it received no gradients and no finalize
        # RPC. Poll until the broadcast lands.
        run_b = _wait_for_round(url_b, task_id, round_index + 1)
        assert run_b["current_round"] == round_index + 1, (
            f"peer node B did not observe round {round_index} over gossip"
        )

    # After R rounds both syncers agree on the round count purely because A's
    # finalizes fanned out to B over libp2p — no RPC ever touched B's syncer.
    assert client_a.get_run(task_id)["current_round"] == NUM_ROUNDS
    assert _wait_for_round(url_b, task_id, NUM_ROUNDS)["current_round"] == NUM_ROUNDS
