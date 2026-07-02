"""``tenzro-trainer`` command-line interface.

Subcommands:

* ``enroll``         — register the trainer DID with a posted task.
* ``run``            — full inner-loop driver: enroll, then for each round,
                       fetch shard, run H steps, submit one outer gradient
                       per fragment.
* ``submit-gradient``— submit a single outer gradient from a precomputed
                       safetensors digest (advanced; useful for syncer-side
                       integration tests).
* ``finalize-round`` — syncer-side helper: aggregate accepted fragment
                       payloads (Mean), compute post-step parameter hashes,
                       advance the run via ``tenzro_training_finalizeRound``.

Phase 1 (Open tier) does not require TEE attestation. The CLI generates an
ephemeral Ed25519 trainer key per run unless ``--seed-file`` is provided.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from typing import Any

from tenzro_trainer.gradient import (
    TrainerKey,
    build_round_gradients,
    compute_outer_delta,
    deserialize_fragment_delta,
    partition_state_dict,
    serialize_fragment,
)
from tenzro_trainer.inner_loop import (
    OuterUpdateScheduler,
    load_partial_state,
    run_inner_loop,
)
from tenzro_trainer.rpc_bridge import RpcClient, RpcError, pretty
from tenzro_trainer.types import OuterGradient, PipelineAssignment, TrainingTaskSpec

log = logging.getLogger("tenzro-trainer")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_key(seed_path: str | None) -> TrainerKey:
    if seed_path:
        with open(seed_path, "rb") as f:
            seed = f.read()
        if len(seed) != 32:
            raise SystemExit(f"seed file {seed_path!r} must contain exactly 32 bytes")
        return TrainerKey.from_seed(seed)
    return TrainerKey.generate()


def _trainer_address_from_did(trainer_did: str) -> bytes:
    """Derive a 32-byte ``Address`` from a DID string.

    Phase 1 trick: hash the DID. The Rust syncer doesn't enforce a binding
    between DID and address yet (Open tier) — the address is just a recipient
    pointer for any pro-rata reward distribution at receipt time. Verified /
    Confidential tiers will replace this with the wallet address bound to the
    trainer's TDIP identity.
    """
    return hashlib.sha256(trainer_did.encode("utf-8")).digest()


def _build_adapter_for_modality(
    modality: str,
    architecture: dict[str, Any],
    hyperparams: dict[str, Any],
) -> Any:
    """Dispatch to the per-modality adapter builder.

    ``hyperparams`` is the task-spec ``metadata`` map — that's how
    wire-level knobs like ``inner_optimizer`` / ``learning_rate`` reach
    the adapters.
    """
    if modality == "Timeseries":
        from tenzro_trainer.adapters.timeseries import build_adapter

        return build_adapter(architecture, hyperparams)
    if modality == "Language":
        from tenzro_trainer.adapters.language import build_adapter as build

        return build(architecture, hyperparams)
    if modality == "Vision":
        from tenzro_trainer.adapters.vision import build_adapter as build

        return build(architecture, hyperparams)
    raise SystemExit(
        f"unsupported modality {modality!r}; expected Timeseries|Language|Vision"
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_enroll(args: argparse.Namespace) -> int:
    rpc = RpcClient(url=args.rpc_url, timeout_secs=args.timeout)
    try:
        result = rpc.enroll_trainer(args.task_id, args.trainer_did)
    except RpcError as e:
        log.error("enrollment failed: %s", e)
        return 1
    print(pretty(result))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    rpc = RpcClient(url=args.rpc_url, timeout_secs=args.timeout)
    key = _load_key(args.seed_file)
    address = _trainer_address_from_did(args.trainer_did)

    # 1. Pull + parse the task spec.
    try:
        run_state = rpc.get_run(args.task_id)
    except RpcError as e:
        log.error("get_run(%s) failed: %s", args.task_id, e)
        return 1
    spec_json = run_state.get("task_spec") or run_state
    try:
        spec = TrainingTaskSpec.from_json(spec_json)
    except (KeyError, TypeError, ValueError) as e:
        log.error("task spec did not parse: %s", e)
        return 1
    arch_json = spec.architecture.to_json()
    modality = spec.architecture.modality.value
    fragment_count = spec.architecture.fragment_count
    inner_steps = spec.inner_steps
    max_rounds = spec.max_rounds

    # 2. Enroll (idempotent on the Rust side).
    try:
        rpc.enroll_trainer(args.task_id, args.trainer_did)
    except RpcError as e:
        if "already enrolled" not in e.message.lower():
            log.error("enrollment failed: %s", e)
            return 1
        log.info("already enrolled, continuing")

    # 3. Pipeline assignment. Bound by the Rust runtime at enrollment and
    # surfaced on the run's `pipeline_assignments` map — re-fetch to read it.
    assignment: PipelineAssignment | None = None
    if spec.pipeline is not None:
        try:
            refreshed = rpc.get_run(args.task_id)
        except RpcError as e:
            log.error("get_run(%s) after enroll failed: %s", args.task_id, e)
            return 1
        raw = (refreshed.get("pipeline_assignments") or {}).get(args.trainer_did)
        if raw is None:
            log.error(
                "pipelined run but no assignment for %s — enrollment did not bind a stage",
                args.trainer_did,
            )
            return 1
        assignment = PipelineAssignment.from_json(raw)
        log.info(
            "pipeline assignment: group %d, stage %d of %d",
            assignment.group_id,
            assignment.stage,
            spec.pipeline.num_stages,
        )

    # 4. Build adapter. Task-spec metadata rides through as hyperparams so
    # `inner_optimizer` / `learning_rate` / etc. are wire-selectable.
    adapter = _build_adapter_for_modality(modality, arch_json, spec.metadata)
    model = adapter.model()
    scheduler = OuterUpdateScheduler(delayed=spec.delayed_apply)
    log.info(
        "running %d round(s) of %d inner steps each on shard %s "
        "(sync=%s quantization=%s delayed_apply=%s)",
        max_rounds,
        inner_steps,
        args.shard_uri,
        spec.sync_strategy.to_json(),
        spec.quantization.label(),
        spec.delayed_apply,
    )

    # 5. Per-round inner loop + outer-gradient submission.
    for round_index in range(max_rounds):
        log.info("--- round %d/%d ---", round_index, max_rounds - 1)
        scheduler.on_round_start(model)
        pre_state, post_state, report = run_inner_loop(
            adapter, args.shard_uri, inner_steps
        )
        log.info(
            "inner loop done: avg_loss=%.4f final_loss=%.4f",
            report.avg_loss,
            report.final_loss,
        )

        delta = compute_outer_delta(pre_state, post_state)
        delta_fragments = partition_state_dict(delta, fragment_count)

        # Fragment eligibility this round: the Streaming DiLoCo shard
        # rotation, intersected with this trainer's pipeline stage.
        active = [
            f
            for f in range(fragment_count)
            if spec.sync_strategy.fragment_active(f, fragment_count, round_index)
            and (
                assignment is None
                or spec.pipeline.stage_of_fragment(f, fragment_count)
                == assignment.stage
            )
        ]
        if not active:
            log.info("round %d: no fragments due from this trainer", round_index)
            continue

        blobs = [
            serialize_fragment(f, delta_fragments[f], spec.quantization)
            for f in active
        ]
        gradients = build_round_gradients(
            task_id=args.task_id,
            round_index=round_index,
            blobs=blobs,
            trainer_did=args.trainer_did,
            trainer_address=address,
            quantization=spec.quantization,
            inner_step_count=(round_index + 1) * inner_steps,
            key=key,
        )
        for g in gradients:
            try:
                rpc.submit_outer_gradient(g)
                log.info(
                    "fragment %d submitted: sha256=%s, %d bytes",
                    g.fragment,
                    g.safetensors_hash.hex()[:16],
                    g.payload_bytes,
                )
            except RpcError as e:
                log.error("fragment %d submit failed: %s", g.fragment, e)
                return 1

        # Reset each synced fragment to θ⁽⁰⁾, then route the *wire-visible*
        # delta through the scheduler. Immediate mode nets to θ⁽ᴴ⁾ exactly
        # when unquantized, and to the lossy quantized delta otherwise — the
        # same values peers and the syncer decode. Delayed mode (DiLoCoX)
        # buffers the update until the start of round r + 1.
        revert: dict[str, Any] = {}
        synced_delta: dict[str, Any] = {}
        for f, blob in zip(active, blobs):
            frag_pre = {k: pre_state[k] for k in delta_fragments[f]}
            revert.update(frag_pre)
            if spec.quantization.is_none:
                synced_delta.update(delta_fragments[f])
            else:
                synced_delta.update(
                    deserialize_fragment_delta(
                        blob.payload, frag_pre, spec.quantization
                    )
                )
        load_partial_state(model, revert)
        scheduler.on_outer_update(model, synced_delta)

    scheduler.flush(model)
    log.info("trainer loop complete (%d rounds)", max_rounds)
    return 0


def cmd_submit_gradient(args: argparse.Namespace) -> int:
    """Submit a precomputed gradient (advanced, for testing)."""
    rpc = RpcClient(url=args.rpc_url, timeout_secs=args.timeout)
    with open(args.gradient_json, "r", encoding="utf-8") as f:
        body = json.load(f)
    g = OuterGradient.from_json(body)
    try:
        result = rpc.submit_outer_gradient(g)
    except RpcError as e:
        log.error("submit failed: %s", e)
        return 1
    print(pretty(result))
    return 0


def cmd_finalize_round(args: argparse.Namespace) -> int:
    """Syncer-side helper: tell the node to advance to round + 1.

    ``--post-step-hashes`` is a JSON file of the form
    ``{"0": "<hex>", "1": "<hex>", ...}`` — one entry per fragment.
    """
    rpc = RpcClient(url=args.rpc_url, timeout_secs=args.timeout)
    with open(args.post_step_hashes, "r", encoding="utf-8") as f:
        raw = json.load(f)
    hashes = {int(k): bytes.fromhex(v) for k, v in raw.items()}
    try:
        result = rpc.finalize_round(args.task_id, args.round_index, hashes)
    except RpcError as e:
        log.error("finalize failed: %s", e)
        return 1
    print(pretty(result))
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--rpc-url",
        default=os.environ.get("TENZRO_RPC_URL", "http://127.0.0.1:8545"),
        help="JSON-RPC URL of the local tenzro-node (default: env TENZRO_RPC_URL or http://127.0.0.1:8545)",
    )
    p.add_argument("--timeout", type=float, default=30.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenzro-trainer",
        description="Tenzro Train Phase 1 reference trainer (Decoupled DiLoCo, PyTorch).",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enroll = sub.add_parser("enroll", help="Register the trainer DID with a posted task")
    _add_common(p_enroll)
    p_enroll.add_argument("--task-id", required=True)
    p_enroll.add_argument("--trainer-did", required=True)
    p_enroll.set_defaults(func=cmd_enroll)

    p_run = sub.add_parser("run", help="Full enroll + per-round inner loop + submit gradients")
    _add_common(p_run)
    p_run.add_argument("--task-id", required=True)
    p_run.add_argument("--trainer-did", required=True)
    p_run.add_argument(
        "--shard-uri",
        required=True,
        help="Shard URI (file:// or scheme-specific). Phase 1 demo adapters accept file:// only.",
    )
    p_run.add_argument(
        "--seed-file",
        default=None,
        help="32-byte Ed25519 seed file (for stable trainer identity). "
        "Omit to generate an ephemeral key.",
    )
    p_run.set_defaults(func=cmd_run)

    p_submit = sub.add_parser(
        "submit-gradient", help="Submit a precomputed OuterGradient JSON (testing)"
    )
    _add_common(p_submit)
    p_submit.add_argument("--gradient-json", required=True)
    p_submit.set_defaults(func=cmd_submit_gradient)

    p_fin = sub.add_parser(
        "finalize-round", help="Syncer-side: advance run to round + 1 with post-step hashes"
    )
    _add_common(p_fin)
    p_fin.add_argument("--task-id", required=True)
    p_fin.add_argument("--round-index", type=int, required=True, dest="round_index")
    p_fin.add_argument(
        "--post-step-hashes",
        required=True,
        help='JSON file mapping fragment index → hex hash, e.g. {"0":"abcd...","1":"ef01..."}',
    )
    p_fin.set_defaults(func=cmd_finalize_round)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
