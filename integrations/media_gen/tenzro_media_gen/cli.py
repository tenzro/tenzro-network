"""``tenzro-media-gen`` — command line for the reference media-gen worker.

Two audiences share one entry point. A worker operator runs ``enroll`` and
``serve``. A requester or an operator debugging a job uses ``catalog``,
``quote``, ``post``, ``jobs``, ``get``, ``receipt``, and ``fetch``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from typing import Any

from .commitments import WorkerKey, compute_job_id, verify_receipt
from .rpc_bridge import RpcClient, RpcError, pretty
from .types import (
    MediaGenExpertRole,
    MediaGenKind,
    MediaGenParams,
    MediaGenStatus,
    MediaGenTaskSpec,
)
from .worker import MediaGenWorker, WorkerConfig, now_millis

DEFAULT_URL = "http://127.0.0.1:8545"


def _client(args: argparse.Namespace) -> RpcClient:
    return RpcClient(url=args.url, timeout_secs=args.timeout)


def _params_from(args: argparse.Namespace, input_image_hash: bytes | None) -> MediaGenParams:
    return MediaGenParams(
        prompt=args.prompt,
        negative_prompt=args.negative_prompt,
        width=args.width,
        height=args.height,
        steps=args.steps,
        guidance_scale=args.guidance_scale,
        num_frames=args.num_frames,
        fps=args.fps,
        seed=args.seed,
        input_image_hash=input_image_hash,
    )


def _decode_hex32(value: str | None, label: str) -> bytes | None:
    if value is None:
        return None
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32 bytes of hex, got {len(raw)}")
    return raw


# ── requester-facing ──────────────────────────────────────────────────


def cmd_catalog(args: argparse.Namespace) -> int:
    models = _client(args).list_catalog()
    if args.json:
        print(pretty(models))
        return 0
    for m in models:
        split = " (split)" if m.get("expert_pair") else ""
        kinds = ", ".join(m.get("kinds") or [])
        print(f"{m['id']}{split}\n  {m['name']} — {kinds}\n  {m['min_vram_gb']} GB VRAM, {m['license']}")
    return 0


def cmd_quote(args: argparse.Namespace) -> int:
    kind = MediaGenKind(args.kind)
    params = _params_from(args, _decode_hex32(args.input_image_hash, "input_image_hash"))
    params.validate_for(kind)
    quote = _client(args).quote(kind, params)
    if args.json:
        print(
            pretty(
                {
                    "kind": quote.kind.value,
                    "pixel_steps": quote.pixel_steps,
                    "per_pixel_step": str(quote.per_pixel_step),
                    "base_fee": str(quote.base_fee),
                    "quote": str(quote.quote),
                }
            )
        )
        return 0
    print(f"{quote.pixel_steps} pixel-steps")
    print(f"{quote.quote} attoTNZO ({quote.base_fee} base + {quote.pixel_steps} x {quote.per_pixel_step})")
    return 0


def cmd_post(args: argparse.Namespace) -> int:
    client = _client(args)
    kind = MediaGenKind(args.kind)

    input_hash: bytes | None = None
    if args.input_image:
        with open(args.input_image, "rb") as fh:
            image_bytes = fh.read()
        published = client.publish_output(image_bytes)
        input_hash = published.output_hash
        print(f"published conditioning image: {input_hash.hex()}", file=sys.stderr)
        if published.output_hash != hashlib.sha256(image_bytes).digest():
            raise ValueError("node returned a hash that does not cover the bytes sent")
    elif args.input_image_hash:
        input_hash = _decode_hex32(args.input_image_hash, "input_image_hash")

    params = _params_from(args, input_hash)
    params.validate_for(kind)

    requester_address = _decode_hex32(args.requester_address, "requester_address")
    if requester_address is None:
        raise ValueError("--requester-address is required")
    created_at = args.created_at if args.created_at is not None else now_millis()

    job_id = compute_job_id(
        args.requester_did,
        requester_address,
        args.model,
        kind,
        params,
        args.max_price,
        created_at,
    )
    spec = MediaGenTaskSpec(
        job_id=job_id,
        requester_did=args.requester_did,
        requester_address=requester_address,
        model_id=args.model,
        kind=kind,
        params=params,
        max_price=args.max_price,
        created_at=created_at,
    )
    job = client.post_job(spec)
    print(job.job_id if not args.json else pretty({"job_id": job.job_id, "status": job.status.value}))
    return 0


def cmd_jobs(args: argparse.Namespace) -> int:
    status = MediaGenStatus(args.status) if args.status else None
    jobs = _client(args).list_jobs(status)
    if args.json:
        print(pretty([{"job_id": j.job_id, "status": j.status.value} for j in jobs]))
        return 0
    for j in jobs:
        roles = ",".join(r.value for r in j.required_roles) or "whole"
        print(f"{j.job_id}  {j.status.value:<10} {j.task_spec.model_id}  [{roles}]")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    job = _client(args).get_job(args.job_id)
    if job is None:
        print(f"no job {args.job_id}", file=sys.stderr)
        return 1
    print(
        pretty(
            {
                "job_id": job.job_id,
                "status": job.status.value,
                "model_id": job.task_spec.model_id,
                "kind": job.task_spec.kind.value,
                "required_roles": [r.value for r in job.required_roles],
                "assignments": [
                    {
                        "worker_did": a.worker_did,
                        "role": a.role.value if a.role else None,
                        "share_bps": a.share_bps,
                    }
                    for a in job.assignments
                ],
                "handoff": (
                    {
                        "from_worker_did": job.handoff.from_worker_did,
                        "latent_hash": job.handoff.latent_hash.hex(),
                        "latent_bytes": job.handoff.latent_bytes,
                        "steps_completed": job.handoff.steps_completed,
                    }
                    if job.handoff
                    else None
                ),
                "error": job.error,
            }
        )
    )
    return 0


def cmd_cancel(args: argparse.Namespace) -> int:
    job = _client(args).cancel_job(args.job_id, args.requester_did)
    print(job.status.value)
    return 0


def cmd_receipt(args: argparse.Namespace) -> int:
    receipt = _client(args).get_receipt(args.job_id)
    if receipt is None:
        print(f"job {args.job_id} has no receipt yet", file=sys.stderr)
        return 1
    print(
        pretty(
            {
                "job_id": receipt.job_id,
                "worker_did": receipt.worker_did,
                "output_hash": receipt.output_hash.hex(),
                "output_mime": receipt.output_mime,
                "output_bytes": receipt.output_bytes,
                "seed_used": receipt.seed_used,
                "generation_time_ms": receipt.generation_time_ms,
                "price_paid": str(receipt.price_paid),
                "signature_valid": verify_receipt(receipt),
            }
        )
    )
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    client = _client(args)
    if args.latent:
        data = client.fetch_latent(args.job_id)
        mime = "application/octet-stream"
    elif args.input:
        data = client.fetch_input(args.job_id)
        mime = "image/*"
    else:
        data, mime = client.fetch_output(args.job_id)

    if args.output == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(args.output, "wb") as fh:
            fh.write(data)
        print(f"{len(data)} bytes of {mime} -> {args.output}", file=sys.stderr)
    return 0


# ── worker-facing ─────────────────────────────────────────────────────


def _worker_key(args: argparse.Namespace) -> WorkerKey:
    seed_hex = args.seed_hex or os.environ.get("TENZRO_MEDIA_GEN_SEED")
    if not seed_hex:
        raise ValueError(
            "a worker key is required: pass --seed-hex or set TENZRO_MEDIA_GEN_SEED "
            "to 32 bytes of hex"
        )
    return WorkerKey.from_seed_hex(seed_hex)


def _holdings(values: list[str]) -> list[tuple[str, MediaGenExpertRole]]:
    """Parse ``model_id:role`` pairs into expert holdings."""
    out: list[tuple[str, MediaGenExpertRole]] = []
    for raw in values:
        model_id, _, role = raw.partition(":")
        if not model_id or not role:
            raise ValueError(f"expert holding {raw!r} must be <model_id>:<high_noise|low_noise>")
        out.append((model_id, MediaGenExpertRole(role)))
    return out


def _worker_config(args: argparse.Namespace) -> WorkerConfig:
    address = _decode_hex32(args.worker_address, "worker_address")
    if address is None:
        raise ValueError("--worker-address is required")
    return WorkerConfig(
        worker_did=args.worker_did,
        worker_address=address,
        served_models=list(args.model or []),
        expert_holdings=_holdings(list(args.expert or [])),
        max_resolution=args.max_resolution,
        max_frames=args.max_frames,
        gpu_vram_gb=args.gpu_vram_gb,
        device=args.device,
        dtype=args.dtype,
        cache_dir=args.cache_dir,
        poll_interval_secs=args.poll_interval,
    )


def cmd_enroll(args: argparse.Namespace) -> int:
    worker = MediaGenWorker(_worker_config(args), _client(args), _worker_key(args))
    worker.enroll()
    print("enrolled")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    worker = MediaGenWorker(_worker_config(args), _client(args), _worker_key(args))
    worker.run()
    return 0


def cmd_workers(args: argparse.Namespace) -> int:
    workers = _client(args).list_workers()
    if args.json:
        print(pretty([w.to_json() for w in workers]))
        return 0
    for w in workers:
        holdings = ", ".join(f"{h.model_id}:{h.role.value}" for h in w.expert_holdings) or "-"
        print(f"{w.worker_did}\n  whole: {', '.join(w.supported_models) or '-'}\n  experts: {holdings}")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a worker signing key.

    Printed to stdout and nowhere else — the worker reads it back from
    ``TENZRO_MEDIA_GEN_SEED`` or ``--seed-hex``, so persisting it is the
    operator's decision.
    """
    key = WorkerKey.generate()
    print(
        pretty(
            {
                "seed_hex": key.seed_bytes.hex(),
                "public_key_hex": key.public_key_bytes.hex(),
            }
        )
    )
    return 0


# ── argument wiring ───────────────────────────────────────────────────


def _add_params_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--prompt", required=True)
    p.add_argument("--negative-prompt", default=None)
    p.add_argument("--width", type=int, required=True)
    p.add_argument("--height", type=int, required=True)
    p.add_argument("--steps", type=int, required=True)
    p.add_argument("--guidance-scale", type=float, default=4.0)
    p.add_argument("--num-frames", type=int, default=None, help="video kinds only")
    p.add_argument("--fps", type=int, default=None, help="video kinds only")
    p.add_argument("--seed", type=int, default=None)


def _add_worker_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--worker-did", required=True)
    p.add_argument("--worker-address", required=True, help="32 bytes of hex")
    p.add_argument("--seed-hex", default=None, help="32-byte Ed25519 seed; else TENZRO_MEDIA_GEN_SEED")
    p.add_argument(
        "--model",
        action="append",
        default=[],
        help="catalog id of a model held whole; repeatable",
    )
    p.add_argument(
        "--expert",
        action="append",
        default=[],
        help="<model_id>:<high_noise|low_noise> for one held expert; repeatable",
    )
    p.add_argument("--max-resolution", type=int, default=2048)
    p.add_argument("--max-frames", type=int, default=None)
    p.add_argument("--gpu-vram-gb", type=float, default=24.0)
    p.add_argument("--device", default="cuda")
    p.add_argument("--dtype", default="bfloat16")
    p.add_argument("--cache-dir", default=None)
    p.add_argument("--poll-interval", type=float, default=5.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenzro-media-gen",
        description="Reference generative-media worker and job client for Tenzro Media Gen.",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help=f"node JSON-RPC endpoint (default {DEFAULT_URL})")
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="seconds to wait on one RPC; raise it when publishing large videos",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("catalog", help="list the curated generative-media models")
    p.set_defaults(func=cmd_catalog)

    p = sub.add_parser("quote", help="price a job without queueing it")
    p.add_argument("--kind", required=True, choices=[k.value for k in MediaGenKind])
    p.add_argument("--input-image-hash", default=None, help="32 bytes of hex")
    _add_params_args(p)
    p.set_defaults(func=cmd_quote)

    p = sub.add_parser("post", help="queue a job")
    p.add_argument("--kind", required=True, choices=[k.value for k in MediaGenKind])
    p.add_argument("--model", required=True, help="catalog id")
    p.add_argument("--requester-did", required=True)
    p.add_argument("--requester-address", required=True, help="32 bytes of hex")
    p.add_argument("--max-price", type=int, required=True, help="attoTNZO ceiling")
    p.add_argument("--created-at", type=int, default=None, help="millis; defaults to now")
    p.add_argument("--input-image", default=None, help="path to publish and condition on")
    p.add_argument("--input-image-hash", default=None, help="hash of an already-published image")
    _add_params_args(p)
    p.set_defaults(func=cmd_post)

    p = sub.add_parser("jobs", help="list jobs this node holds")
    p.add_argument("--status", default=None, choices=[s.value for s in MediaGenStatus])
    p.set_defaults(func=cmd_jobs)

    p = sub.add_parser("get", help="show one job")
    p.add_argument("job_id")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("cancel", help="cancel a pending job")
    p.add_argument("job_id")
    p.add_argument("--requester-did", required=True)
    p.set_defaults(func=cmd_cancel)

    p = sub.add_parser("receipt", help="show a finished job's signed receipt")
    p.add_argument("job_id")
    p.set_defaults(func=cmd_receipt)

    p = sub.add_parser("fetch", help="pull a job's bytes")
    p.add_argument("job_id")
    p.add_argument("-o", "--output", default="-", help="path, or - for stdout")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--latent", action="store_true", help="the intermediate latent")
    group.add_argument("--input", action="store_true", help="the conditioning image")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("workers", help="list workers enrolled with this node")
    p.set_defaults(func=cmd_workers)

    p = sub.add_parser("keygen", help="generate a worker signing key")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("enroll", help="announce this worker to the node")
    _add_worker_args(p)
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("serve", help="enroll, then render jobs until interrupted")
    _add_worker_args(p)
    p.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )
    try:
        return int(args.func(args))
    except RpcError as exc:
        print(f"node rejected the call: {exc}", file=sys.stderr)
        if exc.data is not None:
            print(json.dumps(exc.data, indent=2), file=sys.stderr)
        return 2
    except (ValueError, TimeoutError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
