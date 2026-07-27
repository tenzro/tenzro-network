"""Tenzro Media Gen reference worker (Python).

The node holds the job queue, the curated catalog, the pixel-step price, and
the signed commitments; this package holds the denoising loop. Diffusers and
torch are imported inside the functions that need them, so the wire types,
the commitment preimages, and the JSON-RPC client are usable on a machine
with no GPU stack installed.

See :mod:`tenzro_media_gen.types` for the wire formats,
:mod:`tenzro_media_gen.commitments` for the signed preimages,
:mod:`tenzro_media_gen.rpc_bridge` for the JSON-RPC client,
:mod:`tenzro_media_gen.pipelines` for pipeline loading and the split-expert
loop, and :mod:`tenzro_media_gen.worker` for the claim-render-seal lifecycle.
"""

from tenzro_media_gen.commitments import (
    WorkerKey,
    compute_job_id,
    encode_params,
    encode_task_spec,
    expected_job_id,
    handoff_commitment,
    handoff_signing_bytes,
    receipt_commitment,
    receipt_signing_bytes,
    sign_handoff,
    sign_receipt,
    verify_handoff,
    verify_receipt,
)
from tenzro_media_gen.rpc_bridge import (
    PublishedOutput,
    Quote,
    RpcClient,
    RpcError,
)
from tenzro_media_gen.types import (
    MediaGenAssignment,
    MediaGenExpertHolding,
    MediaGenExpertRole,
    MediaGenHandoff,
    MediaGenJob,
    MediaGenKind,
    MediaGenParams,
    MediaGenPayout,
    MediaGenReceipt,
    MediaGenSettlement,
    MediaGenStatus,
    MediaGenTaskSpec,
    MediaGenWorkerCapability,
    Signature,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # wire types
    "MediaGenAssignment",
    "MediaGenExpertHolding",
    "MediaGenExpertRole",
    "MediaGenHandoff",
    "MediaGenJob",
    "MediaGenKind",
    "MediaGenParams",
    "MediaGenPayout",
    "MediaGenReceipt",
    "MediaGenSettlement",
    "MediaGenStatus",
    "MediaGenTaskSpec",
    "MediaGenWorkerCapability",
    "Signature",
    # commitments
    "WorkerKey",
    "compute_job_id",
    "encode_params",
    "encode_task_spec",
    "expected_job_id",
    "handoff_commitment",
    "handoff_signing_bytes",
    "receipt_commitment",
    "receipt_signing_bytes",
    "sign_handoff",
    "sign_receipt",
    "verify_handoff",
    "verify_receipt",
    # transport
    "PublishedOutput",
    "Quote",
    "RpcClient",
    "RpcError",
]
