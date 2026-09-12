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

import os

# Must run before anything — including this package's own later imports, and
# certainly before `diffusers`/`transformers` ever import `huggingface_hub`
# themselves — because Xet's on/off state is decided once, the first time
# `huggingface_hub` initializes, not re-read per call. Setting this any later
# (inside `pipelines.load_pipeline`, say, after `import diffusers` has
# already pulled `huggingface_hub` in) is too late: confirmed directly by
# testing both orderings against the same repo — set here, `hf_hub_download`
# and `HfApi.list_repo_files` resolve in well under a second and reliably;
# set only later, in the same process, they hang indefinitely.
#
# Root cause: `hf-xet`'s (a Rust extension `huggingface_hub` pulls in by
# default) I/O/threading model is incompatible with the IOCP proactor event
# loop asyncio uses on Windows — see huggingface/huggingface_hub#3429 and
# huggingface/xet-core#446, #869. All three are open with no maintainer fix
# as of writing. `setdefault` rather than an unconditional set, so an
# operator who has verified Xet works on their machine/network can still
# opt back in.
os.environ.setdefault("HF_HUB_DISABLE_XET", "1")

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
    # transport
    "PublishedOutput",
    "Quote",
    "RpcClient",
    "RpcError",
    "Signature",
    # commitments
    "WorkerKey",
    "__version__",
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
]
