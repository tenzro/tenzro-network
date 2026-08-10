"""Reference Python FastAPI sidecar for Tenzro Cortex.

This is a reference implementation of the Cortex HTTP sidecar contract
consumed by `crates/tenzro-cortex/src/sidecar.rs` (`SidecarModel`).

Wire contract (must match `tenzro_cortex::sidecar::InferRequestWire` /
`InferResponseWire` exactly — the field names are the serde names, NOT the
doc-comment names):

    POST /v1/cortex/infer
    Content-Type: application/json
    Authorization: Bearer <optional-token>          # only if SidecarConfig.auth_token set

    request body:
      {
        "model_id":     str,
        "input_hex":    str,          # hex-encoded bytes (no 0x prefix)
        "n_loops_min":  int,
        "n_loops_max":  int,
        "params":       { str: str }  # free-form generation params
      }

    response body (HTTP 200):
      {
        "output_hex":          str,   # hex-encoded response bytes
        "loops_used":          int,   # MUST satisfy n_loops_min <= loops_used <= n_loops_max
        "input_tokens":        int,
        "output_tokens":       int,
        "latency_ms":          int,
        "model_version":       str?,  # optional
        "finish_reason":       str?,  # optional: "stop" | "length" | "converged"
        "experts_activated":   int?,  # optional: MoE expert count
        "weights_hash_hex":    str,   # 32-byte SHA-256 hex, optional "0x" prefix
        "runtime_hash_hex":    str    # 32-byte SHA-256 hex, optional "0x" prefix
      }

Receipt contract (Rust side, do not replicate here):

    The Rust CortexWorker CALLS this sidecar, then re-signs the final
    CortexReceipt with:
      - loops_used reported by this sidecar
      - tokens_in / tokens_out reported by this sidecar
      - weights_hash / runtime_hash reported by this sidecar
      - input_commitment  = SHA-256( canonicalize_input(request) )
      - output_commitment = SHA-256( output_bytes )
      - price_wei         = CortexPricing.compute(...)
      - worker_did / worker_address from the worker
      - Ed25519 signature over signing_preimage() of the full receipt

    This means the sidecar does NOT sign receipts itself — the sidecar
    only has to report metrics faithfully. The worker is the trust root.

Honest RDT semantics:

    A REAL sidecar would wrap a recurrent-depth transformer (e.g.
    OpenMythos) and report `loops_used` == the actual number of inner
    recurrent passes the model took to converge (bounded by the caller's
    [n_loops_min, n_loops_max]). The `weights_hash_hex` would be the
    SHA-256 of the model weight files, and `runtime_hash_hex` the SHA-256
    of the serving container/binary.

    This REFERENCE sidecar uses a deterministic echo model with:
      - loops_used := clamp(n_loops_max, n_loops_min, n_loops_max)
                      (an honest RDT would report convergence-driven loops)
      - weights_hash := SHA-256("weights:" + model_id)
      - runtime_hash := SHA-256("tenzro-cortex-ref-sidecar@" + __version__)
      - output := input  (echo, so the integration test is deterministic)

    The reference is adequate for integration testing the Rust worker,
    receipt signing, pricing, and settlement paths. Replace the
    `_infer_bytes()` function with a real RDT forward pass for production.

Run:

    pip install fastapi uvicorn
    uvicorn server:app --host 127.0.0.1 --port 8088

    # optional auth:
    CORTEX_SIDECAR_TOKEN=secret uvicorn server:app --host 127.0.0.1 --port 8088
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

__version__ = "0.1.0"

# --- wire types ----------------------------------------------------------
# Field names are the serde names in Rust. Do not rename.


class InferRequest(BaseModel):
    model_id: str
    input_hex: str
    n_loops_min: int = Field(..., ge=0)
    n_loops_max: int = Field(..., ge=0)
    params: Dict[str, str] = Field(default_factory=dict)


class InferResponse(BaseModel):
    output_hex: str
    loops_used: int
    input_tokens: int
    output_tokens: int
    latency_ms: int
    model_version: Optional[str] = None
    finish_reason: Optional[str] = None
    experts_activated: Optional[int] = None
    weights_hash_hex: str
    runtime_hash_hex: str


# --- reference inference kernel ------------------------------------------
# Replace this with a real RDT forward pass (e.g. OpenMythos / Huginn).


def _approx_tokens(n_bytes: int) -> int:
    """Rough byte → token count. Real sidecars should use the model's
    tokenizer. Reference uses 4 bytes/token and clamps to >= 1 so that
    pricing treats any non-empty payload as at least one token."""
    return max(1, n_bytes // 4)


def _weights_hash(model_id: str) -> str:
    """Deterministic per-model-id weights hash. In a real sidecar, hash
    the actual weight files at load time and cache the digest."""
    return hashlib.sha256(f"weights:{model_id}".encode("utf-8")).hexdigest()


def _runtime_hash() -> str:
    """Deterministic runtime hash. In a real sidecar, hash the
    container image digest or binary SHA-256."""
    tag = f"tenzro-cortex-ref-sidecar@{__version__}"
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()


def _clamp_loops(requested_max: int, lo: int, hi: int) -> int:
    """Clamp loops_used into the caller-provided budget window.

    A real RDT chooses `loops_used` based on convergence of the recurrent
    block; the value must still land inside [lo, hi]. This reference
    always picks hi so the worker's budget enforcement is exercised but
    never rejects on LoopsOutOfRange."""
    return max(lo, min(hi, requested_max))


def _infer_bytes(model_id: str, input_bytes: bytes, loops: int,
                 params: Dict[str, str]) -> bytes:
    """Reference inference kernel: echo the input. A real sidecar would
    decode the prompt, run a forward pass with `loops` recurrent depth,
    and return the sampled-token bytes.

    Params is passed for parity with real RDT runtimes (temperature,
    top_p, max_tokens, etc.). The reference ignores it."""
    del model_id, loops, params
    return input_bytes


# --- FastAPI app ---------------------------------------------------------

app = FastAPI(
    title="Tenzro Cortex reference sidecar",
    version=__version__,
    description=(
        "Reference implementation of the Cortex HTTP sidecar wire "
        "contract. NOT a real RDT — replace _infer_bytes() with a real "
        "model for production use."
    ),
)


def _check_auth(authorization: Optional[str]) -> None:
    expected = os.environ.get("CORTEX_SIDECAR_TOKEN")
    if not expected:
        return
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[len("bearer "):].strip()
    if token != expected:
        raise HTTPException(status_code=403, detail="invalid bearer token")


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/v1/cortex/infer")
async def infer(
    req: InferRequest,
    authorization: Optional[str] = Header(default=None),
) -> JSONResponse:
    _check_auth(authorization)

    if req.n_loops_min > req.n_loops_max:
        raise HTTPException(
            status_code=400,
            detail=(
                f"n_loops_min ({req.n_loops_min}) > n_loops_max "
                f"({req.n_loops_max})"
            ),
        )
    if req.n_loops_max == 0:
        raise HTTPException(
            status_code=400,
            detail="n_loops_max must be > 0 for RDT inference",
        )

    # Decode the caller-supplied hex payload.
    try:
        input_bytes = bytes.fromhex(req.input_hex)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"input_hex is not valid hex: {e}",
        ) from e

    loops_used = _clamp_loops(req.n_loops_max, req.n_loops_min, req.n_loops_max)

    t0 = time.perf_counter()
    output_bytes = _infer_bytes(req.model_id, input_bytes, loops_used, req.params)
    latency_ms = int((time.perf_counter() - t0) * 1_000)

    resp = InferResponse(
        output_hex=output_bytes.hex(),
        loops_used=loops_used,
        input_tokens=_approx_tokens(len(input_bytes)),
        output_tokens=_approx_tokens(len(output_bytes)),
        latency_ms=latency_ms,
        model_version=f"ref-{__version__}",
        finish_reason="converged",
        experts_activated=None,
        weights_hash_hex=_weights_hash(req.model_id),
        runtime_hash_hex=_runtime_hash(),
    )
    return JSONResponse(content=resp.model_dump(exclude_none=False))


# --- entrypoint ----------------------------------------------------------


def main() -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("CORTEX_SIDECAR_HOST", "127.0.0.1"),
        port=int(os.environ.get("CORTEX_SIDECAR_PORT", "8088")),
        log_level="info",
    )


if __name__ == "__main__":  # pragma: no cover
    main()
