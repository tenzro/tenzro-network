"""JSON-RPC 2.0 client for the media-gen namespace on ``tenzro-node``.

The node exposes 18 methods (see ``crates/tenzro-node/src/rpc.rs``):

Requester-facing
    ``listCatalog`` ``quote`` ``postJob`` ``listJobs`` ``getJob``
    ``cancelJob`` ``getReceipt`` ``fetchOutput``

Worker-facing
    ``enrollWorker`` ``listWorkers`` ``claimJob`` ``markRunning``
    ``failJob`` ``publishOutput`` ``recordHandoff`` ``submitReceipt``
    ``fetchLatent`` ``fetchInput``

Two response conventions differ from the struct wire format and are unwrapped
here: the node stringifies ``u128`` prices in the quote response, and returns
``output_hash`` / ``latent_hash`` as lowercase hex rather than the 32-integer
array the structs use.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

import requests

from .types import (
    MediaGenExpertRole,
    MediaGenHandoff,
    MediaGenJob,
    MediaGenKind,
    MediaGenParams,
    MediaGenReceipt,
    MediaGenStatus,
    MediaGenTaskSpec,
    MediaGenWorkerCapability,
)


class RpcError(RuntimeError):
    """Raised when the JSON-RPC server returns an ``error`` envelope."""

    def __init__(self, code: int, message: str, data: Any | None = None):
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


@dataclass
class PublishedOutput:
    """Both addresses of one blob.

    ``output_hash`` is the canonical SHA-256 a receipt or handoff commits to;
    ``locator`` is the BLAKE3 the blob store indexes by, absent when the node
    has no iroh-backed store bound.
    """

    output_hash: bytes
    locator: str | None
    byte_len: int


@dataclass
class Quote:
    kind: MediaGenKind
    pixel_steps: int
    per_pixel_step: int
    base_fee: int
    quote: int


@dataclass
class RpcClient:
    """Thin JSON-RPC 2.0 client.

    Default target is the local node. The node does not require auth on local
    connections; for remote RPCs prefer mTLS or a reverse proxy over baking
    credentials into this client.
    """

    url: str = "http://127.0.0.1:8545"
    timeout_secs: float = 300.0
    _next_id: int = field(default=1, repr=False)

    def _call(self, method: str, params: Any | None = None) -> Any:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self._next_id,
        }
        self._next_id += 1
        if params is not None:
            payload["params"] = params
        resp = requests.post(self.url, json=payload, timeout=self.timeout_secs)
        resp.raise_for_status()
        body = resp.json()
        if body.get("error") is not None:
            err = body["error"]
            raise RpcError(
                code=int(err.get("code", -1)),
                message=str(err.get("message", "<no message>")),
                data=err.get("data"),
            )
        return body.get("result")

    # ── catalog and pricing ───────────────────────────────────────────

    def list_catalog(self) -> list[dict[str, Any]]:
        result = self._call("tenzro_mediaGen_listCatalog")
        return list((result or {}).get("models") or [])

    def quote(self, kind: MediaGenKind, params: MediaGenParams) -> Quote:
        result = self._call(
            "tenzro_mediaGen_quote",
            {"kind": kind.value, "params": params.to_json()},
        )
        return Quote(
            kind=MediaGenKind(result["kind"]),
            pixel_steps=int(result["pixel_steps"]),
            per_pixel_step=int(result["per_pixel_step"]),
            base_fee=int(result["base_fee"]),
            quote=int(result["quote"]),
        )

    # ── requester-facing job methods ──────────────────────────────────

    def post_job(self, task_spec: MediaGenTaskSpec) -> MediaGenJob:
        result = self._call(
            "tenzro_mediaGen_postJob",
            {"task_spec": task_spec.to_json()},
        )
        return MediaGenJob.from_json(result)

    def list_jobs(self, status: MediaGenStatus | None = None) -> list[MediaGenJob]:
        params = {"status": status.value} if status is not None else None
        result = self._call("tenzro_mediaGen_listJobs", params)
        return [MediaGenJob.from_json(j) for j in (result or {}).get("jobs") or []]

    def get_job(self, job_id: str) -> MediaGenJob | None:
        result = self._call("tenzro_mediaGen_getJob", {"job_id": job_id})
        return MediaGenJob.from_json(result) if result else None

    def cancel_job(self, job_id: str, requester_did: str) -> MediaGenJob:
        result = self._call(
            "tenzro_mediaGen_cancelJob",
            {"job_id": job_id, "requester_did": requester_did},
        )
        return MediaGenJob.from_json(result)

    def get_receipt(self, job_id: str) -> MediaGenReceipt | None:
        result = self._call("tenzro_mediaGen_getReceipt", {"job_id": job_id})
        return MediaGenReceipt.from_json(result) if result else None

    def fetch_output(self, job_id: str) -> tuple[bytes, str]:
        """Pull a completed job's render. Returns ``(bytes, mime)``.

        The node checks the bytes against the hash and length the receipt
        committed to before handing them back.
        """
        result = self._call("tenzro_mediaGen_fetchOutput", {"job_id": job_id})
        return base64.b64decode(result["data"]), str(result["output_mime"])

    def fetch_input(self, job_id: str) -> bytes:
        """Pull the conditioning image an image-conditioned job names.

        The requester publishes it before posting, so the hash is already
        bound into the job id by the time a worker claims the job. The node
        checks the bytes against that hash before handing them back.
        """
        result = self._call("tenzro_mediaGen_fetchInput", {"job_id": job_id})
        return base64.b64decode(result["data"])

    # ── worker-facing methods ─────────────────────────────────────────

    def enroll_worker(self, capability: MediaGenWorkerCapability) -> dict[str, Any]:
        return self._call(
            "tenzro_mediaGen_enrollWorker",
            {"capability": capability.to_json()},
        )

    def list_workers(self) -> list[MediaGenWorkerCapability]:
        result = self._call("tenzro_mediaGen_listWorkers")
        return [MediaGenWorkerCapability.from_json(w) for w in (result or {}).get("workers") or []]

    def claim_job(
        self,
        job_id: str,
        worker_did: str,
        role: MediaGenExpertRole | None = None,
    ) -> MediaGenJob:
        """Take a job, or one half of a split job.

        ``role`` is required on a split job and rejected on a whole one.
        """
        params: dict[str, Any] = {"job_id": job_id, "worker_did": worker_did}
        if role is not None:
            params["role"] = role.value
        return MediaGenJob.from_json(self._call("tenzro_mediaGen_claimJob", params))

    def mark_running(self, job_id: str, worker_did: str) -> MediaGenJob:
        return MediaGenJob.from_json(
            self._call(
                "tenzro_mediaGen_markRunning",
                {"job_id": job_id, "worker_did": worker_did},
            )
        )

    def fail_job(self, job_id: str, worker_did: str, error: str) -> MediaGenJob:
        return MediaGenJob.from_json(
            self._call(
                "tenzro_mediaGen_failJob",
                {"job_id": job_id, "worker_did": worker_did, "error": error},
            )
        )

    def publish_output(self, data: bytes) -> PublishedOutput:
        """Put rendered bytes into the content-addressed store.

        Called before building a commitment, because the commitment names the
        hash this returns.
        """
        if not data:
            raise ValueError("cannot publish empty output")
        result = self._call(
            "tenzro_mediaGen_publishOutput",
            {"bytes": base64.b64encode(data).decode("ascii")},
        )
        return PublishedOutput(
            output_hash=bytes.fromhex(result["output_hash"]),
            locator=result.get("locator"),
            byte_len=int(result["bytes"]),
        )

    def record_handoff(self, handoff: MediaGenHandoff) -> MediaGenJob:
        return MediaGenJob.from_json(
            self._call(
                "tenzro_mediaGen_recordHandoff",
                {"handoff": handoff.to_json()},
            )
        )

    def submit_receipt(self, receipt: MediaGenReceipt) -> MediaGenJob:
        return MediaGenJob.from_json(
            self._call(
                "tenzro_mediaGen_submitReceipt",
                {"receipt": receipt.to_json()},
            )
        )

    def fetch_latent(self, job_id: str) -> bytes:
        """Pull the intermediate latent of a split job.

        The node checks the bytes against the hash and length the handoff
        committed to, so the low-noise expert picks up exactly what the
        high-noise expert signed over.
        """
        result = self._call("tenzro_mediaGen_fetchLatent", {"job_id": job_id})
        return base64.b64decode(result["data"])


def pretty(obj: Any) -> str:
    """Pretty-print a JSON-RPC response for the CLI."""
    return json.dumps(obj, indent=2, sort_keys=True)
