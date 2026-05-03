"""JSON-RPC 2.0 client for the Tenzro Train RPC namespace on ``tenzro-node``.

The Rust node exposes (see ``crates/tenzro-node/src/rpc.rs``):

* ``tenzro_training_postTask`` — sponsor posts a new task (not used by trainers).
* ``tenzro_training_listRuns`` — discover active runs.
* ``tenzro_training_getRun`` — fetch a single run.
* ``tenzro_training_getReceipt`` — fetch a finalized receipt.
* ``tenzro_training_enrollTrainer`` — trainers enroll in a posted run.
* ``tenzro_training_submitOuterGradient`` — trainers submit a gradient.
* ``tenzro_training_finalizeRound`` — syncer-side: advance to next round
  given ``post_step_hashes`` (Python's responsibility, since aggregating +
  applying the outer optimizer step needs PyTorch).

This module is a thin ``requests``-based wrapper. No retries, no auth — the
node is expected to be on localhost (or a private RPC URL set via env).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import requests

from tenzro_trainer.types import OuterGradient, hash_hex


class RpcError(RuntimeError):
    """Raised when the JSON-RPC server returns an ``error`` envelope."""

    def __init__(self, code: int, message: str, data: Any | None = None):
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


@dataclass
class RpcClient:
    """Thin JSON-RPC 2.0 client.

    Phase 1 default: ``http://127.0.0.1:8545``. The node does not require auth
    on local connections; for remote RPCs, prefer mTLS or a reverse proxy
    rather than baking auth into this client.
    """

    url: str = "http://127.0.0.1:8545"
    timeout_secs: float = 30.0
    _next_id: int = 1

    def _call(self, method: str, params: Any | None = None) -> Any:
        payload = {
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
        if "error" in body and body["error"] is not None:
            err = body["error"]
            raise RpcError(
                code=int(err.get("code", -1)),
                message=str(err.get("message", "<no message>")),
                data=err.get("data"),
            )
        return body.get("result")

    # ── trainer-facing methods ────────────────────────────────────────

    def list_runs(self) -> list[dict[str, Any]]:
        result = self._call("tenzro_training_listRuns")
        return list(result or [])

    def get_run(self, task_id: str) -> dict[str, Any]:
        return self._call("tenzro_training_getRun", {"task_id": task_id})

    def get_receipt(self, task_id: str) -> dict[str, Any]:
        return self._call("tenzro_training_getReceipt", {"task_id": task_id})

    def enroll_trainer(self, task_id: str, trainer_did: str) -> dict[str, Any]:
        return self._call(
            "tenzro_training_enrollTrainer",
            {"task_id": task_id, "trainer_did": trainer_did},
        )

    def submit_outer_gradient(self, gradient: OuterGradient) -> dict[str, Any]:
        return self._call(
            "tenzro_training_submitOuterGradient",
            {"gradient": gradient.to_json()},
        )

    # ── syncer-facing helper ──────────────────────────────────────────

    def finalize_round(
        self,
        task_id: str,
        round_index: int,
        post_step_hashes: dict[int, bytes],
    ) -> dict[str, Any]:
        """Advance the syncer to round + 1.

        ``post_step_hashes`` maps fragment index → 32-byte SHA-256 of the
        post-aggregation, post-outer-step parameter blob for that fragment.
        The Rust syncer expects hex strings keyed by stringified fragment id.
        """
        encoded = {str(frag): hash_hex(h) for frag, h in post_step_hashes.items()}
        return self._call(
            "tenzro_training_finalizeRound",
            {
                "task_id": task_id,
                "round": round_index,
                "post_step_hashes": encoded,
            },
        )


def pretty(obj: Any) -> str:
    """Pretty-print a JSON-RPC response for the CLI."""
    return json.dumps(obj, indent=2, sort_keys=True)
