"""Tenzro cross-framework agent core.

This module is the single shared core for all six framework adapters
(LangGraph, CrewAI, Letta, OpenAI Agents SDK, Google ADK, Microsoft Agent
Framework). Per Open Question #4 in
``docs/architecture/agent-interop-protocol-bridge.md`` ("Cross-framework
shim maintenance cost"), there is exactly one integration core; each
adapter is a thin (~50-150 LOC) translation from a framework's native
extension point onto the primitives defined here.

It provides:

* :class:`TenzroClient` — a JSON-RPC 2.0 client to a Tenzro node mirroring
  the node RPC surface (``crates/tenzro-node/src/rpc.rs``):
  provisioning (``tenzro_participate``), mandate validation
  (``tenzro_ap2ValidateMandatePair``), task lifecycle
  (``tenzro_postTask`` / ``tenzro_quoteTask`` / ``tenzro_assignTask`` /
  ``tenzro_completeTask``), and ERC-8004 feedback submission
  (``tenzro_erc8004EncodeFeedback``).
* :class:`TenzroDidEnvelope` — client-side build + Ed25519 sign of the
  Tenzro DID envelope (the auth lingua franca of Layer 1 of the bridge
  doc). The canonical preimage layout is pinned below and MUST be kept in
  sync with the Rust verifier.
* AP2 mandate helpers (IntentMandate / CartMandate / CheckoutMandate /
  PaymentMandate dicts) per ``docs/protocol-research-2026-05/ap2-v02.md``
  and ``crates/tenzro-payments/src/ap2/mod.rs`` field names.
* :class:`ReputationHook` — encodes ERC-8004 feedback calldata on task /
  graph finish (caller signs & broadcasts; see :meth:`TenzroClient.submit_feedback`).

References (canonical wire names & schemas):

* Bridge design: ``docs/architecture/agent-interop-protocol-bridge.md``
  (Layer 1 DID envelope, Layer 4 SDK shim, Open Question #4).
* Node RPC method names: ``crates/tenzro-node/src/rpc.rs``.
* Rust DID envelope reference (authoritative preimage layout):
  ``crates/tenzro-identity/src/envelope.rs``.
* AP2 v0.2 mandate schema: https://ap2-protocol.org/ap2/specification/ and
  ``docs/protocol-research-2026-05/ap2-v02.md``.
* ERC-8004 Trustless Agents: https://eips.ethereum.org/EIPS/eip-8004.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

import httpx
import nacl.signing

# ---------------------------------------------------------------------------
# DID envelope
# ---------------------------------------------------------------------------

#: Domain-separation tag. MUST match the Rust envelope module byte-for-byte.
DOMAIN_TAG: bytes = b"tenzro-did-envelope:v1"


def canonical_params_hash(params: Any) -> str:
    """SHA-256 (hex) of the canonical JSON encoding of ``params``.

    Canonical JSON = ``sort_keys=True`` + compact separators + UTF-8.
    The Rust side computes the identical hash over the same canonical
    bytes; both sides MUST agree on this encoding or signatures will not
    verify cross-language.
    """
    canon = json.dumps(
        params, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def canonical_preimage(
    did: str,
    method: str,
    params_hash_hex: str,
    timestamp: int,
    nonce: bytes,
) -> bytes:
    """Build the canonical preimage signed by the DID's Ed25519 key.

    Layout — MUST match the Rust ``tenzro-identity`` verifier byte-for-byte
    (``crates/tenzro-identity/src/envelope.rs::canonical_preimage``)::

        DOMAIN_TAG                              (b"tenzro-did-envelope:v1")
          || u32_be(len(did))                   (4 bytes)
          || did_utf8
          || u32_be(len(method))                (4 bytes)
          || method_utf8
          || params_hash (32 raw bytes, decoded from the hex digest)
          || timestamp   (u64, big-endian, 8 bytes)
          || nonce       (16 raw bytes)

    ``did`` and ``method`` are length-prefixed with a big-endian ``u32`` so
    the encoding is injective (no two distinct (did, method) pairs collide).
    This length-prefixing is REQUIRED for cross-language verification: the
    Rust verifier prepends the same prefixes, so omitting them here produces
    a different preimage and every signature fails to verify.
    """
    params_hash = bytes.fromhex(params_hash_hex)
    if len(params_hash) != 32:
        raise ValueError("params_hash must be 32 bytes (64 hex chars)")
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    did_bytes = did.encode("utf-8")
    method_bytes = method.encode("utf-8")
    return (
        DOMAIN_TAG
        + len(did_bytes).to_bytes(4, "big", signed=False)
        + did_bytes
        + len(method_bytes).to_bytes(4, "big", signed=False)
        + method_bytes
        + params_hash
        + int(timestamp).to_bytes(8, "big", signed=False)
        + nonce
    )


@dataclass
class TenzroDidEnvelope:
    """A client-built, Ed25519-signed Tenzro DID envelope.

    Serialises to the wire shape::

        {
          "did": "did:tenzro:machine:0x...",
          "method": "ap2.cart.complete",
          "params_hash": "<sha256 hex>",
          "timestamp": 1700000000000,
          "nonce": "<16 bytes hex>",
          "signature": "<ed25519 hex>"
        }
    """

    did: str
    method: str
    params_hash: str
    timestamp: int
    nonce: str  # 16 bytes, hex
    signature: str  # ed25519, hex

    @classmethod
    def sign(
        cls,
        signing_key: "nacl.signing.SigningKey",
        did: str,
        method: str,
        params: Any,
        *,
        timestamp: Optional[int] = None,
        nonce: Optional[bytes] = None,
    ) -> "TenzroDidEnvelope":
        """Build and sign an envelope over ``params``.

        ``timestamp`` defaults to the current Unix time in **milliseconds**
        (the Rust verifier enforces ``±MAX_SKEW_MS`` = 60s freshness against
        a millisecond clock, so seconds-resolution timestamps would always
        be rejected as stale); ``nonce`` defaults to 16 fresh random bytes.
        """
        ts = int(time.time() * 1000) if timestamp is None else int(timestamp)
        nb = secrets.token_bytes(16) if nonce is None else nonce
        ph = canonical_params_hash(params)
        preimage = canonical_preimage(did, method, ph, ts, nb)
        sig = signing_key.sign(preimage).signature
        return cls(
            did=did,
            method=method,
            params_hash=ph,
            timestamp=ts,
            nonce=nb.hex(),
            signature=sig.hex(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "did": self.did,
            "method": self.method,
            "params_hash": self.params_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "signature": self.signature,
        }

    def to_header_value(self) -> str:
        """Serialize to the compact hex header value the node expects in the
        ``X-Tenzro-DID-Envelope`` header / ``tenzro_verifyDidEnvelope`` RPC.

        Byte-identical to the Rust ``TenzroDidEnvelope::to_header_value``:
        ``u32 did_len || did || u32 method_len || method || params_hash(32) ||
        timestamp(u64) || nonce(16) || u32 sig_len || signature``, big-endian, hex.
        """
        import struct

        did_b = self.did.encode("utf-8")
        method_b = self.method.encode("utf-8")
        sig_b = bytes.fromhex(self.signature)
        buf = (
            struct.pack(">I", len(did_b))
            + did_b
            + struct.pack(">I", len(method_b))
            + method_b
            + bytes.fromhex(self.params_hash)
            + struct.pack(">Q", self.timestamp)
            + bytes.fromhex(self.nonce)
            + struct.pack(">I", len(sig_b))
            + sig_b
        )
        return buf.hex()

    def preimage(self) -> bytes:
        """Recompute the canonical preimage for this envelope."""
        return canonical_preimage(
            self.did,
            self.method,
            self.params_hash,
            self.timestamp,
            bytes.fromhex(self.nonce),
        )

    def verify(self, verify_key: "nacl.signing.VerifyKey") -> bool:
        """Verify the signature against ``verify_key``.

        Returns ``True`` on success, ``False`` if the signature does not
        validate. (The Rust verifier additionally resolves the DID and
        binds the public key to the DID's wallet address; this client-side
        check only confirms the signature itself.)
        """
        try:
            verify_key.verify(self.preimage(), bytes.fromhex(self.signature))
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# JSON-RPC client
# ---------------------------------------------------------------------------


class TenzroRpcError(RuntimeError):
    """Raised when the Tenzro node returns a JSON-RPC ``error`` object."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class TenzroClient:
    """Synchronous JSON-RPC 2.0 client to a Tenzro node.

    Mirrors the node RPC surface (``crates/tenzro-node/src/rpc.rs``). The
    method names sent below are the names the node actually dispatches in
    ``rpc.rs``; each is noted inline on its wrapper method.

    Auth-sensitive RPCs accept an optional :class:`TenzroDidEnvelope` which
    rides in the request ``params`` under the ``tenzro_did_envelope`` key
    (the generic-HTTP envelope-ridealong path of bridge doc Layer 1).

    NOTE: as of bridge-doc Phase 1, the shared ``tenzro-identity`` envelope
    is defined and signable but is NOT yet verified on the JSON-RPC path
    (wiring into MCP / x402 / RPC is Phase 2-3). The envelope built by
    :meth:`call_signed` uses the authoritative ``tenzro-identity`` preimage
    layout, so it will be accepted once that verification lands; today the
    node ignores it on the RPC path.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        *,
        signing_key: Optional["nacl.signing.SigningKey"] = None,
        did: Optional[str] = None,
        bearer_jwt: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.rpc_url = rpc_url or os.environ.get(
            "TENZRO_RPC_URL", "https://rpc.tenzro.network"
        )
        self.signing_key = signing_key
        self.did = did
        self.bearer_jwt = bearer_jwt or os.environ.get("TENZRO_BEARER_JWT")
        self.api_key = api_key or os.environ.get("TENZRO_API_KEY")
        self.timeout = timeout
        self._client = client
        self._owns_client = client is None
        self._request_id = 0

    # -- transport ----------------------------------------------------------

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "TenzroClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.bearer_jwt:
            headers["Authorization"] = f"DPoP {self.bearer_jwt}"
        if self.api_key:
            headers["X-Tenzro-Api-Key"] = self.api_key
        return headers

    def call(self, method: str, params: Any = None) -> Any:
        """Send a raw JSON-RPC 2.0 request and return ``result``."""
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params if params is not None else [],
        }
        resp = self._http().post(
            self.rpc_url, headers=self._headers(), json=payload
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            err = data["error"]
            raise TenzroRpcError(
                err.get("code", -32000),
                err.get("message", "unknown"),
                err.get("data"),
            )
        return data.get("result")

    def call_signed(self, method: str, params: Dict[str, Any]) -> Any:
        """Call ``method`` attaching a DID envelope built over ``params``.

        Requires ``signing_key`` and ``did`` to have been configured. The
        envelope is computed over the ``params`` mapping and attached under
        ``tenzro_did_envelope`` (envelope-ridealong, bridge doc Layer 1).
        """
        if self.signing_key is None or self.did is None:
            raise ValueError(
                "call_signed requires signing_key and did on the client"
            )
        envelope = TenzroDidEnvelope.sign(
            self.signing_key, self.did, method, params
        )
        enriched = dict(params)
        enriched["tenzro_did_envelope"] = envelope.to_dict()
        return self.call(method, enriched)

    # -- provisioning -------------------------------------------------------

    def participate(
        self,
        *,
        node_type: str = "agent",
        capabilities: Optional[Sequence[str]] = None,
        **extra: Any,
    ) -> Any:
        """Provision identity / wallet / ERC-8004 agent id for this agent.

        Wire method: ``tenzro_participate``
        (``crates/tenzro-node/src/rpc.rs::handle_participate``). Returns the
        node's provisioning result (TDIP DID, derived wallet addresses,
        ERC-8004 agent id).
        """
        params: Dict[str, Any] = {"node_type": node_type}
        if capabilities is not None:
            params["capabilities"] = list(capabilities)
        params.update(extra)
        return self.call("tenzro_participate", params)

    # -- saga workflow coordination -----------------------------------------

    def workflow_open(
        self,
        workflow_id: str,
        orchestrator_did: str,
        saga_steps: Sequence[Mapping[str, Any]],
        participants: Optional[Sequence[str]] = None,
    ) -> Any:
        """Open a multi-agent saga workflow. Wire method: ``tenzro_workflowOpen``."""
        return self.call(
            "tenzro_workflowOpen",
            {
                "workflow_id": workflow_id,
                "orchestrator_did": orchestrator_did,
                "saga_steps": [dict(s) for s in saga_steps],
                "participants": list(participants) if participants else [],
            },
        )

    def workflow_step_execute(
        self,
        workflow_id: str,
        step_idx: int,
        *,
        proof: Optional[str] = None,
        escrow_amount: Optional[int] = None,
        payer: Optional[str] = None,
        payee: Optional[str] = None,
    ) -> Any:
        """Execute a saga step (Pending->Executing); optionally lock per-step
        escrow. Wire method: ``tenzro_workflowStepExecute``."""
        params: Dict[str, Any] = {"workflow_id": workflow_id, "step_idx": step_idx}
        if proof is not None:
            params["proof"] = proof
        if escrow_amount is not None:
            params["escrow_amount"] = escrow_amount
        if payer is not None:
            params["payer"] = payer
        if payee is not None:
            params["payee"] = payee
        return self.call("tenzro_workflowStepExecute", params)

    def workflow_step_verify(
        self,
        workflow_id: str,
        step_idx: int,
        *,
        witness_signatures: Optional[Sequence[str]] = None,
        outcome_score: Optional[int] = None,
    ) -> Any:
        """Verify a saga step (releases per-step escrow + writes ERC-8004
        reputation). Wire method: ``tenzro_workflowStepVerify``."""
        params: Dict[str, Any] = {"workflow_id": workflow_id, "step_idx": step_idx}
        if witness_signatures is not None:
            params["witness_signatures"] = list(witness_signatures)
        if outcome_score is not None:
            params["outcome_score"] = outcome_score
        return self.call("tenzro_workflowStepVerify", params)

    def workflow_step_compensate(
        self, workflow_id: str, step_idx: int, *, cascade: bool = False
    ) -> Any:
        """Compensate a saga step (refund escrow); cascade=True rolls back every
        lower-index step in reverse. Wire method: ``tenzro_workflowStepCompensate``."""
        return self.call(
            "tenzro_workflowStepCompensate",
            {"workflow_id": workflow_id, "step_idx": step_idx, "cascade": cascade},
        )

    def workflow_finalize(self, workflow_id: str) -> Any:
        """Finalize a saga once all steps are Verified. Wire method:
        ``tenzro_workflowFinalize``."""
        return self.call("tenzro_workflowFinalize", {"workflow_id": workflow_id})

    def get_workflow_saga(self, workflow_id: str) -> Any:
        """Read a saga workflow's state. Wire method: ``tenzro_getWorkflowSaga``."""
        return self.call("tenzro_getWorkflowSaga", {"workflow_id": workflow_id})

    # -- DID envelope verification ------------------------------------------

    def verify_did_envelope(self, envelope_header: str) -> Any:
        """Verify a Tenzro DID envelope (hex header value, from
        ``TenzroDidEnvelope.to_header_value``) via the node. Supports
        did:tenzro / did:key / did:ethr / did:web. Wire method:
        ``tenzro_verifyDidEnvelope``."""
        return self.call("tenzro_verifyDidEnvelope", {"envelope": envelope_header})

    # -- capital intent (capital-allocation standard) -----------------------

    def capital_intent_open(self, intent: Mapping[str, Any]) -> Any:
        """Open a signed Capital Intent (regulated capital allocation over
        tokenized assets). ``intent`` matches the CapitalIntent schema
        (objective/constraints/compliance/authorization/settlement). Wire
        method: ``tenzro_capitalIntentOpen``."""
        return self.call("tenzro_capitalIntentOpen", {"intent": dict(intent)})

    def capital_intent_quote(
        self, intent_id: str, solver_did: str, *, plan: str = "",
        price: int = 0, eta_secs: int = 0,
    ) -> Any:
        """Solver bid to fulfil an intent. Wire: ``tenzro_capitalIntentQuote``."""
        return self.call("tenzro_capitalIntentQuote", {
            "intent_id": intent_id, "solver_did": solver_did,
            "plan": plan, "price": price, "eta_secs": eta_secs,
        })

    def capital_intent_assign(
        self, intent_id: str, solver_did: Optional[str] = None, *,
        auto: bool = False, payer: Optional[str] = None, payee: Optional[str] = None,
    ) -> Any:
        """Assign a solver and (if payer given) lock the principal escrow up to
        the authorized ceiling. Pass ``auto=True`` (or omit ``solver_did``) to
        auto-rank the received quotes by ERC-8004 reputation, then lowest price,
        then fastest eta. Wire: ``tenzro_capitalIntentAssign``."""
        params: Dict[str, Any] = {"intent_id": intent_id}
        if solver_did is not None:
            params["solver_did"] = solver_did
        if auto:
            params["auto"] = True
        if payer is not None:
            params["payer"] = payer
        if payee is not None:
            params["payee"] = payee
        return self.call("tenzro_capitalIntentAssign", params)

    def capital_intent_execute(self, intent_id: str, leg: Mapping[str, Any]) -> Any:
        """Record one executed settlement leg ({venue, asset_id, side, quantity,
        unit_price, settlement_ref?, proof?}). Wire:
        ``tenzro_capitalIntentExecute``."""
        return self.call("tenzro_capitalIntentExecute", {"intent_id": intent_id, "leg": dict(leg)})

    def capital_intent_verify(self, intent_id: str) -> Any:
        """Verify proofs / mark all legs settled. Wire: ``tenzro_capitalIntentVerify``."""
        return self.call("tenzro_capitalIntentVerify", {"intent_id": intent_id})

    def capital_intent_settle(self, intent_id: str, *, payee: Optional[str] = None) -> Any:
        """Release escrow to the solver + write ERC-8004 feedback + finalize.
        Wire: ``tenzro_capitalIntentSettle``."""
        params: Dict[str, Any] = {"intent_id": intent_id}
        if payee is not None:
            params["payee"] = payee
        return self.call("tenzro_capitalIntentSettle", params)

    def capital_intent_compensate(self, intent_id: str) -> Any:
        """Refund the principal escrow and fail the intent (saga compensation).
        Wire: ``tenzro_capitalIntentCompensate``."""
        return self.call("tenzro_capitalIntentCompensate", {"intent_id": intent_id})

    def get_capital_intent(self, intent_id: str) -> Any:
        """Read a capital intent record. Wire: ``tenzro_getCapitalIntent``."""
        return self.call("tenzro_getCapitalIntent", {"intent_id": intent_id})

    # -- proof-of-reserve + attested mint (1:1 backing) ---------------------

    def submit_reserve_attestation(self, attestation: Mapping[str, Any]) -> Any:
        """Record a signed reserve attestation backing a tokenized asset
        ({asset_id, reserves, source, attestor_did, attested_at, signature?}).
        Wire: ``tenzro_submitReserveAttestation``."""
        return self.call("tenzro_submitReserveAttestation", {"attestation": dict(attestation)})

    def attested_mint(self, token_id: str, to: str, amount: int, caller: str) -> Any:
        """Mint a tokenized asset ONLY if post-mint supply <= attested reserves
        (1:1 backing invariant). Wire: ``tenzro_attestedMint``."""
        return self.call("tenzro_attestedMint", {
            "token_id": token_id, "to": to, "amount": amount, "caller": caller,
        })

    def get_reserve(self, asset_id: str) -> Any:
        """Read the current reserve attestation. Wire: ``tenzro_getReserve``."""
        return self.call("tenzro_getReserve", {"asset_id": asset_id})

    # -- mandate validation -------------------------------------------------

    def validate_mandate_pair(
        self,
        checkout_mandate: Mapping[str, Any],
        payment_mandate: Mapping[str, Any],
    ) -> Any:
        """Validate a CheckoutMandate + PaymentMandate VDC pair.

        Wire method: ``tenzro_ap2ValidateMandatePair`` — the name dispatched
        by the node (``crates/tenzro-node/src/rpc.rs``). Enforces the
        three/four-ceiling validation (cart ≤ checkout ≤ DelegationScope ≤
        SpendingPolicy) and the ``accepted_chains`` whitelist.
        """
        return self.call(
            "tenzro_ap2ValidateMandatePair",
            {
                "checkout_mandate": dict(checkout_mandate),
                "payment_mandate": dict(payment_mandate),
            },
        )

    # -- task lifecycle -----------------------------------------------------

    def post_task(self, task: Mapping[str, Any]) -> Any:
        """Post a task to the network. Wire: ``tenzro_postTask``."""
        return self.call("tenzro_postTask", dict(task))

    def quote_task(self, task_id: str, **quote: Any) -> Any:
        """Submit a quote for a task. Wire: ``tenzro_quoteTask``."""
        return self.call("tenzro_quoteTask", {"task_id": task_id, **quote})

    def assign_task(self, task_id: str, assignee: str, **extra: Any) -> Any:
        """Assign a task to a provider. Wire: ``tenzro_assignTask``."""
        return self.call(
            "tenzro_assignTask",
            {"task_id": task_id, "assignee": assignee, **extra},
        )

    def complete_task(self, task_id: str, **result: Any) -> Any:
        """Mark a task complete. Wire: ``tenzro_completeTask``."""
        return self.call("tenzro_completeTask", {"task_id": task_id, **result})

    # -- ERC-8004 reputation ------------------------------------------------

    def submit_feedback(
        self,
        subject_agent_id: int,
        rating: int,
        *,
        context_uri: str = "",
    ) -> Any:
        """Encode ERC-8004 reputation-feedback calldata for ``subject_agent_id``.

        Wire method: ``tenzro_erc8004EncodeFeedback`` with params
        ``subject_agent_id`` / ``rating`` / ``context_uri``. NOTE: this RPC
        only **encodes** the ABI calldata (returns hex); it does not submit
        the feedback on-chain. The caller must sign and broadcast the
        returned calldata (e.g. via ``tenzro_signAndSendTransaction``).
        ``rating`` is the ERC-8004 signed score (e.g. +1 / -1).
        """
        return self.call(
            "tenzro_erc8004EncodeFeedback",
            {
                "subject_agent_id": subject_agent_id,
                "rating": rating,
                "context_uri": context_uri,
            },
        )


# ---------------------------------------------------------------------------
# AP2 mandate helpers
# ---------------------------------------------------------------------------
#
# Field names follow the Tenzro AP2 model in
# crates/tenzro-payments/src/ap2/mod.rs (CheckoutMandate / CartItem /
# PaymentMandate) and the AP2 v0.2 spec (vct claims, checkout_hash binding,
# cnf). The IntentMandate / CartMandate dicts express the AP2 canonical
# mandate names; in the Tenzro model the principal-signed CheckoutMandate
# is the "intent" declaration and CartItem[] is the cart.


def _now_iso() -> str:
    # AP2 mandates use RFC3339 timestamps; Tenzro stores DateTime<Utc>.
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def intent_mandate(
    *,
    principal_did: str,
    agent_did: str,
    description: str,
    max_amount: int,
    asset: str = "USDC",
    accepted_chains: Optional[Sequence[str]] = None,
    expires_at: Optional[str] = None,
    open_mandate: bool = False,
    cnf: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an AP2 IntentMandate dict (pre-authorised autonomous flow).

    Per ``ap2-v02.md`` the IntentMandate authorises a future autonomous
    purchase. ``open_mandate=True`` selects the ``.open`` ``vct`` variants
    (human-not-present) and then ``cnf`` (agent public-key JWK) is required.
    """
    m: Dict[str, Any] = {
        "vct": "mandate.intent.open.1" if open_mandate else "mandate.intent.1",
        "mandate_id": str(uuid.uuid4()),
        "principal_did": principal_did,
        "agent_did": agent_did,
        "description": description,
        "max_amount": int(max_amount),
        "asset": asset,
        "accepted_chains": list(accepted_chains or []),
        "issued_at": _now_iso(),
        "expires_at": expires_at,
    }
    if cnf is not None:
        m["cnf"] = dict(cnf)
    return m


def cart_item(
    *,
    sku: str,
    description: str,
    quantity: int,
    unit_price: int,
    category: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a single AP2 cart line item (``CartItem`` in the Rust model)."""
    return {
        "sku": sku,
        "description": description,
        "quantity": int(quantity),
        "unit_price": int(unit_price),
        "total": int(quantity) * int(unit_price),
        "category": category,
    }


def cart_mandate(
    *,
    agent_did: str,
    merchant_did: str,
    items: Sequence[Mapping[str, Any]],
    asset: str = "USDC",
    chain: str = "tenzro",
) -> Dict[str, Any]:
    """Build an AP2 CartMandate dict (the agent-signed cart).

    The cart total is derived from the line items; the validator checks
    ``cart total ≤ checkout ceiling``.
    """
    items = [dict(i) for i in items]
    return {
        "vct": "mandate.cart.1",
        "mandate_id": str(uuid.uuid4()),
        "agent_did": agent_did,
        "merchant_did": merchant_did,
        "items": items,
        "total_amount": sum(int(i["total"]) for i in items),
        "asset": asset,
        "chain": chain,
        "issued_at": _now_iso(),
    }


def checkout_mandate(
    *,
    principal_did: str,
    agent_did: str,
    description: str,
    max_amount: int,
    asset: str = "USDC",
    accepted_chains: Optional[Sequence[str]] = None,
    allowed_merchants: Optional[Sequence[str]] = None,
    allowed_categories: Optional[Sequence[str]] = None,
    max_uses: Optional[int] = None,
    expires_at: Optional[str] = None,
    human_present: bool = True,
    cnf: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an AP2 CheckoutMandate dict.

    Mirrors ``CheckoutMandate`` in ``crates/tenzro-payments/src/ap2/mod.rs``:
    ``mandate_id`` / ``principal_did`` / ``agent_did`` / ``description`` /
    ``max_amount`` / ``asset`` / ``allowed_merchants`` /
    ``allowed_categories`` / ``accepted_chains`` / ``max_uses`` /
    ``issued_at`` / ``expires_at`` / ``presence`` / ``cnf``. ``presence``
    drives the ``vct`` ``.open`` variant when the human is not present.
    """
    presence = "HumanPresent" if human_present else "HumanNotPresent"
    vct = "mandate.checkout.1" if human_present else "mandate.checkout.open.1"
    m: Dict[str, Any] = {
        "vct": vct,
        "mandate_id": str(uuid.uuid4()),
        "principal_did": principal_did,
        "agent_did": agent_did,
        "description": description,
        "max_amount": int(max_amount),
        "asset": asset,
        "allowed_merchants": list(allowed_merchants or []),
        "allowed_categories": list(allowed_categories or []),
        "accepted_chains": list(accepted_chains or []),
        "max_uses": max_uses,
        "issued_at": _now_iso(),
        "expires_at": expires_at,
        "presence": presence,
    }
    if cnf is not None:
        m["cnf"] = dict(cnf)
    return m


def checkout_hash(checkout: Mapping[str, Any]) -> str:
    """SHA-256 (hex) of the canonical CheckoutMandate bytes.

    AP2 v0.2 §6.2.3: the child PaymentMandate carries
    ``checkout_hash = sha256(parent_checkout_vdc_bytes)`` to bind the pair.
    We hash the canonical JSON encoding of the checkout dict.
    """
    return canonical_params_hash(checkout)


def payment_mandate(
    *,
    checkout: Mapping[str, Any],
    agent_did: str,
    merchant_did: str,
    items: Sequence[Mapping[str, Any]],
    chain: str,
    asset: str = "USDC",
    expires_at: Optional[str] = None,
    human_present: bool = True,
    cnf: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an AP2 PaymentMandate dict bound to its parent CheckoutMandate.

    Mirrors ``PaymentMandate`` in the Rust model:
    ``mandate_id`` / ``checkout_mandate_id`` / ``agent_did`` /
    ``merchant_did`` / ``items`` / ``total_amount`` / ``asset`` / ``chain``
    / ``committed_at`` / ``expires_at`` / ``checkout_hash`` / ``cnf``. The
    ``checkout_hash`` binds this PaymentMandate to ``checkout`` per the AP2
    spec.
    """
    items = [dict(i) for i in items]
    vct = "mandate.payment.1" if human_present else "mandate.payment.open.1"
    m: Dict[str, Any] = {
        "vct": vct,
        "mandate_id": str(uuid.uuid4()),
        "checkout_mandate_id": checkout["mandate_id"],
        "agent_did": agent_did,
        "merchant_did": merchant_did,
        "items": items,
        "total_amount": sum(int(i["total"]) for i in items),
        "asset": asset,
        "chain": chain,
        "committed_at": _now_iso(),
        "expires_at": expires_at,
        "checkout_hash": checkout_hash(checkout),
    }
    if cnf is not None:
        m["cnf"] = dict(cnf)
    return m


# ---------------------------------------------------------------------------
# Reputation hook
# ---------------------------------------------------------------------------


@dataclass
class ReputationHook:
    """Submits ERC-8004 feedback via :class:`TenzroClient` on finish.

    Used by every framework adapter: when a task / graph / run completes,
    the adapter calls :meth:`on_finish` with the subject agent id and an
    outcome. ``outcome_ratings`` maps outcome strings to ERC-8004 ratings
    (default: ``success`` → +1, ``failure`` → -1).
    """

    client: TenzroClient
    subject_agent_id: int
    outcome_ratings: Dict[str, int] = field(
        default_factory=lambda: {"success": 1, "failure": -1}
    )

    def on_finish(
        self,
        outcome: str = "success",
        *,
        context_uri: str = "",
    ) -> Any:
        """Submit feedback for ``outcome``. Returns the RPC result.

        Never raises on an unknown ``outcome`` — falls back to a neutral
        rating of ``0`` so a finish-hook failure can't crash the agent run.
        """
        rating = self.outcome_ratings.get(outcome, 0)
        return self.client.submit_feedback(
            self.subject_agent_id, rating, context_uri=context_uri
        )


__all__ = [
    "DOMAIN_TAG",
    "canonical_params_hash",
    "canonical_preimage",
    "TenzroDidEnvelope",
    "TenzroRpcError",
    "TenzroClient",
    "intent_mandate",
    "cart_item",
    "cart_mandate",
    "checkout_mandate",
    "checkout_hash",
    "payment_mandate",
    "ReputationHook",
]
