#!/usr/bin/env python3
"""TenzroClaw — Tenzro blockchain RPC helper.

Part of the TenzroClaw OpenClaw skill for interacting with the Tenzro Network.
Wraps Tenzro JSON-RPC, Web API, and ecosystem MCP server calls into simple
functions.

Requires: pip install requests

Ecosystem MCP servers (Solana, Ethereum, Chainlink) are
called via the MCP Streamable HTTP protocol. Each ecosystem function uses
mcp_tool_call() to initialize a session and invoke a tool.

Usage:
    python tenzro_rpc.py join_network "Alice"
    python tenzro_rpc.py get_balance 0x1234...
    python tenzro_rpc.py status
    python tenzro_rpc.py register_identity "Alice"
    python tenzro_rpc.py resolve_did "did:tenzro:human:..."
    python tenzro_rpc.py block_height
    python tenzro_rpc.py get_block 0
    python tenzro_rpc.py chain_id
    python tenzro_rpc.py chat gemma4-9b "What is Tenzro?"
    python tenzro_rpc.py route_intent reasoning 1000000000000000000 0.7 strong
    python tenzro_rpc.py chat_by_intent code "Explain this trait bound"
    python tenzro_rpc.py record_route_outcome qwen3-4b 3 escalated
    python tenzro_rpc.py route_difficulty_stats qwen3-4b
    python tenzro_rpc.py list_model_endpoints
    python tenzro_rpc.py create_payment x402 /inference 100 USDC 0xrecipient
    python tenzro_rpc.py verify_payment <challenge_id> x402 <payer_did> 0xpayer 100 USDC 0xsig
    python tenzro_rpc.py list_duties
    python tenzro_rpc.py get_duty <duty_id>
    python tenzro_rpc.py get_token_info MYT
    python tenzro_rpc.py list_tokens
    python tenzro_rpc.py get_token_balance 0x1234...
    python tenzro_rpc.py deploy_contract '<signed ContractDeploy transaction JSON>'
    python tenzro_rpc.py list_bridge_routes
    python tenzro_rpc.py role_stakes 0xwallet
    python tenzro_rpc.py provider_stats
    python tenzro_rpc.py discover_models text
    python tenzro_rpc.py register_machine_identity <controller_did> <public_key_hex> nlp,code <did_envelope_hex>
    python tenzro_rpc.py list_identities
    python tenzro_rpc.py peer_count
    python tenzro_rpc.py syncing
    python tenzro_rpc.py hardware_profile
    python tenzro_rpc.py get_finalized_block
    python tenzro_rpc.py export_config
    python tenzro_rpc.py get_transaction 0x<hash>
    python tenzro_rpc.py get_nonce 0x<address>
    python tenzro_rpc.py get_transaction_history 0x<address>
    python tenzro_rpc.py settle '{"service_type":"inference",...}'
    python tenzro_rpc.py open_payment_channel 0xpartyA 0xpartyB 1000000000000000000
    python tenzro_rpc.py close_payment_channel <channel_id>
    python tenzro_rpc.py inference_request gemma4-9b "What is Tenzro?"
    python tenzro_rpc.py register_model_endpoint gemma4-9b http://localhost:8000/v1
    python tenzro_rpc.py get_model_endpoint <instance_id>
    python tenzro_rpc.py unregister_model_endpoint <instance_id>
    python tenzro_rpc.py serve_model gemma4-9b
    python tenzro_rpc.py stop_model gemma4-9b
    python tenzro_rpc.py delete_model gemma4-9b
    python tenzro_rpc.py list_proposals policy_update
    python tenzro_rpc.py get_voting_power 0x<address>
    python tenzro_rpc.py set_role Validator
    python tenzro_rpc.py list_providers ai
    python tenzro_rpc.py get_provider_pricing
    python tenzro_rpc.py eth_block_number
    python tenzro_rpc.py eth_gas_price
    python tenzro_rpc.py eth_max_priority_fee_per_gas
    python tenzro_rpc.py eth_fee_history 10 latest "[25,50,75]"
    python tenzro_rpc.py eth_get_balance 0x<address>
    python tenzro_rpc.py eth_get_transaction_receipt 0x<hash>
    python tenzro_rpc.py eth_get_code 0x<address>
    python tenzro_rpc.py eth_get_block_by_number latest
    python tenzro_rpc.py net_peer_count
    python tenzro_rpc.py net_version

    # Chainlink MCP tools
    python tenzro_rpc.py chainlink_get_price ETH/USD
    python tenzro_rpc.py ds_list_feeds

    # OAuth 2.1 + DPoP onboarding
    python tenzro_rpc.py onboard_human "Alice" <credential_id> <p256_pubkey> <ml_dsa_pubkey> '<authorization json>'
    python tenzro_rpc.py onboard_delegated_agent did:tenzro:human:... '["inference"]' '{}'
    python tenzro_rpc.py onboard_autonomous_agent <device_public_key_hex> <machine_id>
    python tenzro_rpc.py revoke_jwt <jti> "lost device"
    python tenzro_rpc.py revoke_did did:tenzro:human:... "lost device"

    # AgentBond + Insurance
    python tenzro_rpc.py get_agent_bond did:tenzro:machine:...
    python tenzro_rpc.py get_insurance_pool_balance

    # Adaptive Burn governance dial
    python tenzro_rpc.py list_bound_devices
    python tenzro_rpc.py wallet_readiness
    python tenzro_rpc.py get_economic_policy
    python tenzro_rpc.py get_burn_rate_config
    python tenzro_rpc.py get_supply_metrics
    python tenzro_rpc.py get_burn_rate_recommendation

    # Mempool / hot-state
    python tenzro_rpc.py get_mempool_stats
    python tenzro_rpc.py get_account_contention 0x<address>

    # Managed Databases — local → LAN → network
"""

import json
import sys
from typing import Any

try:
    import requests
except ImportError:
    print(json.dumps({"error": "requests library required: pip install requests"}))
    sys.exit(1)

# Default endpoints — override with environment variables
import os

RPC_URL = os.environ.get("TENZRO_RPC_URL", "https://rpc.tenzro.com")
API_URL = os.environ.get("TENZRO_API_URL", "https://api.tenzro.com")
RPC_TIMEOUT = int(os.environ.get("TENZRO_RPC_TIMEOUT", "120"))

# Ecosystem MCP server endpoints
CHAINLINK_MCP_URL = os.environ.get(
    "CHAINLINK_MCP_URL", "https://chainlink-mcp.tenzro.com/mcp")

_request_id = 0

def _rpc(method: str, params: Any = None) -> dict:
    """Send a JSON-RPC 2.0 request to Tenzro.

    Auth-sensitive RPCs (signing, escrow, settlement) require an OAuth/DPoP
    bearer JWT. Set the TENZRO_BEARER_JWT environment variable to your
    issued JWT and TENZRO_DPOP_PROOF to a fresh DPoP proof header value.
    The server validates both before invoking the auth-mediated signing
    path. Public RPCs (balance, status, block reads) work without auth.

    Which methods need a token is the node's access policy. Node
    administration (the operator and the administrators the policy
    names) never extends to network-wide state, which flows through
    on-chain governance.

    """
    global _request_id
    _request_id += 1
    call_params = params if params is not None else {}
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": call_params,
        "id": _request_id,
    }
    headers = {"Content-Type": "application/json"}
    bearer = os.environ.get("TENZRO_BEARER_JWT")
    if bearer:
        headers["Authorization"] = f"DPoP {bearer}"
    dpop = os.environ.get("TENZRO_DPOP_PROOF")
    if dpop:
        headers["DPoP"] = dpop
    resp = requests.post(RPC_URL, json=payload, headers=headers,
                         timeout=RPC_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        return {"error": data["error"]}
    return data.get("result", {})

def _api_get(path: str) -> dict:
    """GET request to Web API."""
    resp = requests.get(f"{API_URL}{path}", timeout=30)
    resp.raise_for_status()
    return resp.json()

def _api_post(path: str, body: dict) -> dict:
    """POST request to Web API."""
    resp = requests.post(f"{API_URL}{path}", json=body, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _mcp_tool_call(mcp_url: str, tool_name: str,
                   arguments: dict) -> dict:
    """Call a tool on an ecosystem MCP server via Streamable HTTP.

    Handles the MCP initialize handshake, session tracking, and
    SSE response parsing automatically.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    # Step 1: Initialize session
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "tenzroclaw", "version": "0.1.0"},
        },
    }
    resp = requests.post(mcp_url, json=init_payload,
                         headers=headers, timeout=RPC_TIMEOUT)
    resp.raise_for_status()
    session_id = resp.headers.get("mcp-session-id", "")

    # Step 2: Call tool
    tool_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = requests.post(mcp_url, json=tool_payload,
                         headers=headers, timeout=RPC_TIMEOUT)
    resp.raise_for_status()

    # Parse SSE or direct JSON response
    for line in resp.text.split("\n"):
        if line.startswith("data:"):
            try:
                data = json.loads(line[5:].strip())
                if "result" in data:
                    content = data["result"].get("content", [])
                    if content:
                        text = content[0].get("text", "{}")
                        try:
                            return json.loads(text)
                        except (json.JSONDecodeError, ValueError):
                            return {"text": text}
            except (json.JSONDecodeError, ValueError):
                continue

    # Fallback: direct JSON response
    try:
        body = resp.json()
        if "result" in body:
            content = body["result"].get("content", [])
            if content:
                text = content[0].get("text", "{}")
                try:
                    return json.loads(text)
                except (json.JSONDecodeError, ValueError):
                    return {"text": text}
            return body["result"]
        if "error" in body:
            return {"error": body["error"]}
        return body
    except (json.JSONDecodeError, ValueError):
        return {"text": resp.text}

# ── Wallet & Balance ──────────────────────────────────────────────

def get_balance(address: str) -> dict:
    """Get TNZO balance for an address. Returns balance in wei (1 TNZO = 10^18 wei) as a decimal string."""
    result = _rpc("tenzro_getBalance", {"address": address})
    if isinstance(result, str):
        wei = int(result, 16)
        return {"address": address, "balance_wei": str(wei)}
    return result


def send_self_custody_transaction(from_addr: str, to_addr: str, value: int,
                                  signature: str, public_key: str,
                                  pq_signature: str, pq_public_key: str,
                                  timestamp: int,
                                  gas_limit: int = 21000,
                                  gas_price: int = 1_000_000_000,
                                  nonce: int | None = None,
                                  chain_id: int | None = None) -> dict:
    """Submit a pre-signed self-custody TNZO transfer via tenzro_sendRawTransaction.

    A self-custody runner holds its Ed25519 + ML-DSA-65 keypair locally (in a
    TEE seal or an offline signer), builds the canonical Transaction::hash()
    preimage, and signs both legs itself — the node never sees the secret.
    This wrapper only forwards the already-signed material; it does not sign,
    because ML-DSA-65 signing lives with the local signer (the Tenzro CLI
    keystore, the Rust/TypeScript SDK, or a hardware enclave).

    The preimage that `signature` and `pq_signature` cover is
    `chain_id.le || from(32) || to(32) || nonce.le || gas_limit.le ||
    gas_price.le || timestamp.le || {"Transfer":{"amount":<value>}} ||
    pq_len.u32.le || pq_public_key` hashed with SHA-256. `timestamp` is the
    ms-epoch used at signing time and MUST match — the node rebuilds the same
    preimage and rejects a mismatch.

    Args:
        from_addr: 32-byte hex Ed25519 public key (the account address).
        to_addr: 32-byte hex recipient address.
        value: Amount in wei (1 TNZO = 10**18 wei).
        signature: 64-byte hex Ed25519 signature over the preimage.
        public_key: 32-byte hex Ed25519 public key (must derive from_addr).
        pq_signature: 3309-byte hex ML-DSA-65 signature over the preimage.
        pq_public_key: 1952-byte hex ML-DSA-65 verifying key.
        timestamp: ms-epoch timestamp used when the preimage was built.
        gas_limit: Gas limit used at signing time (default 21000).
        gas_price: Gas price in wei used at signing time (default 1e9).
        nonce: Nonce used at signing time. Queried live if omitted — pass it
            explicitly when it must match a nonce fixed at signing.
        chain_id: Chain id used at signing time. Queried live if omitted.
    """
    if nonce is None:
        nonce = _read_quantity("nonce", "eth_getTransactionCount", [from_addr, "latest"])

    if chain_id is None:
        chain_id = _read_quantity("chain id", "eth_chainId", [])

    return _rpc("tenzro_sendRawTransaction", {
        "from": from_addr,
        "to": to_addr,
        "value": str(value),
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "nonce": nonce,
        "chain_id": chain_id,
        "timestamp": timestamp,
        "public_key": public_key,
        "signature": signature,
        "pq_public_key": pq_public_key,
        "pq_signature": pq_signature,
    })

# ── Node Status ───────────────────────────────────────────────────

def get_status() -> dict:
    """Get node status (health, block height, peers, uptime)."""
    return _api_get("/status")

def get_health() -> dict:
    """Health check."""
    return _api_get("/health")

def block_height() -> dict:
    """Get the current block height."""
    result = _rpc("tenzro_blockNumber")
    if isinstance(result, str):
        return {"block_height": int(result, 16), "hex": result}
    return result

def get_block(height: int) -> dict:
    """Get a block by height."""
    return _rpc("tenzro_getBlock", {"height": height})

def get_block_range(start_height: int, end_height: int,
                    max_results: int = 64) -> dict:
    """Fetch a contiguous range of blocks for catch-up sync.

    Returns a dict with `blocks`, `nextHeight`, `moreAvailable`, and `localTip`.
    `moreAvailable` reflects whether the chain has more data past `nextHeight`,
    so a sync loop can step over pruning gaps by repeatedly calling with
    `start_height = response["nextHeight"]` while `moreAvailable` is true.
    """
    return _rpc("tenzro_getBlockRange", {
        "startHeight": start_height,
        "endHeight": end_height,
        "maxResults": max_results,
    })

def chain_id() -> dict:
    """Get the chain ID."""
    result = _rpc("eth_chainId")
    if isinstance(result, str):
        return {"chain_id": int(result, 16), "hex": result}
    return result

def node_info() -> dict:
    """Get full node info via RPC."""
    return _rpc("tenzro_getNodeStatus")

def node_did_document() -> dict:
    """Resolve this node's DID Document — every way of reaching it.

    A node is addressed by its TDIP DID, Ed25519 public key, iroh
    EndpointId and relays, plus its JSON-RPC / MCP / A2A /
    web service URLs. Resolving the DID yields all of them, so a caller
    holding any one identifier can get the rest.

    Also served at ``/.well-known/did.json`` for generic DID resolvers.
    """
    return _rpc("tenzro_nodeDidDocument")

def get_settlement_preference(payee_did: str) -> dict:
    """What asset this payee is paid in.

    Defaults to keeping whatever asset arrived. A payee who declared TNZO is
    paid TNZO or the payment is refused — crediting the inbound stablecoin
    instead would hand them an asset they did not choose.
    """
    return _rpc("tenzro_getSettlementPreference", {"payee_did": payee_did})

# ── Identity ──────────────────────────────────────────────────────

def register_identity(display_name: str | None = None,
                      identity_type: str = "human",
                      controller_did: str | None = None,
                      capabilities: list | None = None,
                      delegation_scope: dict | None = None,
                      public_key: str | None = None,
                      key_type: str = "ed25519") -> dict:
    """Register a TDIP identity. Returns the new DID and (when keypair is
    auto-generated) the private key.

    identity_type:
      - 'human' (default): only `display_name` is meaningful.
      - 'machine': requires `controller_did` and `capabilities`. Optional
        `delegation_scope` constrains spending and operations the machine
        may perform on behalf of the controller.
      - 'autonomous': requires `capabilities`. No human controller; the
        machine acts purely on its own hardware-held key (TPM / Secure Enclave).

    delegation_scope shape (all keys optional):
      {
        "max_transaction_value": "1000000000000000000",  # decimal-string or number
        "max_daily_spend":       "5000000000000000000",
        "allowed_operations":    ["transfer", "inference"],
        "allowed_payment_protocols": ["mpp", "x402"],
        "allowed_chains":        ["tenzro"],
      }
    """
    params = {"identity_type": identity_type}
    if display_name:
        params["display_name"] = display_name
    if controller_did:
        params["controller_did"] = controller_did
    if capabilities:
        params["capabilities"] = capabilities
    if delegation_scope:
        params["delegation_scope"] = delegation_scope
    if public_key:
        params["public_key"] = public_key
        params["key_type"] = key_type
    return _rpc("tenzro_registerIdentity", params)

def register_autonomous_identity(capabilities: list,
                                 public_key: str | None = None,
                                 key_type: str = "ed25519") -> dict:
    """Register an autonomous machine identity (no human controller).
    Convenience wrapper around register_identity(identity_type='autonomous')."""
    return register_identity(
        identity_type="autonomous",
        capabilities=capabilities,
        public_key=public_key,
        key_type=key_type,
    )

def resolve_did(did: str) -> dict:
    """Resolve a DID to identity information."""
    return _rpc("tenzro_resolveIdentity", {"did": did})

def resolve_did_document(did: str) -> dict:
    """Resolve a DID to a W3C DID Document."""
    return _rpc("tenzro_resolveDidDocument", {"did": did})

def join_as_micro_node(display_name: str = "Tenzro User",
                       origin: str = "cli",
                       participant_type: str = "human") -> dict:
    """Join the Tenzro Network as a MicroNode participant.

    Zero-install: provisions a TDIP DID and wallet, and returns the identity,
    wallet, capabilities, network endpoints and chain ID.
    """
    params = {
        "display_name": display_name.lstrip("@"),
        "origin": origin,
        "participant_type": participant_type,
    }
    return _rpc("tenzro_joinAsMicroNode", params)

# ── Verification ──────────────────────────────────────────────────

def verify_zk_proof(proof_bytes: str, public_inputs: list,
                    circuit_id: str) -> dict:
    """Verify a Plonky3 STARK proof over KoalaBear via Web API.

    circuit_id: one of "inference", "settlement", "identity"
    public_inputs: list of hex-encoded 4-byte little-endian KoalaBear chunks
    """
    return _api_post("/verify/zk-proof", {
        "proof_bytes": proof_bytes,
        "public_inputs": public_inputs,
        "circuit_id": circuit_id,
    })

def verify_tee_attestation(vendor: str, report_data: str,
                           measurement: str | None = None) -> dict:
    """Verify a TEE attestation via Web API."""
    body = {"vendor": vendor, "report_data": report_data}
    if measurement:
        body["measurement"] = measurement
    return _api_post("/verify/tee-attestation", body)

# ── Node access ───────────────────────────────────────────────────
#
# Sign in once with a passkey or hardware key for a DPoP-bound access
# token (tenzro_accessChallenge, then tenzro_issueAccessToken with the
# signed answer), and export it as TENZRO_BEARER_JWT with a per-call
# TENZRO_DPOP_PROOF. The policy and token calls are for the node's
# operator and the administrators its access policy names.

def access_challenge(did: str, dpop_jkt: str) -> dict:
    """Ask for a single-use sign-in challenge for `did`, bound to a DPoP key."""
    return _rpc("tenzro_accessChallenge", {"did": did, "dpop_jkt": dpop_jkt})

def get_access_policy() -> dict:
    """The node's access policy, as data and as access.toml text."""
    return _rpc("tenzro_getAccessPolicy")

def set_access_policy(toml_text: str) -> dict:
    """Replace the node's access policy with `toml_text`. Returns the new version."""
    return _rpc("tenzro_setAccessPolicy", {"toml": toml_text})

def preview_access(surface: str, method: str, did: str | None = None) -> dict:
    """What the access policy decides for `did` (anonymous when None) calling `method` on `surface`."""
    params = {"surface": surface, "method": method}
    if did:
        params["did"] = did
    return _rpc("tenzro_previewAccess", params)

def list_access_tokens() -> dict:
    """The live access tokens the node issued."""
    return _rpc("tenzro_listAccessTokens")

def revoke_access_token(target: str) -> dict:
    """Withdraw one access token by jti, or every live token of a DID."""
    key = "did" if target.startswith("did:") else "jti"
    return _rpc("tenzro_revokeAccessToken", {key: target})

# ── Token ─────────────────────────────────────────────────────────

def total_supply() -> dict:
    """Get total TNZO token supply."""
    return _rpc("tenzro_totalSupply")

def token_balance(address: str) -> dict:
    """Get TNZO token balance for an address."""
    return _rpc("tenzro_tokenBalance", {"address": address})

# ── Token Registry & Contracts ───────────────────────────────────


def get_token_info(symbol: str | None = None, evm_address: str | None = None,
                   token_id: str | None = None) -> dict:
    """Look up a token by symbol, EVM address, or token ID.

    Provide exactly one of: symbol, evm_address, or token_id.
    """
    params = {}
    if symbol:
        params["symbol"] = symbol
    if evm_address:
        params["evm_address"] = evm_address
    if token_id:
        params["token_id"] = token_id
    if not params:
        return {"error": "Provide symbol, evm_address, or token_id"}
    return _rpc("tenzro_getToken", params)

def list_tokens(vm_type: str | None = None, limit: int = 50) -> dict:
    """List registered tokens in the unified token registry.

    vm_type: optional filter — evm | svm | native
    limit: max tokens to return (default 50, max 100)
    """
    params = {}
    if vm_type:
        params["vm_type"] = vm_type
    if limit != 50:
        params["limit"] = limit
    return _rpc("tenzro_listTokens", params)

def get_token_balance_all_vms(address: str) -> dict:
    """Get TNZO balance across all VMs (native, EVM wTNZO, SVM wTNZO).

    Returns balances with decimal conversion for each VM representation.
    """
    return _rpc("tenzro_getTokenBalance", {"address": address})

def deploy_contract(signed_tx: dict) -> dict:
    """Submit a contract deployment the deployer signed on its own hardware.

    signed_tx: the fields ``tenzro_sendRawTransaction`` takes, with
    ``tx_type`` a ``ContractDeploy`` carrying the EVM creation code and
    constructor arguments, ``public_key`` and the composite ``signature``.
    The contract is created when a block executes the transaction; the
    answer is its ``tx_hash``.
    """
    return _rpc("tenzro_deployContract", signed_tx)

# ── Models ────────────────────────────────────────────────────────

def list_models(loaded: bool = False) -> dict:
    """List registered AI models.

    With `loaded=True`, list every model this node holds, of every type,
    with its engine, visibility, access and loaded/serving state.
    """
    if loaded:
        return _rpc("tenzro_listModels", {"loaded": True})
    return _rpc("tenzro_listModels")

def chat(model: str, message: str, temperature: float = 0.7,
         max_tokens: int = 512) -> dict:
    """Send a chat completion request to a served AI model."""
    return _rpc("tenzro_chat", {
        "model_id": model,
        "message": message,
        "temperature": temperature,
        "max_tokens": max_tokens,
    })

def list_model_endpoints() -> dict:
    """List running model service endpoints."""
    return _rpc("tenzro_listModelEndpoints")

def _intent_params(use_case: str, budget: int | None = None, optimize: float | None = None,
                   quality_floor: str | None = None, est_input_tokens: int | None = None,
                   est_output_tokens: int | None = None, payer_did: str | None = None,
                   payer_address: str | None = None) -> dict:
    """Assemble the intent fields shared by route_intent and chat_by_intent."""
    params = {"use_case": use_case}
    for key, value in (
        ("budget", str(budget) if budget is not None else None),
        ("optimize", optimize),
        ("quality_floor", quality_floor),
        ("est_input_tokens", est_input_tokens),
        ("est_output_tokens", est_output_tokens),
        ("payer_did", payer_did),
        ("payer_address", payer_address),
    ):
        if value is not None:
            params[key] = value
    return params

def route_intent(use_case: str, budget: int | None = None, optimize: float | None = None,
                 quality_floor: str | None = None, est_input_tokens: int | None = None,
                 est_output_tokens: int | None = None, payer_did: str | None = None,
                 payer_address: str | None = None, prompt: str | None = None) -> dict:
    """Select the best model for an intent without naming one.

    use_case: chat | code | reasoning | research | summarize | extract | embed
    budget: per-request cost cap in the smallest TNZO unit
    optimize: cost-quality knob in [0.0, 1.0]
    quality_floor: cheap | strong — rejects anything below the tier
    payer_did: enables the per-DID rolling-window budget gate
    payer_address: makes the payer's on-chain TNZO balance a hard ceiling
    prompt: the text the model would answer, used only to place the request in
        a difficulty cluster so selection accounts for how hard it is; it is
        not sent to any provider

    Returns the model, tier, estimated cost, fallback chain, the cluster the
    prompt landed in, that model's error rate there, and the winning provider's
    address and endpoint when the offer came from another operator. Discovery
    only — nothing is dispatched and no spend is recorded, though the budget
    gate and the wallet-balance ceiling still apply.
    """
    params = _intent_params(use_case, budget, optimize, quality_floor,
                            est_input_tokens, est_output_tokens,
                            payer_did, payer_address)
    if prompt is not None:
        params["prompt"] = prompt
    return _rpc("tenzro_routeIntent", params)

def chat_by_intent(use_case: str, message: str, budget: int | None = None,
                   optimize: float | None = None, quality_floor: str | None = None,
                   est_input_tokens: int | None = None, est_output_tokens: int | None = None,
                   payer_did: str | None = None, payer_address: str | None = None,
                   temperature: float | None = None, max_tokens: int | None = None) -> dict:
    """Resolve an intent to a model and run the chat in one call.

    Selection walks the cross-model fallback chain, so the intent resolves as
    long as any model that satisfies it has a live offer, and dispatch is
    pinned to the offer that was scored — the price quoted is the price settled
    and the provider share goes to the address that offer named. The decision
    is attached to the response under `route`. Difficulty feedback for resolved
    and failed calls is recorded from the dispatch itself; report an escalation
    with `record_route_outcome`.
    """
    params = _intent_params(use_case, budget, optimize, quality_floor,
                            est_input_tokens, est_output_tokens,
                            payer_did, payer_address)
    params["message"] = message
    if temperature is not None:
        params["temperature"] = temperature
    if max_tokens is not None:
        params["max_tokens"] = max_tokens
    return _rpc("tenzro_chatByIntent", params)

def record_route_outcome(model_id: str, cluster: int, outcome: str) -> dict:
    """Report how a routed call turned out.

    outcome: resolved | escalated | failed. In practice this carries
    `escalated` — the outcome only the caller knows, because it means the
    caller took the answer to a stronger model; the other two are recorded by
    `chat_by_intent` from the dispatch itself. Reporting is advisory:
    `retained` false means the node has no difficulty index wired, so the
    feedback was accepted and discarded.
    """
    return _rpc("tenzro_recordRouteOutcome", {
        "model_id": model_id,
        "cluster": cluster,
        "outcome": outcome,
    })

def route_difficulty_stats(model_id: str | None = None) -> dict:
    """Read the node's difficulty index: cluster count and prompts per cluster.

    With `model_id`, also returns that model's per-cluster outcome counters and
    error rate. An operator diagnostic — routing does not depend on it.
    `enabled` false means the node has no embedding model loaded and routes on
    declared metadata alone.
    """
    params = {}
    if model_id:
        params["model_id"] = model_id
    return _rpc("tenzro_routeDifficultyStats", params)

# ── Payments ──────────────────────────────────────────────────────

def create_payment_challenge(protocol: str, resource: str, amount: int,
                             asset: str = "TNZO",
                             recipient: str | None = None) -> dict:
    """Create a payment challenge (MPP, x402, or native).

    protocol: mpp | x402 | native
    resource: the resource path being paid for (e.g. /inference)
    amount: payment amount in smallest unit
    asset: TNZO, USDC, etc.
    recipient: payee address (required for x402/native)
    """
    params = {
        "protocol": protocol,
        "resource": resource,
        "amount": amount,
        "asset": asset,
    }
    if recipient:
        params["recipient"] = recipient
    return _rpc("tenzro_createPaymentChallenge", params)

def verify_payment(challenge_id: str, protocol: str, payer_did: str,
                   payer_address: str, amount: int, asset: str,
                   signature: str) -> dict:
    """Verify a payment credential and settle on-chain."""
    return _rpc("tenzro_verifyPayment", {
        "challenge_id": challenge_id,
        "protocol": protocol,
        "payer_did": payer_did,
        "payer_address": payer_address,
        "amount": amount,
        "asset": asset,
        "signature": signature,
    })

# ── Delegation ───────────────────────────────────────────────────

# ── Network Duties ──────────────────────────────────────────────

def list_duties() -> dict:
    """List open network duties: work the chain pays the first prover for."""
    return _rpc("tenzro_listDuties", {})

def get_duty(duty_id: str) -> dict:
    """Get one network duty by id."""
    return _rpc("tenzro_getDuty", {"duty_id": duty_id})

# ── Agent Template Marketplace ───────────────────────────────────

# ── Skills Registry ──────────────────────────────────────────────

def _skill_bundle(uri: str, sha256: str, size_bytes: int) -> dict:
    """Build a content-addressed artifact descriptor for a skill.

    uri is a tenzro://blob/<blake3-hex> locator (iroh-blobs verifies BLAKE3
    over the wire); sha256 is the publisher's declared canonical hash of the
    same bytes, which callers pin at invocation without trusting the transport
    that delivered them.
    """
    return {
        "uri": uri,
        "sha256": sha256.strip().lower(),
        "size_bytes": size_bytes,
    }

# ── Agent Spawning & Swarm ───────────────────────────────────────

# ── Cross-Chain Bridge ───────────────────────────────────────────

# ── Staking & Providers ─────────────────────────────────────────


def role_stakes(address: str | None = None) -> dict:
    """An account's stake per role and every role's network total."""
    return _rpc("tenzro_getRoleStakes", {"address": address} if address else {})

def provider_stats() -> dict:
    """Get provider statistics (served models, inferences, staking)."""
    return _rpc("tenzro_getProviderStats")

# ── Additional Verification ──────────────────────────────────────

def verify_transaction(tx_hash: str, sender_public_key: str,
                       signature: str) -> dict:
    """Verify a transaction signature via Web API."""
    return _api_post("/verify/transaction", {
        "tx_hash": tx_hash,
        "sender_public_key": sender_public_key,
        "signature": signature,
    })

def verify_settlement(settlement_id: str, proof_type: str,
                      proof_data: str) -> dict:
    """Verify a settlement receipt via Web API."""
    return _api_post("/verify/settlement", {
        "settlement_id": settlement_id,
        "proof_type": proof_type,
        "proof_data": proof_data,
    })

def verify_inference(request_id: str, model_id: str,
                     result_hash: str) -> dict:
    """Verify an inference result via Web API."""
    return _api_post("/verify/inference", {
        "request_id": request_id,
        "model_id": model_id,
        "result_hash": result_hash,
    })

# ── NFT Collections ──────────────────────────────────────────────

# ── Bridge (governed routes) ─────────────────────────────────────

def list_bridge_routes() -> dict:
    """List every governed bridge route with caps, epoch usage, supply and breaker state."""
    return _rpc("tenzro_listBridgeRoutes", {})

def get_bridge_route(adapter: str, source_chain: str) -> dict:
    """Get one governed bridge route by transport (ccip, ibc, deposit or contract) and external chain."""
    return _rpc("tenzro_getBridgeRoute", {"adapter": adapter, "source_chain": source_chain})


# ── ERC-3643 Compliance ─────────────────────────────────────────

# ── Events & Webhooks ────────────────────────────────────────────

def get_events(filter: dict | None = None, from_cursor: str | None = None,
               limit: int = 100, completeness: bool = False,
               anchor_index: int | None = None) -> dict:
    """Get the chain's events after a cursor, each with its proof.

    filter: optional event filter (e.g. {"event_types": ["log"], "addresses": ["0x.."]})
    from_cursor: optional cursor (height:tx_index:event_index) to resume after
    limit: max events to return (default 100)
    completeness: also return the proof that the page left out nothing the
        filter selects (block-index entries of every block it covered)
    anchor_index: checkpoint every proof ends at (default: latest certified)
    """
    params: dict = {"limit": limit}
    if filter:
        params["filter"] = filter
    if from_cursor:
        params["from_cursor"] = from_cursor
    if completeness:
        params["completeness"] = True
    if anchor_index is not None:
        params["anchor_index"] = anchor_index
    return _rpc("tenzro_queryEvents", params)


# ── Beacon, DA retention, fee markets ─────────


def get_beacon(round_: int | None = None, at_ms: int | None = None) -> dict:
    """The randomness beacon's head, the value at `round_`, or the first
    value at or after `at_ms`."""
    params: dict = {}
    if round_ is not None:
        params["round"] = round_
    if at_ms is not None:
        params["at_ms"] = at_ms
    return _rpc("tenzro_getBeacon", params)


def get_da_object(commitment: str) -> dict:
    """A data-availability object as chain state records it, with its expiry."""
    return _rpc("tenzro_getDaObject", {"commitment": commitment})


def get_da_retention() -> dict:
    """Retention per class (audit never under 183 days), live and expired totals."""
    return _rpc("tenzro_getDaRetention", {})


def get_fee_market() -> dict:
    """The base fee of every resource market: compute, state growth,
    bandwidth, proof, each with its per-block target."""
    return _rpc("tenzro_getFeeMarket", {})


def get_event_status() -> dict:
    """Get the current event stream status (latest sequence, lag, etc.)."""
    return _rpc("tenzro_eventStatus")

# ── SLA Fault Detector ──────────────────────────────────────────

def sla_issue_probe(provider_did: str, epoch: int, round_: int,
                    deadline_ms: int) -> dict:
    """Issue a VRF-bound liveness probe to a provider DID.

    Validator-only. Computes a VRF output over (provider_did, epoch,
    round), registers the probe in the validator's outstanding-probe
    map, and broadcasts it on the `tenzro/sla` gossip topic.

    On a non-validator node this returns JSON-RPC error
    `-32000 SlaManager not initialized`.

    provider_did: DID of the ModelProvider / TeeProvider being probed
    epoch: validator epoch the probe is issued in
    round_: probe round within the epoch
    deadline_ms: Unix-millisecond timestamp by which the provider must
        respond before the probe is considered missed
    """
    return _rpc("tenzro_slaIssueProbe", {
        "provider_did": provider_did,
        "epoch": epoch,
        "round": round_,
        "deadline_ms": deadline_ms,
    })

def sla_list_outstanding_probes() -> dict:
    """List every in-flight probe awaiting a response from any
    provider, regardless of issuer. Used by operators to spot probes
    whose `deadline_ms` has already elapsed without a matching
    response.
    """
    return _rpc("tenzro_slaListOutstandingProbes")

def sla_get_params() -> dict:
    """Read the SLA parameters.

    Returns:
        - unavailable_penalty_wei: what a frozen unavailable verdict takes
          from the provider's compute bond into the insurance pool (decimal
          string)
        - vrf_pubkey: 0x-prefixed hex of this validator's VRF public
          key
    """
    return _rpc("tenzro_slaGetParams")

# ── Snapshot (State Sync) ───────────────────────────────────────

def list_snapshots() -> dict:
    """List the snapshots this node holds and the iroh endpoint it serves
    their data from. The data itself (anchor chain and state buckets) is
    fetched over the node's iroh state-sync protocol, not over JSON-RPC.

    Returns: { "snapshots": [ {height, state_root, manifest_blob, buckets} ],
    "endpoint_id" }
    """
    return _rpc("tenzro_listSnapshots")

def get_snapshot_manifest(height: int) -> dict:
    """Fetch the manifest for the snapshot at `height`.

    Returns the node's JSON-RPC error `-32004 no snapshot at height` if
    no snapshot exists at that height.

    Returns: { "height", "state_root", "anchor_chain", "buckets": [...] }
    """
    return _rpc("tenzro_getSnapshotManifest", {"height": int(height)})

# ── EIP-7702 (Set EOA Account Code) ─────────────────────────────

# ── Permit2 (SignatureTransfer) ─────────────────────────────────

def permit2_verify_and_consume(chain_id: int, owner: str, token: str,
                               amount: str, spender: str, nonce: str,
                               deadline: int, signature: str,
                               witness: str | None = None,
                               witness_type_string: str | None = None) -> dict:
    """Atomically verify a signed Permit2 message and consume its
    (owner, nonce) bitmap slot."""
    params = {
        "chain_id": int(chain_id),
        "owner": owner,
        "token": token,
        "amount": str(amount),
        "spender": spender,
        "nonce": str(nonce),
        "deadline": int(deadline),
        "signature": signature,
    }
    if witness:
        params["witness"] = witness
    if witness_type_string:
        params["witness_type_string"] = witness_type_string
    return _rpc("tenzro_permit2VerifyAndConsume", params)

def permit2_nonce_used(owner: str, nonce: str) -> dict:
    """Check whether a (owner, nonce) slot has been consumed."""
    return _rpc("tenzro_permit2NonceUsed", {"owner": owner, "nonce": str(nonce)})








# ── CAIP discovery (ChainAgnostic/namespaces#184) ───────────────

# ── Tools Registry ──────────────────────────────────────────────

# ── Skills Registry (Extended) ──────────────────────────────────

# ── Agent Template Marketplace (Extended) ───────────────────────

# ── Agent Management (Extended) ────────────────────────────────

def discover_models(query: str | None = None, category: str | None = None) -> dict:
    """Discover AI models available on the network.

    query: optional search query
    category: optional category filter
    """
    params = {}
    if query:
        params["query"] = query
    if category:
        params["category"] = category
    return _rpc("tenzro_discoverModels", params)

def get_agent_terms(agent_did: str) -> dict:
    """An agent's full consensus Terms, its root kind (passkey or machine),
    status, and spend today and this hour against each limit.

    agent_did: the agent's DID

    Returns `{agent_did, root_kind, status, version, approval_digest,
    updated_at_ms, terms, spent}`, or None when it has no Terms on chain.
    """
    return _rpc("tenzro_getAgentTerms", {"agent_did": agent_did})

# ── Identity (Extended) ─────────────────────────────────────────

def register_machine_identity(controller_did: str,
                               public_key: str,
                               capabilities: list,
                               did_envelope: str) -> dict:
    """Register a machine identity under a controller DID.

    controller_did: the DID that controls this machine
    public_key: the machine's P-256 public key (hex x || y) from its TPM or
        Secure Enclave
    capabilities: list of machine capabilities
    did_envelope: the controller's DID envelope (hex) over exactly these
        fields, made on the controller's own device (a Tenzro SDK's
        withRequestEnvelope / with_request_envelope, or
        `tenzro identity register-machine --request-out`); the node refuses a
        machine registration its controller did not sign
    """
    return _rpc("tenzro_registerMachineIdentity", {
        "controller_did": controller_did,
        "public_key": public_key,
        "capabilities": capabilities,
        "did_envelope": did_envelope,
    })

def list_identities(identity_type: str | None = None) -> dict:
    """List all registered identities on the node.

    identity_type: optional filter — human | machine | all
    """
    params = {}
    if identity_type and identity_type != "all":
        params["identity_type"] = identity_type
    return _rpc("tenzro_listIdentities", [params])

# ── Network & Node (Extended) ──────────────────────────────────

def peer_count() -> dict:
    """Get the number of connected peers."""
    return _rpc("tenzro_peerCount")

def syncing() -> dict:
    """Get the sync status of the node."""
    return _rpc("tenzro_syncing")

def get_hardware_profile() -> dict:
    """Get the hardware profile of the node (CPU, RAM, GPU, TEE)."""
    return _rpc("tenzro_getHardwareProfile")

def get_finalized_block() -> dict:
    """Get the latest finalized block."""
    return _rpc("tenzro_getFinalizedBlock")

def export_config() -> dict:
    """Export the node configuration."""
    return _rpc("tenzro_exportConfig")

# ── Transaction (Extended) ─────────────────────────────────────

def get_transaction(tx_hash: str) -> dict:
    """Get transaction details by hash.

    tx_hash: 0x-prefixed hex transaction hash
    """
    return _rpc("tenzro_getTransaction", {"hash": tx_hash})

def get_nonce(address: str) -> dict:
    """Get the nonce (transaction count) for an address.

    address: 0x-prefixed hex address
    """
    return _rpc("tenzro_getNonce", {"address": address})

def get_transaction_history(address: str, limit: int = 50) -> dict:
    """Get transaction history for an address.

    address: 0x-prefixed hex address
    limit: max transactions to return
    """
    return _rpc("tenzro_getTransactionHistory", {
        "address": address, "limit": limit,
    })

# ── Settlement (Extended) ──────────────────────────────────────

def settle(payee: str, amount: str, payment: dict, app_id: str | None = None) -> dict:
    """Settle on the ledger with the payer's own signed authorization.

    payment: {payer, payment_id, authorization}, the payer's PaymentAuthorization
    naming ``payee`` and a ceiling of at least ``amount``.
    """
    params = {"payee": payee, "amount": amount, "payment": payment}
    if app_id is not None:
        params["app_id"] = app_id
    return _rpc("tenzro_settle", params)

def _release_conditions_payload(kind: str) -> Any:
    """Map a short release-condition keyword to the on-chain ReleaseConditions enum payload."""
    k = (kind or "timeout").lower()
    if k == "timeout":
        return "Timeout"
    if k in ("provider", "provider_signature"):
        return "ProviderSignature"
    if k in ("consumer", "consumer_signature"):
        return "ConsumerSignature"
    if k in ("both", "both_signatures"):
        return "BothSignatures"
    if k == "custom":
        return {"Custom": {"condition": ""}}
    raise ValueError(
        f"unsupported release condition '{kind}': use timeout|provider|consumer|both|custom"
    )

def _read_quantity(what: str, method: str, params: Any) -> int:
    """Read a hex quantity a transaction is signed over (nonce, chain id).

    Never substitutes a default: a failed call or an answer that is not a hex
    quantity raises, since a transaction signed over a guessed value is
    refused by the network.
    """
    try:
        result = _rpc(method, params)
    except Exception as e:
        raise RuntimeError(f"could not read the {what} from {RPC_URL}: {e}") from e
    if isinstance(result, str) and result.startswith("0x"):
        try:
            return int(result, 16)
        except ValueError:
            pass
    raise RuntimeError(f"could not read the {what} from {RPC_URL}: {result!r}")

def get_escrow(escrow_id_hex: str) -> dict:
    """Inspect an escrow record by its 32-byte id (hex)."""
    eid = escrow_id_hex if escrow_id_hex.startswith("0x") else "0x" + escrow_id_hex
    return _rpc("tenzro_getEscrow", {"escrow_id": eid})

def open_payment_channel(party_a: str, party_b: str,
                         deposit_wei: int) -> dict:
    """Open a micropayment channel between two parties.

    party_a: first party address
    party_b: second party address
    deposit_wei: initial deposit in wei
    """
    return _rpc("tenzro_openPaymentChannel", {
        "party_a": party_a,
        "party_b": party_b,
        "deposit": deposit_wei,
    })

def close_payment_channel(channel_id: str) -> dict:
    """Close a micropayment channel and settle on-chain.

    channel_id: channel to close
    """
    return _rpc("tenzro_closePaymentChannel", {"channel_id": channel_id})

# ── Model Management (Extended) ────────────────────────────────

def inference_request(model_id: str, input_text: str,
                      max_tokens: int = 512,
                      temperature: float = 0.7) -> dict:
    """Send an inference request to a model.

    model_id: model to run inference on
    input_text: input prompt or text
    max_tokens: maximum tokens to generate
    temperature: sampling temperature
    """
    return _rpc("tenzro_inferenceRequest", {
        "model_id": model_id,
        "input": input_text,
        "max_tokens": max_tokens,
        "temperature": temperature,
    })

def register_model_endpoint(model_id: str, api_url: str,
                            mcp_url: str | None = None) -> dict:
    """Register a model service endpoint.

    model_id: model ID being served
    api_url: API endpoint URL
    mcp_url: optional MCP endpoint URL
    """
    params = {"model_id": model_id, "api_url": api_url}
    if mcp_url:
        params["mcp_url"] = mcp_url
    return _rpc("tenzro_registerModelEndpoint", params)

def get_model_endpoint(instance_id: str) -> dict:
    """Get details of a specific model endpoint.

    instance_id: model instance/endpoint ID
    """
    return _rpc("tenzro_getModelEndpoint", {"instance_id": instance_id})

def unregister_model_endpoint(instance_id: str) -> dict:
    """Unregister a model service endpoint.

    instance_id: model instance/endpoint ID to remove
    """
    return _rpc("tenzro_unregisterModelEndpoint", {"instance_id": instance_id})

def get_model_provenance(name_or_root: str, file: str | None = None) -> dict:
    """Get a model's provenance.

    name_or_root: a model name (a Hub repository such as ``owner/name``, or a
        model id outside the catalog) or a manifest root (64-hex)
    file: optional path in the model; each manifest then carries that
        file's entry and Merkle inclusion proof

    Returns the model's content-addressed manifests (per-file SHA-256 and
    BLAKE3 under a BLAKE3 Merkle root), the origins that observed each one,
    and whether independent origins agree (``verified``). Loads are checked
    against the verified manifest.
    """
    is_root = len(name_or_root) == 64 and all(c in "0123456789abcdef" for c in name_or_root)
    params: dict = {"root": name_or_root} if is_root else {"name": name_or_root}
    if file:
        params["file"] = file
    return _rpc("tenzro_getModelProvenance", params)

def submit_trust_record(record: dict) -> dict:
    """Submit a signed trust record.

    record: a credential, revocation, operator policy, model
        manifest, origin attestation or policy-violation proof, signed by its
        author's hardware key or passkey (a manifest is content-addressed)

    Every node re-verifies the record before storing it. Certifications and
    KYC are issued this way by any issuer; relying parties choose which
    issuers they recognise.
    """
    return _rpc("tenzro_submitTrustRecord", {"record": record})

def serve_model(model_id: str, force_cluster: bool = False,
                force_single: bool = False, visibility: str | None = None) -> dict:
    """Start serving a model for inference.

    model_id: model to serve
    force_cluster: split across the LAN cluster even when the model fits one host
    force_single: never form a cluster; serve single-host
    visibility: "public", "gated" or "private" for this model; omitted, the
        model follows the node's visibility

    When the model is too large for one host the node auto-clusters: it reads
    the GGUF header for shape, discovers LAN members from gossip, and runs a
    layer-wise pipeline across them. No options are required for that path.
    """
    params = {"model_id": model_id}
    if visibility is not None:
        params["visibility"] = visibility
    if force_cluster:
        params["user_forced"] = True
    if force_single:
        params["force_single"] = True
    return _rpc("tenzro_serveModel", params)

def stop_model(model_id: str) -> dict:
    """Stop serving a model.

    model_id: model to stop
    """
    return _rpc("tenzro_stopModel", {"model_id": model_id})

def delete_model(model_id: str) -> dict:
    """Delete a downloaded model.

    model_id: model to delete
    """
    return _rpc("tenzro_deleteModel", {"model_id": model_id})

# ── Governance ─────────────────────────────────────────────────

def list_proposals(kind: str | None = None, limit: int = 20, before: int | None = None) -> dict:
    """List on-chain governance proposals, newest first.

    kind: keep one action kind, e.g. policy_update, parameter_change, treasury_grant
    before: continue from a previous page's `next`
    """
    return _rpc("tenzro_listProposals", {"limit": limit, "before": before, "kind": kind})


def get_voting_power(address: str) -> dict:
    """Get the bonded stake an address votes with, and the network total.

    address: 0x-prefixed hex address
    """
    return _rpc("tenzro_getVotingPower", {"address": address})

# ── Provider Management (Extended) ─────────────────────────────

def set_role(role: str) -> dict:
    """Set the node role.

    role: Validator | ModelProvider | TeeProvider | LightClient
    """
    return _rpc("tenzro_setRole", {"role": role})

def set_provider_pricing(pricing: dict) -> dict:
    """Set provider pricing configuration.

    pricing: dict with model pricing per token/request
    """
    return _rpc("tenzro_setProviderPricing", pricing)

def get_provider_pricing() -> dict:
    """Get the current provider pricing configuration."""
    return _rpc("tenzro_getProviderPricing")

def list_providers(provider_type: str | None = None, cursor: str | None = None) -> dict:
    """One page of the providers discovered via gossip: {providers, next_cursor}.

    provider_type: optional filter — ai | tee | storage | compute |
                   database | cloud | general.
    cursor: the next_cursor of the page before.
    """
    params = {}
    if provider_type:
        params["provider_type"] = provider_type
    if cursor:
        params["cursor"] = cursor
    return _rpc("tenzro_listProviders", params)

# ── EVM Compatibility ──────────────────────────────────────────

def eth_block_number() -> dict:
    """Get the current block number (EVM-compatible)."""
    result = _rpc("eth_blockNumber")
    if isinstance(result, str):
        return {"block_number": int(result, 16), "hex": result}
    return result

def eth_get_balance(address: str, block: str = "latest") -> dict:
    """Get balance via EVM-compatible method.

    address: 0x-prefixed hex address
    block: block number or "latest"
    """
    return _rpc("eth_getBalance", [address, block])

def eth_get_transaction_count(address: str,
                               block: str = "latest") -> dict:
    """Get the transaction count (nonce) for an address.

    address: 0x-prefixed hex address
    block: block number or "latest"
    """
    return _rpc("eth_getTransactionCount", [address, block])

def eth_gas_price() -> dict:
    """Get the current effective gas price (base fee + suggested priority tip).

    Tracks the EIP-1559 fee market — value adjusts ±12.5% per block based on
    parent gas usage vs. the 15M target.
    """
    return _rpc("eth_gasPrice")

def eth_max_priority_fee_per_gas() -> dict:
    """Get the suggested EIP-1559 priority fee (tip) in wei.

    Use this to fill `maxPriorityFeePerGas` on a Type-2 transaction. Derive the
    base-fee portion from `eth_fee_history()` or the parent block's
    `baseFeePerGas` field.
    """
    return _rpc("eth_maxPriorityFeePerGas")

def eth_fee_history(block_count: int = 10,
                    newest_block: str = "latest",
                    reward_percentiles: list | None = None) -> dict:
    """Get base-fee history and gas-usage ratios over the last N blocks.

    block_count: how many recent blocks to include (1..=1024).
    newest_block: hex height or "latest".
    reward_percentiles: optional list of tip percentiles (e.g. [25, 50, 75]).

    Returns `baseFeePerGas` of length `block_count + 1` (the trailing entry is
    the predicted base fee for the next block, suitable as the floor of a
    Type-2 transaction's `maxFeePerGas`), `gasUsedRatio`, and per-block tip
    percentiles when requested.
    """
    percentiles = reward_percentiles if reward_percentiles is not None else []
    return _rpc("eth_feeHistory", [hex(block_count), newest_block, percentiles])

def eth_estimate_gas(tx: dict) -> dict:
    """Estimate gas for a transaction.

    tx: transaction object with from, to, value, data fields
    """
    return _rpc("eth_estimateGas", [tx])

def eth_call(tx: dict, block: str = "latest") -> dict:
    """Execute a read-only contract call.

    tx: transaction object with to, data fields
    block: block number or "latest"
    """
    return _rpc("eth_call", [tx, block])

def eth_get_code(address: str, block: str = "latest") -> dict:
    """Get the bytecode at an address.

    address: contract address
    block: block number or "latest"
    """
    return _rpc("eth_getCode", [address, block])

def eth_get_storage_at(address: str, position: str,
                       block: str = "latest") -> dict:
    """Get storage value at a position.

    address: contract address
    position: storage slot (hex)
    block: block number or "latest"
    """
    return _rpc("eth_getStorageAt", [address, position, block])

def eth_get_logs(filter_obj: dict) -> dict:
    """Get logs matching a filter.

    filter_obj: dict with fromBlock, toBlock, address, topics fields
    """
    return _rpc("eth_getLogs", [filter_obj])

def eth_get_transaction_receipt(tx_hash: str) -> dict:
    """Get a transaction receipt by hash.

    tx_hash: 0x-prefixed hex transaction hash
    """
    return _rpc("eth_getTransactionReceipt", [tx_hash])

def eth_get_block_by_number(block: str = "latest",
                            full_txs: bool = False) -> dict:
    """Get a block by number.

    block: block number (hex) or "latest", "earliest", "pending"
    full_txs: if True, return full transaction objects
    """
    return _rpc("eth_getBlockByNumber", [block, full_txs])

def eth_get_block_by_hash(block_hash: str,
                          full_txs: bool = False) -> dict:
    """Get a block by hash.

    block_hash: 0x-prefixed hex block hash
    full_txs: if True, return full transaction objects
    """
    return _rpc("eth_getBlockByHash", [block_hash, full_txs])

def eth_get_transaction_by_block_number_and_index(
        block: str, index: str) -> dict:
    """Get a transaction by block number and index.

    block: block number (hex) or "latest"
    index: transaction index (hex)
    """
    return _rpc("eth_getTransactionByBlockNumberAndIndex", [block, index])

def eth_syncing() -> dict:
    """Get the sync status (EVM-compatible)."""
    return _rpc("eth_syncing")

def eth_accounts() -> dict:
    """List accounts (EVM-compatible). Returns empty list."""
    return _rpc("eth_accounts")

def net_peer_count() -> dict:
    """Get peer count (EVM-compatible)."""
    return _rpc("net_peerCount")

def net_version() -> dict:
    """Get network version (EVM-compatible)."""
    return _rpc("net_version")

def net_listening() -> dict:
    """Check if node is listening for connections."""
    return _rpc("net_listening")

# ══════════════════════════════════════════════════════════════════
# Ecosystem MCP Tools
# ══════════════════════════════════════════════════════════════════

# ── Chainlink (via chainlink-mcp.tenzro.com) ─────────────────

def chainlink_get_price(pair: str = "ETH/USD") -> dict:
    """Get price from Chainlink AggregatorV3 data feed.

    pair: price pair (e.g. "ETH/USD", "BTC/USD")
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "chainlink_get_price", {
        "pair": pair,
    })

def chainlink_list_feeds(chain: str = "ethereum") -> dict:
    """List available Chainlink price feeds.

    chain: chain name (default "ethereum")
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "chainlink_list_feeds", {
        "chain": chain,
    })

def vrf_request_random(num_words: int = 1) -> dict:
    """Build VRF v2.5 requestRandomWords() calldata.

    num_words: number of random words to request
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "vrf_request_random", {
        "num_words": num_words,
    })

def vrf_get_subscription(sub_id: str) -> dict:
    """Get VRF subscription details.

    sub_id: subscription ID
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "vrf_get_subscription", {
        "sub_id": sub_id,
    })

def ds_get_report(feed_id: str) -> dict:
    """Get a Chainlink Data Streams report.

    feed_id: data stream feed ID
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "ds_get_report", {
        "feed_id": feed_id,
    })

def ds_list_feeds() -> dict:
    """List available Chainlink Data Streams feeds."""
    return _mcp_tool_call(CHAINLINK_MCP_URL, "ds_list_feeds", {})

def por_get_reserve(feed_address: str) -> dict:
    """Get Proof of Reserve data from a Chainlink PoR feed.

    feed_address: PoR feed contract address
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "por_get_reserve", {
        "feed_address": feed_address,
    })

def por_list_feeds() -> dict:
    """List available Chainlink Proof of Reserve feeds."""
    return _mcp_tool_call(CHAINLINK_MCP_URL, "por_list_feeds", {})

# ── Crypto ────────────────────────────────────────────────────────

def verify_signature(public_key: str, message_hex: str,
                     signature_hex: str) -> dict:
    """Verify a cryptographic signature against a public key."""
    return _rpc("tenzro_verifySignature", {
        "public_key": public_key,
        "message_hex": message_hex,
        "signature_hex": signature_hex,
    })

# ── TEE ──────────────────────────────────────────────────────────

def detect_tee() -> dict:
    """Detect available TEE hardware on this node."""
    return _rpc("tenzro_detectTee", {})

def get_tee_attestation(tee_type: str | None = None) -> dict:
    """Generate a TEE attestation report."""
    params = {}
    if tee_type:
        params["tee_type"] = tee_type
    return _rpc("tenzro_getTeeAttestation", params)

def list_tee_providers() -> dict:
    """List all registered TEE providers on the network."""
    return _rpc("tenzro_listTeeProviders", {})

# ── ZK ───────────────────────────────────────────────────────────

def create_zk_proof(circuit_id: str, witness: dict) -> dict:
    """Create a Plonky3 STARK proof over KoalaBear.

    circuit_id: "settlement" (an identity proof is made by the key holder,
    never by a node)
    witness: {"witness": 32-byte hex service result, "binding": 32-byte hex
    request binding}
    """
    params = {"circuit_id": circuit_id, **witness}
    return _rpc("tenzro_createZkProof", params)

def list_zk_circuits() -> dict:
    """List all available ZK circuits."""
    return _rpc("tenzro_listCircuits", {})

# ── App registry + settlement authorization ──────────────────────

# ── Contract ABI ─────────────────────────────────────────────────

# ── OAuth 2.1 + DPoP Onboarding ──────────────────────────────────

def onboard_human(display_name, credential_id, public_key, authorization,
                  dpop_jkt=None):
    """Onboard a new human — provisions a TDIP DID + permissionless wallet rooted
    in a passkey, returns a DPoP-bound OAuth 2.1 access token.

    ``authorization`` is the proof that the caller holds the passkey: its
    assertion over the ``webauthn_challenge`` of a
    ``tenzro_createCustodyChallenge`` challenge with operation
    ``enroll_passkey``, ``account_address`` the P-256 public key (x || y) and
    ``target_hex`` the credential id."""
    params = {
        "display_name": display_name,
        "credential_id": credential_id,
        "public_key": public_key,
        "authorization": authorization,
    }
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    return _rpc("tenzro_onboardHuman", params)

def onboard_delegated_agent(controller_did, capabilities, delegation_scope, dpop_jkt=None):
    """Onboard an agent that acts on behalf of `controller_did`. Inherits the
    controller's act-chain; revoking the controller cascades."""
    if isinstance(capabilities, str):
        capabilities = json.loads(capabilities)
    if isinstance(delegation_scope, str):
        delegation_scope = json.loads(delegation_scope)
    params = {
        "controller_did": controller_did,
        "capabilities": capabilities,
        "delegation_scope": delegation_scope,
    }
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    return _rpc("tenzro_onboardDelegatedAgent", params)

def onboard_autonomous_agent(device_public_key, machine_id, dpop_jkt=None):
    """Onboard a fully autonomous agent rooted in its secure element. Its
    bond must already be locked on chain: an active PostAgentBond of at
    least 1 TNZO for the DID the device key derives."""
    params = {"device_public_key": device_public_key, "machine_id": machine_id}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    return _rpc("tenzro_onboardAutonomousAgent", params)

def refresh_token(refresh_token_value, dpop_proof):
    """Exchange an opaque refresh token for a fresh access JWT.

    Mirrors OAuth 2.1 ``grant_type=refresh_token``. ``dpop_proof`` is a
    DPoP proof over this request from the key the refresh token is bound to
    (``tenzro auth dpop-proof``); the request carries no access token. Each
    refresh token is good for one exchange: keep the ``refresh_token`` the
    answer carries for the next one.
    """
    global _request_id
    _request_id += 1
    payload = {
        "jsonrpc": "2.0",
        "method": "tenzro_refreshToken",
        "params": {"refresh_token": refresh_token_value},
        "id": _request_id,
    }
    headers = {"Content-Type": "application/json", "DPoP": dpop_proof}
    resp = requests.post(RPC_URL, json=payload, headers=headers, timeout=RPC_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        return {"error": data["error"]}
    return data.get("result", {})

def revoke_jwt(jti, did_envelope, reason="revoked"):
    """Revoke a single JWT by its `jti` claim.

    did_envelope proves control of the token's bearer DID or of the
    controller DID that authorized it, bound to method `tenzro_revokeJwt`
    with the jti as the params hash. A jti travels in every audit row, so
    knowing one is not authority to destroy the token.
    """
    return _rpc("tenzro_revokeJwt", {
        "jti": jti,
        "did_envelope": did_envelope,
        "reason": reason,
    })

def revoke_did(did, did_envelope, reason="revoked"):
    """Revoke an entire identity by DID — cascades through the act-chain.

    Requires both the operator admin token on the transport and a
    did_envelope from the DID itself or, for a machine, its controller,
    bound to method `tenzro_revokeIdentity` with the DID string as the params
    hash. The revocation is gossiped network-wide, so neither the operator
    nor the owner gets to make that call alone.
    """
    return _rpc("tenzro_revokeIdentity", {
        "did": did,
        "did_envelope": did_envelope,
        "reason": reason,
    })

# ── Passkey-first wallet custody (WebAuthn P-256) ──

def enroll_passkey(passkey_public_key_hex, credential_id_hex, authorization,
                   display_name=None, salt=0):
    """Enroll a passkey-bound smart account.

    Consumes a WebAuthn registration credential (P-256 public key + opaque
    credential id) with ``authorization``, the passkey's assertion over the
    ``webauthn_challenge`` of an ``enroll_passkey`` custody challenge, creates a
    TDIP human identity, deploys a smart account via the shared AccountFactory,
    and installs the WebAuthnValidator as the primary signer. The signing key
    never leaves the user's hardware secure element.
    """
    params = {
        "passkey_public_key_hex": passkey_public_key_hex,
        "credential_id_hex": credential_id_hex,
        "authorization": authorization,
        "salt": salt,
    }
    if display_name:
        params["display_name"] = display_name
    return _rpc("tenzro_enrollPasskey", params)

def get_keystore(account, anchor=None):
    """A passkey account's keystore from consensus state: its linked passkeys
    (each with the wallet provider's relying party), policy, recovery signers
    and its commitment. Linking, unlinking and recovery are KeystoreUpdate
    transactions the account's devices approve."""
    params = {"account": account}
    if anchor:
        params["anchor"] = anchor
    return _rpc("tenzro_getKeystore", params)

def resolve_credential(credential_id, rp_id=None):
    """The accounts whose keystore links the passkey with this credential id."""
    params = {"credential_id": credential_id}
    if rp_id:
        params["rp_id"] = rp_id
    return _rpc("tenzro_resolveCredential", params)

# ── Browser-launch passkey auth sessions (gcloud-style device flow) ──

def create_passkey_session(kind, display_name=None, salt=0, account_address=None, label=None,
                           op_hash_hex=None, ml_dsa_signature_hex=None):
    """Create a pending browser-launch passkey ceremony session.

    `kind` is "enroll" (new account), "add" (device credential on an existing
    account), or "sign" (verify an assertion over an op hash). Returns a
    session id and the node-served /auth/passkey URL to open in a browser;
    poll `get_passkey_session` until the session reaches a terminal status.
    """
    params = {"kind": kind, "salt": salt}
    if display_name:
        params["display_name"] = display_name
    if account_address:
        params["account_address"] = account_address
    if label:
        params["label"] = label
    if op_hash_hex:
        params["op_hash_hex"] = op_hash_hex
    if ml_dsa_signature_hex:
        params["ml_dsa_signature_hex"] = ml_dsa_signature_hex
    return _rpc("tenzro_createPasskeySession", params)

def get_passkey_session(session_id):
    """Poll a browser-launch passkey ceremony session by id.

    Returns the session kind, status (pending/in_flight/completed/failed/
    expired), and — once terminal — the handler result or error.
    """
    return _rpc("tenzro_getPasskeySession", {"session_id": session_id})

def forget_identity(did):
    """TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously
    revoked identity from the registry and persistent storage. The DID
    must already be in `Revoked` status — call `revoke_did` first, allow
    cascading revocation to propagate, then call this. Distinct from
    `revoke_did` which is a logical delete."""
    return _rpc("tenzro_forgetIdentity", {"did": did})

def exchange_token(
    subject_token,
    child_bearer_did,
    child_dpop_jkt,
    requested_rar=None,
    requested_aap_capabilities=None,
    requested_ttl_secs=None,
):
    """RFC 8693 OAuth 2.0 Token Exchange — mint a narrower child JWT.

    Exchanges ``subject_token`` (a parent JWT) for a child JWT bound to
    ``child_dpop_jkt`` (RFC 7638 thumbprint), with a strict subset of
    the parent's RAR grants and AAP capabilities. The child token's
    ``controller_did`` is set to the parent's ``sub``, extending the
    act-chain by one hop.

    Subset enforcement is performed by the AS — over-scoped requests
    are rejected with JSON-RPC error ``-32002``. Pass
    ``requested_ttl_secs=None`` to use the engine default (clamped to
    parent's remaining lifetime).
    """
    if isinstance(requested_rar, str):
        requested_rar = json.loads(requested_rar)
    if isinstance(requested_aap_capabilities, str):
        requested_aap_capabilities = json.loads(requested_aap_capabilities)
    params = {
        "subject_token": subject_token,
        "child_bearer_did": child_bearer_did,
        "child_dpop_jkt": child_dpop_jkt,
        "requested_rar": requested_rar or {},
        "requested_aap_capabilities": requested_aap_capabilities or [],
    }
    if requested_ttl_secs is not None:
        params["requested_ttl_secs"] = requested_ttl_secs
    return _rpc("tenzro_exchangeToken", params)

def introspect_token(token):
    """RFC 7662 OAuth 2.0 Token Introspection.

    Ask the AS whether ``token`` is currently active and, if so,
    return its full claim set (RAR ``authorization_details``, AAP
    ``aap_*`` claims, ``cnf``, ``controller_did``, etc.). Per
    RFC 7662 §2.2 a failed validation returns ``{"active": false}``
    with no other fields — the AS does not leak why the token is
    inactive.
    """
    return _rpc("tenzro_introspectToken", {"token": token})

def oauth_discovery():
    """RFC 8414 / RFC 9728 OAuth Authorization Server / Protected
    Resource Metadata.

    Returns the same metadata document published at
    ``GET /.well-known/openid-configuration``, augmented with AAP
    extensions: ``authorization_details_types_supported`` (8 RAR
    types), ``aap_claims_supported`` (7 AAP claims), and
    ``dpop_signing_alg_values_supported`` (``["EdDSA"]``).
    """
    return _rpc("tenzro_oauthDiscovery", None)

# ── AP2 (Agent Payments Protocol) ────────────────────────────────

def governance_get(kind: str, ident: str) -> dict:
    """Read a proposal, an enacted policy (ident = its kind) or a grant."""
    clean = ident[2:] if ident.startswith("0x") else ident
    method, params = {
        "proposal": ("tenzro_getProposal", {"proposal_id": clean}),
        "policy": ("tenzro_getPolicy", {"kind": ident}),
        "grant": ("tenzro_getGrant", {"grant_id": clean}),
    }[kind]
    return _rpc(method, params)

# ── ERC-8004 (Trustless Agents Registry — full Jan 2026 revision surface) ────

# -- Identity registry --------------------------------------------------

# -- Reputation registry ------------------------------------------------

# -- Validation registry -----------------------------------------------

# ── Iroh (Content-Addressed Transport) ────────────────────────────
#
# Wraps the tenzro_iroh_* JSON-RPC namespace. The same shared
# IrohBackedResolver backs the storage DA backend, model-weight peer fetch,
# and A2A-over-iroh.

def iroh_get_info() -> dict:
    """Return endpoint id, Pkarr relay, docs flag, and bound ALPNs."""
    return _rpc("tenzro_iroh_getInfo", {})

def iroh_get_endpoint_id() -> dict:
    """Return just the iroh EndpointId (z-base-32 + 32-byte hex)."""
    return _rpc("tenzro_iroh_getEndpointId", {})

def iroh_list_alpns() -> dict:
    """List ALPNs bound on the shared iroh router."""
    return _rpc("tenzro_iroh_listAlpns", {})

def iroh_publish_blob(data: bytes) -> dict:
    """Publish raw bytes as a tenzro://blob/<blake3-hex> URI.

    `data` is base64-encoded on the wire; the response includes
    `tenzro_uri`, `blake3_hex`, and `size_bytes`.
    """
    import base64
    b64 = base64.b64encode(data).decode("ascii")
    return _rpc("tenzro_iroh_publishBlob", {"bytes_b64": b64})

def iroh_fetch_blob(tenzro_uri: str) -> bytes:
    """Fetch a tenzro://{blob,model,receipt}/... URI to bytes.

    Returns the decoded payload (the base64 envelope on the wire is
    unwrapped here so callers get raw bytes back).
    """
    import base64
    resp = _rpc("tenzro_iroh_fetchBlob", {"tenzro_uri": tenzro_uri})
    return base64.b64decode(resp.get("bytes_b64", ""))

def iroh_resolve(tenzro_uri: str) -> bytes:
    """Alias for iroh_fetch_blob for code that thinks of the URI as a name."""
    return iroh_fetch_blob(tenzro_uri)

# ── App hosting (sites / functions / machines) ────────────────────
#
# Wraps the tenzro_site* / tenzro_function* / tenzro_machine* / lease
# JSON-RPC surface. Deploy a static site, a wasi:http function, or a
# Firecracker microVM and serve it under a public hostname
# (myapp.apps.tenzro.com) routed from the operator's ingress edge to any
# serving node over the tenzro/http ALPN. Content is uploaded as
# content-addressed blobs first (iroh_publish_blob); deploy calls
# reference each blob by hash.
#
# Mutations (publish / remove / set-alias / claim-domain …) are
# DID-owner authenticated: pass did_envelope=<signed envelope value>.
# The node verifies the envelope's did equals the owner_did.

def _with_env(params: dict, did_envelope: str | None) -> dict:
    """Attach the signed DID envelope to a mutation's params when supplied."""
    if did_envelope is not None:
        params = dict(params)
        params["did_envelope"] = did_envelope
    return params

# Static sites ---------------------------------------------------------

# Hostname aliases -----------------------------------------------------

# Ingress placement ----------------------------------------------------

# Custom domains -------------------------------------------------------

# Functions (wasi:http components) -------------------------------------

# Machines (Firecracker microVMs) --------------------------------------

# Placement leases -----------------------------------------------------

# ── Multi-modal inference ─────────────────────────────────────────
#
# Wraps the JSON-RPC surface added by Layer A. Each modality follows
# the same shape: list catalog (curated entries), list (loaded models),
# load/unload, and the inference verb itself.

# Forecast (timeseries) -------------------------------------------------

def list_forecast_catalog() -> dict:
    """List the curated timeseries forecast model catalog."""
    return _rpc("tenzro_listForecastCatalog", {})

def _routed(params: dict, verification: str | None, provider: str | None) -> dict:
    """Add the verification level (none, receipt, optimistic, tee) and the
    provider pin to a modality call. A model the node does not serve goes to
    a provider offering it; an optimistic answer may be re-executed on
    another provider and a mismatch refunds the caller."""
    if verification is not None:
        params["verification"] = verification
    if provider is not None:
        params["provider"] = provider
    return params


def forecast(model_id: str, history: list, horizon: int,
             quantiles: list | None = None,
             frequency_seconds: int | None = None,
             verification: str | None = None, provider: str | None = None) -> dict:
    """Run a probabilistic forecast. `history` is oldest-first observations."""
    params = {"model_id": model_id, "history": history, "horizon": horizon}
    if quantiles is not None:
        params["quantiles"] = quantiles
    if frequency_seconds is not None:
        params["frequency_seconds"] = frequency_seconds
    return _rpc("tenzro_forecast", _routed(params, verification, provider))

# Vision embeddings -----------------------------------------------------

def list_vision_catalog() -> dict:
    """List the curated vision encoder catalog."""
    return _rpc("tenzro_listVisionCatalog", {})

def vision_embed(model_id: str, image_b64: str,
                 normalize: bool = True,
                 verification: str | None = None, provider: str | None = None) -> dict:
    """Embed a base64-encoded image with the named vision encoder.

    Returns a dense embedding vector (e.g. 768-dim for DINOv3-base).
    """
    return _rpc("tenzro_imageEmbed", _routed({
        "model_id": model_id,
        "image_base64": image_b64,
        "normalize": normalize,
    }, verification, provider))

def vision_similarity(image_embedding: list, text_embedding: list) -> dict:
    """Pure cosine similarity between two embeddings.

    Pass two vectors of identical dimension — typically an image embedding
    from `vision_embed` and a text embedding from the matching text encoder
    (CLIP / SigLIP text tower). No model is loaded — pure math.
    """
    return _rpc("tenzro_imageTextSimilarity", {
        "image_embedding": image_embedding,
        "text_embedding": text_embedding,
    })

# Text embeddings -------------------------------------------------------

def list_text_embedding_catalog() -> dict:
    """List the curated text embedding catalog (Qwen3-Embedding, EmbeddingGemma, BGE-M3, ...)."""
    return _rpc("tenzro_listTextEmbeddingCatalog", {})

def text_embed(model_id: str, inputs: list,
               requested_dim: int | None = None,
               normalize: bool = False,
               verification: str | None = None, provider: str | None = None) -> dict:
    """Embed a batch of inputs; optional Matryoshka truncation.

    An input is a string, or a dict with `text`, `image` (base64) and/or
    `video` (base64 frames) embedded as one item; pictures and video need a
    vision-language embedder.
    """
    params = {"model_id": model_id, "inputs": inputs, "normalize": normalize}
    if requested_dim is not None:
        params["requested_dim"] = requested_dim
    return _rpc("tenzro_textEmbed", _routed(params, verification, provider))

# Segmentation ----------------------------------------------------------

def list_segmentation_catalog() -> dict:
    """List the curated prompt-driven segmentation catalog (SAM 2, EdgeSAM, MobileSAM).

    Text-promptable SAM 3 is a separate runtime with its own catalog —
    see `list_text_segmentation_catalog`.
    """
    return _rpc("tenzro_listSegmentationCatalog", {})

def segment(model_id: str, image_b64: str, prompts: list,
            verification: str | None = None, provider: str | None = None) -> dict:
    """Run promptable segmentation.

    Prompts are original-image pixel coordinates, either
    `{"type": "point", "x": .., "y": .., "is_foreground": true}` or
    `{"type": "box", "x0": .., "y0": .., "x1": .., "y1": ..}`.
    """
    return _rpc("tenzro_segment", _routed({
        "model_id": model_id,
        "image_base64": image_b64,
        "prompts": prompts,
    }, verification, provider))

# Text-promptable segmentation (SAM 3) ----------------------------------

def list_text_segmentation_catalog() -> dict:
    """List the curated open-vocabulary segmentation catalog (SAM 3 family)."""
    return _rpc("tenzro_listTextSegmentationCatalog", {})

def load_text_segmentation_model(model_id: str, visibility: str | None = None) -> dict:
    """Load a catalog SAM-3-family segmenter by `model_id`."""
    return _load_catalog_model("tenzro_loadTextSegmentationModel", model_id, visibility)

def unload_text_segmentation_model(model_id: str) -> dict:
    """Drop a registered text-promptable segmenter."""
    return _rpc("tenzro_unloadTextSegmentationModel", {"model_id": model_id})

def text_segment(model_id: str, image_b64: str, text_prompt: str,
                 box_prompt: dict | None = None,
                 score_threshold: float = 0.5,
                 verification: str | None = None, provider: str | None = None) -> dict:
    """Segment by free-text label (e.g. "dog", "sofa") — no click needed.

    Pass an empty `text_prompt` with a `box_prompt` of
    `{"cx": .., "cy": .., "w": .., "h": ..}` to run box-only mode.
    """
    params = {
        "model_id": model_id,
        "image_base64": image_b64,
        "text_prompt": text_prompt,
        "score_threshold": score_threshold,
    }
    if box_prompt is not None:
        params["box_prompt"] = box_prompt
    return _rpc("tenzro_textSegment", _routed(params, verification, provider))

# Detection -------------------------------------------------------------

def list_detection_catalog() -> dict:
    """List the curated detection catalog (RF-DETR, D-FINE)."""
    return _rpc("tenzro_listDetectionCatalog", {})

def detect(model_id: str, image_b64: str,
           score_threshold: float = 0.5,
           verification: str | None = None, provider: str | None = None) -> dict:
    """Run object detection on the given image."""
    return _rpc("tenzro_detect", _routed({
        "model_id": model_id,
        "image_base64": image_b64,
        "score_threshold": score_threshold,
    }, verification, provider))


# Rerank ----------------------------------------------------------------

def list_rerank_catalog() -> dict:
    """List the reranker catalog."""
    return _rpc("tenzro_listRerankCatalog", {})


def rerank(model_id: str, query: str | dict, documents: list,
           top_n: int | None = None, verification: str | None = None,
           provider: str | None = None) -> dict:
    """Score documents against a query, best first.

    The query and every document are a string, or a dict with `text`,
    `image` (base64) and/or `video` (base64 frames); pictures and video need
    a vision-language reranker. Billed per (query, document) pair.
    """
    return _rpc("tenzro_rerank", _routed({
        "model_id": model_id,
        "query": query,
        "documents": documents,
        "top_n": top_n,
    }, verification, provider))


# Speech synthesis -------------------------------------------------------

def speak(model_id: str, text: str, language: str | None = None,
          seed: int | None = None, verification: str | None = None,
          provider: str | None = None) -> dict:
    """Speak text with a loaded speech model; returns base64 WAV."""
    return _rpc("tenzro_speak", _routed({
        "model_id": model_id,
        "input": text,
        "language": language,
        "seed": seed,
    }, verification, provider))


# Audio (ASR) -----------------------------------------------------------

def list_audio_catalog() -> dict:
    """List the curated ASR catalog (Moonshine, Distil-Whisper, Whisper-turbo, Parakeet, Canary)."""
    return _rpc("tenzro_listAudioCatalog", {})

def transcribe(model_id: str, audio_b64: str, language: str | None = None,
               timestamps: bool = False,
               temperature: float | None = None,
               verification: str | None = None, provider: str | None = None) -> dict:
    """Transcribe a base64-encoded audio buffer (WAV/MP3/FLAC)."""
    params = {
        "model_id": model_id,
        "audio_base64": audio_b64,
        "timestamps": timestamps,
    }
    if language is not None:
        params["language"] = language
    if temperature is not None:
        params["temperature"] = temperature
    return _rpc("tenzro_transcribe", _routed(params, verification, provider))

# Video -----------------------------------------------------------------

def list_video_catalog() -> dict:
    """List the curated video encoder catalog (V-JEPA 2 ViT-L / ViT-H / ViT-g)."""
    return _rpc("tenzro_listVideoCatalog", {})

def transcribe_stream(model_id: str, pcm_chunks, sample_rate: int = 16000,
                      language: str | None = None,
                      verification: str | None = None):
    """Transcribe live audio as it is captured.

    `pcm_chunks` yields mono 16-bit little-endian PCM byte chunks (from a
    microphone, or a file read piece by piece). The node answers on the
    realtime transport with `partial` transcripts of the open segment and
    `final` segments committed at pauses (each billed by the second of
    audio and receipted), then `done`. Yields `{"event", "data"}` dicts.
    The node must serve the model.
    """
    import base64

    def lines():
        opening = {"model_id": model_id, "sample_rate": sample_rate,
                   "language": language, "verification": verification}
        yield (json.dumps(opening) + "\n").encode()
        for chunk in pcm_chunks:
            line = {"pcm_s16le_base64": base64.b64encode(chunk).decode()}
            yield (json.dumps(line) + "\n").encode()

    headers = {"Content-Type": "application/x-ndjson"}
    bearer = os.environ.get("TENZRO_BEARER_JWT")
    if bearer:
        headers["Authorization"] = f"DPoP {bearer}"
    dpop = os.environ.get("TENZRO_DPOP_PROOF")
    if dpop:
        headers["DPoP"] = dpop
    url = RPC_URL.rstrip("/") + "/tenzro/realtime/transcribe"
    with requests.post(url, data=lines(), headers=headers, stream=True,
                       timeout=RPC_TIMEOUT) as resp:
        resp.raise_for_status()
        event = None
        for raw in resp.iter_lines(decode_unicode=True):
            if raw.startswith("event:"):
                event = raw[len("event:"):].strip()
            elif raw.startswith("data:"):
                yield {"event": event, "data": json.loads(raw[len("data:"):].strip())}


def video_embed(model_id: str, video_b64: str, normalize: bool = False,
                frame_stride: int | None = None,
                verification: str | None = None, provider: str | None = None) -> dict:
    """Embed a base64-encoded video clip into one clip-level vector.

    The node extracts evenly-spaced frames, embeds each through the image
    encoder the clip encoder was registered over, and mean-pools.
    `frame_stride` replaces the even spacing with a fixed stride.
    """
    params = {
        "model_id": model_id,
        "video_base64": video_b64,
        "normalize": normalize,
    }
    if frame_stride is not None:
        params["frame_stride"] = frame_stride
    return _rpc("tenzro_videoEmbed", _routed(params, verification, provider))

# Multi-modal load / unload --------------------------------------------
#
# Symmetric load/unload pair per modality. Every catalog loader takes the
# same two parameters: the catalog `model_id` and an optional `visibility`
# ('public', 'gated' or 'private'; omitted follows the node). The node
# fetches and verifies the files the signed catalog entry names, takes every
# shape from the entry, and enforces its licence tier: it refuses with
# JSON-RPC -32010 when the operator has not accepted that entry's terms
# (started with `--accept-license <id>` or `--accept-non-commercial`).
# Those are node-operator startup flags, never client parameters.
# `list_models(loaded=True)` lists every loaded model of every type.

def _load_catalog_model(method: str, model_id: str, visibility: str | None) -> dict:
    params = {"model_id": model_id}
    if visibility is not None:
        params["visibility"] = visibility
    return _rpc(method, params)

def load_forecast_model(model_id: str, visibility: str | None = None) -> dict:
    """Load a catalog forecast (timeseries) model by `model_id`."""
    return _load_catalog_model("tenzro_loadForecastModel", model_id, visibility)

def unload_forecast_model(model_id: str) -> dict:
    """Drop a registered forecast model from the node."""
    return _rpc("tenzro_unloadForecastModel", {"model_id": model_id})

def load_vision_model(model_id: str, visibility: str | None = None) -> dict:
    """Load a catalog vision encoder (CLIP, SigLIP, DINO) by `model_id`."""
    return _load_catalog_model("tenzro_loadVisionModel", model_id, visibility)

def unload_vision_model(model_id: str) -> dict:
    """Drop a registered vision encoder."""
    return _rpc("tenzro_unloadVisionModel", {"model_id": model_id})

def load_text_embedding_model(model_id: str, visibility: str | None = None) -> dict:
    """Load a catalog text encoder by `model_id`."""
    return _load_catalog_model("tenzro_loadTextEmbeddingModel", model_id, visibility)

def unload_text_embedding_model(model_id: str) -> dict:
    """Drop a registered text encoder."""
    return _rpc("tenzro_unloadTextEmbeddingModel", {"model_id": model_id})

def load_segmentation_model(model_id: str, visibility: str | None = None) -> dict:
    """Load a catalog segmenter (SAM 2 / EdgeSAM / MobileSAM) by `model_id`."""
    return _load_catalog_model("tenzro_loadSegmentationModel", model_id, visibility)

def unload_segmentation_model(model_id: str) -> dict:
    """Drop a registered segmenter."""
    return _rpc("tenzro_unloadSegmentationModel", {"model_id": model_id})

def load_detection_model(model_id: str, visibility: str | None = None) -> dict:
    """Load a catalog detector (RF-DETR, D-FINE) by `model_id`."""
    return _load_catalog_model("tenzro_loadDetectionModel", model_id, visibility)

def unload_detection_model(model_id: str) -> dict:
    """Drop a registered detector."""
    return _rpc("tenzro_unloadDetectionModel", {"model_id": model_id})

def load_audio_model(model_id: str, visibility: str | None = None) -> dict:
    """Load a catalog speech-recognition model by `model_id`."""
    return _load_catalog_model("tenzro_loadAudioModel", model_id, visibility)

def unload_audio_model(model_id: str) -> dict:
    """Drop a registered ASR model."""
    return _rpc("tenzro_unloadAudioModel", {"model_id": model_id})

def load_video_model(model_id: str, vision_model_id: str,
                     num_frames: int | None = None,
                     visibility: str | None = None) -> dict:
    """Register a clip encoder over an already-loaded image encoder.

    Video embedding is frame-based: the node extracts `num_frames`
    evenly-spaced frames (default 8, clamped to 1..128), embeds each
    through the encoder named by `vision_model_id`, and mean-pools. Load
    that image encoder with `load_vision_model` first — an unloaded id is
    refused with JSON-RPC -32004.
    """
    params = {"model_id": model_id, "vision_model_id": vision_model_id}
    if num_frames is not None: params["num_frames"] = num_frames
    if visibility is not None: params["visibility"] = visibility
    return _rpc("tenzro_loadVideoModel", params)

def unload_video_model(model_id: str) -> dict:
    """Drop a registered video encoder."""
    return _rpc("tenzro_unloadVideoModel", {"model_id": model_id})

# Agent memory tier ----------------------------------------------------
#
# Every memory_* RPC requires DPoP+JWT bearer auth. Set TENZRO_BEARER_JWT
# and TENZRO_DPOP_PROOF in the environment before calling these helpers.
# The server matches the bearer's DID against `agent_did` (or its
# controller_did for delegated agents) and rejects cross-agent reads
# with JSON-RPC -32001.

# ── AgentBond ────────────────────────────────────────────

def get_agent_bond(agent_did: str) -> dict:
    """Read the AgentBond state for `agent_did`.

    Returns the full bond record (controller_did, amount, lifecycle state,
    cooldown, history depth, promotion eligibility) or `null` if the agent
    has no bond posted.
    """
    return _rpc("tenzro_getAgentBond", {"agent_did": agent_did})

def list_agent_bonds_by_controller(controller_did: str) -> dict:
    """List every AgentBond posted by `controller_did`.

    Returns `{ controller_did, count, aggregate_bond, bonds: [...] }`.
    `aggregate_bond` is the sum of effective-for-promotion amounts across
    all active bonds the controller holds.
    """
    return _rpc("tenzro_listAgentBondsByController", {
        "controller_did": controller_did,
    })

# ── Insurance ────────────────────────────────────────────

def list_insurance_claims() -> dict:
    """List every insurance claim (Open + Approved + Rejected + Paid)."""
    return _rpc("tenzro_listInsuranceClaims", {})

def get_insurance_claim(claim_id: str) -> dict:
    """Fetch a single insurance claim by its id."""
    return _rpc("tenzro_getInsuranceClaim", {"claim_id": claim_id})

def get_insurance_pool_balance() -> dict:
    """Read the current insurance pool vault balance."""
    return _rpc("tenzro_getInsurancePoolBalance", {})

# ── Devices and machine ownership ─────────────────────────────────

def bind_device(identity_did: str, label: str, attestation_object_b64: str) -> dict:
    """Bind a device to an identity from a WebAuthn registration.

    `attestation_object_b64` is the base64 attestation object from
    `navigator.credentials.create()`. The node parses and grades it against
    the vendor roots it pins — nothing the client asserts about its own
    hardware is taken on trust, and **no platform account is an identity
    authority**.

    A device is refused when its credential can sync to a cloud account (which
    would prove control of an account rather than possession of a device) or
    when no verified attestation says its key lives in a TEE or secure element.
    """
    return _rpc(
        "tenzro_bindDevice",
        {
            "identity_did": identity_did,
            "label": label,
            "attestation_object_b64": attestation_object_b64,
        },
    )

def mirror_settlement(from_addr: str, interaction: dict, targets: list, primary_committed: bool = True) -> dict:
    """Record an anchored settlement on other chains, in parallel, as Bridge
    transactions the wallet ``from_addr`` (the payer or a relayer) signs.

    `targets` is `[{"chain": "eip155:8453", "self_contained": True}, ...]`.

    A self-contained mirror writes the canonical settlement bytes, so the
    record stays readable with no Tenzro node in existence — the only form that
    survives the Tenzro Ledger losing state, which matters while Tenzro is a
    preview network. A digest-only mirror is cheaper and proves a payload you already
    hold is the one that settled, but cannot tell you what settled.

    Each target is dispatched independently. There is no two-phase commit
    across chains that do not know about each other, so a failure on one does
    not roll back one that already landed; the report says which did.
    """
    return _rpc(
        "tenzro_mirrorSettlement",
        {
            "from": from_addr,
            "interaction": interaction,
            "targets": targets,
            "primary_committed": primary_committed,
        },
    )

def settlement_networks() -> dict:
    """The rails a payment can settle on, and the smallest worthwhile payment on each.

    Supporting x402 and being able to carry a micropayment are different
    properties. Base speaks x402 fluently and still cannot carry a one-cent
    charge without roughly 10% overhead, so an agent that picks a rail by
    "does it support x402" loses money on every metered call. Read this before
    declaring what asset you want to be paid in.
    """
    return _rpc("tenzro_settlementNetworks", {})

def route_payment(
    amount_wei: str,
    asset: str | None = None,
    tnzo_micro_usd: int | None = None,
) -> dict:
    """Where a specific charge would settle.

    Four outcomes: `accumulate` (below the micro-settlement floor — hold it in
    a channel, settling alone costs more than it moves), `primary` (the Tenzro
    Ledger), `secondary` (a rail carrying the payee's asset), and
    `no_viable_rail` (clears the floor, but nothing carries that asset at this
    size — accumulate or accept another asset).

    Omit `tnzo_micro_usd` and the node settles on the home chain rather than
    routing real money on a guessed exchange rate.
    """
    return _rpc(
        "tenzro_settlementNetworks",
        {
            "amount_wei": amount_wei,
            "asset": asset,
            "tnzo_micro_usd": tnzo_micro_usd,
        },
    )

def list_bound_devices(identity_did: str) -> dict:
    """List the devices that can authenticate as an identity.

    Each entry reports what it proved: attestation format, key protection tier,
    whether the chain reached a pinned vendor root, the backup flags, and
    whether its signature counter is a usable clone signal (it is not, for a
    synced credential). Also reports whether a wallet may be created yet.
    """
    return _rpc("tenzro_listBoundDevices", {"identity_did": identity_did})

def revoke_bound_device(identity_did: str, credential_id: str) -> dict:
    """Unbind a device and end every session it authorised, in one action.

    Both happen together by design: removing the device without ending its
    sessions would leave a lost phone's access live, which is the exact
    situation the user is trying to fix.
    """
    return _rpc(
        "tenzro_revokeBoundDevice",
        {"identity_did": identity_did, "credential_id": credential_id},
    )

def wallet_readiness(identity_did: str, this_device_credential_id: str | None = None) -> dict:
    """Whether a wallet may be created for this identity, and if not, why.

    A wallet held behind a single device is lost with that device. The machine
    the user is on is the first; a genuinely separate hardware-bound device — a
    phone, another machine — must be bound before there is anything to lose.
    Returns a `remedy` code alongside the reason.
    """
    return _rpc(
        "tenzro_walletReadiness",
        {
            "identity_did": identity_did,
            "this_device_credential_id": this_device_credential_id,
        },
    )

def transfer_machine_ownership(
    machine_did: str,
    new_owner_did: str,
    authority: str,
    controller_did: str | None = None,
    hardware_root_hex: str | None = None,
) -> dict:
    """Move a machine to another identity.

    The authority required is whatever anchors the machine. Pass
    `authority="controller"` with `controller_did` for a machine a human or
    institution delegated; pass `authority="hardware_root"` with
    `hardware_root_hex` for a machine nobody delegated. The two are **not**
    interchangeable: holding the hardware cannot take a machine that has an
    accountable party — that is a compromise, not an acquisition.
    """
    return _rpc(
        "tenzro_transferMachineOwnership",
        {
            "machine_did": machine_did,
            "new_owner_did": new_owner_did,
            "authority": authority,
            "controller_did": controller_did,
            "hardware_root_hex": hardware_root_hex,
        },
    )

# ── Economics ─────────────────────────────────────────────────────

def get_economic_policy() -> dict:
    """Read the economic policy this node applies to every settlement.

    Returns the live `EconomicPolicy` — the validating split (operator /
    treasury), the delegated split (operator / rpc-provider / treasury), the
    network's default settlement asset, and the
    micro-settlement floor beneath which a charge settles through a payment
    channel rather than its own transaction.

    Also reports, per capability, which economic mode this node is in. A
    **private** capability keeps the whole payment — nobody discovered it and
    no validator was engaged on the caller's behalf. A **public validating**
    one shares with the treasury. A **public delegated** one also pays the RPC
    provider validating on its behalf.

    Read this before paying rather than inferring the split from a receipt
    afterwards. Every rate is governance-set, never a constant.
    """
    return _rpc("tenzro_getEconomicPolicy", {})

# ── Adaptive Burn ────────────────────────────────────────

def get_burn_rate_config() -> dict:
    """Read the current adaptive-burn configuration and supply targets.

    Returns `{ config: {...}, targets: {...} }` covering the per-rail burn
    bps splits (base_fee, local_fee, paymaster) and the SupplyTargets
    governance dial (rolling window, neutral band, alarm thresholds,
    magnitude caps, fast-track timelock).
    """
    return _rpc("tenzro_getBurnRateConfig", {})

def get_supply_metrics() -> dict:
    """Read the latest SupplyMetricsSnapshot.

    Includes block height, circulating supply, epoch delta, rolling-bps,
    BurnBreakdown (per-rail), and EmissionBreakdown.
    """
    return _rpc("tenzro_getSupplyMetrics", {})

def get_burn_rate_recommendation() -> dict:
    """Read the latest BurnRateRecommendation.

    Returns `{ action, is_alarm, magnitude_bps, above_proposal_floor,
    deviation_bps, basis }` where `action` is one of Disabled / NoChange /
    IncreaseBurnPct / DecreaseBurnPct / AlarmHighInflation / AlarmHighDeflation.
    `magnitude_bps` is capped by `magnitude_cap_normal_bps` (or alarm cap).
    """
    return _rpc("tenzro_getBurnRateRecommendation", {})

def list_adaptive_burn_proposals() -> list:
    """List burn-dial governance proposals, newest first: the policy updates
    that set the burn shares or the supply targets the dial steers by."""
    page = _rpc("tenzro_listProposals", {"kind": "policy_update", "limit": 100})
    return [
        p
        for p in (page or {}).get("proposals", [])
        if {"AdaptiveBurnConfigUpdate", "SupplyTargetsUpdate"}
        & set(((p.get("proposal") or {}).get("action") or {}).get("update", {}))
    ]

# ── Escrow listing ────────────────────────────────────────────────

def list_escrows_by_payer(payer: str) -> dict:
    """List every escrow opened by `payer` (hex address).

    Returns `{ payer, count, escrows: [...] }`.
    """
    return _rpc("tenzro_listEscrowsByPayer", {"payer": payer})

def list_escrows_by_payee(payee: str) -> dict:
    """List every escrow whose recipient is `payee` (hex address).

    Returns `{ payee, count, escrows: [...] }`.
    """
    return _rpc("tenzro_listEscrowsByPayee", {"payee": payee})

# ── Mempool ────────────────────────────────────────────────────────

def get_mempool_stats() -> dict:
    """Read per-lane mempool statistics (admission control).

    Returns admitted / rejected_rate_limited / rejected_fee_floor /
    rejected_mempool_full counters plus refill_per_sec / burst_capacity /
    fee_floor_mult / weight per lane (Verified, Delegated, Open).
    """
    return _rpc("tenzro_getMempoolStats", {})

def get_mempool_lane(address: str) -> dict:
    """Inspect the lane assignment and bucket state for `address`.

    Useful for debugging "why is my transaction being rate-limited?"
    without consuming a token. Returns the resolved lane, bucket_key, and
    current snapshot. For Machine identities, the bucket may be keyed on
    the controller wallet rather than the queried address.
    """
    return _rpc("tenzro_getMempoolLane", {"address": address})

def get_account_contention(address: str) -> dict:
    """Read the hot-state local fee market score for `address`.

    Returns score / reexecutions / writes / is_hot / multiplier and the
    current effective base fee + per-gas surcharge for transactions
    touching this account.
    """
    return _rpc("tenzro_getAccountContention", {"address": address})

# ── DA offload ───────────────────────────────────────────

def get_da_backends() -> dict:
    """List configured DA backends and their health status.

    Only `inline` is configured today; EigenDA / Celestia / Avail
    entries appear once their feature-gated adapters are wired.
    """
    return _rpc("tenzro_getDaBackends", {})

def verify_da_pointer(pointer: dict) -> dict:
    """Probe whether a DA pointer is dereferenceable right now.

    `pointer` is a dict with `backend` (`inline` | `eigenda` |
    `celestia` | `avail`), hex `namespace`, hex `locator`, and optional
    hex `commitment_kzg` / `attestation_root` (32 bytes).
    """
    return _rpc("tenzro_verifyDaPointer", {"pointer": pointer})

# ── Receipts & principal chain ───────────────────────────

# ── Agent lifecycle & kill-switch ─────────────────────────────────

def list_kill_switch_by_agent(agent_did: str) -> dict:
    """List every kill-switch receipt targeting `agent_did`.

    Chronological order (oldest first). Each receipt is the on-VM record
    of a `PauseAgent` / `QuarantineAgent` / `TerminateAgent` execution.
    """
    return _rpc("tenzro_listKillSwitchByAgent", {"agent_did": agent_did})

def list_kill_switch_by_controller(controller_did: str) -> dict:
    """List every kill-switch receipt authorised by `controller_did`.

    Across all targeted agents, chronological order.
    """
    return _rpc("tenzro_listKillSwitchByController", {
        "controller_did": controller_did,
    })

def get_kill_switch_receipt(receipt_id: str) -> dict:
    """Fetch a single kill-switch receipt by hex `receipt_id`.

    Returns `null` if the id is unknown.
    """
    return _rpc("tenzro_getKillSwitchReceipt", {"receipt_id": receipt_id})

# ── Inference usage & provider reputation ─────────────────────────

def list_inference_usage(model_id: str | None = None,
                         provider: str | None = None) -> dict:
    """List inference usage records / aggregates.

    Both filters absent → `{ global, models, providers }` aggregates.
    `model_id` only → per-model stats. `provider` only → per-provider stats.
    Both → intersection records from the bounded recent ring.
    """
    params = {}
    if model_id is not None:
        params["model_id"] = model_id
    if provider is not None:
        params["provider"] = provider
    return _rpc("tenzro_listInferenceUsage", params)

def get_generation(generation_id: str) -> dict:
    """Read the recorded stats for one generation by the id you already hold.

    `generation_id` is the `chatcmpl-...` from any chat route, or the
    `request_id` of an inference dispatched over JSON-RPC. Returns
    `{ id, model, provider, input_tokens, output_tokens, total_tokens,
    bytes_in, bytes_out, cost_wei, latency_ms, tokens_per_second, created }`.

    Useful after consuming a stream: the token counts and cost arrive in the
    terminal chunk, which a client that stops reading at the last token never
    sees. A generation is recorded when it finishes, so an error means the id
    is unknown to this node, the generation is still running, or it failed
    before completing.
    """
    return _rpc("tenzro_getGeneration", {"id": generation_id})


# ── Provenance & disputes ─────────────────────────────────────────

def get_provenance(content_hash: str) -> dict:
    """Look up a cached ContentProvenanceManifest by 32-byte hex `content_hash`.

    Read path for the EU AI Act Art. 50(2) machine-readable
    synthetic-content marker. The store is bounded LRU-by-signed_at, so a
    `not found` does not prove the response was never signed.
    """
    return _rpc("tenzro_getContentProvenance", {"content_hash": content_hash})

# ── Validator registry (read-only) ────────────────────────────────

def get_validator_state(address: str) -> dict:
    """Fetch a single validator's registry entry by 32-byte address.

    `address` is hex-encoded (with or without `0x` prefix) on the request
    path. The response's `address` / `withdrawal_address` are
    base58-encoded; pubkeys are plain hex without `0x`. Returns `null`
    if the address is not registered.
    """
    return _rpc("tenzro_getValidatorState", {"address": address})

def list_validators(status: str | None = None) -> dict:
    """List validators, optionally filtered by status.

    Status is one of: Active / Candidate / PendingActive / PendingExit
    / Exited / Jailed. Returns `{ count, validators: [...] }`.
    """
    params = {"status": status} if status else {}
    return _rpc("tenzro_listValidators", params)

def list_active_validators() -> dict:
    """List only the currently-Active validators producing blocks.

    Convenience over `list_validators("Active")`. Returns the same
    `{ count, validators: [...] }` shape.
    """
    return _rpc("tenzro_listActiveValidators", {})


def get_router_metrics() -> dict:
    """Read the inference router's live metrics snapshot.

    Reports total requests routed, hedges dispatched, hedges won, and requests
    abandoned on the whole-request deadline.
    """
    return _rpc("tenzro_getRouterMetrics", {})

# ── CLI ───────────────────────────────────────────────────────────

# ---------------------------------------------------------------------------
# DID envelope verification
# ---------------------------------------------------------------------------

def verify_did_envelope(envelope_hex: str) -> dict:
    """Verify a Tenzro DID envelope (hex header value) — did:tenzro/key/ethr/web."""
    return _rpc("tenzro_verifyDidEnvelope", {"envelope": envelope_hex})

def submit_reserve_attestation(attestation: dict) -> dict:
    return _rpc("tenzro_submitReserveAttestation", {"attestation": attestation})

def get_reserve(asset_id: str) -> dict:
    return _rpc("tenzro_getReserve", {"asset_id": asset_id})

# ---------------------------------------------------------------------------
# Workflow durable reads (extends the saga write surface above)
# ---------------------------------------------------------------------------

# ── Institutional primitives ──────────────────────────────────────

def urwa_is_kill_switched(token_id_hex: str) -> dict:
    """Read the ERC-7943 (uRWA) kill-switch state for a 32-byte token id."""
    return _rpc("tenzro_urwaIsKillSwitched", {"token_id_hex": token_id_hex})

def urwa_get_frozen_tokens(token_id_hex: str, account_hex: str) -> dict:
    """Read the ERC-7943 frozen-amount for a (token, account) pair."""
    return _rpc(
        "tenzro_urwaGetFrozenTokens",
        {"token_id_hex": token_id_hex, "account_hex": account_hex},
    )

def quote_bridge_fee_in_tnzo(adapter: str, dest_chain: str,
                             native_fee_smallest_unit: str) -> dict:
    """Quote a destination-native bridge fee in TNZO."""
    return _rpc(
        "tenzro_quoteBridgeFeeInTnzo",
        {
            "adapter": adapter,
            "dest_chain": dest_chain,
            "native_fee_smallest_unit": native_fee_smallest_unit,
        },
    )

# ── Storage Market ────────────────────────────────────────────────

def storage_store_object(object_id: str, data: str, owner: str = "",
                         data_shards: int = 4,
                         parity_shards: int = 2) -> dict:
    """Store an erasure-coded object on this node's storage provider.

    `data` is the base64-encoded payload.
    """
    params = {
        "object_id": object_id,
        "data": data,
        "data_shards": data_shards,
        "parity_shards": parity_shards,
    }
    if owner:
        params["owner"] = owner
    return _rpc("tenzro_storageStoreObject", params)

# ── Universal RPC gateway ─────────────────────────────────────────
#
# The wrappers in this module cover what the node served when each was
# written. These two cover everything, including methods added to a node newer
# than this file — the directory comes from the node, not from a list here.
#
# Authorization is unchanged: a call through the gateway runs behind the same
# admin-token gate, API-key scope gate, and default-deny classification as any
# other call, so it reaches exactly what your credentials already allow.

def list_rpc_methods(namespace: str | None = None, contains: str | None = None) -> dict:
    """Enumerate every JSON-RPC method this node serves.

    Each entry carries how it is gated (`admin` vs `open`) and which API-key
    scope it needs, so you can tell "I need a differently-scoped key" from "I
    need the operator's token" without provoking the error first.

    `namespace` and `contains` narrow the listing; unfiltered it lists every
    method the node serves.
    """
    params = {}
    if namespace is not None:
        params["namespace"] = namespace
    if contains is not None:
        params["contains"] = contains
    return _rpc("tenzro_listRpcMethods", params)

def call_rpc(method: str, params: dict | None = None) -> dict:
    """Invoke any JSON-RPC method by name.

    The escape hatch for anything without a named wrapper above. Discover names
    with `list_rpc_methods` first.
    """
    return _rpc(method, params if params is not None else {})

def supports(method: str) -> bool:
    """Whether this node serves `method`.

    Asks the node rather than checking a list in this file, so it stays correct
    against a node newer than this skill.
    """
    result = list_rpc_methods(contains=method)
    rows = result.get("methods") or []
    return any(r.get("method") == method for r in rows)

def storage_set_pricing(mode: str = "dynamic", capacity: str = "0",
                        min_rate: str | None = None, max_rate: str | None = None) -> dict:
    """Set the byte-epoch storage pricing policy."""
    params = {"mode": mode, "capacity": capacity}
    if min_rate is not None:
        params["min_rate"] = min_rate
    if max_rate is not None:
        params["max_rate"] = max_rate
    return _rpc("tenzro_storageSetPricing", params)

def storage_status() -> dict:
    """Summary of this node's storage-provider state."""
    return _rpc("tenzro_storageStatus", [])

# ── Managed Databases ─────────────────────────────────────────────

# ── MoE Expert Sharding ───────────────────────────────────────────

def moe_shard_map(model_id: str) -> dict:
    """Return the expert-shard map for a MoE model across known providers."""
    return _rpc("tenzro_moeShardMap", {"model_id": model_id})

def moe_plan_dispatch(model_id: str, routings: list,
                      allow_cold: bool = False) -> dict:
    """Plan the per-holder dispatch for a list of per-token top-k routings."""
    return _rpc("tenzro_moePlanDispatch", {
        "model_id": model_id,
        "routings": routings,
        "allow_cold": allow_cold,
    })

def moe_replication_policy() -> dict:
    """Return the current replication policy used by shard-view consumers."""
    return _rpc("tenzro_moeReplicationPolicy", [])

def moe_catalog_shape(model_id: str) -> dict:
    """Return the catalog-side MoE topology for a model."""
    return _rpc("tenzro_moeCatalogShape", {"model_id": model_id})

def moe_prepare_experts(model_id: str, layer: int, experts: list | None = None,
                        include_gate: bool = True, quant=None) -> dict:
    """Slice a checkpoint into per-expert blobs and publish them for holders.

    ``quant`` is a preset string (``q4_k_m`` / ``q8_0`` / ``q4_k`` / ``q6_k``)
    or a per-projection object like ``{"gate": "q4_k", "up": "q4_k",
    "down": "q6_k"}``; omit for dense f32 blobs. Omit ``experts`` (or pass an
    empty list) to prepare every expert in the layer. Returns a ``job_id`` to
    poll with :func:`moe_prepare_status`.
    """
    params = {"model_id": model_id, "layer": layer, "include_gate": include_gate}
    if experts:
        params["experts"] = experts
    if quant is not None:
        params["quant"] = quant
    return _rpc("tenzro_moePrepareExperts", params)

def moe_prepare_status(job_id: str) -> dict:
    """Poll an expert-preparation job for its state and prepared blob URIs."""
    return _rpc("tenzro_moePrepareStatus", {"job_id": job_id})

def moe_expert_status() -> dict:
    """Resident experts / gates with residency tier, footprint, and GPU flag."""
    return _rpc("tenzro_moeExpertStatus", [])

def moe_forward(model_id: str, layer: int, d_model: int, hidden: list) -> dict:
    """Run one distributed MoE layer forward.

    Gate-routes ``hidden`` (row-major ``[num_tokens, d_model]`` f32) locally,
    fans the selected experts out to holders, and combines the gate-weighted
    outputs.
    """
    return _rpc("tenzro_moeForward", {
        "model_id": model_id,
        "layer": layer,
        "d_model": d_model,
        "hidden": hidden,
    })

# ── Local Discovery & Cluster ─────────────────────────────────────

def node_profile() -> dict:
    """The local node's hardware self-profile and derived serving values."""
    return _rpc("tenzro_nodeProfile", [])

COMMANDS = {
    "get_beacon": lambda args: get_beacon(
        int(args[0]) if args else None, int(args[1]) if len(args) > 1 else None),
    "get_da_object": lambda args: get_da_object(args[0]),
    "get_da_retention": lambda args: get_da_retention(),
    "get_fee_market": lambda args: get_fee_market(),
    # Wallet & Balance
    "join_network": lambda args: join_as_micro_node(
        args[0] if args else "Tenzro User",
        args[1] if len(args) > 1 else "cli",
    ),
    "list_bridge_routes": lambda args: list_bridge_routes(),
    "get_bridge_route": lambda args: get_bridge_route(args[0], args[1]),
    "get_balance": lambda args: get_balance(args[0]),
    "balance": lambda args: get_balance(args[0]),
    # DID envelope verification
    "verify_envelope": lambda args: verify_did_envelope(args[0]),
    # Capital Intent (regulated capital allocation) + Reserve attestations
    "submit_reserve_attestation": lambda args: submit_reserve_attestation(json.loads(args[0])),
    "get_reserve": lambda args: get_reserve(args[0]),
    # Node Status
    "status": lambda args: get_status(),
    "health": lambda args: get_health(),
    "block_height": lambda args: block_height(),
    "get_block": lambda args: get_block(int(args[0])),
    "chain_id": lambda args: chain_id(),
    "node_info": lambda args: node_info(),
    # Identity
    "register_identity": lambda args: register_identity(args[0]),
    "resolve_did": lambda args: resolve_did(args[0]),
    "resolve_did_document": lambda args: resolve_did_document(args[0]),
    "revoke_did": lambda args: revoke_did(
        args[0], args[1], args[2] if len(args) > 2 else "revoked",
    ),
    "forget_identity": lambda args: forget_identity(args[0]),
    # Passkey smart accounts
    "enroll_passkey": lambda args: enroll_passkey(
        args[0],
        args[1],
        json.loads(args[2]),
        args[3] if len(args) > 3 else None,
        int(args[4]) if len(args) > 4 else 0,
    ),
    "get_keystore": lambda args: get_keystore(args[0], json.loads(args[1]) if len(args) > 1 else None),
    "resolve_credential": lambda args: resolve_credential(args[0], args[1] if len(args) > 1 else None),
    # Browser-launch passkey auth sessions
    "create_passkey_session": lambda args: create_passkey_session(
        args[0],
        args[1] if len(args) > 1 else None,
        int(args[2]) if len(args) > 2 else 0,
        args[3] if len(args) > 3 else None,
        args[4] if len(args) > 4 else None,
        args[5] if len(args) > 5 else None,
        args[6] if len(args) > 6 else None,
    ),
    "get_passkey_session": lambda args: get_passkey_session(args[0]),
    # Verification
    "verify_zk_proof": lambda args: verify_zk_proof(
        args[0],
        json.loads(args[1]) if len(args) > 1 else [],
        args[2],
    ),
    "verify_transaction": lambda args: verify_transaction(args[0], args[1], args[2]),
    "verify_settlement": lambda args: verify_settlement(args[0], args[1], args[2]),
    "verify_inference": lambda args: verify_inference(args[0], args[1], args[2]),
    # Node access
    "access_challenge": lambda args: access_challenge(args[0], args[1]),
    "get_access_policy": lambda args: get_access_policy(),
    "set_access_policy": lambda args: set_access_policy(open(args[0]).read()),
    "preview_access": lambda args: preview_access(args[0], args[1], args[2] if len(args) > 2 else None),
    "list_access_tokens": lambda args: list_access_tokens(),
    "revoke_access_token": lambda args: revoke_access_token(args[0]),
    # Token
    "total_supply": lambda args: total_supply(),
    "token_balance": lambda args: token_balance(args[0]),
    # Token Registry & Contracts
    "get_token_info": lambda args: get_token_info(symbol=args[0]),
    "list_tokens": lambda args: list_tokens(
        args[0] if args else None,
        int(args[1]) if len(args) > 1 else 50,
    ),
    "get_token_balance": lambda args: get_token_balance_all_vms(args[0]),
    "deploy_contract": lambda args: deploy_contract(json.loads(args[0])),
    # Models
    "list_models": lambda args: list_models(len(args) > 0 and args[0].lower() == "true"),
    "chat": lambda args: chat(args[0], " ".join(args[1:]) if len(args) > 1 else args[1]),
    "list_model_endpoints": lambda args: list_model_endpoints(),
    "route_intent": lambda args: route_intent(
        args[0],
        int(args[1]) if len(args) > 1 else None,
        float(args[2]) if len(args) > 2 else None,
        args[3] if len(args) > 3 else None,
    ),
    "chat_by_intent": lambda args: chat_by_intent(args[0], " ".join(args[1:])),
    "record_route_outcome": lambda args: record_route_outcome(
        args[0], int(args[1]), args[2]
    ),
    "route_difficulty_stats": lambda args: route_difficulty_stats(
        args[0] if args else None
    ),
    # Payments
    "create_payment": lambda args: create_payment_challenge(
        args[0], args[1], int(args[2]),
        args[3] if len(args) > 3 else "TNZO",
        args[4] if len(args) > 4 else None,
    ),
    "verify_payment": lambda args: verify_payment(
        args[0], args[1], args[2], args[3], int(args[4]), args[5], args[6],
    ),
    # Network Duties
    "list_duties": lambda args: list_duties(),
    "get_duty": lambda args: get_duty(args[0]),
    # Agent Templates
    # Skills Registry
    # Tools Registry
    # Agent Spawning & Swarm
    "discover_models": lambda args: discover_models(args[0] if args else None),
    # Agent Template (Extended)
    # Bridge
    # Staking & Providers
    "role_stakes": lambda args: role_stakes(args[0] if args else None),
    "provider_stats": lambda args: provider_stats(),
    # NFT Collections
    # ERC-3643 Compliance
    # Identity (Extended)
    "register_machine_identity": lambda args: register_machine_identity(
        args[0],
        args[1],
        args[2].split(","),
        args[3],
    ),
    "list_identities": lambda args: list_identities(args[0] if args else None),
    "get_model_provenance": lambda args: get_model_provenance(
        args[0], args[1] if len(args) > 1 else None,
    ),
    "submit_trust_record": lambda args: submit_trust_record(json.loads(args[0])),
    # Network & Node (Extended)
    "peer_count": lambda args: peer_count(),
    "syncing": lambda args: syncing(),
    "hardware_profile": lambda args: get_hardware_profile(),
    "get_finalized_block": lambda args: get_finalized_block(),
    "export_config": lambda args: export_config(),
    # Transaction (Extended)
    "get_transaction": lambda args: get_transaction(args[0]),
    "get_nonce": lambda args: get_nonce(args[0]),
    "get_transaction_history": lambda args: get_transaction_history(
        args[0], int(args[1]) if len(args) > 1 else 50,
    ),
    # Settlement (Extended)
    "settle": lambda args: settle(
        args[0], args[1], json.loads(args[2]), args[3] if len(args) > 3 else None,
    ),
    # create_escrow: payer payee amount_wei [asset] [expires_at_ms] [release]
    # (uses ambient OAuth/DPoP — set TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF)
    # release_escrow: payer escrow_id_hex [proof_data_hex]
    # refund_escrow: payer escrow_id_hex
    # get_escrow: escrow_id_hex
    "get_escrow": lambda args: get_escrow(args[0]),
    "open_payment_channel": lambda args: open_payment_channel(
        args[0], args[1], int(args[2]),
    ),
    "close_payment_channel": lambda args: close_payment_channel(args[0]),
    # Model Management (Extended)
    "inference_request": lambda args: inference_request(args[0], " ".join(args[1:])),
    "register_model_endpoint": lambda args: register_model_endpoint(args[0], args[1]),
    "get_model_endpoint": lambda args: get_model_endpoint(args[0]),
    "unregister_model_endpoint": lambda args: unregister_model_endpoint(args[0]),
    "serve_model": lambda args: serve_model(
        args[0],
        args[1].lower() in ("1", "true", "yes") if len(args) > 1 else False,
        args[2].lower() in ("1", "true", "yes") if len(args) > 2 else False,
        args[3] if len(args) > 3 else "network",
    ),
    "stop_model": lambda args: stop_model(args[0]),
    "delete_model": lambda args: delete_model(args[0]),
    # Token (Extended)
    # Governance
    "list_proposals": lambda args: list_proposals(args[0] if args else None),
    "get_voting_power": lambda args: get_voting_power(args[0]),
    # Provider Management (Extended)
    "set_role": lambda args: set_role(args[0]),
    "set_provider_pricing": lambda args: set_provider_pricing(
        json.loads(args[0]) if args else {},
    ),
    "get_provider_pricing": lambda args: get_provider_pricing(),
    "list_providers": lambda args: list_providers(args[0] if args else None),
    # EVM Compatibility
    "eth_block_number": lambda args: eth_block_number(),
    "eth_get_balance": lambda args: eth_get_balance(args[0]),
    "eth_get_transaction_count": lambda args: eth_get_transaction_count(args[0]),
    "eth_gas_price": lambda args: eth_gas_price(),
    "eth_max_priority_fee_per_gas": lambda args: eth_max_priority_fee_per_gas(),
    "eth_fee_history": lambda args: eth_fee_history(
        int(args[0]) if args else 10,
        args[1] if len(args) > 1 else "latest",
        json.loads(args[2]) if len(args) > 2 else None,
    ),
    "eth_estimate_gas": lambda args: eth_estimate_gas(json.loads(args[0])),
    "eth_call": lambda args: eth_call(json.loads(args[0])),
    "eth_get_code": lambda args: eth_get_code(args[0]),
    "eth_get_storage_at": lambda args: eth_get_storage_at(args[0], args[1]),
    "eth_get_logs": lambda args: eth_get_logs(json.loads(args[0])),
    "eth_get_transaction_receipt": lambda args: eth_get_transaction_receipt(args[0]),
    "eth_get_block_by_number": lambda args: eth_get_block_by_number(
        args[0] if args else "latest",
    ),
    "eth_get_block_by_hash": lambda args: eth_get_block_by_hash(args[0]),
    "eth_get_tx_by_block_and_index": lambda args: eth_get_transaction_by_block_number_and_index(
        args[0], args[1],
    ),
    "eth_syncing": lambda args: eth_syncing(),
    "eth_accounts": lambda args: eth_accounts(),
    "net_peer_count": lambda args: net_peer_count(),
    "net_version": lambda args: net_version(),
    "net_listening": lambda args: net_listening(),
    # Events & Webhooks
    "get_events": lambda args: get_events(
        None, None,
        int(args[0]) if args else 100,
    ),
    "get_event_status": lambda args: get_event_status(),
    # SLA Fault Detector
    "sla_issue_probe": lambda args: sla_issue_probe(
        args[0], int(args[1]), int(args[2]), int(args[3]),
    ),
    "sla_list_outstanding_probes": lambda args: sla_list_outstanding_probes(),
    "sla_get_params": lambda args: sla_get_params(),
    # Snapshot (State Sync)
    "list_snapshots": lambda args: list_snapshots(),
    "get_snapshot_manifest": lambda args: get_snapshot_manifest(int(args[0])),
    # ── EIP-7702 ──
    # ── Permit2 ──
    "permit2_verify_and_consume": lambda args: permit2_verify_and_consume(
        int(args[0]), args[1], args[2], args[3], args[4], args[5], int(args[6]), args[7],
        args[8] if len(args) > 8 else None,
        args[9] if len(args) > 9 else None,
    ),
    "permit2_nonce_used": lambda args: permit2_nonce_used(args[0], args[1]),
    # ── Institutional primitives ──
    "urwa_is_kill_switched": lambda args: urwa_is_kill_switched(args[0]),
    "urwa_get_frozen_tokens": lambda args: urwa_get_frozen_tokens(args[0], args[1]),
    "quote_bridge_fee_in_tnzo": lambda args: quote_bridge_fee_in_tnzo(
        args[0], args[1], args[2]
    ),
    # ── CAIP discovery ──
    # ── Ecosystem: Solana ──
    # ── Ecosystem: Ethereum ──
    # ── Ecosystem: Chainlink ──
    "chainlink_get_price": lambda args: chainlink_get_price(
        args[0] if args else "ETH/USD",
    ),
    "chainlink_list_feeds": lambda args: chainlink_list_feeds(
        args[0] if args else "ethereum",
    ),
    "vrf_request_random": lambda args: vrf_request_random(
        int(args[0]) if args else 1,
    ),
    "vrf_get_subscription": lambda args: vrf_get_subscription(args[0]),
    "ds_get_report": lambda args: ds_get_report(args[0]),
    "ds_list_feeds": lambda args: ds_list_feeds(),
    "por_get_reserve": lambda args: por_get_reserve(args[0]),
    "por_list_feeds": lambda args: por_list_feeds(),
    # ── Crypto ──
    "verify_signature": lambda args: verify_signature(args[0], args[1], args[2]),
    # ── TEE ──
    "detect_tee": lambda args: detect_tee(),
    "get_tee_attestation": lambda args: get_tee_attestation(
        args[0] if args else None,
    ),
    "verify_tee_attestation": lambda args: verify_tee_attestation(args[0], args[1]),
    "list_tee_providers": lambda args: list_tee_providers(),
    # ── ZK ──
    "create_zk_proof": lambda args: create_zk_proof(
        args[0],
        json.loads(args[1]) if len(args) > 1 else {},
    ),
    "list_zk_circuits": lambda args: list_zk_circuits(),
    # ── App registry + settlement authorization ──
    # ── Contract ABI ──
    # ── OAuth 2.1 + DPoP Onboarding ──
    "onboard_human": lambda args: onboard_human(
        args[0], args[1], args[2], json.loads(args[3]), args[4] if len(args) > 4 else None
    ),
    "onboard_delegated_agent": lambda args: onboard_delegated_agent(args[0], args[1], args[2], args[3] if len(args) > 3 else None),
    "onboard_autonomous_agent": lambda args: onboard_autonomous_agent(args[0], args[1], args[2] if len(args) > 2 else None),
    "refresh_token": lambda args: refresh_token(args[0], args[1]),
    "revoke_jwt": lambda args: revoke_jwt(
        args[0], args[1], args[2] if len(args) > 2 else "revoked",
    ),
    # ── AP2 (Agent Payments Protocol) ──
    "governance_get": lambda args: governance_get(args[0], args[1]),
    # ── ERC-8004 (Trustless Agents Registry — full Jan 2026 revision surface) ──
    # ── Multi-modal: forecast / vision / text-embed / segment / text-segment /
    #    detect / transcribe / video ──
    "list_forecast_catalog": lambda args: list_forecast_catalog(),
    "forecast": lambda args: forecast(
        args[0],
        json.loads(args[1]),
        int(args[2]),
        json.loads(args[3]) if len(args) > 3 and args[3] else None,
        int(args[4]) if len(args) > 4 and args[4] else None,
    ),
    "list_vision_catalog": lambda args: list_vision_catalog(),
    "vision_embed": lambda args: vision_embed(
        args[0], args[1],
        args[2].lower() != "false" if len(args) > 2 else True,
    ),
    "vision_similarity": lambda args: vision_similarity(json.loads(args[0]), json.loads(args[1])),
    "list_text_embedding_catalog": lambda args: list_text_embedding_catalog(),
    "text_embed": lambda args: text_embed(
        args[0],
        json.loads(args[1]),
        int(args[2]) if len(args) > 2 and args[2] else None,
        args[3].lower() == "true" if len(args) > 3 and args[3] else False,
    ),
    "list_segmentation_catalog": lambda args: list_segmentation_catalog(),
    "segment": lambda args: segment(args[0], args[1], json.loads(args[2])),
    "list_text_segmentation_catalog": lambda args: list_text_segmentation_catalog(),
    "text_segment": lambda args: text_segment(
        args[0], args[1], args[2],
        box_prompt=json.loads(args[3]) if len(args) > 3 and args[3] else None,
        score_threshold=float(args[4]) if len(args) > 4 and args[4] else 0.5,
    ),
    "list_detection_catalog": lambda args: list_detection_catalog(),
    "list_rerank_catalog": lambda args: list_rerank_catalog(),
    "speak": lambda args: speak(args[0], args[1], args[2] if len(args) > 2 and args[2] else None),
    "rerank": lambda args: rerank(args[0], json.loads(args[1]) if args[1].lstrip().startswith("{") else args[1],
                                  json.loads(args[2]),
                                  int(args[3]) if len(args) > 3 and args[3] else None),
    "detect": lambda args: detect(
        args[0], args[1],
        float(args[2]) if len(args) > 2 else 0.5,
    ),
    "list_audio_catalog": lambda args: list_audio_catalog(),
    "transcribe": lambda args: transcribe(
        args[0], args[1],
        args[2] if len(args) > 2 and args[2] else None,
        args[3].lower() == "true" if len(args) > 3 and args[3] else False,
        float(args[4]) if len(args) > 4 and args[4] else None,
    ),
    "list_video_catalog": lambda args: list_video_catalog(),
    "video_embed": lambda args: video_embed(
        args[0], args[1],
        args[2].lower() == "true" if len(args) > 2 and args[2] else False,
        int(args[3]) if len(args) > 3 and args[3] else None,
    ),
    # ── Multi-modal load / unload (surface symmetry) ──
    "load_forecast_model": lambda args: load_forecast_model(
        args[0], args[1] if len(args) > 1 and args[1] else None,
    ),
    "unload_forecast_model": lambda args: unload_forecast_model(args[0]),
    "load_vision_model": lambda args: load_vision_model(
        args[0], args[1] if len(args) > 1 and args[1] else None,
    ),
    "unload_vision_model": lambda args: unload_vision_model(args[0]),
    "load_text_embedding_model": lambda args: load_text_embedding_model(
        args[0], args[1] if len(args) > 1 and args[1] else None,
    ),
    "unload_text_embedding_model": lambda args: unload_text_embedding_model(args[0]),
    "load_text_segmentation_model": lambda args: load_text_segmentation_model(
        args[0], args[1] if len(args) > 1 and args[1] else None,
    ),
    "unload_text_segmentation_model": lambda args: unload_text_segmentation_model(args[0]),
    "load_segmentation_model": lambda args: load_segmentation_model(
        args[0], args[1] if len(args) > 1 and args[1] else None,
    ),
    "unload_segmentation_model": lambda args: unload_segmentation_model(args[0]),
    "load_detection_model": lambda args: load_detection_model(
        args[0], args[1] if len(args) > 1 and args[1] else None,
    ),
    "unload_detection_model": lambda args: unload_detection_model(args[0]),
    "load_audio_model": lambda args: load_audio_model(
        args[0], args[1] if len(args) > 1 and args[1] else None,
    ),
    "unload_audio_model": lambda args: unload_audio_model(args[0]),
    "load_video_model": lambda args: load_video_model(
        args[0], args[1],
        num_frames=int(args[2]) if len(args) > 2 and args[2] else None,
        visibility=args[3] if len(args) > 3 and args[3] else None,
    ),
    "unload_video_model": lambda args: unload_video_model(args[0]),
    # ── Agent memory tier ──
    # ── AgentBond ──
    "get_agent_bond": lambda args: get_agent_bond(args[0]),
    "list_agent_bonds_by_controller": lambda args: list_agent_bonds_by_controller(args[0]),
    # ── Insurance ──
    "list_insurance_claims": lambda args: list_insurance_claims(),
    "get_insurance_claim": lambda args: get_insurance_claim(args[0]),
    "get_insurance_pool_balance": lambda args: get_insurance_pool_balance(),
    # ── Adaptive Burn ──
    "bind_device": lambda args: bind_device(
        args["identity_did"], args["label"], args["attestation_object_b64"]
    ),
    "mirror_settlement": lambda args: mirror_settlement(
        args["from"], args["interaction"], args["targets"], args.get("primary_committed", True)
    ),
    "settlement_networks": lambda args: settlement_networks(),
    "route_payment": lambda args: route_payment(
        args["amount_wei"], args.get("asset"), args.get("tnzo_micro_usd")
    ),
    "list_bound_devices": lambda args: list_bound_devices(args["identity_did"]),
    "revoke_bound_device": lambda args: revoke_bound_device(
        args["identity_did"], args["credential_id"]
    ),
    "wallet_readiness": lambda args: wallet_readiness(
        args["identity_did"], args.get("this_device_credential_id")
    ),
    "transfer_machine_ownership": lambda args: transfer_machine_ownership(
        args["machine_did"],
        args["new_owner_did"],
        args["authority"],
        args.get("controller_did"),
        args.get("hardware_root_hex"),
    ),
    "get_economic_policy": lambda args: get_economic_policy(),
    "get_burn_rate_config": lambda args: get_burn_rate_config(),
    "get_supply_metrics": lambda args: get_supply_metrics(),
    "get_burn_rate_recommendation": lambda args: get_burn_rate_recommendation(),
    "list_adaptive_burn_proposals": lambda args: list_adaptive_burn_proposals(),
    # ── Escrow listing ──
    "list_escrows_by_payer": lambda args: list_escrows_by_payer(args[0]),
    "list_escrows_by_payee": lambda args: list_escrows_by_payee(args[0]),
    # ── Validator registry (read-only) ──
    "get_validator_state": lambda args: get_validator_state(args[0]),
    "list_validators": lambda args: list_validators(args[0] if args else None),
    "list_active_validators": lambda args: list_active_validators(),
    # ── Mempool ──
    "get_mempool_stats": lambda args: get_mempool_stats(),
    "get_mempool_lane": lambda args: get_mempool_lane(args[0]),
    "get_account_contention": lambda args: get_account_contention(args[0]),
    # ── DA offload ──
    "get_da_backends": lambda args: get_da_backends(),
    "verify_da_pointer": lambda args: verify_da_pointer(json.loads(args[0])),
    # ── Agent lifecycle & kill-switch ──
    "list_kill_switch_by_agent": lambda args: list_kill_switch_by_agent(args[0]),
    "list_kill_switch_by_controller": lambda args: list_kill_switch_by_controller(args[0]),
    "get_kill_switch_receipt": lambda args: get_kill_switch_receipt(args[0]),
    # ── Inference usage & provider reputation ──
    "list_inference_usage": lambda args: list_inference_usage(
        args[0] if len(args) > 0 and args[0] else None,
        args[1] if len(args) > 1 and args[1] else None,
    ),
    # ── Provenance & disputes ──
    "get_provenance": lambda args: get_provenance(args[0]),
    # ── Agent JWKs, daily spend, capability attestations ──
    "get_agent_terms": lambda args: get_agent_terms(args[0]),
    # ── Storage Market ──
    "storage_store_object": lambda args: storage_store_object(
        args[0],
        args[1],
        args[2] if len(args) > 2 and args[2] else "",
        int(args[3]) if len(args) > 3 else 4,
        int(args[4]) if len(args) > 4 else 2,
    ),
    "storage_set_pricing": lambda args: storage_set_pricing(
        args[0] if len(args) > 0 and args[0] else "dynamic",
        args[1] if len(args) > 1 else "0",
        args[2] if len(args) > 2 and args[2] else None,
        args[3] if len(args) > 3 and args[3] else None,
    ),
    "storage_status": lambda args: storage_status(),
    # ── Managed Databases ──
    # ── MoE Expert Sharding ──
    "moe_shard_map": lambda args: moe_shard_map(args[0]),
    "moe_plan_dispatch": lambda args: moe_plan_dispatch(
        args[0],
        json.loads(args[1]) if len(args) > 1 else [],
        args[2].lower() in ("1", "true", "yes") if len(args) > 2 else False,
    ),
    "moe_replication_policy": lambda args: moe_replication_policy(),
    "moe_catalog_shape": lambda args: moe_catalog_shape(args[0]),
    "moe_prepare_experts": lambda args: moe_prepare_experts(
        args[0],
        int(args[1]),
        json.loads(args[2]) if len(args) > 2 and args[2] else None,
        args[3].lower() in ("1", "true", "yes") if len(args) > 3 else True,
        (json.loads(args[4]) if args[4].strip().startswith("{") else args[4])
        if len(args) > 4 and args[4] else None,
    ),
    "moe_prepare_status": lambda args: moe_prepare_status(args[0]),
    "moe_expert_status": lambda args: moe_expert_status(),
    "moe_forward": lambda args: moe_forward(
        args[0],
        int(args[1]),
        int(args[2]),
        json.loads(args[3]) if len(args) > 3 else [],
    ),
    # ── Local Discovery & Cluster ──
    "node_profile": lambda args: node_profile(),
}

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        print("Available commands:")
        for cmd in sorted(COMMANDS):
            print(f"  {cmd}")
        sys.exit(0)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd not in COMMANDS:
        print(json.dumps({"error": f"Unknown command: {cmd}"}))
        sys.exit(1)

    try:
        result = COMMANDS[cmd](args)
        print(json.dumps(result, indent=2, default=str))
    except requests.exceptions.ConnectionError:
        print(json.dumps({"error": f"Cannot connect to Tenzro node at {RPC_URL}"}))
        sys.exit(1)
    except IndexError:
        print(json.dumps({"error": f"Missing arguments for command: {cmd}"}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
