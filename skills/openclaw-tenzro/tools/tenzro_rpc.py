#!/usr/bin/env python3
"""TenzroClaw — Tenzro blockchain RPC helper.

Part of the TenzroClaw OpenClaw skill for interacting with the Tenzro Network.
Wraps Tenzro JSON-RPC, Web API, and ecosystem MCP server calls into simple
functions.

Requires: pip install requests

Ecosystem MCP servers (Solana, Ethereum, LayerZero, Chainlink, Canton) are
called via the MCP Streamable HTTP protocol. Each ecosystem function uses
mcp_tool_call() to initialize a session and invoke a tool.

Usage:
    python tenzro_rpc.py join_network "Alice"
    python tenzro_rpc.py get_balance 0x1234...
    python tenzro_rpc.py create_wallet
    python tenzro_rpc.py faucet 0x1234...
    python tenzro_rpc.py send 0xfrom 0xto 1000000000000000000
    python tenzro_rpc.py status
    python tenzro_rpc.py register_identity "Alice"
    python tenzro_rpc.py resolve_did "did:tenzro:human:..."
    python tenzro_rpc.py block_height
    python tenzro_rpc.py get_block 0
    python tenzro_rpc.py chain_id
    python tenzro_rpc.py chat gemma4-9b "What is Tenzro?"
    python tenzro_rpc.py list_model_endpoints
    python tenzro_rpc.py create_payment x402 /inference 100 USDC 0xrecipient
    python tenzro_rpc.py verify_payment <challenge_id> x402 <payer_did> 0xpayer 100 USDC 0xsig
    python tenzro_rpc.py set_delegation did:tenzro:machine:... 10000000 100000000
    python tenzro_rpc.py post_task "Review code" "Review this Rust code" code_review 50000000000000000000
    python tenzro_rpc.py list_tasks
    python tenzro_rpc.py get_task <task_id>
    python tenzro_rpc.py cancel_task <task_id>
    python tenzro_rpc.py submit_quote <task_id> 40000000000000000000 gemma4-9b 30
    python tenzro_rpc.py list_agent_templates
    python tenzro_rpc.py register_agent_template "Code Reviewer" "Reviews code" specialist "You are..."
    python tenzro_rpc.py get_agent_template <template_id>
    python tenzro_rpc.py register_agent "my-agent" 0xaddress nlp,code
    python tenzro_rpc.py spawn_agent <parent_id> "sub-agent" data,nlp
    python tenzro_rpc.py run_agent_task <agent_id> "Summarize network stats"
    python tenzro_rpc.py create_swarm <orchestrator_id> researcher:nlp,data coder:code
    python tenzro_rpc.py get_swarm_status <swarm_id>
    python tenzro_rpc.py terminate_swarm <swarm_id>
    python tenzro_rpc.py create_token "My Token" MYT 0xcreator 1000000000000000000000
    python tenzro_rpc.py get_token_info MYT
    python tenzro_rpc.py list_tokens
    python tenzro_rpc.py get_token_balance 0x1234...
    python tenzro_rpc.py cross_vm_transfer TNZO 1000000000000000000 evm svm 0xfrom 0xto
    python tenzro_rpc.py deploy_contract evm 0xbytecode 0xdeployer
    python tenzro_rpc.py bridge_tokens tenzro ethereum TNZO 1000000000000000000 0xsender 0xrecipient
    python tenzro_rpc.py stake 1000000000000000000 Validator
    python tenzro_rpc.py unstake 1000000000000000000
    python tenzro_rpc.py register_provider model-provider
    python tenzro_rpc.py provider_stats
    python tenzro_rpc.py list_skills
    python tenzro_rpc.py list_skills web search
    python tenzro_rpc.py register_skill "web-search" "1.0.0" did:tenzro:machine:agent-abc "Searches the web" 1000000000000000000
    python tenzro_rpc.py search_skills "web search"
    python tenzro_rpc.py use_skill <skill_id> '{"query":"hello"}'
    python tenzro_rpc.py spawn_agent_with_skill <parent_id> "sub-agent" <skill_id> nlp,search
    python tenzro_rpc.py get_skill <skill_id>
    python tenzro_rpc.py update_skill <skill_id>
    python tenzro_rpc.py register_tool "web-search" "Searches the web" "https://example.com/mcp"
    python tenzro_rpc.py list_tools
    python tenzro_rpc.py get_tool <tool_id>
    python tenzro_rpc.py search_tools "web search"
    python tenzro_rpc.py use_tool <tool_id> '{"query":"hello"}'
    python tenzro_rpc.py update_tool <tool_id>
    python tenzro_rpc.py list_agents
    python tenzro_rpc.py send_agent_message <from_id> <to_id> "Hello agent"
    python tenzro_rpc.py delegate_task <agent_id> "Summarize data"
    python tenzro_rpc.py discover_models text
    python tenzro_rpc.py discover_agents nlp
    python tenzro_rpc.py fund_agent <agent_id> 1000000000000000000
    python tenzro_rpc.py assign_task <task_id> <provider>
    python tenzro_rpc.py complete_task <task_id> "Task result here"
    python tenzro_rpc.py update_task <task_id>
    python tenzro_rpc.py update_agent_template <template_id>
    python tenzro_rpc.py run_agent_template <agent_id>
    python tenzro_rpc.py download_agent_template <template_id>
    python tenzro_rpc.py spawn_agent_template <template_id> "My Agent"
    python tenzro_rpc.py import_identity did:tenzro:human:... <private_key>
    python tenzro_rpc.py register_machine_identity <controller_did> nlp,code
    python tenzro_rpc.py add_service <did> LinkedDomains https://example.com
    python tenzro_rpc.py add_credential <did> KycAttestation <issuer_did>
    python tenzro_rpc.py list_identities
    python tenzro_rpc.py pay_mpp https://api.example.com/resource
    python tenzro_rpc.py pay_x402 https://api.example.com/resource
    python tenzro_rpc.py payment_gateway_info
    python tenzro_rpc.py list_payment_sessions
    python tenzro_rpc.py get_payment_receipt <receipt_id>
    python tenzro_rpc.py peer_count
    python tenzro_rpc.py syncing
    python tenzro_rpc.py hardware_profile
    python tenzro_rpc.py list_accounts
    python tenzro_rpc.py get_finalized_block
    python tenzro_rpc.py export_config
    python tenzro_rpc.py get_transaction 0x<hash>
    python tenzro_rpc.py get_nonce 0x<address>
    python tenzro_rpc.py get_transaction_history 0x<address>
    python tenzro_rpc.py settle '{"service_type":"inference",...}'
    python tenzro_rpc.py get_settlement <settlement_id>
    python tenzro_rpc.py create_escrow 0xpayer 0xpayee 1000000000000000000
    python tenzro_rpc.py release_escrow 0xpayer <escrow_id_hex>
    python tenzro_rpc.py refund_escrow 0xpayer <escrow_id_hex>
    python tenzro_rpc.py open_payment_channel 0xpartyA 0xpartyB 1000000000000000000
    python tenzro_rpc.py close_payment_channel <channel_id>
    python tenzro_rpc.py inference_request gemma4-9b "What is Tenzro?"
    python tenzro_rpc.py register_model_endpoint gemma4-9b http://localhost:8000/v1
    python tenzro_rpc.py get_model_endpoint <instance_id>
    python tenzro_rpc.py unregister_model_endpoint <instance_id>
    python tenzro_rpc.py download_model gemma4-9b
    python tenzro_rpc.py get_download_progress gemma4-9b
    python tenzro_rpc.py serve_model gemma4-9b
    python tenzro_rpc.py stop_model gemma4-9b
    python tenzro_rpc.py delete_model gemma4-9b
    python tenzro_rpc.py swap_token TNZO USDC 1000000000000000000 0xsender
    python tenzro_rpc.py agent_pay_for_inference <agent_id> gemma4-9b 1000000000000000000
    python tenzro_rpc.py wrap_tnzo 0xaddress 1000000000000000000
    python tenzro_rpc.py list_proposals
    python tenzro_rpc.py create_proposal "Change fee" "Lower network fee to 0.3%"
    python tenzro_rpc.py vote <proposal_id> for
    python tenzro_rpc.py get_voting_power 0x<address>
    python tenzro_rpc.py delegate_voting_power 0xfrom 0xto
    python tenzro_rpc.py list_canton_domains
    python tenzro_rpc.py list_daml_contracts
    python tenzro_rpc.py submit_daml_command create MyTemplate party1
    python tenzro_rpc.py set_role Validator
    python tenzro_rpc.py list_providers llm
    python tenzro_rpc.py get_provider_schedule
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

    # Ecosystem MCP tools — Solana
    python tenzro_rpc.py solana_get_balance <address>
    python tenzro_rpc.py solana_get_price <token_id>
    python tenzro_rpc.py solana_swap <input_mint> <output_mint> <amount>
    python tenzro_rpc.py solana_get_slot
    python tenzro_rpc.py solana_get_tps

    # Ecosystem MCP tools — Ethereum
    python tenzro_rpc.py chainlink_get_price ETH/USD
    python tenzro_rpc.py eth_get_gas_price_ext
    python tenzro_rpc.py eth_resolve_ens vitalik.eth

    # Ecosystem MCP tools — LayerZero
    python tenzro_rpc.py lz_list_chains
    python tenzro_rpc.py lz_quote_fee 30101 30184 0x

    # Ecosystem MCP tools — Chainlink
    python tenzro_rpc.py ccip_get_supported_chains
    python tenzro_rpc.py ds_list_feeds

    # Ecosystem MCP tools — Canton
    python tenzro_rpc.py canton_get_health
    python tenzro_rpc.py canton_list_parties

    # OAuth 2.1 + DPoP onboarding
    python tenzro_rpc.py onboard_human "Alice"
    python tenzro_rpc.py onboard_delegated_agent did:tenzro:human:... '["inference"]' '{}'
    python tenzro_rpc.py onboard_autonomous_agent 0xbond_funding_address
    python tenzro_rpc.py revoke_jwt <jti> "lost device"
    python tenzro_rpc.py revoke_did did:tenzro:human:... "lost device"

    # AgentBond + Insurance (Spec 9)
    python tenzro_rpc.py get_agent_bond did:tenzro:machine:...
    python tenzro_rpc.py post_agent_bond 0xcontroller did:tenzro:machine:agent did:tenzro:human:owner 1000000000000000000000
    python tenzro_rpc.py file_insurance_claim did:tenzro:human:claimant 0xclaimant did:tenzro:machine:bad_agent 5000000000000000000 1
    python tenzro_rpc.py get_insurance_pool_balance

    # Adaptive Burn governance dial (Spec 8)
    python tenzro_rpc.py get_burn_rate_config
    python tenzro_rpc.py get_supply_metrics
    python tenzro_rpc.py get_burn_rate_recommendation

    # SeedAgent treasury (Spec 10)
    python tenzro_rpc.py get_treasury_earmark
    python tenzro_rpc.py list_seed_agents
    python tenzro_rpc.py get_network_activity 24h true

    # Mempool / dual-rail / hot-state (Specs 2, 3, 6)
    python tenzro_rpc.py get_burn_quota
    python tenzro_rpc.py get_mempool_stats
    python tenzro_rpc.py get_account_contention 0x<address>

    # Receipts & disputes
    python tenzro_rpc.py list_receipts_by_controller did:tenzro:human:...
    python tenzro_rpc.py summarize_controller did:tenzro:human:...
    python tenzro_rpc.py get_provider_reputation 0x<provider>
    python tenzro_rpc.py list_disputes_by_channel <channel_id>
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

RPC_URL = os.environ.get("TENZRO_RPC_URL", "https://rpc.tenzro.network")
API_URL = os.environ.get("TENZRO_API_URL", "https://api.tenzro.network")
RPC_TIMEOUT = int(os.environ.get("TENZRO_RPC_TIMEOUT", "120"))

# Ecosystem MCP server endpoints
SOLANA_MCP_URL = os.environ.get(
    "SOLANA_MCP_URL", "https://solana-mcp.tenzro.network/mcp")
ETHEREUM_MCP_URL = os.environ.get(
    "ETHEREUM_MCP_URL", "https://ethereum-mcp.tenzro.network/mcp")
LAYERZERO_MCP_URL = os.environ.get(
    "LAYERZERO_MCP_URL", "https://layerzero-mcp.tenzro.network/mcp")
CHAINLINK_MCP_URL = os.environ.get(
    "CHAINLINK_MCP_URL", "https://chainlink-mcp.tenzro.network/mcp")
CANTON_MCP_URL = os.environ.get(
    "CANTON_MCP_URL", "https://canton-mcp.tenzro.network/mcp")

_request_id = 0


def _rpc(method: str, params: Any = None) -> dict:
    """Send a JSON-RPC 2.0 request to Tenzro.

    Auth-sensitive RPCs (signing, escrow, settlement) require an OAuth/DPoP
    bearer JWT. Set the TENZRO_BEARER_JWT environment variable to your
    issued JWT and TENZRO_DPOP_PROOF to a fresh DPoP proof header value.
    The server validates both before invoking the auth-mediated signing
    path. Public RPCs (balance, status, block reads) work without auth.
    """
    global _request_id
    _request_id += 1
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params if params is not None else {},
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


def create_wallet(key_type: str = "ed25519") -> dict:
    """Generate a new self-custody Tenzro wallet (2-of-3 MPC, 32-byte address).

    Returns the canonical Tenzro wallet shape: `wallet_id`, 32-byte hex
    `address`, base58 `display_address`, `public_key`, `key_type`,
    `threshold`, `total_shares`. The faucet, `eth_getBalance`, and all
    transaction RPCs accept the 32-byte address directly.
    """
    return _rpc("tenzro_createWallet", {"key_type": key_type})


def get_balance(address: str) -> dict:
    """Get TNZO balance for an address (returns hex wei)."""
    result = _rpc("tenzro_getBalance", {"address": address})
    if isinstance(result, str):
        wei = int(result, 16)
        tnzo = wei / 1e18
        return {"address": address, "balance_wei": result, "balance_tnzo": f"{tnzo:.6f}"}
    return result


def send_transaction(from_addr: str, to_addr: str, value: int,
                     gas_limit: int = 21000,
                     gas_price: int = 1_000_000_000) -> dict:
    """Send a TNZO transfer transaction via ambient OAuth/DPoP auth.

    The server looks up the wallet bound to the bearer DID (set
    TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF environment variables) and
    signs the transaction on its behalf via tenzro_signAndSendTransaction
    — the node constructs the canonical Transaction::hash() preimage
    including the PQ public key, signs both Ed25519 and ML-DSA-65 legs,
    verifies them, and submits atomically. Private keys never travel
    over the wire.
    """
    nonce_result = _rpc("eth_getTransactionCount", [from_addr, "latest"])
    nonce = int(nonce_result, 16) if isinstance(nonce_result, str) else 0

    chain_id_result = _rpc("eth_chainId", [])
    chain_id = int(chain_id_result, 16) if isinstance(chain_id_result, str) else 1337

    return _rpc("tenzro_signAndSendTransaction", {
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "nonce": nonce,
        "chain_id": chain_id,
    })


def sign_transaction(from_addr: str, to_addr: str, value: int,
                     gas_limit: int = 21000,
                     gas_price: int = 1_000_000_000,
                     nonce: int = None,
                     chain_id: int = None) -> dict:
    """Sign a transaction server-side without submitting it.

    Uses ambient OAuth/DPoP auth — the bearer JWT identifies which wallet
    the server should use to sign. Returns a dict with the classical
    Ed25519 signature + public_key, the ML-DSA-65 pq_signature +
    pq_public_key, the server-canonical timestamp, and the resulting
    tx_hash. The caller can later submit by passing those fields to
    eth_sendRawTransaction unchanged.
    """
    if nonce is None:
        nonce_result = _rpc("eth_getTransactionCount", [from_addr, "latest"])
        nonce = int(nonce_result, 16) if isinstance(nonce_result, str) else 0

    if chain_id is None:
        chain_id_result = _rpc("eth_chainId", [])
        chain_id = int(chain_id_result, 16) if isinstance(chain_id_result, str) else 1337

    return _rpc("tenzro_signTransaction", {
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "nonce": nonce,
        "chain_id": chain_id,
    })


def sign_and_send(from_addr: str, to_addr: str,
                  amount_tnzo: float) -> dict:
    """Sign and send a TNZO transfer in one call.

    Uses ambient OAuth/DPoP auth (TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF
    env vars) — no private key required.

    Args:
        from_addr: Sender hex address (must match the bearer's wallet)
        to_addr: Recipient hex address
        amount_tnzo: Amount in TNZO (e.g., 1.5 for 1.5 TNZO)

    Returns:
        Transaction result with tx_hash
    """
    value_wei = int(amount_tnzo * 1_000_000_000_000_000_000)
    return send_transaction(
        from_addr=from_addr,
        to_addr=to_addr,
        value=value_wei,
    )


# ── Faucet ────────────────────────────────────────────────────────


def request_faucet(address: str) -> dict:
    """Request testnet TNZO from the faucet (100 TNZO, 24h cooldown).

    Use the hex public key (from create_wallet 'address' field) as the address.
    """
    # Try RPC first (more reliable), fall back to Web API
    result = _rpc("tenzro_faucet", {"address": address})
    if result and "error" not in result:
        return result
    return _api_post("/faucet", {"address": address})


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
    return _rpc("tenzro_nodeInfo")


# ── Identity ──────────────────────────────────────────────────────


def register_identity(display_name: str, public_key: str = None,
                      key_type: str = "ed25519") -> dict:
    """Register a human identity and get a DID."""
    params = {"display_name": display_name}
    if public_key:
        params["public_key"] = public_key
        params["key_type"] = key_type
    return _rpc("tenzro_registerIdentity", params)


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

    Zero-install — auto-provisions a TDIP DID and MPC wallet.
    Returns full identity, wallet, capabilities, network endpoints, and chain ID.
    Falls back to tenzro_participate for older nodes.
    """
    params = {
        "display_name": display_name.lstrip("@"),
        "origin": origin,
        "participant_type": participant_type,
    }
    result = _rpc("tenzro_joinAsMicroNode", params)
    if "error" in result:
        # Fall back to legacy tenzro_participate
        result = _rpc("tenzro_participate", {"display_name": display_name.lstrip("@")})
    return result


def set_username(did: str, username: str) -> dict:
    """Set a human-readable username for a DID.

    did: the DID to attach the username to (e.g. did:tenzro:human:<uuid>)
    username: the desired username (unique across the network)
    """
    return _rpc("tenzro_setUsername", [{"did": did, "username": username}])


def resolve_username(username: str) -> dict:
    """Resolve a username to its associated DID and identity info.

    username: the username to look up
    """
    return _rpc("tenzro_resolveUsername", [{"username": username}])


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
                           measurement: str = None) -> dict:
    """Verify a TEE attestation via Web API."""
    body = {"vendor": vendor, "report_data": report_data}
    if measurement:
        body["measurement"] = measurement
    return _api_post("/verify/tee-attestation", body)


# ── Token ─────────────────────────────────────────────────────────


def total_supply() -> dict:
    """Get total TNZO token supply."""
    return _rpc("tenzro_totalSupply")


def token_balance(address: str) -> dict:
    """Get TNZO token balance for an address."""
    return _rpc("tenzro_tokenBalance", {"address": address})


# ── Token Registry & Contracts ───────────────────────────────────


def create_token(name: str, symbol: str, creator: str,
                 initial_supply: str, decimals: int = 18,
                 mintable: bool = False, burnable: bool = False) -> dict:
    """Create an ERC-20 token via the factory and register in the unified registry.

    name: human-readable token name (e.g. "My Token")
    symbol: ticker symbol (e.g. "MYT")
    creator: creator address (0x-prefixed hex, 20 or 32 bytes)
    initial_supply: total initial supply as a decimal string (in smallest unit)
    decimals: token decimal places (default 18)
    mintable: allow minting beyond initial supply (default False)
    burnable: allow burning tokens (default False)
    """
    params = {
        "name": name,
        "symbol": symbol,
        "creator": creator,
        "initial_supply": initial_supply,
        "decimals": decimals,
    }
    if mintable:
        params["mintable"] = True
    if burnable:
        params["burnable"] = True
    return _rpc("tenzro_createToken", params)


def get_token_info(symbol: str = None, evm_address: str = None,
                   token_id: str = None) -> dict:
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


def list_tokens(vm_type: str = None, limit: int = 50) -> dict:
    """List registered tokens in the unified token registry.

    vm_type: optional filter — evm | svm | daml | native
    limit: max tokens to return (default 50, max 100)
    """
    params = {}
    if vm_type:
        params["vm_type"] = vm_type
    if limit != 50:
        params["limit"] = limit
    return _rpc("tenzro_listTokens", params)


def get_token_balance_all_vms(address: str) -> dict:
    """Get TNZO balance across all VMs (native, EVM wTNZO, SVM wTNZO, DAML holding).

    Returns balances with decimal conversion for each VM representation.
    """
    return _rpc("tenzro_getTokenBalance", {"address": address})


def cross_vm_transfer(token: str, amount: str, from_vm: str, to_vm: str,
                      from_address: str, to_address: str) -> dict:
    """Transfer tokens atomically between VMs using the pointer model.

    token: token symbol (e.g. "TNZO") or token ID
    amount: transfer amount as a decimal string (in smallest unit)
    from_vm/to_vm: evm | svm | daml | native
    from_address/to_address: 0x-prefixed hex addresses
    """
    return _rpc("tenzro_crossVmTransfer", {
        "token": token,
        "amount": amount,
        "from_vm": from_vm,
        "to_vm": to_vm,
        "from_address": from_address,
        "to_address": to_address,
    })


def deploy_contract(vm_type: str, bytecode: str, deployer: str,
                    constructor_args: str = None,
                    gas_limit: int = 3_000_000) -> dict:
    """Deploy smart contract bytecode to EVM, SVM, or DAML.

    vm_type: evm | svm | daml
    bytecode: 0x-prefixed hex contract bytecode
    deployer: 0x-prefixed hex deployer address
    constructor_args: optional 0x-prefixed hex ABI-encoded constructor arguments
    gas_limit: gas limit for deployment (default 3,000,000)
    """
    params = {
        "vm_type": vm_type,
        "bytecode": bytecode,
        "deployer": deployer,
        "gas_limit": gas_limit,
    }
    if constructor_args:
        params["constructor_args"] = constructor_args
    return _rpc("tenzro_deployContract", params)


# ── Models ────────────────────────────────────────────────────────


def list_models() -> dict:
    """List registered AI models."""
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


# ── Payments ──────────────────────────────────────────────────────


def create_payment_challenge(protocol: str, resource: str, amount: int,
                             asset: str = "TNZO",
                             recipient: str = None) -> dict:
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


def set_delegation_scope(machine_did: str, max_transaction_value: int,
                         max_daily_spend: int,
                         allowed_operations: list = None,
                         allowed_chains: list = None) -> dict:
    """Set delegation scope for a machine DID."""
    params = {
        "machine_did": machine_did,
        "max_transaction_value": max_transaction_value,
        "max_daily_spend": max_daily_spend,
    }
    if allowed_operations:
        params["allowed_operations"] = allowed_operations
    if allowed_chains:
        params["allowed_chains"] = allowed_chains
    return _rpc("tenzro_setDelegationScope", params)


# ── Task Marketplace ─────────────────────────────────────────────


def post_task(title: str, description: str, task_type: str,
              budget_wei: int, required_capabilities: list = None) -> dict:
    """Post a task to the decentralized AI task marketplace.

    task_type: inference | code_review | data_analysis | content_generation |
               agent_execution | translation | research | custom:<name>
    budget_wei: maximum budget in wei
    """
    params = {
        "title": title,
        "description": description,
        "task_type": task_type,
        "budget": budget_wei,
    }
    if required_capabilities:
        params["required_capabilities"] = required_capabilities
    return _rpc("tenzro_postTask", params)


def list_tasks(status: str = None, task_type: str = None) -> dict:
    """List tasks on the marketplace, optionally filtered."""
    params = {}
    if status:
        params["status"] = status
    if task_type:
        params["task_type"] = task_type
    return _rpc("tenzro_listTasks", params)


def get_task(task_id: str) -> dict:
    """Get details of a specific task."""
    return _rpc("tenzro_getTask", {"task_id": task_id})


def cancel_task(task_id: str) -> dict:
    """Cancel a task (poster only)."""
    return _rpc("tenzro_cancelTask", {"task_id": task_id})


def submit_quote(task_id: str, price_wei: int, model_id: str = None,
                 estimated_time_secs: int = None) -> dict:
    """Submit a quote for a task as a provider/agent."""
    params = {
        "task_id": task_id,
        "price": price_wei,
    }
    if model_id:
        params["model_id"] = model_id
    if estimated_time_secs is not None:
        params["estimated_time"] = estimated_time_secs
    return _rpc("tenzro_submitQuote", params)


# ── Agent Template Marketplace ───────────────────────────────────


def list_agent_templates(agent_type: str = None) -> dict:
    """List available agent templates.

    agent_type: autonomous | tool_agent | orchestrator | specialist | multi_modal
    """
    params = {}
    if agent_type:
        params["agent_type"] = agent_type
    return _rpc("tenzro_listAgentTemplates", params)


def register_agent_template(name: str, description: str,
                            agent_type: str,
                            system_prompt: str = None,
                            capabilities: list = None) -> dict:
    """Register a new agent template on the marketplace."""
    params = {
        "name": name,
        "description": description,
        "agent_type": agent_type,
    }
    if system_prompt:
        params["system_prompt"] = system_prompt
    if capabilities:
        params["capabilities"] = capabilities
    return _rpc("tenzro_registerAgentTemplate", params)


def get_agent_template(template_id: str) -> dict:
    """Get details of a specific agent template."""
    return _rpc("tenzro_getAgentTemplate", {"template_id": template_id})


def spawn_agent_from_template(template_id: str, name: str,
                              capabilities: list = None,
                              parent_machine_did: str = None) -> dict:
    """Spawn a new agent from a marketplace template.

    template_id: the template to instantiate
    name: display name for the spawned agent
    capabilities: optional additional capabilities beyond the template defaults
    parent_machine_did: optional parent machine DID. When set, the spawned
        agent's effective delegation scope is the strict intersection of the
        parent's scope and the template's spec — the child can never be
        broader than its parent on any axis (numeric ceilings, allow-lists,
        time bound).
    """
    params = {
        "template_id": template_id,
        "name": name,
    }
    if capabilities:
        params["capabilities"] = capabilities
    if parent_machine_did:
        params["parent_machine_did"] = parent_machine_did
    return _rpc("tenzro_spawnAgentFromTemplate", params)


def rate_agent_template(template_id: str, rating: int,
                        review: str = None) -> dict:
    """Rate an agent template (1-5 stars) with an optional text review.

    template_id: the template to rate
    rating: integer 1-5
    review: optional review text
    """
    params = {
        "template_id": template_id,
        "rating": rating,
    }
    if review:
        params["review"] = review
    return _rpc("tenzro_rateAgentTemplate", params)


def search_agent_templates(query: str, agent_type: str = None,
                           limit: int = 20) -> dict:
    """Search agent templates by free-text query.

    query: search query string
    agent_type: optional filter — autonomous | tool_agent | orchestrator | specialist | multi_modal
    limit: max results to return (default 20)
    """
    params = {"query": query}
    if agent_type:
        params["agent_type"] = agent_type
    if limit != 20:
        params["limit"] = limit
    return _rpc("tenzro_searchAgentTemplates", params)


def get_agent_template_stats(template_id: str) -> dict:
    """Get usage statistics for an agent template.

    Returns spawn count, average rating, total reviews, and revenue.
    """
    return _rpc("tenzro_getAgentTemplateStats", {"template_id": template_id})


# ── Skills Registry ──────────────────────────────────────────────


def list_skills(tag: str = None, creator_did: str = None,
                max_price: int = None, active_only: bool = True,
                limit: int = 50, offset: int = 0) -> dict:
    """List skills in the decentralized Skills Registry."""
    params = {"active_only": active_only}
    if tag:
        params["tag"] = tag
    if creator_did:
        params["creator_did"] = creator_did
    if max_price is not None:
        params["max_price"] = max_price
    if limit != 50:
        params["limit"] = limit
    if offset > 0:
        params["offset"] = offset
    return _rpc("tenzro_listSkills", params)


def register_skill(name: str, version: str, creator_did: str,
                   description: str, price_per_call: int,
                   tags: list = None, required_capabilities: list = None,
                   endpoint: str = None, input_schema: dict = None,
                   output_schema: dict = None) -> dict:
    """Register a new skill in the Skills Registry."""
    params = {
        "name": name,
        "version": version,
        "creator_did": creator_did,
        "description": description,
        "price_per_call": price_per_call,
    }
    if tags:
        params["tags"] = tags
    if required_capabilities:
        params["required_capabilities"] = required_capabilities
    if endpoint:
        params["endpoint"] = endpoint
    if input_schema:
        params["input_schema"] = input_schema
    if output_schema:
        params["output_schema"] = output_schema
    return _rpc("tenzro_registerSkill", params)


def search_skills(query: str, tag: str = None, max_price: int = None,
                  limit: int = 20) -> dict:
    """Search skills by free-text query."""
    params = {"query": query, "active_only": True}
    if tag:
        params["tag"] = tag
    if max_price is not None:
        params["max_price"] = max_price
    if limit != 20:
        params["limit"] = limit
    return _rpc("tenzro_searchSkills", params)


def use_skill(skill_id: str, input_data: dict = None) -> dict:
    """Invoke a skill by ID with given input payload."""
    return _rpc("tenzro_useSkill", {
        "skill_id": skill_id,
        "input": input_data or {},
    })


def get_skill_usage(skill_id: str) -> dict:
    """Get usage statistics for a skill.

    Returns total invocations, unique callers, revenue, and average latency.
    """
    return _rpc("tenzro_getSkillUsage", [{"skill_id": skill_id}])


def get_tool_usage(tool_id: str) -> dict:
    """Get usage statistics for a tool.

    Returns total invocations, unique callers, error rate, and average latency.
    """
    return _rpc("tenzro_getToolUsage", [{"tool_id": tool_id}])


def spawn_agent_with_skill(parent_id: str, name: str, skill_id: str,
                           capabilities: list = None) -> dict:
    """Spawn a new agent pre-configured with a specific skill."""
    params = {
        "parent_id": parent_id,
        "name": name,
        "skill_id": skill_id,
    }
    if capabilities:
        params["capabilities"] = capabilities
    return _rpc("tenzro_spawnAgentWithSkill", params)


# ── Agent Spawning & Swarm ───────────────────────────────────────


def register_agent(name: str, address: str,
                   capabilities: list = None) -> dict:
    """Register a new AI agent with identity and wallet."""
    params = {
        "name": name,
        "address": address,
    }
    if capabilities:
        params["capabilities"] = capabilities
    return _rpc("tenzro_registerAgent", params)


def spawn_agent(parent_id: str, name: str,
                capabilities: list = None) -> dict:
    """Spawn a sub-agent from a parent agent."""
    params = {
        "parent_id": parent_id,
        "name": name,
    }
    if capabilities:
        params["capabilities"] = capabilities
    return _rpc("tenzro_spawnAgent", params)


def run_agent_task(agent_id: str, task: str,
                   max_steps: int = 10) -> dict:
    """Run an autonomous task via the agentic execution loop."""
    return _rpc("tenzro_runAgentTask", {
        "agent_id": agent_id,
        "task": task,
        "max_steps": max_steps,
    })


def create_swarm(orchestrator_id: str,
                 members: list) -> dict:
    """Create a swarm of agents coordinated by an orchestrator.

    members: list of dicts with 'name' and 'capabilities' keys,
             or strings like 'researcher:nlp,data'
    """
    parsed = []
    for m in members:
        if isinstance(m, dict):
            parsed.append(m)
        elif isinstance(m, str) and ":" in m:
            name, caps = m.split(":", 1)
            parsed.append({
                "name": name,
                "capabilities": caps.split(","),
            })
        else:
            parsed.append({"name": str(m), "capabilities": []})
    return _rpc("tenzro_createSwarm", {
        "orchestrator_id": orchestrator_id,
        "members": parsed,
    })


def get_swarm_status(swarm_id: str) -> dict:
    """Get the status of a swarm and its members."""
    return _rpc("tenzro_getSwarmStatus", {"swarm_id": swarm_id})


def terminate_swarm(swarm_id: str) -> dict:
    """Terminate a swarm and all its member agents."""
    return _rpc("tenzro_terminateSwarm", {"swarm_id": swarm_id})


# ── Cross-Chain Bridge ───────────────────────────────────────────


def bridge_tokens(source_chain: str, dest_chain: str, asset: str,
                  amount_wei: int, sender: str,
                  recipient: str) -> dict:
    """Bridge tokens between chains.

    source_chain/dest_chain: tenzro | ethereum | solana | base
    asset: TNZO, USDC, etc.
    """
    return _rpc("tenzro_bridgeTokens", {
        "source_chain": source_chain,
        "destination_chain": dest_chain,
        "asset": asset,
        "amount": amount_wei,
        "sender": sender,
        "recipient": recipient,
    })


# ── Staking & Providers ─────────────────────────────────────────


def stake_tokens(amount_wei: int,
                 role: str = "Validator") -> dict:
    """Stake TNZO tokens.

    role: Validator | ModelProvider | TeeProvider
    """
    return _rpc("tenzro_stake", {
        "amount": amount_wei,
        "role": role,
    })


def unstake_tokens(amount_wei: int) -> dict:
    """Unstake TNZO tokens (initiates unbonding period)."""
    return _rpc("tenzro_unstake", {"amount": amount_wei})


def register_provider(provider_type: str) -> dict:
    """Register as a provider (model-provider or tee-provider)."""
    return _rpc("tenzro_registerProvider", {
        "provider_type": provider_type,
    })


def provider_stats() -> dict:
    """Get provider statistics (served models, inferences, staking)."""
    return _rpc("tenzro_providerStats")


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


def create_nft_collection(name: str, symbol: str, creator: str,
                          standard: str = "erc721") -> dict:
    """Create a new NFT collection.

    name: collection display name
    symbol: short symbol (e.g. TNFT)
    creator: address of the collection creator
    standard: token standard — erc721 or erc1155
    """
    return _rpc("tenzro_createNftCollection", {
        "name": name,
        "symbol": symbol,
        "creator": creator,
        "standard": standard,
    })


def mint_nft(collection_id: str, to: str, token_id: str,
             uri: str) -> dict:
    """Mint a single NFT in a collection.

    collection_id: the collection to mint into
    to: recipient address
    token_id: unique token ID within the collection
    uri: metadata URI for the token
    """
    return _rpc("tenzro_mintNft", {
        "collection_id": collection_id,
        "to": to,
        "token_id": token_id,
        "uri": uri,
    })


def mint_nft_batch(collection_id: str, to: str, token_ids: list,
                   uris: list) -> dict:
    """Mint multiple NFTs in a single transaction.

    collection_id: the collection to mint into
    to: recipient address
    token_ids: list of unique token IDs
    uris: list of metadata URIs (must match token_ids length)
    """
    return _rpc("tenzro_mintNftBatch", {
        "collection_id": collection_id,
        "to": to,
        "token_ids": token_ids,
        "uris": uris,
    })


def transfer_nft(collection_id: str, from_addr: str, to: str,
                 token_id: str) -> dict:
    """Transfer an NFT to another address.

    collection_id: the collection containing the token
    from_addr: current owner address
    to: recipient address
    token_id: token ID to transfer
    """
    return _rpc("tenzro_transferNft", {
        "collection_id": collection_id,
        "from": from_addr,
        "to": to,
        "token_id": token_id,
    })


def get_nft_owner(collection_id: str, token_id: str) -> dict:
    """Get the owner of a specific NFT."""
    return _rpc("tenzro_getNftOwner", {
        "collection_id": collection_id,
        "token_id": token_id,
    })


def get_nft_balance(collection_id: str, address: str) -> dict:
    """Get the number of NFTs an address owns in a collection."""
    return _rpc("tenzro_getNftBalance", {
        "collection_id": collection_id,
        "address": address,
    })


def get_nft_collection(collection_id: str) -> dict:
    """Get details of an NFT collection (name, symbol, total supply, standard)."""
    return _rpc("tenzro_getNftCollection", {"collection_id": collection_id})


def list_nft_collections(limit: int = 50) -> dict:
    """List all NFT collections on the network."""
    params = {}
    if limit != 50:
        params["limit"] = limit
    return _rpc("tenzro_listNftCollections", params)


# ── Bridge (Extended) ────────────────────────────────────────────


def bridge_quote(from_chain: str, to_chain: str, token: str,
                 amount: int, protocol: str = None) -> dict:
    """Get a fee quote for bridging tokens between chains.

    from_chain: source chain (tenzro, ethereum, solana, base, etc.)
    to_chain: destination chain
    token: token symbol (TNZO, USDC, etc.)
    amount: amount in wei
    protocol: optional bridge protocol (layerzero, ccip, debridge)
    """
    params = {
        "from_chain": from_chain,
        "to_chain": to_chain,
        "token": token,
        "amount": amount,
    }
    if protocol:
        params["protocol"] = protocol
    return _rpc("tenzro_bridgeQuote", params)


def bridge_execute(from_chain: str, to_chain: str, token: str,
                   amount: int, sender: str, recipient: str,
                   protocol: str = None) -> dict:
    """Execute a cross-chain token bridge transfer.

    from_chain: source chain
    to_chain: destination chain
    token: token symbol
    amount: amount in wei
    sender: sender address on source chain
    recipient: recipient address on destination chain
    protocol: optional bridge protocol to use
    """
    params = {
        "from_chain": from_chain,
        "to_chain": to_chain,
        "token": token,
        "amount": amount,
        "sender": sender,
        "recipient": recipient,
    }
    if protocol:
        params["protocol"] = protocol
    return _rpc("tenzro_bridgeExecute", params)


def bridge_status(transfer_id: str, protocol: str = None) -> dict:
    """Check the status of a cross-chain bridge transfer.

    transfer_id: the bridge transfer ID or tx hash
    protocol: optional bridge protocol to query
    """
    params = {"transfer_id": transfer_id}
    if protocol:
        params["protocol"] = protocol
    return _rpc("tenzro_bridgeStatus", params)


def bridge_with_hook(from_chain: str, to_chain: str, token: str,
                     amount: int, sender: str, hook_target: str,
                     hook_calldata: str,
                     revert_on_fail: bool = True) -> dict:
    """Bridge tokens with a post-delivery hook (compose call on destination).

    from_chain: source chain
    to_chain: destination chain
    token: token symbol
    amount: amount in wei
    sender: sender address
    hook_target: contract address to call on destination after delivery
    hook_calldata: hex-encoded calldata for the hook
    revert_on_fail: if True, revert the bridge if the hook fails
    """
    return _rpc("tenzro_bridgeWithHook", {
        "from_chain": from_chain,
        "to_chain": to_chain,
        "token": token,
        "amount": amount,
        "sender": sender,
        "hook_target": hook_target,
        "hook_calldata": hook_calldata,
        "revert_on_fail": revert_on_fail,
    })


# ── deBridge Cross-Chain ────────────────────────────────────────


def debridge_search_tokens(query, chain_id=None):
    """Search for tokens on deBridge DLN."""
    params = {"query": query}
    if chain_id:
        params["chain_id"] = int(chain_id)
    return _rpc("tenzro_debridgeSearchTokens", params)


def debridge_get_chains():
    """List all chains supported by deBridge DLN."""
    return _rpc("tenzro_debridgeGetChains", {})


def debridge_get_instructions():
    """Get deBridge operational instructions."""
    return _rpc("tenzro_debridgeGetInstructions", {})


def debridge_create_tx(src_chain, dst_chain, src_token, dst_token,
                       amount, recipient):
    """Create a cross-chain transaction via deBridge DLN."""
    return _rpc("tenzro_debridgeCreateTx", {
        "src_chain_id": int(src_chain),
        "dst_chain_id": int(dst_chain),
        "src_token": src_token,
        "dst_token": dst_token,
        "amount": amount,
        "recipient": recipient,
    })


def debridge_same_chain_swap(chain_id, token_in, token_out, amount):
    """Same-chain token swap via deBridge."""
    return _rpc("tenzro_debridgeSameChainSwap", {
        "chain_id": int(chain_id),
        "token_in": token_in,
        "token_out": token_out,
        "amount": amount,
    })


# ── ERC-7802 Crosschain Token ───────────────────────────────────


def crosschain_mint(bridge: str, to: str, amount: int,
                    sender: str) -> dict:
    """Mint tokens via an authorized crosschain bridge (ERC-7802).

    bridge: authorized bridge address
    to: recipient address
    amount: amount in wei to mint
    sender: address initiating the crosschain mint
    """
    return _rpc("tenzro_crosschainMint", {
        "bridge": bridge,
        "to": to,
        "amount": amount,
        "sender": sender,
    })


def crosschain_burn(bridge: str, from_addr: str, amount: int,
                    destination: str) -> dict:
    """Burn tokens for crosschain transfer (ERC-7802).

    bridge: authorized bridge address
    from_addr: address whose tokens are burned
    amount: amount in wei to burn
    destination: destination chain identifier or address
    """
    return _rpc("tenzro_crosschainBurn", {
        "bridge": bridge,
        "from": from_addr,
        "amount": amount,
        "destination": destination,
    })


def authorize_bridge(bridge: str, name: str,
                     daily_mint_limit: int = None,
                     daily_burn_limit: int = None) -> dict:
    """Authorize a bridge for crosschain mint/burn operations (ERC-7802).

    bridge: bridge contract address to authorize
    name: human-readable bridge name
    daily_mint_limit: optional daily mint cap in wei
    daily_burn_limit: optional daily burn cap in wei
    """
    params = {
        "bridge": bridge,
        "name": name,
    }
    if daily_mint_limit is not None:
        params["daily_mint_limit"] = daily_mint_limit
    if daily_burn_limit is not None:
        params["daily_burn_limit"] = daily_burn_limit
    return _rpc("tenzro_authorizeBridge", params)


def list_authorized_bridges() -> dict:
    """List all authorized crosschain bridges (ERC-7802)."""
    return _rpc("tenzro_listAuthorizedBridges")


# ── ERC-3643 Compliance ─────────────────────────────────────────


def check_compliance(token_id: str, from_addr: str, to: str,
                     amount: int) -> dict:
    """Check if a transfer is compliant under ERC-3643 rules.

    token_id: the regulated token ID or symbol
    from_addr: sender address
    to: recipient address
    amount: transfer amount in wei
    """
    return _rpc("tenzro_checkCompliance", {
        "token_id": token_id,
        "from": from_addr,
        "to": to,
        "amount": amount,
    })


def register_compliance(token_id: str, require_kyc: bool = False,
                        min_kyc_tier: int = 1,
                        require_accreditation: bool = False,
                        max_holders: int = None,
                        max_transfer_amount: int = None) -> dict:
    """Register compliance rules for a token (ERC-3643).

    token_id: token to attach rules to
    require_kyc: require KYC verification for holders
    min_kyc_tier: minimum KYC tier (1-3) if require_kyc is True
    require_accreditation: require accredited investor status
    max_holders: optional cap on total token holders
    max_transfer_amount: optional max single transfer amount in wei
    """
    params = {
        "token_id": token_id,
        "require_kyc": require_kyc,
        "min_kyc_tier": min_kyc_tier,
        "require_accreditation": require_accreditation,
    }
    if max_holders is not None:
        params["max_holders"] = max_holders
    if max_transfer_amount is not None:
        params["max_transfer_amount"] = max_transfer_amount
    return _rpc("tenzro_registerCompliance", params)


def freeze_address(token_id: str, address: str,
                   reason: str) -> dict:
    """Freeze an address from transferring a regulated token (ERC-3643).

    token_id: the regulated token ID
    address: address to freeze
    reason: reason for freezing (e.g. "sanctions", "investigation")
    """
    return _rpc("tenzro_freezeAddress", {
        "token_id": token_id,
        "address": address,
        "reason": reason,
    })


def unfreeze_address(token_id: str, address: str) -> dict:
    """Unfreeze a previously frozen address (ERC-3643).

    token_id: the regulated token ID
    address: address to unfreeze
    """
    return _rpc("tenzro_unfreezeAddress", {
        "token_id": token_id,
        "address": address,
    })


def recover_tokens(token_id: str, from_addr: str, to: str,
                   amount: int, reason: str) -> dict:
    """Recover tokens from an address (ERC-3643 forced transfer).

    token_id: the regulated token ID
    from_addr: address to recover from
    to: address to send recovered tokens to
    amount: amount in wei to recover
    reason: regulatory reason for recovery
    """
    return _rpc("tenzro_recoverTokens", {
        "token_id": token_id,
        "from": from_addr,
        "to": to,
        "amount": amount,
        "reason": reason,
    })


def add_identity_claim(address: str, topic: str, issuer: str,
                       data: str = "", valid_from: str = None,
                       valid_to: str = None) -> dict:
    """Add an identity claim to an address for compliance verification.

    address: the address to add the claim for
    topic: claim topic (e.g. "kyc", "accredited_investor", "jurisdiction")
    issuer: DID of the claim issuer
    data: optional claim data payload
    valid_from: optional ISO-8601 start time
    valid_to: optional ISO-8601 expiry time
    """
    params = {
        "address": address,
        "topic": topic,
        "issuer": issuer,
        "data": data,
    }
    if valid_from:
        params["valid_from"] = valid_from
    if valid_to:
        params["valid_to"] = valid_to
    return _rpc("tenzro_addIdentityClaim", params)


def add_trusted_issuer(issuer_did: str, name: str,
                       topics: list) -> dict:
    """Register a trusted claim issuer for compliance verification.

    issuer_did: DID of the trusted issuer
    name: human-readable name of the issuer
    topics: list of claim topics this issuer is trusted for
    """
    return _rpc("tenzro_addTrustedIssuer", {
        "issuer_did": issuer_did,
        "name": name,
        "topics": topics,
    })


# ── Events & Webhooks ────────────────────────────────────────────


def get_events(filter: dict = None, from_sequence: int = None,
               limit: int = 100) -> dict:
    """Get events from the network event stream.

    filter: optional filter dict (e.g. {"type": "transfer", "token": "TNZO"})
    from_sequence: optional sequence number to resume from
    limit: max events to return (default 100)
    """
    params = {}
    if filter:
        params["filter"] = filter
    if from_sequence is not None:
        params["from_sequence"] = from_sequence
    if limit != 100:
        params["limit"] = limit
    return _rpc("tenzro_getEvents", params)


def get_event_status() -> dict:
    """Get the current event stream status (latest sequence, lag, etc.)."""
    return _rpc("tenzro_getEventStatus")


def register_webhook(url: str, filter: dict = None,
                     secret: str = "",
                     confirmed_delivery: bool = False) -> dict:
    """Register a webhook for real-time event delivery.

    url: HTTPS endpoint to receive POST callbacks
    filter: optional event filter dict
    secret: optional HMAC secret for verifying webhook payloads
    confirmed_delivery: if True, retry delivery until confirmed
    """
    params = {"url": url}
    if filter:
        params["filter"] = filter
    if secret:
        params["secret"] = secret
    if confirmed_delivery:
        params["confirmed_delivery"] = confirmed_delivery
    return _rpc("tenzro_registerWebhook", params)


def list_webhooks() -> dict:
    """List all registered webhooks."""
    return _rpc("tenzro_listWebhooks")


def delete_webhook(webhook_id: str) -> dict:
    """Delete a registered webhook.

    webhook_id: the webhook ID to remove
    """
    return _rpc("tenzro_deleteWebhook", {"webhook_id": webhook_id})


# ── Tools Registry ──────────────────────────────────────────────


def register_tool(name: str, description: str, endpoint: str,
                  tool_type: str = "mcp", capabilities: list = None,
                  category: str = "general", version: str = "1.0.0",
                  creator_did: str = None) -> dict:
    """Register a new tool (MCP server endpoint) in the Tools Registry.

    name: tool name
    description: tool description
    endpoint: MCP server endpoint URL
    tool_type: mcp | api | native (default mcp)
    capabilities: list of capabilities (e.g. ["web-search", "code-execution"])
    category: tool category (e.g. "search", "code", "data")
    version: version string
    creator_did: optional creator DID
    """
    params = {
        "name": name,
        "description": description,
        "endpoint": endpoint,
        "tool_type": tool_type,
        "category": category,
        "version": version,
    }
    if capabilities:
        params["capabilities"] = capabilities
    if creator_did:
        params["creator_did"] = creator_did
    return _rpc("tenzro_registerTool", [params])


def list_tools(tool_type: str = None, category: str = None,
               status: str = None, limit: int = 20) -> dict:
    """List registered tools (MCP servers) on the network.

    tool_type: optional filter — mcp | api | native
    category: optional category filter
    status: optional — active | inactive | available
    limit: max tools to return (default 20)
    """
    params = {"limit": limit}
    if tool_type:
        params["tool_type"] = tool_type
    if category:
        params["category"] = category
    if status:
        params["status"] = status
    return _rpc("tenzro_listTools", [params])


def get_tool(tool_id: str) -> dict:
    """Get details of a specific tool by ID."""
    return _rpc("tenzro_getTool", [{"tool_id": tool_id}])


def search_tools(query: str, limit: int = 10) -> dict:
    """Search for tools by keyword."""
    return _rpc("tenzro_searchTools", [{"query": query, "limit": limit}])


def use_tool(tool_id: str, params: dict = None,
             tool_name: str = None) -> dict:
    """Invoke a tool via its MCP endpoint.

    tool_id: tool ID to invoke
    params: input parameters dict
    tool_name: optional specific MCP tool name to call
    """
    call_params = {
        "tool_id": tool_id,
        "params": params or {},
    }
    if tool_name:
        call_params["tool_name"] = tool_name
    return _rpc("tenzro_useTool", [call_params])


def update_tool(tool_id: str, description: str = None,
                endpoint: str = None, version: str = None,
                capabilities: list = None,
                status: str = None) -> dict:
    """Update an existing tool registration.

    tool_id: tool to update
    Only provided fields are updated.
    """
    params = {"tool_id": tool_id}
    if description:
        params["description"] = description
    if endpoint:
        params["endpoint"] = endpoint
    if version:
        params["version"] = version
    if capabilities:
        params["capabilities"] = capabilities
    if status:
        params["status"] = status
    return _rpc("tenzro_updateTool", [params])


# ── Skills Registry (Extended) ──────────────────────────────────


def get_skill(skill_id: str) -> dict:
    """Get details of a specific skill by ID."""
    return _rpc("tenzro_getSkill", [{"skill_id": skill_id}])


def update_skill(skill_id: str, description: str = None,
                 version: str = None, price_per_call: int = None,
                 tags: list = None, endpoint: str = None,
                 status: str = None) -> dict:
    """Update an existing skill registration.

    skill_id: skill to update
    Only provided fields are updated.
    """
    params = {"skill_id": skill_id}
    if description:
        params["description"] = description
    if version:
        params["version"] = version
    if price_per_call is not None:
        params["price_per_call"] = price_per_call
    if tags:
        params["tags"] = tags
    if endpoint:
        params["endpoint"] = endpoint
    if status:
        params["status"] = status
    return _rpc("tenzro_updateSkill", [params])


# ── Task Marketplace (Extended) ─────────────────────────────────


def assign_task(task_id: str, provider: str) -> dict:
    """Assign a task to a specific provider/agent.

    task_id: the task to assign
    provider: provider address or agent ID to assign to
    """
    return _rpc("tenzro_assignTask", [{"task_id": task_id, "provider": provider}])


def complete_task(task_id: str, result: str) -> dict:
    """Submit the result for a completed task.

    task_id: the task being completed
    result: result data or output text
    """
    return _rpc("tenzro_completeTask", [{"task_id": task_id, "result": result}])


def update_task(task_id: str, status: str = None,
                description: str = None, budget_wei: int = None) -> dict:
    """Update an existing task.

    task_id: task to update
    Only provided fields are updated.
    """
    params = {"task_id": task_id}
    if status:
        params["status"] = status
    if description:
        params["description"] = description
    if budget_wei is not None:
        params["budget"] = budget_wei
    return _rpc("tenzro_updateTask", [params])


# ── Agent Template Marketplace (Extended) ───────────────────────


def update_agent_template(template_id: str, description: str = None,
                          system_prompt: str = None,
                          capabilities: list = None,
                          status: str = None) -> dict:
    """Update an existing agent template.

    template_id: template to update
    Only provided fields are updated.
    """
    params = {"template_id": template_id}
    if description:
        params["description"] = description
    if system_prompt:
        params["system_prompt"] = system_prompt
    if capabilities:
        params["capabilities"] = capabilities
    if status:
        params["status"] = status
    return _rpc("tenzro_updateAgentTemplate", [params])


def run_agent_template(agent_id: str, max_iterations: int = 10,
                       dry_run: bool = False) -> dict:
    """Run an agent spawned from a template.

    agent_id: the spawned agent ID to run
    max_iterations: max execution iterations
    dry_run: if True, simulate without side effects
    """
    return _rpc("tenzro_runAgentTemplate", {
        "agent_id": agent_id,
        "max_iterations": max_iterations,
        "dry_run": dry_run,
    })


def download_agent_template(template_id: str) -> dict:
    """Download an agent template's definition for local use.

    template_id: the template to download
    """
    return _rpc("tenzro_downloadAgentTemplate", {"template_id": template_id})


def spawn_agent_template(template_id: str, display_name: str,
                         parent_machine_did: str = None) -> dict:
    """Spawn a new agent from a template with identity and wallet provisioning.

    template_id: the template to instantiate
    display_name: display name for the spawned agent
    parent_machine_did: optional parent machine DID. When set, the spawned
        agent's effective delegation scope is the strict intersection of the
        parent's scope and the template's spec — the child can never be
        broader than its parent on any axis (numeric ceilings, allow-lists,
        time bound).
    """
    params = {
        "template_id": template_id,
        "display_name": display_name,
    }
    if parent_machine_did:
        params["parent_machine_did"] = parent_machine_did
    return _rpc("tenzro_spawnAgentTemplate", params)


# ── Agent Management (Extended) ────────────────────────────────


def list_agents() -> dict:
    """List all registered agents on the node."""
    return _rpc("tenzro_listAgents")


def send_agent_message(from_id: str, to_id: str, message: str) -> dict:
    """Send a message between agents.

    from_id: sender agent ID
    to_id: recipient agent ID
    message: message content
    """
    return _rpc("tenzro_sendAgentMessage", {
        "from": from_id,
        "to": to_id,
        "message": message,
    })


def delegate_task(agent_id: str, task: str,
                  target_agent: str = None) -> dict:
    """Delegate a task to an agent or sub-agent.

    agent_id: the agent doing the delegation
    task: task description
    target_agent: optional specific agent to delegate to
    """
    params = {"agent_id": agent_id, "task": task}
    if target_agent:
        params["target_agent"] = target_agent
    return _rpc("tenzro_delegateTask", params)


def discover_models(query: str = None, category: str = None) -> dict:
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


def discover_agents(capability: str = None) -> dict:
    """Discover agents available on the network.

    capability: optional capability filter
    """
    params = {}
    if capability:
        params["capability"] = capability
    return _rpc("tenzro_discoverAgents", params)


def fund_agent(agent_id: str, amount_wei: int) -> dict:
    """Fund an agent's wallet with TNZO.

    agent_id: agent to fund
    amount_wei: amount in wei to transfer
    """
    return _rpc("tenzro_fundAgent", {
        "agent_id": agent_id,
        "amount": amount_wei,
    })


# ── Identity (Extended) ─────────────────────────────────────────


def import_identity(did: str, private_key: str,
                    key_type: str = "ed25519") -> dict:
    """Import an existing identity by DID and private key.

    did: the DID to import
    private_key: hex-encoded private key
    key_type: ed25519 or secp256k1
    """
    return _rpc("tenzro_importIdentity", [{
        "did": did,
        "private_key": private_key,
        "key_type": key_type,
    }])


def register_machine_identity(controller_did: str,
                               capabilities: list = None,
                               display_name: str = None) -> dict:
    """Register a machine identity controlled by a human DID.

    controller_did: the human DID that controls this machine
    capabilities: list of machine capabilities
    display_name: optional display name
    """
    params = {"controller": controller_did, "identity_type": "machine"}
    if capabilities:
        params["capabilities"] = capabilities
    if display_name:
        params["display_name"] = display_name
    return _rpc("tenzro_registerMachineIdentity", params)


def add_service(did: str, service_type: str, endpoint: str,
                description: str = None) -> dict:
    """Add a service endpoint to a DID document.

    did: the DID to add the service to
    service_type: service type (e.g. "LinkedDomains", "MessagingService")
    endpoint: service endpoint URL
    description: optional description
    """
    params = {
        "did": did,
        "service_type": service_type,
        "endpoint": endpoint,
    }
    if description:
        params["description"] = description
    return _rpc("tenzro_addService", [params])


def add_credential(did: str, credential_type: str, issuer: str,
                   claims: dict = None) -> dict:
    """Add a verifiable credential to an identity.

    did: the DID to add the credential to
    credential_type: credential type (e.g. "KycAttestation")
    issuer: issuer DID
    claims: optional claims dict
    """
    params = {
        "did": did,
        "credential_type": credential_type,
        "issuer": issuer,
    }
    if claims:
        params["claims"] = claims
    return _rpc("tenzro_addCredential", [params])


def list_identities(identity_type: str = None) -> dict:
    """List all registered identities on the node.

    identity_type: optional filter — human | machine | all
    """
    params = {}
    if identity_type and identity_type != "all":
        params["identity_type"] = identity_type
    return _rpc("tenzro_listIdentities", [params])


# ── Payments (Extended) ─────────────────────────────────────────


def pay_mpp(url: str, payer_did: str = None, wallet: str = None,
            max_amount: int = None) -> dict:
    """Pay for a resource using the MPP (Machine Payments Protocol).

    url: resource URL to pay for
    payer_did: optional payer DID
    wallet: optional wallet ID
    max_amount: optional maximum amount willing to pay
    """
    params = {"url": url}
    if payer_did:
        params["payer_did"] = payer_did
    if wallet:
        params["wallet"] = wallet
    if max_amount is not None:
        params["max_amount"] = max_amount
    return _rpc("tenzro_payMpp", [params])


def pay_x402(url: str, payer_did: str = None, wallet: str = None,
             max_amount: int = None) -> dict:
    """Pay for a resource using x402 (HTTP 402 Payment Protocol).

    url: resource URL to pay for
    payer_did: optional payer DID
    wallet: optional wallet ID
    max_amount: optional maximum amount willing to pay
    """
    params = {"url": url}
    if payer_did:
        params["payer_did"] = payer_did
    if wallet:
        params["wallet"] = wallet
    if max_amount is not None:
        params["max_amount"] = max_amount
    return _rpc("tenzro_payX402", [params])


def payment_gateway_info() -> dict:
    """Get payment gateway info (supported protocols, networks, assets)."""
    return _rpc("tenzro_paymentGatewayInfo")


def list_x402_schemes() -> dict:
    """List the x402 scheme backends registered on the connected node.

    Each scheme corresponds to a different verification path under the x402
    protocol: 'tenzro-hybrid' (Ed25519 hybrid signature over canonical
    preimage), 'exact-eip3009' (USDC EIP-3009 meta-transaction via the CDP
    facilitator), 'permit2' (Uniswap Permit2 via the CDP facilitator), and
    'erc7710' (delegation redemption). Use the returned ids in the
    'extra.scheme' field of an x402 PaymentRequirement.

    Returns:
        dict with keys 'default' (str), 'schemes' (list of {id, description}),
        and 'count' (int).
    """
    return _rpc("tenzro_listX402Schemes")


def list_payment_sessions(include_closed: bool = False) -> dict:
    """List active MPP payment sessions.

    include_closed: if True, include closed sessions
    """
    return _rpc("tenzro_listPaymentSessions", [{"include_closed": include_closed}])


def get_payment_receipt(receipt_id: str) -> dict:
    """Get details of a payment receipt.

    receipt_id: the receipt ID to look up
    """
    return _rpc("tenzro_getPaymentReceipt", [receipt_id])


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


def list_accounts() -> dict:
    """List all accounts/wallets on the node."""
    return _rpc("tenzro_listAccounts")


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


def settle(settlement_request: dict) -> dict:
    """Submit a settlement request.

    settlement_request: dict with service_type, provider, consumer, amount, proof
    """
    return _rpc("tenzro_settle", settlement_request)


def get_settlement(settlement_id: str) -> dict:
    """Get details of a settlement by ID."""
    return _rpc("tenzro_getSettlement", {"settlement_id": settlement_id})


def _release_conditions_payload(kind: str) -> dict:
    """Map a short release-condition keyword to the on-chain ReleaseConditions enum payload."""
    k = (kind or "timeout").lower()
    if k == "timeout":
        return {"type": "Timeout"}
    if k in ("provider", "provider_signature"):
        return {"type": "ProviderSignature"}
    if k in ("consumer", "consumer_signature"):
        return {"type": "ConsumerSignature"}
    if k in ("both", "both_signatures"):
        return {"type": "BothSignatures"}
    if k in ("verifier", "verifier_signature"):
        return {"type": "VerifierSignature"}
    if k == "custom":
        return {"type": "Custom", "data": ""}
    raise ValueError(
        f"unsupported release condition '{kind}': use timeout|provider|consumer|both|verifier|custom"
    )


def _fetch_nonce_and_chain_id(address: str) -> tuple:
    """Best-effort nonce + chain_id lookup. Returns (0, 1337) on failure."""
    try:
        nonce_hex = _rpc("eth_getTransactionCount", [address, "latest"])
        nonce = int(nonce_hex.replace("0x", ""), 16) if isinstance(nonce_hex, str) else 0
    except Exception:
        nonce = 0
    try:
        chain_id_hex = _rpc("eth_chainId", [])
        chain_id = int(chain_id_hex.replace("0x", ""), 16) if isinstance(chain_id_hex, str) else 1337
    except Exception:
        chain_id = 1337
    return nonce, chain_id


def create_escrow(payer: str, payee: str, amount_wei: int,
                  asset_id: str = "TNZO", expires_at_ms: int = 0,
                  release_conditions: str = "timeout") -> dict:
    """Create an on-chain escrow via signed CreateEscrow transaction.

    Uses ambient OAuth/DPoP auth (TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF
    env vars) — the server looks up the wallet bound to the bearer DID
    and signs on its behalf. The bearer's wallet address must equal `payer`.

    The escrow_id is derived deterministically by the VM as
    SHA-256("tenzro/escrow/id" || payer || nonce_le); funds are locked at a
    vault address derived from that id. Only the original payer can release or
    refund.

    payer: payer address (must match the bearer's wallet)
    payee: payee address (recipient on successful release)
    amount_wei: amount to lock in escrow (smallest unit; 1 TNZO = 10^18 wei)
    asset_id: asset identifier (default "TNZO")
    expires_at_ms: unix timestamp in milliseconds when the escrow expires (0 = never)
    release_conditions: one of timeout|provider|consumer|both|verifier|custom

    Returns the JSON-RPC result of tenzro_signAndSendTransaction (typically a tx_hash).
    """
    nonce, chain_id = _fetch_nonce_and_chain_id(payer)
    tx_type = {
        "type": "CreateEscrow",
        "data": {
            "payee": payee,
            "amount": str(amount_wei),
            "asset_id": asset_id,
            "expires_at": expires_at_ms,
            "release_conditions": _release_conditions_payload(release_conditions),
        },
    }
    params = {
        "from": payer,
        "to": payee,
        "value": 0,
        "gas_limit": 75000,
        "gas_price": 1_000_000_000,
        "nonce": nonce,
        "chain_id": chain_id,
        "tx_type": tx_type,
    }
    return _rpc("tenzro_signAndSendTransaction", params)


def release_escrow(payer: str, escrow_id_hex: str,
                   proof_data_hex: str = "") -> dict:
    """Release an escrow to the payee via signed ReleaseEscrow transaction.

    Uses ambient OAuth/DPoP auth — the bearer JWT must belong to the
    original payer; the VM rejects releases from any other address.

    payer: payer address (must match the bearer's wallet)
    escrow_id_hex: 32-byte escrow id (hex, with or without 0x)
    proof_data_hex: optional proof bytes (hex)
    """
    escrow_id_bytes = list(bytes.fromhex(escrow_id_hex.replace("0x", "")))
    if len(escrow_id_bytes) != 32:
        raise ValueError(f"escrow_id must be 32 bytes, got {len(escrow_id_bytes)}")
    proof_bytes = list(bytes.fromhex(proof_data_hex.replace("0x", ""))) if proof_data_hex else []

    nonce, chain_id = _fetch_nonce_and_chain_id(payer)
    tx_type = {
        "type": "ReleaseEscrow",
        "data": {
            "escrow_id": escrow_id_bytes,
            "proof": {
                "proof_type": "Timeout",
                "proof_data": proof_bytes,
                "signatures": [],
            },
        },
    }
    params = {
        "from": payer,
        "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "value": 0,
        "gas_limit": 60000,
        "gas_price": 1_000_000_000,
        "nonce": nonce,
        "chain_id": chain_id,
        "tx_type": tx_type,
    }
    return _rpc("tenzro_signAndSendTransaction", params)


def refund_escrow(payer: str, escrow_id_hex: str) -> dict:
    """Refund an escrow back to the payer via signed RefundEscrow transaction.

    Uses ambient OAuth/DPoP auth. Only the original payer can submit this,
    AND the escrow must be expired (or use Timeout/Custom release conditions).
    """
    escrow_id_bytes = list(bytes.fromhex(escrow_id_hex.replace("0x", "")))
    if len(escrow_id_bytes) != 32:
        raise ValueError(f"escrow_id must be 32 bytes, got {len(escrow_id_bytes)}")

    nonce, chain_id = _fetch_nonce_and_chain_id(payer)
    tx_type = {
        "type": "RefundEscrow",
        "data": {"escrow_id": escrow_id_bytes},
    }
    params = {
        "from": payer,
        "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "value": 0,
        "gas_limit": 50000,
        "gas_price": 1_000_000_000,
        "nonce": nonce,
        "chain_id": chain_id,
        "tx_type": tx_type,
    }
    return _rpc("tenzro_signAndSendTransaction", params)


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
                            mcp_url: str = None) -> dict:
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


def download_model(model_id: str) -> dict:
    """Download a model from the registry.

    model_id: model to download
    """
    return _rpc("tenzro_downloadModel", {"model_id": model_id})


def get_download_progress(model_id: str) -> dict:
    """Get download progress for a model.

    model_id: model being downloaded
    """
    return _rpc("tenzro_getDownloadProgress", {"model_id": model_id})


def serve_model(model_id: str) -> dict:
    """Start serving a model for inference.

    model_id: model to serve
    """
    return _rpc("tenzro_serveModel", {"model_id": model_id})


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


# ── Token (Extended) ───────────────────────────────────────────


def swap_token(from_token: str, to_token: str, amount: int,
               sender: str) -> dict:
    """Swap one token for another.

    from_token: source token symbol or ID
    to_token: destination token symbol or ID
    amount: amount in smallest unit
    sender: sender address
    """
    return _rpc("tenzro_swapToken", {
        "from_token": from_token,
        "to_token": to_token,
        "amount": amount,
        "sender": sender,
    })


def agent_pay_for_inference(agent_id: str, model_id: str,
                            amount: int) -> dict:
    """Execute the agent payment pipeline for inference.

    agent_id: agent paying for inference
    model_id: model to pay for
    amount: payment amount in wei
    """
    return _rpc("tenzro_agentPayForInference", {
        "agent_id": agent_id,
        "model_id": model_id,
        "amount": amount,
    })


def wrap_tnzo(address: str, amount: int, vm_type: str = "evm") -> dict:
    """Wrap native TNZO to a VM representation (no-op in pointer model).

    address: address wrapping TNZO
    amount: amount in wei
    vm_type: target VM — evm | svm | daml
    """
    return _rpc("tenzro_wrapTnzo", {
        "address": address,
        "amount": amount,
        "vm_type": vm_type,
    })


# ── Governance ─────────────────────────────────────────────────


def list_proposals() -> dict:
    """List governance proposals."""
    return _rpc("tenzro_listProposals")


def create_proposal(title: str, description: str,
                    proposal_type: str = "parameter_change",
                    params: dict = None) -> dict:
    """Create a governance proposal.

    title: proposal title
    description: proposal description
    proposal_type: parameter_change | treasury_spend | protocol_upgrade
    params: optional proposal-specific parameters
    """
    p = {
        "title": title,
        "description": description,
        "proposal_type": proposal_type,
    }
    if params:
        p["params"] = params
    return _rpc("tenzro_createProposal", p)


def vote(proposal_id: str, vote_value: str, voter: str = None) -> dict:
    """Vote on a governance proposal.

    proposal_id: proposal to vote on
    vote_value: for | against | abstain
    voter: optional voter address
    """
    p = {"proposal_id": proposal_id, "vote": vote_value}
    if voter:
        p["voter"] = voter
    return _rpc("tenzro_vote", p)


def get_voting_power(address: str) -> dict:
    """Get the voting power for an address.

    address: 0x-prefixed hex address
    """
    return _rpc("tenzro_getVotingPower", {"address": address})


def delegate_voting_power(from_addr: str, to_addr: str) -> dict:
    """Delegate voting power to another address.

    from_addr: delegator address
    to_addr: delegate address
    """
    return _rpc("tenzro_delegateVotingPower", {
        "from": from_addr,
        "to": to_addr,
    })


# ── Canton / DAML ──────────────────────────────────────────────


def list_canton_domains() -> dict:
    """List Canton synchronizer domains."""
    return _rpc("tenzro_listCantonDomains")


def list_daml_contracts(domain: str = None,
                        template_id: str = None) -> dict:
    """List DAML contracts, optionally filtered.

    domain: optional domain filter
    template_id: optional template ID filter
    """
    params = {}
    if domain:
        params["domain"] = domain
    if template_id:
        params["template_id"] = template_id
    return _rpc("tenzro_listDamlContracts", params)


def submit_daml_command(command_type: str, template_id: str,
                        party: str, payload: dict = None) -> dict:
    """Submit a DAML command to Canton.

    command_type: create | exercise
    template_id: DAML template ID
    party: acting party
    payload: command payload
    """
    params = {
        "command_type": command_type,
        "template_id": template_id,
        "party": party,
    }
    if payload:
        params["payload"] = payload
    return _rpc("tenzro_submitDamlCommand", params)


# ── Provider Management (Extended) ─────────────────────────────


def set_role(role: str) -> dict:
    """Set the node role.

    role: Validator | ModelProvider | TeeProvider | LightClient
    """
    return _rpc("tenzro_setRole", {"role": role})


def set_provider_schedule(schedule: dict) -> dict:
    """Set provider availability schedule.

    schedule: dict with day/time availability windows
    """
    return _rpc("tenzro_setProviderSchedule", schedule)


def get_provider_schedule() -> dict:
    """Get the current provider schedule."""
    return _rpc("tenzro_getProviderSchedule")


def set_provider_pricing(pricing: dict) -> dict:
    """Set provider pricing configuration.

    pricing: dict with model pricing per token/request
    """
    return _rpc("tenzro_setProviderPricing", pricing)


def get_provider_pricing() -> dict:
    """Get the current provider pricing configuration."""
    return _rpc("tenzro_getProviderPricing")


def list_providers(provider_type: str = None) -> dict:
    """List all providers discovered via gossipsub.

    provider_type: optional filter — llm | tee | general
    """
    params = {}
    if provider_type:
        params["provider_type"] = provider_type
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
                    reward_percentiles: list = None) -> dict:
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


# ── Solana (via solana-mcp.tenzro.network) ────────────────────────


def solana_swap(input_mint: str, output_mint: str, amount: int,
                slippage_bps: int = 100) -> dict:
    """Swap tokens on Solana via Jupiter aggregator.

    input_mint: input token mint address
    output_mint: output token mint address
    amount: amount in smallest unit (lamports / token decimals)
    slippage_bps: slippage tolerance in basis points (default 100 = 1%)
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_swap", {
        "input_mint": input_mint,
        "output_mint": output_mint,
        "amount": amount,
        "slippage_bps": slippage_bps,
    })


def solana_get_price(token_id: str) -> dict:
    """Get token price on Solana.

    token_id: token mint address or symbol
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_price", {
        "token_id": token_id,
    })


def solana_stake(amount_sol: float, validator_address: str) -> dict:
    """Stake SOL to a validator.

    amount_sol: amount of SOL to stake
    validator_address: validator vote account address
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_stake", {
        "amount_sol": amount_sol,
        "validator_address": validator_address,
    })


def solana_get_yield(protocol: str = None) -> dict:
    """Get Solana staking/DeFi yield information.

    protocol: optional protocol filter
    """
    params = {}
    if protocol:
        params["protocol"] = protocol
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_yield", params)


def solana_get_balance(address: str) -> dict:
    """Get SOL balance for an address.

    address: Solana public key (base58)
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_balance", {
        "address": address,
    })


def solana_get_token_accounts(owner_address: str) -> dict:
    """Get all SPL token accounts for an owner.

    owner_address: Solana public key (base58)
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_token_accounts", {
        "owner_address": owner_address,
    })


def solana_transfer(from_addr: str, to_addr: str,
                    amount_lamports: int) -> dict:
    """Transfer SOL between addresses.

    from_addr: sender public key
    to_addr: recipient public key
    amount_lamports: amount in lamports
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_transfer", {
        "from": from_addr,
        "to": to_addr,
        "amount": amount_lamports,
    })


def solana_get_token_info(mint_address: str) -> dict:
    """Get SPL token metadata by mint address.

    mint_address: token mint address
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_token_info", {
        "mint_address": mint_address,
    })


def solana_get_nft(mint_address: str) -> dict:
    """Get NFT metadata via Metaplex DAS API.

    mint_address: NFT mint address
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_nft", {
        "mint_address": mint_address,
    })


def solana_get_nfts_by_owner(owner_address: str) -> dict:
    """Get all NFTs owned by an address.

    owner_address: Solana public key (base58)
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_nfts_by_owner", {
        "owner_address": owner_address,
    })


def solana_get_slot() -> dict:
    """Get the current Solana slot number."""
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_slot", {})


def solana_get_tps() -> dict:
    """Get current Solana transactions per second."""
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_tps", {})


def solana_get_transaction(signature: str) -> dict:
    """Get a Solana transaction by signature.

    signature: transaction signature (base58)
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_get_transaction", {
        "signature": signature,
    })


def solana_resolve_domain(domain: str) -> dict:
    """Resolve a Bonfida SNS domain to a Solana address.

    domain: SNS domain name (e.g. "tenzro.sol")
    """
    return _mcp_tool_call(SOLANA_MCP_URL, "solana_resolve_domain", {
        "domain": domain,
    })


# ── Ethereum (via ethereum-mcp.tenzro.network) ───────────────────


def eth_get_price_chainlink(feed_address: str = None) -> dict:
    """Get token price from Chainlink data feeds.

    feed_address: optional Chainlink feed address (defaults to ETH/USD)
    """
    params = {}
    if feed_address:
        params["feed_address"] = feed_address
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_get_price", params)


def eth_get_gas_price_ext() -> dict:
    """Get current Ethereum gas price from the network."""
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_get_gas_price", {})


def eth_estimate_gas_ext(to: str, data: str = None,
                         value: str = None) -> dict:
    """Estimate gas for an Ethereum transaction.

    to: recipient address
    data: optional calldata (hex)
    value: optional value in wei (hex)
    """
    params = {"to": to}
    if data:
        params["data"] = data
    if value:
        params["value"] = value
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_estimate_gas", params)


def eth_get_fee_history(block_count: int = 10) -> dict:
    """Get Ethereum fee history for recent blocks.

    block_count: number of blocks to look back
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_get_fee_history", {
        "block_count": block_count,
    })


def eth_get_erc20_balance(token_address: str,
                          owner_address: str) -> dict:
    """Get ERC-20 token balance for an address.

    token_address: ERC-20 contract address
    owner_address: wallet address to check
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_get_token_balance", {
        "token_address": token_address,
        "owner_address": owner_address,
    })


def eth_get_tx(tx_hash: str) -> dict:
    """Get an Ethereum transaction by hash.

    tx_hash: 0x-prefixed transaction hash
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_get_transaction", {
        "tx_hash": tx_hash,
    })


def eth_get_block_info(block_number: str = None) -> dict:
    """Get an Ethereum block by number.

    block_number: block number (hex or decimal) or "latest"
    """
    params = {}
    if block_number:
        params["block_number"] = block_number
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_get_block", params)


def eth_get_receipt(tx_hash: str) -> dict:
    """Get an Ethereum transaction receipt.

    tx_hash: 0x-prefixed transaction hash
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_get_transaction_receipt", {
        "tx_hash": tx_hash,
    })


def eth_resolve_ens(name: str) -> dict:
    """Resolve an ENS name to an Ethereum address.

    name: ENS name (e.g. "vitalik.eth")
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_resolve_ens", {
        "name": name,
    })


def eth_lookup_ens(address: str) -> dict:
    """Reverse-lookup an ENS name from an Ethereum address.

    address: 0x-prefixed Ethereum address
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_lookup_ens", {
        "address": address,
    })


def eth_call_contract(to: str, data: str) -> dict:
    """Execute a read-only contract call on Ethereum.

    to: contract address
    data: ABI-encoded calldata (hex)
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_call_contract", {
        "to": to,
        "data": data,
    })


def eth_encode_function(function_sig: str, args: list) -> dict:
    """ABI-encode a function call.

    function_sig: function signature (e.g. "transfer(address,uint256)")
    args: list of argument values
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_encode_function", {
        "function_sig": function_sig,
        "args": args,
    })


def eth_register_agent_8004(agent_name: str, capabilities: list,
                            metadata_uri: str) -> dict:
    """Register an AI agent via ERC-8004.

    agent_name: agent display name
    capabilities: list of capability strings
    metadata_uri: URI pointing to agent metadata
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_register_agent_8004", {
        "agent_name": agent_name,
        "capabilities": capabilities,
        "metadata_uri": metadata_uri,
    })


def eth_lookup_agent_8004(agent_id: str) -> dict:
    """Look up an AI agent registered via ERC-8004.

    agent_id: on-chain agent ID
    """
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_lookup_agent_8004", {
        "agent_id": agent_id,
    })


def eth_get_attestation(schema_id: str, attester: str = None) -> dict:
    """Get an EAS (Ethereum Attestation Service) attestation.

    schema_id: attestation schema ID
    attester: optional attester address filter
    """
    params = {"schema_id": schema_id}
    if attester:
        params["attester"] = attester
    return _mcp_tool_call(ETHEREUM_MCP_URL, "eth_get_attestation", params)


# ── LayerZero (via layerzero-mcp.tenzro.network) ─────────────────


def lz_quote_fee(src_eid: int, dst_eid: int, message: str,
                 options: str = None) -> dict:
    """Quote LayerZero messaging fee via EndpointV2.quote().

    src_eid: source chain endpoint ID
    dst_eid: destination chain endpoint ID
    message: message payload (hex)
    options: optional TYPE_3 options (hex)
    """
    params = {
        "src_eid": src_eid,
        "dst_eid": dst_eid,
        "message": message,
    }
    if options:
        params["options"] = options
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_quote_fee", params)


def lz_send_message(src_eid: int, dst_eid: int, receiver: str,
                    message: str, options: str = None) -> dict:
    """Build LayerZero EndpointV2.send() calldata.

    src_eid: source chain endpoint ID
    dst_eid: destination chain endpoint ID
    receiver: recipient address (bytes32 hex)
    message: message payload (hex)
    options: optional TYPE_3 options (hex)
    """
    params = {
        "src_eid": src_eid,
        "dst_eid": dst_eid,
        "receiver": receiver,
        "message": message,
    }
    if options:
        params["options"] = options
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_send_message", params)


def lz_track_message(tx_hash: str) -> dict:
    """Track a LayerZero message by source transaction hash.

    tx_hash: 0x-prefixed transaction hash
    """
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_track_message", {
        "tx_hash": tx_hash,
    })


def lz_oft_quote(src_eid: int, dst_eid: int, amount: int,
                 token: str = None) -> dict:
    """Quote an OFT (Omnichain Fungible Token) transfer.

    src_eid: source chain endpoint ID
    dst_eid: destination chain endpoint ID
    amount: amount in shared decimals
    token: optional OFT contract address
    """
    params = {
        "src_eid": src_eid,
        "dst_eid": dst_eid,
        "amount": amount,
    }
    if token:
        params["token"] = token
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_oft_quote", params)


def lz_oft_send(src_eid: int, dst_eid: int, amount: int,
                recipient: str, token: str = None) -> dict:
    """Build OFT send() calldata with auto fee quoting.

    src_eid: source chain endpoint ID
    dst_eid: destination chain endpoint ID
    amount: amount in shared decimals (uint64)
    recipient: recipient address (bytes32 hex)
    token: optional OFT contract address
    """
    params = {
        "src_eid": src_eid,
        "dst_eid": dst_eid,
        "amount": amount,
        "recipient": recipient,
    }
    if token:
        params["token"] = token
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_oft_send", params)


def lz_list_chains() -> dict:
    """List all LayerZero-supported chains with endpoint IDs."""
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_list_chains", {})


def lz_get_chain_rpc(chain: str) -> dict:
    """Get RPC URL for a LayerZero-supported chain.

    chain: chain name or endpoint ID
    """
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_get_chain_rpc", {
        "chain": chain,
    })


def lz_list_dvns(chain: str = None) -> dict:
    """List LayerZero DVNs (Decentralized Verifier Networks).

    chain: optional chain filter
    """
    params = {}
    if chain:
        params["chain"] = chain
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_list_dvns", params)


def lz_get_deployments(chain: str = None) -> dict:
    """Get LayerZero contract deployments.

    chain: optional chain filter
    """
    params = {}
    if chain:
        params["chain"] = chain
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_get_deployments", params)


def lz_transfer_quote(src_chain: str, dst_chain: str, token: str,
                      amount: int) -> dict:
    """Get a unified cross-chain transfer quote (130+ chains).

    src_chain: source chain name or ID
    dst_chain: destination chain name or ID
    token: token symbol or address
    amount: transfer amount
    """
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_transfer_quote", {
        "src_chain": src_chain,
        "dst_chain": dst_chain,
        "token": token,
        "amount": amount,
    })


def lz_transfer_build(quote_id: str) -> dict:
    """Build signable transaction steps from a transfer quote.

    quote_id: quote ID returned by lz_transfer_quote
    """
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_transfer_build", {
        "quote_id": quote_id,
    })


def lz_stargate_quote(src_chain: str, dst_chain: str, token: str,
                      amount: int) -> dict:
    """Quote a Stargate V2 native bridge transfer.

    src_chain: source chain name
    dst_chain: destination chain name
    token: token symbol (ETH, USDC, USDT)
    amount: amount to bridge
    """
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_stargate_quote", {
        "src_chain": src_chain,
        "dst_chain": dst_chain,
        "token": token,
        "amount": amount,
    })


def lz_stargate_send(src_chain: str, dst_chain: str, token: str,
                     amount: int, recipient: str) -> dict:
    """Build Stargate V2 sendToken() calldata with auto fee.

    src_chain: source chain name
    dst_chain: destination chain name
    token: token symbol (ETH, USDC, USDT)
    amount: amount to bridge
    recipient: recipient address
    """
    return _mcp_tool_call(LAYERZERO_MCP_URL, "lz_stargate_send", {
        "src_chain": src_chain,
        "dst_chain": dst_chain,
        "token": token,
        "amount": amount,
        "recipient": recipient,
    })


# ── Chainlink (via chainlink-mcp.tenzro.network) ─────────────────


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


def ccip_get_fee(src_chain: str, dst_chain: str,
                 data_size: int = 0) -> dict:
    """Get CCIP messaging fee via Router.getFee().

    src_chain: source chain name
    dst_chain: destination chain name
    data_size: payload size in bytes
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "ccip_get_fee", {
        "src_chain": src_chain,
        "dst_chain": dst_chain,
        "data_size": data_size,
    })


def ccip_send_message(src_chain: str, dst_chain: str,
                      receiver: str, data: str) -> dict:
    """Build CCIP Router.ccipSend() calldata.

    src_chain: source chain name
    dst_chain: destination chain name
    receiver: recipient address
    data: message payload (hex)
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "ccip_send_message", {
        "src_chain": src_chain,
        "dst_chain": dst_chain,
        "receiver": receiver,
        "data": data,
    })


def ccip_track_message(message_id: str) -> dict:
    """Track a CCIP message by ID.

    message_id: CCIP message ID
    """
    return _mcp_tool_call(CHAINLINK_MCP_URL, "ccip_track_message", {
        "message_id": message_id,
    })


def ccip_get_supported_chains() -> dict:
    """List chains supported by Chainlink CCIP."""
    return _mcp_tool_call(CHAINLINK_MCP_URL, "ccip_get_supported_chains",
                          {})


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


# ── Canton (via canton-mcp.tenzro.network) ────────────────────────


def canton_submit_command(command_type: str, template_id: str,
                          party: str, payload: dict = None) -> dict:
    """Submit a DAML command via Canton JSON Ledger API v2.

    command_type: create | exercise
    template_id: DAML template ID
    party: acting party
    payload: command payload
    """
    params = {
        "command_type": command_type,
        "template_id": template_id,
        "party": party,
    }
    if payload:
        params["payload"] = payload
    return _mcp_tool_call(CANTON_MCP_URL, "canton_submit_command", params)


def canton_list_contracts(party: str = None,
                          template_id: str = None) -> dict:
    """List active DAML contracts.

    party: optional party filter
    template_id: optional template filter
    """
    params = {}
    if party:
        params["party"] = party
    if template_id:
        params["template_id"] = template_id
    return _mcp_tool_call(CANTON_MCP_URL, "canton_list_contracts", params)


def canton_get_events(contract_id: str) -> dict:
    """Get events for a DAML contract.

    contract_id: DAML contract ID
    """
    return _mcp_tool_call(CANTON_MCP_URL, "canton_get_events", {
        "contract_id": contract_id,
    })


def canton_get_transaction(tx_id: str) -> dict:
    """Get a Canton transaction by ID.

    tx_id: transaction ID
    """
    return _mcp_tool_call(CANTON_MCP_URL, "canton_get_transaction", {
        "tx_id": tx_id,
    })


def canton_allocate_party(party_name: str) -> dict:
    """Allocate a new Canton party.

    party_name: display name for the party
    """
    return _mcp_tool_call(CANTON_MCP_URL, "canton_allocate_party", {
        "party_name": party_name,
    })


def canton_list_parties() -> dict:
    """List all Canton parties."""
    return _mcp_tool_call(CANTON_MCP_URL, "canton_list_parties", {})


def canton_list_domains_ext() -> dict:
    """List Canton synchronizer domains (via MCP)."""
    return _mcp_tool_call(CANTON_MCP_URL, "canton_list_domains", {})


def canton_get_health() -> dict:
    """Get Canton participant health status."""
    return _mcp_tool_call(CANTON_MCP_URL, "canton_get_health", {})


def canton_get_balance_ext(party: str, token: str = None) -> dict:
    """Get CIP-56 token balance on Canton.

    party: Canton party identifier
    token: optional token filter
    """
    params = {"party": party}
    if token:
        params["token"] = token
    return _mcp_tool_call(CANTON_MCP_URL, "canton_get_balance", params)


def canton_transfer(from_party: str, to_party: str, amount: str,
                    token: str = "TNZO") -> dict:
    """Transfer tokens on Canton.

    from_party: sender party
    to_party: recipient party
    amount: transfer amount (DAML Decimal string)
    token: token symbol (default TNZO)
    """
    return _mcp_tool_call(CANTON_MCP_URL, "canton_transfer", {
        "from_party": from_party,
        "to_party": to_party,
        "amount": amount,
        "token": token,
    })


def canton_create_asset(party: str, asset_type: str,
                        amount: str) -> dict:
    """Create a tokenized asset on Canton.

    party: issuing party
    asset_type: type of asset
    amount: asset amount (DAML Decimal string)
    """
    return _mcp_tool_call(CANTON_MCP_URL, "canton_create_asset", {
        "party": party,
        "asset_type": asset_type,
        "amount": amount,
    })


def canton_dvp_settle(buyer: str, seller: str, asset_id: str,
                      payment_amount: str) -> dict:
    """Execute DvP (Delivery versus Payment) settlement on Canton.

    buyer: buyer party
    seller: seller party
    asset_id: asset contract ID
    payment_amount: payment amount (DAML Decimal string)
    """
    return _mcp_tool_call(CANTON_MCP_URL, "canton_dvp_settle", {
        "buyer": buyer,
        "seller": seller,
        "asset_id": asset_id,
        "payment_amount": payment_amount,
    })


def canton_upload_dar(dar_path: str) -> dict:
    """Upload a DAR (DAML Archive) to Canton.

    dar_path: path or URL to the DAR file
    """
    return _mcp_tool_call(CANTON_MCP_URL, "canton_upload_dar", {
        "dar_path": dar_path,
    })


def canton_get_fee_schedule(domain: str = None) -> dict:
    """Get Canton fee schedule for a synchronizer domain.

    domain: optional domain ID
    """
    params = {}
    if domain:
        params["domain"] = domain
    return _mcp_tool_call(CANTON_MCP_URL, "canton_get_fee_schedule",
                          params)


# ── Crypto ────────────────────────────────────────────────────────


def sign_message(private_key: str, message_hex: str,
                 key_type: str = "ed25519") -> dict:
    """Sign a message with a private key (Ed25519 or Secp256k1)."""
    return _rpc("tenzro_signMessage", {
        "private_key": private_key,
        "message_hex": message_hex,
        "key_type": key_type,
    })


def verify_signature(public_key: str, message_hex: str,
                     signature_hex: str) -> dict:
    """Verify a cryptographic signature against a public key."""
    return _rpc("tenzro_verifySignature", {
        "public_key": public_key,
        "message_hex": message_hex,
        "signature_hex": signature_hex,
    })


def encrypt_data(key_hex: str, plaintext_hex: str) -> dict:
    """Encrypt data with AES-256-GCM. Returns ciphertext + nonce."""
    return _rpc("tenzro_encrypt", {
        "key_hex": key_hex,
        "plaintext_hex": plaintext_hex,
    })


def decrypt_data(key_hex: str, ciphertext_hex: str,
                 nonce_hex: str) -> dict:
    """Decrypt AES-256-GCM ciphertext with key and nonce."""
    return _rpc("tenzro_decrypt", {
        "key_hex": key_hex,
        "ciphertext_hex": ciphertext_hex,
        "nonce_hex": nonce_hex,
    })


def derive_key(password: str) -> dict:
    """Derive a 256-bit key from a password using Argon2id."""
    return _rpc("tenzro_deriveKey", {"password": password})


def generate_keypair(key_type: str = "ed25519") -> dict:
    """Generate a new cryptographic keypair (Ed25519 or Secp256k1)."""
    return _rpc("tenzro_generateKeypair", {"key_type": key_type})


def hash_sha256(data_hex: str) -> dict:
    """Compute SHA-256 hash of hex-encoded data."""
    return _rpc("tenzro_hashSha256", {"data_hex": data_hex})


def hash_keccak256(data_hex: str) -> dict:
    """Compute Keccak-256 hash of hex-encoded data."""
    return _rpc("tenzro_hashKeccak256", {"data_hex": data_hex})


def x25519_key_exchange(private_key_hex: str,
                        public_key_hex: str) -> dict:
    """Perform X25519 Diffie-Hellman key exchange."""
    return _rpc("tenzro_x25519KeyExchange", {
        "private_key_hex": private_key_hex,
        "public_key_hex": public_key_hex,
    })


# ── TEE ──────────────────────────────────────────────────────────


def detect_tee() -> dict:
    """Detect available TEE hardware on this node."""
    return _rpc("tenzro_detectTee", {})


def get_tee_attestation(tee_type: str = None) -> dict:
    """Generate a TEE attestation report."""
    params = {}
    if tee_type:
        params["tee_type"] = tee_type
    return _rpc("tenzro_getAttestation", params)


def seal_data(data_hex: str, key_id: str) -> dict:
    """Seal (encrypt) data within the TEE enclave."""
    return _rpc("tenzro_sealData", {
        "data_hex": data_hex,
        "key_id": key_id,
    })


def unseal_data(sealed_hex: str, key_id: str) -> dict:
    """Unseal (decrypt) TEE-sealed data."""
    return _rpc("tenzro_unsealData", {
        "sealed_hex": sealed_hex,
        "key_id": key_id,
    })


def list_tee_providers() -> dict:
    """List all registered TEE providers on the network."""
    return _rpc("tenzro_listTeeProviders", {})


# ── ZK ───────────────────────────────────────────────────────────


def create_zk_proof(circuit_id: str, witness: dict) -> dict:
    """Create a Plonky3 STARK proof over KoalaBear.

    circuit_id: one of "inference", "settlement", "identity"
    witness: circuit-specific witness fields (numeric values), e.g.
        - inference: {model_checksum, input_checksum, computed_output}
        - settlement: {payer_balance, service_proof, nonce, prev_nonce, amount}
        - identity: {private_key, capabilities, capability_blinding,
                     actual_reputation, minimum_reputation}
    """
    params = {"circuit_id": circuit_id, **witness}
    return _rpc("tenzro_createZkProof", params)


def list_zk_circuits() -> dict:
    """List all available ZK circuits."""
    return _rpc("tenzro_listCircuits", {})


# ── Custody ──────────────────────────────────────────────────────


def create_mpc_wallet_advanced(threshold: int = 2,
                               total_shares: int = 3,
                               key_type: str = "ed25519") -> dict:
    """Create an MPC threshold wallet with custom config."""
    return _rpc("tenzro_createMpcWallet", {
        "threshold": threshold,
        "total_shares": total_shares,
        "key_type": key_type,
    })


def export_keystore(wallet_id: str, password: str) -> dict:
    """Export a wallet as an encrypted keystore JSON."""
    return _rpc("tenzro_exportKeystore", {
        "wallet_id": wallet_id,
        "password": password,
    })


def import_keystore(keystore_json: str, password: str) -> dict:
    """Import a wallet from an encrypted keystore JSON."""
    return _rpc("tenzro_importKeystore", {
        "keystore_json": keystore_json,
        "password": password,
    })


def get_key_shares(wallet_id: str) -> dict:
    """Get key share metadata for an MPC wallet."""
    return _rpc("tenzro_getKeyShares", {"wallet_id": wallet_id})


def rotate_keys(wallet_id: str) -> dict:
    """Rotate key shares of an MPC wallet."""
    return _rpc("tenzro_rotateKeys", {"wallet_id": wallet_id})


def set_spending_limits(wallet_id: str, daily_limit: float,
                        per_tx_limit: float) -> dict:
    """Set spending limits for a wallet."""
    return _rpc("tenzro_setSpendingLimits", {
        "wallet_id": wallet_id,
        "daily_limit": daily_limit,
        "per_tx_limit": per_tx_limit,
    })


def get_spending_limits(wallet_id: str) -> dict:
    """Get current spending limits for a wallet."""
    return _rpc("tenzro_getSpendingLimits", {"wallet_id": wallet_id})


def authorize_session(wallet_id: str, duration_secs: int,
                      operations: list) -> dict:
    """Authorize a temporary wallet session with allowed operations."""
    return _rpc("tenzro_authorizeSession", {
        "wallet_id": wallet_id,
        "duration_secs": duration_secs,
        "operations": operations,
    })


def revoke_session(session_id: str) -> dict:
    """Revoke an active wallet session."""
    return _rpc("tenzro_revokeSession", {"session_id": session_id})


# ── App / Paymaster ──────────────────────────────────────────────


def register_app(name: str, master_wallet_address: str) -> dict:
    """Register a new application with a master wallet."""
    return _rpc("tenzro_registerApp", {
        "name": name,
        "master_wallet_address": master_wallet_address,
    })


def create_user_wallet(app_id: str, label: str,
                       initial_funding: float = None) -> dict:
    """Create a user wallet under an application."""
    params = {"app_id": app_id, "label": label}
    if initial_funding is not None:
        params["initial_funding"] = initial_funding
    return _rpc("tenzro_createUserWallet", params)


def fund_user_wallet(master_address: str, user_address: str,
                     amount: float) -> dict:
    """Fund a user wallet from the app master wallet."""
    return _rpc("tenzro_fundUserWallet", {
        "master_address": master_address,
        "user_address": user_address,
        "amount": amount,
    })


def list_user_wallets(app_id: str) -> dict:
    """List all user wallets for an application."""
    return _rpc("tenzro_listUserWallets", {"app_id": app_id})


def sponsor_transaction(master_address: str, to: str,
                        amount: float) -> dict:
    """Sponsor a transaction using the paymaster wallet."""
    return _rpc("tenzro_sponsorTransaction", {
        "master_address": master_address,
        "to": to,
        "amount": amount,
    })


def get_usage_stats(app_id: str) -> dict:
    """Get usage statistics for an application."""
    return _rpc("tenzro_getUsageStats", {"app_id": app_id})


# ── Contract ABI ─────────────────────────────────────────────────


def encode_function(function_sig: str, args: list = None) -> dict:
    """ABI-encode a function call (e.g. 'transfer(address,uint256)')."""
    return _rpc("tenzro_encodeFunction", {
        "function_sig": function_sig,
        "args": args or [],
    })


def decode_result(data_hex: str, output_types: list) -> dict:
    """ABI-decode contract return data."""
    return _rpc("tenzro_decodeResult", {
        "data_hex": data_hex,
        "output_types": output_types,
    })


# ── OAuth 2.1 + DPoP Onboarding ──────────────────────────────────

def onboard_human(display_name, dpop_jkt=None):
    """Onboard a new human — provisions a TDIP DID + MPC wallet, returns
    a DPoP-bound OAuth 2.1 access token."""
    params = {"display_name": display_name}
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


def onboard_autonomous_agent(bond_funding_address, dpop_jkt=None):
    """Onboard a fully autonomous agent — requires a slashable TNZO bond
    posted at `bond_funding_address`."""
    params = {"bond_funding_address": bond_funding_address}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    return _rpc("tenzro_onboardAutonomousAgent", params)


def refresh_token(refresh_token_value, dpop_jkt=None):
    """Exchange an opaque refresh token for a fresh access JWT.

    Mirrors OAuth 2.1 ``grant_type=refresh_token``. The refresh token is
    re-usable until its absolute 30-day expiry (no rotation in V1). Pass
    ``dpop_jkt`` to upgrade a previously-unbound session to DPoP-bound,
    or to rotate the bound key.
    """
    params = {"refresh_token": refresh_token_value}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    return _rpc("tenzro_refreshToken", params)


def link_wallet_for_auth(wallet_id, dpop_jkt=None, display_name=None, ttl_secs=None):
    """Bind an existing MPC wallet to a fresh self-custody TDIP identity
    and mint an access JWT scoped for self-custody.

    Bridges ``tenzro_createWallet`` (which only returns ``wallet_id`` +
    ``address``) to the auth-mediated signing path: callers who created
    a wallet first can later obtain an access token bound to that
    wallet by passing back ``wallet_id`` plus an optional DPoP key
    thumbprint. Returns the same envelope as ``onboard_human``
    (``access_token`` + ``refresh_token`` + ``dpop_bound``).
    """
    params = {"wallet_id": wallet_id}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    if display_name:
        params["display_name"] = display_name
    if ttl_secs:
        params["ttl_secs"] = ttl_secs
    return _rpc("tenzro_linkWalletForAuth", params)


def revoke_jwt(jti, reason="revoked"):
    """Revoke a single JWT by its `jti` claim."""
    return _rpc("tenzro_revokeJwt", {"jti": jti, "reason": reason})


def revoke_did(did, reason="revoked"):
    """Revoke an entire identity by DID — cascades through the act-chain."""
    return _rpc("tenzro_revokeDid", {"did": did, "reason": reason})


def forget_identity(did):
    """TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously
    revoked identity from the registry and persistent storage. The DID
    must already be in `Revoked` status — call `revoke_did` first, allow
    cascading revocation to propagate, then call this. Distinct from
    `revoke_did` which is a logical delete."""
    return _rpc("tenzro_forgetIdentity", {"did": did})


def list_pending_approvals(approver_did):
    """List approvals in `Pending` status for the given approver DID."""
    return _rpc("tenzro_listPendingApprovals", {"approver_did": approver_did})


def decide_approval(approval_id, decision, approver_did):
    """Decide a pending approval — `decision` is `"approved"` or `"denied"`."""
    return _rpc("tenzro_decideApproval", {
        "approval_id": approval_id,
        "decision": decision,
        "approver_did": approver_did,
    })


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


def ap2_protocol_info() -> dict:
    """Return AP2 protocol identifiers and supported VDC types."""
    return _rpc("tenzro_ap2ProtocolInfo", {})


def ap2_sign_mandate(mandate_kind: str, mandate: dict, signer_did: str) -> dict:
    """Sign an AP2 v0.2 Checkout or Payment mandate via the auth-bound wallet's Ed25519 key.

    Args:
        mandate_kind: ``"checkout"`` (principal-signed pre-authorization) or
            ``"payment"`` (agent-signed final-offer commit) per AP2 v0.2.
        mandate: The full mandate object (CheckoutMandate or PaymentMandate JSON).
        signer_did: Signer DID — must match the controller of the auth-bound
            wallet (principal for checkout, agent for payment).

    Returns the assembled, self-verified Vdc JSON.
    """
    return _rpc(
        "tenzro_ap2SignMandate",
        {"mandate_kind": mandate_kind, "mandate": mandate, "signer_did": signer_did},
    )


def ap2_verify_mandate(vdc: dict) -> dict:
    """Verify a single AP2 Verifiable Digital Credential envelope."""
    return _rpc("tenzro_ap2VerifyMandate", {"vdc": vdc})


def ap2_validate_mandate_pair(
    checkout_vdc: dict,
    payment_vdc: dict,
    enforce_delegation: bool = False,
) -> dict:
    """Validate that a CheckoutMandate + PaymentMandate VDC pair are consistent (AP2 v0.2).

    When ``enforce_delegation`` is True, the node additionally cross-checks
    the agent's TDIP ``DelegationScope`` against the payment total via
    ``IdentityRegistry.enforce_operation(agent_did, "payment", total)``.
    Both layers must admit the payment for ``valid: true``. The response
    includes ``delegation_enforced`` so callers can confirm which path ran.
    """
    return _rpc("tenzro_ap2ValidateMandatePair", {
        "checkout_vdc": checkout_vdc,
        "payment_vdc": payment_vdc,
        "enforce_delegation": enforce_delegation,
    })


def ap2_create_session(agent_did: str, provider_did: str, service: str,
                       max_amount: int, asset: str = "TNZO") -> dict:
    """Create a new AP2 session authorizing the agent to pay the provider."""
    return _rpc("tenzro_ap2CreateSession", {
        "agent_did": agent_did,
        "provider_did": provider_did,
        "service": service,
        "max_amount": max_amount,
        "asset": asset,
    })


def ap2_authorize_payment(session_id: str, amount: int) -> dict:
    """Request a payment authorization under an existing AP2 session."""
    return _rpc("tenzro_ap2AuthorizePayment", {
        "session_id": session_id,
        "amount": amount,
    })


def ap2_execute_payment(session_id: str, authorization_id: str) -> dict:
    """Execute a previously-authorized AP2 payment."""
    return _rpc("tenzro_ap2ExecutePayment", {
        "session_id": session_id,
        "authorization_id": authorization_id,
    })


def ap2_cancel_session(session_id: str) -> dict:
    """Cancel an AP2 session, revoking remaining authorizations."""
    return _rpc("tenzro_ap2CancelSession", {"session_id": session_id})


def ap2_get_session(session_id: str) -> dict:
    """Fetch AP2 session state."""
    return _rpc("tenzro_ap2GetSession", {"session_id": session_id})


def ap2_list_agent_sessions(agent_did: str) -> dict:
    """List all AP2 sessions for an agent DID."""
    return _rpc("tenzro_ap2ListAgentSessions", {"agent_did": agent_did})


# ── ERC-8004 (Trustless Agents Registry — full v0.6+ surface) ────


# -- Identity registry --------------------------------------------------

def erc8004_derive_agent_id(did: str) -> dict:
    """Derive the canonical ERC-8004 agentId = keccak256(utf8(did))."""
    return _rpc("tenzro_erc8004DeriveAgentId", {"did": did})


def erc8004_encode_register(did: str, agent_address: str,
                            metadata_uri: str) -> dict:
    """Encode calldata for IdentityRegistry.registerAgent(bytes32 agentId, address agentAddress, string metadataURI)."""
    return _rpc("tenzro_erc8004EncodeRegister", {
        "did": did,
        "agent_address": agent_address,
        "metadata_uri": metadata_uri,
    })


def erc8004_encode_get_agent(agent_id: str) -> dict:
    """Encode calldata for IdentityRegistry.getAgent(bytes32 agentId)."""
    return _rpc("tenzro_erc8004EncodeGetAgent", {"agent_id": agent_id})


def erc8004_decode_get_agent(return_data: str) -> dict:
    """Decode (address, string) returndata from getAgent() into {agent_address, metadata_uri}."""
    return _rpc("tenzro_erc8004DecodeGetAgent", {"return_data": return_data})


def erc8004_encode_set_agent_uri(agent_id: str, metadata_uri: str) -> dict:
    """Encode calldata for IdentityRegistry.setAgentURI(uint256 agentId, string metadataURI) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeSetAgentURI", {
        "agent_id": agent_id,
        "metadata_uri": metadata_uri,
    })


def erc8004_encode_set_agent_wallet(agent_id: str, new_wallet: str,
                                     deadline: int, signature: str) -> dict:
    """Encode calldata for IdentityRegistry.setAgentWallet(uint256, address, uint256, bytes) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeSetAgentWallet", {
        "agent_id": agent_id,
        "new_wallet": new_wallet,
        "deadline": deadline,
        "signature": signature,
    })


def erc8004_encode_set_metadata(agent_id: str, metadata_key: str,
                                 metadata_value: str) -> dict:
    """Encode calldata for IdentityRegistry.setMetadata(uint256, string, bytes) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeSetMetadata", {
        "agent_id": agent_id,
        "metadata_key": metadata_key,
        "metadata_value": metadata_value,
    })


def erc8004_encode_get_metadata(agent_id: str, metadata_key: str) -> dict:
    """Encode calldata for IdentityRegistry.getMetadata(uint256, string) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeGetMetadata", {
        "agent_id": agent_id,
        "metadata_key": metadata_key,
    })


def erc8004_decode_get_metadata(return_data: str) -> dict:
    """Decode bytes returndata from getMetadata() into {metadata_value} (v0.6+)."""
    return _rpc("tenzro_erc8004DecodeGetMetadata", {"return_data": return_data})


def erc8004_encode_get_agent_uri(agent_id: str) -> dict:
    """Encode calldata for IdentityRegistry.getAgentURI(uint256 agentId) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeGetAgentURI", {"agent_id": agent_id})


def erc8004_encode_get_agent_wallet(agent_id: str) -> dict:
    """Encode calldata for IdentityRegistry.getAgentWallet(uint256 agentId) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeGetAgentWallet", {"agent_id": agent_id})


# -- Reputation registry ------------------------------------------------

def erc8004_encode_feedback(subject_agent_id: str, rating: int,
                            context_uri: str) -> dict:
    """Encode calldata for ReputationRegistry.submitFeedback(bytes32, int8, string).

    `rating` is in -100..=100 (Tenzro convention).
    """
    return _rpc("tenzro_erc8004EncodeFeedback", {
        "subject_agent_id": subject_agent_id,
        "rating": rating,
        "context_uri": context_uri,
    })


def erc8004_encode_get_feedback(subject_agent_id: str, index: int) -> dict:
    """Encode calldata for ReputationRegistry.getFeedback(bytes32 subject, uint256 index)."""
    return _rpc("tenzro_erc8004EncodeGetFeedback", {
        "subject_agent_id": subject_agent_id,
        "index": index,
    })


def erc8004_encode_get_feedback_count(subject_agent_id: str) -> dict:
    """Encode calldata for ReputationRegistry.getFeedbackCount(bytes32 subject)."""
    return _rpc("tenzro_erc8004EncodeGetFeedbackCount", {
        "subject_agent_id": subject_agent_id,
    })


def erc8004_encode_revoke_feedback(agent_id: str, feedback_id: str) -> dict:
    """Encode calldata for ReputationRegistry.revokeFeedback(uint256, bytes32) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeRevokeFeedback", {
        "agent_id": agent_id,
        "feedback_id": feedback_id,
    })


def erc8004_encode_append_response(agent_id: str, feedback_id: str,
                                    response_uri: str) -> dict:
    """Encode calldata for ReputationRegistry.appendResponse(uint256, bytes32, string) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeAppendResponse", {
        "agent_id": agent_id,
        "feedback_id": feedback_id,
        "response_uri": response_uri,
    })


def erc8004_encode_is_feedback_revoked(agent_id: str, feedback_id: str) -> dict:
    """Encode calldata for ReputationRegistry.isFeedbackRevoked(uint256, bytes32) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeIsFeedbackRevoked", {
        "agent_id": agent_id,
        "feedback_id": feedback_id,
    })


def erc8004_encode_get_feedback_responses(agent_id: str, feedback_id: str) -> dict:
    """Encode calldata for ReputationRegistry.getFeedbackResponses(uint256, bytes32) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeGetFeedbackResponses", {
        "agent_id": agent_id,
        "feedback_id": feedback_id,
    })


# -- Validation registry -----------------------------------------------

def erc8004_encode_validation_request(validator_address: str, agent_id: str,
                                       request_uri: str,
                                       request_hash: str) -> dict:
    """Encode calldata for ValidationRegistry.validationRequest(address, uint256, string, bytes32)."""
    return _rpc("tenzro_erc8004EncodeValidationRequest", {
        "validator_address": validator_address,
        "agent_id": agent_id,
        "request_uri": request_uri,
        "request_hash": request_hash,
    })


def erc8004_encode_validation_response(request_hash: str, response: int,
                                        response_uri: str,
                                        response_hash: str,
                                        tag: str = "") -> dict:
    """Encode calldata for ValidationRegistry.validationResponse(bytes32, uint8, string, bytes32, string).

    `response` is a 0..=100 quality score per the canonical ERC-8004 spec.
    """
    return _rpc("tenzro_erc8004EncodeValidationResponse", {
        "request_hash": request_hash,
        "response": response,
        "response_uri": response_uri,
        "response_hash": response_hash,
        "tag": tag,
    })


def erc8004_encode_get_validation(request_hash: str) -> dict:
    """Encode calldata for ValidationRegistry.getValidation(bytes32 requestHash) (v0.6+)."""
    return _rpc("tenzro_erc8004EncodeGetValidation", {"request_hash": request_hash})


# ── Wormhole (Cross-Chain Bridge) ────────────────────────────────


def wormhole_chain_id(chain: str) -> dict:
    """Look up the Wormhole chain id for a chain name (e.g. 'ethereum')."""
    return _rpc("tenzro_wormholeChainId", {"chain": chain})


def wormhole_parse_vaa_id(vaa_id: str) -> dict:
    """Parse a Wormhole VAA id (chain/emitter/sequence) into components."""
    return _rpc("tenzro_wormholeParseVaaId", {"vaa_id": vaa_id})


def wormhole_bridge(source_chain: str, dest_chain: str, asset: str,
                    amount: int, sender: str, recipient: str) -> dict:
    """Execute a Wormhole cross-chain bridge transfer."""
    return _rpc("tenzro_wormholeBridge", {
        "source_chain": source_chain,
        "dest_chain": dest_chain,
        "asset": asset,
        "amount": amount,
        "sender": sender,
        "recipient": recipient,
    })


# ── CCT (Chainlink Cross-Chain Token) Pool Registry ──────────────


def cct_list_pools() -> dict:
    """List all registered TNZO CCT pools across chains."""
    return _rpc("tenzro_cctListPools", {})


def cct_get_pool(chain: str) -> dict:
    """Get CCT pool details for a specific chain."""
    return _rpc("tenzro_cctGetPool", {"chain": chain})


# ── Multi-modal inference (wave 1) ────────────────────────────────
#
# Wraps the JSON-RPC surface added by Layer A. Each modality follows
# the same shape: list catalog (curated entries), list (loaded models),
# load/unload, and the inference verb itself.

# Forecast (timeseries) -------------------------------------------------

def list_forecast_catalog() -> dict:
    """List the curated timeseries forecast model catalog."""
    return _rpc("tenzro_listForecastCatalog", {})


def list_forecast_models() -> dict:
    """List timeseries forecast models currently loaded on this node."""
    return _rpc("tenzro_listForecastModels", {})


def forecast(model_id: str, series: list, horizon: int,
             quantiles: list = None) -> dict:
    """Run a probabilistic forecast on the given series."""
    params = {"model_id": model_id, "series": series, "horizon": horizon}
    if quantiles is not None:
        params["quantiles"] = quantiles
    return _rpc("tenzro_forecast", params)


# Vision embeddings -----------------------------------------------------

def list_vision_catalog() -> dict:
    """List the curated vision encoder catalog."""
    return _rpc("tenzro_listVisionCatalog", {})


def list_vision_models() -> dict:
    """List vision encoders currently loaded on this node."""
    return _rpc("tenzro_listVisionModels", {})


def vision_embed(model_id: str, image_b64: str,
                 normalize: bool = True) -> dict:
    """Embed a base64-encoded image with the named vision encoder."""
    return _rpc("tenzro_visionEmbed", {
        "model_id": model_id,
        "image_b64": image_b64,
        "normalize": normalize,
    })


def vision_similarity(model_id: str, image_b64: str, text: str) -> dict:
    """Cosine similarity between an image embedding and a text prompt."""
    return _rpc("tenzro_visionSimilarity", {
        "model_id": model_id,
        "image_b64": image_b64,
        "text": text,
    })


# Text embeddings -------------------------------------------------------

def list_text_embedding_catalog() -> dict:
    """List the curated text embedding catalog (Qwen3-Embedding, EmbeddingGemma, BGE-M3, ...)."""
    return _rpc("tenzro_listTextEmbeddingCatalog", {})


def list_text_embedding_models() -> dict:
    """List text embedding models currently loaded on this node."""
    return _rpc("tenzro_listTextEmbeddingModels", {})


def text_embed(model_id: str, inputs: list,
               requested_dim: int = None) -> dict:
    """Embed a batch of strings; optional Matryoshka truncation."""
    params = {"model_id": model_id, "inputs": inputs}
    if requested_dim is not None:
        params["requested_dim"] = requested_dim
    return _rpc("tenzro_textEmbed", params)


# Segmentation ----------------------------------------------------------

def list_segmentation_catalog() -> dict:
    """List the curated segmentation catalog (SAM 3, SAM 2, EdgeSAM, MobileSAM)."""
    return _rpc("tenzro_listSegmentationCatalog", {})


def list_segmentation_models() -> dict:
    """List segmentation models currently loaded on this node."""
    return _rpc("tenzro_listSegmentationModels", {})


def segment(model_id: str, image_b64: str, prompts: list) -> dict:
    """Run promptable segmentation. Prompts: [{"type":"point",...} | {"type":"box",...}, ...]."""
    return _rpc("tenzro_segment", {
        "model_id": model_id,
        "image_b64": image_b64,
        "prompts": prompts,
    })


# Detection -------------------------------------------------------------

def list_detection_catalog() -> dict:
    """List the curated detection catalog (RF-DETR, D-FINE)."""
    return _rpc("tenzro_listDetectionCatalog", {})


def list_detection_models() -> dict:
    """List detection models currently loaded on this node."""
    return _rpc("tenzro_listDetectionModels", {})


def detect(model_id: str, image_b64: str,
           score_threshold: float = 0.5) -> dict:
    """Run object detection on the given image."""
    return _rpc("tenzro_detect", {
        "model_id": model_id,
        "image_b64": image_b64,
        "score_threshold": score_threshold,
    })


# Audio (ASR) -----------------------------------------------------------

def list_audio_catalog() -> dict:
    """List the curated ASR catalog (Moonshine, Distil-Whisper, Whisper-turbo, Parakeet, Canary)."""
    return _rpc("tenzro_listAudioCatalog", {})


def list_audio_models() -> dict:
    """List audio models currently loaded on this node."""
    return _rpc("tenzro_listAudioModels", {})


def transcribe(model_id: str, audio_b64: str, language: str = None,
               timestamps: bool = False) -> dict:
    """Transcribe a base64-encoded audio buffer."""
    params = {
        "model_id": model_id,
        "audio_b64": audio_b64,
        "timestamps": timestamps,
    }
    if language is not None:
        params["language"] = language
    return _rpc("tenzro_transcribe", params)


# Video -----------------------------------------------------------------

def list_video_catalog() -> dict:
    """List the curated video catalog (empty in wave 1 — license/export gap)."""
    return _rpc("tenzro_listVideoCatalog", {})


def list_video_models() -> dict:
    """List video models currently loaded on this node."""
    return _rpc("tenzro_listVideoModels", {})


def video_embed(model_id: str, video_b64: str,
                frame_stride: int = 30) -> dict:
    """Embed a base64-encoded video clip."""
    return _rpc("tenzro_videoEmbed", {
        "model_id": model_id,
        "video_b64": video_b64,
        "frame_stride": frame_stride,
    })


# ── AgentBond (Spec 9) ────────────────────────────────────────────


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


def post_agent_bond(controller_address: str, agent_did: str,
                    controller_did: str, amount_wei: int) -> dict:
    """Post a new AgentBond via signed `PostAgentBond` transaction.

    Locks `amount_wei` TNZO from `controller_address` (the bearer wallet)
    into the bond vault for `agent_did`. The bond enters Active state and
    promotes the agent to the Delegated admission lane while ≥ the
    configured `bond_min_for_promotion`.

    Uses ambient OAuth/DPoP auth — `controller_address` must match the
    bearer's wallet. The VM enforces that `agent_did` either has no prior
    bond or its prior bond is in a terminal state.
    """
    nonce, chain_id = _fetch_nonce_and_chain_id(controller_address)
    tx_type = {
        "type": "PostAgentBond",
        "data": {
            "agent_did": agent_did,
            "controller_did": controller_did,
            "amount": str(amount_wei),
        },
    }
    params = {
        "from": controller_address,
        "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "value": 0,
        "gas_limit": 90000,
        "gas_price": 1_000_000_000,
        "nonce": nonce,
        "chain_id": chain_id,
        "tx_type": tx_type,
    }
    return _rpc("tenzro_signAndSendTransaction", params)


def increase_agent_bond(controller_address: str, agent_did: str,
                        amount_wei: int) -> dict:
    """Top up an existing Active AgentBond by `amount_wei`.

    Uses ambient OAuth/DPoP auth — `controller_address` must equal the
    original poster (the bond's controller). Locks additional TNZO into
    the same bond vault.
    """
    nonce, chain_id = _fetch_nonce_and_chain_id(controller_address)
    tx_type = {
        "type": "IncreaseAgentBond",
        "data": {
            "agent_did": agent_did,
            "amount": str(amount_wei),
        },
    }
    params = {
        "from": controller_address,
        "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "value": 0,
        "gas_limit": 75000,
        "gas_price": 1_000_000_000,
        "nonce": nonce,
        "chain_id": chain_id,
        "tx_type": tx_type,
    }
    return _rpc("tenzro_signAndSendTransaction", params)


def withdraw_agent_bond(controller_address: str, agent_did: str) -> dict:
    """Initiate cooldown on an Active AgentBond via `WithdrawAgentBond`.

    Funds are not released by the VM — finalisation happens off-VM via the
    node-side BondManager once `cooldown_ms` has elapsed. Uses ambient
    OAuth/DPoP auth — `controller_address` must equal the bond's controller.
    """
    nonce, chain_id = _fetch_nonce_and_chain_id(controller_address)
    tx_type = {
        "type": "WithdrawAgentBond",
        "data": {"agent_did": agent_did},
    }
    params = {
        "from": controller_address,
        "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "value": 0,
        "gas_limit": 60000,
        "gas_price": 1_000_000_000,
        "nonce": nonce,
        "chain_id": chain_id,
        "tx_type": tx_type,
    }
    return _rpc("tenzro_signAndSendTransaction", params)


# ── Insurance (Spec 9) ────────────────────────────────────────────


def file_insurance_claim(claimant_did: str, claimant_address: str,
                         against_agent_did: str, amount_requested_wei: int,
                         nonce: int,
                         receipt_refs: list = None,
                         narrative: str = None) -> dict:
    """Open a new insurance claim against a bonded agent.

    The claim enters `Open` status awaiting governance adjudication; payout
    (if approved) is settled via a separate `PayInsuranceClaim` transaction.
    `nonce` is a per-claim disambiguator used in the deterministic claim_id
    derivation. `receipt_refs` is an optional list of receipt-id strings;
    `narrative` is capped at 1024 bytes server-side.
    """
    params = {
        "claimant_did": claimant_did,
        "claimant_address": claimant_address,
        "against_agent_did": against_agent_did,
        "amount_requested": str(amount_requested_wei),
        "nonce": nonce,
    }
    if receipt_refs is not None:
        params["receipt_refs"] = receipt_refs
    if narrative is not None:
        params["narrative"] = narrative
    return _rpc("tenzro_fileInsuranceClaim", params)


def list_insurance_claims() -> dict:
    """List every insurance claim (Open + Approved + Rejected + Paid)."""
    return _rpc("tenzro_listInsuranceClaims", {})


def get_insurance_claim(claim_id: str) -> dict:
    """Fetch a single insurance claim by its id."""
    return _rpc("tenzro_getInsuranceClaim", {"claim_id": claim_id})


def get_insurance_pool_balance() -> dict:
    """Read the current insurance pool vault balance."""
    return _rpc("tenzro_getInsurancePoolBalance", {})


# ── Adaptive Burn (Spec 8) ────────────────────────────────────────


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


def list_adaptive_burn_proposals() -> dict:
    """List adaptive-burn governance proposals.

    Surfaces auto-generated burn-rate adjustment proposals queued by the
    governance executor. Returns `{ proposals: [...], count }`.
    """
    return _rpc("tenzro_listAdaptiveBurnProposals", {})


# ── SeedAgent (Spec 10) ───────────────────────────────────────────


def get_treasury_earmark(name: str = None) -> dict:
    """Read the SeedAgent treasury earmark singleton.

    Returns the genesis-funded TNZO allocation, decay schedule, remaining
    balance, drawn-to-date, and master `enabled` switch. Only one earmark
    exists in wave 1 (`name == "SeedAgent"`); the optional `name` arg is a
    forward-compat filter.
    """
    params = {}
    if name is not None:
        params["name"] = name
    return _rpc("tenzro_getTreasuryEarmark", params)


def get_seed_agent_charter(charter_id: str) -> dict:
    """Read a SeedAgent governance charter by hex `charter_id`.

    Returns the operations whitelist, spend caps (daily/monthly/per-tx),
    target throughput, counterparty filter, sunset, and enabled flag.
    """
    return _rpc("tenzro_getSeedAgentCharter", {"charter_id": charter_id})


def list_seed_agent_charters() -> dict:
    """List every governance-signed SeedAgent charter."""
    return _rpc("tenzro_listSeedAgentCharters", {})


def list_seed_agents(charter_id: str = None) -> dict:
    """List SeedAgent registry records, optionally filtered by `charter_id`.

    Returns per-DID provisioning state: agent_did, controller_did,
    charter_id, status (Active|Paused|Quarantined|Terminated), bond_id,
    allocation_used, provisioned_at, last_active.
    """
    params = {}
    if charter_id is not None:
        params["charter_id"] = charter_id
    return _rpc("tenzro_listSeedAgents", params)


def get_network_activity(window: str = None,
                         exclude_seed: bool = False) -> dict:
    """Read aggregated network-activity counters.

    `window` is a string like "24h" / "7d"; `exclude_seed` filters out
    transactions where either side is flagged `is_seed_agent` (so organic
    activity can be measured against the bootstrap baseline). Returns
    inference / settlement / bridge / 7683 counts plus seed-agent totals.
    """
    params = {}
    if window is not None:
        params["window"] = window
    if exclude_seed:
        params["exclude_seed"] = exclude_seed
    return _rpc("tenzro_getNetworkActivity", params)


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


# ── Burn quota & mempool (Specs 3 + 6) ────────────────────────────


def get_burn_quota() -> dict:
    """Read the singleton BurnQuota state (Spec 3 — dual-rail gas+burn).

    Returns balance / cap / daily_target / min_reserve_bps / min_reserve /
    last_refill / total_drained / total_refilled / deficit / can_drain_one.
    Wave-1 is read-only — drains/refills happen in-process.
    """
    return _rpc("tenzro_getBurnQuota", {})


def get_mempool_stats() -> dict:
    """Read per-lane mempool statistics (Spec 2 — admission control).

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
    """Read the hot-state local fee market score for `address` (Spec 6).

    Returns score / reexecutions / writes / is_hot / multiplier and the
    current effective base fee + per-gas surcharge for transactions
    touching this account.
    """
    return _rpc("tenzro_getAccountContention", {"address": address})


# ── DA offload (Spec 7) ───────────────────────────────────────────


def get_da_backends() -> dict:
    """List configured DA backends and their health status.

    Wave-1 ships only `inline_fallback`; EigenDA / Celestia / Avail entries
    appear when their feature-gated adapters land.
    """
    return _rpc("tenzro_getDaBackends", {})


def verify_da_pointer(pointer: dict) -> dict:
    """Probe whether a DA pointer is dereferenceable right now.

    `pointer` is a dict with `backend` (`inline_fallback` | `eigenda` |
    `celestia` | `avail`), hex `namespace`, hex `locator`, and optional
    hex `commitment_kzg` / `attestation_root` (32 bytes).
    """
    return _rpc("tenzro_verifyDaPointer", {"pointer": pointer})


# ── Receipts & principal chain (Spec 5) ───────────────────────────


def get_receipt_principal_chain(receipt_id: str) -> dict:
    """Walk the principal chain for a settlement receipt.

    Returns the ordered chain of acting DIDs from the leaf actor up to the
    terminal controller, reconstructed from the receipt's delegation graph.
    """
    return _rpc("tenzro_getReceiptPrincipalChain", {"receipt_id": receipt_id})


def list_receipts_by_actor(actor_did: str) -> dict:
    """List receipt ids whose acting DID matches `actor_did`. Oldest first."""
    return _rpc("tenzro_listReceiptsByActor", {"did": actor_did})


def list_receipts_by_controller(controller_did: str) -> dict:
    """List receipt ids whose principal chain terminates at `controller_did`.

    Oldest first.
    """
    return _rpc("tenzro_listReceiptsByController", {"did": controller_did})


def summarize_controller(controller_did: str,
                        since: int = None,
                        until: int = None) -> dict:
    """Aggregate a controller's activity across an optional unix-second window.

    Returns receipt count, total settled value, distinct delegated agents,
    KYC-tier evolution, and bond extremes.
    """
    params = {"did": controller_did}
    if since is not None:
        params["since"] = since
    if until is not None:
        params["until"] = until
    return _rpc("tenzro_summarizeController", params)


# ── Agent lifecycle & kill-switch ─────────────────────────────────


def get_agent_lifecycle(agent_id: str) -> dict:
    """Read the lifecycle state machine for `agent_id`.

    Returns current state (Created|Active|Suspended|Terminated), last
    state-change timestamp, last heartbeat, and the full state history.
    """
    return _rpc("tenzro_getAgentLifecycle", {"agent_id": agent_id})


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


def list_inference_usage(model_id: str = None,
                         provider: str = None) -> dict:
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


def get_provider_reputation(provider_address: str) -> dict:
    """Read the current reputation score for an inference provider.

    Returns `{ provider, reputation }` where `reputation` is a u64 in
    [0, 1000]. The score moves +1 / -5 per success/failure.
    """
    return _rpc("tenzro_getProviderReputation", {"provider": provider_address})


# ── Provenance & disputes ─────────────────────────────────────────


def get_provenance(content_hash: str) -> dict:
    """Look up a cached ProvenanceManifest by 32-byte hex `content_hash`.

    Wave-1 read path for the EU AI Act Art. 50(2) machine-readable
    synthetic-content marker. The store is bounded LRU-by-signed_at, so a
    `not found` does not prove the response was never signed.
    """
    return _rpc("tenzro_getProvenance", {"content_hash": content_hash})


def get_dispute(dispute_id: str) -> dict:
    """Fetch a single channel dispute record by id.

    Returns the full ChannelDispute (challenger, evidence, status,
    timestamps, resolution).
    """
    return _rpc("tenzro_getDispute", {"dispute_id": dispute_id})


def list_disputes_by_channel(channel_id: str) -> dict:
    """List every dispute (open or historical) attached to a channel.

    Returns `{ channel_id, count, disputes: [...] }`. Empty list is not
    an error.
    """
    return _rpc("tenzro_listDisputesByChannel", {"channel_id": channel_id})


# ── CLI ───────────────────────────────────────────────────────────

COMMANDS = {
    # Wallet & Balance
    "join_network": lambda args: join_as_micro_node(
        args[0] if args else "Tenzro User",
        args[1] if len(args) > 1 else "cli",
    ),
    "create_wallet": lambda args: create_wallet(args[0] if args else "ed25519"),
    "get_balance": lambda args: get_balance(args[0]),
    "balance": lambda args: get_balance(args[0]),
    "send": lambda args: send_transaction(
        args[0],
        args[1],
        int(args[2]),
    ),
    "faucet": lambda args: request_faucet(args[0]),
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
    "set_username": lambda args: set_username(args[0], args[1]),
    "resolve_username": lambda args: resolve_username(args[0]),
    "revoke_did": lambda args: revoke_did(args[0], args[1] if len(args) > 1 else "revoked"),
    "forget_identity": lambda args: forget_identity(args[0]),
    # Verification
    "verify_zk_proof": lambda args: verify_zk_proof(
        args[0],
        json.loads(args[1]) if len(args) > 1 else [],
        args[2],
    ),
    "verify_transaction": lambda args: verify_transaction(args[0], args[1], args[2]),
    "verify_settlement": lambda args: verify_settlement(args[0], args[1], args[2]),
    "verify_inference": lambda args: verify_inference(args[0], args[1], args[2]),
    # Token
    "total_supply": lambda args: total_supply(),
    "token_balance": lambda args: token_balance(args[0]),
    # Token Registry & Contracts
    "create_token": lambda args: create_token(
        args[0], args[1], args[2], args[3],
        int(args[4]) if len(args) > 4 else 18,
        "--mintable" in args,
        "--burnable" in args,
    ),
    "get_token_info": lambda args: get_token_info(symbol=args[0]),
    "list_tokens": lambda args: list_tokens(
        args[0] if args else None,
        int(args[1]) if len(args) > 1 else 50,
    ),
    "get_token_balance": lambda args: get_token_balance_all_vms(args[0]),
    "cross_vm_transfer": lambda args: cross_vm_transfer(
        args[0], args[1], args[2], args[3], args[4], args[5],
    ),
    "deploy_contract": lambda args: deploy_contract(
        args[0], args[1], args[2],
        args[3] if len(args) > 3 else None,
        int(args[4]) if len(args) > 4 else 3_000_000,
    ),
    # Models
    "list_models": lambda args: list_models(),
    "chat": lambda args: chat(args[0], " ".join(args[1:]) if len(args) > 1 else args[1]),
    "list_model_endpoints": lambda args: list_model_endpoints(),
    # Payments
    "create_payment": lambda args: create_payment_challenge(
        args[0], args[1], int(args[2]),
        args[3] if len(args) > 3 else "TNZO",
        args[4] if len(args) > 4 else None,
    ),
    "verify_payment": lambda args: verify_payment(
        args[0], args[1], args[2], args[3], int(args[4]), args[5], args[6],
    ),
    # Delegation
    "set_delegation": lambda args: set_delegation_scope(
        args[0], int(args[1]), int(args[2]),
    ),
    # Task Marketplace
    "post_task": lambda args: post_task(
        args[0], args[1], args[2], int(args[3]),
    ),
    "list_tasks": lambda args: list_tasks(
        args[0] if args else None,
        args[1] if len(args) > 1 else None,
    ),
    "get_task": lambda args: get_task(args[0]),
    "cancel_task": lambda args: cancel_task(args[0]),
    "submit_quote": lambda args: submit_quote(
        args[0], int(args[1]),
        args[2] if len(args) > 2 else None,
        int(args[3]) if len(args) > 3 else None,
    ),
    # Agent Templates
    "list_agent_templates": lambda args: list_agent_templates(
        args[0] if args else None,
    ),
    "register_agent_template": lambda args: register_agent_template(
        args[0], args[1], args[2],
        args[3] if len(args) > 3 else None,
    ),
    "get_agent_template": lambda args: get_agent_template(args[0]),
    "spawn_agent_from_template": lambda args: spawn_agent_from_template(
        args[0], args[1],
        args[2].split(",") if len(args) > 2 else None,
        args[3] if len(args) > 3 else None,
    ),
    "rate_agent_template": lambda args: rate_agent_template(
        args[0], int(args[1]),
        args[2] if len(args) > 2 else None,
    ),
    "search_agent_templates": lambda args: search_agent_templates(
        " ".join(args) if args else "",
    ),
    "get_agent_template_stats": lambda args: get_agent_template_stats(args[0]),
    # Skills Registry
    "list_skills": lambda args: list_skills(
        args[0] if args else None,
        args[1] if len(args) > 1 else None,
    ),
    "register_skill": lambda args: register_skill(
        args[0], args[1], args[2], args[3], int(args[4]),
        args[5].split(",") if len(args) > 5 else None,
    ),
    "search_skills": lambda args: search_skills(
        " ".join(args) if args else "",
    ),
    "use_skill": lambda args: use_skill(
        args[0],
        json.loads(args[1]) if len(args) > 1 else None,
    ),
    "spawn_agent_with_skill": lambda args: spawn_agent_with_skill(
        args[0], args[1], args[2],
        args[3].split(",") if len(args) > 3 else None,
    ),
    "get_skill": lambda args: get_skill(args[0]),
    "update_skill": lambda args: update_skill(
        args[0],
        args[1] if len(args) > 1 else None,
    ),
    "get_skill_usage": lambda args: get_skill_usage(args[0]),
    "get_tool_usage": lambda args: get_tool_usage(args[0]),
    # Tools Registry
    "register_tool": lambda args: register_tool(
        args[0], args[1], args[2],
        args[3] if len(args) > 3 else "mcp",
    ),
    "list_tools": lambda args: list_tools(
        args[0] if args else None,
    ),
    "get_tool": lambda args: get_tool(args[0]),
    "search_tools": lambda args: search_tools(
        " ".join(args) if args else "",
    ),
    "use_tool": lambda args: use_tool(
        args[0],
        json.loads(args[1]) if len(args) > 1 else None,
    ),
    "update_tool": lambda args: update_tool(args[0]),
    # Agent Spawning & Swarm
    "register_agent": lambda args: register_agent(
        args[0], args[1],
        args[2].split(",") if len(args) > 2 else None,
    ),
    "spawn_agent": lambda args: spawn_agent(
        args[0], args[1],
        args[2].split(",") if len(args) > 2 else None,
    ),
    "run_agent_task": lambda args: run_agent_task(args[0], " ".join(args[1:])),
    "create_swarm": lambda args: create_swarm(args[0], args[1:]),
    "get_swarm_status": lambda args: get_swarm_status(args[0]),
    "terminate_swarm": lambda args: terminate_swarm(args[0]),
    "list_agents": lambda args: list_agents(),
    "send_agent_message": lambda args: send_agent_message(args[0], args[1], " ".join(args[2:])),
    "delegate_task": lambda args: delegate_task(args[0], " ".join(args[1:])),
    "discover_models": lambda args: discover_models(args[0] if args else None),
    "discover_agents": lambda args: discover_agents(args[0] if args else None),
    "fund_agent": lambda args: fund_agent(args[0], int(args[1])),
    # Task Marketplace (Extended)
    "assign_task": lambda args: assign_task(args[0], args[1]),
    "complete_task": lambda args: complete_task(args[0], " ".join(args[1:])),
    "update_task": lambda args: update_task(args[0]),
    # Agent Template (Extended)
    "update_agent_template": lambda args: update_agent_template(args[0]),
    "run_agent_template": lambda args: run_agent_template(
        args[0], int(args[1]) if len(args) > 1 else 10,
    ),
    "download_agent_template": lambda args: download_agent_template(args[0]),
    "spawn_agent_template": lambda args: spawn_agent_template(
        args[0], args[1],
        args[2] if len(args) > 2 else None,
    ),
    # Bridge
    "bridge_tokens": lambda args: bridge_tokens(
        args[0], args[1], args[2], int(args[3]), args[4], args[5],
    ),
    # Staking & Providers
    "stake": lambda args: stake_tokens(
        int(args[0]), args[1] if len(args) > 1 else "Validator",
    ),
    "unstake": lambda args: unstake_tokens(int(args[0])),
    "register_provider": lambda args: register_provider(args[0]),
    "provider_stats": lambda args: provider_stats(),
    # NFT Collections
    "create_nft_collection": lambda args: create_nft_collection(
        args[0], args[1], args[2],
        args[3] if len(args) > 3 else "erc721",
    ),
    "mint_nft": lambda args: mint_nft(args[0], args[1], args[2], args[3]),
    "mint_nft_batch": lambda args: mint_nft_batch(
        args[0], args[1],
        args[2].split(","), args[3].split(","),
    ),
    "transfer_nft": lambda args: transfer_nft(args[0], args[1], args[2], args[3]),
    "get_nft_owner": lambda args: get_nft_owner(args[0], args[1]),
    "get_nft_balance": lambda args: get_nft_balance(args[0], args[1]),
    "get_nft_collection": lambda args: get_nft_collection(args[0]),
    "list_nft_collections": lambda args: list_nft_collections(
        int(args[0]) if args else 50,
    ),
    # Bridge (Extended)
    "bridge_quote": lambda args: bridge_quote(
        args[0], args[1], args[2], int(args[3]),
        args[4] if len(args) > 4 else None,
    ),
    "bridge_execute": lambda args: bridge_execute(
        args[0], args[1], args[2], int(args[3]), args[4], args[5],
        args[6] if len(args) > 6 else None,
    ),
    "bridge_status": lambda args: bridge_status(
        args[0], args[1] if len(args) > 1 else None,
    ),
    "bridge_with_hook": lambda args: bridge_with_hook(
        args[0], args[1], args[2], int(args[3]),
        args[4], args[5], args[6],
        "--no-revert" not in args,
    ),
    # ERC-7802 Crosschain
    "crosschain_mint": lambda args: crosschain_mint(
        args[0], args[1], int(args[2]), args[3],
    ),
    "crosschain_burn": lambda args: crosschain_burn(
        args[0], args[1], int(args[2]), args[3],
    ),
    "authorize_bridge": lambda args: authorize_bridge(
        args[0], args[1],
        int(args[2]) if len(args) > 2 else None,
        int(args[3]) if len(args) > 3 else None,
    ),
    "list_authorized_bridges": lambda args: list_authorized_bridges(),
    # ERC-3643 Compliance
    "check_compliance": lambda args: check_compliance(
        args[0], args[1], args[2], int(args[3]),
    ),
    "register_compliance": lambda args: register_compliance(
        args[0],
        "--kyc" in args,
        int(args[args.index("--min-tier") + 1]) if "--min-tier" in args else 1,
        "--accredited" in args,
    ),
    "freeze_address": lambda args: freeze_address(args[0], args[1], args[2]),
    "unfreeze_address": lambda args: unfreeze_address(args[0], args[1]),
    "recover_tokens": lambda args: recover_tokens(
        args[0], args[1], args[2], int(args[3]), args[4],
    ),
    "add_identity_claim": lambda args: add_identity_claim(
        args[0], args[1], args[2],
        args[3] if len(args) > 3 else "",
    ),
    "add_trusted_issuer": lambda args: add_trusted_issuer(
        args[0], args[1], args[2].split(","),
    ),
    # Identity (Extended)
    "import_identity": lambda args: import_identity(args[0], args[1]),
    "register_machine_identity": lambda args: register_machine_identity(
        args[0],
        args[1].split(",") if len(args) > 1 else None,
    ),
    "add_service": lambda args: add_service(args[0], args[1], args[2]),
    "add_credential": lambda args: add_credential(args[0], args[1], args[2]),
    "list_identities": lambda args: list_identities(args[0] if args else None),
    # Payments (Extended)
    "pay_mpp": lambda args: pay_mpp(args[0]),
    "pay_x402": lambda args: pay_x402(args[0]),
    "payment_gateway_info": lambda args: payment_gateway_info(),
    "list_x402_schemes": lambda args: list_x402_schemes(),
    "list_payment_sessions": lambda args: list_payment_sessions(
        "--all" in args,
    ),
    "get_payment_receipt": lambda args: get_payment_receipt(args[0]),
    # Network & Node (Extended)
    "peer_count": lambda args: peer_count(),
    "syncing": lambda args: syncing(),
    "hardware_profile": lambda args: get_hardware_profile(),
    "list_accounts": lambda args: list_accounts(),
    "get_finalized_block": lambda args: get_finalized_block(),
    "export_config": lambda args: export_config(),
    # Transaction (Extended)
    "get_transaction": lambda args: get_transaction(args[0]),
    "get_nonce": lambda args: get_nonce(args[0]),
    "get_transaction_history": lambda args: get_transaction_history(
        args[0], int(args[1]) if len(args) > 1 else 50,
    ),
    # Settlement (Extended)
    "settle": lambda args: settle(json.loads(args[0]) if args else {}),
    "get_settlement": lambda args: get_settlement(args[0]),
    # create_escrow: payer payee amount_wei [asset] [expires_at_ms] [release]
    # (uses ambient OAuth/DPoP — set TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF)
    "create_escrow": lambda args: create_escrow(
        args[0], args[1], int(args[2]),
        args[3] if len(args) > 3 else "TNZO",
        int(args[4]) if len(args) > 4 else 0,
        args[5] if len(args) > 5 else "timeout",
    ),
    # release_escrow: payer escrow_id_hex [proof_data_hex]
    "release_escrow": lambda args: release_escrow(
        args[0], args[1], args[2] if len(args) > 2 else "",
    ),
    # refund_escrow: payer escrow_id_hex
    "refund_escrow": lambda args: refund_escrow(args[0], args[1]),
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
    "download_model": lambda args: download_model(args[0]),
    "get_download_progress": lambda args: get_download_progress(args[0]),
    "serve_model": lambda args: serve_model(args[0]),
    "stop_model": lambda args: stop_model(args[0]),
    "delete_model": lambda args: delete_model(args[0]),
    # Token (Extended)
    "swap_token": lambda args: swap_token(args[0], args[1], int(args[2]), args[3]),
    "agent_pay_for_inference": lambda args: agent_pay_for_inference(
        args[0], args[1], int(args[2]),
    ),
    "wrap_tnzo": lambda args: wrap_tnzo(args[0], int(args[1]),
        args[2] if len(args) > 2 else "evm",
    ),
    # Governance
    "list_proposals": lambda args: list_proposals(),
    "create_proposal": lambda args: create_proposal(args[0], args[1]),
    "vote": lambda args: vote(args[0], args[1]),
    "get_voting_power": lambda args: get_voting_power(args[0]),
    "delegate_voting_power": lambda args: delegate_voting_power(args[0], args[1]),
    # Canton / DAML
    "list_canton_domains": lambda args: list_canton_domains(),
    "list_daml_contracts": lambda args: list_daml_contracts(
        args[0] if args else None,
    ),
    "submit_daml_command": lambda args: submit_daml_command(
        args[0], args[1], args[2],
        json.loads(args[3]) if len(args) > 3 else None,
    ),
    # Provider Management (Extended)
    "set_role": lambda args: set_role(args[0]),
    "set_provider_schedule": lambda args: set_provider_schedule(
        json.loads(args[0]) if args else {},
    ),
    "get_provider_schedule": lambda args: get_provider_schedule(),
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
    "register_webhook": lambda args: register_webhook(
        args[0],
        None,
        args[1] if len(args) > 1 else "",
    ),
    "list_webhooks": lambda args: list_webhooks(),
    "delete_webhook": lambda args: delete_webhook(args[0]),
    # ── Ecosystem: Solana ──
    "solana_swap": lambda args: solana_swap(
        args[0], args[1], int(args[2]),
        int(args[3]) if len(args) > 3 else 100,
    ),
    "solana_get_price": lambda args: solana_get_price(args[0]),
    "solana_stake": lambda args: solana_stake(float(args[0]), args[1]),
    "solana_get_yield": lambda args: solana_get_yield(
        args[0] if args else None,
    ),
    "solana_get_balance": lambda args: solana_get_balance(args[0]),
    "solana_get_token_accounts": lambda args: solana_get_token_accounts(
        args[0],
    ),
    "solana_transfer": lambda args: solana_transfer(
        args[0], args[1], int(args[2]),
    ),
    "solana_get_token_info": lambda args: solana_get_token_info(args[0]),
    "solana_get_nft": lambda args: solana_get_nft(args[0]),
    "solana_get_nfts_by_owner": lambda args: solana_get_nfts_by_owner(
        args[0],
    ),
    "solana_get_slot": lambda args: solana_get_slot(),
    "solana_get_tps": lambda args: solana_get_tps(),
    "solana_get_transaction": lambda args: solana_get_transaction(args[0]),
    "solana_resolve_domain": lambda args: solana_resolve_domain(args[0]),
    # ── Ecosystem: Ethereum ──
    "eth_get_price_chainlink": lambda args: eth_get_price_chainlink(
        args[0] if args else None,
    ),
    "eth_get_gas_price_ext": lambda args: eth_get_gas_price_ext(),
    "eth_estimate_gas_ext": lambda args: eth_estimate_gas_ext(
        args[0],
        args[1] if len(args) > 1 else None,
        args[2] if len(args) > 2 else None,
    ),
    "eth_get_fee_history": lambda args: eth_get_fee_history(
        int(args[0]) if args else 10,
    ),
    "eth_get_erc20_balance": lambda args: eth_get_erc20_balance(
        args[0], args[1],
    ),
    "eth_get_tx": lambda args: eth_get_tx(args[0]),
    "eth_get_block_info": lambda args: eth_get_block_info(
        args[0] if args else None,
    ),
    "eth_get_receipt": lambda args: eth_get_receipt(args[0]),
    "eth_resolve_ens": lambda args: eth_resolve_ens(args[0]),
    "eth_lookup_ens": lambda args: eth_lookup_ens(args[0]),
    "eth_call_contract": lambda args: eth_call_contract(args[0], args[1]),
    "eth_encode_function": lambda args: eth_encode_function(
        args[0], json.loads(args[1]) if len(args) > 1 else [],
    ),
    "eth_register_agent_8004": lambda args: eth_register_agent_8004(
        args[0],
        args[1].split(",") if len(args) > 1 else [],
        args[2] if len(args) > 2 else "",
    ),
    "eth_lookup_agent_8004": lambda args: eth_lookup_agent_8004(args[0]),
    "eth_get_attestation": lambda args: eth_get_attestation(
        args[0], args[1] if len(args) > 1 else None,
    ),
    # ── Ecosystem: LayerZero ──
    "lz_quote_fee": lambda args: lz_quote_fee(
        int(args[0]), int(args[1]), args[2],
        args[3] if len(args) > 3 else None,
    ),
    "lz_send_message": lambda args: lz_send_message(
        int(args[0]), int(args[1]), args[2], args[3],
        args[4] if len(args) > 4 else None,
    ),
    "lz_track_message": lambda args: lz_track_message(args[0]),
    "lz_oft_quote": lambda args: lz_oft_quote(
        int(args[0]), int(args[1]), int(args[2]),
        args[3] if len(args) > 3 else None,
    ),
    "lz_oft_send": lambda args: lz_oft_send(
        int(args[0]), int(args[1]), int(args[2]), args[3],
        args[4] if len(args) > 4 else None,
    ),
    "lz_list_chains": lambda args: lz_list_chains(),
    "lz_get_chain_rpc": lambda args: lz_get_chain_rpc(args[0]),
    "lz_list_dvns": lambda args: lz_list_dvns(
        args[0] if args else None,
    ),
    "lz_get_deployments": lambda args: lz_get_deployments(
        args[0] if args else None,
    ),
    "lz_transfer_quote": lambda args: lz_transfer_quote(
        args[0], args[1], args[2], int(args[3]),
    ),
    "lz_transfer_build": lambda args: lz_transfer_build(args[0]),
    "lz_stargate_quote": lambda args: lz_stargate_quote(
        args[0], args[1], args[2], int(args[3]),
    ),
    "lz_stargate_send": lambda args: lz_stargate_send(
        args[0], args[1], args[2], int(args[3]), args[4],
    ),
    # ── Ecosystem: Chainlink ──
    "chainlink_get_price": lambda args: chainlink_get_price(
        args[0] if args else "ETH/USD",
    ),
    "chainlink_list_feeds": lambda args: chainlink_list_feeds(
        args[0] if args else "ethereum",
    ),
    "ccip_get_fee": lambda args: ccip_get_fee(
        args[0], args[1],
        int(args[2]) if len(args) > 2 else 0,
    ),
    "ccip_send_message": lambda args: ccip_send_message(
        args[0], args[1], args[2], args[3],
    ),
    "ccip_track_message": lambda args: ccip_track_message(args[0]),
    "ccip_get_supported_chains": lambda args: ccip_get_supported_chains(),
    "vrf_request_random": lambda args: vrf_request_random(
        int(args[0]) if args else 1,
    ),
    "vrf_get_subscription": lambda args: vrf_get_subscription(args[0]),
    "ds_get_report": lambda args: ds_get_report(args[0]),
    "ds_list_feeds": lambda args: ds_list_feeds(),
    "por_get_reserve": lambda args: por_get_reserve(args[0]),
    "por_list_feeds": lambda args: por_list_feeds(),
    # ── Ecosystem: Canton ──
    "canton_submit_command": lambda args: canton_submit_command(
        args[0], args[1], args[2],
        json.loads(args[3]) if len(args) > 3 else None,
    ),
    "canton_list_contracts_ext": lambda args: canton_list_contracts(
        args[0] if args else None,
        args[1] if len(args) > 1 else None,
    ),
    "canton_get_events": lambda args: canton_get_events(args[0]),
    "canton_get_transaction": lambda args: canton_get_transaction(args[0]),
    "canton_allocate_party": lambda args: canton_allocate_party(args[0]),
    "canton_list_parties": lambda args: canton_list_parties(),
    "canton_list_domains_ext": lambda args: canton_list_domains_ext(),
    "canton_get_health": lambda args: canton_get_health(),
    "canton_get_balance_ext": lambda args: canton_get_balance_ext(
        args[0], args[1] if len(args) > 1 else None,
    ),
    "canton_transfer": lambda args: canton_transfer(
        args[0], args[1], args[2],
        args[3] if len(args) > 3 else "TNZO",
    ),
    "canton_create_asset": lambda args: canton_create_asset(
        args[0], args[1], args[2],
    ),
    "canton_dvp_settle": lambda args: canton_dvp_settle(
        args[0], args[1], args[2], args[3],
    ),
    "canton_upload_dar": lambda args: canton_upload_dar(args[0]),
    "canton_get_fee_schedule": lambda args: canton_get_fee_schedule(
        args[0] if args else None,
    ),
    # ── Ecosystem: deBridge ──
    "debridge_search_tokens": lambda args: debridge_search_tokens(args[0], args[1] if len(args) > 1 else None),
    "debridge_get_chains": lambda args: debridge_get_chains(),
    "debridge_get_instructions": lambda args: debridge_get_instructions(),
    "debridge_create_tx": lambda args: debridge_create_tx(args[0], args[1], args[2], args[3], args[4], args[5]),
    "debridge_same_chain_swap": lambda args: debridge_same_chain_swap(args[0], args[1], args[2], args[3]),
    # ── Crypto ──
    "sign_message": lambda args: sign_message(
        args[0], args[1], args[2] if len(args) > 2 else "ed25519",
    ),
    "verify_signature": lambda args: verify_signature(args[0], args[1], args[2]),
    "encrypt_data": lambda args: encrypt_data(args[0], args[1]),
    "decrypt_data": lambda args: decrypt_data(args[0], args[1], args[2]),
    "derive_key": lambda args: derive_key(args[0]),
    "generate_keypair": lambda args: generate_keypair(
        args[0] if args else "ed25519",
    ),
    "hash_sha256": lambda args: hash_sha256(args[0]),
    "hash_keccak256": lambda args: hash_keccak256(args[0]),
    "x25519_key_exchange": lambda args: x25519_key_exchange(args[0], args[1]),
    # ── TEE ──
    "detect_tee": lambda args: detect_tee(),
    "get_tee_attestation": lambda args: get_tee_attestation(
        args[0] if args else None,
    ),
    "verify_tee_attestation": lambda args: verify_tee_attestation(args[0], args[1]),
    "seal_data": lambda args: seal_data(args[0], args[1]),
    "unseal_data": lambda args: unseal_data(args[0], args[1]),
    "list_tee_providers": lambda args: list_tee_providers(),
    # ── ZK ──
    "create_zk_proof": lambda args: create_zk_proof(
        args[0],
        json.loads(args[1]) if len(args) > 1 else {},
    ),
    "list_zk_circuits": lambda args: list_zk_circuits(),
    # ── Custody ──
    "create_mpc_wallet_advanced": lambda args: create_mpc_wallet_advanced(
        int(args[0]) if args else 2,
        int(args[1]) if len(args) > 1 else 3,
        args[2] if len(args) > 2 else "ed25519",
    ),
    "export_keystore": lambda args: export_keystore(args[0], args[1]),
    "import_keystore": lambda args: import_keystore(args[0], args[1]),
    "get_key_shares": lambda args: get_key_shares(args[0]),
    "rotate_keys": lambda args: rotate_keys(args[0]),
    "set_spending_limits": lambda args: set_spending_limits(
        args[0], float(args[1]), float(args[2]),
    ),
    "get_spending_limits": lambda args: get_spending_limits(args[0]),
    "authorize_session": lambda args: authorize_session(
        args[0], int(args[1]),
        args[2].split(",") if len(args) > 2 else [],
    ),
    "revoke_session": lambda args: revoke_session(args[0]),
    # ── App / Paymaster ──
    "register_app": lambda args: register_app(args[0], args[1]),
    "create_user_wallet": lambda args: create_user_wallet(
        args[0], args[1],
        float(args[2]) if len(args) > 2 else None,
    ),
    "fund_user_wallet": lambda args: fund_user_wallet(
        args[0], args[1], float(args[2]),
    ),
    "list_user_wallets": lambda args: list_user_wallets(args[0]),
    "sponsor_transaction": lambda args: sponsor_transaction(
        args[0], args[1], float(args[2]),
    ),
    "get_usage_stats": lambda args: get_usage_stats(args[0]),
    # ── Contract ABI ──
    "encode_function": lambda args: encode_function(
        args[0],
        json.loads(args[1]) if len(args) > 1 else [],
    ),
    "decode_result": lambda args: decode_result(
        args[0],
        json.loads(args[1]) if len(args) > 1 else [],
    ),
    # ── OAuth 2.1 + DPoP Onboarding ──
    "onboard_human": lambda args: onboard_human(args[0], args[1] if len(args) > 1 else None),
    "onboard_delegated_agent": lambda args: onboard_delegated_agent(args[0], args[1], args[2], args[3] if len(args) > 3 else None),
    "onboard_autonomous_agent": lambda args: onboard_autonomous_agent(args[0], args[1] if len(args) > 1 else None),
    "refresh_token": lambda args: refresh_token(args[0], args[1] if len(args) > 1 else None),
    "link_wallet_for_auth": lambda args: link_wallet_for_auth(
        args[0],
        args[1] if len(args) > 1 else None,
        args[2] if len(args) > 2 else None,
        int(args[3]) if len(args) > 3 else None,
    ),
    "revoke_jwt": lambda args: revoke_jwt(args[0], args[1] if len(args) > 1 else "revoked"),
    "revoke_did": lambda args: revoke_did(args[0], args[1] if len(args) > 1 else "revoked"),
    "list_pending_approvals": lambda args: list_pending_approvals(args[0]),
    "decide_approval": lambda args: decide_approval(args[0], args[1], args[2]),
    # ── AP2 (Agent Payments Protocol) ──
    "ap2_protocol_info": lambda args: ap2_protocol_info(),
    "ap2_sign_mandate": lambda args: ap2_sign_mandate(
        args[0], json.loads(args[1]), args[2]
    ),
    "ap2_verify_mandate": lambda args: ap2_verify_mandate(json.loads(args[0])),
    "ap2_validate_mandate_pair": lambda args: ap2_validate_mandate_pair(
        json.loads(args[0]),
        json.loads(args[1]),
        bool(json.loads(args[2])) if len(args) > 2 else False,
    ),
    "ap2_create_session": lambda args: ap2_create_session(
        args[0], args[1], args[2], int(args[3]),
        args[4] if len(args) > 4 else "TNZO",
    ),
    "ap2_authorize_payment": lambda args: ap2_authorize_payment(
        args[0], int(args[1]),
    ),
    "ap2_execute_payment": lambda args: ap2_execute_payment(args[0], args[1]),
    "ap2_cancel_session": lambda args: ap2_cancel_session(args[0]),
    "ap2_get_session": lambda args: ap2_get_session(args[0]),
    "ap2_list_agent_sessions": lambda args: ap2_list_agent_sessions(args[0]),
    # ── ERC-8004 (Trustless Agents Registry — full v0.6+ surface) ──
    "erc8004_derive_agent_id": lambda args: erc8004_derive_agent_id(args[0]),
    "erc8004_encode_register": lambda args: erc8004_encode_register(
        args[0], args[1], args[2],
    ),
    "erc8004_encode_get_agent": lambda args: erc8004_encode_get_agent(args[0]),
    "erc8004_decode_get_agent": lambda args: erc8004_decode_get_agent(args[0]),
    "erc8004_encode_set_agent_uri": lambda args: erc8004_encode_set_agent_uri(
        args[0], args[1],
    ),
    "erc8004_encode_set_agent_wallet": lambda args: erc8004_encode_set_agent_wallet(
        args[0], args[1], int(args[2]), args[3],
    ),
    "erc8004_encode_set_metadata": lambda args: erc8004_encode_set_metadata(
        args[0], args[1], args[2],
    ),
    "erc8004_encode_get_metadata": lambda args: erc8004_encode_get_metadata(
        args[0], args[1],
    ),
    "erc8004_decode_get_metadata": lambda args: erc8004_decode_get_metadata(args[0]),
    "erc8004_encode_get_agent_uri": lambda args: erc8004_encode_get_agent_uri(args[0]),
    "erc8004_encode_get_agent_wallet": lambda args: erc8004_encode_get_agent_wallet(args[0]),
    "erc8004_encode_feedback": lambda args: erc8004_encode_feedback(
        args[0], int(args[1]), args[2],
    ),
    "erc8004_encode_get_feedback": lambda args: erc8004_encode_get_feedback(
        args[0], int(args[1]),
    ),
    "erc8004_encode_get_feedback_count": lambda args: erc8004_encode_get_feedback_count(args[0]),
    "erc8004_encode_revoke_feedback": lambda args: erc8004_encode_revoke_feedback(
        args[0], args[1],
    ),
    "erc8004_encode_append_response": lambda args: erc8004_encode_append_response(
        args[0], args[1], args[2],
    ),
    "erc8004_encode_is_feedback_revoked": lambda args: erc8004_encode_is_feedback_revoked(
        args[0], args[1],
    ),
    "erc8004_encode_get_feedback_responses": lambda args: erc8004_encode_get_feedback_responses(
        args[0], args[1],
    ),
    "erc8004_encode_validation_request": lambda args: erc8004_encode_validation_request(
        args[0], args[1], args[2], args[3],
    ),
    "erc8004_encode_validation_response": lambda args: erc8004_encode_validation_response(
        args[0], int(args[1]), args[2], args[3],
        args[4] if len(args) > 4 else "",
    ),
    "erc8004_encode_get_validation": lambda args: erc8004_encode_get_validation(args[0]),
    # ── Wormhole ──
    "wormhole_chain_id": lambda args: wormhole_chain_id(args[0]),
    "wormhole_parse_vaa_id": lambda args: wormhole_parse_vaa_id(args[0]),
    "wormhole_bridge": lambda args: wormhole_bridge(
        args[0], args[1], args[2], int(args[3]), args[4], args[5],
    ),
    # ── CCT (Chainlink Cross-Chain Token) ──
    "cct_list_pools": lambda args: cct_list_pools(),
    "cct_get_pool": lambda args: cct_get_pool(args[0]),
    # ── Multi-modal: forecast / vision / text-embed / segment / detect / transcribe / video ──
    "list_forecast_catalog": lambda args: list_forecast_catalog(),
    "list_forecast_models": lambda args: list_forecast_models(),
    "forecast": lambda args: forecast(
        args[0],
        json.loads(args[1]),
        int(args[2]),
        json.loads(args[3]) if len(args) > 3 else None,
    ),
    "list_vision_catalog": lambda args: list_vision_catalog(),
    "list_vision_models": lambda args: list_vision_models(),
    "vision_embed": lambda args: vision_embed(
        args[0], args[1],
        args[2].lower() != "false" if len(args) > 2 else True,
    ),
    "vision_similarity": lambda args: vision_similarity(args[0], args[1], args[2]),
    "list_text_embedding_catalog": lambda args: list_text_embedding_catalog(),
    "list_text_embedding_models": lambda args: list_text_embedding_models(),
    "text_embed": lambda args: text_embed(
        args[0],
        json.loads(args[1]),
        int(args[2]) if len(args) > 2 else None,
    ),
    "list_segmentation_catalog": lambda args: list_segmentation_catalog(),
    "list_segmentation_models": lambda args: list_segmentation_models(),
    "segment": lambda args: segment(args[0], args[1], json.loads(args[2])),
    "list_detection_catalog": lambda args: list_detection_catalog(),
    "list_detection_models": lambda args: list_detection_models(),
    "detect": lambda args: detect(
        args[0], args[1],
        float(args[2]) if len(args) > 2 else 0.5,
    ),
    "list_audio_catalog": lambda args: list_audio_catalog(),
    "list_audio_models": lambda args: list_audio_models(),
    "transcribe": lambda args: transcribe(
        args[0], args[1],
        args[2] if len(args) > 2 else None,
        args[3].lower() == "true" if len(args) > 3 else False,
    ),
    "list_video_catalog": lambda args: list_video_catalog(),
    "list_video_models": lambda args: list_video_models(),
    "video_embed": lambda args: video_embed(
        args[0], args[1],
        int(args[2]) if len(args) > 2 else 30,
    ),
    # ── AgentBond (Spec 9) ──
    "get_agent_bond": lambda args: get_agent_bond(args[0]),
    "list_agent_bonds_by_controller": lambda args: list_agent_bonds_by_controller(args[0]),
    "post_agent_bond": lambda args: post_agent_bond(
        args[0], args[1], args[2], int(args[3]),
    ),
    "increase_agent_bond": lambda args: increase_agent_bond(
        args[0], args[1], int(args[2]),
    ),
    "withdraw_agent_bond": lambda args: withdraw_agent_bond(args[0], args[1]),
    # ── Insurance (Spec 9) ──
    "file_insurance_claim": lambda args: file_insurance_claim(
        args[0], args[1], args[2], int(args[3]), int(args[4]),
        json.loads(args[5]) if len(args) > 5 else None,
        args[6] if len(args) > 6 else None,
    ),
    "list_insurance_claims": lambda args: list_insurance_claims(),
    "get_insurance_claim": lambda args: get_insurance_claim(args[0]),
    "get_insurance_pool_balance": lambda args: get_insurance_pool_balance(),
    # ── Adaptive Burn (Spec 8) ──
    "get_burn_rate_config": lambda args: get_burn_rate_config(),
    "get_supply_metrics": lambda args: get_supply_metrics(),
    "get_burn_rate_recommendation": lambda args: get_burn_rate_recommendation(),
    "list_adaptive_burn_proposals": lambda args: list_adaptive_burn_proposals(),
    # ── SeedAgent (Spec 10) ──
    "get_treasury_earmark": lambda args: get_treasury_earmark(
        args[0] if args else None,
    ),
    "get_seed_agent_charter": lambda args: get_seed_agent_charter(args[0]),
    "list_seed_agent_charters": lambda args: list_seed_agent_charters(),
    "list_seed_agents": lambda args: list_seed_agents(
        args[0] if args else None,
    ),
    "get_network_activity": lambda args: get_network_activity(
        args[0] if args else None,
        args[1].lower() == "true" if len(args) > 1 else False,
    ),
    # ── Escrow listing ──
    "list_escrows_by_payer": lambda args: list_escrows_by_payer(args[0]),
    "list_escrows_by_payee": lambda args: list_escrows_by_payee(args[0]),
    # ── Burn quota & mempool (Specs 3 + 6) ──
    "get_burn_quota": lambda args: get_burn_quota(),
    "get_mempool_stats": lambda args: get_mempool_stats(),
    "get_mempool_lane": lambda args: get_mempool_lane(args[0]),
    "get_account_contention": lambda args: get_account_contention(args[0]),
    # ── DA offload (Spec 7) ──
    "get_da_backends": lambda args: get_da_backends(),
    "verify_da_pointer": lambda args: verify_da_pointer(json.loads(args[0])),
    # ── Receipts & principal chain (Spec 5) ──
    "get_receipt_principal_chain": lambda args: get_receipt_principal_chain(args[0]),
    "list_receipts_by_actor": lambda args: list_receipts_by_actor(args[0]),
    "list_receipts_by_controller": lambda args: list_receipts_by_controller(args[0]),
    "summarize_controller": lambda args: summarize_controller(
        args[0],
        int(args[1]) if len(args) > 1 else None,
        int(args[2]) if len(args) > 2 else None,
    ),
    # ── Agent lifecycle & kill-switch ──
    "get_agent_lifecycle": lambda args: get_agent_lifecycle(args[0]),
    "list_kill_switch_by_agent": lambda args: list_kill_switch_by_agent(args[0]),
    "list_kill_switch_by_controller": lambda args: list_kill_switch_by_controller(args[0]),
    "get_kill_switch_receipt": lambda args: get_kill_switch_receipt(args[0]),
    # ── Inference usage & provider reputation ──
    "list_inference_usage": lambda args: list_inference_usage(
        args[0] if len(args) > 0 and args[0] else None,
        args[1] if len(args) > 1 and args[1] else None,
    ),
    "get_provider_reputation": lambda args: get_provider_reputation(args[0]),
    # ── Provenance & disputes ──
    "get_provenance": lambda args: get_provenance(args[0]),
    "get_dispute": lambda args: get_dispute(args[0]),
    "list_disputes_by_channel": lambda args: list_disputes_by_channel(args[0]),
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
