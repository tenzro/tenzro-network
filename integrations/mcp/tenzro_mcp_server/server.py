"""Tenzro Network MCP Server — 149 blockchain tools for AI agents.

Exposes the full Tenzro Network JSON-RPC interface as MCP tools,
enabling AI agents to interact with the Tenzro L1 settlement layer,
manage wallets, stake tokens, bridge cross-chain, run inference,
coordinate agent swarms, and more.
"""

from fastmcp import FastMCP
from .rpc_client import rpc_call, api_call
import json

mcp = FastMCP("Tenzro Network")


# ---------------------------------------------------------------------------
# Wallet & Balance (6 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_balance(address: str) -> str:
    """Get the TNZO token balance for a hex address. Returns the balance in wei."""
    result = await rpc_call("eth_getBalance", [address, "latest"])
    return json.dumps({"address": address, "balance": result})


@mcp.tool
async def create_wallet(key_type: str = "ed25519") -> str:
    """Provision a self-custody Tenzro 2-of-3 MPC wallet.

    Returns the canonical Tenzro wallet shape: ``wallet_id``, 32-byte hex
    ``address`` (the form used by ``eth_getBalance``, the faucet, and all
    transaction RPCs), base58 ``display_address``, ``public_key``,
    ``key_type`` (``ed25519`` or ``secp256k1``), ``threshold`` (2), and
    ``total_shares`` (3). No seed phrase or private key is ever returned —
    the keystore holds shares and the node never sees a full key.
    """
    result = await rpc_call("tenzro_createWallet", [key_type])
    return json.dumps(result)


@mcp.tool
async def send_transaction(
    from_addr: str,
    to_addr: str,
    amount: str,
    gas_limit: int = 21000,
    gas_price: int = 1_000_000_000,
) -> str:
    """Send a TNZO transfer transaction via ambient OAuth/DPoP auth.

    Uses tenzro_signAndSendTransaction which looks up the wallet bound
    to the bearer DID (forwarded by the Tenzro MCP middleware via
    Authorization: DPoP <jwt> + DPoP: <proof>) and signs the canonical
    Transaction::hash() preimage on its behalf, then submits atomically.
    The node synchronously verifies the Ed25519 signature before
    accepting the transaction. Private keys never travel over the wire.
    """
    nonce_hex = await rpc_call("eth_getTransactionCount", [from_addr, "latest"])
    chain_id_hex = await rpc_call("eth_chainId", [])
    nonce = int(nonce_hex, 16) if isinstance(nonce_hex, str) else 0
    chain_id = int(chain_id_hex, 16) if isinstance(chain_id_hex, str) else 1337
    if isinstance(amount, str) and amount.startswith("0x"):
        value_int = int(amount, 16)
    else:
        value_int = int(amount)
    result = await rpc_call(
        "tenzro_signAndSendTransaction",
        {
            "from": from_addr,
            "to": to_addr,
            "value": value_int,
            "gas_limit": gas_limit,
            "gas_price": gas_price,
            "nonce": nonce,
            "chain_id": chain_id,
        },
    )
    return json.dumps({"tx_hash": result} if isinstance(result, str) else result)


@mcp.tool
async def request_faucet(address: str) -> str:
    """Request 100 testnet TNZO tokens from the faucet (24h cooldown per address)."""
    result = await rpc_call("tenzro_faucet", {"address": address})
    return json.dumps(result)


@mcp.tool
async def token_balance(address: str) -> str:
    """Get the TNZO token balance for an address via the token subsystem."""
    result = await rpc_call("tenzro_tokenBalance", [address])
    return json.dumps({"address": address, "balance": result})


@mcp.tool
async def total_supply() -> str:
    """Get the total TNZO token supply."""
    result = await rpc_call("tenzro_totalSupply", [])
    return json.dumps({"total_supply": result})


# ---------------------------------------------------------------------------
# OAuth 2.1 + DPoP Onboarding & Delegation (8 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def onboard_human(display_name: str, dpop_jkt: str = "", ttl_secs: int = 0) -> str:
    """Provision a fresh human TDIP identity + MPC wallet and mint a
    self-custody OAuth 2.1 access JWT + opaque refresh token.

    Pass ``dpop_jkt`` (RFC 7638 thumbprint of a client-held P-256 / Ed25519
    public key) to mint a DPoP-bound token; omit it for the simpler bearer
    flow. ``ttl_secs`` is optional and clamped server-side.
    """
    params = {"display_name": display_name}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    if ttl_secs:
        params["ttl_secs"] = ttl_secs
    result = await rpc_call("tenzro_onboardHuman", [params])
    return json.dumps(result)


@mcp.tool
async def onboard_delegated_agent(
    controller_did: str,
    capabilities: list,
    delegation_scope: dict,
    dpop_jkt: str = "",
) -> str:
    """Onboard an agent that acts on behalf of ``controller_did``.

    The agent inherits the controller's act-chain — revoking the
    controller cascades. ``capabilities`` is a list of capability
    strings; ``delegation_scope`` is the spend/operation envelope.
    """
    params = {
        "controller_did": controller_did,
        "capabilities": capabilities,
        "delegation_scope": delegation_scope,
    }
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    result = await rpc_call("tenzro_onboardDelegatedAgent", [params])
    return json.dumps(result)


@mcp.tool
async def onboard_autonomous_agent(bond_funding_address: str, dpop_jkt: str = "") -> str:
    """Onboard a fully autonomous agent — requires a slashable TNZO bond
    posted at ``bond_funding_address``."""
    params = {"bond_funding_address": bond_funding_address}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    result = await rpc_call("tenzro_onboardAutonomousAgent", [params])
    return json.dumps(result)


@mcp.tool
async def refresh_token(refresh_token_value: str, dpop_jkt: str = "") -> str:
    """Exchange an opaque refresh token for a fresh access JWT.

    Mirrors OAuth 2.1 ``grant_type=refresh_token``. The same refresh
    token may be re-used until its absolute 30-day expiry (no rotation
    in V1). Pass ``dpop_jkt`` to upgrade an unbound session to
    DPoP-bound or to rotate the bound key.
    """
    params = {"refresh_token": refresh_token_value}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    result = await rpc_call("tenzro_refreshToken", [params])
    return json.dumps(result)


@mcp.tool
async def link_wallet_for_auth(
    wallet_id: str,
    dpop_jkt: str = "",
    display_name: str = "",
    ttl_secs: int = 0,
) -> str:
    """Bind an existing MPC wallet to a fresh self-custody TDIP identity
    and mint an access JWT.

    Bridges ``create_wallet`` (which returns only ``wallet_id`` +
    ``address``) to the auth-mediated signing path: callers who created
    a wallet first can later obtain an access token bound to that
    wallet by passing back ``wallet_id`` plus an optional DPoP key
    thumbprint. Returns the same envelope as ``onboard_human``.
    """
    params = {"wallet_id": wallet_id}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    if display_name:
        params["display_name"] = display_name
    if ttl_secs:
        params["ttl_secs"] = ttl_secs
    result = await rpc_call("tenzro_linkWalletForAuth", [params])
    return json.dumps(result)


@mcp.tool
async def exchange_token(
    subject_token: str,
    child_bearer_did: str,
    child_dpop_jkt: str,
    requested_rar: dict,
    requested_aap_capabilities: list,
    requested_ttl_secs: int = 0,
) -> str:
    """RFC 8693 OAuth 2.0 Token Exchange — mint a narrower child JWT.

    Exchanges ``subject_token`` (a parent JWT) for a child JWT bound to
    ``child_dpop_jkt`` (RFC 7638 thumbprint), with a strict subset of
    the parent's RAR grants and AAP capabilities. The child token's
    ``controller_did`` is set to the parent's ``sub``, extending the
    act-chain by one hop.

    Subset enforcement is performed by the AS — over-scoped requests
    are rejected with JSON-RPC error ``-32002``. Pass
    ``requested_ttl_secs=0`` to use the engine default (clamped to
    parent's remaining lifetime).
    """
    params = {
        "subject_token": subject_token,
        "child_bearer_did": child_bearer_did,
        "child_dpop_jkt": child_dpop_jkt,
        "requested_rar": requested_rar,
        "requested_aap_capabilities": requested_aap_capabilities,
    }
    if requested_ttl_secs:
        params["requested_ttl_secs"] = requested_ttl_secs
    result = await rpc_call("tenzro_exchangeToken", [params])
    return json.dumps(result)


@mcp.tool
async def introspect_token(token: str) -> str:
    """RFC 7662 OAuth 2.0 Token Introspection.

    Ask the AS whether ``token`` is currently active and, if so,
    return its full claim set (RAR ``authorization_details``, AAP
    ``aap_*`` claims, ``cnf``, ``controller_did``, etc.). Per
    RFC 7662 §2.2 a failed validation returns ``{"active": false}``
    with no other fields — the AS does not leak why the token is
    inactive.
    """
    result = await rpc_call("tenzro_introspectToken", [{"token": token}])
    return json.dumps(result)


@mcp.tool
async def oauth_discovery() -> str:
    """RFC 8414 / RFC 9728 OAuth Authorization Server / Protected
    Resource Metadata.

    Returns the same metadata document published at
    ``GET /.well-known/openid-configuration``, augmented with AAP
    extensions: ``authorization_details_types_supported`` (8 RAR
    types), ``aap_claims_supported`` (7 AAP claims), and
    ``dpop_signing_alg_values_supported`` (``["EdDSA"]``).
    """
    result = await rpc_call("tenzro_oauthDiscovery", [])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Node & Blocks (3 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_node_status() -> str:
    """Get the current node status including block height, peer count, uptime, and role."""
    result = await rpc_call("tenzro_nodeInfo", [])
    return json.dumps(result)


@mcp.tool
async def get_block(height: int) -> str:
    """Get a block by height with its transactions and metadata."""
    result = await rpc_call("eth_getBlockByNumber", [hex(height), False])
    return json.dumps(result)


@mcp.tool
async def get_block_range(
    start_height: int, end_height: int, max_results: int = 64
) -> str:
    """Fetch a contiguous range of blocks by height (default 64, max 256).

    Returns block summaries plus `nextHeight` and `moreAvailable` so a lagging
    client can paginate forward until caught up. `moreAvailable` reflects
    whether the chain has further blocks beyond `nextHeight`, independent of
    the requested `endHeight`, so a sync loop can step over pruning gaps.
    """
    result = await rpc_call(
        "tenzro_getBlockRange",
        {
            "startHeight": start_height,
            "endHeight": end_height,
            "maxResults": max_results,
        },
    )
    return json.dumps(result)


@mcp.tool
async def get_gas_price() -> str:
    """Returns the current effective gas price in wei (base fee + suggested tip).

    Tracks the EIP-1559 fee market — value adjusts ±12.5% per block based on
    parent gas usage vs. the 15M target.
    """
    result = await rpc_call("eth_gasPrice", [])
    return json.dumps({"gas_price_wei_hex": result})


@mcp.tool
async def get_max_priority_fee_per_gas() -> str:
    """Returns a suggested EIP-1559 priority fee (tip) in wei.

    Use this to fill `maxPriorityFeePerGas` on a Type-2 transaction. Derive
    the base-fee portion from `get_fee_history` or the parent block's
    `baseFeePerGas`.
    """
    result = await rpc_call("eth_maxPriorityFeePerGas", [])
    return json.dumps({"max_priority_fee_per_gas_wei_hex": result})


@mcp.tool
async def get_fee_history(
    block_count: int = 10,
    newest_block: str = "latest",
    reward_percentiles: list[float] | None = None,
) -> str:
    """Returns base-fee history and gas-usage ratios over the last N blocks.

    `baseFeePerGas` has length `block_count + 1` — the last entry is the
    predicted base fee for the next block, suitable as the floor of a Type-2
    transaction's `maxFeePerGas`. `reward[i][j]` is the j-th requested
    percentile of priority tips paid in block `oldestBlock + i` (omitted when
    `reward_percentiles` is None or empty).
    """
    percentiles = reward_percentiles if reward_percentiles is not None else []
    result = await rpc_call(
        "eth_feeHistory",
        [hex(block_count), newest_block, percentiles],
    )
    return json.dumps(result)


@mcp.tool
async def get_svm_cross_vm_program_info() -> str:
    """Return the canonical Tenzro Cross-VM SVM-native program ID and instruction
    discriminators. The program ID is deterministically derived as
    `SHA-256("tenzro/svm/program/cross_vm")`. Discriminators are
    Anchor-style 8-byte `SHA-256("global:<snake_case_name>")[..8]`.

    Use this to construct SVM Instructions targeting the Tenzro Cross-VM
    native program from any SVM client (e.g. @solana/web3.js).
    """
    return json.dumps({
        "program_id": {
            "hex": "5c03dd6cf580ecafb5ca11a9e1d6448176bb1dfa9d4886c65d9024df77542695",
            "base58": "7CBvjJtsMxYFsxYkpcXYoTDZpC8PhMVy1DVVQBopvWCC",
            "derivation_domain": "tenzro/svm/program/cross_vm",
        },
        "instructions": {
            "bridge_to_evm": {
                "discriminator_hex": "92a8a45c33225f25",
                "payload_size": 68,
                "payload_layout": "mint(32) || evm_dest(20) || amount(u64 LE) || nonce(u64 LE)",
            },
            "bridge_from_evm": {
                "discriminator_hex": "3038733289f4cd75",
                "payload_size": 80,
                "payload_layout": "mint(32) || svm_dest(32) || amount(u64 LE) || nonce(u64 LE)",
            },
            "register_token_pointer": {
                "discriminator_hex": "9a8e01390f994522",
                "payload_size": 84,
                "payload_layout": "mint(32) || evm_token_address(20) || token_id(32)",
            },
            "transfer_cross_vm": {
                "discriminator_hex": "bc684168aba7abb9",
                "payload_size": 81,
                "payload_layout": (
                    "mint(32) || dest_vm(u8) || dest_address(32) || "
                    "amount(u64 LE) || nonce(u64 LE)"
                ),
                "dest_vm_values": {"NATIVE": 0, "EVM": 1, "SVM": 2, "DAML": 3},
            },
        },
    })


@mcp.tool
async def get_transaction(tx_hash: str) -> str:
    """Look up a transaction by its hash. Returns type, sender, recipient, amount, and status."""
    result = await rpc_call("eth_getTransactionByHash", [tx_hash])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Identity (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def register_identity(identity_type: str, display_name: str) -> str:
    """Register a new TDIP identity. identity_type is 'human' or 'machine'."""
    result = await rpc_call(
        "tenzro_registerIdentity", [identity_type, display_name]
    )
    return json.dumps(result)


@mcp.tool
async def resolve_did(did: str) -> str:
    """Resolve a DID to its identity info and delegation scope."""
    result = await rpc_call("tenzro_resolveIdentity", [did])
    return json.dumps(result)


@mcp.tool
async def revoke_did(did: str, reason: str = "revoked via MCP") -> str:
    """Revoke an identity by DID. Cascades JWT invalidation through the
    entire act-chain. Logical delete — record stays in CF_IDENTITIES with
    `Revoked` status. To hard-delete, follow up with `forget_identity`."""
    result = await rpc_call("tenzro_revokeDid", {"did": did, "reason": reason})
    return json.dumps(result)


@mcp.tool
async def forget_identity(did: str) -> str:
    """TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously
    revoked identity from the registry and persistent storage. The DID
    must already be in `Revoked` status — call `revoke_did` first, allow
    cascading revocation to propagate, then call this."""
    result = await rpc_call("tenzro_forgetIdentity", {"did": did})
    return json.dumps(result)


@mcp.tool
async def set_delegation_scope(
    machine_did: str,
    max_transaction_value: int = None,
    allowed_operations: list = None,
) -> str:
    """Set spending limits and allowed operations for a machine DID."""
    params = {"machine_did": machine_did}
    if max_transaction_value is not None:
        params["max_transaction_value"] = max_transaction_value
    if allowed_operations is not None:
        params["allowed_operations"] = allowed_operations
    result = await rpc_call("tenzro_setDelegationScope", params)
    return json.dumps(result)


@mcp.tool
async def set_username(did: str, username: str) -> str:
    """Set a human-readable username for a DID."""
    result = await rpc_call("tenzro_setUsername", [did, username])
    return json.dumps(result)


@mcp.tool
async def resolve_username(username: str) -> str:
    """Resolve a username to its associated DID and identity info."""
    result = await rpc_call("tenzro_resolveUsername", [username])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Payments (8 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_payment_challenge(
    protocol: str, resource: str, amount: str
) -> str:
    """Create a payment challenge. protocol is 'mpp', 'x402', or 'native'."""
    result = await rpc_call(
        "tenzro_createPaymentChallenge",
        {"protocol": protocol, "resource": resource, "amount": amount},
    )
    return json.dumps(result)


@mcp.tool
async def verify_payment(
    challenge_id: str, protocol: str, payer_did: str, amount: str
) -> str:
    """Verify a payment credential against a challenge and settle on-chain."""
    result = await rpc_call(
        "tenzro_verifyPayment",
        {
            "challenge_id": challenge_id,
            "protocol": protocol,
            "payer_did": payer_did,
            "amount": amount,
        },
    )
    return json.dumps(result)


@mcp.tool
async def list_payment_protocols() -> str:
    """List supported payment protocols (MPP, x402, native) and their capabilities."""
    result = await rpc_call("tenzro_paymentGatewayInfo", [])
    return json.dumps(result)


@mcp.tool
async def list_x402_schemes() -> str:
    """List the x402 scheme backends registered on this node.

    Each scheme corresponds to a verification path under the x402 protocol:
    'tenzro-hybrid' (Ed25519 hybrid sig over canonical preimage),
    'exact-eip3009' (USDC EIP-3009 meta-tx via CDP facilitator),
    'permit2' (Uniswap Permit2 via CDP facilitator),
    'erc7710' (delegation redemption).

    Use the returned ids in the 'extra.scheme' field of an x402 PaymentRequirement.
    """
    result = await rpc_call("tenzro_listX402Schemes", [])
    return json.dumps(result)


@mcp.tool
async def settle_payment(
    from_addr: str, to_addr: str, amount: str, service_type: str
) -> str:
    """Settle a payment between two addresses for a given service type."""
    result = await rpc_call(
        "tenzro_settle",
        {
            "from": from_addr,
            "to": to_addr,
            "amount": amount,
            "service_type": service_type,
        },
    )
    return json.dumps(result)


def _release_conditions_payload(release_conditions: str) -> dict:
    """Map a release-condition keyword to the typed payload expected by the VM."""
    key = release_conditions.lower()
    if key in ("timeout",):
        return {"type": "Timeout"}
    if key in ("provider", "provider_signature"):
        return {"type": "ProviderSignature"}
    if key in ("consumer", "consumer_signature"):
        return {"type": "ConsumerSignature"}
    if key in ("both", "both_signatures"):
        return {"type": "BothSignatures"}
    if key in ("verifier", "verifier_signature"):
        return {"type": "VerifierSignature"}
    if key == "custom":
        return {"type": "Custom", "data": ""}
    raise ValueError(
        f"unsupported release condition '{release_conditions}': use "
        "timeout|provider|consumer|both|verifier|custom"
    )


def _parse_escrow_id(escrow_id_hex: str) -> list:
    """Parse a 32-byte hex escrow id into a list of byte ints."""
    clean = escrow_id_hex[2:] if escrow_id_hex.startswith("0x") else escrow_id_hex
    if len(clean) != 64:
        raise ValueError(f"escrow_id must be 32 bytes (64 hex chars), got {len(clean)}")
    return list(bytes.fromhex(clean))


async def _fetch_nonce_and_chain_id(address: str) -> tuple:
    nonce_hex = await rpc_call("eth_getTransactionCount", [address, "latest"])
    chain_id_hex = await rpc_call("eth_chainId", [])
    nonce = int(nonce_hex, 16) if isinstance(nonce_hex, str) else 0
    chain_id = int(chain_id_hex, 16) if isinstance(chain_id_hex, str) else 1337
    return nonce, chain_id


@mcp.tool
async def create_escrow(
    payer: str,
    payee: str,
    amount: str,
    asset: str = "TNZO",
    expires_at: int = 0,
    release_conditions: str = "timeout",
) -> str:
    """Create an on-chain escrow via a signed CreateEscrow transaction.

    Uses ambient OAuth/DPoP auth — the bearer JWT must belong to `payer`;
    the server signs on behalf of the bound wallet. Private keys never
    travel over the wire.

    The escrow_id is derived deterministically by the VM as
    SHA-256("tenzro/escrow/id" || payer || nonce_le) and funds are locked
    at a vault address derived from that id. Only the original payer can
    later release or refund.

    `release_conditions` is one of:
    timeout | provider | consumer | both | verifier | custom
    """
    conditions = _release_conditions_payload(release_conditions)
    nonce, chain_id = await _fetch_nonce_and_chain_id(payer)
    tx_type = {
        "type": "CreateEscrow",
        "data": {
            "payee": payee,
            "amount": str(amount),
            "asset_id": asset,
            "expires_at": int(expires_at),
            "release_conditions": conditions,
        },
    }
    result = await rpc_call(
        "tenzro_signAndSendTransaction",
        {
            "from": payer,
            "to": payee,
            "value": 0,
            "gas_limit": 75_000,
            "gas_price": 1_000_000_000,
            "nonce": nonce,
            "chain_id": chain_id,
            "tx_type": tx_type,
        },
    )
    return json.dumps({"tx_hash": result} if isinstance(result, str) else result)


@mcp.tool
async def release_escrow(
    payer: str,
    escrow_id: str,
    proof_data_hex: str = "",
) -> str:
    """Release escrowed funds to the payee via a signed ReleaseEscrow transaction.

    Uses ambient OAuth/DPoP auth — the bearer JWT must belong to the
    original payer. The VM rejects releases from any other address.
    """
    escrow_id_bytes = _parse_escrow_id(escrow_id)
    proof_bytes = []
    if proof_data_hex:
        clean = proof_data_hex[2:] if proof_data_hex.startswith("0x") else proof_data_hex
        proof_bytes = list(bytes.fromhex(clean))
    nonce, chain_id = await _fetch_nonce_and_chain_id(payer)
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
    result = await rpc_call(
        "tenzro_signAndSendTransaction",
        {
            "from": payer,
            "to": "0x" + "00" * 32,
            "value": 0,
            "gas_limit": 60_000,
            "gas_price": 1_000_000_000,
            "nonce": nonce,
            "chain_id": chain_id,
            "tx_type": tx_type,
        },
    )
    return json.dumps({"tx_hash": result} if isinstance(result, str) else result)


@mcp.tool
async def refund_escrow(payer: str, escrow_id: str) -> str:
    """Refund escrowed funds back to the payer via a signed RefundEscrow transaction.

    Uses ambient OAuth/DPoP auth — the bearer JWT must belong to the
    original payer. The escrow must be expired (or use Timeout/Custom
    release conditions).
    """
    escrow_id_bytes = _parse_escrow_id(escrow_id)
    nonce, chain_id = await _fetch_nonce_and_chain_id(payer)
    tx_type = {
        "type": "RefundEscrow",
        "data": {"escrow_id": escrow_id_bytes},
    }
    result = await rpc_call(
        "tenzro_signAndSendTransaction",
        {
            "from": payer,
            "to": "0x" + "00" * 32,
            "value": 0,
            "gas_limit": 50_000,
            "gas_price": 1_000_000_000,
            "nonce": nonce,
            "chain_id": chain_id,
            "tx_type": tx_type,
        },
    )
    return json.dumps({"tx_hash": result} if isinstance(result, str) else result)


@mcp.tool
async def get_escrow(escrow_id: str) -> str:
    """Inspect an escrow record by its 32-byte hex id."""
    clean = escrow_id[2:] if escrow_id.startswith("0x") else escrow_id
    if len(clean) != 64:
        raise ValueError(f"escrow_id must be 32 bytes (64 hex chars), got {len(clean)}")
    result = await rpc_call(
        "tenzro_getEscrow", [{"escrow_id": "0x" + clean}]
    )
    return json.dumps(result)


@mcp.tool
async def open_payment_channel(
    sender: str, recipient: str, deposit: str
) -> str:
    """Open an off-chain micropayment channel with an initial deposit."""
    result = await rpc_call(
        "tenzro_openPaymentChannel",
        {"sender": sender, "recipient": recipient, "deposit": deposit},
    )
    return json.dumps(result)


@mcp.tool
async def close_payment_channel(channel_id: str) -> str:
    """Close a micropayment channel and settle the final balances on-chain."""
    result = await rpc_call("tenzro_closePaymentChannel", [channel_id])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# AP2 — Agent Payments Protocol (3 tools)
#
# AP2 is Google/Stripe/Mastercard's verifiable-credential mandate model for
# agentic commerce. The principal signs a CheckoutMandate ("agent X may spend
# up to Y on Z before T") and the agent commits to a PaymentMandate (specific
# basket + total). Both are wrapped in `Vdc` envelopes carrying Ed25519
# signatures and a JCS-style canonical preimage.
#
# Position: TDIP identifies. AP2 authorizes. Tenzro settles.
# ---------------------------------------------------------------------------


@mcp.tool
async def ap2_sign_mandate(
    mandate_kind: str,
    mandate: dict,
    signer_did: str,
) -> str:
    """Sign an AP2 v0.2 mandate (checkout or payment) with the auth-bound wallet's Ed25519 key.

    Args:
        mandate_kind: ``"checkout"`` (principal-signed pre-authorization) or
            ``"payment"`` (agent-signed final-offer commit) per AP2 v0.2.
        mandate: The mandate object — CheckoutMandate or PaymentMandate, matching
            ``mandate_kind``.
        signer_did: Signer DID — must match the controller of the auth-bound
            wallet (principal for checkout, agent for payment).

    Auth: DPoP+JWT mandatory. The wallet must be Ed25519 (AP2 v0.2 only
    supports ``ed25519``). Returns the assembled, self-verified Vdc JSON.
    """
    result = await rpc_call(
        "tenzro_ap2SignMandate",
        [{"mandate_kind": mandate_kind, "mandate": mandate, "signer_did": signer_did}],
    )
    return json.dumps(result)


@mcp.tool
async def ap2_verify_mandate(vdc: dict) -> str:
    """Verify the Ed25519 signature on a Vdc-wrapped AP2 mandate (checkout or payment).

    Args:
        vdc: The full Vdc JSON envelope as produced by the AP2 SDK.

    Returns the mandate id, kind, signer DID, and signing algorithm on success;
    `valid: false` with an error string on failure.
    """
    result = await rpc_call("tenzro_ap2VerifyMandate", [{"vdc": vdc}])
    return json.dumps(result)


@mcp.tool
async def ap2_validate_mandate_pair(
    checkout_vdc: dict,
    payment_vdc: dict,
    enforce_delegation: bool = False,
) -> str:
    """Cross-validate an AP2 v0.2 PaymentMandate against its parent CheckoutMandate.

    Checks both Vdc signatures, principal/agent binding, checkout ceiling,
    merchant whitelist, expiry, and (when ``enforce_delegation`` is true)
    additionally enforces the agent's TDIP DelegationScope against the payment
    total via ``IdentityRegistry::enforce_operation(agent_did, "payment", total)``.

    Args:
        checkout_vdc: The principal-signed CheckoutMandate Vdc (AP2 v0.2).
        payment_vdc: The agent-signed PaymentMandate Vdc (AP2 v0.2).
        enforce_delegation: If true, run the TDIP delegation gate after
            AP2 validation succeeds. Default false (AP2-only).

    Returns ``valid: true`` with mandate ids on success; ``valid: false``
    with an error string on failure. The response includes
    ``delegation_enforced`` to surface which validation path ran.
    """
    result = await rpc_call(
        "tenzro_ap2ValidateMandatePair",
        [{
            "checkout_vdc": checkout_vdc,
            "payment_vdc": payment_vdc,
            "enforce_delegation": enforce_delegation,
        }],
    )
    return json.dumps(result)


@mcp.tool
async def ap2_protocol_info() -> str:
    """Return AP2 protocol metadata: version, signing algorithm, mandate kinds,
    presence modes, and the Tenzro positioning statement."""
    result = await rpc_call("tenzro_ap2ProtocolInfo", [])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# AI Models (10 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def list_models(category: str = None, name: str = None) -> str:
    """List available AI models. Optionally filter by category or name."""
    params = {}
    if category:
        params["category"] = category
    if name:
        params["name"] = name
    result = await rpc_call(
        "tenzro_listModels", params if params else []
    )
    return json.dumps(result)


@mcp.tool
async def chat_completion(
    model: str,
    message: str,
    temperature: float = 0.7,
    max_tokens: int = 1024,
) -> str:
    """Send a chat completion request to a served model and return the response."""
    result = await rpc_call(
        "tenzro_chat",
        {
            "model": model,
            "message": message,
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
    )
    return json.dumps(result)


@mcp.tool
async def list_model_endpoints() -> str:
    """List active model service endpoints with their API/MCP URLs and status."""
    result = await rpc_call("tenzro_listModelEndpoints", [])
    return json.dumps(result)


@mcp.tool
async def discover_models(
    category: str = None, max_price: float = None
) -> str:
    """Discover models available on the network with optional price filtering."""
    params = {}
    if category:
        params["category"] = category
    if max_price is not None:
        params["max_price"] = max_price
    result = await rpc_call("tenzro_discoverModels", params)
    return json.dumps(result)


@mcp.tool
async def download_model(model_id: str) -> str:
    """Download a model from the registry to the local node."""
    result = await rpc_call("tenzro_downloadModel", [model_id])
    return json.dumps(result)


@mcp.tool
async def serve_model(model_id: str) -> str:
    """Start serving a model for inference on this node."""
    result = await rpc_call("tenzro_serveModel", [model_id])
    return json.dumps(result)


@mcp.tool
async def stop_model(model_id: str) -> str:
    """Stop serving a model on this node."""
    result = await rpc_call("tenzro_stopModel", [model_id])
    return json.dumps(result)


@mcp.tool
async def delete_model(model_id: str) -> str:
    """Delete a downloaded model from the local node."""
    result = await rpc_call("tenzro_deleteModel", [model_id])
    return json.dumps(result)


@mcp.tool
async def get_download_progress(model_id: str) -> str:
    """Check the download progress of a model."""
    result = await rpc_call("tenzro_getDownloadProgress", [model_id])
    return json.dumps(result)


@mcp.tool
async def list_providers(provider_type: str = None) -> str:
    """List registered providers. Optionally filter by type (Validator, ModelProvider, TeeProvider)."""
    params = [provider_type] if provider_type else []
    result = await rpc_call("tenzro_listProviders", params)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Staking & Governance (7 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def stake_tokens(amount: str, provider_type: str) -> str:
    """Stake TNZO tokens as a Validator, ModelProvider, or TeeProvider."""
    result = await rpc_call("tenzro_stake", [amount, provider_type])
    return json.dumps(result)


@mcp.tool
async def unstake_tokens(amount: str, provider_type: str) -> str:
    """Unstake TNZO tokens and initiate the unbonding period."""
    result = await rpc_call("tenzro_unstake", [amount, provider_type])
    return json.dumps(result)


@mcp.tool
async def register_provider(provider_type: str, endpoint: str) -> str:
    """Register as a network provider with a service endpoint."""
    result = await rpc_call(
        "tenzro_registerProvider",
        {"provider_type": provider_type, "endpoint": endpoint},
    )
    return json.dumps(result)


@mcp.tool
async def get_provider_stats(address: str = None) -> str:
    """Get provider statistics: served models, inferences, staking totals."""
    params = [address] if address else []
    result = await rpc_call("tenzro_providerStats", params)
    return json.dumps(result)


@mcp.tool
async def list_proposals() -> str:
    """List active governance proposals."""
    result = await rpc_call("tenzro_listProposals", [])
    return json.dumps(result)


@mcp.tool
async def vote_on_proposal(proposal_id: str, vote: str) -> str:
    """Vote on a governance proposal. vote is 'for', 'against', or 'abstain'."""
    result = await rpc_call("tenzro_vote", [proposal_id, vote])
    return json.dumps(result)


@mcp.tool
async def get_voting_power(address: str) -> str:
    """Get the voting power for an address based on staked TNZO."""
    result = await rpc_call("tenzro_getVotingPower", [address])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Bridge (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def bridge_tokens(
    token: str,
    from_chain: str,
    to_chain: str,
    amount: str,
    recipient: str,
) -> str:
    """Bridge tokens between Tenzro, Ethereum, Solana, or Base via LayerZero/CCIP/deBridge."""
    result = await rpc_call(
        "tenzro_bridgeTokens",
        {
            "token": token,
            "from_chain": from_chain,
            "to_chain": to_chain,
            "amount": amount,
            "recipient": recipient,
        },
    )
    return json.dumps(result)


@mcp.tool
async def get_bridge_routes(from_chain: str, to_chain: str) -> str:
    """Get available bridge routes between two chains with fees and timing."""
    result = await rpc_call(
        "tenzro_getBridgeRoutes", [from_chain, to_chain]
    )
    return json.dumps(result)


@mcp.tool
async def list_bridge_adapters() -> str:
    """List registered bridge adapters (LayerZero, CCIP, deBridge, Canton)."""
    result = await rpc_call("tenzro_listBridgeAdapters", [])
    return json.dumps(result)


@mcp.tool
async def bridge_quote(
    token: str, from_chain: str, to_chain: str, amount: str
) -> str:
    """Get a fee quote for bridging tokens between two chains."""
    result = await rpc_call(
        "tenzro_bridgeQuote",
        {
            "token": token,
            "from_chain": from_chain,
            "to_chain": to_chain,
            "amount": amount,
        },
    )
    return json.dumps(result)


@mcp.tool
async def bridge_with_hook(
    token: str,
    from_chain: str,
    to_chain: str,
    amount: str,
    hook_target: str,
    hook_calldata: str,
) -> str:
    """Bridge tokens with a post-delivery hook to execute a contract call on the destination chain."""
    result = await rpc_call(
        "tenzro_bridgeWithHook",
        {
            "token": token,
            "from_chain": from_chain,
            "to_chain": to_chain,
            "amount": amount,
            "hook_target": hook_target,
            "hook_calldata": hook_calldata,
        },
    )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Tokens (7 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_token(
    name: str,
    symbol: str,
    decimals: int = 18,
    initial_supply: str = "1000000",
) -> str:
    """Create a new ERC-20 token via the factory and register it in the unified registry."""
    result = await rpc_call(
        "tenzro_createToken",
        {
            "name": name,
            "symbol": symbol,
            "decimals": decimals,
            "initial_supply": initial_supply,
        },
    )
    return json.dumps(result)


@mcp.tool
async def get_token_info(query: str) -> str:
    """Look up a token by symbol, EVM address, or token ID."""
    result = await rpc_call("tenzro_getToken", [query])
    return json.dumps(result)


@mcp.tool
async def list_tokens(vm_type: str = None) -> str:
    """List registered tokens with optional VM type filter (evm, svm, daml)."""
    params = [vm_type] if vm_type else []
    result = await rpc_call("tenzro_listTokens", params)
    return json.dumps(result)


@mcp.tool
async def deploy_contract(
    code: str, contract_type: str = "evm"
) -> str:
    """Deploy bytecode to the EVM, SVM, or DAML runtime."""
    result = await rpc_call(
        "tenzro_deployContract",
        {"code": code, "contract_type": contract_type},
    )
    return json.dumps(result)


@mcp.tool
async def cross_vm_transfer(
    token: str,
    from_addr: str,
    to_addr: str,
    amount: str,
    from_vm: str,
    to_vm: str,
) -> str:
    """Perform an atomic cross-VM token transfer using the TNZO pointer model."""
    result = await rpc_call(
        "tenzro_crossVmTransfer",
        {
            "token": token,
            "from": from_addr,
            "to": to_addr,
            "amount": amount,
            "from_vm": from_vm,
            "to_vm": to_vm,
        },
    )
    return json.dumps(result)


@mcp.tool
async def wrap_tnzo(vm_type: str = "evm") -> str:
    """Wrap native TNZO to its VM representation (no-op in pointer model)."""
    result = await rpc_call("tenzro_wrapTnzo", [vm_type])
    return json.dumps(result)


@mcp.tool
async def get_token_balance(address: str) -> str:
    """Get TNZO balance across all VMs with decimal conversion."""
    result = await rpc_call("tenzro_getTokenBalance", [address])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Tasks (7 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def post_task(
    task_type: str, description: str, budget: str
) -> str:
    """Post a new task to the task marketplace."""
    result = await rpc_call(
        "tenzro_postTask",
        {
            "task_type": task_type,
            "description": description,
            "budget": budget,
        },
    )
    return json.dumps(result)


@mcp.tool
async def list_tasks(
    task_type: str = None, status: str = None
) -> str:
    """List tasks in the marketplace. Optionally filter by type or status."""
    params = {}
    if task_type:
        params["task_type"] = task_type
    if status:
        params["status"] = status
    result = await rpc_call(
        "tenzro_listTasks", params if params else []
    )
    return json.dumps(result)


@mcp.tool
async def get_task(task_id: str) -> str:
    """Get details of a specific task by its ID."""
    result = await rpc_call("tenzro_getTask", [task_id])
    return json.dumps(result)


@mcp.tool
async def quote_task(task_id: str, price: str, model: str) -> str:
    """Submit a quote for a task with a proposed price and model."""
    result = await rpc_call(
        "tenzro_quoteTask",
        {"task_id": task_id, "price": price, "model": model},
    )
    return json.dumps(result)


@mcp.tool
async def assign_task(task_id: str, agent_id: str) -> str:
    """Assign a task to a specific agent."""
    result = await rpc_call("tenzro_assignTask", [task_id, agent_id])
    return json.dumps(result)


@mcp.tool
async def complete_task(task_id: str, result_data: str) -> str:
    """Mark a task as complete with the result data."""
    result = await rpc_call(
        "tenzro_completeTask",
        {"task_id": task_id, "result": result_data},
    )
    return json.dumps(result)


@mcp.tool
async def cancel_task(task_id: str) -> str:
    """Cancel a task in the marketplace."""
    result = await rpc_call("tenzro_cancelTask", [task_id])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Agents (9 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def register_agent(name: str, capabilities: list[str]) -> str:
    """Register a new AI agent with the specified capabilities."""
    result = await rpc_call(
        "tenzro_registerAgent",
        {"name": name, "capabilities": capabilities},
    )
    return json.dumps(result)


@mcp.tool
async def send_agent_message(
    from_agent: str,
    to_agent: str,
    message_type: str,
    payload: str,
) -> str:
    """Send a message from one agent to another via the A2A protocol."""
    result = await rpc_call(
        "tenzro_sendAgentMessage",
        {
            "from": from_agent,
            "to": to_agent,
            "message_type": message_type,
            "payload": payload,
        },
    )
    return json.dumps(result)


@mcp.tool
async def spawn_agent(
    parent_did: str, name: str, role: str
) -> str:
    """Spawn a child agent from a parent identity with a specific role."""
    result = await rpc_call(
        "tenzro_spawnAgent",
        {"parent_did": parent_did, "name": name, "role": role},
    )
    return json.dumps(result)


@mcp.tool
async def create_swarm(
    orchestrator_did: str, member_count: int
) -> str:
    """Create a multi-agent swarm with the specified number of members."""
    result = await rpc_call(
        "tenzro_createSwarm",
        {
            "orchestrator_did": orchestrator_did,
            "member_count": member_count,
        },
    )
    return json.dumps(result)


@mcp.tool
async def get_swarm_status(swarm_id: str) -> str:
    """Get the current status and member list of an agent swarm."""
    result = await rpc_call("tenzro_getSwarm", [swarm_id])
    return json.dumps(result)


@mcp.tool
async def terminate_swarm(swarm_id: str) -> str:
    """Terminate an agent swarm and release all members."""
    result = await rpc_call("tenzro_terminateSwarm", [swarm_id])
    return json.dumps(result)


@mcp.tool
async def list_agents() -> str:
    """List all registered agents on the network."""
    result = await rpc_call("tenzro_listAgents", [])
    return json.dumps(result)


@mcp.tool
async def get_agent_info(agent_id: str) -> str:
    """Get detailed information about a specific agent."""
    result = await rpc_call("tenzro_getAgentInfo", [agent_id])
    return json.dumps(result)


@mcp.tool
async def deregister_agent(agent_id: str) -> str:
    """Deregister an agent from the network."""
    result = await rpc_call("tenzro_deregisterAgent", [agent_id])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Agent Templates (7 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def register_agent_template(
    name: str,
    description: str,
    template_type: str,
    capabilities: list[str],
) -> str:
    """Register a reusable agent template in the marketplace."""
    result = await rpc_call(
        "tenzro_registerAgentTemplate",
        {
            "name": name,
            "description": description,
            "template_type": template_type,
            "capabilities": capabilities,
        },
    )
    return json.dumps(result)


@mcp.tool
async def list_agent_templates(template_type: str = None) -> str:
    """List available agent templates. Optionally filter by type."""
    params = [template_type] if template_type else []
    result = await rpc_call("tenzro_listAgentTemplates", params)
    return json.dumps(result)


@mcp.tool
async def get_agent_template(template_id: str) -> str:
    """Get details of a specific agent template."""
    result = await rpc_call("tenzro_getAgentTemplate", [template_id])
    return json.dumps(result)


@mcp.tool
async def search_agent_templates(query: str) -> str:
    """Search agent templates by name or description."""
    result = await rpc_call("tenzro_searchAgentTemplates", [query])
    return json.dumps(result)


@mcp.tool
async def spawn_from_template(
    template_id: str,
    name: str = "MCP Spawned Agent",
    parent_machine_did: str | None = None,
) -> str:
    """Spawn a new agent from a registered template.

    When ``parent_machine_did`` is provided, the spawned agent's effective
    delegation scope is the strict intersection of the parent's scope and
    the template's spec — the child can never be broader than its parent
    on any axis (numeric ceilings, allow-lists, time bound).
    """
    params: dict = {"template_id": template_id, "name": name}
    if parent_machine_did is not None:
        params["parent_machine_did"] = parent_machine_did
    result = await rpc_call("tenzro_spawnAgentFromTemplate", params)
    return json.dumps(result)


@mcp.tool
async def rate_template(
    template_id: str, rating: int, review: str = None
) -> str:
    """Rate an agent template (1-5 stars) with an optional text review."""
    params = {"template_id": template_id, "rating": rating}
    if review:
        params["review"] = review
    result = await rpc_call("tenzro_rateAgentTemplate", params)
    return json.dumps(result)


@mcp.tool
async def get_template_stats(template_id: str) -> str:
    """Get usage statistics for an agent template."""
    result = await rpc_call(
        "tenzro_getAgentTemplateStats", [template_id]
    )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# NFTs (6 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_nft_collection(
    name: str, symbol: str, nft_type: str = "erc721"
) -> str:
    """Create a new NFT collection. nft_type is 'erc721' or 'erc1155'."""
    result = await rpc_call(
        "tenzro_createNftCollection",
        {"name": name, "symbol": symbol, "nft_type": nft_type},
    )
    return json.dumps(result)


@mcp.tool
async def mint_nft(
    collection_id: str,
    token_id: str,
    recipient: str,
    metadata_uri: str,
) -> str:
    """Mint a new NFT in a collection to a recipient address."""
    result = await rpc_call(
        "tenzro_mintNft",
        {
            "collection_id": collection_id,
            "token_id": token_id,
            "recipient": recipient,
            "metadata_uri": metadata_uri,
        },
    )
    return json.dumps(result)


@mcp.tool
async def transfer_nft(
    collection_id: str,
    token_id: str,
    from_addr: str,
    to_addr: str,
) -> str:
    """Transfer an NFT from one address to another."""
    result = await rpc_call(
        "tenzro_transferNft",
        {
            "collection_id": collection_id,
            "token_id": token_id,
            "from": from_addr,
            "to": to_addr,
        },
    )
    return json.dumps(result)


@mcp.tool
async def get_nft_info(
    collection_id: str, token_id: str = None
) -> str:
    """Get info about an NFT collection or a specific token within it."""
    params = {"collection_id": collection_id}
    if token_id:
        params["token_id"] = token_id
    result = await rpc_call("tenzro_getNftInfo", params)
    return json.dumps(result)


@mcp.tool
async def list_nft_collections(creator: str = None) -> str:
    """List NFT collections. Optionally filter by creator address."""
    params = [creator] if creator else []
    result = await rpc_call("tenzro_listNftCollections", params)
    return json.dumps(result)


@mcp.tool
async def register_nft_pointer(
    collection_id: str, target_vm: str, target_address: str
) -> str:
    """Register a cross-VM pointer for an NFT collection."""
    result = await rpc_call(
        "tenzro_registerNftPointer",
        {
            "collection_id": collection_id,
            "target_vm": target_vm,
            "target_address": target_address,
        },
    )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Compliance (3 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def check_compliance(
    token: str, from_addr: str, to_addr: str, amount: str
) -> str:
    """Check if a token transfer complies with registered compliance rules."""
    result = await rpc_call(
        "tenzro_checkCompliance",
        {
            "token": token,
            "from": from_addr,
            "to": to_addr,
            "amount": amount,
        },
    )
    return json.dumps(result)


@mcp.tool
async def register_compliance(
    token: str, kyc_required: bool, holder_limit: int = None
) -> str:
    """Register compliance rules for a token (KYC requirement, holder limits)."""
    params = {"token": token, "kyc_required": kyc_required}
    if holder_limit is not None:
        params["holder_limit"] = holder_limit
    result = await rpc_call("tenzro_registerCompliance", params)
    return json.dumps(result)


@mcp.tool
async def freeze_address(token: str, address: str) -> str:
    """Freeze an address for a specific token, preventing all transfers."""
    result = await rpc_call("tenzro_freezeAddress", [token, address])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Canton (3 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def list_canton_domains() -> str:
    """List available Canton synchronization domains."""
    result = await rpc_call("tenzro_listCantonDomains", [])
    return json.dumps(result)


@mcp.tool
async def list_daml_contracts(domain_id: str) -> str:
    """List active DAML contracts on a Canton domain."""
    result = await rpc_call("tenzro_listDamlContracts", [domain_id])
    return json.dumps(result)


@mcp.tool
async def submit_daml_command(
    domain_id: str, command_type: str, payload: str
) -> str:
    """Submit a DAML command (create or exercise) to a Canton domain."""
    result = await rpc_call(
        "tenzro_submitDamlCommand",
        {
            "domain_id": domain_id,
            "command_type": command_type,
            "payload": payload,
        },
    )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Verification (1 tool)
# ---------------------------------------------------------------------------


@mcp.tool
async def verify_zk_proof(
    proof: str, circuit_id: str, public_inputs: list[str]
) -> str:
    """Verify a Plonky3 STARK proof over the KoalaBear field.

    circuit_id: one of "inference", "settlement", "identity"
    public_inputs: list of hex-encoded 4-byte little-endian KoalaBear field-element chunks
    """
    result = await api_call(
        "/verify/zk-proof",
        "POST",
        {
            "proof_bytes": proof,
            "circuit_id": circuit_id,
            "public_inputs": public_inputs,
        },
    )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Events (3 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_events(
    from_block: int = None,
    to_block: int = None,
    event_type: str = None,
) -> str:
    """Get blockchain events with optional block range and type filters."""
    params = {}
    if from_block is not None:
        params["from_block"] = from_block
    if to_block is not None:
        params["to_block"] = to_block
    if event_type:
        params["event_type"] = event_type
    result = await rpc_call("tenzro_getEvents", params)
    return json.dumps(result)


@mcp.tool
async def subscribe_events(filter: str) -> str:
    """Subscribe to real-time blockchain events matching a filter expression."""
    result = await rpc_call("tenzro_subscribeEvents", [filter])
    return json.dumps(result)


@mcp.tool
async def register_webhook(
    url: str, filter: str = None, secret: str = None
) -> str:
    """Register a webhook URL to receive event notifications."""
    params = {"url": url}
    if filter:
        params["filter"] = filter
    if secret:
        params["secret"] = secret
    result = await rpc_call("tenzro_registerWebhook", params)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Join (1 tool)
# ---------------------------------------------------------------------------


@mcp.tool
async def join_as_participant(display_name: str) -> str:
    """Join the Tenzro network as a participant. Provisions identity, wallet, and hardware profile."""
    result = await rpc_call(
        "tenzro_joinAsMicroNode", {"display_name": display_name}
    )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Skills Registry (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def list_skills() -> str:
    """List all registered skills in the Tenzro skills registry."""
    result = await rpc_call("tenzro_listSkills", [])
    return json.dumps(result)


@mcp.tool
async def register_skill(
    name: str, category: str, description: str, tags: list[str]
) -> str:
    """Register a new skill in the skills registry."""
    result = await rpc_call(
        "tenzro_registerSkill",
        {
            "name": name,
            "category": category,
            "description": description,
            "tags": tags,
        },
    )
    return json.dumps(result)


@mcp.tool
async def search_skills(query: str) -> str:
    """Search the skills registry by keyword or tag."""
    result = await rpc_call("tenzro_searchSkills", [query])
    return json.dumps(result)


@mcp.tool
async def get_skill(skill_id: str) -> str:
    """Get details of a specific skill by its ID."""
    result = await rpc_call("tenzro_getSkill", [skill_id])
    return json.dumps(result)


@mcp.tool
async def use_skill(skill_id: str, input_data: str) -> str:
    """Invoke a registered skill with the given input data."""
    result = await rpc_call(
        "tenzro_useSkill", {"skill_id": skill_id, "input": input_data}
    )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Tools Registry (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def list_registered_tools() -> str:
    """List all registered MCP tools in the tools registry."""
    result = await rpc_call("tenzro_listTools", [])
    return json.dumps(result)


@mcp.tool
async def register_tool(
    name: str, tool_type: str, endpoint: str, description: str
) -> str:
    """Register a new tool (MCP server endpoint) in the tools registry."""
    result = await rpc_call(
        "tenzro_registerTool",
        {
            "name": name,
            "tool_type": tool_type,
            "endpoint": endpoint,
            "description": description,
        },
    )
    return json.dumps(result)


@mcp.tool
async def search_tools(query: str) -> str:
    """Search the tools registry by keyword."""
    result = await rpc_call("tenzro_searchTools", [query])
    return json.dumps(result)


@mcp.tool
async def get_tool_info(tool_id: str) -> str:
    """Get details of a specific registered tool by its ID."""
    result = await rpc_call("tenzro_getTool", [tool_id])
    return json.dumps(result)


@mcp.tool
async def use_registered_tool(tool_id: str, input_data: str) -> str:
    """Invoke a registered tool with the given input data."""
    result = await rpc_call(
        "tenzro_useTool", {"tool_id": tool_id, "input": input_data}
    )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Network (1 tool)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_hardware_profile() -> str:
    """Detect and return the hardware profile of the local node (CPU, RAM, GPU, TEE)."""
    result = await rpc_call("tenzro_hardwareProfile", [])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Usage (2 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_skill_usage(skill_id: str) -> str:
    """Get usage statistics for a registered skill."""
    result = await rpc_call("tenzro_getSkillUsage", [skill_id])
    return json.dumps(result)


@mcp.tool
async def get_tool_usage(tool_id: str) -> str:
    """Get usage statistics for a registered tool."""
    result = await rpc_call("tenzro_getToolUsage", [tool_id])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Crypto (9 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def sign_message(private_key: str, message_hex: str, key_type: str = "ed25519") -> str:
    """Sign a message with Ed25519 or Secp256k1 private key."""
    result = await rpc_call("tenzro_signMessage", {"private_key": private_key, "message_hex": message_hex, "key_type": key_type})
    return json.dumps(result)


@mcp.tool
async def verify_signature(public_key: str, message_hex: str, signature_hex: str, key_type: str = "ed25519") -> str:
    """Verify a signature against a message and public key."""
    result = await rpc_call("tenzro_verifySignature", {"public_key": public_key, "message_hex": message_hex, "signature_hex": signature_hex, "key_type": key_type})
    return json.dumps(result)


@mcp.tool
async def encrypt_data(plaintext_hex: str, key_hex: str) -> str:
    """Encrypt data using AES-256-GCM. Returns ciphertext with nonce and tag."""
    result = await rpc_call("tenzro_encryptData", {"plaintext_hex": plaintext_hex, "key_hex": key_hex})
    return json.dumps(result)


@mcp.tool
async def decrypt_data(ciphertext_hex: str, key_hex: str) -> str:
    """Decrypt AES-256-GCM encrypted data. Input must include nonce and tag."""
    result = await rpc_call("tenzro_decryptData", {"ciphertext_hex": ciphertext_hex, "key_hex": key_hex})
    return json.dumps(result)


@mcp.tool
async def derive_key(seed_hex: str, path: str) -> str:
    """Derive a child key from a seed using the given derivation path."""
    result = await rpc_call("tenzro_deriveKey", {"seed_hex": seed_hex, "path": path})
    return json.dumps(result)


@mcp.tool
async def generate_keypair(key_type: str = "ed25519") -> str:
    """Generate a new cryptographic keypair (ed25519 or secp256k1). Returns public and private key hex."""
    result = await rpc_call("tenzro_generateKeypair", {"key_type": key_type})
    return json.dumps(result)


@mcp.tool
async def hash_sha256(data_hex: str) -> str:
    """Compute SHA-256 hash of hex-encoded data."""
    result = await rpc_call("tenzro_hashSha256", {"data_hex": data_hex})
    return json.dumps(result)


@mcp.tool
async def hash_keccak256(data_hex: str) -> str:
    """Compute Keccak-256 hash of hex-encoded data."""
    result = await rpc_call("tenzro_hashKeccak256", {"data_hex": data_hex})
    return json.dumps(result)


@mcp.tool
async def x25519_key_exchange(private_key_hex: str, peer_public_key_hex: str) -> str:
    """Perform X25519 Diffie-Hellman key exchange. Returns shared secret."""
    result = await rpc_call("tenzro_x25519KeyExchange", {"private_key_hex": private_key_hex, "peer_public_key_hex": peer_public_key_hex})
    return json.dumps(result)


# ---------------------------------------------------------------------------
# TEE (6 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def detect_tee() -> str:
    """Detect available TEE hardware on the current node (TDX, SEV-SNP, Nitro, GPU CC)."""
    result = await rpc_call("tenzro_detectTee", [])
    return json.dumps(result)


@mcp.tool
async def get_tee_attestation(provider: str = "auto") -> str:
    """Get a TEE attestation quote from the specified provider (auto, tdx, sev-snp, nitro, gpu)."""
    result = await rpc_call("tenzro_getTeeAttestation", {"provider": provider})
    return json.dumps(result)


@mcp.tool
async def verify_tee_attestation_rpc(provider: str, quote_hex: str) -> str:
    """Verify a TEE attestation quote via RPC. Returns verification result and measurements."""
    result = await rpc_call("tenzro_verifyTeeAttestation", {"provider": provider, "quote_hex": quote_hex})
    return json.dumps(result)


@mcp.tool
async def seal_data(plaintext_hex: str, key_id: str) -> str:
    """Seal data inside a TEE enclave using hardware-bound encryption."""
    result = await rpc_call("tenzro_sealData", {"plaintext_hex": plaintext_hex, "key_id": key_id})
    return json.dumps(result)


@mcp.tool
async def unseal_data(ciphertext_hex: str, key_id: str) -> str:
    """Unseal TEE-sealed data. Only works on the same hardware that sealed it."""
    result = await rpc_call("tenzro_unsealData", {"ciphertext_hex": ciphertext_hex, "key_id": key_id})
    return json.dumps(result)


@mcp.tool
async def list_tee_providers() -> str:
    """List registered TEE providers on the network with their attestation status."""
    result = await rpc_call("tenzro_listTeeProviders", [])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# ZK (2 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_zk_proof(circuit_id: str, witness: str) -> str:
    """Create a Plonky3 STARK proof over the KoalaBear field.

    circuit_id: one of "inference", "settlement", "identity"
    witness: JSON object with circuit-specific witness fields, e.g.
        - inference: {"model_checksum": <u64>, "input_checksum": <u64>, "computed_output": <u64>}
        - settlement: {"payer_balance": <u64>, "service_proof": <u64>, "nonce": <u64>,
                       "prev_nonce": <u64>, "amount": <u64>}
        - identity:   {"private_key": <u64>, "capabilities": <u64>, "capability_blinding": <u64>,
                       "actual_reputation": <u64>, "minimum_reputation": <u64>}
    """
    params = {"circuit_id": circuit_id, **json.loads(witness)}
    result = await rpc_call("tenzro_createZkProof", params)
    return json.dumps(result)


@mcp.tool
async def list_zk_circuits() -> str:
    """List available ZK circuits (inference, settlement, identity — all Plonky3 STARKs over KoalaBear)."""
    result = await rpc_call("tenzro_listCircuits", [])
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Custody (9 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_mpc_wallet(threshold: int = 2, total_shares: int = 3, key_type: str = "ed25519") -> str:
    """Create an MPC threshold wallet with the specified threshold and share count."""
    result = await rpc_call("tenzro_createMpcWallet", {"threshold": threshold, "total_shares": total_shares, "key_type": key_type})
    return json.dumps(result)


@mcp.tool
async def export_keystore(address: str, password: str) -> str:
    """Export an encrypted keystore file (Argon2id KDF) for a wallet address."""
    result = await rpc_call("tenzro_exportKeystore", {"address": address, "password": password})
    return json.dumps(result)


@mcp.tool
async def import_keystore(keystore_json: str, password: str) -> str:
    """Import a wallet from an encrypted keystore file."""
    result = await rpc_call("tenzro_importKeystore", {"keystore_json": keystore_json, "password": password})
    return json.dumps(result)


@mcp.tool
async def get_key_shares(address: str) -> str:
    """Get the MPC key share configuration for a wallet (threshold, total, share indices)."""
    result = await rpc_call("tenzro_getKeyShares", {"address": address})
    return json.dumps(result)


@mcp.tool
async def rotate_keys(address: str) -> str:
    """Rotate the MPC key shares for a wallet without changing the address."""
    result = await rpc_call("tenzro_rotateKeys", {"address": address})
    return json.dumps(result)


@mcp.tool
async def set_spending_limits(address: str, daily_limit: str, per_tx_limit: str) -> str:
    """Set daily and per-transaction spending limits for a wallet."""
    result = await rpc_call("tenzro_setSpendingLimits", {"address": address, "daily_limit": daily_limit, "per_tx_limit": per_tx_limit})
    return json.dumps(result)


@mcp.tool
async def get_spending_limits(address: str) -> str:
    """Get the current spending limits and usage for a wallet."""
    result = await rpc_call("tenzro_getSpendingLimits", {"address": address})
    return json.dumps(result)


@mcp.tool
async def authorize_session(address: str, duration_secs: int, max_amount: str) -> str:
    """Create a time-limited session key for automated transactions."""
    result = await rpc_call("tenzro_authorizeSession", {"address": address, "duration_secs": duration_secs, "max_amount": max_amount})
    return json.dumps(result)


@mcp.tool
async def revoke_session(address: str, session_id: str) -> str:
    """Revoke an active session key for a wallet."""
    result = await rpc_call("tenzro_revokeSession", {"address": address, "session_id": session_id})
    return json.dumps(result)


# ---------------------------------------------------------------------------
# App (6 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def register_app(name: str, description: str, callback_url: str = None) -> str:
    """Register an application to use Tenzro custody and wallet services."""
    params = {"name": name, "description": description}
    if callback_url:
        params["callback_url"] = callback_url
    result = await rpc_call("tenzro_registerApp", params)
    return json.dumps(result)


@mcp.tool
async def create_user_wallet(app_id: str, user_id: str, key_type: str = "ed25519") -> str:
    """Create a custodial wallet for an app user. The app manages the key shares."""
    result = await rpc_call("tenzro_createUserWallet", {"app_id": app_id, "user_id": user_id, "key_type": key_type})
    return json.dumps(result)


@mcp.tool
async def fund_user_wallet(app_id: str, user_id: str, amount: str) -> str:
    """Fund a user wallet from the app treasury."""
    result = await rpc_call("tenzro_fundUserWallet", {"app_id": app_id, "user_id": user_id, "amount": amount})
    return json.dumps(result)


@mcp.tool
async def list_user_wallets(app_id: str) -> str:
    """List all user wallets managed by an application."""
    result = await rpc_call("tenzro_listUserWallets", {"app_id": app_id})
    return json.dumps(result)


@mcp.tool
async def sponsor_transaction(app_id: str, user_address: str, tx_data: str) -> str:
    """Sponsor a transaction for a user (app pays gas via paymaster)."""
    result = await rpc_call("tenzro_sponsorTransaction", {"app_id": app_id, "user_address": user_address, "tx_data": tx_data})
    return json.dumps(result)


@mcp.tool
async def get_usage_stats(app_id: str) -> str:
    """Get usage statistics for an application (wallets, transactions, gas spent)."""
    result = await rpc_call("tenzro_getUsageStats", {"app_id": app_id})
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Contract Encoding (2 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def encode_function(abi_json: str, function_name: str, args: str) -> str:
    """ABI-encode a smart contract function call. Returns hex-encoded calldata."""
    result = await rpc_call("tenzro_encodeFunction", {"abi_json": abi_json, "function_name": function_name, "args": args})
    return json.dumps(result)


@mcp.tool
async def decode_result(abi_json: str, function_name: str, data_hex: str) -> str:
    """ABI-decode the return data from a smart contract call."""
    result = await rpc_call("tenzro_decodeResult", {"abi_json": abi_json, "function_name": function_name, "data_hex": data_hex})
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Streaming (2 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def chat_stream(model: str, message: str, max_tokens: int = 1024) -> str:
    """Send a chat completion request and stream the response token by token."""
    result = await rpc_call("tenzro_chatStream", {"model": model, "message": message, "max_tokens": max_tokens})
    return json.dumps(result)


@mcp.tool
async def subscribe_events_stream(filter: str = "all") -> str:
    """Subscribe to real-time blockchain events. Returns a subscription ID for streaming."""
    result = await rpc_call("tenzro_subscribeEventsStream", {"filter": filter})
    return json.dumps(result)


# ---------------------------------------------------------------------------
# deBridge Cross-Chain (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def debridge_search_tokens(query: str, chain_id: int = None) -> str:
    """Search for tokens available on deBridge DLN. Returns token addresses, symbols, and supported chains."""
    params = {"query": query}
    if chain_id:
        params["chain_id"] = chain_id
    result = await rpc_call("tenzro_debridgeSearchTokens", params)
    return json.dumps(result)


@mcp.tool
async def debridge_get_chains() -> str:
    """Get all blockchain networks supported by deBridge DLN for cross-chain transfers."""
    result = await rpc_call("tenzro_debridgeGetChains", {})
    return json.dumps(result)


@mcp.tool
async def debridge_get_instructions() -> str:
    """Get deBridge operational instructions and guidance for cross-chain transfers."""
    result = await rpc_call("tenzro_debridgeGetInstructions", {})
    return json.dumps(result)


@mcp.tool
async def debridge_create_tx(
    src_chain_id: int,
    dst_chain_id: int,
    src_token: str,
    dst_token: str,
    amount: str,
    recipient: str,
    sender: str = None,
) -> str:
    """Create a cross-chain transaction via deBridge DLN. Returns transaction data ready for signing."""
    params = {
        "src_chain_id": src_chain_id,
        "dst_chain_id": dst_chain_id,
        "src_token": src_token,
        "dst_token": dst_token,
        "amount": amount,
        "recipient": recipient,
    }
    if sender:
        params["sender"] = sender
    result = await rpc_call("tenzro_debridgeCreateTx", params)
    return json.dumps(result)


@mcp.tool
async def debridge_same_chain_swap(
    chain_id: int,
    token_in: str,
    token_out: str,
    amount: str,
    sender: str = None,
) -> str:
    """Execute a same-chain token swap via deBridge without cross-chain bridging."""
    params = {"chain_id": chain_id, "token_in": token_in, "token_out": token_out, "amount": amount}
    if sender:
        params["sender"] = sender
    result = await rpc_call("tenzro_debridgeSameChainSwap", params)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Tenzro MCP Server")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "http"],
    )
    parser.add_argument("--port", type=int, default=3001)
    args = parser.parse_args()

    if args.transport == "http":
        mcp.run(transport="http", port=args.port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
