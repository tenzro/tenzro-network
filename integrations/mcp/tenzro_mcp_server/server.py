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
async def get_balance(address: str) -> dict:
    """Get the TNZO token balance for a hex address. Returns the balance in wei."""
    result = await rpc_call("eth_getBalance", [address, "latest"])
    return {"address": address, "balance": result}


@mcp.tool
async def create_wallet() -> dict:
    """Provision a self-custody Tenzro 2-of-3 FROST-Ed25519 (RFC 9591) threshold wallet.

    Returns the canonical Tenzro wallet shape: ``wallet_id``, 32-byte hex
    ``address`` (the form used by ``eth_getBalance``, the faucet, and all
    transaction RPCs), base58 ``display_address``, ``public_key``,
    ``key_type`` (always ``ed25519`` — FROST-Ed25519 is the only scheme),
    ``threshold`` (2), and ``total_shares`` (3). The wallet additionally
    carries a mandatory ML-DSA-65 post-quantum signing key for hybrid
    signatures. No seed phrase or private key is ever returned — the
    keystore holds FROST secret shares + PQ seed and the node never sees
    a full key.
    """
    result = await rpc_call("tenzro_createWallet", [])
    return result


@mcp.tool
async def send_transaction(
    from_addr: str,
    to_addr: str,
    amount: str,
    gas_limit: int = 21000,
    gas_price: int = 1_000_000_000,
) -> dict:
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
            # Decimal string carries the full u128 range — JSON numbers
            # clamp to u64 in the handler's numeric path.
            "value": str(value_int),
            "gas_limit": gas_limit,
            "gas_price": gas_price,
            "nonce": nonce,
            "chain_id": chain_id,
        },
    )
    return {"tx_hash": result} if isinstance(result, str) else result


@mcp.tool
async def request_faucet(address: str) -> dict:
    """Request 100 testnet TNZO tokens from the faucet (24h cooldown per address)."""
    result = await rpc_call("tenzro_faucet", {"address": address})
    return result


@mcp.tool
async def token_balance(address: str) -> dict:
    """Get the TNZO token balance for an address via the token subsystem."""
    result = await rpc_call("tenzro_tokenBalance", {"address": address})
    return {"address": address, "balance": result}


@mcp.tool
async def total_supply() -> dict:
    """Get the total TNZO token supply."""
    result = await rpc_call("tenzro_totalSupply", [])
    return {"total_supply": result}


# ---------------------------------------------------------------------------
# OAuth 2.1 + DPoP Onboarding & Delegation (8 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def onboard_human(display_name: str, dpop_jkt: str = "", ttl_secs: int = 0) -> dict:
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
    return result


@mcp.tool
async def onboard_delegated_agent(
    controller_did: str,
    capabilities: list,
    delegation_scope: dict,
    dpop_jkt: str = "",
) -> dict:
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
    return result


@mcp.tool
async def onboard_autonomous_agent(bond_funding_address: str, dpop_jkt: str = "") -> dict:
    """Onboard a fully autonomous agent — requires a slashable TNZO bond
    posted at ``bond_funding_address``."""
    params = {"bond_funding_address": bond_funding_address}
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    result = await rpc_call("tenzro_onboardAutonomousAgent", [params])
    return result


@mcp.tool
async def refresh_token(refresh_token_value: str, dpop_jkt: str = "") -> dict:
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
    return result


@mcp.tool
async def link_wallet_for_auth(
    wallet_id: str,
    dpop_jkt: str = "",
    display_name: str = "",
    ttl_secs: int = 0,
) -> dict:
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
    return result


@mcp.tool
async def exchange_token(
    subject_token: str,
    child_bearer_did: str,
    child_dpop_jkt: str,
    requested_rar: dict,
    requested_aap_capabilities: list,
    requested_ttl_secs: int = 0,
) -> dict:
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
    return result


@mcp.tool
async def introspect_token(token: str) -> dict:
    """RFC 7662 OAuth 2.0 Token Introspection.

    Ask the AS whether ``token`` is currently active and, if so,
    return its full claim set (RAR ``authorization_details``, AAP
    ``aap_*`` claims, ``cnf``, ``controller_did``, etc.). Per
    RFC 7662 §2.2 a failed validation returns ``{"active": false}``
    with no other fields — the AS does not leak why the token is
    inactive.
    """
    result = await rpc_call("tenzro_introspectToken", [{"token": token}])
    return result


@mcp.tool
async def oauth_discovery() -> dict:
    """RFC 8414 / RFC 9728 OAuth Authorization Server / Protected
    Resource Metadata.

    Returns the same metadata document published at
    ``GET /.well-known/openid-configuration``, augmented with AAP
    extensions: ``authorization_details_types_supported`` (8 RAR
    types), ``aap_claims_supported`` (7 AAP claims), and
    ``dpop_signing_alg_values_supported`` (``["EdDSA"]``).
    """
    result = await rpc_call("tenzro_oauthDiscovery", [])
    return result


# ---------------------------------------------------------------------------
# Node & Blocks (3 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_node_status() -> dict:
    """Get the current node status including block height, peer count, uptime, and role."""
    result = await rpc_call("tenzro_nodeInfo", [])
    return result


@mcp.tool
async def get_block(height: int) -> dict:
    """Get a block by height with its transactions and metadata."""
    result = await rpc_call("eth_getBlockByNumber", [hex(height), False])
    return result


@mcp.tool
async def get_block_range(
    start_height: int, end_height: int, max_results: int = 64
) -> dict:
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
    return result


@mcp.tool
async def get_gas_price() -> dict:
    """Returns the current effective gas price in wei (base fee + suggested tip).

    Tracks the EIP-1559 fee market — value adjusts ±12.5% per block based on
    parent gas usage vs. the 15M target.
    """
    result = await rpc_call("eth_gasPrice", [])
    return {"gas_price_wei_hex": result}


@mcp.tool
async def get_max_priority_fee_per_gas() -> dict:
    """Returns a suggested EIP-1559 priority fee (tip) in wei.

    Use this to fill `maxPriorityFeePerGas` on a Type-2 transaction. Derive
    the base-fee portion from `get_fee_history` or the parent block's
    `baseFeePerGas`.
    """
    result = await rpc_call("eth_maxPriorityFeePerGas", [])
    return {"max_priority_fee_per_gas_wei_hex": result}


@mcp.tool
async def get_fee_history(
    block_count: int = 10,
    newest_block: str = "latest",
    reward_percentiles: list[float] | None = None,
) -> dict:
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
    return result


@mcp.tool
async def get_svm_cross_vm_program_info() -> dict:
    """Return the canonical Tenzro Cross-VM SVM-native program ID and instruction
    discriminators. The program ID is deterministically derived as
    `SHA-256("tenzro/svm/program/cross_vm")`. Discriminators are
    Anchor-style 8-byte `SHA-256("global:<snake_case_name>")[..8]`.

    Use this to construct SVM Instructions targeting the Tenzro Cross-VM
    native program from any SVM client (e.g. @solana/web3.js).
    """
    return {
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
    }


@mcp.tool
async def get_transaction_receipt(tx_hash: str) -> dict:
    """Look up a transaction receipt by its hash. Returns sender, recipient, status, gas used, and logs."""
    result = await rpc_call("eth_getTransactionReceipt", [tx_hash])
    return result


# ---------------------------------------------------------------------------
# Identity (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def register_identity(identity_type: str, display_name: str) -> dict:
    """Register a new TDIP identity. identity_type is 'human' or 'machine'."""
    result = await rpc_call(
        "tenzro_registerIdentity", [identity_type, display_name]
    )
    return result


@mcp.tool
async def resolve_did(did: str) -> dict:
    """Resolve a DID to its identity info and delegation scope."""
    result = await rpc_call("tenzro_resolveIdentity", {"did": did})
    return result


@mcp.tool
async def revoke_did(did: str, reason: str = "revoked via MCP") -> dict:
    """Revoke an identity by DID. Cascades JWT invalidation through the
    entire act-chain. Logical delete — record stays in CF_IDENTITIES with
    `Revoked` status. To hard-delete, follow up with `forget_identity`."""
    result = await rpc_call("tenzro_revokeDid", {"did": did, "reason": reason})
    return result


@mcp.tool
async def forget_identity(did: str) -> dict:
    """TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously
    revoked identity from the registry and persistent storage. The DID
    must already be in `Revoked` status — call `revoke_did` first, allow
    cascading revocation to propagate, then call this."""
    result = await rpc_call("tenzro_forgetIdentity", {"did": did})
    return result


@mcp.tool
async def set_delegation_scope(
    machine_did: str,
    max_transaction_value: int = None,
    allowed_operations: list = None,
) -> dict:
    """Set spending limits and allowed operations for a machine DID."""
    params = {"machine_did": machine_did}
    if max_transaction_value is not None:
        params["max_transaction_value"] = max_transaction_value
    if allowed_operations is not None:
        params["allowed_operations"] = allowed_operations
    result = await rpc_call("tenzro_setDelegationScope", params)
    return result


@mcp.tool
async def set_username(did: str, username: str) -> dict:
    """Set a human-readable username for a DID."""
    result = await rpc_call("tenzro_setUsername", {"did": did, "username": username})
    return result


@mcp.tool
async def resolve_username(username: str) -> dict:
    """Resolve a username to its associated DID and identity info."""
    result = await rpc_call("tenzro_resolveUsername", {"username": username})
    return result


# ---------------------------------------------------------------------------
# Payments (8 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_payment_challenge(
    protocol: str, resource: str, amount: str
) -> dict:
    """Create a payment challenge. protocol is 'mpp', 'x402', or 'native'."""
    result = await rpc_call(
        "tenzro_createPaymentChallenge",
        {"protocol": protocol, "resource": resource, "amount": amount},
    )
    return result


@mcp.tool
async def verify_payment(
    challenge_id: str, protocol: str, payer_did: str, amount: str
) -> dict:
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
    return result


@mcp.tool
async def list_payment_protocols() -> dict:
    """List supported payment protocols (MPP, x402, native) and their capabilities."""
    result = await rpc_call("tenzro_paymentGatewayInfo", [])
    return result


@mcp.tool
async def list_x402_schemes() -> dict:
    """List the x402 scheme backends registered on this node.

    Each scheme corresponds to a verification path under the x402 protocol:
    'tenzro-hybrid' (Ed25519 hybrid sig over canonical preimage),
    'exact-eip3009' (USDC EIP-3009 meta-tx via CDP facilitator),
    'permit2' (Uniswap Permit2 via CDP facilitator),
    'erc7710' (delegation redemption).

    Use the returned ids in the 'extra.scheme' field of an x402 PaymentRequirement.
    """
    result = await rpc_call("tenzro_listX402Schemes", [])
    return result


@mcp.tool
async def settle_payment(
    from_addr: str, to_addr: str, amount: str, service_type: str
) -> dict:
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
    return result


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
) -> dict:
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
    return {"tx_hash": result} if isinstance(result, str) else result


@mcp.tool
async def release_escrow(
    payer: str,
    escrow_id: str,
    proof_data_hex: str = "",
) -> dict:
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
    return {"tx_hash": result} if isinstance(result, str) else result


@mcp.tool
async def refund_escrow(payer: str, escrow_id: str) -> dict:
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
    return {"tx_hash": result} if isinstance(result, str) else result


@mcp.tool
async def get_escrow(escrow_id: str) -> dict:
    """Inspect an escrow record by its 32-byte hex id."""
    clean = escrow_id[2:] if escrow_id.startswith("0x") else escrow_id
    if len(clean) != 64:
        raise ValueError(f"escrow_id must be 32 bytes (64 hex chars), got {len(clean)}")
    result = await rpc_call(
        "tenzro_getEscrow", [{"escrow_id": "0x" + clean}]
    )
    return result


@mcp.tool
async def open_payment_channel(
    sender: str, recipient: str, deposit: str
) -> dict:
    """Open an off-chain micropayment channel with an initial deposit."""
    result = await rpc_call(
        "tenzro_openPaymentChannel",
        {"sender": sender, "recipient": recipient, "deposit": deposit},
    )
    return result


@mcp.tool
async def close_payment_channel(channel_id: str) -> dict:
    """Close a micropayment channel and settle the final balances on-chain."""
    result = await rpc_call("tenzro_closePaymentChannel", {"channel_id": channel_id})
    return result


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
) -> dict:
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
    return result


@mcp.tool
async def ap2_verify_mandate(vdc: dict) -> dict:
    """Verify the Ed25519 signature on a Vdc-wrapped AP2 mandate (checkout or payment).

    Args:
        vdc: The full Vdc JSON envelope as produced by the AP2 SDK.

    Returns the mandate id, kind, signer DID, and signing algorithm on success;
    `valid: false` with an error string on failure.
    """
    result = await rpc_call("tenzro_ap2VerifyMandate", [{"vdc": vdc}])
    return result


@mcp.tool
async def ap2_validate_mandate_pair(
    checkout_vdc: dict,
    payment_vdc: dict,
    enforce_delegation: bool = False,
) -> dict:
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
    return result


@mcp.tool
async def ap2_protocol_info() -> dict:
    """Return AP2 protocol metadata: version, signing algorithm, mandate kinds,
    presence modes, and the Tenzro positioning statement."""
    result = await rpc_call("tenzro_ap2ProtocolInfo", [])
    return result


# ---------------------------------------------------------------------------
# AI Models (10 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def list_models(category: str = None, name: str = None) -> dict:
    """List available AI models. Optionally filter by category or name."""
    params = {}
    if category:
        params["category"] = category
    if name:
        params["name"] = name
    result = await rpc_call(
        "tenzro_listModels", params if params else []
    )
    return result


@mcp.tool
async def chat_completion(
    model: str,
    message: str,
    temperature: float = 0.7,
    max_tokens: int = 1024,
) -> dict:
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
    return result


@mcp.tool
async def list_model_endpoints() -> dict:
    """List active model service endpoints with their API/MCP URLs and status."""
    result = await rpc_call("tenzro_listModelEndpoints", [])
    return result


@mcp.tool
async def discover_models(
    category: str = None, max_price: float = None
) -> dict:
    """Discover models available on the network with optional price filtering."""
    params = {}
    if category:
        params["category"] = category
    if max_price is not None:
        params["max_price"] = max_price
    result = await rpc_call("tenzro_discoverModels", params)
    return result


@mcp.tool
async def download_model(model_id: str) -> dict:
    """Download a model from the registry to the local node."""
    result = await rpc_call("tenzro_downloadModel", {"model_id": model_id})
    return result


@mcp.tool
async def serve_model(model_id: str) -> dict:
    """Start serving a model for inference on this node."""
    result = await rpc_call("tenzro_serveModel", {"model_id": model_id})
    return result


@mcp.tool
async def stop_model(model_id: str) -> dict:
    """Stop serving a model on this node."""
    result = await rpc_call("tenzro_stopModel", {"model_id": model_id})
    return result


@mcp.tool
async def delete_model(model_id: str) -> dict:
    """Delete a downloaded model from the local node."""
    result = await rpc_call("tenzro_deleteModel", {"model_id": model_id})
    return result


@mcp.tool
async def get_download_progress(model_id: str) -> dict:
    """Check the download progress of a model."""
    result = await rpc_call("tenzro_getDownloadProgress", {"model_id": model_id})
    return result


@mcp.tool
async def list_providers(provider_type: str = None) -> dict:
    """List registered providers. Optionally filter by type (Validator, ModelProvider, TeeProvider)."""
    params = [provider_type] if provider_type else []
    result = await rpc_call("tenzro_listProviders", params)
    return result


# ---------------------------------------------------------------------------
# Staking & Governance (7 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def stake_tokens(amount: str, provider_type: str) -> dict:
    """Stake TNZO tokens as a Validator, ModelProvider, or TeeProvider."""
    result = await rpc_call("tenzro_stake", {"amount": amount, "provider_type": provider_type})
    return result


@mcp.tool
async def unstake_tokens(amount: str, provider_type: str) -> dict:
    """Unstake TNZO tokens and initiate the unbonding period."""
    result = await rpc_call("tenzro_unstake", {"amount": amount, "provider_type": provider_type})
    return result


@mcp.tool
async def register_provider(provider_type: str, endpoint: str) -> dict:
    """Register as a network provider with a service endpoint."""
    result = await rpc_call(
        "tenzro_registerProvider",
        {"provider_type": provider_type, "endpoint": endpoint},
    )
    return result


@mcp.tool
async def get_provider_stats(address: str = None) -> dict:
    """Get provider statistics: served models, inferences, staking totals."""
    params = [address] if address else []
    result = await rpc_call("tenzro_providerStats", params)
    return result


# ---------------------------------------------------------------------------
# Validator Registry (read + key rotation)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_validator_state(address: str) -> dict:
    """Fetch a single validator's registry entry by 32-byte hex address.

    Returns null if the address is not registered.
    """
    return await rpc_call("tenzro_getValidatorState", {"address": address})


@mcp.tool
async def list_validators(status: str = None) -> dict:
    """List validators in the registry, optionally filtered by status.

    status: Active | Candidate | PendingActive | PendingExit | Exited | Jailed
    """
    params = {"status": status} if status else {}
    return await rpc_call("tenzro_listValidators", params)


@mcp.tool
async def list_active_validators() -> dict:
    """List only currently-Active validators (those producing blocks)."""
    return await rpc_call("tenzro_listActiveValidators", {})


@mcp.tool
async def rotate_validator_key(
    address: str,
    new_consensus_pubkey: str,
    new_pq_pubkey: str,
    new_bls_pubkey: str,
    nonce: int,
    signature: str,
) -> dict:
    """Rotate a validator's consensus + PQ + BLS keys.

    The signature is produced offline by the operator: sign
    SHA-256("tenzro/rotate-validator-key" || address(32) ||
    new_consensus(32) || new_pq(1952) || new_bls(48) || nonce_le(8))
    with the *current* Ed25519 consensus key. All hex fields are
    0x-prefixed.

    The rotation lands on the receiving node only. Operators must
    fan out the same call to every active validator before the next
    epoch boundary — see tools/deploy/rotate-validator-key.sh.
    """
    return await rpc_call(
        "tenzro_rotateValidatorKey",
        {
            "address": address,
            "new_consensus_pubkey": new_consensus_pubkey,
            "new_pq_pubkey": new_pq_pubkey,
            "new_bls_pubkey": new_bls_pubkey,
            "nonce": nonce,
            "signature": signature,
        },
    )


@mcp.tool
async def list_proposals() -> dict:
    """List active governance proposals."""
    result = await rpc_call("tenzro_listProposals", [])
    return result


@mcp.tool
async def vote_on_proposal(proposal_id: str, vote: str) -> dict:
    """Vote on a governance proposal. vote is 'for', 'against', or 'abstain'."""
    result = await rpc_call("tenzro_vote", {"proposal_id": proposal_id, "vote": vote})
    return result


@mcp.tool
async def get_voting_power(address: str) -> dict:
    """Get the voting power for an address based on staked TNZO."""
    result = await rpc_call("tenzro_getVotingPower", {"address": address})
    return result


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
) -> dict:
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
    return result


@mcp.tool
async def get_bridge_routes(from_chain: str, to_chain: str) -> dict:
    """Get available bridge routes between two chains with fees and timing."""
    result = await rpc_call(
        "tenzro_getBridgeRoutes", [from_chain, to_chain]
    )
    return result


@mcp.tool
async def list_bridge_adapters() -> dict:
    """List registered bridge adapters (LayerZero, CCIP, deBridge, Canton)."""
    result = await rpc_call("tenzro_listBridgeAdapters", [])
    return result


@mcp.tool
async def bridge_quote(
    token: str, from_chain: str, to_chain: str, amount: str
) -> dict:
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
    return result


@mcp.tool
async def bridge_with_hook(
    token: str,
    from_chain: str,
    to_chain: str,
    amount: str,
    hook_target: str,
    hook_calldata: str,
) -> dict:
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
    return result


# ---------------------------------------------------------------------------
# Tokens (7 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_token(
    name: str,
    symbol: str,
    decimals: int = 18,
    initial_supply: str = "1000000",
) -> dict:
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
    return result


@mcp.tool
async def get_token_info(query: str) -> dict:
    """Look up a token by symbol, EVM address, or token ID."""
    if query.startswith("0x") and len(query) == 42:
        params = {"evm_address": query}
    elif query.isdigit():
        params = {"token_id": query}
    else:
        params = {"symbol": query}
    result = await rpc_call("tenzro_getToken", params)
    return result


@mcp.tool
async def list_tokens(vm_type: str = None) -> dict:
    """List registered tokens with optional VM type filter (evm, svm, daml)."""
    params = [vm_type] if vm_type else []
    result = await rpc_call("tenzro_listTokens", params)
    return result


@mcp.tool
async def deploy_contract(
    code: str, contract_type: str = "evm"
) -> dict:
    """Deploy bytecode to the EVM, SVM, or DAML runtime."""
    result = await rpc_call(
        "tenzro_deployContract",
        {"code": code, "contract_type": contract_type},
    )
    return result


@mcp.tool
async def cross_vm_transfer(
    token: str,
    from_addr: str,
    to_addr: str,
    amount: str,
    from_vm: str,
    to_vm: str,
) -> dict:
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
    return result


@mcp.tool
async def wrap_tnzo(address: str, amount: str, vm_type: str = "evm") -> dict:
    """Wrap native TNZO to its VM representation for an address/amount.

    ``amount`` is in wei (smallest unit). ``vm_type`` selects the target VM
    representation ("evm", "svm", "tempo")."""
    result = await rpc_call(
        "tenzro_wrapTnzo",
        {"address": address, "amount": amount, "to_vm": vm_type},
    )
    return result


@mcp.tool
async def get_token_balance(address: str) -> dict:
    """Get TNZO balance across all VMs with decimal conversion."""
    result = await rpc_call("tenzro_getTokenBalance", {"address": address})
    return result


# ---------------------------------------------------------------------------
# Tasks (7 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def post_task(
    task_type: str, description: str, budget: str
) -> dict:
    """Post a new task to the task marketplace."""
    result = await rpc_call(
        "tenzro_postTask",
        {
            "task_type": task_type,
            "description": description,
            "budget": budget,
        },
    )
    return result


@mcp.tool
async def list_tasks(
    task_type: str = None, status: str = None
) -> dict:
    """List tasks in the marketplace. Optionally filter by type or status."""
    params = {}
    if task_type:
        params["task_type"] = task_type
    if status:
        params["status"] = status
    result = await rpc_call(
        "tenzro_listTasks", params if params else []
    )
    return result


@mcp.tool
async def get_task(task_id: str) -> dict:
    """Get details of a specific task by its ID."""
    result = await rpc_call("tenzro_getTask", {"task_id": task_id})
    return result


@mcp.tool
async def quote_task(task_id: str, price: str, model: str) -> dict:
    """Submit a quote for a task with a proposed price and model."""
    result = await rpc_call(
        "tenzro_quoteTask",
        {"task_id": task_id, "price": price, "model": model},
    )
    return result


@mcp.tool
async def assign_task(task_id: str, agent_id: str) -> dict:
    """Assign a task to a specific agent."""
    result = await rpc_call("tenzro_assignTask", {"task_id": task_id, "provider": agent_id})
    return result


@mcp.tool
async def complete_task(task_id: str, result_data: str) -> dict:
    """Mark a task as complete with the result data."""
    result = await rpc_call(
        "tenzro_completeTask",
        {"task_id": task_id, "result": result_data},
    )
    return result


@mcp.tool
async def cancel_task(task_id: str) -> dict:
    """Cancel a task in the marketplace."""
    result = await rpc_call("tenzro_cancelTask", {"task_id": task_id})
    return result


# ---------------------------------------------------------------------------
# Agents (9 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def register_agent(name: str, capabilities: list[str]) -> dict:
    """Register a new AI agent with the specified capabilities."""
    result = await rpc_call(
        "tenzro_registerAgent",
        {"name": name, "capabilities": capabilities},
    )
    return result


@mcp.tool
async def send_agent_message(
    from_agent: str,
    to_agent: str,
    message_type: str,
    payload: str,
) -> dict:
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
    return result


@mcp.tool
async def spawn_agent(
    parent_did: str, name: str, role: str
) -> dict:
    """Spawn a child agent from a parent identity with a specific role."""
    result = await rpc_call(
        "tenzro_spawnAgent",
        {"parent_did": parent_did, "name": name, "role": role},
    )
    return result


@mcp.tool
async def create_swarm(
    orchestrator_did: str, member_count: int
) -> dict:
    """Create a multi-agent swarm with the specified number of members."""
    result = await rpc_call(
        "tenzro_createSwarm",
        {
            "orchestrator_did": orchestrator_did,
            "member_count": member_count,
        },
    )
    return result


@mcp.tool
async def get_swarm_status(swarm_id: str) -> dict:
    """Get the current status and member list of an agent swarm."""
    result = await rpc_call("tenzro_getSwarmStatus", {"swarm_id": swarm_id})
    return result


@mcp.tool
async def terminate_swarm(swarm_id: str) -> dict:
    """Terminate an agent swarm and release all members."""
    result = await rpc_call("tenzro_terminateSwarm", {"swarm_id": swarm_id})
    return result


@mcp.tool
async def list_agents() -> dict:
    """List all registered agents on the network."""
    result = await rpc_call("tenzro_listAgents", [])
    return result


@mcp.tool
async def get_agent_info(agent_id: str) -> dict:
    """Get detailed information about a specific agent."""
    result = await rpc_call("tenzro_getAgent", {"agent_id": agent_id})
    return result


@mcp.tool
async def deregister_agent(agent_id: str, reason: str = "Operator deregister") -> dict:
    """Deregister (suspend) an agent from the active network registry."""
    result = await rpc_call(
        "tenzro_suspendAgent", {"agent_id": agent_id, "reason": reason}
    )
    return result


# ---------------------------------------------------------------------------
# Agent Templates (7 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def register_agent_template(
    name: str,
    description: str,
    template_type: str,
    creator: str,
    system_prompt: str = "",
    tags: list[str] | None = None,
    template_id: str | None = None,
    pricing: str = "free",
    creator_did: str | None = None,
    creator_wallet: str | None = None,
) -> dict:
    """Register a reusable agent template in the marketplace.

    creator: hex-encoded (0x-prefixed) creator address — required by the node.
    template_id: optional stable id (e.g. "ref-..."); registration fails if it
        already exists. When omitted the node mints a UUID.
    pricing: "free", "per_execution:<wei>", "per_token:<wei>",
        "subscription:<wei>", or "revenue_share:<bps>". Non-free pricing
        requires creator_wallet (receives the creator share of each invocation).
    """
    params: dict = {
        "name": name,
        "description": description,
        "template_type": template_type,
        "creator": creator,
        "system_prompt": system_prompt,
        "tags": tags or [],
        "pricing": pricing,
    }
    if template_id:
        params["template_id"] = template_id
    if creator_did:
        params["creator_did"] = creator_did
    if creator_wallet:
        params["creator_wallet"] = creator_wallet
    result = await rpc_call("tenzro_registerAgentTemplate", params)
    return result


@mcp.tool
async def list_agent_templates(template_type: str = None) -> dict:
    """List available agent templates. Optionally filter by type."""
    params = [template_type] if template_type else []
    result = await rpc_call("tenzro_listAgentTemplates", params)
    return result


@mcp.tool
async def get_agent_template(template_id: str) -> dict:
    """Get details of a specific agent template."""
    result = await rpc_call("tenzro_getAgentTemplate", {"template_id": template_id})
    return result


@mcp.tool
async def search_agent_templates(query: str) -> dict:
    """Search agent templates by name or description."""
    result = await rpc_call("tenzro_searchAgentTemplates", {"query": query})
    return result


@mcp.tool
async def spawn_from_template(
    template_id: str,
    name: str = "MCP Spawned Agent",
    parent_machine_did: str | None = None,
) -> dict:
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
    return result


@mcp.tool
async def rate_template(
    template_id: str, rating: int, review: str = None
) -> dict:
    """Rate an agent template (1-5 stars) with an optional text review."""
    params = {"template_id": template_id, "rating": rating}
    if review:
        params["review"] = review
    result = await rpc_call("tenzro_rateAgentTemplate", params)
    return result


@mcp.tool
async def get_template_stats(template_id: str) -> dict:
    """Get usage statistics for an agent template."""
    result = await rpc_call(
        "tenzro_getAgentTemplateStats", [template_id]
    )
    return result


# ---------------------------------------------------------------------------
# NFTs (6 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_nft_collection(
    name: str, symbol: str, nft_type: str = "erc721"
) -> dict:
    """Create a new NFT collection. nft_type is 'erc721' or 'erc1155'."""
    result = await rpc_call(
        "tenzro_createNftCollection",
        {"name": name, "symbol": symbol, "nft_type": nft_type},
    )
    return result


@mcp.tool
async def mint_nft(
    collection_id: str,
    token_id: str,
    recipient: str,
    metadata_uri: str,
) -> dict:
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
    return result


@mcp.tool
async def transfer_nft(
    collection_id: str,
    token_id: str,
    from_addr: str,
    to_addr: str,
) -> dict:
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
    return result


@mcp.tool
async def get_nft_info(
    collection_id: str, token_id: str = None
) -> dict:
    """Get info about an NFT collection or a specific token within it."""
    params = {"collection_id": collection_id}
    if token_id:
        params["token_id"] = token_id
    result = await rpc_call("tenzro_getNftInfo", params)
    return result


@mcp.tool
async def list_nft_collections(creator: str = None) -> dict:
    """List NFT collections. Optionally filter by creator address."""
    params = [creator] if creator else []
    result = await rpc_call("tenzro_listNftCollections", params)
    return result


@mcp.tool
async def register_nft_pointer(
    collection_id: str, target_vm: str, target_address: str
) -> dict:
    """Register a cross-VM pointer for an NFT collection."""
    result = await rpc_call(
        "tenzro_registerNftPointer",
        {
            "collection_id": collection_id,
            "target_vm": target_vm,
            "target_address": target_address,
        },
    )
    return result


# ---------------------------------------------------------------------------
# Compliance (3 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def check_compliance(
    token: str, from_addr: str, to_addr: str, amount: str
) -> dict:
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
    return result


@mcp.tool
async def register_compliance(
    token: str, kyc_required: bool, holder_limit: int = None
) -> dict:
    """Register compliance rules for a token (KYC requirement, holder limits)."""
    params = {"token": token, "kyc_required": kyc_required}
    if holder_limit is not None:
        params["holder_limit"] = holder_limit
    result = await rpc_call("tenzro_registerCompliance", params)
    return result


@mcp.tool
async def freeze_address(token: str, address: str) -> dict:
    """Freeze an address for a specific token, preventing all transfers."""
    result = await rpc_call("tenzro_freezeAddress", {"token_id": token, "address": address})
    return result


# ---------------------------------------------------------------------------
# Canton (3 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def list_canton_domains() -> dict:
    """List Canton synchronizer domains configured on this node.

    Returns the ``{enabled, domains, message?}`` envelope. Check ``enabled``
    before treating ``domains`` as live.
    """
    result = await rpc_call("tenzro_listCantonDomains", {})
    return result


@mcp.tool
async def list_daml_contracts(
    template_ids: list[str], query: dict | None = None
) -> dict:
    """Query active DAML contracts on the shared Canton domain.

    template_ids: one or more DAML template ids (required, non-empty).
    query: optional structural filter applied against ``createArguments``.
    """
    params: dict = {"template_ids": template_ids}
    if query is not None:
        params["query"] = query
    result = await rpc_call("tenzro_listDamlContracts", params)
    return result


@mcp.tool
async def submit_daml_create(template_id: str, create_arguments: dict) -> dict:
    """Submit a DAML ``create`` command on the shared Canton domain."""
    result = await rpc_call(
        "tenzro_submitDamlCommand",
        {
            "command_type": "create",
            "template_id": template_id,
            "create_arguments": create_arguments,
        },
    )
    return result


@mcp.tool
async def submit_daml_exercise(
    template_id: str, contract_id: str, choice: str, choice_argument: dict
) -> dict:
    """Submit a DAML ``exercise`` command on an existing contract."""
    result = await rpc_call(
        "tenzro_submitDamlCommand",
        {
            "command_type": "exercise",
            "template_id": template_id,
            "contract_id": contract_id,
            "choice": choice,
            "choice_argument": choice_argument,
        },
    )
    return result


# ---------------------------------------------------------------------------
# Verification (1 tool)
# ---------------------------------------------------------------------------


@mcp.tool
async def verify_zk_proof(
    proof: str, circuit_id: str, public_inputs: list[str]
) -> dict:
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
    return result


# ---------------------------------------------------------------------------
# Events (3 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_events(
    from_block: int = None,
    to_block: int = None,
    event_type: str = None,
) -> dict:
    """Get blockchain events with optional block range and type filters."""
    params = {}
    if from_block is not None:
        params["from_block"] = from_block
    if to_block is not None:
        params["to_block"] = to_block
    if event_type:
        params["event_type"] = event_type
    result = await rpc_call("tenzro_getEvents", params)
    return result


@mcp.tool
async def subscribe_events(filter: str) -> dict:
    """Subscribe to real-time blockchain events matching a filter expression."""
    result = await rpc_call("tenzro_subscribeEvents", [filter])
    return result


@mcp.tool
async def register_webhook(
    url: str, filter: str = None, secret: str = None
) -> dict:
    """Register a webhook URL to receive event notifications."""
    params = {"url": url}
    if filter:
        params["filter"] = filter
    if secret:
        params["secret"] = secret
    result = await rpc_call("tenzro_registerWebhook", params)
    return result


# ---------------------------------------------------------------------------
# Join (1 tool)
# ---------------------------------------------------------------------------


@mcp.tool
async def join_as_participant(display_name: str) -> dict:
    """Join the Tenzro network as a participant. Provisions identity, wallet, and hardware profile."""
    result = await rpc_call(
        "tenzro_joinAsMicroNode", {"display_name": display_name}
    )
    return result


# ---------------------------------------------------------------------------
# Skills Registry (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def list_skills() -> dict:
    """List all registered skills in the Tenzro skills registry."""
    result = await rpc_call("tenzro_listSkills", [])
    return result


@mcp.tool
async def register_skill(
    name: str, category: str, description: str, tags: list[str]
) -> dict:
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
    return result


@mcp.tool
async def search_skills(query: str) -> dict:
    """Search the skills registry by keyword or tag."""
    result = await rpc_call("tenzro_searchSkills", {"query": query})
    return result


@mcp.tool
async def get_skill(skill_id: str) -> dict:
    """Get details of a specific skill by its ID."""
    result = await rpc_call("tenzro_getSkill", {"skill_id": skill_id})
    return result


@mcp.tool
async def use_skill(skill_id: str, input_data: str) -> dict:
    """Invoke a registered skill with the given input data."""
    result = await rpc_call(
        "tenzro_useSkill", {"skill_id": skill_id, "input": input_data}
    )
    return result


# ---------------------------------------------------------------------------
# Tools Registry (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def list_registered_tools() -> dict:
    """List all registered MCP tools in the tools registry."""
    result = await rpc_call("tenzro_listTools", [])
    return result


@mcp.tool
async def register_tool(
    name: str, tool_type: str, endpoint: str, description: str
) -> dict:
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
    return result


@mcp.tool
async def search_tools(query: str) -> dict:
    """Search the tools registry by keyword."""
    result = await rpc_call("tenzro_searchTools", {"query": query})
    return result


@mcp.tool
async def get_tool_info(tool_id: str) -> dict:
    """Get details of a specific registered tool by its ID."""
    result = await rpc_call("tenzro_getTool", {"tool_id": tool_id})
    return result


@mcp.tool
async def use_registered_tool(tool_id: str, input_data: str) -> dict:
    """Invoke a registered tool with the given input data."""
    result = await rpc_call(
        "tenzro_useTool", {"tool_id": tool_id, "input": input_data}
    )
    return result


# ---------------------------------------------------------------------------
# Network (1 tool)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_hardware_profile() -> dict:
    """Detect and return the hardware profile of the local node (CPU, RAM, GPU, TEE)."""
    result = await rpc_call("tenzro_hardwareProfile", [])
    return result


# ---------------------------------------------------------------------------
# Usage (2 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def get_skill_usage(skill_id: str) -> dict:
    """Get usage statistics for a registered skill."""
    result = await rpc_call("tenzro_getSkillUsage", {"skill_id": skill_id})
    return result


@mcp.tool
async def get_tool_usage(tool_id: str) -> dict:
    """Get usage statistics for a registered tool."""
    result = await rpc_call("tenzro_getToolUsage", {"tool_id": tool_id})
    return result


# ---------------------------------------------------------------------------
# Crypto (9 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def sign_message(message_hex: str) -> dict:
    """Sign a message with the auth-bound wallet (FROST-Ed25519 + ML-DSA-65 hybrid).

    The signer is resolved from the bearer DID via OAuth/DPoP; raw private
    keys never travel over the wire. Returns the hybrid signature (classical
    leg + post-quantum leg).
    """
    result = await rpc_call("tenzro_signMessage", {"message_hex": message_hex})
    return result


@mcp.tool
async def verify_signature(public_key: str, message_hex: str, signature_hex: str) -> dict:
    """Verify a signature against a message and public key.

    Key type (Ed25519 vs Secp256k1) is inferred from the public key length
    (32 bytes → Ed25519, 33 bytes → Secp256k1).
    """
    result = await rpc_call("tenzro_verifySignature", {"public_key": public_key, "message_hex": message_hex, "signature_hex": signature_hex})
    return result


@mcp.tool
async def encrypt_data(plaintext_hex: str, key_hex: str) -> dict:
    """Encrypt data using AES-256-GCM. Returns ciphertext with nonce and tag."""
    result = await rpc_call("tenzro_encryptData", {"plaintext_hex": plaintext_hex, "key_hex": key_hex})
    return result


@mcp.tool
async def decrypt_data(ciphertext_hex: str, key_hex: str) -> dict:
    """Decrypt AES-256-GCM encrypted data. Input must include nonce and tag."""
    result = await rpc_call("tenzro_decryptData", {"ciphertext_hex": ciphertext_hex, "key_hex": key_hex})
    return result


@mcp.tool
async def derive_key(seed_hex: str, path: str) -> dict:
    """Derive a child key from a seed using the given derivation path."""
    result = await rpc_call("tenzro_deriveKey", {"seed_hex": seed_hex, "path": path})
    return result


@mcp.tool
async def generate_keypair(key_type: str = "ed25519") -> dict:
    """Generate a new cryptographic keypair (ed25519 or secp256k1). Returns public and private key hex."""
    result = await rpc_call("tenzro_generateKeypair", {"key_type": key_type})
    return result


@mcp.tool
async def hash_sha256(data_hex: str) -> dict:
    """Compute SHA-256 hash of hex-encoded data."""
    result = await rpc_call("tenzro_hashSha256", {"data_hex": data_hex})
    return result


@mcp.tool
async def hash_keccak256(data_hex: str) -> dict:
    """Compute Keccak-256 hash of hex-encoded data."""
    result = await rpc_call("tenzro_hashKeccak256", {"data_hex": data_hex})
    return result


@mcp.tool
async def x25519_key_exchange(private_key_hex: str, peer_public_key_hex: str) -> dict:
    """Perform X25519 Diffie-Hellman key exchange. Returns shared secret."""
    result = await rpc_call("tenzro_x25519KeyExchange", {"private_key_hex": private_key_hex, "peer_public_key_hex": peer_public_key_hex})
    return result


# ---------------------------------------------------------------------------
# TEE (6 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def detect_tee() -> dict:
    """Detect available TEE hardware on the current node (TDX, SEV-SNP, Nitro, GPU CC)."""
    result = await rpc_call("tenzro_detectTee", [])
    return result


@mcp.tool
async def get_tee_attestation(provider: str = "auto") -> dict:
    """Get a TEE attestation quote from the specified provider (auto, tdx, sev-snp, nitro, gpu)."""
    result = await rpc_call("tenzro_getTeeAttestation", {"provider": provider})
    return result


@mcp.tool
async def verify_tee_attestation_rpc(provider: str, quote_hex: str) -> dict:
    """Verify a TEE attestation quote via RPC. Returns verification result and measurements."""
    result = await rpc_call("tenzro_verifyTeeAttestation", {"provider": provider, "quote_hex": quote_hex})
    return result


@mcp.tool
async def seal_data(plaintext_hex: str, key_id: str) -> dict:
    """Seal data inside a TEE enclave using hardware-bound encryption."""
    result = await rpc_call("tenzro_sealData", {"plaintext_hex": plaintext_hex, "key_id": key_id})
    return result


@mcp.tool
async def unseal_data(ciphertext_hex: str, key_id: str) -> dict:
    """Unseal TEE-sealed data. Only works on the same hardware that sealed it."""
    result = await rpc_call("tenzro_unsealData", {"ciphertext_hex": ciphertext_hex, "key_id": key_id})
    return result


@mcp.tool
async def list_tee_providers() -> dict:
    """List registered TEE providers on the network with their attestation status."""
    result = await rpc_call("tenzro_listTeeProviders", [])
    return result


# ---------------------------------------------------------------------------
# ZK (2 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_zk_proof(circuit_id: str, witness: str) -> dict:
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
    return result


@mcp.tool
async def list_zk_circuits() -> dict:
    """List available ZK circuits (inference, settlement, identity — all Plonky3 STARKs over KoalaBear)."""
    result = await rpc_call("tenzro_listCircuits", [])
    return result


# ---------------------------------------------------------------------------
# Custody (9 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def create_mpc_wallet(threshold: int = 2, total_shares: int = 3) -> dict:
    """Create a FROST-Ed25519 (RFC 9591) threshold wallet with the specified threshold and share count.

    Pairs the FROST-Ed25519 classical leg with a mandatory ML-DSA-65 post-quantum
    signing key for hybrid signatures.
    """
    result = await rpc_call("tenzro_createMpcWallet", {"threshold": threshold, "total_shares": total_shares})
    return result


@mcp.tool
async def export_keystore(address: str, password: str) -> dict:
    """Export an encrypted keystore file (Argon2id KDF) for a wallet address."""
    result = await rpc_call("tenzro_exportKeystore", {"address": address, "password": password})
    return result


@mcp.tool
async def import_keystore(keystore_json: str, password: str) -> dict:
    """Import a wallet from an encrypted keystore file."""
    result = await rpc_call("tenzro_importKeystore", {"keystore_json": keystore_json, "password": password})
    return result


@mcp.tool
async def get_key_shares(address: str) -> dict:
    """Get the FROST-Ed25519 secret share configuration for a wallet (threshold, total, share indices)."""
    result = await rpc_call("tenzro_getKeyShares", {"address": address})
    return result


@mcp.tool
async def rotate_keys(address: str) -> dict:
    """Rotate the FROST-Ed25519 secret shares for a wallet without changing the address."""
    result = await rpc_call("tenzro_rotateKeys", {"address": address})
    return result


@mcp.tool
async def set_spending_limits(address: str, daily_limit: str, per_tx_limit: str) -> dict:
    """Set daily and per-transaction spending limits for a wallet."""
    result = await rpc_call("tenzro_setSpendingLimits", {"address": address, "daily_limit": daily_limit, "per_tx_limit": per_tx_limit})
    return result


@mcp.tool
async def get_spending_limits(address: str) -> dict:
    """Get the current spending limits and usage for a wallet."""
    result = await rpc_call("tenzro_getSpendingLimits", {"address": address})
    return result


@mcp.tool
async def authorize_session(address: str, duration_secs: int, max_amount: str) -> dict:
    """Create a time-limited session key for automated transactions."""
    result = await rpc_call("tenzro_authorizeSession", {"address": address, "duration_secs": duration_secs, "max_amount": max_amount})
    return result


@mcp.tool
async def revoke_session(address: str, session_id: str) -> dict:
    """Revoke an active session key for a wallet."""
    result = await rpc_call("tenzro_revokeSession", {"address": address, "session_id": session_id})
    return result


# ---------------------------------------------------------------------------
# App (6 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def register_app(name: str, description: str, callback_url: str = None) -> dict:
    """Register an application to use Tenzro custody and wallet services."""
    params = {"name": name, "description": description}
    if callback_url:
        params["callback_url"] = callback_url
    result = await rpc_call("tenzro_registerApp", params)
    return result


@mcp.tool
async def create_user_wallet(app_id: str, user_id: str) -> dict:
    """Create a custodial FROST-Ed25519 (RFC 9591) wallet for an app user. The app manages the key shares."""
    result = await rpc_call("tenzro_createUserWallet", {"app_id": app_id, "user_id": user_id})
    return result


@mcp.tool
async def fund_user_wallet(app_id: str, user_id: str, amount: str) -> dict:
    """Fund a user wallet from the app treasury."""
    result = await rpc_call("tenzro_fundUserWallet", {"app_id": app_id, "user_id": user_id, "amount": amount})
    return result


@mcp.tool
async def list_user_wallets(app_id: str) -> dict:
    """List all user wallets managed by an application."""
    result = await rpc_call("tenzro_listUserWallets", {"app_id": app_id})
    return result


@mcp.tool
async def sponsor_transaction(app_id: str, user_address: str, tx_data: str) -> dict:
    """Sponsor a transaction for a user (app pays gas via paymaster)."""
    result = await rpc_call("tenzro_sponsorTransaction", {"app_id": app_id, "user_address": user_address, "tx_data": tx_data})
    return result


@mcp.tool
async def get_usage_stats(app_id: str) -> dict:
    """Get usage statistics for an application (wallets, transactions, gas spent)."""
    result = await rpc_call("tenzro_getUsageStats", {"app_id": app_id})
    return result


# ---------------------------------------------------------------------------
# Contract Encoding (2 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def encode_function(abi_json: str, function_name: str, args: str) -> dict:
    """ABI-encode a smart contract function call. Returns hex-encoded calldata."""
    result = await rpc_call("tenzro_encodeFunction", {"abi_json": abi_json, "function_name": function_name, "args": args})
    return result


@mcp.tool
async def decode_result(abi_json: str, function_name: str, data_hex: str) -> dict:
    """ABI-decode the return data from a smart contract call."""
    result = await rpc_call("tenzro_decodeResult", {"abi_json": abi_json, "function_name": function_name, "data_hex": data_hex})
    return result


# ---------------------------------------------------------------------------
# Streaming (2 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def chat_stream(model: str, message: str, max_tokens: int = 1024) -> dict:
    """Send a chat completion request and stream the response token by token."""
    result = await rpc_call("tenzro_chatStream", {"model": model, "message": message, "max_tokens": max_tokens})
    return result


@mcp.tool
async def subscribe_events_stream(filter: str = "all") -> dict:
    """Subscribe to real-time blockchain events. Returns a subscription ID for streaming."""
    result = await rpc_call("tenzro_subscribeEventsStream", {"filter": filter})
    return result


# ---------------------------------------------------------------------------
# deBridge Cross-Chain (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def debridge_search_tokens(query: str, chain_id: int = None) -> dict:
    """Search for tokens available on deBridge DLN. Returns token addresses, symbols, and supported chains."""
    params = {"query": query}
    if chain_id:
        params["chain_id"] = chain_id
    result = await rpc_call("tenzro_debridgeSearchTokens", params)
    return result


@mcp.tool
async def debridge_get_chains() -> dict:
    """Get all blockchain networks supported by deBridge DLN for cross-chain transfers."""
    result = await rpc_call("tenzro_debridgeGetChains", {})
    return result


@mcp.tool
async def debridge_get_instructions() -> dict:
    """Get deBridge operational instructions and guidance for cross-chain transfers."""
    result = await rpc_call("tenzro_debridgeGetInstructions", {})
    return result


@mcp.tool
async def debridge_create_tx(
    src_chain_id: int,
    dst_chain_id: int,
    src_token: str,
    dst_token: str,
    amount: str,
    recipient: str,
    sender: str = None,
) -> dict:
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
    return result


@mcp.tool
async def debridge_same_chain_swap(
    chain_id: int,
    token_in: str,
    token_out: str,
    amount: str,
    sender: str = None,
) -> dict:
    """Execute a same-chain token swap via deBridge without cross-chain bridging."""
    params = {"chain_id": chain_id, "token_in": token_in, "token_out": token_out, "amount": amount}
    if sender:
        params["sender"] = sender
    result = await rpc_call("tenzro_debridgeSameChainSwap", params)
    return result


# ---------------------------------------------------------------------------
# Saga workflow coordination (mirrors the tenzro_workflow* RPCs / Rust MCP tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def workflow_open(
    workflow_id: str,
    orchestrator_did: str,
    saga_steps: list,
    participants: list | None = None,
) -> dict:
    """Open a multi-agent saga workflow. `saga_steps` is a list of
    {id?, executor_did?, compensation?} objects; each step runs an
    Execute -> Verify -> Compensate lifecycle with optional per-step escrow."""
    params = {
        "workflow_id": workflow_id,
        "orchestrator_did": orchestrator_did,
        "saga_steps": saga_steps,
        "participants": participants or [],
    }
    return await rpc_call("tenzro_workflowOpen", params)


@mcp.tool
async def workflow_step_execute(
    workflow_id: str,
    step_idx: int,
    proof: str | None = None,
    escrow_amount: str | None = None,
    payer: str | None = None,
    payee: str | None = None,
) -> dict:
    """Execute a saga step (Pending -> Executing). If `escrow_amount` is set,
    lock a per-step escrow (payer -> vault); `payer` and `payee` are required then."""
    params: dict = {"workflow_id": workflow_id, "step_idx": step_idx}
    if proof is not None:
        params["proof"] = proof
    if escrow_amount is not None:
        params["escrow_amount"] = escrow_amount
    if payer is not None:
        params["payer"] = payer
    if payee is not None:
        params["payee"] = payee
    return await rpc_call("tenzro_workflowStepExecute", params)


@mcp.tool
async def workflow_step_verify(
    workflow_id: str,
    step_idx: int,
    witness_signatures: list | None = None,
    outcome_score: int | None = None,
) -> dict:
    """Verify a saga step (Executing -> Verified): release any per-step escrow
    (vault -> payee) and emit ERC-8004 reputation for the step executor."""
    params: dict = {"workflow_id": workflow_id, "step_idx": step_idx}
    if witness_signatures is not None:
        params["witness_signatures"] = witness_signatures
    if outcome_score is not None:
        params["outcome_score"] = outcome_score
    return await rpc_call("tenzro_workflowStepVerify", params)


@mcp.tool
async def workflow_step_compensate(
    workflow_id: str,
    step_idx: int,
    cascade: bool = False,
) -> dict:
    """Compensate a saga step (refund vault -> payer). With cascade=True, also
    compensate every lower-index executed/verified step in reverse order."""
    return await rpc_call(
        "tenzro_workflowStepCompensate",
        {"workflow_id": workflow_id, "step_idx": step_idx, "cascade": cascade},
    )


@mcp.tool
async def workflow_finalize(workflow_id: str) -> dict:
    """Finalize a saga once all steps are Verified: compute the receipt hash and
    mark the workflow Completed."""
    return await rpc_call("tenzro_workflowFinalize", {"workflow_id": workflow_id})


@mcp.tool
async def get_workflow_saga(workflow_id: str) -> dict:
    """Read a saga workflow's current state (steps, statuses, escrows, receipt)."""
    return await rpc_call("tenzro_getWorkflowSaga", {"workflow_id": workflow_id})


# ---------------------------------------------------------------------------
# DID envelope verification
# ---------------------------------------------------------------------------


@mcp.tool
async def verify_did_envelope(envelope: str) -> dict:
    """Verify a Tenzro DID envelope passed as a hex header value (the
    X-Tenzro-DID-Envelope value). Supports did:tenzro (registry), did:key,
    did:ethr (recoverable secp256k1), and did:web (resolved over HTTPS).
    Returns {valid, did, method} or {valid: false, error}."""
    return await rpc_call("tenzro_verifyDidEnvelope", {"envelope": envelope})


# ---------------------------------------------------------------------------
# Capital Intent standard (agentic capital allocation over tokenized assets)
# ---------------------------------------------------------------------------


@mcp.tool
async def capital_intent_open(intent: dict) -> dict:
    """Open a signed Capital Intent — regulated capital allocation over
    tokenized assets (the capital-markets analog of an AP2 Intent Mandate).
    `intent` matches the CapitalIntent schema: objective (acquire/exit/
    rebalance/hedge/yield), constraints, compliance (reg_regime, min_kyc_tier),
    authorization (ceilings), settlement."""
    return await rpc_call("tenzro_capitalIntentOpen", {"intent": intent})


@mcp.tool
async def capital_intent_quote(
    intent_id: str, solver_did: str, plan: str = "", price: int = 0, eta_secs: int = 0
) -> dict:
    """Solver bid to fulfil a capital intent (ranked by ERC-8004 + KYA)."""
    return await rpc_call("tenzro_capitalIntentQuote", {
        "intent_id": intent_id, "solver_did": solver_did,
        "plan": plan, "price": price, "eta_secs": eta_secs,
    })


@mcp.tool
async def capital_intent_assign(
    intent_id: str, solver_did: str | None = None, auto: bool = False,
    payer: str | None = None, payee: str | None = None
) -> dict:
    """Assign a solver. Omit solver_did or pass auto=True to auto-rank received
    quotes by ERC-8004 reputation, then lowest price, then fastest eta. If payer
    given, lock principal escrow up to the ceiling."""
    params: dict = {"intent_id": intent_id}
    if solver_did is not None:
        params["solver_did"] = solver_did
    if auto:
        params["auto"] = True
    if payer is not None:
        params["payer"] = payer
    if payee is not None:
        params["payee"] = payee
    return await rpc_call("tenzro_capitalIntentAssign", params)


@mcp.tool
async def capital_intent_execute(intent_id: str, leg: dict) -> dict:
    """Record one executed settlement leg ({venue, asset_id, side, quantity,
    unit_price, settlement_ref?, proof?})."""
    return await rpc_call("tenzro_capitalIntentExecute", {"intent_id": intent_id, "leg": leg})


@mcp.tool
async def capital_intent_verify(intent_id: str) -> dict:
    """Verify proofs / require all legs settled."""
    return await rpc_call("tenzro_capitalIntentVerify", {"intent_id": intent_id})


@mcp.tool
async def capital_intent_settle(intent_id: str, payee: str | None = None) -> dict:
    """Release escrow to the solver, write ERC-8004 feedback, finalize."""
    params: dict = {"intent_id": intent_id}
    if payee is not None:
        params["payee"] = payee
    return await rpc_call("tenzro_capitalIntentSettle", params)


@mcp.tool
async def capital_intent_compensate(intent_id: str) -> dict:
    """Refund the principal escrow and fail the intent (saga compensation)."""
    return await rpc_call("tenzro_capitalIntentCompensate", {"intent_id": intent_id})


@mcp.tool
async def get_capital_intent(intent_id: str) -> dict:
    """Read a capital intent record (status, quotes, legs, escrow, receipt)."""
    return await rpc_call("tenzro_getCapitalIntent", {"intent_id": intent_id})


# ---------------------------------------------------------------------------
# Proof-of-Reserve + attested-mint (1:1 backing invariant)
# ---------------------------------------------------------------------------


@mcp.tool
async def submit_reserve_attestation(attestation: dict) -> dict:
    """Record a signed reserve attestation backing a tokenized asset (PoR):
    {asset_id, reserves, source(issuer|tee|chainlink_por|oracle), attestor_did,
    attested_at, signature?}. Consumed by attested-mint to enforce 1:1 backing."""
    return await rpc_call("tenzro_submitReserveAttestation", {"attestation": attestation})


@mcp.tool
async def attested_mint(token_id: str, to: str, amount: int, caller: str) -> dict:
    """Mint a tokenized asset ONLY if post-mint supply <= attested reserves
    (1:1 backing as a protocol invariant). Rejects if no reserve attestation or
    if reserves are insufficient."""
    return await rpc_call("tenzro_attestedMint", {
        "token_id": token_id, "to": to, "amount": amount, "caller": caller,
    })


@mcp.tool
async def get_reserve(asset_id: str) -> dict:
    """Read the current reserve attestation for a tokenized asset."""
    return await rpc_call("tenzro_getReserve", {"asset_id": asset_id})


# ---------------------------------------------------------------------------
# EIP-7702 (Set EOA Account Code) helpers
# ---------------------------------------------------------------------------


@mcp.tool
async def eip7702_signing_hash(
    chain_id: int, delegate_address: str, nonce: int
) -> dict:
    """Compute the secp256k1 signing hash for an EIP-7702 authorization
    tuple `(chain_id, delegate_address, nonce)`. Sign client-side with
    the EOA's secp256k1 key."""
    return await rpc_call(
        "tenzro_eip7702SigningHash",
        {"chain_id": chain_id, "delegate_address": delegate_address, "nonce": nonce},
    )


@mcp.tool
async def eip7702_build_designator(delegate_address: str) -> dict:
    """Build the 23-byte EIP-7702 designator
    (`0xef0100 || delegate_address`)."""
    return await rpc_call(
        "tenzro_eip7702BuildDesignator", {"delegate_address": delegate_address}
    )


@mcp.tool
async def eip7702_parse_designator(code: str) -> dict:
    """Decode account code and extract the delegate address if it's
    a valid EIP-7702 designator."""
    return await rpc_call("tenzro_eip7702ParseDesignator", {"code": code})


@mcp.tool
async def eip7702_protocol_info() -> dict:
    """Read static metadata about the EIP-7702 support surface."""
    return await rpc_call("tenzro_eip7702ProtocolInfo", {})


# ---------------------------------------------------------------------------
# Permit2 SignatureTransfer
# ---------------------------------------------------------------------------


@mcp.tool
async def permit2_domain_separator(chain_id: int) -> dict:
    """Read the per-chain Permit2 EIP-712 domain separator."""
    return await rpc_call("tenzro_permit2DomainSeparator", {"chain_id": chain_id})


@mcp.tool
async def permit2_digest(
    chain_id: int,
    owner: str,
    token: str,
    amount: str,
    spender: str,
    nonce: str,
    deadline: int,
    witness: str | None = None,
    witness_type_string: str | None = None,
) -> dict:
    """Compute the EIP-712 digest a user signs for a Permit2
    SignatureTransfer (with optional witness binding for ERC-7683)."""
    params = {
        "chain_id": chain_id,
        "owner": owner,
        "token": token,
        "amount": amount,
        "spender": spender,
        "nonce": nonce,
        "deadline": deadline,
    }
    if witness:
        params["witness"] = witness
    if witness_type_string:
        params["witness_type_string"] = witness_type_string
    return await rpc_call("tenzro_permit2Digest", params)


@mcp.tool
async def permit2_verify_and_consume(
    chain_id: int,
    owner: str,
    token: str,
    amount: str,
    spender: str,
    nonce: str,
    deadline: int,
    signature: str,
    witness: str | None = None,
    witness_type_string: str | None = None,
) -> dict:
    """Atomically verify a signed Permit2 message and consume the
    (owner, nonce) slot."""
    params = {
        "chain_id": chain_id,
        "owner": owner,
        "token": token,
        "amount": amount,
        "spender": spender,
        "nonce": nonce,
        "deadline": deadline,
        "signature": signature,
    }
    if witness:
        params["witness"] = witness
    if witness_type_string:
        params["witness_type_string"] = witness_type_string
    return await rpc_call("tenzro_permit2VerifyAndConsume", params)


@mcp.tool
async def permit2_nonce_used(owner: str, nonce: str) -> dict:
    """Check whether a (owner, nonce) slot has been consumed."""
    return await rpc_call("tenzro_permit2NonceUsed", {"owner": owner, "nonce": nonce})


# ---------------------------------------------------------------------------
# Secure-Mint Registry — 1:1 reserve-attestation invariant for tokenized RWAs
# ---------------------------------------------------------------------------


@mcp.tool
async def set_secure_mint_policy(
    asset_id: str,
    reserve: str,
    por_feed_id: str,
    attester_did: str,
    attestation_hash: str,
    attested_at: int,
    ttl_secs: int,
    circulating: str | None = None,
) -> dict:
    """Set or update a Secure-Mint policy. Enforces
    `circulating + amount <= reserve` at every mint."""
    params = {
        "asset_id": asset_id,
        "reserve": reserve,
        "por_feed_id": por_feed_id,
        "attester_did": attester_did,
        "attestation_hash": attestation_hash,
        "attested_at": attested_at,
        "ttl_secs": ttl_secs,
    }
    if circulating is not None:
        params["circulating"] = circulating
    return await rpc_call("tenzro_setSecureMintPolicy", params)


@mcp.tool
async def get_secure_mint_policy(asset_id: str) -> dict:
    """Read the Secure-Mint policy for an asset."""
    return await rpc_call("tenzro_getSecureMintPolicy", {"asset_id": asset_id})


@mcp.tool
async def clear_secure_mint_policy(asset_id: str) -> dict:
    """Clear the Secure-Mint policy for an asset."""
    return await rpc_call("tenzro_clearSecureMintPolicy", {"asset_id": asset_id})


@mcp.tool
async def secure_mint_check(asset_id: str, amount: str) -> dict:
    """Read-only invariant check for a proposed mint."""
    return await rpc_call(
        "tenzro_secureMintCheck", {"asset_id": asset_id, "amount": amount}
    )


@mcp.tool
async def secure_mint_apply(asset_id: str, amount: str) -> dict:
    """Atomic check + circulating increment."""
    return await rpc_call(
        "tenzro_secureMintApply", {"asset_id": asset_id, "amount": amount}
    )


@mcp.tool
async def secure_mint_record_burn(asset_id: str, amount: str) -> dict:
    """Record a redemption (decrement circulating)."""
    return await rpc_call(
        "tenzro_secureMintRecordBurn", {"asset_id": asset_id, "amount": amount}
    )


# ---------------------------------------------------------------------------
# Hyperlane V3 (sovereign Tenzro-validator-set ISM)
# ---------------------------------------------------------------------------


@mcp.tool
async def hyperlane_list_chains() -> dict:
    """List supported Hyperlane chains and their canonical domain ids."""
    return await rpc_call("tenzro_hyperlaneListChains", {})


@mcp.tool
async def hyperlane_quote_dispatch(
    origin_domain: int,
    destination_domain: int,
    recipient: str,
    body_hex: str,
    sender: str | None = None,
    interchain_gas_payment: str | None = None,
) -> dict:
    """Quote the interchain gas payment for a dispatch."""
    params = {
        "origin_domain": origin_domain,
        "destination_domain": destination_domain,
        "recipient": recipient,
        "body_hex": body_hex,
    }
    if sender:
        params["sender"] = sender
    if interchain_gas_payment:
        params["interchain_gas_payment"] = interchain_gas_payment
    return await rpc_call("tenzro_hyperlaneQuoteDispatch", params)


@mcp.tool
async def hyperlane_dispatch(
    origin_domain: int,
    destination_domain: int,
    recipient: str,
    body_hex: str,
    sender: str | None = None,
    interchain_gas_payment: str | None = None,
) -> dict:
    """Dispatch a Hyperlane V3 message through the canonical Mailbox."""
    params = {
        "origin_domain": origin_domain,
        "destination_domain": destination_domain,
        "recipient": recipient,
        "body_hex": body_hex,
    }
    if sender:
        params["sender"] = sender
    if interchain_gas_payment:
        params["interchain_gas_payment"] = interchain_gas_payment
    return await rpc_call("tenzro_hyperlaneDispatch", params)


@mcp.tool
async def hyperlane_get_message(message_id: str) -> dict:
    """Look up a Hyperlane message by id."""
    return await rpc_call("tenzro_hyperlaneGetMessage", {"message_id": message_id})


# ---------------------------------------------------------------------------
# Axelar GMP — Cosmos / Move / Stellar / XRPL reach
# ---------------------------------------------------------------------------


@mcp.tool
async def axelar_list_chains() -> dict:
    """List supported Axelar chains."""
    return await rpc_call("tenzro_axelarListChains", {})


@mcp.tool
async def axelar_call_contract(
    source_chain: str,
    destination_chain: str,
    destination_address: str,
    payload_hex: str,
    gas_token: str | None = None,
    gas_amount: str | None = None,
) -> dict:
    """Dispatch an Axelar GMP `call_contract` message."""
    params = {
        "source_chain": source_chain,
        "destination_chain": destination_chain,
        "destination_address": destination_address,
        "payload_hex": payload_hex,
    }
    if gas_token:
        params["gas_token"] = gas_token
    if gas_amount:
        params["gas_amount"] = gas_amount
    return await rpc_call("tenzro_axelarCallContract", params)


@mcp.tool
async def axelar_pay_gas(
    payload_hash: str,
    source_chain: str,
    destination_chain: str,
    destination_address: str,
    gas_token: str,
    gas_amount: str,
) -> dict:
    """Pre-pay the Axelar Gas Service for a previously-dispatched message."""
    return await rpc_call(
        "tenzro_axelarPayGas",
        {
            "payload_hash": payload_hash,
            "source_chain": source_chain,
            "destination_chain": destination_chain,
            "destination_address": destination_address,
            "gas_token": gas_token,
            "gas_amount": gas_amount,
        },
    )


@mcp.tool
async def axelar_get_message(payload_hash: str) -> dict:
    """Look up an Axelar GMP message by payload hash."""
    return await rpc_call(
        "tenzro_axelarGetMessage", {"payload_hash": payload_hash}
    )


# ---------------------------------------------------------------------------
# Babylon Bitcoin Staking
# ---------------------------------------------------------------------------


@mcp.tool
async def babylon_register_finality_provider(
    validator: str, btc_pk: str, commission_bps: int
) -> dict:
    """Register a Tenzro validator as a Babylon finality provider."""
    return await rpc_call(
        "tenzro_babylonRegisterFinalityProvider",
        {
            "validator": validator,
            "btc_pk": btc_pk,
            "commission_bps": commission_bps,
        },
    )


@mcp.tool
async def babylon_get_finality_provider(validator: str) -> dict:
    """Read the Babylon finality-provider record for a Tenzro validator."""
    return await rpc_call(
        "tenzro_babylonGetFinalityProvider", {"validator": validator}
    )


@mcp.tool
async def babylon_list_finality_providers() -> dict:
    """List every registered Babylon finality provider."""
    return await rpc_call("tenzro_babylonListFinalityProviders", {})


@mcp.tool
async def babylon_total_stake_for_provider(validator: str) -> dict:
    """Sum BTC delegations for a finality provider."""
    return await rpc_call(
        "tenzro_babylonTotalStakeForProvider", {"validator": validator}
    )


@mcp.tool
async def babylon_submit_finality_signature(
    validator: str, block_hash: str, eots_signature: str
) -> dict:
    """Submit an EOTS over a Tenzro block hash."""
    return await rpc_call(
        "tenzro_babylonSubmitFinalitySignature",
        {
            "validator": validator,
            "block_hash": block_hash,
            "eots_signature": eots_signature,
        },
    )


@mcp.tool
async def babylon_list_delegations(validator: str) -> dict:
    """List BTC delegations for a finality provider."""
    return await rpc_call(
        "tenzro_babylonListDelegations", {"validator": validator}
    )


# ---------------------------------------------------------------------------
# CAIP discovery (ChainAgnostic/namespaces#184)
# ---------------------------------------------------------------------------


@mcp.tool
async def caip2() -> dict:
    """Get the CAIP-2 chain id for this node:
    `tenzro:<lowercase hex of the first 16 bytes of the genesis block
    hash>`. Returns `{chain_id, namespace, reference, evm_chain_id}`."""
    return await rpc_call("tenzro_caip2", {})


@mcp.tool
async def caip10(address: str) -> dict:
    """Get the CAIP-10 account id. Accepts hex or base58btc;
    normalises to canonical 64-hex."""
    return await rpc_call("tenzro_caip10", {"address": address})


@mcp.tool
async def caip19(
    kind: str,
    token_id: str | None = None,
    collection_id: str | None = None,
    nft_token_id: str | None = None,
) -> dict:
    """Get the CAIP-19 asset id. `kind` is one of `slip44` /
    `token` / `nft` per the submitted `tenzro` CAIP namespace."""
    params = {"kind": kind}
    if token_id:
        params["token_id"] = token_id
    if collection_id:
        params["collection_id"] = collection_id
    if nft_token_id:
        params["nft_token_id"] = nft_token_id
    return await rpc_call("tenzro_caip19", params)


# ---------------------------------------------------------------------------
# Canton / DAML (15 tools — Canton 3.5+ JSON Ledger API)
# ---------------------------------------------------------------------------


@mcp.tool
async def canton_list_domains() -> dict:
    """List the Canton synchronizer domains this node is configured against."""
    return await rpc_call("tenzro_listCantonDomains", {})


@mcp.tool
async def canton_list_contracts(
    template_ids: list[str],
    query: dict | None = None,
) -> dict:
    """Query active DAML contracts. `template_ids` must contain at least one
    template id (Canton 3.5+ rejects empty filter sets). Optional `query`
    applies a structural filter against `createArguments` client-side."""
    params: dict = {"template_ids": template_ids}
    if query is not None:
        params["query"] = query
    return await rpc_call("tenzro_listDamlContracts", params)


@mcp.tool
async def canton_submit_command(
    command_type: str,
    template_id: str,
    arguments: dict | None = None,
    contract_id: str | None = None,
    choice: str | None = None,
    choice_argument: dict | None = None,
) -> dict:
    """Submit a DAML create or exercise command."""
    params: dict = {
        "command_type": command_type,
        "template_id": template_id,
    }
    if arguments is not None:
        params["arguments"] = arguments
    if contract_id is not None:
        params["contract_id"] = contract_id
    if choice is not None:
        params["choice"] = choice
    if choice_argument is not None:
        params["choice_argument"] = choice_argument
    return await rpc_call("tenzro_submitDamlCommand", params)


@mcp.tool
async def canton_upload_dar(dar_content_base64: str) -> dict:
    """Upload a DAR (DAML Archive) to the participant via POST /v2/packages
    (Canton 3.5+ JSON Ledger API). `dar_content_base64` is base64-encoded
    DAR file bytes. Returns Canton's structured response — typically the
    list of package ids that got installed."""
    return await rpc_call(
        "tenzro_canton_uploadDar", {"dar_content_base64": dar_content_base64}
    )


@mcp.tool
async def canton_list_parties() -> dict:
    """List every party known to the participant via GET /v2/parties/known.
    Note: on the Tenzro DevNet the `daml_ledger_api` scope may not grant
    read access to the party registry; expect `{partyDetails: []}` in
    that case."""
    return await rpc_call("tenzro_canton_listParties", {})


@mcp.tool
async def canton_health() -> dict:
    """Combined health probe — `/livez`, `/readyz`, `/v2/version`. Returns
    `{alive, ready, ready_detail, version}` where `version` carries
    Canton CIP feature flags when reachable."""
    return await rpc_call("tenzro_canton_health", {})


@mcp.tool
async def canton_version() -> dict:
    """Returns participant version + CIP feature flags via GET /v2/version
    (Canton 3.5+)."""
    return await rpc_call("tenzro_canton_version", {})


@mcp.tool
async def canton_get_transaction(update_id: str) -> dict:
    """Fetch a Canton transaction tree by update id. The update id must
    be a hex string (Canton 3.5+ rejects bare labels)."""
    return await rpc_call(
        "tenzro_canton_getTransaction", {"update_id": update_id}
    )


@mcp.tool
async def canton_list_packages() -> dict:
    """List every DAML package installed on the participant via
    GET /v2/packages. Returns `{packageIds: [<hex>...]}`. Useful for
    capability discovery before contract creation."""
    return await rpc_call("tenzro_canton_listPackages", {})


@mcp.tool
async def canton_coin_balance() -> dict:
    """Returns the Canton Coin (CIP-56) balance for the participant's
    party by summing every `Splice.Amulet:Amulet` contract the party
    is a stakeholder on. Returns `{party, amulet_count,
    total_initial_amount, token_standard:"CIP-56"}`."""
    return await rpc_call("tenzro_canton_coinBalance", {})


@mcp.tool
async def canton_fee_schedule() -> dict:
    """Returns the participant's Canton fee schedule sourced from the
    latest `Splice.AmuletRules:AmuletRules` contract."""
    return await rpc_call("tenzro_canton_feeSchedule", {})


@mcp.tool
async def canton_connected_synchronizers() -> dict:
    """Returns the synchronizers the participant's party is currently
    connected to via GET /v2/state/connected-synchronizers. Each entry
    includes `synchronizerAlias`, `synchronizerId`, and `permission`
    (SUBMISSION / CONFIRMATION / OBSERVATION). `reconnect()`-style
    synchronizer subscription management is a Canton Admin Console gRPC
    operation that the JSON Ledger API does not expose."""
    return await rpc_call("tenzro_canton_connectedSynchronizers", {})


@mcp.tool
async def canton_get_my_user() -> dict:
    """Returns the OAuth principal's Canton user record via
    GET /v2/users/<client_id>@clients (CIP-26 User Management).
    The Tenzro node derives the user id from its OAuth client id;
    Canton 3.5.1 has no /users/me alias (returns 404 USER_NOT_FOUND).
    Returns `{user: {id, primaryParty, isDeactivated, metadata,
    identityProviderId}}`."""
    return await rpc_call("tenzro_canton_getMyUser", {})


@mcp.tool
async def canton_allocate_party(
    party_id_hint: str, display_name: str | None = None
) -> dict:
    """Allocate a new party on the participant via POST /v2/parties.
    Returns `{party_id, party_id_hint}` where `party_id` is the
    fully-qualified `<hint>::<participant-hash>` form. The newly
    allocated party has no `CanActAs` / `CanReadAs` grants on any
    user by default — follow up with `canton_grant_user_rights` so
    the operator's OAuth user can submit DAML commands on its
    behalf."""
    params: dict = {"party_id_hint": party_id_hint}
    if display_name is not None:
        params["display_name"] = display_name
    return await rpc_call("tenzro_allocateParty", params)


@mcp.tool
async def canton_grant_user_rights(
    party: str,
    user_id: str | None = None,
    can_act_as: bool = True,
    can_read_as: bool = False,
) -> dict:
    """Grant `CanActAs` / `CanReadAs` rights on a Canton party to
    a user (Canton 3.5+ User Management Service via
    POST /v2/users/{userId}/rights). Without these grants the
    operator's OAuth user cannot submit DAML commands as the party
    even if the party exists.

    `party` must be the fully-qualified party id
    `<hint>::<participant-hash>`. Pass `user_id=None` to grant to
    the OAuth principal's own user id (`<client_id>@clients`).
    Returns `{newlyGrantedRights: [...]}`."""
    return await rpc_call(
        "tenzro_canton_grantUserRights",
        {
            "user_id": user_id,
            "party": party,
            "can_act_as": can_act_as,
            "can_read_as": can_read_as,
        },
    )


@mcp.tool
async def canton_list_user_rights(user_id: str | None = None) -> dict:
    """List the rights granted to a Canton user via
    GET /v2/users/{userId}/rights. Returns
    `{rights: [{kind: {CanActAs: {value: {party}}}}, ...]}`.
    Pass `user_id=None` to list rights for the OAuth principal's
    own user."""
    params: dict = {}
    if user_id is not None:
        params["user_id"] = user_id
    return await rpc_call("tenzro_canton_listUserRights", params)


@mcp.tool
async def canton_get_my_analytics() -> dict:
    """Subject self-read: returns this tenant's Canton call
    aggregates for the API key configured on this MCP client.

    Counters are maintained server-side in RocksDB
    (`CF_CANTON_ANALYTICS`) — every canton-scoped JSON-RPC call
    increments `calls_total` (or `errors_total`) plus the
    corresponding per-method bucket. Lets a tenant answer
    "how many DAML transactions have I submitted, and which
    methods am I hitting?" without operator help.

    Returns
    `{key_id, canton_user_id, calls_total, errors_total,
    calls_by_method, errors_by_method, first_seen_at,
    last_called_at}`.
    """
    return await rpc_call("tenzro_canton_getMyAnalytics", {})


@mcp.tool
async def canton_list_api_key_analytics(key_id: str | None = None) -> dict:
    """Operator admin-read: returns per-tenant Canton call
    aggregates for every API key (or just one when `key_id` is
    set). Requires the operator admin token at the node level.

    Rows are sorted by `last_called_at` descending. Returns
    `{analytics: [...]}` where each row matches the shape
    documented on `canton_get_my_analytics`.
    """
    params: dict = {}
    if key_id is not None:
        params["key_id"] = key_id
    return await rpc_call("tenzro_canton_listApiKeyAnalytics", params)


# ---------------------------------------------------------------------------
# Wave 7/9/12 — institutional primitives: uRWA / IVMS101 / attested
# clock / SignedAgentCard / Wormhole NTT / bridge-fee-in-TNZO
# ---------------------------------------------------------------------------


@mcp.tool
async def urwa_is_kill_switched(token_id_hex: str) -> dict:
    """Read the ERC-7943 (uRWA) kill-switch state for a 32-byte token id.

    Returns ``{token_id_hex, active, selectors, precompile_addresses}``.
    When ``active`` is ``True`` every transfer of the token reverts at
    the EVM transfer hook until the operator clears the switch via the
    admin-gated ``tenzro_urwaClearKillSwitch`` RPC.
    """
    return await rpc_call("tenzro_urwaIsKillSwitched", {"token_id_hex": token_id_hex})


@mcp.tool
async def urwa_get_frozen_tokens(token_id_hex: str, account_hex: str) -> dict:
    """Read the ERC-7943 frozen-amount for a (token, account) pair.

    Returns the frozen amount in the token smallest unit. The
    transferable balance equals ``balance - frozen_amount``; transfers
    that would push the post-debit balance below zero revert.
    """
    return await rpc_call(
        "tenzro_urwaGetFrozenTokens",
        {"token_id_hex": token_id_hex, "account_hex": account_hex},
    )


@mcp.tool
async def urwa_set_frozen_tokens(
    token_id_hex: str,
    account_hex: str,
    amount: str,
    reason: str | None = None,
) -> dict:
    """(Admin) Freeze a specific amount on an ERC-7943 token account.

    The transferable balance becomes ``balance - amount``. Optional
    ``reason`` is recorded for audit. Requires the
    ``X-Tenzro-Admin-Token`` header on the underlying RPC client.
    """
    return await rpc_call(
        "tenzro_urwaSetFrozenTokens",
        {
            "token_id_hex": token_id_hex,
            "account_hex": account_hex,
            "amount": amount,
            "reason": reason,
        },
    )


@mcp.tool
async def urwa_trigger_kill_switch(
    token_id_hex: str,
    triggered_by_did: str | None = None,
    reason: str | None = None,
) -> dict:
    """(Admin) Activate the ERC-7943 kill-switch on a token.

    All transfers of the token revert until ``urwa_clear_kill_switch``
    is called. The ``triggered_by_did`` and ``reason`` fields are
    persisted to the audit log.
    """
    return await rpc_call(
        "tenzro_urwaTriggerKillSwitch",
        {
            "token_id_hex": token_id_hex,
            "triggered_by_did": triggered_by_did,
            "reason": reason,
        },
    )


@mcp.tool
async def urwa_clear_kill_switch(token_id_hex: str) -> dict:
    """(Admin) Clear the ERC-7943 kill-switch on a token. Transfers resume."""
    return await rpc_call(
        "tenzro_urwaClearKillSwitch", {"token_id_hex": token_id_hex}
    )


@mcp.tool
async def ivms101_canonical_hash(envelope: dict) -> dict:
    """Compute the canonical SHA-256 binding hash for an IVMS101 Travel Rule envelope.

    The envelope carries ``originator + beneficiary + originating_vasp +
    beneficiary_vasp + transfer`` records per the FATF JSON schema. The
    returned hash anchors a settlement receipt to a specific
    originator/beneficiary/VASP/transfer-data record — auditors trace
    receipt → IVMS101 envelope → VASP DIDs end-to-end without PII
    landing on-chain (the envelope itself stays off-chain, typically
    carried via TRP).
    """
    return await rpc_call("tenzro_ivms101Hash", envelope)


@mcp.tool
async def attested_clock_now() -> dict:
    """Return the current node wall-clock as a Tenzro AttestedTimestamp envelope.

    Carries ``wall_ms``, ``monotonic_ns``, and ``tee_vendor`` metadata.
    Used by long-running multi-party workflows that cannot trust any
    single replica's wall-clock — DvP settlement deadlines, AP2 mandate
    expiry, margin-call grace periods, parametric-insurance trigger
    windows. When the node is not running inside a TEE the envelope is
    unsigned (``tee_vendor`` is ``null``) and relying parties MUST
    reject it for production mandate / deadline use.
    """
    return await rpc_call("tenzro_attestedClockNow", [])


@mcp.tool
async def signed_agent_card_canonical_hash(agent_card: dict) -> dict:
    """Compute the canonical hash for an A2A v1.0 SignedAgentCard payload.

    Domain owners hash + JWS-sign the agent card; relying parties
    re-verify the canonical hash to detect a hostile reverse-proxy or
    intermediate-cache rewrite of ``url`` / ``skills`` /
    ``securitySchemes``. Production-grade A2A 2026 conformance bar.
    """
    return await rpc_call("tenzro_signedAgentCardCanonicalHash", agent_card)


@mcp.tool
async def wormhole_ntt_list_chains() -> dict:
    """Enumerate the registered Wormhole NTT chain catalog.

    Returns ``{chains, transceiver_kinds, scaffolding}``. NTT is
    Wormhole's 2026 multi-chain native-token primitive — instead of
    wrapped tokens locked at a vault, an ``NttManager`` mints / burns
    the native token directly on each chain with quorum-aggregated
    Transceiver attestation (Wormhole / Axelar / LayerZero / custom).
    """
    return await rpc_call("tenzro_wormholeNttListChains", [])


@mcp.tool
async def quote_bridge_fee_in_tnzo(
    adapter: str,
    dest_chain: str,
    native_fee_smallest_unit: str,
) -> dict:
    """Quote a destination-native bridge fee in TNZO.

    ``adapter`` is one of ``layerzero | ccip | wormhole | debridge |
    hyperlane | axelar | lifi | canton``; ``dest_chain`` is a CAIP-2
    identifier (e.g. ``eip155:1``). Returns the canonical
    ``BridgeFeeQuote`` envelope including the TNZO debit due, spot rate
    at quote time, TTL window, and backing oracle
    (``chainlink_feed | governance | fallback``).
    """
    return await rpc_call(
        "tenzro_quoteBridgeFeeInTnzo",
        {
            "adapter": adapter,
            "dest_chain": dest_chain,
            "native_fee_smallest_unit": native_fee_smallest_unit,
        },
    )


@mcp.tool
async def list_bridge_sponsorship_pools() -> dict:
    """Enumerate per-adapter bridge sponsorship-pool vault addresses.

    Vault addresses are deterministic ``SHA-256("tenzro/bridge/
    sponsorship-vault" || adapter)[..20]`` — same on every Tenzro node,
    survives restarts. Returns ``{pools, total}`` for all 8 registered
    adapters (layerzero / ccip / wormhole / debridge / hyperlane /
    axelar / lifi / canton).
    """
    return await rpc_call("tenzro_listBridgeSponsorshipPools", [])


@mcp.tool
async def set_bridge_fee_rate(
    adapter: str,
    dest_chain: str,
    rate_q18: str,
    markup_bps: int = 100,
    valid_window_ms: int = 60_000,
) -> dict:
    """(Operator admin-token-gated) Register a governance-set rate row.

    ``rate_q18`` is the Q18 fixed-point destination-native-to-TNZO rate
    (e.g. ``"2000000000000000000"`` for 2.0). ``markup_bps`` applies
    on top of the spot rate. ``valid_window_ms`` is the live-quote TTL.
    Requires ``X-Tenzro-Admin-Token``.
    """
    return await rpc_call(
        "tenzro_setBridgeFeeRate",
        [{
            "adapter": adapter,
            "dest_chain": dest_chain,
            "rate_q18": rate_q18,
            "markup_bps": markup_bps,
            "valid_window_ms": valid_window_ms,
        }],
    )


@mcp.tool
async def sponsor_bridge_fee(
    quote_id_hex: str,
    adapter: str,
    dest_chain: str,
    native_fee_smallest_unit: str,
    tnzo_amount_wei: str,
    rate_q18_hex: str,
    issued_at_ms: int,
    valid_until_ms: int,
    payer_did: str,
    oracle_backing: str = "governance",
) -> dict:
    """Sponsor a previously-quoted destination-native bridge fee in TNZO.

    Debits the ``payer_did`` for ``tnzo_amount_wei`` and credits the
    per-adapter sponsorship pool with ``native_fee_smallest_unit`` of
    outstanding native-fee commitment. Returns the
    ``BridgeSponsorshipReceipt`` envelope. Requires an API key with
    ``chainlink`` scope.
    """
    return await rpc_call(
        "tenzro_sponsorBridgeFee",
        [{
            "quote_id_hex": quote_id_hex,
            "adapter": adapter,
            "dest_chain": dest_chain,
            "native_fee_smallest_unit": native_fee_smallest_unit,
            "tnzo_amount_wei": tnzo_amount_wei,
            "rate_q18_hex": rate_q18_hex,
            "issued_at_ms": issued_at_ms,
            "valid_until_ms": valid_until_ms,
            "oracle_backing": oracle_backing,
            "payer_did": payer_did,
        }],
    )


@mcp.tool
async def set_sponsorship_refill_threshold(
    adapter: str,
    refill_threshold_bps: int,
) -> dict:
    """(Operator admin-token-gated) Set per-adapter pool refill threshold.

    When the pool's TNZO balance drops below ``refill_threshold_bps`` of
    expected daily outflow, the network treasury auto-rebalances.
    ``0`` disables auto-refill. Requires ``X-Tenzro-Admin-Token``.
    """
    return await rpc_call(
        "tenzro_setSponsorshipRefillThreshold",
        [{"adapter": adapter, "refill_threshold_bps": refill_threshold_bps}],
    )


@mcp.tool
async def get_bridge_analytics() -> dict:
    """Subject self-read of the caller's own Chainlink/bridge analytics.

    Returns CU consumption (Alchemy-style Compute Units), per-method
    counters, error counts, and rate-limit rejections for the API key
    presented as ``X-Tenzro-Api-Key`` with ``chainlink`` scope.
    """
    return await rpc_call("tenzro_getBridgeAnalytics", [])


@mcp.tool
async def list_bridge_analytics(key_id: str | None = None) -> dict:
    """(Operator admin-token-gated) Cross-tenant Chainlink/bridge analytics.

    Returns every per-tenant Chainlink/bridge aggregate (CU consumption,
    call counts, error counts, rate-limit rejections). Optional
    ``key_id`` filter narrows the result to a single tenant. Requires
    ``X-Tenzro-Admin-Token``.
    """
    params = {"key_id": key_id} if key_id else None
    return await rpc_call("tenzro_listBridgeAnalytics", params)


@mcp.tool
async def workflow_set_step_deadline(
    workflow_id: str,
    step_idx: int,
    attested_deadline: dict,
) -> dict:
    """Bind a TEE-attested deadline to a saga step.

    After the deadline passes (with 30s tolerance per Canton 3.5
    timestamp-drift guidance) ``tenzro_workflowStepExecute`` refuses
    the transition and the caller MUST
    ``tenzro_workflowStepCompensate``. The monotonic counter on the
    deadline binds it to a specific enclave instance so a relayer
    cannot backdate via wall-clock manipulation. Only applies to
    steps in ``Pending`` status.
    """
    return await rpc_call(
        "tenzro_workflowSetStepDeadline",
        {
            "workflow_id": workflow_id,
            "step_idx": step_idx,
            "attested_deadline": attested_deadline,
        },
    )


# ---------------------------------------------------------------------------
# Storage Market (6 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def storage_store_object(
    object_id: str,
    data: str,
    owner: str = "",
    data_shards: int = 4,
    parity_shards: int = 2,
) -> dict:
    """Store an object on this node's storage provider with erasure coding.

    `data` is the base64-encoded payload. `data_shards`/`parity_shards`
    set the Reed-Solomon redundancy scheme.
    """
    params = {
        "object_id": object_id,
        "data": data,
        "data_shards": data_shards,
        "parity_shards": parity_shards,
    }
    if owner:
        params["owner"] = owner
    return await rpc_call("tenzro_storageStoreObject", params)


@mcp.tool
async def storage_open_deal(
    object_id: str,
    renter: str,
    size_bytes: int,
    total_epochs: int,
) -> dict:
    """Open a streaming storage deal for a stored object.

    `renter` is a hex address that pre-funds from its deposit; the
    per-epoch price is `size_bytes` times the byte-epoch rate.
    """
    return await rpc_call(
        "tenzro_storageOpenDeal",
        {
            "object_id": object_id,
            "renter": renter,
            "size_bytes": size_bytes,
            "total_epochs": total_epochs,
        },
    )


@mcp.tool
async def storage_charge_epoch(deal_id: str) -> dict:
    """Run one proof-of-retrievability-gated charge epoch for a storage deal.

    Charges the deal only when the retrievability challenge passes.
    """
    return await rpc_call("tenzro_storageChargeEpoch", {"deal_id": deal_id})


@mcp.tool
async def storage_get_deal(deal_id: str) -> dict:
    """Look up a storage deal by its id."""
    return await rpc_call("tenzro_storageGetDeal", {"deal_id": deal_id})


@mcp.tool
async def storage_set_pricing(
    mode: str = "dynamic",
    capacity: str = "0",
    min_rate: str = "",
    max_rate: str = "",
) -> dict:
    """Set the byte-epoch storage pricing policy.

    `mode` is "dynamic"; `capacity` is the byte-epoch capacity. `min_rate`
    and `max_rate` bound the dynamic rate when provided.
    """
    params = {"mode": mode, "capacity": capacity}
    if min_rate:
        params["min_rate"] = min_rate
    if max_rate:
        params["max_rate"] = max_rate
    return await rpc_call("tenzro_storageSetPricing", params)


@mcp.tool
async def storage_status() -> dict:
    """Return a summary of this node's storage-provider state."""
    return await rpc_call("tenzro_storageStatus", [])


# ---------------------------------------------------------------------------
# Compute Rental (5 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def compute_book_rental(renter: str, total_epochs: int) -> dict:
    """Book a fixed-term compute rental against this provider.

    `renter` is a hex address that pre-funds from its deposit; the
    per-epoch price is the provider's effective rate.
    """
    return await rpc_call(
        "tenzro_computeBookRental",
        {"renter": renter, "total_epochs": total_epochs},
    )


@mcp.tool
async def compute_settle_epoch(rental_id: str, proof_valid: bool = True) -> dict:
    """Settle one epoch of an active compute rental, gated on the availability proof.

    A valid proof streams the epoch slice to the provider; an invalid or
    missing proof makes the renter whole from stake.
    """
    return await rpc_call(
        "tenzro_computeSettleEpoch",
        {"rental_id": rental_id, "proof_valid": proof_valid},
    )


@mcp.tool
async def compute_get_rental(rental_id: str) -> dict:
    """Look up a compute rental by its id."""
    return await rpc_call("tenzro_computeGetRental", {"rental_id": rental_id})


@mcp.tool
async def compute_set_pricing(
    mode: str = "dynamic",
    capacity: str = "0",
    min_rate: str = "",
    max_rate: str = "",
) -> dict:
    """Set the per-epoch compute pricing policy.

    `mode` is "dynamic"; `capacity` is the epoch-slot capacity. `min_rate`
    and `max_rate` bound the dynamic rate when provided.
    """
    params = {"mode": mode, "capacity": capacity}
    if min_rate:
        params["min_rate"] = min_rate
    if max_rate:
        params["max_rate"] = max_rate
    return await rpc_call("tenzro_computeSetPricing", params)


@mcp.tool
async def compute_status() -> dict:
    """Return a summary of this node's compute-rental state."""
    return await rpc_call("tenzro_computeStatus", [])


# ---------------------------------------------------------------------------
# MoE Expert Sharding (4 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def moe_shard_map(model_id: str) -> dict:
    """Return the expert-shard map for a MoE model across known providers.

    Reports per-expert holders, replication counts, role counts, and the
    under-replicated and hot experts under the current replication policy.
    """
    return await rpc_call("tenzro_moeShardMap", {"model_id": model_id})


@mcp.tool
async def moe_plan_dispatch(
    model_id: str,
    routings: list,
    allow_cold: bool = False,
) -> dict:
    """Plan the per-holder dispatch for a list of per-token top-k routings.

    Each routing is `{"token_index": int, "experts": [{"layer": int,
    "expert": int}, ...]}`. Set `allow_cold` to include providers that do
    not currently hold the expert resident.
    """
    return await rpc_call(
        "tenzro_moePlanDispatch",
        {"model_id": model_id, "routings": routings, "allow_cold": allow_cold},
    )


@mcp.tool
async def moe_replication_policy() -> dict:
    """Return the current replication policy used by shard-view consumers."""
    return await rpc_call("tenzro_moeReplicationPolicy", [])


@mcp.tool
async def moe_catalog_shape(model_id: str) -> dict:
    """Return the catalog-side MoE topology for a model.

    Reports num_experts, experts_per_token, shared_experts, and
    params_per_expert; null for dense models.
    """
    return await rpc_call("tenzro_moeCatalogShape", {"model_id": model_id})


# ---------------------------------------------------------------------------
# Local Discovery & Cluster (4 tools)
# ---------------------------------------------------------------------------


@mcp.tool
async def local_peers() -> dict:
    """Return peer IDs discovered on this node's local network segment via mDNS."""
    return await rpc_call("tenzro_localPeers", [])


@mcp.tool
async def node_reachability() -> dict:
    """Return this node's sustained connectivity tier."""
    return await rpc_call("tenzro_nodeReachability", [])


@mcp.tool
async def node_profile() -> dict:
    """Return the local node's hardware self-profile and derived serving values.

    Reports the linked runtime build, CPU architecture, operating system,
    detected compute devices, serving VRAM, backend, and capability key.
    """
    return await rpc_call("tenzro_nodeProfile", [])


@mcp.tool
async def cluster_plan(
    model: dict,
    members: list,
    user_forced: bool = False,
) -> dict:
    """Compute a deterministic cluster placement for a model across candidate members.

    `model` is `{"layers": int, "hidden_dim": int, "total_vram_gb": float}`.
    `members` is a list of cluster member descriptors. Returns the fit
    decision and, when a cluster forms, the VRAM-weighted layer assignment.
    """
    return await rpc_call(
        "tenzro_clusterPlan",
        {"model": model, "members": members, "user_forced": user_forced},
    )


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
