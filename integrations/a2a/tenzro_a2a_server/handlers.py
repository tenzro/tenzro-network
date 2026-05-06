"""Handler functions for each routed skill.

Every handler accepts the user's natural-language text (and optional metadata)
and returns a plain-text or JSON response string by calling the Tenzro JSON-RPC
or Web API.
"""

from .rpc_client import rpc_call, api_call
import json
import re


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_address(text: str) -> str | None:
    """Extract a hex address from text."""
    m = re.search(r"0x[a-fA-F0-9]+", text)
    return m.group(0) if m else None


def _extract_did(text: str) -> str | None:
    """Extract a did:tenzro:... or did:pdis:... identifier."""
    m = re.search(r"did:(tenzro|pdis):\S+", text)
    return m.group(0).rstrip("?.!,;") if m else None


def _extract_amount(text: str) -> float | None:
    """Extract a numeric amount from text like 'send 10 TNZO'."""
    m = re.search(r"(\d+(?:\.\d+)?)\s*(?:TNZO|tnzo|tokens?)?", text)
    return float(m.group(1)) if m else None


def _extract_name(text: str) -> str:
    """Extract a name/label from the end of the text, fallback to 'Anonymous'."""
    words = text.strip().rstrip("?.!,;").split()
    return words[-1] if len(words) > 2 else "Anonymous"


def _extract_id(text: str, prefix: str = "") -> str | None:
    """Extract a UUID-like or prefixed identifier."""
    pattern = (
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    m = re.search(pattern, text)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Wallet & Blockchain
# ---------------------------------------------------------------------------

async def handle_wallet(text: str, metadata: dict = None) -> str:
    t = text.lower()
    addr = _extract_address(text)

    if "create" in t or "new wallet" in t:
        result = await rpc_call("tenzro_createWallet", ["ed25519"])
        return (
            f"Wallet created:\n"
            f"  Address: {result['address']}\n"
            f"  Key type: {result['key_type']}\n"
            f"  Threshold: {result['threshold']}-of-{result['total_shares']}"
        )

    if ("send" in t or "transfer" in t) and addr:
        # Try to find a second address and amount
        addresses = re.findall(r"0x[a-fA-F0-9]+", text)
        amount = _extract_amount(text)
        if len(addresses) >= 2 and amount:
            from_addr = addresses[0]
            to_addr = addresses[1]
            # Query nonce and chain id
            nonce_hex = await rpc_call("eth_getTransactionCount", [from_addr, "latest"])
            chain_id_hex = await rpc_call("eth_chainId", [])
            nonce = int(nonce_hex, 16) if nonce_hex else 0
            chain_id = int(chain_id_hex, 16) if chain_id_hex else 1337
            wei = int(amount * 1e18)
            # Hybrid-signed atomic submit. The node identifies the signing
            # wallet from the ambient DPoP-bound JWT, constructs the
            # canonical Transaction::hash() preimage including the PQ
            # public key, signs both Ed25519 and ML-DSA-65 legs, and
            # submits. Private keys never travel over the wire.
            result = await rpc_call("tenzro_signAndSendTransaction", {
                "from": from_addr,
                "to": to_addr,
                "value": wei,
                "gas_limit": 21000,
                "gas_price": 10**9,
                "nonce": nonce,
                "chain_id": chain_id,
            })
            return f"Transaction sent.\n  Hash: {result}\n  From: {from_addr}\n  To: {to_addr}\n  Amount: {amount} TNZO"
        return (
            "To send TNZO, provide: from address, to address, and amount.\n"
            "Example: 'Send 10 TNZO from 0xabc... to 0xdef...'"
        )

    if addr:
        result = await rpc_call("eth_getBalance", [addr, "latest"])
        wei = int(result, 16) if result else 0
        tnzo = wei / 1e18
        return f"Balance for {addr}: {tnzo:.6f} TNZO ({wei} wei)"

    return (
        "Wallet operations:\n"
        "  - 'Create a new wallet'\n"
        "  - 'Check balance for 0xabc...'\n"
        "  - 'Send 10 TNZO from 0xabc... to 0xdef...'"
    )


async def handle_block(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "transaction" in t:
        tx_hash = _extract_address(text)
        if tx_hash:
            result = await rpc_call("tenzro_getTransaction", [tx_hash])
            return json.dumps(result, indent=2)
        return "Provide a transaction hash (0x...) to look up."

    # Batch-fetch block range for catch-up sync.
    # Triggered by "range", "sync from", "catch up", or any message containing
    # two numbers (interpreted as start..end heights).
    if any(k in t for k in ["range", "catch up", "catch-up", "sync from", "block range"]):
        nums = re.findall(r"\d+", text)
        if len(nums) >= 2:
            start = int(nums[0])
            end = int(nums[1])
            max_results = int(nums[2]) if len(nums) >= 3 else 64
            params = {"startHeight": start, "endHeight": end, "maxResults": max_results}
            result = await rpc_call("tenzro_getBlockRange", params)
            blocks = result.get("blocks", []) if isinstance(result, dict) else []
            return (
                f"Block range {start}..{end} (max {max_results}):\n"
                f"  Returned: {len(blocks)} blocks\n"
                f"  nextHeight: {result.get('nextHeight')}\n"
                f"  moreAvailable: {result.get('moreAvailable')}\n"
                f"  localTip: {result.get('localTip')}"
            )
        return (
            "Provide start and end heights to fetch a block range.\n"
            "Example: 'block range 1000 1063' or 'sync from 0 to 255'.\n"
            "Returns up to 256 blocks per call with nextHeight + moreAvailable for pagination."
        )

    if any(k in t for k in ["fee", "gas price", "gasprice", "tip", "1559", "eip-1559"]):
        return await handle_fee_market(text, metadata)

    result = await rpc_call("eth_blockNumber", [])
    height = int(result, 16) if result else 0
    return f"Current block height: {height}"


async def handle_fee_market(text: str, metadata: dict = None) -> str:
    """Inspect the EIP-1559 fee market: current effective gas price, suggested
    priority tip, and recent base-fee history. Useful for sizing
    `maxFeePerGas` / `maxPriorityFeePerGas` on Type-2 transactions.
    """
    nums = re.findall(r"\d+", text or "")
    blocks = int(nums[0]) if nums else 10
    blocks = max(1, min(blocks, 1024))

    gas_price = await rpc_call("eth_gasPrice", [])
    priority = await rpc_call("eth_maxPriorityFeePerGas", [])
    history = await rpc_call(
        "eth_feeHistory",
        [hex(blocks), "latest", [25, 50, 75]],
    )

    def _wei(hex_str):
        try:
            return int(hex_str, 16)
        except (TypeError, ValueError):
            return 0

    base_fees = history.get("baseFeePerGas", []) if isinstance(history, dict) else []
    next_block_base = _wei(base_fees[-1]) if base_fees else 0
    ratios = history.get("gasUsedRatio", []) if isinstance(history, dict) else []
    avg_ratio = (sum(ratios) / len(ratios)) if ratios else 0.0

    return (
        f"Fee Market (EIP-1559):\n"
        f"  Effective gas price: {_wei(gas_price)} wei\n"
        f"  Suggested priority tip: {_wei(priority)} wei\n"
        f"  Next-block base fee: {next_block_base} wei\n"
        f"  Sampled blocks: {blocks}\n"
        f"  Avg gas-used ratio: {avg_ratio:.3f}\n"
        f"  (Adjusts ±12.5% per block vs. 15M target.)"
    )


async def handle_status(text: str, metadata: dict = None) -> str:
    result = await rpc_call("tenzro_nodeInfo", [])
    lines = [
        "Node Status:",
        f"  Role: {result.get('role', 'unknown')}",
        f"  State: {result.get('state', 'unknown')}",
        f"  Peers: {result.get('peer_count', 0)}",
        f"  Block height: {result.get('block_height', 0)}",
        f"  Uptime: {result.get('uptime_secs', 0)}s",
    ]
    # Surface sync gap from peer-reported network tip.
    sync = await rpc_call("tenzro_syncing", [])
    if isinstance(sync, dict) and sync.get("syncing"):
        current = sync.get("current_block", 0)
        highest = sync.get("highest_block", 0)
        gap = max(0, int(highest) - int(current))
        lines.append(f"  Syncing: yes (behind by {gap} blocks; network tip {highest})")
    else:
        lines.append("  Syncing: no (caught up)")
    return "\n".join(lines)


async def handle_network(text: str, metadata: dict = None) -> str:
    peer_count = await rpc_call("tenzro_peerCount", [])
    listening = await rpc_call("net_listening", [])
    return (
        f"Network Info:\n"
        f"  Peers: {peer_count}\n"
        f"  Listening: {listening}"
    )


async def handle_faucet(text: str, metadata: dict = None) -> str:
    addr = _extract_address(text)
    if not addr:
        return "Provide an address to receive testnet TNZO.\nExample: 'Request faucet tokens for 0xabc...'"
    result = await api_call("/faucet", method="POST", body={"address": addr})
    if result.get("error"):
        return f"Faucet error: {result['error']}"
    amount = result.get("amount", "100")
    tx_hash = result.get("tx_hash", "pending")
    return (
        f"Faucet tokens sent!\n"
        f"  Address: {addr}\n"
        f"  Amount: {amount} TNZO\n"
        f"  Tx hash: {tx_hash}"
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

async def handle_identity(text: str, metadata: dict = None) -> str:
    t = text.lower()
    did = _extract_did(text)

    # TDIP/GDPR Article 17 right-to-erasure. Two-phase: revoke first, then forget.
    if did and ("forget" in t or "erase" in t or "right to be forgotten" in t):
        result = await rpc_call("tenzro_forgetIdentity", {"did": did})
        return (
            f"Identity erased (Article 17):\n"
            f"  DID: {did}\n"
            f"  Status: {result.get('status', 'erased')}\n"
            f"  Note: {result.get('note', 'Hard-deleted from CF_IDENTITIES')}"
        )

    if did and ("revoke" in t or "cancel" in t):
        reason = metadata.get("reason", "revoked via A2A") if metadata else "revoked via A2A"
        result = await rpc_call("tenzro_revokeDid", {"did": did, "reason": reason})
        return (
            f"Identity revoked:\n"
            f"  DID: {did}\n"
            f"  Affected JTIs: {result.get('affected_jti_count', 0)}\n"
            f"  Cascade: {result.get('cascade', '')}"
        )

    if did:
        result = await rpc_call("tenzro_resolveIdentity", [did])
        return json.dumps(result, indent=2)

    if "register" in t:
        name = _extract_name(text)
        identity_type = "machine" if "machine" in t else "human"
        result = await rpc_call("tenzro_registerIdentity", [identity_type, name])
        return (
            f"Identity registered:\n"
            f"  DID: {result.get('did', 'unknown')}\n"
            f"  Type: {identity_type}\n"
            f"  Status: {result.get('status', 'active')}"
        )

    if "username" in t:
        if "set" in t:
            words = text.strip().split()
            username = words[-1].rstrip("?.!,;") if len(words) > 2 else None
            if username:
                result = await rpc_call("tenzro_setUsername", [username])
                return f"Username set: {username}\n{json.dumps(result, indent=2)}"
            return "Provide a username to set. Example: 'Set my username to alice'"
        words = text.strip().split()
        username = words[-1].rstrip("?.!,;")
        result = await rpc_call("tenzro_resolveUsername", [username])
        return json.dumps(result, indent=2)

    return (
        "Identity operations:\n"
        "  - 'Register a new human identity named Alice'\n"
        "  - 'Resolve DID did:tenzro:human:abc123'\n"
        "  - 'Revoke DID did:tenzro:human:abc123'\n"
        "  - 'Forget DID did:tenzro:human:abc123' (Article 17 right-to-erasure)\n"
        "  - 'Set my username to alice'\n"
        "  - 'Resolve username bob'"
    )


# ---------------------------------------------------------------------------
# AI Inference
# ---------------------------------------------------------------------------

async def handle_inference(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "list" in t and "model" in t:
        result = await rpc_call("tenzro_listModels", [])
        if not result:
            return "No models currently registered on the network."
        lines = ["Available models:"]
        for m in result:
            lines.append(f"  - {m.get('name', 'unknown')} ({m.get('id', '')})")
        return "\n".join(lines)

    if "chat" in t or "ask" in t or "complete" in t:
        # Extract the prompt after keywords
        prompt = text
        for kw in ["chat", "ask", "complete", "say"]:
            idx = t.find(kw)
            if idx >= 0:
                prompt = text[idx + len(kw):].strip().lstrip(":").strip()
                break
        result = await rpc_call("tenzro_chat", {"model_id": "default", "message": prompt, "max_tokens": 100})
        return json.dumps(result, indent=2)

    if "endpoint" in t:
        result = await rpc_call("tenzro_listModelEndpoints", [])
        return json.dumps(result, indent=2)

    result = await rpc_call("tenzro_listModels", [])
    if not result:
        return "No models currently available. Use 'list models' to check later."
    lines = ["Available models:"]
    for m in result:
        lines.append(
            f"  - {m.get('name', 'unknown')} | "
            f"Category: {m.get('category', 'n/a')} | "
            f"ID: {m.get('id', '')}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Staking & Provider
# ---------------------------------------------------------------------------

async def handle_staking(text: str, metadata: dict = None) -> str:
    t = text.lower()
    addr = _extract_address(text)
    amount = _extract_amount(text)

    if "unstake" in t or "withdraw" in t:
        if addr and amount:
            result = await rpc_call("tenzro_unstake", [addr, str(amount)])
            return f"Unstake initiated: {amount} TNZO from {addr}\n{json.dumps(result, indent=2)}"
        return "To unstake, provide: address and amount.\nExample: 'Unstake 100 TNZO from 0xabc...'"

    if "stake" in t and amount and addr:
        role = "Validator"
        if "model" in t or "provider" in t:
            role = "ModelProvider"
        if "tee" in t:
            role = "TeeProvider"
        result = await rpc_call("tenzro_stake", [addr, str(amount), role])
        return f"Staked {amount} TNZO as {role} from {addr}\n{json.dumps(result, indent=2)}"

    if addr:
        result = await rpc_call("tenzro_getVotingPower", [addr])
        return f"Staking info for {addr}:\n{json.dumps(result, indent=2)}"

    return (
        "Staking operations:\n"
        "  - 'Stake 1000 TNZO from 0xabc... as Validator'\n"
        "  - 'Unstake 500 TNZO from 0xabc...'\n"
        "  - 'Get staking info for 0xabc...'"
    )


async def handle_provider(text: str, metadata: dict = None) -> str:
    t = text.lower()
    addr = _extract_address(text)

    if "register" in t and addr:
        result = await rpc_call("tenzro_registerProvider", [addr])
        return f"Provider registered: {addr}\n{json.dumps(result, indent=2)}"

    if ("status" in t or "stats" in t) and addr:
        result = await rpc_call("tenzro_providerStats", [addr])
        return f"Provider stats for {addr}:\n{json.dumps(result, indent=2)}"

    return (
        "Provider operations:\n"
        "  - 'Register as provider with address 0xabc...'\n"
        "  - 'Get provider status for 0xabc...'"
    )


# ---------------------------------------------------------------------------
# Payments
# ---------------------------------------------------------------------------

async def handle_payment(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "session" in t:
        result = await rpc_call("tenzro_listPaymentSessions", [])
        return f"Payment sessions:\n{json.dumps(result, indent=2)}"

    if "info" in t or "gateway" in t:
        result = await rpc_call("tenzro_paymentGatewayInfo", [])
        return f"Payment gateway info:\n{json.dumps(result, indent=2)}"

    if "scheme" in t and "x402" in t:
        result = await rpc_call("tenzro_listX402Schemes", [])
        return f"x402 scheme registry:\n{json.dumps(result, indent=2)}"

    if "challenge" in t:
        protocol = "mpp"
        if "x402" in t:
            protocol = "x402"
        result = await rpc_call("tenzro_createPaymentChallenge", [protocol, "/resource"])
        return f"Payment challenge created ({protocol}):\n{json.dumps(result, indent=2)}"

    if "ap2" in t:
        amount = _extract_amount(text)
        if "create" in t and amount:
            return (
                f"To create an AP2 payment for {amount} TNZO, provide:\n"
                f"  - Payer DID\n"
                f"  - Payee DID\n"
                f"  - Amount: {amount} TNZO\n"
                f"Use JSON format for full AP2 payment creation."
            )
        if "authorize" in t:
            return (
                "AP2 authorization requires:\n"
                "  - Agent DID\n"
                "  - Spending limit (TNZO)\n"
                "  - Time window (seconds)"
            )
        if "status" in t:
            pay_id = _extract_id(text)
            if pay_id:
                return f"AP2 payment status lookup for {pay_id} -- use tenzro_getSettlement RPC."
            return "Provide a payment ID to check status."
        if "cancel" in t:
            pay_id = _extract_id(text)
            if pay_id:
                return f"AP2 payment cancellation for {pay_id} -- submit cancel via settlement RPC."
            return "Provide a payment ID to cancel."
        if "execute" in t:
            pay_id = _extract_id(text)
            if pay_id:
                return f"AP2 payment execution for {pay_id} -- submit via settlement RPC."
            return "Provide a payment ID to execute."

    if "mpp" in t:
        result = await rpc_call("tenzro_createPaymentChallenge", ["mpp", "/resource"])
        return f"MPP challenge:\n{json.dumps(result, indent=2)}"

    if "x402" in t:
        result = await rpc_call("tenzro_createPaymentChallenge", ["x402", "/resource"])
        return f"x402 challenge:\n{json.dumps(result, indent=2)}"

    return (
        "Payment operations:\n"
        "  - 'Create MPP payment challenge'\n"
        "  - 'Create x402 payment challenge'\n"
        "  - 'List x402 schemes'\n"
        "  - 'List payment sessions'\n"
        "  - 'AP2 create payment for 100 TNZO'\n"
        "  - 'Payment gateway info'"
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

async def handle_verification(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "tee" in t or "attestation" in t:
        provider = (metadata or {}).get("provider") if metadata else None
        quote = (metadata or {}).get("quote") if metadata else None
        if not provider or not quote:
            return (
                "TEE attestation verification requires a real provider and quote.\n"
                "Pass via metadata: {\"provider\": \"tdx|sev-snp|nitro|nvidia-gpu\", \"quote\": \"<base64>\"}\n"
                "Supported providers: tdx, sev-snp, nitro, nvidia-gpu"
            )
        result = await api_call("/verify/tee-attestation", method="POST", body={
            "provider": provider,
            "quote": quote,
        })
        return f"TEE attestation verification:\n{json.dumps(result, indent=2)}"

    if "transaction" in t or "signature" in t:
        tx_hash = _extract_address(text)
        if tx_hash:
            result = await api_call("/verify/transaction", method="POST", body={
                "tx_hash": tx_hash,
            })
            return f"Transaction verification:\n{json.dumps(result, indent=2)}"
        return "Provide a transaction hash to verify its signature."

    if "zk" in t or "proof" in t:
        md = metadata or {}
        proof = md.get("proof") or md.get("proof_bytes")
        public_inputs = md.get("public_inputs")
        circuit_id = md.get("circuit_id")
        if not proof or public_inputs is None or not circuit_id:
            return (
                "ZK proof verification requires a Plonky3 STARK proof, public inputs, and circuit_id.\n"
                "Pass via metadata: {\"circuit_id\": \"inference|settlement|identity\", "
                "\"proof_bytes\": \"<hex>\", \"public_inputs\": [\"<hex>\", ...]}\n"
                "public_inputs entries are 4-byte little-endian KoalaBear field-element chunks."
            )
        result = await api_call("/verify/zk-proof", method="POST", body={
            "circuit_id": circuit_id,
            "proof_bytes": proof,
            "public_inputs": public_inputs,
        })
        return f"ZK proof verification:\n{json.dumps(result, indent=2)}"

    return (
        "Verification operations:\n"
        "  - 'Verify a ZK proof'\n"
        "  - 'Check TEE attestation'\n"
        "  - 'Verify transaction signature for 0xabc...'"
    )


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

async def handle_bridge(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "route" in t:
        return (
            "To get bridge routes, specify source and destination chains.\n"
            "Example: 'Get bridge routes from Tenzro to Ethereum'\n"
            "Supported chains: Ethereum, Solana, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche"
        )

    if "adapter" in t or "list" in t:
        return (
            "Available bridge adapters:\n"
            "  - LayerZero V2 (omnichain messaging + OFT)\n"
            "  - Chainlink CCIP v1.6 (cross-chain messaging)\n"
            "  - deBridge DLN (intent-based swaps)\n"
            "  - LI.FI Aggregator (58+ chains)\n"
            "  - Canton (DAML enterprise)"
        )

    if "fee" in t or "estimate" in t:
        return (
            "To estimate bridge fees, provide:\n"
            "  - Source chain\n"
            "  - Destination chain\n"
            "  - Token and amount\n"
            "Example: 'Estimate bridge fee for 500 USDC from Ethereum to Arbitrum'"
        )

    amount = _extract_amount(text)
    if amount:
        return (
            f"To bridge {amount} tokens, provide:\n"
            f"  - Source chain\n"
            f"  - Destination chain\n"
            f"  - Token symbol\n"
            f"  - Sender and recipient addresses\n"
            f"Use the MCP server at mcp.tenzro.network/mcp for programmatic bridging."
        )

    return (
        "Cross-chain bridge operations:\n"
        "  - 'Bridge 100 TNZO from Ethereum to Solana'\n"
        "  - 'Get bridge routes from Tenzro to Base'\n"
        "  - 'Estimate bridge fee for 500 USDC to Arbitrum'\n"
        "  - 'List available bridge adapters'\n"
        "Supported: LayerZero, CCIP, deBridge, LI.FI, Canton"
    )


# ---------------------------------------------------------------------------
# Join / Onboarding
# ---------------------------------------------------------------------------

async def handle_join(text: str, metadata: dict = None) -> str:
    name = _extract_name(text)
    if name.lower() in ("network", "tenzro", "micronode", "join", "node"):
        name = "Anonymous"

    result = await rpc_call("tenzro_participate", [name])

    did = result.get("did", "unknown")
    address = result.get("address", "unknown")
    capabilities = result.get("capabilities", [])

    cap_lines = "\n".join(f"    - {c}" for c in capabilities) if capabilities else "    (default capabilities)"

    return (
        f"Welcome to the Tenzro Network!\n"
        f"\n"
        f"  Name: {name}\n"
        f"  DID: {did}\n"
        f"  Wallet: {address}\n"
        f"  Capabilities:\n"
        f"{cap_lines}\n"
        f"\n"
        f"Your identity and MPC wallet have been provisioned.\n"
        f"Use 'faucet' to request testnet TNZO tokens."
    )


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

async def handle_list_tokens(text: str, metadata: dict = None) -> str:
    result = await rpc_call("tenzro_listTokens", [])
    if not result:
        return "No tokens registered in the unified token registry."
    tokens = result.get("tokens", result) if isinstance(result, dict) else result
    if not tokens:
        return "No tokens registered in the unified token registry."
    lines = [f"Registered tokens ({len(tokens)}):"]
    for tok in tokens:
        lines.append(
            f"  - {tok.get('symbol', '?')} ({tok.get('name', '?')}) | "
            f"VM: {tok.get('vm_type', 'all')} | "
            f"ID: {tok.get('token_id', '')}"
        )
    return "\n".join(lines)


async def handle_create_token(text: str, metadata: dict = None) -> str:
    # Try to extract token details from text
    # Pattern: "Create token MyToken (MTK) with 1000000 supply"
    name_match = re.search(r"(?:called|named|token)\s+(\w+)", text, re.IGNORECASE)
    symbol_match = re.search(r"\((\w{2,6})\)", text)
    supply = _extract_amount(text)

    if name_match and symbol_match and supply:
        name = name_match.group(1)
        symbol = symbol_match.group(1)
        result = await rpc_call("tenzro_createToken", [name, symbol, str(int(supply)), "18"])
        return f"Token created:\n{json.dumps(result, indent=2)}"

    return (
        "To create a token, provide:\n"
        "  - Name, symbol, total supply, decimals\n"
        "Example: 'Create a token called MyToken (MTK) with 1000000 supply'\n"
        "Default decimals: 18"
    )


async def handle_token_info(text: str, metadata: dict = None) -> str:
    # Extract symbol or address
    addr = _extract_address(text)
    if addr:
        result = await rpc_call("tenzro_getToken", [addr])
        return json.dumps(result, indent=2)

    words = text.strip().split()
    symbol = words[-1].rstrip("?.!,;").upper() if words else None
    if symbol and len(symbol) <= 10:
        result = await rpc_call("tenzro_getToken", [symbol])
        return json.dumps(result, indent=2)

    return "Provide a token symbol or address.\nExample: 'Get token info for TNZO'"


async def handle_token_balance(text: str, metadata: dict = None) -> str:
    addr = _extract_address(text)
    if addr:
        result = await rpc_call("tenzro_getTokenBalance", [addr])
        return f"Token balance for {addr}:\n{json.dumps(result, indent=2)}"
    return "Provide an address to check token balance.\nExample: 'Get token balance for 0xabc...'"


async def handle_cross_vm_transfer(text: str, metadata: dict = None) -> str:
    # Surface SVM-native program info when the question is about constructing
    # an SVM-side instruction (program id, discriminator, etc.).
    t = text.lower()
    if any(
        k in t
        for k in (
            "program id",
            "program-id",
            "discriminator",
            "tenzro_cross_vm",
            "anchor",
            "instruction data",
            "svm program",
            "cross-vm program",
            "cross vm program",
        )
    ):
        return await handle_svm_cross_vm_info(text, metadata)

    return (
        "Cross-VM token transfer requires:\n"
        "  - Token symbol or ID\n"
        "  - Source VM (evm, svm, daml)\n"
        "  - Target VM (evm, svm, daml)\n"
        "  - Amount\n"
        "  - Sender address\n"
        "Example: 'Transfer 100 TNZO from EVM to SVM for 0xabc...'\n"
        "Note: TNZO uses the pointer model (no bridge risk).\n\n"
        "If you're building an SVM-side instruction directly, ask for "
        "'tenzro_cross_vm program id' or 'cross-vm discriminators'."
    )


async def handle_svm_cross_vm_info(text: str, metadata: dict = None) -> str:
    """Return the canonical Tenzro Cross-VM SVM-native program ID and the four
    Anchor-style instruction discriminators for SVM clients."""
    return (
        "Tenzro Cross-VM SVM-native program:\n"
        "  Program ID (base58):  7CBvjJtsMxYFsxYkpcXYoTDZpC8PhMVy1DVVQBopvWCC\n"
        "  Program ID (hex):     5c03dd6cf580ecafb5ca11a9e1d6448176bb1dfa9d4886c65d9024df77542695\n"
        "  Derivation:           SHA-256(\"tenzro/svm/program/cross_vm\")\n"
        "\n"
        "Instruction discriminators (Anchor-style, 8 bytes):\n"
        "  bridge_to_evm           92a8a45c33225f25  (68-byte payload)\n"
        "  bridge_from_evm         3038733289f4cd75  (80-byte payload)\n"
        "  register_token_pointer  9a8e01390f994522  (84-byte payload)\n"
        "  transfer_cross_vm       bc684168aba7abb9  (81-byte payload)\n"
        "\n"
        "Layout: [ discriminator (8) | payload (n) ]. Integers are little-endian.\n"
        "dest_vm tag for transfer_cross_vm: 0=Native, 1=EVM, 2=SVM, 3=DAML.\n"
        "\n"
        "Use the SDK encoders for byte-correct payloads:\n"
        "  TypeScript: encodeBridgeToEvm / encodeBridgeFromEvm / "
        "encodeRegisterTokenPointer / encodeTransferCrossVm from \"tenzro\"\n"
        "  Python:     encode_bridge_to_evm / encode_bridge_from_evm / "
        "encode_register_token_pointer / encode_transfer_cross_vm\n"
        "  Rust:       tenzro_sdk::svm_cross_vm::encode_*"
    )


async def handle_wrap_tnzo(text: str, metadata: dict = None) -> str:
    addr = _extract_address(text)
    amount = _extract_amount(text)
    if addr and amount:
        vm = "evm"
        if "svm" in text.lower() or "solana" in text.lower():
            vm = "svm"
        elif "daml" in text.lower() or "canton" in text.lower():
            vm = "daml"
        result = await rpc_call("tenzro_wrapTnzo", [addr, str(amount), vm])
        return f"Wrap TNZO:\n{json.dumps(result, indent=2)}"
    return (
        "To wrap TNZO for a specific VM:\n"
        "  - Provide address, amount, and target VM\n"
        "Example: 'Wrap 50 TNZO for EVM from 0xabc...'\n"
        "Note: In the pointer model, wrapping is a no-op (balances are unified)."
    )


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

async def handle_contract(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "vm" in t or "supported" in t:
        return (
            "Supported VMs for contract deployment:\n"
            "  - EVM (Ethereum Virtual Machine) -- Solidity bytecode\n"
            "  - SVM (Solana Virtual Machine) -- BPF programs\n"
            "  - DAML (Canton) -- DAML templates via DAR upload"
        )

    bytecode = _extract_address(text)  # bytecodes start with 0x too
    if bytecode and len(bytecode) > 42:  # longer than an address
        vm_type = "evm"
        if "svm" in t or "solana" in t:
            vm_type = "svm"
        elif "daml" in t or "canton" in t:
            vm_type = "daml"
        result = await rpc_call("tenzro_deployContract", [vm_type, bytecode])
        return f"Contract deployed:\n{json.dumps(result, indent=2)}"

    return (
        "To deploy a smart contract, provide:\n"
        "  - VM type: evm, svm, or daml\n"
        "  - Bytecode (hex-encoded, starting with 0x)\n"
        "  - Constructor arguments (optional)\n"
        "Example: 'Deploy an EVM contract with bytecode 0x6080604052...'"
    )


# ---------------------------------------------------------------------------
# NFT
# ---------------------------------------------------------------------------

async def handle_nft(text: str, metadata: dict = None) -> str:
    t = text.lower()
    addr = _extract_address(text)

    if "create" in t or "collection" in t:
        return (
            "To create an NFT collection, provide:\n"
            "  - Collection name\n"
            "  - Symbol\n"
            "  - Standard (ERC-721 or ERC-1155)\n"
            "  - Base URI for metadata\n"
            "This will deploy an NFT contract via the multi-VM runtime."
        )

    if "mint" in t:
        if addr:
            return (
                f"To mint an NFT in collection {addr}, provide:\n"
                f"  - Token URI or metadata\n"
                f"  - Recipient address\n"
                f"  - Token ID (for ERC-1155)"
            )
        return "Provide the collection address to mint. Example: 'Mint an NFT in collection 0xabc...'"

    if "transfer" in t:
        return (
            "To transfer an NFT, provide:\n"
            "  - Collection address\n"
            "  - Token ID\n"
            "  - Recipient address"
        )

    if "owner" in t or "query" in t:
        return (
            "To query NFT ownership, provide:\n"
            "  - Collection address\n"
            "  - Token ID"
        )

    return (
        "NFT operations:\n"
        "  - 'Create a new ERC-721 NFT collection'\n"
        "  - 'Mint an NFT in collection 0xabc...'\n"
        "  - 'Transfer NFT #42 to 0xdef...'\n"
        "  - 'Query ownership of NFT #7'"
    )


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

async def handle_compliance(text: str, metadata: dict = None) -> str:
    t = text.lower()
    addr = _extract_address(text)

    if "kyc" in t and addr:
        return (
            f"KYC verification for {addr}:\n"
            f"  Use tenzro_resolveIdentity to check KYC tier.\n"
            f"  KYC tiers: Unverified (0), Basic (1), Enhanced (2), Full (3)"
        )

    if "accredit" in t and addr:
        return (
            f"Accreditation check for {addr}:\n"
            f"  Query the identity registry for credential type 'AccreditedInvestor'."
        )

    if "country" in t or "restrict" in t:
        return (
            "Country restrictions are managed per-token via the T-REX identity registry.\n"
            "  Provide a token symbol to query restrictions."
        )

    if "freeze" in t and addr:
        return (
            f"To freeze token holdings for {addr}:\n"
            f"  This requires compliance officer role and T-REX token contract interaction."
        )

    if "issuer" in t:
        return (
            "Trusted issuer management:\n"
            "  - Add a trusted issuer with their DID and claim topics\n"
            "  - Remove a trusted issuer by DID\n"
            "  - List all trusted issuers for a token"
        )

    return (
        "Compliance & KYC operations (ERC-3643 T-REX):\n"
        "  - 'Verify KYC status for 0xabc...'\n"
        "  - 'Check accreditation for 0xdef...'\n"
        "  - 'List country restrictions for token XYZ'\n"
        "  - 'Freeze token holdings for 0x123...'\n"
        "  - 'Add a trusted issuer to the registry'"
    )


# ---------------------------------------------------------------------------
# Cross-Chain Token Standard (ERC-7802)
# ---------------------------------------------------------------------------

async def handle_crosschain(text: str, metadata: dict = None) -> str:
    t = text.lower()
    addr = _extract_address(text)

    if "authorize" in t and addr:
        return (
            f"To authorize bridge {addr} for cross-chain minting:\n"
            f"  Submit an ERC-7802 authorizeBridge transaction with the bridge address.\n"
            f"  This grants mint/burn rights on the target chain."
        )

    if "rate limit" in t:
        return (
            "To set a cross-chain rate limit:\n"
            "  Provide bridge address, token, and limit (tokens/day).\n"
            "  Example: 'Set rate limit for bridge 0xabc... to 10000 TNZO/day'"
        )

    if "audit" in t or "trail" in t:
        return (
            "Cross-chain audit trail:\n"
            "  Query ERC-7802 CrossChainMint and CrossChainBurn events.\n"
            "  Provide a token address or bridge address to filter."
        )

    if "revoke" in t and addr:
        return (
            f"To revoke bridge authorization for {addr}:\n"
            f"  Submit an ERC-7802 revokeBridge transaction."
        )

    return (
        "ERC-7802 Cross-Chain Token Standard:\n"
        "  - 'Authorize a bridge for cross-chain minting'\n"
        "  - 'Set rate limit for bridge 0xabc... to 10000 TNZO/day'\n"
        "  - 'Query audit trail for cross-chain transfers'\n"
        "  - 'Revoke bridge authorization for 0xdef...'"
    )


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

async def handle_events(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "websocket" in t or "subscribe" in t:
        return (
            "WebSocket event streaming:\n"
            "  Connect to ws://rpc.tenzro.network and call eth_subscribe.\n"
            "  Supported subscriptions:\n"
            "    - newHeads (new blocks)\n"
            "    - logs (contract events, with optional address/topics filter)\n"
            "    - pendingTransactions"
        )

    if "webhook" in t:
        return (
            "Webhook registration:\n"
            "  Provide a callback URL, event filter, and optional contract address.\n"
            "  Webhooks are signed with HMAC-SHA256 for verification.\n"
            "  Example: 'Register webhook at https://myapp.com/hook for transfers on 0xabc...'"
        )

    if "histor" in t or "query" in t:
        addr = _extract_address(text)
        if addr:
            return (
                f"To query historical events for {addr}:\n"
                f"  Use eth_getLogs with the contract address and block range."
            )
        return "Provide a contract address to query historical events."

    return (
        "Event streaming options:\n"
        "  - 'Subscribe to new block events via WebSocket'\n"
        "  - 'Register a webhook for transfer events'\n"
        "  - 'Query historical events for contract 0xabc...'\n"
        "  - 'Stream pending transactions in real time'"
    )


# ---------------------------------------------------------------------------
# Canton / DAML
# ---------------------------------------------------------------------------

async def handle_canton(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "domain" in t:
        result = await rpc_call("tenzro_listCantonDomains", [])
        return f"Canton domains:\n{json.dumps(result, indent=2)}"

    if "contract" in t:
        result = await rpc_call("tenzro_listDamlContracts", [])
        return f"DAML contracts:\n{json.dumps(result, indent=2)}"

    if "submit" in t or "command" in t:
        return (
            "To submit a DAML command, provide:\n"
            "  - Command type: create or exercise\n"
            "  - Template ID (for create)\n"
            "  - Contract ID (for exercise)\n"
            "  - Payload (JSON)\n"
            "Use the Canton MCP server at canton-mcp.tenzro.network/mcp for full access."
        )

    return (
        "Canton / DAML operations:\n"
        "  - 'List Canton domains'\n"
        "  - 'List DAML contracts'\n"
        "  - 'Submit a DAML command'"
    )


# ---------------------------------------------------------------------------
# Task Marketplace
# ---------------------------------------------------------------------------

async def handle_task_marketplace(text: str, metadata: dict = None) -> str:
    t = text.lower()
    task_id = _extract_id(text)

    if "post" in t or "create" in t:
        amount = _extract_amount(text)
        return (
            "To post a task to the marketplace, provide:\n"
            f"  - Description of the task\n"
            f"  - Budget: {amount or '?'} TNZO\n"
            f"  - Category (inference, code-review, data-analysis, etc.)\n"
            f"  - Deadline (optional)\n"
            "The budget is held in escrow until task completion."
        )

    if "cancel" in t and task_id:
        result = await rpc_call("tenzro_cancelTask", [task_id])
        return f"Task canceled: {task_id}\n{json.dumps(result, indent=2)}"

    if "quote" in t and task_id:
        amount = _extract_amount(text)
        if amount:
            result = await rpc_call("tenzro_quoteTask", [task_id, str(amount)])
            return f"Quote submitted for task {task_id}: {amount} TNZO\n{json.dumps(result, indent=2)}"
        return f"Provide a quote amount for task {task_id}.\nExample: 'Submit a quote of 50 TNZO for task {task_id}'"

    if task_id:
        result = await rpc_call("tenzro_getTask", [task_id])
        return f"Task details:\n{json.dumps(result, indent=2)}"

    # Default: list tasks
    result = await rpc_call("tenzro_listTasks", [])
    if not result:
        return "No tasks currently listed on the marketplace."
    lines = ["Task marketplace:"]
    for task in result:
        lines.append(
            f"  - [{task.get('status', '?')}] {task.get('title', 'Untitled')} | "
            f"Budget: {task.get('budget', '?')} TNZO | "
            f"ID: {task.get('id', '')}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent Marketplace
# ---------------------------------------------------------------------------

async def handle_agent_marketplace(text: str, metadata: dict = None) -> str:
    t = text.lower()
    template_id = _extract_id(text)

    if "register" in t or "publish" in t:
        return (
            "To register an agent template, provide:\n"
            "  - Name\n"
            "  - Description\n"
            "  - Capabilities (list)\n"
            "  - Pricing model (per-task, per-hour, subscription)\n"
            "  - Agent type (autonomous, semi-autonomous, tool)"
        )

    if "rate" in t and template_id:
        # Try to extract rating
        rating_match = re.search(r"(\d)\s*star", text)
        rating = int(rating_match.group(1)) if rating_match else None
        if rating:
            return f"Rating {rating} stars submitted for template {template_id}."
        return f"Provide a star rating (1-5) for template {template_id}."

    if "spawn" in t and template_id:
        return (
            f"To spawn an agent from template {template_id}:\n"
            f"  This will create a new agent instance with its own DID and wallet.\n"
            f"  The agent inherits all capabilities defined in the template."
        )

    if "stats" in t and template_id:
        result = await rpc_call("tenzro_getAgentTemplate", [template_id])
        return f"Template stats:\n{json.dumps(result, indent=2)}"

    if template_id:
        result = await rpc_call("tenzro_getAgentTemplate", [template_id])
        return f"Agent template:\n{json.dumps(result, indent=2)}"

    if "search" in t:
        query = text.split("search")[-1].strip().rstrip("?.!,;") if "search" in t else ""
        result = await rpc_call("tenzro_listAgentTemplates", [])
        if not result:
            return "No agent templates found."
        lines = [f"Agent templates matching '{query}':"] if query else ["Available agent templates:"]
        for tmpl in result:
            lines.append(
                f"  - {tmpl.get('name', 'Unnamed')} | "
                f"Type: {tmpl.get('agent_type', '?')} | "
                f"ID: {tmpl.get('id', '')}"
            )
        return "\n".join(lines)

    # Default: list
    result = await rpc_call("tenzro_listAgentTemplates", [])
    if not result:
        return "No agent templates registered on the marketplace."
    lines = ["Available agent templates:"]
    for tmpl in result:
        lines.append(
            f"  - {tmpl.get('name', 'Unnamed')} | "
            f"Type: {tmpl.get('agent_type', '?')} | "
            f"ID: {tmpl.get('id', '')}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent Spawning
# ---------------------------------------------------------------------------

async def handle_agent_spawning(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "list" in t and ("child" in t or "agent" in t):
        result = await rpc_call("tenzro_listAgentTemplates", [])
        return f"Spawned agents:\n{json.dumps(result, indent=2)}"

    if "spawn" in t:
        # Try to extract agent name
        name_match = re.search(r"(?:named?|called)\s+['\"]?(\w+)['\"]?", text, re.IGNORECASE)
        name = name_match.group(1) if name_match else "sub-agent"
        # Try to extract capabilities
        cap_match = re.search(r"(?:with|capability|capabilities)\s+(.+?)(?:\.|$)", text, re.IGNORECASE)
        capabilities = cap_match.group(1).strip().rstrip("?.!,;") if cap_match else "general"

        return (
            f"Agent spawn request:\n"
            f"  Name: {name}\n"
            f"  Capabilities: {capabilities}\n"
            f"\n"
            f"Each spawned agent receives:\n"
            f"  - Its own TDIP DID (did:tenzro:machine:...)\n"
            f"  - MPC wallet (2-of-3 threshold)\n"
            f"  - Delegation scope from parent\n"
            f"  - Max 50 child agents per parent\n"
            f"\n"
            f"Use the A2A protocol or tenzro_registerAgent RPC for programmatic spawning."
        )

    if "run" in t or "task" in t:
        return (
            "To run an autonomous agent task:\n"
            "  - Spawn or select an agent\n"
            "  - Submit a task description\n"
            "  - The agent executes autonomously within its delegation scope\n"
            "  - Results are returned via A2A protocol"
        )

    return (
        "Agent spawning operations:\n"
        "  - 'Spawn a sub-agent with coding capabilities'\n"
        "  - 'Spawn an agent named researcher with web-search capability'\n"
        "  - 'List my child agents'\n"
        "  - 'Run an autonomous agent task'"
    )


# ---------------------------------------------------------------------------
# Swarm Orchestration
# ---------------------------------------------------------------------------

async def handle_swarm(text: str, metadata: dict = None) -> str:
    t = text.lower()
    swarm_id = _extract_id(text)

    if "create" in t:
        count_match = re.search(r"(\d+)\s*(?:agent|member|worker)", text)
        count = int(count_match.group(1)) if count_match else 3
        return (
            f"Swarm creation request:\n"
            f"  Members: {count}\n"
            f"\n"
            f"Each swarm member gets its own DID and wallet.\n"
            f"The orchestrator can broadcast tasks to all members simultaneously.\n"
            f"Use tenzro_createSwarm RPC for programmatic creation."
        )

    if "status" in t and swarm_id:
        return (
            f"To get swarm status for {swarm_id}:\n"
            f"  Use tenzro_getSwarm RPC with the swarm ID."
        )

    if "terminat" in t and swarm_id:
        return (
            f"To terminate swarm {swarm_id}:\n"
            f"  Use tenzro_terminateSwarm RPC. This will:\n"
            f"  - Stop all member agents\n"
            f"  - Settle any pending payments\n"
            f"  - Archive the swarm state"
        )

    if "broadcast" in t:
        return (
            "To broadcast a task to all swarm members:\n"
            "  Provide the swarm ID and task description.\n"
            "  All members execute in parallel; results are aggregated."
        )

    return (
        "Swarm orchestration:\n"
        "  - 'Create a swarm with 3 research agents'\n"
        "  - 'Get swarm status for swarm-id-123'\n"
        "  - 'Terminate swarm swarm-id-456'\n"
        "  - 'Broadcast a task to my swarm'"
    )


# ---------------------------------------------------------------------------
# deBridge
# ---------------------------------------------------------------------------

async def handle_debridge(text: str, metadata: dict = None) -> str:
    t = text.lower()
    if "chain" in t or "supported" in t or "network" in t:
        result = await rpc_call("tenzro_debridgeGetChains", {})
        if isinstance(result, dict):
            chains = result.get("chains", result)
            if isinstance(chains, list):
                lines = [f"deBridge supported chains ({len(chains)}):"]
                for c in chains[:20]:
                    name = c.get("name", c.get("chainName", "?"))
                    cid = c.get("chainId", c.get("id", "?"))
                    lines.append(f"  - {name} (chainId: {cid})")
                return "\n".join(lines)
        return json.dumps(result, indent=2)
    if "search" in t or "find token" in t:
        words = text.split()
        query = words[-1] if len(words) > 1 else "USDC"
        result = await rpc_call("tenzro_debridgeSearchTokens", {"query": query})
        return json.dumps(result, indent=2)
    if "instruction" in t:
        result = await rpc_call("tenzro_debridgeGetInstructions", {})
        return json.dumps(result, indent=2)
    if "swap" in t and "same" in t:
        return "To do a same-chain swap via deBridge, provide: chain_id, token_in address, token_out address, and amount."
    return ("deBridge DLN cross-chain operations:\n"
            "  - 'debridge chains' — list supported networks\n"
            "  - 'debridge search USDC' — find token addresses\n"
            "  - 'debridge instructions' — operational guidance\n"
            "  - 'debridge create tx' — create cross-chain transfer\n"
            "  - 'debridge same chain swap' — swap on same chain")


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

async def handle_crypto(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "sign" in t:
        return (
            "To sign a message, provide:\n"
            "  - Private key (hex)\n"
            "  - Message (hex)\n"
            "  - Key type: ed25519 or secp256k1\n"
            "Use the MCP server's sign_message tool for programmatic signing."
        )

    if "verify" in t:
        return (
            "To verify a signature, provide:\n"
            "  - Public key (hex)\n"
            "  - Message (hex)\n"
            "  - Signature (hex)\n"
            "  - Key type: ed25519 or secp256k1"
        )

    if "encrypt" in t:
        return (
            "To encrypt data with AES-256-GCM, provide:\n"
            "  - Plaintext data (hex)\n"
            "  - Encryption key (hex, 32 bytes)\n"
            "Returns ciphertext with nonce and authentication tag."
        )

    if "decrypt" in t:
        return (
            "To decrypt AES-256-GCM data, provide:\n"
            "  - Ciphertext (hex, includes nonce + tag)\n"
            "  - Decryption key (hex, 32 bytes)"
        )

    if "keccak" in t:
        result = await rpc_call("tenzro_hashKeccak256", {"data_hex": "0x"})
        return f"Keccak-256 hash result:\n{json.dumps(result, indent=2)}"

    if "sha" in t or "hash" in t:
        result = await rpc_call("tenzro_hashSha256", {"data_hex": "0x"})
        return f"SHA-256 hash result:\n{json.dumps(result, indent=2)}"

    if "key exchange" in t or "x25519" in t or "diffie" in t:
        return (
            "X25519 key exchange requires:\n"
            "  - Your private key (hex)\n"
            "  - Peer's public key (hex)\n"
            "Returns a shared secret for deriving encryption keys."
        )

    if "keygen" in t or "generate" in t or "keypair" in t:
        key_type = "secp256k1" if "secp" in t else "ed25519"
        result = await rpc_call("tenzro_generateKeypair", {"key_type": key_type})
        return f"Generated {key_type} keypair:\n{json.dumps(result, indent=2)}"

    return (
        "Cryptographic operations:\n"
        "  - 'Sign a message with ed25519'\n"
        "  - 'Verify a signature'\n"
        "  - 'Encrypt data with AES-256-GCM'\n"
        "  - 'Decrypt data'\n"
        "  - 'Hash data with SHA-256'\n"
        "  - 'Hash data with Keccak-256'\n"
        "  - 'Generate a keypair'\n"
        "  - 'X25519 key exchange'"
    )


# ---------------------------------------------------------------------------
# TEE
# ---------------------------------------------------------------------------

async def handle_tee(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "detect" in t:
        result = await rpc_call("tenzro_detectTee", [])
        return f"TEE hardware detection:\n{json.dumps(result, indent=2)}"

    if "attest" in t or "quote" in t:
        provider = "auto"
        if "tdx" in t:
            provider = "tdx"
        elif "sev" in t or "snp" in t:
            provider = "sev-snp"
        elif "nitro" in t:
            provider = "nitro"
        elif "gpu" in t or "nvidia" in t:
            provider = "gpu"
        result = await rpc_call("tenzro_getTeeAttestation", {"provider": provider})
        return f"TEE attestation ({provider}):\n{json.dumps(result, indent=2)}"

    if "seal" in t and "unseal" not in t:
        return (
            "To seal data inside a TEE enclave, provide:\n"
            "  - Plaintext data (hex)\n"
            "  - Key ID for hardware-bound encryption\n"
            "Sealed data can only be unsealed on the same hardware."
        )

    if "unseal" in t:
        return (
            "To unseal TEE-sealed data, provide:\n"
            "  - Ciphertext (hex)\n"
            "  - Key ID used during sealing\n"
            "Must run on the same hardware that sealed the data."
        )

    if "provider" in t or "list" in t:
        result = await rpc_call("tenzro_listTeeProviders", [])
        return f"TEE providers:\n{json.dumps(result, indent=2)}"

    return (
        "TEE (Trusted Execution Environment) operations:\n"
        "  - 'Detect TEE hardware'\n"
        "  - 'Get TEE attestation'\n"
        "  - 'Seal data in enclave'\n"
        "  - 'Unseal enclave data'\n"
        "  - 'List TEE providers'\n"
        "Supported: Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC"
    )


# ---------------------------------------------------------------------------
# Custody
# ---------------------------------------------------------------------------

async def handle_custody(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "create" in t or "new" in t:
        result = await rpc_call("tenzro_createMpcWallet", {"threshold": 2, "total_shares": 3, "key_type": "ed25519"})
        return f"MPC wallet created:\n{json.dumps(result, indent=2)}"

    if "export" in t:
        addr = _extract_address(text)
        if addr:
            return (
                f"To export keystore for {addr}:\n"
                f"  Provide a password to encrypt the keystore file.\n"
                f"  Uses Argon2id KDF (64MB memory, 3 iterations)."
            )
        return "Provide a wallet address to export. Example: 'Export keystore for 0xabc...'"

    if "import" in t:
        return (
            "To import a keystore:\n"
            "  - Provide the encrypted keystore JSON\n"
            "  - Provide the decryption password\n"
            "  The wallet will be restored with its MPC key shares."
        )

    if "rotate" in t:
        addr = _extract_address(text)
        if addr:
            return f"Key rotation for {addr} refreshes MPC shares without changing the address."
        return "Provide a wallet address to rotate keys. Example: 'Rotate keys for 0xabc...'"

    if "spending" in t or "limit" in t:
        if "set" in t:
            return (
                "To set spending limits, provide:\n"
                "  - Wallet address\n"
                "  - Daily limit (TNZO)\n"
                "  - Per-transaction limit (TNZO)"
            )
        addr = _extract_address(text)
        if addr:
            result = await rpc_call("tenzro_getSpendingLimits", {"address": addr})
            return f"Spending limits for {addr}:\n{json.dumps(result, indent=2)}"
        return "Provide a wallet address. Example: 'Get spending limits for 0xabc...'"

    if "session" in t:
        if "revoke" in t or "cancel" in t:
            return (
                "To revoke a session key, provide:\n"
                "  - Wallet address\n"
                "  - Session ID"
            )
        return (
            "To create a session key, provide:\n"
            "  - Wallet address\n"
            "  - Duration (seconds)\n"
            "  - Maximum spend amount\n"
            "Session keys enable automated transactions within limits."
        )

    if "share" in t:
        addr = _extract_address(text)
        if addr:
            result = await rpc_call("tenzro_getKeyShares", {"address": addr})
            return f"Key shares for {addr}:\n{json.dumps(result, indent=2)}"
        return "Provide a wallet address. Example: 'Get key shares for 0xabc...'"

    return (
        "Custody & MPC wallet operations:\n"
        "  - 'Create a new MPC wallet'\n"
        "  - 'Export keystore for 0xabc...'\n"
        "  - 'Import a keystore'\n"
        "  - 'Rotate keys for 0xabc...'\n"
        "  - 'Set spending limits'\n"
        "  - 'Get spending limits for 0xabc...'\n"
        "  - 'Create a session key'\n"
        "  - 'Get key shares for 0xabc...'"
    )


# ---------------------------------------------------------------------------
# ZK Proofs
# ---------------------------------------------------------------------------

async def handle_zk(text: str, metadata: dict = None) -> str:
    t = text.lower()

    if "create" in t or "prove" in t or "generate proof" in t:
        return (
            "To create a Plonky3 STARK proof, provide:\n"
            "  - circuit_id: one of \"inference\", \"settlement\", \"identity\"\n"
            "  - witness fields specific to the circuit (numeric values).\n"
            "Tenzro uses Plonky3 STARKs over the KoalaBear field — no trusted setup, "
            "no proving keys, post-quantum-conjectured soundness."
        )

    if "circuit" in t or "list" in t:
        result = await rpc_call("tenzro_listCircuits", [])
        return f"Available ZK circuits:\n{json.dumps(result, indent=2)}"

    if "verify" in t:
        return (
            "To verify a ZK proof, pass via metadata:\n"
            "  {\"circuit_id\": \"inference|settlement|identity\", "
            "\"proof_bytes\": \"<hex>\", \"public_inputs\": [\"<hex>\", ...]}\n"
            "public_inputs entries are 4-byte little-endian KoalaBear field-element chunks."
        )

    return (
        "Zero-knowledge proof operations (Plonky3 STARKs over KoalaBear):\n"
        "  - 'Create a ZK proof for inference verification'\n"
        "  - 'List ZK circuits'\n"
        "  - 'Verify a ZK proof'\n"
        "Circuits: inference, settlement, identity"
    )


# ---------------------------------------------------------------------------
# AP2 Mandate Verification (Google AP2 spec)
# ---------------------------------------------------------------------------

async def handle_ap2(text: str, metadata: dict = None) -> str:
    """AP2 v0.2 session lifecycle + mandate verification (Checkout/Payment VDCs)."""
    t = text.lower()

    # Protocol info
    if "protocol" in t or "info" in t or "version" in t or "supported" in t:
        result = await rpc_call("tenzro_ap2ProtocolInfo", [])
        return f"AP2 protocol info:\n{json.dumps(result, indent=2)}"

    # Sign a Checkout or Payment mandate via the auth-bound wallet
    if "sign" in t and ("mandate" in t or "vdc" in t or "checkout" in t or "payment" in t):
        md = metadata or {}
        mandate_kind = md.get("mandate_kind")
        mandate = md.get("mandate")
        signer_did = md.get("signer_did") or _extract_did(text)
        if mandate_kind not in ("checkout", "payment") or mandate is None or not signer_did:
            return (
                "To sign an AP2 v0.2 mandate, provide:\n"
                "  metadata.mandate_kind  ('checkout' | 'payment')\n"
                "  metadata.mandate       (full CheckoutMandate or PaymentMandate JSON)\n"
                "  metadata.signer_did    (must match the auth-bound wallet's controller DID)\n"
                "Auth: DPoP+JWT mandatory. Wallet must be Ed25519 (AP2 v0.2)."
            )
        result = await rpc_call(
            "tenzro_ap2SignMandate",
            [{"mandate_kind": mandate_kind, "mandate": mandate, "signer_did": signer_did}],
        )
        return f"AP2 mandate signed:\n{json.dumps(result, indent=2)}"

    # Verify a single mandate VDC - requires JSON in metadata
    if "verify" in t and ("mandate" in t or "vdc" in t):
        vdc = (metadata or {}).get("vdc")
        if vdc is None:
            return (
                "To verify an AP2 mandate, send the full VDC envelope as "
                "`metadata.vdc` (JSON-LD VC with proof).\n"
                "Supports CheckoutMandate and PaymentMandate per AP2 v0.2."
            )
        result = await rpc_call("tenzro_ap2VerifyMandate", [{"vdc": vdc}])
        return f"AP2 mandate verification:\n{json.dumps(result, indent=2)}"

    # Validate Checkout+Payment pair
    if ("validate" in t or "pair" in t) and ("checkout" in t or "payment" in t):
        md = metadata or {}
        checkout_vdc = md.get("checkout_vdc") or md.get("checkout")
        payment_vdc = md.get("payment_vdc") or md.get("payment")
        # `metadata.enforce_delegation` (bool) opts into the TDIP gate:
        # AP2 validates the payment, then `IdentityRegistry::enforce_operation`
        # checks the agent's DelegationScope against the payment total.
        enforce_delegation = bool(md.get("enforce_delegation", False))
        if checkout_vdc is None or payment_vdc is None:
            return (
                "To validate an AP2 v0.2 mandate pair, send both VDCs as "
                "`metadata.checkout_vdc` and `metadata.payment_vdc`.\n"
                "Set `metadata.enforce_delegation = true` to additionally "
                "enforce the agent's TDIP DelegationScope against the payment total.\n"
                "The node verifies each VDC and cross-checks checkout↔payment consistency."
            )
        result = await rpc_call(
            "tenzro_ap2ValidateMandatePair",
            [{
                "checkout_vdc": checkout_vdc,
                "payment_vdc": payment_vdc,
                "enforce_delegation": enforce_delegation,
            }],
        )
        return f"AP2 Checkout/Payment pair validation:\n{json.dumps(result, indent=2)}"

    # Session lifecycle
    session_id = _extract_id(text)
    md = metadata or {}

    if "create" in t and "session" in t:
        agent_did = md.get("agent_did") or _extract_did(text)
        provider_did = md.get("provider_did")
        service = md.get("service", "default")
        amount = md.get("max_amount") or _extract_amount(text)
        asset = md.get("asset", "TNZO")
        if agent_did and provider_did and amount is not None:
            result = await rpc_call(
                "tenzro_ap2CreateSession",
                [{
                    "agent_did": agent_did,
                    "provider_did": provider_did,
                    "service": service,
                    "max_amount": str(amount),
                    "asset": asset,
                }],
            )
            return f"AP2 session created:\n{json.dumps(result, indent=2)}"
        return (
            "To create an AP2 session, provide:\n"
            "  metadata.agent_did, metadata.provider_did, metadata.max_amount\n"
            "  metadata.service (optional), metadata.asset (default TNZO)"
        )

    if "authorize" in t and session_id:
        amount = _extract_amount(text) or md.get("amount")
        if amount is None:
            return f"Provide an amount to authorize for session {session_id}."
        result = await rpc_call(
            "tenzro_ap2AuthorizePayment",
            [{"session_id": session_id, "amount": str(amount)}],
        )
        return f"AP2 authorization:\n{json.dumps(result, indent=2)}"

    if "execute" in t and session_id:
        auth_id = md.get("authorization_id") or _extract_id(text)
        if not auth_id:
            return f"Provide authorization_id in metadata to execute on session {session_id}."
        result = await rpc_call(
            "tenzro_ap2ExecutePayment",
            [{"session_id": session_id, "authorization_id": auth_id}],
        )
        return f"AP2 execution receipt:\n{json.dumps(result, indent=2)}"

    if "cancel" in t and session_id:
        result = await rpc_call(
            "tenzro_ap2CancelSession", [{"session_id": session_id}]
        )
        return f"AP2 session cancelled:\n{json.dumps(result, indent=2)}"

    if session_id:
        result = await rpc_call(
            "tenzro_ap2GetSession", [{"session_id": session_id}]
        )
        return f"AP2 session:\n{json.dumps(result, indent=2)}"

    if "list" in t:
        agent_did = md.get("agent_did") or _extract_did(text)
        if agent_did:
            result = await rpc_call(
                "tenzro_ap2ListAgentSessions", [{"agent_did": agent_did}]
            )
            return f"AP2 sessions for {agent_did}:\n{json.dumps(result, indent=2)}"
        return "Provide an agent DID (metadata.agent_did) to list sessions."

    return (
        "AP2 (Agentic Payment Protocol) operations:\n"
        "  - 'AP2 protocol info' — version, supported mandate types & DID methods\n"
        "  - 'Create AP2 session' (needs metadata.agent_did, provider_did, max_amount)\n"
        "  - 'Authorize <amount> on session <id>'\n"
        "  - 'Execute session <id>' (needs metadata.authorization_id)\n"
        "  - 'Cancel session <id>' / 'Get session <id>' / 'List sessions'\n"
        "  - 'Verify AP2 mandate' (send metadata.vdc)\n"
        "  - 'Validate AP2 checkout/payment pair' (metadata.checkout_vdc + payment_vdc)"
    )


# ---------------------------------------------------------------------------
# ERC-8004 Trustless Agents Registry
# ---------------------------------------------------------------------------

async def handle_erc8004(text: str, metadata: dict = None) -> str:
    """ERC-8004 Trustless Agents Registry — full v0.6+ calldata surface (Identity / Reputation / Validation)."""
    t = text.lower()
    md = metadata or {}

    # ── Identity registry ────────────────────────────────────────────

    if "derive" in t or "agent id" in t or "agentid" in t:
        did = md.get("did")
        if did:
            result = await rpc_call(
                "tenzro_erc8004DeriveAgentId",
                [{"did": did}],
            )
            return f"ERC-8004 agentId:\n{json.dumps(result, indent=2)}"
        return (
            "Derive an ERC-8004 agentId (= keccak256(utf8(did))) with:\n"
            "  metadata.did (Tenzro DID string)"
        )

    if "register" in t:
        did = md.get("did")
        agent_address = md.get("agent_address") or _extract_address(text)
        metadata_uri = md.get("metadata_uri") or md.get("uri")
        if did and agent_address and metadata_uri:
            result = await rpc_call(
                "tenzro_erc8004EncodeRegister",
                [{
                    "did": did,
                    "agent_address": agent_address,
                    "metadata_uri": metadata_uri,
                }],
            )
            return f"ERC-8004 registerAgent calldata:\n{json.dumps(result, indent=2)}"
        return (
            "Encode IdentityRegistry.registerAgent() with:\n"
            "  metadata.did, metadata.agent_address, metadata.metadata_uri"
        )

    if "set agent uri" in t or ("set" in t and "uri" in t):
        agent_id = md.get("agent_id")
        metadata_uri = md.get("metadata_uri") or md.get("uri")
        if agent_id and metadata_uri:
            result = await rpc_call(
                "tenzro_erc8004EncodeSetAgentURI",
                [{"agent_id": agent_id, "metadata_uri": metadata_uri}],
            )
            return f"ERC-8004 setAgentURI calldata:\n{json.dumps(result, indent=2)}"
        return "Encode setAgentURI() with: metadata.agent_id, metadata.metadata_uri"

    if "set agent wallet" in t or ("rotate" in t and "wallet" in t):
        agent_id = md.get("agent_id")
        new_wallet = md.get("new_wallet")
        deadline = md.get("deadline")
        signature = md.get("signature")
        if agent_id and new_wallet and deadline is not None and signature:
            result = await rpc_call(
                "tenzro_erc8004EncodeSetAgentWallet",
                [{
                    "agent_id": agent_id,
                    "new_wallet": new_wallet,
                    "deadline": int(deadline),
                    "signature": signature,
                }],
            )
            return f"ERC-8004 setAgentWallet calldata:\n{json.dumps(result, indent=2)}"
        return (
            "Encode setAgentWallet() with:\n"
            "  metadata.agent_id, metadata.new_wallet, metadata.deadline, metadata.signature"
        )

    if "set metadata" in t:
        agent_id = md.get("agent_id")
        key = md.get("metadata_key") or md.get("key")
        value = md.get("metadata_value") or md.get("value")
        if agent_id and key and value is not None:
            result = await rpc_call(
                "tenzro_erc8004EncodeSetMetadata",
                [{"agent_id": agent_id, "metadata_key": key, "metadata_value": value}],
            )
            return f"ERC-8004 setMetadata calldata:\n{json.dumps(result, indent=2)}"
        return "Encode setMetadata() with: metadata.agent_id, metadata.metadata_key, metadata.metadata_value (hex)"

    if "get metadata" in t:
        agent_id = md.get("agent_id")
        key = md.get("metadata_key") or md.get("key")
        if md.get("return_data"):
            result = await rpc_call(
                "tenzro_erc8004DecodeGetMetadata",
                [{"return_data": md["return_data"]}],
            )
            return f"ERC-8004 metadata (decoded):\n{json.dumps(result, indent=2)}"
        if agent_id and key:
            result = await rpc_call(
                "tenzro_erc8004EncodeGetMetadata",
                [{"agent_id": agent_id, "metadata_key": key}],
            )
            return f"ERC-8004 getMetadata calldata:\n{json.dumps(result, indent=2)}"
        return (
            "Encode getMetadata() with: metadata.agent_id, metadata.metadata_key\n"
            "Decode by passing metadata.return_data (eth_call return)."
        )

    if "get agent uri" in t:
        agent_id = md.get("agent_id")
        if agent_id:
            result = await rpc_call(
                "tenzro_erc8004EncodeGetAgentURI",
                [{"agent_id": agent_id}],
            )
            return f"ERC-8004 getAgentURI calldata:\n{json.dumps(result, indent=2)}"
        return "Provide metadata.agent_id to encode getAgentURI() calldata."

    if "get agent wallet" in t:
        agent_id = md.get("agent_id")
        if agent_id:
            result = await rpc_call(
                "tenzro_erc8004EncodeGetAgentWallet",
                [{"agent_id": agent_id}],
            )
            return f"ERC-8004 getAgentWallet calldata:\n{json.dumps(result, indent=2)}"
        return "Provide metadata.agent_id to encode getAgentWallet() calldata."

    if "get agent" in t or ("get" in t and "agent" in t and "id" in t):
        agent_id = md.get("agent_id")
        if not agent_id and not md.get("return_data"):
            return "Provide metadata.agent_id to encode getAgent() calldata."
        if md.get("return_data"):
            result = await rpc_call(
                "tenzro_erc8004DecodeGetAgent",
                [{"return_data": md["return_data"]}],
            )
            return f"ERC-8004 agent (decoded):\n{json.dumps(result, indent=2)}"
        result = await rpc_call(
            "tenzro_erc8004EncodeGetAgent", [{"agent_id": agent_id}]
        )
        return f"ERC-8004 getAgent calldata:\n{json.dumps(result, indent=2)}"

    # ── Reputation registry ──────────────────────────────────────────

    if "revoke" in t and "feedback" in t:
        agent_id = md.get("agent_id")
        feedback_id = md.get("feedback_id")
        if agent_id and feedback_id:
            result = await rpc_call(
                "tenzro_erc8004EncodeRevokeFeedback",
                [{"agent_id": agent_id, "feedback_id": feedback_id}],
            )
            return f"ERC-8004 revokeFeedback calldata:\n{json.dumps(result, indent=2)}"
        return "Encode revokeFeedback() with: metadata.agent_id, metadata.feedback_id"

    if "append" in t and ("response" in t or "feedback" in t):
        agent_id = md.get("agent_id")
        feedback_id = md.get("feedback_id")
        response_uri = md.get("response_uri") or md.get("uri")
        if agent_id and feedback_id and response_uri:
            result = await rpc_call(
                "tenzro_erc8004EncodeAppendResponse",
                [{
                    "agent_id": agent_id,
                    "feedback_id": feedback_id,
                    "response_uri": response_uri,
                }],
            )
            return f"ERC-8004 appendResponse calldata:\n{json.dumps(result, indent=2)}"
        return "Encode appendResponse() with: metadata.agent_id, metadata.feedback_id, metadata.response_uri"

    if "is" in t and "revoked" in t:
        agent_id = md.get("agent_id")
        feedback_id = md.get("feedback_id")
        if agent_id and feedback_id:
            result = await rpc_call(
                "tenzro_erc8004EncodeIsFeedbackRevoked",
                [{"agent_id": agent_id, "feedback_id": feedback_id}],
            )
            return f"ERC-8004 isFeedbackRevoked calldata:\n{json.dumps(result, indent=2)}"
        return "Encode isFeedbackRevoked() with: metadata.agent_id, metadata.feedback_id"

    if "feedback" in t and "responses" in t:
        agent_id = md.get("agent_id")
        feedback_id = md.get("feedback_id")
        if agent_id and feedback_id:
            result = await rpc_call(
                "tenzro_erc8004EncodeGetFeedbackResponses",
                [{"agent_id": agent_id, "feedback_id": feedback_id}],
            )
            return f"ERC-8004 getFeedbackResponses calldata:\n{json.dumps(result, indent=2)}"
        return "Encode getFeedbackResponses() with: metadata.agent_id, metadata.feedback_id"

    if "feedback count" in t or ("count" in t and "feedback" in t):
        subject = md.get("subject_agent_id") or md.get("agent_id")
        if subject:
            result = await rpc_call(
                "tenzro_erc8004EncodeGetFeedbackCount",
                [{"subject_agent_id": subject}],
            )
            return f"ERC-8004 getFeedbackCount calldata:\n{json.dumps(result, indent=2)}"
        return "Encode getFeedbackCount() with: metadata.subject_agent_id"

    if "get feedback" in t:
        subject = md.get("subject_agent_id") or md.get("agent_id")
        index = md.get("index")
        if subject and index is not None:
            result = await rpc_call(
                "tenzro_erc8004EncodeGetFeedback",
                [{"subject_agent_id": subject, "index": int(index)}],
            )
            return f"ERC-8004 getFeedback calldata:\n{json.dumps(result, indent=2)}"
        return "Encode getFeedback() with: metadata.subject_agent_id, metadata.index"

    if "feedback" in t or "reputation" in t:
        subject = md.get("subject_agent_id") or md.get("agent_id")
        rating = md.get("rating") if md.get("rating") is not None else md.get("score")
        context_uri = md.get("context_uri") or md.get("uri")
        if subject and rating is not None and context_uri:
            result = await rpc_call(
                "tenzro_erc8004EncodeFeedback",
                [{
                    "subject_agent_id": subject,
                    "rating": int(rating),
                    "context_uri": context_uri,
                }],
            )
            return f"ERC-8004 submitFeedback calldata:\n{json.dumps(result, indent=2)}"
        return (
            "Encode submitFeedback() with:\n"
            "  metadata.subject_agent_id, metadata.rating (-100..=100), metadata.context_uri"
        )

    # ── Validation registry ──────────────────────────────────────────

    if "request" in t and "validation" in t:
        validator_address = md.get("validator_address") or md.get("validator_id")
        agent_id = md.get("agent_id")
        request_uri = md.get("request_uri") or md.get("uri")
        request_hash = md.get("request_hash") or md.get("data_hash")
        if validator_address and agent_id and request_uri and request_hash:
            result = await rpc_call(
                "tenzro_erc8004EncodeValidationRequest",
                [{
                    "validator_address": validator_address,
                    "agent_id": agent_id,
                    "request_uri": request_uri,
                    "request_hash": request_hash,
                }],
            )
            return f"ERC-8004 validationRequest calldata:\n{json.dumps(result, indent=2)}"
        return (
            "Encode validationRequest() with:\n"
            "  metadata.validator_address, metadata.agent_id, metadata.request_uri, metadata.request_hash"
        )

    if "get validation" in t:
        request_hash = md.get("request_hash") or md.get("data_hash")
        if request_hash:
            result = await rpc_call(
                "tenzro_erc8004EncodeGetValidation",
                [{"request_hash": request_hash}],
            )
            return f"ERC-8004 getValidation calldata:\n{json.dumps(result, indent=2)}"
        return "Encode getValidation() with: metadata.request_hash"

    if ("submit" in t or "response" in t) and "validation" in t:
        request_hash = md.get("request_hash") or md.get("data_hash")
        response = md.get("response")
        response_uri = md.get("response_uri") or md.get("uri")
        response_hash = md.get("response_hash")
        tag = md.get("tag")
        if request_hash and response is not None and response_uri and response_hash and tag:
            result = await rpc_call(
                "tenzro_erc8004EncodeValidationResponse",
                [{
                    "request_hash": request_hash,
                    "response": response,
                    "response_uri": response_uri,
                    "response_hash": response_hash,
                    "tag": tag,
                }],
            )
            return f"ERC-8004 validationResponse calldata:\n{json.dumps(result, indent=2)}"
        return (
            "Encode validationResponse() with:\n"
            "  metadata.request_hash, metadata.response (0..=100), metadata.response_uri,\n"
            "  metadata.response_hash, metadata.tag"
        )

    return (
        "ERC-8004 Trustless Agents Registry (v0.6+) operations:\n"
        "  Identity:\n"
        "    - 'Derive agent id' (metadata.did)\n"
        "    - 'Register agent' (metadata.did, agent_address, metadata_uri)\n"
        "    - 'Get agent <id>' (metadata.agent_id; pass metadata.return_data to decode)\n"
        "    - 'Set agent uri' / 'set agent wallet' / 'set metadata' / 'get metadata'\n"
        "    - 'Get agent uri' / 'get agent wallet'\n"
        "  Reputation:\n"
        "    - 'Submit feedback' (subject_agent_id, rating -100..=100, context_uri)\n"
        "    - 'Get feedback' / 'get feedback count' / 'revoke feedback'\n"
        "    - 'Append response' / 'is revoked' / 'feedback responses'\n"
        "  Validation:\n"
        "    - 'Request validation' (validator_address, agent_id, request_uri, request_hash)\n"
        "    - 'Submit validation response' (request_hash, response, response_uri, response_hash, tag)\n"
        "    - 'Get validation' (request_hash)"
    )


# ---------------------------------------------------------------------------
# Wormhole Cross-Chain Bridge
# ---------------------------------------------------------------------------

async def handle_wormhole(text: str, metadata: dict = None) -> str:
    """Wormhole chain id lookup, VAA parsing, and token bridging."""
    t = text.lower()
    md = metadata or {}

    if "chain id" in t or "chainid" in t:
        chain = md.get("chain")
        if not chain:
            words = text.strip().split()
            chain = words[-1].rstrip("?.!,;").lower() if words else None
        if chain:
            result = await rpc_call("tenzro_wormholeChainId", [{"chain": chain}])
            return f"Wormhole chain id for {chain}:\n{json.dumps(result, indent=2)}"
        return "Provide a chain name (e.g. 'Wormhole chain id for ethereum')."

    if "vaa" in t or "parse" in t:
        vaa_id = md.get("vaa_id")
        if not vaa_id:
            m = re.search(r"\d+/[0-9a-fA-Fx]+/\d+", text)
            if m:
                vaa_id = m.group(0)
        if vaa_id:
            result = await rpc_call(
                "tenzro_wormholeParseVaaId", [{"vaa_id": vaa_id}]
            )
            return f"Parsed VAA {vaa_id}:\n{json.dumps(result, indent=2)}"
        return (
            "Parse a Wormhole VAA id of the form `<chain>/<emitter>/<sequence>`.\n"
            "Pass as metadata.vaa_id or in the message text."
        )

    if "bridge" in t or "transfer" in t or "send" in t:
        source_chain = md.get("source_chain")
        dest_chain = md.get("dest_chain")
        asset = md.get("asset", "TNZO")
        amount = md.get("amount") or _extract_amount(text)
        sender = md.get("sender")
        recipient = md.get("recipient")
        if source_chain and dest_chain and amount is not None and sender and recipient:
            result = await rpc_call(
                "tenzro_wormholeBridge",
                [{
                    "source_chain": source_chain,
                    "dest_chain": dest_chain,
                    "asset": asset,
                    "amount": str(amount),
                    "sender": sender,
                    "recipient": recipient,
                }],
            )
            return f"Wormhole transfer:\n{json.dumps(result, indent=2)}"
        return (
            "To bridge via Wormhole, provide metadata fields:\n"
            "  source_chain, dest_chain, asset (default TNZO), amount, sender, recipient\n"
            "Example: bridge 100 TNZO from ethereum to solana"
        )

    return (
        "Wormhole cross-chain operations:\n"
        "  - 'Wormhole chain id for ethereum' (or solana, base, arbitrum, optimism)\n"
        "  - 'Parse VAA <chain>/<emitter>/<sequence>'\n"
        "  - 'Bridge <amount> <asset> from <src> to <dst>' (with sender/recipient in metadata)"
    )


# ---------------------------------------------------------------------------
# CCT (Chainlink Cross-Chain Token)
# ---------------------------------------------------------------------------

async def handle_cct(text: str, metadata: dict = None) -> str:
    """TNZO CCT pool registry — Ethereum LockRelease + BurnMint on L2s and Solana."""
    t = text.lower()
    md = metadata or {}

    if "list" in t or "all" in t or "pools" in t:
        result = await rpc_call("tenzro_cctListPools", [{}])
        pools = result.get("pools", []) if isinstance(result, dict) else []
        if not pools:
            return "No CCT pools registered."
        lines = [f"TNZO CCT pools ({result.get('count', len(pools))}):"]
        for p in pools:
            lines.append(
                f"  - {p.get('chain_id', '?')} | {p.get('pool_type', '?')} | "
                f"pool: {p.get('pool_address', '?')} | "
                f"selector: {p.get('chain_selector', '?')}"
            )
        return "\n".join(lines)

    chain = md.get("chain")
    if not chain:
        for candidate in ("ethereum", "base", "arbitrum", "optimism", "solana"):
            if candidate in t:
                chain = candidate
                break
    if chain:
        result = await rpc_call("tenzro_cctGetPool", [{"chain": chain}])
        return f"TNZO CCT pool on {chain}:\n{json.dumps(result, indent=2)}"

    return (
        "TNZO CCT (Chainlink Cross-Chain Token) pool registry:\n"
        "  - 'List CCT pools' — show all registered pools\n"
        "  - 'Get CCT pool on ethereum' — Ethereum uses LockRelease\n"
        "  - 'Get CCT pool on base|arbitrum|optimism|solana' — BurnMint pools"
    )


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Authentication (OAuth 2.1 + DPoP onboarding, refresh, link wallet)
# ---------------------------------------------------------------------------

async def handle_auth(text: str, metadata: dict = None) -> str:
    """OAuth 2.1 + DPoP auth flows: onboard human/agent, refresh access tokens,
    link an existing MPC wallet to a new auth session.

    Token shape: HS256 access tokens (1h TTL) + opaque UUID refresh tokens
    (30-day TTL). DPoP binding via RFC 7638 SHA-256 thumbprint of the
    client-held P-256/Ed25519 public key — pass the thumbprint as
    `metadata.dpop_jkt` to bind the token to a key the client controls.
    """
    t = text.lower()
    md = metadata or {}
    dpop_jkt = md.get("dpop_jkt", "")
    ttl_secs = md.get("ttl_secs")

    if "refresh" in t:
        token = md.get("refresh_token")
        if not token:
            return (
                "To refresh, supply metadata.refresh_token (and optionally "
                "metadata.dpop_jkt to bind the new access token).\n"
                "Example: 'Refresh my access token' with "
                "metadata={refresh_token: '...', dpop_jkt: '...'}"
            )
        params = {"refresh_token": token}
        if dpop_jkt:
            params["dpop_jkt"] = dpop_jkt
        result = await rpc_call("tenzro_refreshToken", [params])
        return json.dumps(result, indent=2)

    if "link" in t and "wallet" in t:
        wallet_id = md.get("wallet_id")
        if not wallet_id:
            return (
                "To link a wallet for auth, supply metadata.wallet_id.\n"
                "Optional: metadata.dpop_jkt, metadata.display_name, "
                "metadata.ttl_secs."
            )
        params = {"wallet_id": wallet_id}
        if dpop_jkt:
            params["dpop_jkt"] = dpop_jkt
        if md.get("display_name"):
            params["display_name"] = md["display_name"]
        if ttl_secs:
            params["ttl_secs"] = ttl_secs
        result = await rpc_call("tenzro_linkWalletForAuth", [params])
        return json.dumps(result, indent=2)

    if "human" in t or ("onboard" in t and "agent" not in t):
        display_name = md.get("display_name") or _extract_name(text)
        params = {"display_name": display_name}
        if dpop_jkt:
            params["dpop_jkt"] = dpop_jkt
        if ttl_secs:
            params["ttl_secs"] = ttl_secs
        result = await rpc_call("tenzro_onboardHuman", [params])
        return json.dumps(result, indent=2)

    if "delegated" in t or ("agent" in t and "controller" in t):
        controller_did = md.get("controller_did")
        capabilities = md.get("capabilities", [])
        delegation_scope = md.get("delegation_scope", {})
        if not controller_did:
            return (
                "To onboard a delegated agent, supply metadata.controller_did "
                "(the human DID granting authority), plus optional "
                "metadata.capabilities and metadata.delegation_scope."
            )
        params = {
            "controller_did": controller_did,
            "capabilities": capabilities,
            "delegation_scope": delegation_scope,
        }
        if dpop_jkt:
            params["dpop_jkt"] = dpop_jkt
        result = await rpc_call("tenzro_onboardDelegatedAgent", [params])
        return json.dumps(result, indent=2)

    if "autonomous" in t or ("agent" in t and "bond" in t):
        bond_funding_address = md.get("bond_funding_address")
        if not bond_funding_address:
            return (
                "To onboard an autonomous agent, supply "
                "metadata.bond_funding_address (the funded wallet that pays "
                "the autonomy bond)."
            )
        params = {"bond_funding_address": bond_funding_address}
        if dpop_jkt:
            params["dpop_jkt"] = dpop_jkt
        result = await rpc_call("tenzro_onboardAutonomousAgent", [params])
        return json.dumps(result, indent=2)

    if "exchange" in t:
        # RFC 8693 OAuth 2.0 Token Exchange — mint a narrower child JWT
        # bound to a different DPoP key with a strict subset of the
        # parent's RAR + AAP capabilities.
        subject_token = md.get("subject_token")
        child_bearer_did = md.get("child_bearer_did")
        child_dpop_jkt = md.get("child_dpop_jkt")
        if not (subject_token and child_bearer_did and child_dpop_jkt):
            return (
                "To exchange a token, supply metadata.subject_token (parent "
                "JWT), metadata.child_bearer_did (DID for the child token's "
                "sub), metadata.child_dpop_jkt (RFC 7638 thumbprint the "
                "child binds to). Optional: metadata.requested_rar (RFC 9396 "
                "scope envelope), metadata.requested_aap_capabilities (AAP "
                "capability list), metadata.requested_ttl_secs."
            )
        params = {
            "subject_token": subject_token,
            "child_bearer_did": child_bearer_did,
            "child_dpop_jkt": child_dpop_jkt,
            "requested_rar": md.get("requested_rar", {}),
            "requested_aap_capabilities": md.get(
                "requested_aap_capabilities", []
            ),
        }
        if md.get("requested_ttl_secs"):
            params["requested_ttl_secs"] = md["requested_ttl_secs"]
        result = await rpc_call("tenzro_exchangeToken", [params])
        return json.dumps(result, indent=2)

    if "introspect" in t:
        # RFC 7662 OAuth 2.0 Token Introspection.
        token = md.get("token")
        if not token:
            return (
                "To introspect a token, supply metadata.token (the JWT to "
                "validate). Returns the full claim set on success or "
                '{"active": false} per RFC 7662 §2.2 if inactive.'
            )
        result = await rpc_call("tenzro_introspectToken", [{"token": token}])
        return json.dumps(result, indent=2)

    if "discovery" in t or "well-known" in t or "metadata" in t:
        # RFC 8414 OAuth Authorization Server Metadata.
        result = await rpc_call("tenzro_oauthDiscovery", [])
        return json.dumps(result, indent=2)

    return (
        "Auth operations:\n"
        "  - 'Onboard human Alice'                    (tenzro_onboardHuman)\n"
        "  - 'Onboard delegated agent'                (metadata.controller_did, capabilities, delegation_scope)\n"
        "  - 'Onboard autonomous agent'               (metadata.bond_funding_address)\n"
        "  - 'Refresh my access token'                (metadata.refresh_token, optional dpop_jkt)\n"
        "  - 'Link wallet for auth'                   (metadata.wallet_id, optional dpop_jkt/display_name/ttl_secs)\n"
        "  - 'Exchange token'                         (metadata.subject_token, child_bearer_did, child_dpop_jkt, requested_rar, requested_aap_capabilities) -- RFC 8693\n"
        "  - 'Introspect token'                       (metadata.token) -- RFC 7662\n"
        "  - 'Discovery' or 'well-known metadata'     -- RFC 8414 AS metadata\n"
        "\n"
        "All flows accept metadata.dpop_jkt -- RFC 7638 SHA-256 thumbprint\n"
        "of a client-held P-256/Ed25519 public key. Pass it to bind the\n"
        "issued access token to a key the client controls."
    )


async def handle_help(text: str, metadata: dict = None) -> str:
    return (
        "Tenzro Network Agent -- 23 skills available:\n"
        "\n"
        "  Blockchain:\n"
        "    wallet     - Create wallets, check balances, send TNZO\n"
        "    identity   - Register/resolve DIDs, manage usernames\n"
        "    staking    - Stake TNZO, manage validators/providers\n"
        "    token      - Create ERC-20 tokens, cross-VM transfers\n"
        "    contract   - Deploy smart contracts (EVM/SVM/DAML)\n"
        "    nft        - NFT collections (ERC-721/1155)\n"
        "    bridge     - Cross-chain via LayerZero/CCIP/deBridge\n"
        "\n"
        "  AI & Agents:\n"
        "    inference   - Route AI inference requests\n"
        "    task_marketplace - Post/browse AI tasks with escrow\n"
        "    agent_marketplace - Discover/spawn agent templates\n"
        "    agent_spawning - Spawn autonomous sub-agents\n"
        "    swarm       - Orchestrate agent swarms\n"
        "\n"
        "  Payments & Settlement:\n"
        "    settlement  - Micropayment channels, escrow\n"
        "    ap2-payments - Agent-to-agent payments\n"
        "    payment     - MPP/x402 payment challenges\n"
        "\n"
        "  Security & Compliance:\n"
        "    crypto       - Sign, verify, encrypt, decrypt, hash, keygen\n"
        "    tee          - TEE detection, attestation, seal/unseal data\n"
        "    zk           - ZK proof creation, verification, circuits\n"
        "    custody      - MPC wallets, keystore, sessions, limits\n"
        "    verification - ZK proofs, TEE attestations\n"
        "    compliance   - ERC-3643 T-REX KYC\n"
        "    crosschain   - ERC-7802 cross-chain tokens\n"
        "\n"
        "  Infrastructure:\n"
        "    join    - Join as MicroNode (zero-install onboarding)\n"
        "    auth    - OAuth 2.1 + DPoP onboard/refresh/link-wallet\n"
        "    events  - WebSocket/webhook event streaming\n"
        "\n"
        "Try: 'Check my TNZO balance for 0xabc...'\n"
        "     'Join the Tenzro Network as Alice'\n"
        "     'List available AI models'"
    )


# ---------------------------------------------------------------------------
# Lifecycle (kill-switch)
# ---------------------------------------------------------------------------

async def handle_lifecycle(text: str, metadata: dict = None) -> str:
    t = text.lower()
    agent_did = _extract_id(text)

    if "pause" in t:
        return (
            f"Pause agent {agent_did or '<agent-did>'}:\n"
            f"  Sign and submit a PauseAgent transaction via tenzro_signAndSendTransaction.\n"
            f"  Reversible: halts A2A messaging and inference dispatch but preserves stake.\n"
            f"  Required fields: agent_did, controller_did, reason.\n"
            f"  Gas: 60000."
        )

    if "quarantin" in t:
        return (
            f"Quarantine agent {agent_did or '<agent-did>'}:\n"
            f"  Sign and submit a QuarantineAgent transaction via tenzro_signAndSendTransaction.\n"
            f"  Reversible: halts messaging AND freezes stake (blocks unstake/withdraw).\n"
            f"  Required fields: agent_did, controller_did, reason.\n"
            f"  Optional: 32-byte evidence_hash for off-chain audit linkage.\n"
            f"  Gas: 90000."
        )

    if "terminat" in t or "kill" in t:
        cascade_hint = " with cascade" if "cascade" in t or "descend" in t else ""
        return (
            f"Terminate agent {agent_did or '<agent-did>'}{cascade_hint}:\n"
            f"  Sign and submit a TerminateAgent transaction via tenzro_signAndSendTransaction.\n"
            f"  TERMINAL — irreversible.\n"
            f"  Required fields: agent_did, controller_did, reason.\n"
            f"  Optional: evidence_hash, slash_bps (0-10000), cascade (bool).\n"
            f"  Gas: 120000."
        )

    if "receipt" in t or "list" in t or "history" in t or "audit" in t:
        return (
            "Kill-switch receipts are persisted on-chain and queryable by:\n"
            "  - tenzro_listKillSwitchReceiptsByAgent\n"
            "  - tenzro_listKillSwitchReceiptsByController\n"
            "  - tenzro_getKillSwitchReceipt\n"
            "Each receipt records the action (Pause/Quarantine/Terminate), agent_did,\n"
            "controller_did, reason, evidence_hash, slash_bps, cascade flag,\n"
            "frozen_at_block, and tx_hash."
        )

    return (
        "Agent lifecycle (kill-switch) — three-tier intervention:\n"
        "  - 'Pause agent <did>'           (reversible halt)\n"
        "  - 'Quarantine agent <did>'      (halt + freeze stake)\n"
        "  - 'Terminate agent <did>'       (irreversible; optional slash + cascade)\n"
        "  - 'List kill-switch receipts'   (audit trail)\n"
        "All operations require the controller's signed transaction via\n"
        "tenzro_signAndSendTransaction. EU AI Act Article 14/16 compliant."
    )


# ---------------------------------------------------------------------------
# Handler dispatch table
# ---------------------------------------------------------------------------

HANDLERS: dict[str, callable] = {
    "wallet": handle_wallet,
    "block": handle_block,
    "status": handle_status,
    "network": handle_network,
    "faucet": handle_faucet,
    "identity": handle_identity,
    "inference": handle_inference,
    "staking": handle_staking,
    "provider": handle_provider,
    "payment": handle_payment,
    "verification": handle_verification,
    "bridge": handle_bridge,
    "join": handle_join,
    "list_tokens": handle_list_tokens,
    "create_token": handle_create_token,
    "token_info": handle_token_info,
    "token_balance": handle_token_balance,
    "cross_vm_transfer": handle_cross_vm_transfer,
    "svm_cross_vm_info": handle_svm_cross_vm_info,
    "wrap_tnzo": handle_wrap_tnzo,
    "contract": handle_contract,
    "nft": handle_nft,
    "compliance": handle_compliance,
    "crosschain": handle_crosschain,
    "events": handle_events,
    "canton": handle_canton,
    "task_marketplace": handle_task_marketplace,
    "agent_marketplace": handle_agent_marketplace,
    "agent_spawning": handle_agent_spawning,
    "swarm_orchestration": handle_swarm,
    "lifecycle": handle_lifecycle,
    "debridge": handle_debridge,
    "crypto": handle_crypto,
    "tee": handle_tee,
    "custody": handle_custody,
    "zk": handle_zk,
    "ap2": handle_ap2,
    "erc8004": handle_erc8004,
    "wormhole": handle_wormhole,
    "cct": handle_cct,
    "auth": handle_auth,
    "help": handle_help,
}
