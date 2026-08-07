"""Handler functions for each routed skill.

Every handler accepts the user's natural-language text (and optional metadata)
and returns a plain-text or JSON response string by calling the Tenzro JSON-RPC
or Web API.
"""

import base64
import binascii
import json
import re

from .rpc_client import api_call, rpc_call

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_address(text: str) -> str | None:
    """Extract a hex address from text."""
    m = re.search(r"0x[a-fA-F0-9]+", text)
    return m.group(0) if m else None


def _extract_did(text: str) -> str | None:
    """Extract a did:tenzro:... identifier."""
    m = re.search(r"did:tenzro:\S+", text)
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


async def handle_wallet(text: str, metadata: dict | None = None) -> str:
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

    op = (metadata or {}).get("op")
    if op == "send_self_custody":
        # Self-custody submit: the runner holds its Ed25519 + ML-DSA-65 key
        # locally, builds the canonical Transaction::hash() preimage, and
        # signs both legs itself — the node never sees the secret. This
        # branch forwards the already-signed hex material to
        # eth_sendRawTransaction; it cannot be expressed in free text so it
        # requires a structured metadata payload. Preimage covered by the
        # signatures: chain_id.le || from(32) || to(32) || nonce.le ||
        # gas_limit.le || gas_price.le || timestamp.le ||
        # {"Transfer":{"amount":<value>}} || pq_len.u32.le || pq_public_key,
        # hashed with SHA-256. `timestamp` (ms epoch) MUST match signing time.
        md = metadata or {}
        required = (
            "from",
            "to",
            "value",
            "signature",
            "public_key",
            "pq_signature",
            "pq_public_key",
            "timestamp",
        )
        if not all(md.get(k) is not None and md.get(k) != "" for k in required):
            return (
                "Self-custody send requires a structured metadata payload "
                "with: from (32-byte hex), to (32-byte hex), value (wei "
                "decimal string), signature (64-byte hex Ed25519), "
                "public_key (32-byte hex Ed25519), pq_signature (3309-byte "
                "hex ML-DSA-65), pq_public_key (1952-byte hex ML-DSA-65), "
                "timestamp (ms epoch used at signing time). Optional: "
                "nonce, chain_id, gas_limit, gas_price. The signatures are "
                "produced offline by the local hybrid signer over the "
                "canonical Transaction::hash() preimage."
            )
        from_addr = md["from"]
        nonce = md.get("nonce")
        if nonce is None:
            nonce_hex = await rpc_call("eth_getTransactionCount", [from_addr, "latest"])
            nonce = int(nonce_hex, 16) if nonce_hex else 0
        chain_id = md.get("chain_id")
        if chain_id is None:
            chain_id_hex = await rpc_call("eth_chainId", [])
            chain_id = int(chain_id_hex, 16) if chain_id_hex else 1337
        result = await rpc_call(
            "eth_sendRawTransaction",
            {
                "from": from_addr,
                "to": md["to"],
                "value": str(md["value"]),
                "gas_limit": md.get("gas_limit", 21000),
                "gas_price": md.get("gas_price", 10**9),
                "nonce": nonce,
                "chain_id": chain_id,
                "timestamp": md["timestamp"],
                "public_key": md["public_key"],
                "signature": md["signature"],
                "pq_public_key": md["pq_public_key"],
                "pq_signature": md["pq_signature"],
            },
        )
        return (
            f"Self-custody transaction submitted.\n"
            f"  Hash: {result}\n"
            f"  From: {from_addr}\n"
            f"  To: {md['to']}"
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
            result = await rpc_call(
                "tenzro_signAndSendTransaction",
                {
                    "from": from_addr,
                    "to": to_addr,
                    # Decimal string carries the full u128 range — JSON numbers
                    # clamp to u64 in the handler's numeric path.
                    "value": str(wei),
                    "gas_limit": 21000,
                    "gas_price": 10**9,
                    "nonce": nonce,
                    "chain_id": chain_id,
                },
            )
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


async def handle_block(text: str, metadata: dict | None = None) -> str:
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
    if any(
        k in t for k in ["range", "catch up", "catch-up", "sync from", "block range"]
    ):
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


async def handle_fee_market(text: str, metadata: dict | None = None) -> str:
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


async def handle_status(text: str, metadata: dict | None = None) -> str:
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


async def handle_network(text: str, metadata: dict | None = None) -> str:
    peer_count = await rpc_call("tenzro_peerCount", [])
    listening = await rpc_call("net_listening", [])
    return f"Network Info:\n  Peers: {peer_count}\n  Listening: {listening}"


async def handle_faucet(text: str, metadata: dict | None = None) -> str:
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


async def handle_identity(text: str, metadata: dict | None = None) -> str:
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
        reason = (
            metadata.get("reason", "revoked via A2A") if metadata else "revoked via A2A"
        )
        # The node requires a signed envelope proving control of the DID (or
        # of its controller) on top of the operator admin token — a revocation
        # gossips network-wide, so neither party makes that call alone. The
        # caller supplies it in metadata; absent it the node refuses, which is
        # the correct outcome rather than something to paper over here.
        did_envelope = metadata.get("did_envelope", "") if metadata else ""
        result = await rpc_call(
            "tenzro_revokeDid",
            {"did": did, "did_envelope": did_envelope, "reason": reason},
        )
        return (
            f"Identity revoked:\n"
            f"  DID: {did}\n"
            f"  Affected JTIs: {result.get('affected_jti_count', 0)}\n"
            f"  Cascade: {result.get('cascade', '')}"
        )

    if did:
        result = await rpc_call("tenzro_resolveIdentity", {"did": did})
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


def _build_route_intent_params(text: str, metadata: dict | None = None) -> dict:
    """Assembles tenzro_routeIntent params from metadata, defaulting use_case.

    metadata["payer_did"] enables the per-DID rolling-window budget gate;
    metadata["payer_address"] makes the payer's on-chain TNZO balance a hard
    ceiling. metadata["prompt"] is the text the model would answer, used only
    to place the request in a difficulty cluster so selection accounts for how
    hard the prompt is — it is not sent to any provider. tenzro_chatByIntent
    derives it from the chat turns, so it only matters when routing without
    dispatching.
    """
    metadata = metadata or {}
    params: dict = {}
    use_case = metadata.get("use_case")
    if not use_case:
        t = text.lower()
        for candidate in ("reasoning", "code", "summarize", "extract", "embed", "chat"):
            if candidate in t:
                use_case = candidate
                break
    params["use_case"] = use_case or "chat"
    for key in (
        "budget",
        "optimize",
        "quality_floor",
        "est_input_tokens",
        "est_output_tokens",
        "payer_did",
        "payer_address",
        "prompt",
    ):
        if metadata.get(key) is not None:
            params[key] = metadata[key]
    return params


def _apply_jurisdiction_params(params: dict, metadata: dict | None = None) -> None:
    """Forwards the caller's jurisdiction pin and receipt-strictness flag.

    metadata["jurisdiction"] is a comma-separated pin of ISO 3166-1 alpha-2
    country codes and/or bloc tokens (case-insensitive); the serving node must
    declare a matching attestation-bound locality claim or the request is
    refused. metadata["jurisdiction_receipt"] set to "required" fails the
    request unless the response carries a verifiable signed jurisdiction
    receipt (returned under "tenzro_jurisdiction").
    """
    metadata = metadata or {}
    for key in ("jurisdiction", "jurisdiction_receipt"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            params[key] = value.strip()


def _sniff_image_media_type(raw: bytes) -> str | None:
    """Identifies an image's media type from its leading bytes.

    A serving projector reads the format from the bytes themselves; this is the
    wire label the image content block carries alongside the base64 payload.
    """
    if raw.startswith(b"\x89PNG"):
        return "image/png"
    if raw.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(raw) >= 12 and raw[0:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    if raw.startswith(b"GIF8"):
        return "image/gif"
    return None


def _chat_image_blocks(metadata: dict | None = None) -> list[dict]:
    """Builds the image content blocks for a chat turn from the caller's metadata.

    metadata["images"] is a list of base64-encoded images, or
    metadata["image_base64"] a single one. Both take raw PNG / JPEG / WebP /
    GIF bytes; the media type is read from the bytes. An entry whose format is
    unrecognized is skipped rather than sent with a wrong label.

    Attachments only reach a model that loaded a multimodal projector. A
    text-only model refuses the request, so the caller learns the model cannot
    see rather than getting an answer that silently ignored the image.
    """
    metadata = metadata or {}
    payloads = metadata.get("images")
    if payloads is None:
        single = metadata.get("image_base64")
        payloads = [single] if single else []
    if isinstance(payloads, str):
        payloads = [payloads]

    blocks: list[dict] = []
    for payload in payloads:
        if not isinstance(payload, str) or not payload.strip():
            continue
        try:
            raw = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError):
            continue
        media_type = _sniff_image_media_type(raw)
        if media_type is None:
            continue
        blocks.append(
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": media_type,
                    "data": payload,
                },
            }
        )
    return blocks


def _chat_turn_params(prompt: str, blocks: list[dict]) -> dict:
    """Chat params for one turn: the simple shape, or the rich shape with images.

    Images lead the turn and the text follows, matching the order the serving
    node binds attachments in.
    """
    if not blocks:
        return {"message": prompt}
    return {
        "messages": [
            {"role": "user", "content": blocks + [{"type": "text", "text": prompt}]}
        ],
    }


def _chat_result_text(result: dict) -> dict:
    """Normalizes a rich chat response to the simple shape's reported fields.

    The rich shape answers with a content-block list and nests token counts
    under `usage`; flattening keeps one response shape for callers regardless
    of whether their turn carried attachments.
    """
    if not isinstance(result, dict) or "content" not in result:
        return result
    blocks = result.get("content") or []
    usage = result.get("usage") or {}
    flattened = {
        "output": "".join(
            b.get("text", "")
            for b in blocks
            if isinstance(b, dict) and b.get("type") == "text"
        ),
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
    }
    for key in (
        "model",
        "stop_reason",
        "cost_wei",
        "settlement",
        "location",
        "commitment",
        "tenzro_jurisdiction",
        "load",
    ):
        if result.get(key) is not None:
            flattened[key] = result[key]
    return flattened


async def handle_inference(text: str, metadata: dict | None = None) -> str:
    t = text.lower()

    if "list" in t and "model" in t:
        result = await rpc_call("tenzro_listModels", [])
        if not result:
            return "No models currently registered on the network."
        lines = ["Available models:"]
        for m in result:
            lines.append(f"  - {m.get('name', 'unknown')} ({m.get('id', '')})")
        return "\n".join(lines)

    # Route feedback: report how a routed call turned out so per-cluster error
    # rates reflect what happened rather than only what the catalog declares.
    # In practice this carries "escalated" — the outcome only the caller knows,
    # because it means the caller took the answer to a stronger model.
    # "resolved" and "failed" are already recorded by tenzro_chatByIntent from
    # the dispatch itself. retained=false in the response means the node has no
    # difficulty index, so the report was accepted and discarded.
    if "outcome" in t:
        md = metadata or {}
        missing = [k for k in ("model_id", "cluster", "outcome") if md.get(k) is None]
        if missing:
            return "Reporting a route outcome needs metadata: " + ", ".join(missing)
        result = await rpc_call(
            "tenzro_recordRouteOutcome",
            {
                "model_id": md["model_id"],
                "cluster": md["cluster"],
                "outcome": md["outcome"],
            },
        )
        return json.dumps(result, indent=2)

    # Difficulty index: how many prompt clusters the node has discovered and
    # how many prompts landed in each, plus a model's per-cluster outcome
    # counters when metadata names one. An operator diagnostic — routing does
    # not depend on it. enabled=false means the node has no embedding model
    # loaded and routes on declared metadata alone.
    if "difficulty" in t or ("cluster" in t and "stat" in t):
        params: dict = {}
        model_id = (metadata or {}).get("model_id")
        if model_id:
            params["model_id"] = model_id
        result = await rpc_call("tenzro_routeDifficultyStats", params)
        return json.dumps(result, indent=2)

    # Intent routing: discover the best model for a use case + budget without
    # naming one. "route"/"intent"/"best model", or a use_case in metadata,
    # triggers tenzro_routeIntent (discovery only — nothing is dispatched).
    if (
        "route" in t
        or "intent" in t
        or "best model" in t
        or (metadata and metadata.get("use_case"))
    ) and "chat" not in t:
        params = _build_route_intent_params(text, metadata)
        result = await rpc_call("tenzro_routeIntent", params)
        return json.dumps(result, indent=2)

    # Chat by intent: "chat by intent" or metadata use_case with a chat verb
    # discovers a model then dispatches in one call via tenzro_chatByIntent.
    if "chat" in t and (
        "intent" in t or "use case" in t or (metadata and metadata.get("use_case"))
    ):
        prompt = text
        for kw in ["chat", "ask", "complete", "say"]:
            idx = t.find(kw)
            if idx >= 0:
                prompt = text[idx + len(kw) :].strip().lstrip(":").strip()
                break
        params = _build_route_intent_params(text, metadata)
        params.update(_chat_turn_params(prompt, _chat_image_blocks(metadata)))
        params["max_tokens"] = (metadata or {}).get("max_tokens", 256)
        _apply_jurisdiction_params(params, metadata)
        result = await rpc_call("tenzro_chatByIntent", params)
        return json.dumps(_chat_result_text(result), indent=2)

    if "chat" in t or "ask" in t or "complete" in t:
        # Extract the prompt after keywords
        prompt = text
        for kw in ["chat", "ask", "complete", "say"]:
            idx = t.find(kw)
            if idx >= 0:
                prompt = text[idx + len(kw) :].strip().lstrip(":").strip()
                break
        params = {
            "model_id": (metadata or {}).get("model_id", "default"),
            "max_tokens": (metadata or {}).get("max_tokens", 100),
        }
        params.update(_chat_turn_params(prompt, _chat_image_blocks(metadata)))
        _apply_jurisdiction_params(params, metadata)
        result = await rpc_call("tenzro_chat", params)
        return json.dumps(_chat_result_text(result), indent=2)

    # Content-addressed weights: the canonical BLAKE3 / SHA-256 record a
    # fetcher verifies weights against before load. "hash" + "model" reads a
    # record (metadata.model_id) or lists every recorded hash.
    if "hash" in t and "model" in t:
        model_id = (metadata or {}).get("model_id")
        if (model_id or "get" in t or "record" in t) and model_id:
            result = await rpc_call("tenzro_getModelHash", [{"model_id": model_id}])
            return json.dumps(result, indent=2)
        result = await rpc_call("tenzro_listModelHashes", [])
        return json.dumps(result, indent=2)

    # Peer-first model download: weights are pulled from Tenzro peers over
    # iroh blobs (BLAKE3-verified on transfer), falling back to HuggingFace,
    # then checked against the canonical hash record before load.
    if "download" in t and "model" in t:
        model_id = (metadata or {}).get("model_id")
        if not model_id:
            return (
                "Specify the model to download via metadata.model_id. "
                "Fetch is peer-first over iroh blobs (BLAKE3-verified), "
                "falling back to HuggingFace, and the weights are checked "
                "against the canonical hash record before load. Optionally set "
                "metadata.source to 'network' (verified network providers only) "
                "or 'huggingface' (HuggingFace only)."
            )
        req = {"model_id": model_id}
        source = (metadata or {}).get("source")
        if source:
            req["source"] = source
        result = await rpc_call("tenzro_downloadModel", [req])
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


async def handle_staking(text: str, metadata: dict | None = None) -> str:
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


async def handle_validator_lifecycle(text: str, metadata: dict | None = None) -> str:
    """Read + key-rotation operations on the validator registry.

    Read paths trigger on conversational input; the rotation path
    requires a structured `metadata` payload because it carries a
    1952-byte ML-DSA-65 verifying key and an offline Ed25519 signature
    that cannot be expressed in free-text. Metadata shape:

        {
          "op": "rotate_keys",
          "address": "0x...",
          "new_consensus_pubkey": "0x...",
          "new_pq_pubkey": "0x...",
          "new_bls_pubkey": "0x...",
          "nonce": 7,
          "signature": "0x..."
        }
    """
    t = text.lower()
    addr = _extract_address(text)

    op = (metadata or {}).get("op")
    if op == "rotate_keys" or "rotate" in t:
        md = metadata or {}
        # Allow text-extracted address to fill in if metadata omits it.
        address = md.get("address") or addr
        if (
            not all(
                md.get(k)
                for k in (
                    "new_consensus_pubkey",
                    "new_pq_pubkey",
                    "new_bls_pubkey",
                    "nonce",
                    "signature",
                )
            )
            or not address
        ):
            return (
                "Validator key rotation requires a structured metadata "
                "payload with: address, new_consensus_pubkey, "
                "new_pq_pubkey (1952-byte hex), new_bls_pubkey (48-byte "
                "hex), nonce (u64), signature (64-byte hex). The "
                "signature is produced offline with the current "
                "consensus key over the canonical preimage."
            )
        result = await rpc_call(
            "tenzro_rotateValidatorKey",
            {
                "address": address,
                "new_consensus_pubkey": md["new_consensus_pubkey"],
                "new_pq_pubkey": md["new_pq_pubkey"],
                "new_bls_pubkey": md["new_bls_pubkey"],
                "nonce": md["nonce"],
                "signature": md["signature"],
            },
        )
        return (
            f"Validator key rotation submitted for {address}.\n"
            f"{json.dumps(result, indent=2)}"
        )

    if "active" in t and "validator" in t:
        result = await rpc_call("tenzro_listActiveValidators", {})
        return f"Active validators:\n{json.dumps(result, indent=2)}"

    if "list" in t and "validator" in t:
        result = await rpc_call("tenzro_listValidators", {})
        return f"All validators:\n{json.dumps(result, indent=2)}"

    if addr:
        result = await rpc_call("tenzro_getValidatorState", {"address": addr})
        return f"Validator {addr}:\n{json.dumps(result, indent=2)}"

    return (
        "Validator-lifecycle operations:\n"
        "  - 'List active validators'\n"
        "  - 'List all validators'\n"
        "  - 'Get validator 0xabc...'\n"
        "  - Rotate keys (requires structured metadata; see OPERATOR_GUIDE §9.3)."
    )


async def handle_provider(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    addr = _extract_address(text)

    if "register" in t and addr:
        result = await rpc_call("tenzro_registerProvider", [addr])
        return f"Provider registered: {addr}\n{json.dumps(result, indent=2)}"

    if ("status" in t or "stats" in t) and addr:
        result = await rpc_call("tenzro_providerStats", [addr])
        return f"Provider stats for {addr}:\n{json.dumps(result, indent=2)}"

    if "capacity" in t:
        result = await rpc_call("tenzro_listProviderCapacity", [])
        return f"Provider capacity (advertised + measured):\n{json.dumps(result, indent=2)}"

    return (
        "Provider operations:\n"
        "  - 'Register as provider with address 0xabc...'\n"
        "  - 'Get provider status for 0xabc...'\n"
        "  - 'List provider capacity'"
    )


# ---------------------------------------------------------------------------
# Payments
# ---------------------------------------------------------------------------


async def handle_payment(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    md = metadata or {}

    if "session" in t:
        result = await rpc_call("tenzro_listPaymentSessions", [])
        return f"Payment sessions:\n{json.dumps(result, indent=2)}"

    if "info" in t or "gateway" in t:
        result = await rpc_call("tenzro_paymentGatewayInfo", [])
        return f"Payment gateway info:\n{json.dumps(result, indent=2)}"

    # x402 Bazaar — resource discovery and monetization
    if "x402" in t and ("bazaar" in t or "protocol info" in t):
        result = await rpc_call("tenzro_x402ProtocolInfo", [])
        return f"x402 protocol info:\n{json.dumps(result, indent=2)}"

    if "x402" in t and "register" in t and md.get("sellerDid") and md.get("resource"):
        params = {
            "sellerDid": md["sellerDid"],
            "resource": md["resource"],
            "scheme": md.get("scheme", "tenzro-hybrid"),
            "network": md.get("network", "tenzro"),
            "asset": md.get("asset", "TNZO"),
            "payTo": md["payTo"],
            "maxAmountRequired": md["maxAmountRequired"],
        }
        for opt in ("description", "mimeType", "maxTimeoutSeconds", "tags", "extra"):
            if md.get(opt) is not None:
                params[opt] = md[opt]
        result = await rpc_call("tenzro_x402RegisterResource", params)
        return f"x402 resource registered:\n{json.dumps(result, indent=2)}"

    if "x402" in t and ("discover" in t or "find" in t or "bazaar" in t):
        params = {}
        for opt in ("scheme", "network", "asset", "sellerDid", "tags", "limit"):
            if md.get(opt) is not None:
                params[opt] = md[opt]
        result = await rpc_call("tenzro_x402DiscoverResources", params)
        return f"x402 resources:\n{json.dumps(result, indent=2)}"

    if "x402" in t and ("deregister" in t or "remove" in t) and md.get("listingId"):
        result = await rpc_call(
            "tenzro_x402DeregisterResource",
            {
                "listingId": md["listingId"],
                "sellerDid": md.get("sellerDid"),
            },
        )
        return f"x402 resource deregistered:\n{json.dumps(result, indent=2)}"

    if "x402" in t and "verify" in t and md.get("requirement"):
        result = await rpc_call(
            "tenzro_x402VerifyOffer", {"requirement": md["requirement"]}
        )
        return f"x402 offer verification:\n{json.dumps(result, indent=2)}"

    if "x402" in t and ("payment id" in t or "paymentid" in t) and md.get("payerDid"):
        params = {"payerDid": md["payerDid"]}
        if md.get("requirement") is not None:
            params["requirement"] = md["requirement"]
        if md.get("offerCommitment") is not None:
            params["offerCommitment"] = md["offerCommitment"]
        result = await rpc_call("tenzro_x402PaymentId", params)
        return f"x402 payment id:\n{json.dumps(result, indent=2)}"

    if "scheme" in t and "x402" in t:
        result = await rpc_call("tenzro_listX402Schemes", [])
        return f"x402 scheme registry:\n{json.dumps(result, indent=2)}"

    if "challenge" in t:
        protocol = "mpp"
        if "x402" in t:
            protocol = "x402"
        result = await rpc_call(
            "tenzro_createPaymentChallenge", [protocol, "/resource"]
        )
        return (
            f"Payment challenge created ({protocol}):\n{json.dumps(result, indent=2)}"
        )

    if "ap2" in t:
        # The AP2 v0.2 lifecycle (sessions, mandate sign/verify/validate) is
        # handled by `handle_ap2`, which drives the real `tenzro_ap2*` RPCs.
        return await handle_ap2(text, metadata)

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
        "  - 'AP2 protocol info' (routes to the AP2 v0.2 session/mandate handler)\n"
        "  - 'Payment gateway info'\n"
        "  - 'x402 protocol info'\n"
        "  - 'x402 register resource' (metadata: sellerDid, resource, payTo, "
        "maxAmountRequired, scheme?, network?, asset?, description?, tags?)\n"
        "  - 'x402 discover resources' (metadata: scheme?, network?, asset?, "
        "sellerDid?, tags?, limit?)\n"
        "  - 'x402 deregister resource' (metadata: listingId, sellerDid)\n"
        "  - 'x402 verify offer' (metadata: requirement)\n"
        "  - 'x402 payment id' (metadata: payerDid, requirement?|offerCommitment?)"
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


async def handle_verification(text: str, metadata: dict | None = None) -> str:
    t = text.lower()

    if "tee" in t or "attestation" in t:
        provider = (metadata or {}).get("provider") if metadata else None
        quote = (metadata or {}).get("quote") if metadata else None
        if not provider or not quote:
            return (
                "TEE attestation verification requires a real provider and quote.\n"
                'Pass via metadata: {"provider": "tdx|sev-snp|nitro|nvidia-gpu", "quote": "<base64>"}\n'
                "Supported providers: tdx, sev-snp, nitro, nvidia-gpu"
            )
        result = await api_call(
            "/verify/tee-attestation",
            method="POST",
            body={
                "provider": provider,
                "quote": quote,
            },
        )
        return f"TEE attestation verification:\n{json.dumps(result, indent=2)}"

    if "transaction" in t or "signature" in t:
        tx_hash = _extract_address(text)
        if tx_hash:
            result = await api_call(
                "/verify/transaction",
                method="POST",
                body={
                    "tx_hash": tx_hash,
                },
            )
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
                'Pass via metadata: {"circuit_id": "inference|settlement|identity", '
                '"proof_bytes": "<hex>", "public_inputs": ["<hex>", ...]}\n'
                "public_inputs entries are 4-byte little-endian KoalaBear field-element chunks."
            )
        result = await api_call(
            "/verify/zk-proof",
            method="POST",
            body={
                "circuit_id": circuit_id,
                "proof_bytes": proof,
                "public_inputs": public_inputs,
            },
        )
        return f"ZK proof verification:\n{json.dumps(result, indent=2)}"

    if "provenance" in t or "synthetic" in t:
        md = metadata or {}
        content_hash = md.get("content_hash") or _extract_address(text)
        if not content_hash:
            return (
                "Provenance lookup requires a 32-byte hex content_hash.\n"
                'Pass via metadata: {"content_hash": "0x..."}'
            )
        result = await rpc_call("tenzro_getContentProvenance", {"content_hash": content_hash})
        return f"Provenance manifest:\n{json.dumps(result, indent=2)}"

    return (
        "Verification operations:\n"
        "  - 'Verify a ZK proof'\n"
        "  - 'Check TEE attestation'\n"
        "  - 'Verify transaction signature for 0xabc...'\n"
        "  - 'Look up provenance' (metadata: content_hash)"
    )


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


async def handle_bridge(text: str, metadata: dict | None = None) -> str:
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
            f"Use the MCP server at mcp.tenzro.xyz/mcp for programmatic bridging."
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


async def handle_join(text: str, metadata: dict | None = None) -> str:
    name = _extract_name(text)
    if name.lower() in ("network", "tenzro", "micronode", "join", "node"):
        name = "Anonymous"

    result = await rpc_call("tenzro_participate", [name])

    did = result.get("did", "unknown")
    address = result.get("address", "unknown")
    capabilities = result.get("capabilities", [])

    cap_lines = (
        "\n".join(f"    - {c}" for c in capabilities)
        if capabilities
        else "    (default capabilities)"
    )

    return (
        f"Welcome to the Tenzro Network!\n"
        f"\n"
        f"  Name: {name}\n"
        f"  DID: {did}\n"
        f"  Wallet: {address}\n"
        f"  Capabilities:\n"
        f"{cap_lines}\n"
        f"\n"
        f"Your identity and FROST-Ed25519 threshold wallet have been provisioned.\n"
        f"Use 'faucet' to request testnet TNZO tokens."
    )


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


async def handle_list_tokens(text: str, metadata: dict | None = None) -> str:
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


async def handle_create_token(text: str, metadata: dict | None = None) -> str:
    # Try to extract token details from text
    # Pattern: "Create token MyToken (MTK) with 1000000 supply"
    name_match = re.search(r"(?:called|named|token)\s+(\w+)", text, re.IGNORECASE)
    symbol_match = re.search(r"\((\w{2,6})\)", text)
    supply = _extract_amount(text)

    if name_match and symbol_match and supply:
        name = name_match.group(1)
        symbol = symbol_match.group(1)
        result = await rpc_call(
            "tenzro_createToken", [name, symbol, str(int(supply)), "18"]
        )
        return f"Token created:\n{json.dumps(result, indent=2)}"

    return (
        "To create a token, provide:\n"
        "  - Name, symbol, total supply, decimals\n"
        "Example: 'Create a token called MyToken (MTK) with 1000000 supply'\n"
        "Default decimals: 18"
    )


async def handle_token_info(text: str, metadata: dict | None = None) -> str:
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


async def handle_token_balance(text: str, metadata: dict | None = None) -> str:
    addr = _extract_address(text)
    if addr:
        result = await rpc_call("tenzro_getTokenBalance", [addr])
        return f"Token balance for {addr}:\n{json.dumps(result, indent=2)}"
    return "Provide an address to check token balance.\nExample: 'Get token balance for 0xabc...'"


async def handle_cross_vm_transfer(text: str, metadata: dict | None = None) -> str:
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


async def handle_svm_cross_vm_info(text: str, metadata: dict | None = None) -> str:
    """Return the canonical Tenzro Cross-VM SVM-native program ID and the four
    Anchor-style instruction discriminators for SVM clients."""
    return (
        "Tenzro Cross-VM SVM-native program:\n"
        "  Program ID (base58):  7CBvjJtsMxYFsxYkpcXYoTDZpC8PhMVy1DVVQBopvWCC\n"
        "  Program ID (hex):     5c03dd6cf580ecafb5ca11a9e1d6448176bb1dfa9d4886c65d9024df77542695\n"
        '  Derivation:           SHA-256("tenzro/svm/program/cross_vm")\n'
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
        'encodeRegisterTokenPointer / encodeTransferCrossVm from "tenzro"\n'
        "  Python:     encode_bridge_to_evm / encode_bridge_from_evm / "
        "encode_register_token_pointer / encode_transfer_cross_vm\n"
        "  Rust:       tenzro_sdk::svm_cross_vm::encode_*"
    )


async def handle_wrap_tnzo(text: str, metadata: dict | None = None) -> str:
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


async def handle_contract(text: str, metadata: dict | None = None) -> str:
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


async def handle_nft(text: str, metadata: dict | None = None) -> str:
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
        return "To query NFT ownership, provide:\n  - Collection address\n  - Token ID"

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


async def handle_compliance(text: str, metadata: dict | None = None) -> str:
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


async def handle_crosschain(text: str, metadata: dict | None = None) -> str:
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


async def handle_events(text: str, metadata: dict | None = None) -> str:
    t = text.lower()

    if "websocket" in t or "subscribe" in t:
        return (
            "WebSocket event streaming:\n"
            "  Connect to ws://rpc.tenzro.xyz and call eth_subscribe.\n"
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


async def handle_canton(text: str, metadata: dict | None = None) -> str:
    t = text.lower()

    # ── Live read-side methods (Canton 3.5+ JSON Ledger API) ──

    if "health" in t or "livez" in t or "readyz" in t:
        result = await rpc_call("tenzro_canton_health", {})
        return f"Canton health:\n{json.dumps(result, indent=2)}"

    if "version" in t or "feature" in t:
        result = await rpc_call("tenzro_canton_version", {})
        return f"Canton version + features:\n{json.dumps(result, indent=2)}"

    if "my user" in t or "myuser" in t or "primary party" in t or "who am i" in t:
        result = await rpc_call("tenzro_canton_getMyUser", {})
        return f"Canton user record:\n{json.dumps(result, indent=2)}"

    if (
        "list party" in t
        or "list parties" in t
        or "known party" in t
        or "known parties" in t
    ):
        result = await rpc_call("tenzro_canton_listParties", {})
        return f"Canton parties:\n{json.dumps(result, indent=2)}"

    if (
        "list package" in t
        or "list packages" in t
        or "installed package" in t
        or "dar list" in t
    ):
        result = await rpc_call("tenzro_canton_listPackages", {})
        return f"Canton installed packages:\n{json.dumps(result, indent=2)}"

    if "coin balance" in t or "amulet" in t or "cip-56" in t or "cip 56" in t:
        result = await rpc_call("tenzro_canton_coinBalance", {})
        return f"Canton Coin balance (CIP-56):\n{json.dumps(result, indent=2)}"

    if "fee schedule" in t or "amulet rules" in t or "amuletrules" in t:
        result = await rpc_call("tenzro_canton_feeSchedule", {})
        return f"Canton fee schedule:\n{json.dumps(result, indent=2)}"

    if (
        "connected synchronizer" in t
        or "synchronizer subscription" in t
        or "connected domain" in t
    ):
        result = await rpc_call("tenzro_canton_connectedSynchronizers", {})
        return f"Connected synchronizers:\n{json.dumps(result, indent=2)}"

    if "domain" in t:
        result = await rpc_call("tenzro_listCantonDomains", {})
        return f"Canton domains:\n{json.dumps(result, indent=2)}"

    # ── Methods requiring explicit input — guide the caller ──

    if "upload" in t and "dar" in t:
        return (
            "Upload a DAR via tenzro_canton_uploadDar { dar_content_base64 }.\n"
            "  - base64-encode the .dar file bytes\n"
            "  - Canton 3.5+ JSON Ledger API: POST /v2/packages\n"
            "  - returns the installed package ids\n"
            "Use the canton-mcp.tenzro.xyz/mcp `canton_upload_dar` tool for direct upload."
        )

    if "transaction" in t and ("get" in t or "lookup" in t or "fetch" in t):
        return (
            "Fetch a Canton transaction by hex update id:\n"
            "  tenzro_canton_getTransaction { update_id: '<hex>' }"
        )

    if "allocate" in t and "party" in t:
        return (
            "Allocate a new Canton party:\n"
            "  tenzro_allocateParty { party_id_hint, display_name? }\n"
            "Returns the fully-qualified party id `<hint>::<participant-hash>`.\n"
            "Note: a newly-allocated party has no CanActAs/CanReadAs grants on "
            "any user by default — follow up with `grant user rights` so the "
            "operator's OAuth user can submit DAML commands as the party."
        )

    if "grant" in t and ("right" in t or "rights" in t):
        return (
            "Grant CanActAs / CanReadAs rights on a Canton party (Canton 3.5+ CIP-26):\n"
            "  tenzro_canton_grantUserRights { party, user_id?, can_act_as?, can_read_as?, identity_provider_id? }\n"
            "Pass `user_id` omitted to grant to the OAuth principal's own user. "
            "IDP-scoped users (Stage 2 tenants) require `identity_provider_id`."
        )

    if "list" in t and ("right" in t or "rights" in t):
        result = await rpc_call("tenzro_canton_listUserRights", {})
        return f"Canton user rights:\n{json.dumps(result, indent=2)}"

    if "analytics" in t or ("my" in t and ("usage" in t or "calls" in t)):
        result = await rpc_call("tenzro_canton_getMyAnalytics", {})
        return (
            "Canton per-tenant analytics (self-read):\n"
            f"{json.dumps(result, indent=2)}\n\n"
            "Counters are maintained server-side in RocksDB "
            "(`CF_CANTON_ANALYTICS`) — every canton-scoped JSON-RPC call "
            "increments calls_total (or errors_total) plus the per-method "
            "bucket. Operators can list every tenant via "
            "tenzro_canton_listApiKeyAnalytics (admin token gated)."
        )

    if "contract" in t:
        return (
            "List DAML contracts (template id required):\n"
            "  tenzro_listDamlContracts { template_ids: ['<template>'], query?: {...} }\n"
            "Example: 'List contracts for template #splice-amulet:Splice.Amulet:Amulet'."
        )

    if "submit" in t or "command" in t:
        return (
            "Submit a DAML command:\n"
            "  tenzro_submitDamlCommand { command_type: 'create'|'exercise', template_id, ... }\n"
            "Required: the presenting API key must carry a `canton_user_id` "
            "binding. The node resolves the user's `primaryParty` and uses it "
            "as `actAs`. Pass `act_as: <party>` to pin a specific party — the "
            "node verifies the caller is authorized on that party (either it "
            "matches `primaryParty` or is on `can_act_as_parties`)."
        )

    if "watch" in t and "party" in t:
        return (
            "Watch active contracts for an explicit party:\n"
            "  tenzro_canton_watchParty { party, template_ids: ['<tid>', ...] }\n"
            "Authorization: the presenting key must be authorized for `party` "
            "— either it matches the key's `primaryParty`, or the party is on "
            "the key's `can_read_as_parties` / `can_act_as_parties` whitelist. "
            "Anything else returns -32004."
        )

    if "mirror" in t and ("workflow" in t or "obligation" in t):
        return (
            "Mirror a Tenzro workflow (or obligation) into Canton:\n"
            "  tenzro_mirrorWorkflowToCanton { workflow_id, synchronizer_id }\n"
            "  tenzro_mirrorObligationToCanton { obligation_id, parent_contract_id }\n"
            "These write operator-signed `Tenzro.Workflow:WorkflowAnchor` and "
            "`Tenzro.Workflow:ObligationAnchor` contracts under the operator's "
            "participant-default party. Admin-token-gated — tenant API keys "
            "cannot produce these contracts."
        )

    if "idp" in t or "identity provider" in t:
        return (
            "Per-tenant Canton IdentityProviderConfig (Stage 2.b):\n"
            "  tenzro_canton_createIdp { identity_provider_id, issuer_url, "
            "jwks_url, audience }\n"
            "  tenzro_canton_listIdps {}\n"
            "  tenzro_canton_deleteIdp { identity_provider_id }\n"
            "Operator-only — admin-token-gated. Tenants minted against their "
            "own IDP route their JWTs through their own upstream issuer, "
            "staying isolated from the operator's IDP."
        )

    if "list analytics" in t or "all tenants" in t or "every tenant" in t:
        return (
            "Operator admin-read of every tenant's Canton call analytics:\n"
            "  tenzro_canton_listApiKeyAnalytics { key_id? }\n"
            "Admin-token-gated; non-admin callers see -32001. Pass `key_id` "
            "to narrow to a single tenant."
        )

    return (
        "Canton / DAML operations (Canton 3.5+ JSON Ledger API):\n"
        "  Reads (no args):\n"
        "    - 'Canton health' / 'Canton version' / 'Canton my user'\n"
        "    - 'Canton list parties' / 'list packages' / 'connected synchronizers'\n"
        "    - 'Canton coin balance' / 'Canton fee schedule' / 'List domains'\n"
        "    - 'List Canton user rights'\n"
        "    - 'Canton analytics' (self-read)\n"
        "  Reads (with args):\n"
        "    - 'List DAML contracts for template <tid>'\n"
        "    - 'Get Canton transaction <hex-update-id>'\n"
        "    - 'Watch party <party-fq> for template <tid>'\n"
        "  Tenant writes (require canton_user_id binding):\n"
        "    - 'Allocate Canton party'\n"
        "    - 'Grant Canton user rights for party <fq-party-id>'\n"
        "    - 'Submit DAML command'\n"
        "    - 'Upload DAR'\n"
        "  Operator writes (admin-token-gated):\n"
        "    - 'Mirror workflow to Canton'\n"
        "    - 'Mirror obligation to Canton'\n"
        "    - 'Create / list / delete IDP'\n"
        "    - 'List analytics (every tenant)'"
    )


# ---------------------------------------------------------------------------
# Task Marketplace
# ---------------------------------------------------------------------------


async def handle_task_marketplace(text: str, metadata: dict | None = None) -> str:
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


async def handle_agent_marketplace(text: str, metadata: dict | None = None) -> str:
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
        query = (
            text.split("search")[-1].strip().rstrip("?.!,;") if "search" in t else ""
        )
        result = await rpc_call("tenzro_listAgentTemplates", [])
        if not result:
            return "No agent templates found."
        lines = (
            [f"Agent templates matching '{query}':"]
            if query
            else ["Available agent templates:"]
        )
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


async def handle_agent_spawning(text: str, metadata: dict | None = None) -> str:
    t = text.lower()

    if "list" in t and ("child" in t or "agent" in t):
        result = await rpc_call("tenzro_listAgentTemplates", [])
        return f"Spawned agents:\n{json.dumps(result, indent=2)}"

    if "spawn" in t:
        # Try to extract agent name
        name_match = re.search(
            r"(?:named?|called)\s+['\"]?(\w+)['\"]?", text, re.IGNORECASE
        )
        name = name_match.group(1) if name_match else "sub-agent"
        # Try to extract capabilities
        cap_match = re.search(
            r"(?:with|capability|capabilities)\s+(.+?)(?:\.|$)", text, re.IGNORECASE
        )
        capabilities = (
            cap_match.group(1).strip().rstrip("?.!,;") if cap_match else "general"
        )

        return (
            f"Agent spawn request:\n"
            f"  Name: {name}\n"
            f"  Capabilities: {capabilities}\n"
            f"\n"
            f"Each spawned agent receives:\n"
            f"  - Its own TDIP DID (did:tenzro:machine:...)\n"
            f"  - FROST-Ed25519 threshold wallet (2-of-3, RFC 9591)\n"
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
# Capability Registry
# ---------------------------------------------------------------------------

# Short forms the node maps onto concrete capability variants. Anything else
# is registered as a custom capability under its own name.
_CAPABILITY_SHORT_FORMS = (
    "nlp",
    "vision",
    "code",
    "data",
    "blockchain",
    "smart_contract",
    "api_integration",
    "coordination",
)


def _extract_capability(text: str) -> str | None:
    """Pull a capability name out of a request.

    Quoted names win outright. Otherwise a bare short form anywhere in the
    text is accepted, then whatever follows 'for'.
    """
    m = re.search(r"['\"]([\w-]+)['\"]", text)
    if m:
        return m.group(1)

    t = text.lower()
    for short in _CAPABILITY_SHORT_FORMS:
        if re.search(rf"\b{re.escape(short)}\b", t):
            return short

    m = re.search(r"\bfor\s+([\w-]+)", text, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_capability_agent_id(text: str) -> str | None:
    """Pull an agent identifier out of a request.

    Agent ids on the capability registry are free-form strings rather than
    UUIDs, so ``_extract_id`` does not apply.
    """
    m = re.search(r"\bagent\s+([\w:.-]+)", text, re.IGNORECASE)
    if not m:
        return None
    candidate = m.group(1).rstrip("?.!,;")
    # 'attestations for agent foo' matches; 'best agent for vision' does not.
    return None if candidate.lower() in ("for", "id") else candidate


async def handle_capability_registry(text: str, metadata: dict | None = None) -> str:
    t = text.lower()

    if "best" in t or "pick" in t or "tee-backed agent" in t:
        capability = _extract_capability(text)
        if not capability:
            return (
                "Name the capability to select for, e.g. "
                "\"Pick the best agent for 'code'\"."
            )
        result = await rpc_call(
            "tenzro_findBestAgentForCapability", {"capability": capability}
        )
        best = result.get("best_agent")
        if not best:
            return (
                f"No agent on this node claims '{capability}' "
                f"({result.get('total_candidates', 0)} candidates)."
            )
        return (
            f"Best agent for '{capability}':\n"
            f"  Agent: {best}\n"
            f"  Candidates considered: {result.get('total_candidates', 0)}\n"
            f"\n"
            f"Selection prefers TEE-backed attestations, most recent first."
        )

    agent_id = _extract_capability_agent_id(text)
    if agent_id and "attestation" in t:
        result = await rpc_call(
            "tenzro_getAgentCapabilityAttestations", {"agent_id": agent_id}
        )
        return f"Attestations for agent {agent_id}:\n{json.dumps(result, indent=2)}"

    if "attestation" in t:
        capability = _extract_capability(text)
        if not capability:
            return (
                "Name the capability to inspect, e.g. "
                "\"Show attestations for the 'nlp' capability\"."
            )
        result = await rpc_call(
            "tenzro_getCapabilityAttestations",
            {"capability": capability, "verified_only": "verif" in t},
        )
        return (
            f"Attestations for '{capability}' "
            f"(verified_only={result.get('verified_only', False)}):\n"
            f"{json.dumps(result.get('attestations', []), indent=2)}"
        )

    if "list" in t or "capabilit" in t or "discover" in t:
        result = await rpc_call("tenzro_listCapabilities", {})
        lines = [
            f"  {entry.get('capability')}: "
            f"{entry.get('agent_count', 0)} agents, "
            f"{entry.get('attestation_count', 0)} attestations"
            for entry in result.get("capabilities", [])
        ]
        body = "\n".join(lines) if lines else "  (none registered)"
        out = f"Registered capabilities ({result.get('total', 0)}):\n{body}"
        if result.get("truncated"):
            out += "\n  … list truncated by the node's response cap."
        rejected = result.get("rejected_attestation_count", 0)
        if rejected:
            out += (
                f"\n\n{rejected} attestation(s) rejected since boot — signature "
                f"mismatch or malformed payload. Worth investigating."
            )
        return out

    return (
        "Capability registry operations:\n"
        "  - 'List all registered capabilities on this node'\n"
        "  - \"Show attestations for the 'nlp' capability\"\n"
        "  - 'Show attestations issued for agent agent-id-123'\n"
        "  - \"Pick the best agent for 'code'\""
    )


# ---------------------------------------------------------------------------
# Swarm Orchestration
# ---------------------------------------------------------------------------


async def handle_swarm(text: str, metadata: dict | None = None) -> str:
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


async def handle_debridge(text: str, metadata: dict | None = None) -> str:
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
    return (
        "deBridge DLN cross-chain operations:\n"
        "  - 'debridge chains' — list supported networks\n"
        "  - 'debridge search USDC' — find token addresses\n"
        "  - 'debridge instructions' — operational guidance\n"
        "  - 'debridge create tx' — create cross-chain transfer\n"
        "  - 'debridge same chain swap' — swap on same chain"
    )


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------


async def handle_crypto(text: str, metadata: dict | None = None) -> str:
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


async def handle_tee(text: str, metadata: dict | None = None) -> str:
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
# Passkey-first custody
# ---------------------------------------------------------------------------


async def handle_passkey(text: str, metadata: dict | None = None) -> str:
    """Passkey-bound ERC-4337 smart-account onboarding and custody.

    Query and session-launch operations dispatch to real RPCs. Ceremonies that
    require structured WebAuthn material (enroll, add device credential,
    add-guardian, recovery, session-key grant) are guided: the P-256 public
    key, credential id, and ML-DSA-65 key are produced by the caller's secure
    element and cannot be derived from free text, so the handler either opens a
    browser-launch ceremony session or returns the exact params to supply.
    """
    t = text.lower()
    addr = _extract_address(text)

    # List enrolled credentials on an account.
    if "list" in t and ("passkey" in t or "credential" in t):
        if addr:
            result = await rpc_call("tenzro_listPasskeys", {"account_address": addr})
            return f"Enrolled passkeys for {addr}:\n{json.dumps(result, indent=2)}"
        return "Provide an account address. Example: 'List passkeys for 0xabc...'"

    # Second-factor policy: get or set.
    if "policy" in t or "second factor" in t or "two credential" in t:
        if "set" in t and addr:
            factor = (
                "two_credentials"
                if any(k in t for k in ["two", "2fa", "dual"])
                else "single_credential"
            )
            result = await rpc_call(
                "tenzro_setPasskeyPolicy",
                {
                    "account_address": addr,
                    "second_factor": factor,
                },
            )
            return f"Passkey policy for {addr} set to {factor}:\n{json.dumps(result, indent=2)}"
        if addr:
            result = await rpc_call(
                "tenzro_getPasskeyPolicy", {"account_address": addr}
            )
            return f"Passkey policy for {addr}:\n{json.dumps(result, indent=2)}"
        return "Provide an account address. Example: 'Get passkey policy for 0xabc...'"

    # Pending guardian-quorum recoveries on an account.
    if "recovery" in t or "recover" in t:
        if "finalize" in t or "complete" in t:
            rid = _extract_id(text)
            if rid:
                result = await rpc_call("tenzro_finalizeRecovery", {"recovery_id": rid})
                return f"Recovery {rid} finalized:\n{json.dumps(result, indent=2)}"
            return (
                "Provide a recovery id to finalize. Example: 'Finalize recovery <uuid>'"
            )
        if "list" in t or "pending" in t or "status" in t:
            if addr:
                result = await rpc_call(
                    "tenzro_listPendingRecoveries", {"account_address": addr}
                )
                return f"Pending recoveries for {addr}:\n{json.dumps(result, indent=2)}"
            return "Provide an account address. Example: 'List pending recoveries for 0xabc...'"
        return (
            "To initiate a guardian-quorum recovery (rotate to a new passkey), "
            "call tenzro_initiateRecovery with:\n"
            "  - account_address\n"
            "  - new_passkey_public_key_hex (P-256 key from the new device)\n"
            "  - new_credential_id_hex\n"
            "  - new_ml_dsa_public_key_hex (optional PQ leg)\n"
            "  - ttl_secs (optional, default 86400, max 604800)\n"
            "Guardians then submit composite signatures over the returned "
            "recovery_op_hash_hex; finalize once quorum is reached."
        )

    # Add a social-recovery guardian.
    if "guardian" in t:
        return (
            "To add a social-recovery guardian, call tenzro_addGuardian with:\n"
            "  - account_address\n"
            "  - guardian_ed25519_pubkey_hex\n"
            "  - guardian_ml_dsa_pubkey_hex\n"
            "  - label (optional)\n"
            "  - threshold (optional new N-of-M quorum)"
        )

    # Grant a scoped session key to an agent.
    if "session key" in t or ("session" in t and "grant" in t):
        return (
            "To grant a scoped session key, call tenzro_grantSessionKey with:\n"
            "  - account_address\n"
            "  - session_pubkey_hex (32-byte Ed25519 verifying key)\n"
            "  - allowed_selectors_hex (4-byte function selectors)\n"
            "  - allowed_targets (20-byte addresses; empty = any)\n"
            "  - per-tx and validity bounds\n"
            "Session keys let an agent transact within limits without the "
            "user's passkey."
        )

    # Add a device credential to an existing account.
    if "add" in t and ("passkey" in t or "device" in t or "credential" in t):
        if addr:
            return (
                f"To add a device credential to {addr}, register a WebAuthn "
                "credential on the new device, then call tenzro_addPasskey with "
                "account_address, new_passkey_public_key_hex, "
                "new_credential_id_hex, and an optional label. The node mints "
                "the new credential's ML-DSA-65 post-quantum leg in its TEE. "
                "Or say 'browser add passkey for "
                f"{addr}' to launch the ceremony in a browser."
            )
        if "browser" in t:
            # Fall through to session launch below.
            pass
        else:
            return "Provide an account address. Example: 'Add a device credential to 0xabc...'"

    # Browser-launch WebAuthn ceremony (gcloud-style device flow).
    if "browser" in t or "launch" in t or "open" in t:
        if "add" in t and addr:
            result = await rpc_call(
                "tenzro_createPasskeySession",
                {
                    "kind": "add",
                    "account_address": addr,
                    "salt": 0,
                },
            )
        else:
            result = await rpc_call(
                "tenzro_createPasskeySession",
                {
                    "kind": "enroll",
                    "salt": 0,
                },
            )
        return (
            "Passkey ceremony session created. Open the returned auth URL in a "
            "browser to run the WebAuthn ceremony, then poll "
            f"tenzro_getPasskeySession:\n{json.dumps(result, indent=2)}"
        )

    # Enroll a new passkey-bound smart account.
    if (
        "enroll" in t
        or ("new" in t and ("account" in t or "passkey" in t))
        or "onboard" in t
    ):
        return (
            "To enroll a passkey-bound ERC-4337 smart account, register a "
            "WebAuthn credential in the browser, then either:\n"
            "  - say 'browser enroll passkey' to launch the ceremony "
            "(tenzro_createPasskeySession kind=enroll), or\n"
            "  - call tenzro_enrollPasskey directly with "
            "passkey_public_key_hex, credential_id_hex, ml_dsa_public_key_hex, "
            "an optional display_name, and a salt.\n"
            "The signing key never leaves the hardware secure element; the "
            "WebAuthnValidator is installed as the account's primary signer."
        )

    return (
        "Passkey-first custody (Coinbase / Daimo / Argent pattern):\n"
        "  - 'Enroll a passkey-bound smart account'\n"
        "  - 'Browser enroll passkey' (gcloud-style device flow)\n"
        "  - 'Add a device credential to 0xabc...'\n"
        "  - 'List passkeys for 0xabc...'\n"
        "  - 'Get passkey policy for 0xabc...' / 'Set two-credential policy for 0xabc...'\n"
        "  - 'Add a guardian to my account'\n"
        "  - 'Initiate a recovery ceremony to rotate my passkey'\n"
        "  - 'List pending recoveries for 0xabc...' / 'Finalize recovery <uuid>'\n"
        "  - 'Grant a session key to my trading agent'"
    )


# ---------------------------------------------------------------------------
# Custody
# ---------------------------------------------------------------------------


async def handle_custody(text: str, metadata: dict | None = None) -> str:
    t = text.lower()

    if "create" in t or "new" in t:
        result = await rpc_call(
            "tenzro_createMpcWallet", {"threshold": 2, "total_shares": 3}
        )
        return (
            f"FROST-Ed25519 threshold wallet created:\n{json.dumps(result, indent=2)}"
        )

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
            "  The wallet will be restored with its FROST-Ed25519 secret shares."
        )

    if "rotate" in t:
        addr = _extract_address(text)
        if addr:
            return f"Key rotation for {addr} refreshes FROST-Ed25519 secret shares without changing the address."
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
                "To revoke a session key, provide:\n  - Wallet address\n  - Session ID"
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
        "Custody & FROST-Ed25519 threshold wallet operations:\n"
        "  - 'Create a new FROST-Ed25519 threshold wallet'\n"
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


async def handle_zk(text: str, metadata: dict | None = None) -> str:
    t = text.lower()

    if "create" in t or "prove" in t or "generate proof" in t:
        return (
            "To create a Plonky3 STARK proof, provide:\n"
            '  - circuit_id: one of "inference", "settlement", "identity"\n'
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
            '  {"circuit_id": "inference|settlement|identity", '
            '"proof_bytes": "<hex>", "public_inputs": ["<hex>", ...]}\n'
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


async def handle_ap2(text: str, metadata: dict | None = None) -> str:
    """AP2 v0.2 session lifecycle + mandate verification (Checkout/Payment VDCs)."""
    t = text.lower()

    # Protocol info
    if "protocol" in t or "info" in t or "version" in t or "supported" in t:
        result = await rpc_call("tenzro_ap2ProtocolInfo", [])
        return f"AP2 protocol info:\n{json.dumps(result, indent=2)}"

    # Sign a Checkout or Payment mandate via the auth-bound wallet
    if "sign" in t and (
        "mandate" in t or "vdc" in t or "checkout" in t or "payment" in t
    ):
        md = metadata or {}
        mandate_kind = md.get("mandate_kind")
        mandate = md.get("mandate")
        signer_did = md.get("signer_did") or _extract_did(text)
        if (
            mandate_kind not in ("checkout", "payment")
            or mandate is None
            or not signer_did
        ):
            return (
                "To sign an AP2 v0.2 mandate, provide:\n"
                "  metadata.mandate_kind  ('checkout' | 'payment')\n"
                "  metadata.mandate       (full CheckoutMandate or PaymentMandate JSON)\n"
                "  metadata.signer_did    (must match the auth-bound wallet's controller DID)\n"
                "Auth: DPoP+JWT mandatory. Wallet must be Ed25519 (AP2 v0.2)."
            )
        result = await rpc_call(
            "tenzro_ap2SignMandate",
            [
                {
                    "mandate_kind": mandate_kind,
                    "mandate": mandate,
                    "signer_did": signer_did,
                }
            ],
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
            [
                {
                    "checkout_vdc": checkout_vdc,
                    "payment_vdc": payment_vdc,
                    "enforce_delegation": enforce_delegation,
                }
            ],
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
                [
                    {
                        "agent_did": agent_did,
                        "provider_did": provider_did,
                        "service": service,
                        "max_amount": str(amount),
                        "asset": asset,
                    }
                ],
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
        result = await rpc_call("tenzro_ap2CancelSession", [{"session_id": session_id}])
        return f"AP2 session cancelled:\n{json.dumps(result, indent=2)}"

    if session_id:
        result = await rpc_call("tenzro_ap2GetSession", [{"session_id": session_id}])
        return f"AP2 session:\n{json.dumps(result, indent=2)}"

    if "list" in t and "mandate" in t:
        controller_did = md.get("controller_did") or _extract_did(text)
        if controller_did:
            result = await rpc_call(
                "tenzro_listMandates", [{"controller_did": controller_did}]
            )
            return f"AP2 mandates for {controller_did}:\n{json.dumps(result, indent=2)}"
        return "Provide a controller DID (metadata.controller_did) to list persisted mandates."

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


async def handle_erc8004(text: str, metadata: dict | None = None) -> str:
    """ERC-8004 Trustless Agents Registry — full v0.6+ calldata surface (Identity / Reputation / Validation)."""
    t = text.lower()
    md = metadata or {}

    # ── Identity registry ────────────────────────────────────────────

    if "register" in t:
        agent_uri = md.get("agent_uri") or md.get("uri") or md.get("metadata_uri")
        metadata = md.get("metadata")
        if agent_uri and isinstance(metadata, list):
            result = await rpc_call(
                "tenzro_erc8004EncodeRegisterWithMetadata",
                [{"agent_uri": agent_uri, "metadata": metadata}],
            )
            return f"ERC-8004 register(string,(string,bytes)[]) calldata:\n{json.dumps(result, indent=2)}"
        if agent_uri:
            result = await rpc_call(
                "tenzro_erc8004EncodeRegisterWithUri",
                [{"agent_uri": agent_uri}],
            )
            return (
                f"ERC-8004 register(string) calldata:\n{json.dumps(result, indent=2)}"
            )
        result = await rpc_call("tenzro_erc8004EncodeRegister", [{}])
        return f"ERC-8004 register() calldata:\n{json.dumps(result, indent=2)}"

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
                [
                    {
                        "agent_id": agent_id,
                        "new_wallet": new_wallet,
                        "deadline": int(deadline),
                        "signature": signature,
                    }
                ],
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
                [
                    {
                        "agent_id": agent_id,
                        "feedback_id": feedback_id,
                        "response_uri": response_uri,
                    }
                ],
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
            return (
                f"ERC-8004 isFeedbackRevoked calldata:\n{json.dumps(result, indent=2)}"
            )
        return (
            "Encode isFeedbackRevoked() with: metadata.agent_id, metadata.feedback_id"
        )

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
            return (
                f"ERC-8004 getFeedbackCount calldata:\n{json.dumps(result, indent=2)}"
            )
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
                [
                    {
                        "subject_agent_id": subject,
                        "rating": int(rating),
                        "context_uri": context_uri,
                    }
                ],
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
                [
                    {
                        "validator_address": validator_address,
                        "agent_id": agent_id,
                        "request_uri": request_uri,
                        "request_hash": request_hash,
                    }
                ],
            )
            return (
                f"ERC-8004 validationRequest calldata:\n{json.dumps(result, indent=2)}"
            )
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
        if (
            request_hash
            and response is not None
            and response_uri
            and response_hash
            and tag
        ):
            result = await rpc_call(
                "tenzro_erc8004EncodeValidationResponse",
                [
                    {
                        "request_hash": request_hash,
                        "response": response,
                        "response_uri": response_uri,
                        "response_hash": response_hash,
                        "tag": tag,
                    }
                ],
            )
            return (
                f"ERC-8004 validationResponse calldata:\n{json.dumps(result, indent=2)}"
            )
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


async def handle_wormhole(text: str, metadata: dict | None = None) -> str:
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
            result = await rpc_call("tenzro_wormholeParseVaaId", [{"vaa_id": vaa_id}])
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
                [
                    {
                        "source_chain": source_chain,
                        "dest_chain": dest_chain,
                        "asset": asset,
                        "amount": str(amount),
                        "sender": sender,
                        "recipient": recipient,
                    }
                ],
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


async def handle_cct(text: str, metadata: dict | None = None) -> str:
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


async def handle_auth(text: str, metadata: dict | None = None) -> str:
    """OAuth 2.1 + DPoP auth flows: onboard human/agent, refresh access tokens,
    link an existing FROST-Ed25519 threshold wallet to a new auth session.

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
            "requested_aap_capabilities": md.get("requested_aap_capabilities", []),
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


async def handle_approval(text: str, metadata: dict | None = None) -> str:
    """Out-of-band approval loop for actions the controller put on the
    always-ask list.

    The agent's first attempt at such an action returns JSON-RPC -32002
    carrying `data.approval_id`. The approver then lists pending records,
    inspects one, and decides. On `approved` the agent retries the *same*
    action with that `approval_id` and it executes -- the approval is
    single-use and is checked for action parity, so an approval for one
    amount cannot be redeemed against another. On `denied` the retry
    returns -32001 carrying the approver's `deny_reason`, so the agent
    learns why and can adapt rather than only learning it was refused.
    """
    t = text.lower()
    md = metadata or {}
    approval_id = md.get("approval_id")

    if "decide" in t or "approve" in t or "deny" in t or "reject" in t:
        if not approval_id:
            return (
                "To decide an approval, supply metadata.approval_id (returned "
                "as data.approval_id on the -32002 error from the original "
                "attempt) and metadata.approver_did.\n"
                "Optional: metadata.deny_reason -- recorded on a denial and "
                "returned to the requesting agent when it retries, so the "
                "agent can act on the reason. Ignored for an approval."
            )
        decision = md.get("decision")
        if not decision:
            decision = "denied" if ("deny" in t or "reject" in t) else "approved"
        params = {"approval_id": approval_id, "decision": decision}
        if md.get("approver_did"):
            params["approver_did"] = md["approver_did"]
        if md.get("deny_reason"):
            params["deny_reason"] = md["deny_reason"]
        result = await rpc_call("tenzro_decideApproval", params)
        return json.dumps(result, indent=2)

    if "pending" in t or "list" in t:
        approver_did = md.get("approver_did")
        if not approver_did:
            return (
                "To list pending approvals, supply metadata.approver_did -- "
                "the DID the requests were routed to for signoff."
            )
        result = await rpc_call(
            "tenzro_listPendingApprovals", {"approver_did": approver_did}
        )
        return json.dumps(result, indent=2)

    if approval_id:
        result = await rpc_call("tenzro_getApproval", {"approval_id": approval_id})
        return json.dumps(result, indent=2)

    return (
        "Approval operations:\n"
        "  - 'List pending approvals'   (metadata.approver_did)              -- tenzro_listPendingApprovals\n"
        "  - 'Get approval'             (metadata.approval_id)               -- tenzro_getApproval\n"
        "  - 'Approve request'          (metadata.approval_id, approver_did) -- tenzro_decideApproval\n"
        "  - 'Deny request'             (metadata.approval_id, approver_did, deny_reason)\n"
        "\n"
        "The loop: the agent's first attempt at an always-ask action returns\n"
        "-32002 with data.approval_id. Once approved, the agent retries the\n"
        "same action passing approval_id and it executes -- approvals are\n"
        "single-use and must match the action they were granted for. A denial\n"
        "returns -32001 carrying deny_reason so the agent can adapt."
    )


async def handle_help(text: str, metadata: dict | None = None) -> str:
    return (
        "Tenzro Network Agent -- 70 skills available. Highlights:\n"
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
        "    media-gen   - Generative image and video, priced per pixel-step\n"
        "    task_marketplace - Post/browse AI tasks with escrow\n"
        "    agent_marketplace - Discover/spawn agent templates\n"
        "    agent_spawning - Spawn autonomous sub-agents\n"
        "    capability_registry - Discover capabilities and their attestations\n"
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
        "    custody      - FROST-Ed25519 threshold wallets, keystore, sessions, limits\n"
        "    passkey      - Passkey-bound ERC-4337 accounts, social recovery, session keys\n"
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


async def handle_lifecycle(text: str, metadata: dict | None = None) -> str:
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


async def handle_capital(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "open" in t or "create" in t:
        return (
            "Open a Capital Intent (capital-markets analog of an AP2 Intent Mandate):\n"
            "  RPC: tenzro_capitalIntentOpen\n"
            "  Payload (CapitalIntent): { objective: { kind, basket | target },\n"
            "                            constraints: { max_price?, max_eta_secs?, ... },\n"
            "                            compliance: { reg_regime?, required_kya?, jurisdictions? },\n"
            "                            authorization: { principal_did, signature, expires_at },\n"
            "                            settlement_req: { payer, payee?, asset_id, amount } }\n"
            "  objective.kind ∈ { acquire | exit | rebalance | hedge | yield }."
        )
    if "quote" in t or "bid" in t:
        return (
            "Submit a solver bid against an opened intent:\n"
            "  RPC: tenzro_capitalIntentQuote\n"
            "  Required: { intent_id, solver_did, plan, price, eta_secs }"
        )
    if "assign" in t or "select" in t or "pick" in t:
        return (
            "Assign a Capital Intent to a solver:\n"
            "  RPC: tenzro_capitalIntentAssign\n"
            "  Required: { intent_id }\n"
            "  Optional: { solver_did, auto: true (auto-rank by ERC-8004 + price + eta), payer, payee }"
        )
    if "execute" in t or "leg" in t:
        return (
            "Execute a leg of an assigned intent:\n"
            "  RPC: tenzro_capitalIntentExecute\n"
            "  Required: { intent_id, leg: { venue, asset_id, side: 'acquire' | 'exit',\n"
            "                                quantity, unit_price, settlement_ref?, proof? } }"
        )
    if "verify" in t:
        return "Verify a step: tenzro_capitalIntentVerify { intent_id }"
    if "compensat" in t or "roll" in t or "rollback" in t:
        return "Compensate (roll back) a step: tenzro_capitalIntentCompensate { intent_id }"
    if "settle" in t or "release" in t:
        return (
            "Settle the intent — release escrow to the payee:\n"
            "  RPC: tenzro_capitalIntentSettle { intent_id, payee? }"
        )
    if "get" in t:
        return "Read intent state: tenzro_getCapitalIntent { intent_id }"
    if "reserve" in t and "attest" in t:
        return (
            "Reserve attestations (1:1 backing for tokenized assets):\n"
            "  Submit:  tenzro_submitReserveAttestation { attestation }\n"
            "  Read:    tenzro_getReserve { asset_id }\n"
            "  attestation shape: { asset_id, source, amount, attester_did,\n"
            "                       signature, attested_at, proof? }"
        )
    if "mint" in t and ("attest" in t or "back" in t):
        return (
            "Attested mint — token issuance gated by a fresh reserve attestation:\n"
            "  RPC: tenzro_attestedMint { token_id, to, amount, caller }"
        )
    return (
        "Capital Intent (regulated capital allocation) — capital-markets analog of an AP2 Intent Mandate.\n"
        "  - 'Open a Capital Intent'    (tenzro_capitalIntentOpen)\n"
        "  - 'Submit a solver quote'    (tenzro_capitalIntentQuote)\n"
        "  - 'Auto-assign intent'       (tenzro_capitalIntentAssign auto=true)\n"
        "  - 'Execute leg'              (tenzro_capitalIntentExecute)\n"
        "  - 'Verify step'              (tenzro_capitalIntentVerify)\n"
        "  - 'Compensate step'          (tenzro_capitalIntentCompensate)\n"
        "  - 'Settle intent'            (tenzro_capitalIntentSettle)\n"
        "  - 'Submit reserve attestation' (tenzro_submitReserveAttestation)\n"
        "  - 'Attested mint'            (tenzro_attestedMint)"
    )


async def handle_workflow(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "open" in t or "start" in t or "create" in t:
        return (
            "Open a multi-agent saga workflow:\n"
            "  RPC: tenzro_workflowOpen\n"
            "  Payload: { creator_did, participants[], steps[{step_id, status}], metadata? }"
        )
    if "execute" in t and "step" in t:
        return (
            "Execute a step (Pending → Executing, optionally lock per-step escrow):\n"
            "  RPC: tenzro_workflowStepExecute { workflow_id, step_id, escrow_amount? }"
        )
    if "verify" in t and "step" in t:
        return "Verify a step's outcome: tenzro_workflowStepVerify { workflow_id, step_id }"
    if "compensat" in t and "step" in t:
        return "Compensate a step (roll back): tenzro_workflowStepCompensate { workflow_id, step_id }"
    if "finaliz" in t:
        return (
            "Finalize the workflow — emits a WorkflowReceipt when all steps complete:\n"
            "  RPC: tenzro_workflowFinalize { workflow_id }"
        )
    if "saga" in t:
        return "Read the underlying saga (step state): tenzro_getWorkflowSaga { workflow_id }"
    if "lifecycle" in t:
        return "Read the lifecycle record: tenzro_getWorkflowLifecycle { workflow_id }"
    if "receipt" in t:
        if "list" in t:
            return (
                "List recent workflow receipts: tenzro_listWorkflowReceipts { limit? }"
            )
        return "Read the workflow receipt: tenzro_getWorkflowReceipt { workflow_id }"
    if "metric" in t:
        return "Read operational metrics: tenzro_getWorkflowOperationalMetrics { workflow_id }"
    if "canton" in t or "mirror" in t:
        return "Mirror a workflow to Canton DAML: tenzro_mirrorWorkflowToCanton { workflow_id }"
    if "creator" in t:
        return "List workflows by creator DID: tenzro_listWorkflowsByCreator { creator_did }"
    if "participant" in t:
        return "List workflows by participant DID: tenzro_listWorkflowsByParticipant { participant_did }"
    if "status" in t:
        return "List workflows by status: tenzro_listWorkflowsByStatus { status }"
    if "envelope" in t:
        return "Verify a DID-signed envelope: tenzro_verifyDidEnvelope { envelope }"
    return (
        "Multi-agent saga workflows — Execute → Verify → Compensate step lifecycles.\n"
        "  - 'Open workflow'            (tenzro_workflowOpen)\n"
        "  - 'Execute step'             (tenzro_workflowStepExecute)\n"
        "  - 'Verify step'              (tenzro_workflowStepVerify)\n"
        "  - 'Compensate step'          (tenzro_workflowStepCompensate)\n"
        "  - 'Finalize workflow'        (tenzro_workflowFinalize)\n"
        "  - 'Get workflow'             (tenzro_getWorkflow / getWorkflowSaga / getWorkflowLifecycle)\n"
        "  - 'List receipts'            (tenzro_listWorkflowReceipts)\n"
        "  - 'List by creator/participant/status' (tenzro_listWorkflowsBy*)\n"
        "  - 'Mirror to Canton'         (tenzro_mirrorWorkflowToCanton)\n"
        "  - 'Verify DID envelope'      (tenzro_verifyDidEnvelope)"
    )


async def handle_eip7702(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "signing" in t or "signing hash" in t:
        return (
            "Compute the EIP-7702 secp256k1 signing hash for an authorization tuple:\n"
            "  RPC: tenzro_eip7702SigningHash { chain_id, delegate_address, nonce }\n"
            "  Returns: signing_hash (32-byte keccak), signing_data, magic_byte=0x05\n"
            "  Sign the hash with the EOA's secp256k1 private key out of band."
        )
    if "designator" in t and ("build" in t or "construct" in t):
        return (
            "Build the 23-byte EIP-7702 designator (0xef0100 || delegate_address):\n"
            "  RPC: tenzro_eip7702BuildDesignator { delegate_address }"
        )
    if "parse" in t or "decode" in t:
        return (
            "Decode account code; report the delegate address if it is a valid 7702 designator:\n"
            "  RPC: tenzro_eip7702ParseDesignator { code }"
        )
    if "protocol" in t or "info" in t:
        return (
            "Read EIP-7702 static protocol metadata:\n  RPC: tenzro_eip7702ProtocolInfo"
        )
    return (
        "EIP-7702 (Set EOA Account Code) helpers — Pectra Type-4 delegation registry.\n"
        "  - 'Signing hash'         (tenzro_eip7702SigningHash)\n"
        "  - 'Build designator'     (tenzro_eip7702BuildDesignator)\n"
        "  - 'Parse designator'     (tenzro_eip7702ParseDesignator)\n"
        "  - 'Protocol info'        (tenzro_eip7702ProtocolInfo)"
    )


async def handle_permit2(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "domain" in t and "separator" in t:
        return (
            "Read the per-chain Permit2 EIP-712 domain separator:\n"
            "  RPC: tenzro_permit2DomainSeparator { chain_id }\n"
            "  Verifying contract: 0x0000…00001023 (canonical Tenzro Permit2)"
        )
    if "digest" in t:
        return (
            "Compute the EIP-712 digest a user signs:\n"
            "  RPC: tenzro_permit2Digest { chain_id, owner, token, amount, spender, nonce, deadline, witness?, witness_type_string? }\n"
            "  Witness is optional — used by ERC-7683 origin opens to bind the permit to a specific cross-chain order."
        )
    if "verify" in t or "consume" in t:
        return (
            "Atomically verify a signed Permit2 message and consume its (owner, nonce) slot:\n"
            "  RPC: tenzro_permit2VerifyAndConsume { chain_id, owner, token, amount, spender, nonce, deadline, signature, witness?, witness_type_string? }"
        )
    if "nonce" in t and "used" in t:
        return (
            "Check whether a (owner, nonce) slot has been consumed:\n"
            "  RPC: tenzro_permit2NonceUsed { owner, nonce }"
        )
    return (
        "Permit2 SignatureTransfer (canonical Tenzro Permit2 at 0x0000…00001023).\n"
        "  - 'Domain separator'     (tenzro_permit2DomainSeparator)\n"
        "  - 'Digest'               (tenzro_permit2Digest)\n"
        "  - 'Verify and consume'   (tenzro_permit2VerifyAndConsume)\n"
        "  - 'Nonce used'           (tenzro_permit2NonceUsed)"
    )


async def handle_secure_mint(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "pause" in t and "global" in t:
        return (
            "Trip or clear the global issuance circuit breaker (admin-gated):\n"
            "  RPC: tenzro_setGlobalIssuancePause { paused }"
        )
    if "pause" in t:
        return (
            "Trip or clear the per-token issuance circuit breaker (admin-gated):\n"
            "  RPC: tenzro_setSecureMintPaused { token, paused }"
        )
    if "set" in t and "polic" in t:
        return (
            "Set or update a Secure-Mint policy for a tokenized asset:\n"
            "  RPC: tenzro_setSecureMintPolicy { token, asset_id, reserve, circulating?, por_feed_id, attester_did, attestation_hash, attested_at, ttl_secs, heartbeat_secs?, mint_window_cap?, mint_window_secs?, paused? }"
        )
    if "get" in t and "polic" in t:
        return "Read the Secure-Mint policy: tenzro_getSecureMintPolicy { token }"
    if "clear" in t and "polic" in t:
        return "Clear the Secure-Mint policy: tenzro_clearSecureMintPolicy { token }"
    if "check" in t:
        return (
            "Read-only invariant check for a proposed mint:\n"
            "  RPC: tenzro_secureMintCheck { token, amount }"
        )
    if "apply" in t or "mint" in t:
        return (
            "Atomically check the 1:1 invariant and increment circulating:\n"
            "  RPC: tenzro_secureMintApply { token, amount }"
        )
    if "burn" in t or "redemption" in t:
        return (
            "Record a redemption (decrement circulating):\n"
            "  RPC: tenzro_secureMintRecordBurn { token, amount }"
        )
    return (
        "Secure-Mint registry — per-token 1:1 reserve-attestation invariant for tokenized RWAs.\n"
        "  - 'Set policy'           (tenzro_setSecureMintPolicy)\n"
        "  - 'Get / clear policy'   (tenzro_getSecureMintPolicy / clearSecureMintPolicy)\n"
        "  - 'Check'                (tenzro_secureMintCheck)\n"
        "  - 'Apply'                (tenzro_secureMintApply)\n"
        "  - 'Record burn'          (tenzro_secureMintRecordBurn)\n"
        "  - 'Pause token'          (tenzro_setSecureMintPaused)\n"
        "  - 'Global pause'         (tenzro_setGlobalIssuancePause)"
    )


async def handle_treasury(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    md = metadata or {}

    if "approve" in t:
        required = [
            "withdrawal_id",
            "asset_id",
            "amount",
            "approver",
            "public_key",
            "signature",
        ]
        if all(k in md for k in required):
            result = await rpc_call(
                "tenzro_treasuryApproveWithdrawal",
                {
                    "withdrawal_id": md["withdrawal_id"],
                    "asset_id": md["asset_id"],
                    "amount": str(md["amount"]),
                    "approver": md["approver"],
                    "key_type": md.get("key_type", "ed25519"),
                    "public_key": md["public_key"],
                    "signature": md["signature"],
                },
            )
            return f"Treasury withdrawal approval:\n{json.dumps(result, indent=2)}"
        return (
            "Approve a treasury withdrawal with a signed approval:\n"
            "  RPC: tenzro_treasuryApproveWithdrawal { withdrawal_id, asset_id, amount, approver, key_type?, public_key, signature }\n"
            '  Signature preimage: "tenzro/treasury/withdrawal-approval" || withdrawal_id || asset_id || amount (u128 LE)\n'
            "  Pass the fields via message metadata to submit directly."
        )

    if "execute" in t:
        if all(k in md for k in ["withdrawal_id", "asset_id", "amount"]):
            result = await rpc_call(
                "tenzro_treasuryExecuteWithdrawal",
                {
                    "withdrawal_id": md["withdrawal_id"],
                    "asset_id": md["asset_id"],
                    "amount": str(md["amount"]),
                },
            )
            return f"Treasury withdrawal execution:\n{json.dumps(result, indent=2)}"
        return (
            "Execute a treasury withdrawal once approvals reach the threshold:\n"
            "  RPC: tenzro_treasuryExecuteWithdrawal { withdrawal_id, asset_id, amount }\n"
            "  Pass the fields via message metadata to submit directly."
        )

    if "pending" in t or "show" in t or "get" in t or "status" in t:
        wid = md.get("withdrawal_id")
        if not wid:
            m = re.search(r"\b(wd-[\w-]+)\b", text)
            if m:
                wid = m.group(1)
        if wid:
            result = await rpc_call(
                "tenzro_treasuryGetPendingWithdrawal",
                {"withdrawal_id": wid},
            )
            return f"Pending treasury withdrawal {wid}:\n{json.dumps(result, indent=2)}"

    return (
        "Treasury multisig withdrawals:\n"
        "  - 'Show pending treasury withdrawal <id>'  (tenzro_treasuryGetPendingWithdrawal)\n"
        "  - 'Approve treasury withdrawal'            (tenzro_treasuryApproveWithdrawal — signed approval via metadata)\n"
        "  - 'Execute treasury withdrawal'            (tenzro_treasuryExecuteWithdrawal)\n"
        "  Withdrawer-set and threshold changes are admin-token-gated operator RPCs\n"
        "  (tenzro_treasuryAddWithdrawer / RemoveWithdrawer / SetWithdrawalThreshold)."
    )


async def handle_stable_asset(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "register" in t:
        return (
            "Register an issuer's stable-asset policy (needs the `issuer` API-key scope):\n"
            "  RPC: tenzro_registerStableAsset { issuer, unit_token, symbol, reserve_source, por_feed_id, allowed_rails, settlement_dst }\n"
            "  reserve_source: { kind: 'custodial', attester_did, asset_caip19 } or { kind: 'on_chain_vault', vault, asset_caip19 }"
        )
    if "get" in t or "read" in t or "polic" in t:
        return "Read an issuer's stable-asset policy: tenzro_getStableAsset { issuer, unit_token }"
    if "redeem" in t or "burn" in t:
        return (
            "Redeem (burn) stable units, decrementing circulating:\n"
            "  RPC: tenzro_redeemStableAsset { issuer, unit_token, amount }"
        )
    if "mint" in t:
        return (
            "Mint stable units, hard-gated by the Secure-Mint reserve floor:\n"
            "  RPC: tenzro_mintStableAsset { issuer, unit_token, amount }"
        )
    return (
        "Stable-Asset issuance — issuer-agnostic stable units layered on the Secure-Mint reserve floor.\n"
        "  - 'Register'   (tenzro_registerStableAsset, needs `issuer` scope)\n"
        "  - 'Get'        (tenzro_getStableAsset)\n"
        "  - 'Mint'       (tenzro_mintStableAsset)\n"
        "  - 'Redeem'     (tenzro_redeemStableAsset)"
    )


async def handle_hyperlane(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "list" in t and "chain" in t:
        return "List supported Hyperlane chains: tenzro_hyperlaneListChains"
    if "quote" in t:
        return (
            "Quote interchain gas for a dispatch:\n"
            "  RPC: tenzro_hyperlaneQuoteDispatch { origin_domain, destination_domain, recipient, body_hex, sender?, interchain_gas_payment? }"
        )
    if "dispatch" in t or "send" in t:
        return (
            "Dispatch a Hyperlane V3 message through the canonical Mailbox:\n"
            "  RPC: tenzro_hyperlaneDispatch { origin_domain, destination_domain, recipient, body_hex, sender?, interchain_gas_payment? }"
        )
    if "message" in t or "lookup" in t or "get" in t:
        return "Look up a Hyperlane message: tenzro_hyperlaneGetMessage { message_id }"
    return (
        "Hyperlane V3 messaging — sovereign Tenzro-validator-set ISM.\n"
        "  - 'List chains'          (tenzro_hyperlaneListChains)\n"
        "  - 'Quote dispatch'       (tenzro_hyperlaneQuoteDispatch)\n"
        "  - 'Dispatch'             (tenzro_hyperlaneDispatch)\n"
        "  - 'Get message'          (tenzro_hyperlaneGetMessage)"
    )


async def handle_axelar(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "list" in t and "chain" in t:
        return (
            "List supported Axelar chains (30+ across EVM / Cosmos / Move / Stellar / XRPL):\n"
            "  RPC: tenzro_axelarListChains"
        )
    if "call" in t and "contract" in t:
        return (
            "Dispatch an Axelar GMP call_contract message:\n"
            "  RPC: tenzro_axelarCallContract { source_chain, destination_chain, destination_address, payload_hex, gas_token?, gas_amount? }"
        )
    if "pay" in t and "gas" in t:
        return (
            "Pre-pay the Axelar Gas Service for a previously-dispatched message:\n"
            "  RPC: tenzro_axelarPayGas { payload_hash, source_chain, destination_chain, destination_address, gas_token, gas_amount }"
        )
    if "message" in t or "lookup" in t or "get" in t:
        return "Look up an Axelar GMP message: tenzro_axelarGetMessage { payload_hash }"
    return (
        "Axelar GMP — Cosmos / Move / Stellar / XRPL reach via call_contract + Gas Service.\n"
        "  - 'List chains'          (tenzro_axelarListChains)\n"
        "  - 'Call contract'        (tenzro_axelarCallContract)\n"
        "  - 'Pay gas'              (tenzro_axelarPayGas)\n"
        "  - 'Get message'          (tenzro_axelarGetMessage)"
    )


async def handle_babylon(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "register" in t and "finality" in t:
        return (
            "Register a Tenzro validator as a Babylon finality provider:\n"
            "  RPC: tenzro_babylonRegisterFinalityProvider { validator, btc_pk, commission_bps }"
        )
    if "list" in t and "finality" in t:
        return "List registered finality providers: tenzro_babylonListFinalityProviders"
    if "total" in t and ("stake" in t or "delegation" in t):
        return (
            "Sum BTC delegations for a finality provider:\n"
            "  RPC: tenzro_babylonTotalStakeForProvider { validator }"
        )
    if "submit" in t and "finality" in t:
        return (
            "Submit an EOTS over a Tenzro block hash (slashable on equivocation):\n"
            "  RPC: tenzro_babylonSubmitFinalitySignature { validator, block_hash, eots_signature }"
        )
    if "delegation" in t:
        return "List BTC delegations for a finality provider: tenzro_babylonListDelegations { validator }"
    return (
        "Babylon Bitcoin staking — Tenzro validators economically secured by native BTC.\n"
        "  - 'Register finality provider'  (tenzro_babylonRegisterFinalityProvider)\n"
        "  - 'List finality providers'     (tenzro_babylonListFinalityProviders)\n"
        "  - 'Total stake'                 (tenzro_babylonTotalStakeForProvider)\n"
        "  - 'Submit finality signature'   (tenzro_babylonSubmitFinalitySignature)\n"
        "  - 'List delegations'            (tenzro_babylonListDelegations)"
    )


async def handle_caip(text: str, metadata: dict | None = None) -> str:
    t = text.lower()
    if "caip-2" in t or "caip2" in t or "chain id" in t:
        return (
            "Get the CAIP-2 chain id (`tenzro:<lowercase hex of first 16 bytes of genesis block hash>`):\n"
            "  RPC: tenzro_caip2"
        )
    if "caip-10" in t or "caip10" in t or "account id" in t:
        return (
            "Get the CAIP-10 account id (accepts hex or base58btc on input, normalises to canonical 64-hex):\n"
            "  RPC: tenzro_caip10 { address }"
        )
    if "caip-19" in t or "caip19" in t or "asset id" in t or "asset_namespace" in t:
        return (
            "Get the CAIP-19 asset id (supports `slip44` / `token` / `nft` asset namespaces):\n"
            "  RPC: tenzro_caip19 { kind, token_id?, collection_id?, nft_token_id? }\n"
            "  Native TNZO: kind=slip44 (SLIP-44 coin index 1414421071)."
        )
    return (
        "Tenzro CAIP namespace identifiers per ChainAgnostic/namespaces#184.\n"
        "  - 'CAIP-2'               (tenzro_caip2)\n"
        "  - 'CAIP-10'              (tenzro_caip10 { address })\n"
        "  - 'CAIP-19'              (tenzro_caip19 { kind, token_id?, collection_id?, nft_token_id? })"
    )


# ---------------------------------------------------------------------------
# Storage Market
# ---------------------------------------------------------------------------


async def handle_storage(text: str, metadata: dict | None = None) -> str:
    """Storage-market reads and provider operations.

    Deals, objects, charge epochs, and pricing carry structured fields
    that cannot be expressed in free text, so they read from `metadata`.
    """
    t = text.lower()
    md = metadata or {}

    if "store" in t and md.get("object_id") and md.get("data"):
        params = {
            "object_id": md["object_id"],
            "data": md["data"],
            "data_shards": md.get("data_shards", 4),
            "parity_shards": md.get("parity_shards", 2),
        }
        if md.get("owner"):
            params["owner"] = md["owner"]
        result = await rpc_call("tenzro_storageStoreObject", params)
        return f"Object stored:\n{json.dumps(result, indent=2)}"

    if ("open" in t or "deal" in t) and md.get("object_id") and md.get("renter"):
        result = await rpc_call(
            "tenzro_storageOpenDeal",
            {
                "object_id": md["object_id"],
                "renter": md["renter"],
                "size_bytes": md.get("size_bytes", 0),
                "total_epochs": md.get("total_epochs", 0),
            },
        )
        return f"Storage deal opened:\n{json.dumps(result, indent=2)}"

    if ("charge" in t or "epoch" in t) and md.get("deal_id"):
        result = await rpc_call("tenzro_storageChargeEpoch", {"deal_id": md["deal_id"]})
        return f"Storage charge epoch:\n{json.dumps(result, indent=2)}"

    if md.get("deal_id"):
        result = await rpc_call("tenzro_storageGetDeal", {"deal_id": md["deal_id"]})
        return f"Storage deal:\n{json.dumps(result, indent=2)}"

    if "pricing" in t and md.get("capacity"):
        params = {"mode": md.get("mode", "dynamic"), "capacity": md["capacity"]}
        if md.get("min_rate"):
            params["min_rate"] = md["min_rate"]
        if md.get("max_rate"):
            params["max_rate"] = md["max_rate"]
        result = await rpc_call("tenzro_storageSetPricing", params)
        return f"Storage pricing set:\n{json.dumps(result, indent=2)}"

    if "status" in t or "provider" in t:
        result = await rpc_call("tenzro_storageStatus", [])
        return f"Storage provider status:\n{json.dumps(result, indent=2)}"

    return (
        "Storage-market operations:\n"
        "  - 'Storage status'\n"
        "  - 'Store object' (metadata: object_id, data base64, owner?, data_shards?, parity_shards?)\n"
        "  - 'Open storage deal' (metadata: object_id, renter, size_bytes, total_epochs)\n"
        "  - 'Charge storage epoch' (metadata: deal_id)\n"
        "  - 'Get storage deal' (metadata: deal_id)\n"
        "  - 'Set storage pricing' (metadata: mode, capacity, min_rate?, max_rate?)"
    )


# ---------------------------------------------------------------------------
# Compute Rental
# ---------------------------------------------------------------------------


async def handle_compute(text: str, metadata: dict | None = None) -> str:
    """Compute-rental reads and provider operations.

    Rental bookings and settlements carry structured fields, so they read
    from `metadata`.
    """
    t = text.lower()
    md = metadata or {}

    if "book" in t and md.get("renter"):
        result = await rpc_call(
            "tenzro_computeBookRental",
            {
                "renter": md["renter"],
                "total_epochs": md.get("total_epochs", 0),
            },
        )
        return f"Compute rental booked:\n{json.dumps(result, indent=2)}"

    if "settle" in t and md.get("rental_id"):
        result = await rpc_call(
            "tenzro_computeSettleEpoch",
            {
                "rental_id": md["rental_id"],
                "proof_valid": md.get("proof_valid", True),
            },
        )
        return f"Compute settle epoch:\n{json.dumps(result, indent=2)}"

    if md.get("rental_id"):
        result = await rpc_call(
            "tenzro_computeGetRental", {"rental_id": md["rental_id"]}
        )
        return f"Compute rental:\n{json.dumps(result, indent=2)}"

    if "pricing" in t and md.get("capacity"):
        params = {"mode": md.get("mode", "dynamic"), "capacity": md["capacity"]}
        if md.get("min_rate"):
            params["min_rate"] = md["min_rate"]
        if md.get("max_rate"):
            params["max_rate"] = md["max_rate"]
        result = await rpc_call("tenzro_computeSetPricing", params)
        return f"Compute pricing set:\n{json.dumps(result, indent=2)}"

    if "status" in t or "provider" in t:
        result = await rpc_call("tenzro_computeStatus", [])
        return f"Compute provider status:\n{json.dumps(result, indent=2)}"

    return (
        "Compute-rental operations:\n"
        "  - 'Compute status'\n"
        "  - 'Book compute rental' (metadata: renter, total_epochs)\n"
        "  - 'Settle compute epoch' (metadata: rental_id, proof_valid?)\n"
        "  - 'Get compute rental' (metadata: rental_id)\n"
        "  - 'Set compute pricing' (metadata: mode, capacity, min_rate?, max_rate?)"
    )


# ---------------------------------------------------------------------------
# MoE Expert Sharding
# ---------------------------------------------------------------------------


async def handle_moe(text: str, metadata: dict | None = None) -> str:
    """MoE expert-shard map, dispatch planning, replication policy, catalog
    topology, expert/gate weight loading, runtime status, and distributed
    layer forwards. The model id reads from `metadata` or free text; blob
    sources, layer/expert indices, and hidden states read from `metadata`.
    """
    t = text.lower()
    md = metadata or {}
    model_id = md.get("model_id")
    if not model_id:
        m = re.search(r"[\w./-]+", text.split()[-1]) if text.split() else None
        model_id = m.group(0) if m else None

    if "status" in t:
        result = await rpc_call("tenzro_moeExpertStatus", [])
        return f"MoE expert runtime status:\n{json.dumps(result, indent=2)}"

    if "policy" in t or "replication" in t:
        result = await rpc_call("tenzro_moeReplicationPolicy", [])
        return f"MoE replication policy:\n{json.dumps(result, indent=2)}"

    if "load" in t and "unload" not in t and model_id and md.get("layer") is not None:
        params = {"model_id": model_id, "layer": md["layer"]}
        if md.get("blob_base64"):
            params["blob_base64"] = md["blob_base64"]
        elif md.get("uri"):
            params["uri"] = md["uri"]
        if "gate" in t:
            result = await rpc_call("tenzro_moeGateLoad", params)
            return f"MoE gate load:\n{json.dumps(result, indent=2)}"
        if md.get("expert") is not None:
            params["expert"] = md["expert"]
            result = await rpc_call("tenzro_moeExpertLoad", params)
            return f"MoE expert load:\n{json.dumps(result, indent=2)}"

    if (
        "forward" in t
        and model_id
        and md.get("layer") is not None
        and md.get("d_model")
        and md.get("hidden_states")
    ):
        params = {
            "model_id": model_id,
            "layer": md["layer"],
            "d_model": md["d_model"],
            "hidden_states": md["hidden_states"],
            "allow_cold": md.get("allow_cold", False),
        }
        if md.get("top_k") is not None:
            params["top_k"] = md["top_k"]
        result = await rpc_call("tenzro_moeForward", params)
        return f"MoE distributed forward:\n{json.dumps(result, indent=2)}"

    if ("dispatch" in t or "plan" in t) and model_id and md.get("routings"):
        result = await rpc_call(
            "tenzro_moePlanDispatch",
            {
                "model_id": model_id,
                "routings": md["routings"],
                "allow_cold": md.get("allow_cold", False),
            },
        )
        return f"MoE dispatch plan:\n{json.dumps(result, indent=2)}"

    if ("shape" in t or "topology" in t or "catalog" in t) and model_id:
        result = await rpc_call("tenzro_moeCatalogShape", {"model_id": model_id})
        return f"MoE catalog shape:\n{json.dumps(result, indent=2)}"

    if model_id:
        result = await rpc_call("tenzro_moeShardMap", {"model_id": model_id})
        return f"MoE shard map for {model_id}:\n{json.dumps(result, indent=2)}"

    return (
        "MoE expert-shard operations:\n"
        "  - 'MoE shard map <model_id>'\n"
        "  - 'MoE catalog shape <model_id>'\n"
        "  - 'MoE replication policy'\n"
        "  - 'MoE plan dispatch <model_id>' (metadata: routings, allow_cold?)\n"
        "  - 'MoE expert status'\n"
        "  - 'MoE load expert' (metadata: model_id, layer, expert, blob_base64 | uri)\n"
        "  - 'MoE load gate' (metadata: model_id, layer, blob_base64 | uri)\n"
        "  - 'MoE forward' (metadata: model_id, layer, d_model, hidden_states, top_k?, allow_cold?)"
    )


# ---------------------------------------------------------------------------
# Generative Image & Video
# ---------------------------------------------------------------------------


async def handle_media_gen(text: str, metadata: dict | None = None) -> str:
    """Generative image and video: the curated diffusers catalog, a
    pixel-step price quote, the job queue, the worker registry, a job's
    signed receipt, and posting or cancelling a job. Job ids, task specs,
    and quote parameters read from `metadata`.
    """
    t = text.lower()
    md = metadata or {}
    job_id = md.get("job_id")

    if "catalog" in t:
        result = await rpc_call("tenzro_mediaGen_listCatalog", [])
        return f"Generative media catalog:\n{json.dumps(result, indent=2)}"

    if "quote" in t or "price" in t or "cost" in t:
        kind = md.get("kind", "text2image")
        params = md.get("params")
        if params is None:
            params = {
                k: md[k]
                for k in ("prompt", "model_id", "width", "height", "steps", "frames")
                if md.get(k) is not None
            }
        result = await rpc_call(
            "tenzro_mediaGen_quote", {"kind": kind, "params": params}
        )
        return f"Media-gen quote:\n{json.dumps(result, indent=2)}"

    if "worker" in t:
        result = await rpc_call("tenzro_mediaGen_listWorkers", [])
        return f"Media-gen workers:\n{json.dumps(result, indent=2)}"

    if "receipt" in t and job_id:
        result = await rpc_call("tenzro_mediaGen_getReceipt", {"job_id": job_id})
        return f"Media-gen receipt for {job_id}:\n{json.dumps(result, indent=2)}"

    if "post" in t and md.get("task_spec"):
        result = await rpc_call(
            "tenzro_mediaGen_postJob", {"task_spec": md["task_spec"]}
        )
        return f"Media-gen job posted:\n{json.dumps(result, indent=2)}"

    if "cancel" in t and job_id and md.get("requester_did"):
        result = await rpc_call(
            "tenzro_mediaGen_cancelJob",
            {
                "job_id": job_id,
                "requester_did": md["requester_did"],
            },
        )
        return f"Media-gen job cancelled:\n{json.dumps(result, indent=2)}"

    if job_id:
        result = await rpc_call("tenzro_mediaGen_getJob", {"job_id": job_id})
        return f"Media-gen job {job_id}:\n{json.dumps(result, indent=2)}"

    params = {"status": md["status"]} if md.get("status") else {}
    result = await rpc_call("tenzro_mediaGen_listJobs", params)
    return f"Media-gen jobs:\n{json.dumps(result, indent=2)}"


# ---------------------------------------------------------------------------
# Operability Inspection
# ---------------------------------------------------------------------------


async def handle_operability(text: str, metadata: dict | None = None) -> str:
    """Read-only operability surface: Tenzro Train run/receipt/manifest
    inspection, SLA fault-detector parameters and probes, and state-sync
    snapshot inspection. Validator-registry reads route to the
    validator-lifecycle handler. Identifiers read from `metadata` or free
    text.
    """
    t = text.lower()
    md = metadata or {}
    task_id = md.get("task_id")
    if not task_id:
        m = re.search(r"task-[\w.-]+", text)
        task_id = m.group(0) if m else None

    # --- SLA fault detector ---
    if "probe" in t:
        if (
            "issue" in t
            and md.get("provider_did")
            and md.get("epoch") is not None
            and md.get("round") is not None
        ):
            result = await rpc_call(
                "tenzro_slaIssueProbe",
                {
                    "provider_did": md["provider_did"],
                    "epoch": md["epoch"],
                    "round": md["round"],
                    "deadline_ms": md.get("deadline_ms", 5000),
                },
            )
            return f"SLA probe issued:\n{json.dumps(result, indent=2)}"
        result = await rpc_call("tenzro_slaListOutstandingProbes", [])
        return f"Outstanding SLA probes:\n{json.dumps(result, indent=2)}"

    if "sla" in t:
        result = await rpc_call("tenzro_slaGetParams", [])
        return f"SLA fault-detector parameters:\n{json.dumps(result, indent=2)}"

    # --- state-sync snapshots ---
    if "snapshot" in t or "state-sync" in t:
        if "chunk" in t and md.get("height") is not None:
            result = await rpc_call(
                "tenzro_getSnapshotChunk",
                {
                    "height": md["height"],
                    "chunk_index": md.get("chunk_index", 0),
                },
            )
            return f"Snapshot chunk:\n{json.dumps(result, indent=2)}"
        if "manifest" in t and md.get("height") is not None:
            result = await rpc_call(
                "tenzro_getSnapshotManifest", {"height": md["height"]}
            )
            return f"Snapshot manifest:\n{json.dumps(result, indent=2)}"
        result = await rpc_call("tenzro_listSnapshots", [])
        return f"Local snapshots:\n{json.dumps(result, indent=2)}"

    # --- Tenzro Train inspection ---
    if "daemon" in t or "trainer status" in t:
        result = await rpc_call("tenzro_getTrainerDaemonStatus", {})
        return f"Trainer daemon status:\n{json.dumps(result, indent=2)}"

    if "receipt" in t and task_id:
        result = await rpc_call("tenzro_training_getReceipt", {"task_id": task_id})
        return f"Training receipt for {task_id}:\n{json.dumps(result, indent=2)}"

    if ("manifest" in t or "sealed" in t) and task_id:
        result = await rpc_call(
            "tenzro_training_getSealedManifest", {"task_id": task_id}
        )
        return f"Sealed-shard manifest for {task_id}:\n{json.dumps(result, indent=2)}"

    if task_id:
        result = await rpc_call("tenzro_training_getRun", {"task_id": task_id})
        return f"Training run {task_id}:\n{json.dumps(result, indent=2)}"

    if "train" in t and ("run" in t or "list" in t):
        result = await rpc_call("tenzro_training_listRuns", [])
        return f"Tenzro Train runs:\n{json.dumps(result, indent=2)}"

    return (
        "Operability inspection operations:\n"
        "  - 'List Tenzro Train runs'\n"
        "  - 'Get training run task-…' (metadata: task_id)\n"
        "  - 'Get training receipt task-…' (metadata: task_id)\n"
        "  - 'Get sealed manifest task-…' (metadata: task_id)\n"
        "  - 'Show trainer daemon status'\n"
        "  - 'Show SLA fault-detector parameters'\n"
        "  - 'List outstanding SLA probes'\n"
        "  - 'Issue SLA probe' (metadata: provider_did, epoch, round, deadline_ms?)\n"
        "  - 'List snapshots'\n"
        "  - 'Get snapshot manifest' (metadata: height)\n"
        "  - 'Get snapshot chunk' (metadata: height, chunk_index)\n"
        "Validator-registry reads ('List active validators', 'Get validator "
        "state 0x…') route to the validator-lifecycle skill."
    )


# ---------------------------------------------------------------------------
# Local Discovery & Cluster
# ---------------------------------------------------------------------------


async def handle_discovery(text: str, metadata: dict | None = None) -> str:
    """Local mDNS peers, reachability tier, hardware self-profile, and
    deterministic cluster placement. The cluster plan reads its model and
    members from `metadata`.
    """
    t = text.lower()
    md = metadata or {}

    if "preview" in t and md.get("model_id"):
        result = await rpc_call(
            "tenzro_clusterPreview",
            {
                "model_id": md["model_id"],
                "user_forced": md.get("user_forced", False),
                "force_single": md.get("force_single", False),
            },
        )
        return f"Cluster preview:\n{json.dumps(result, indent=2)}"

    if "cluster" in t and md.get("model") and md.get("members"):
        result = await rpc_call(
            "tenzro_clusterPlan",
            {
                "model": md["model"],
                "members": md["members"],
                "user_forced": md.get("user_forced", False),
            },
        )
        return f"Cluster plan:\n{json.dumps(result, indent=2)}"

    if "reachability" in t or "reachable" in t or "tier" in t:
        result = await rpc_call("tenzro_nodeReachability", [])
        return f"Node reachability:\n{json.dumps(result, indent=2)}"

    if "profile" in t or "hardware" in t:
        result = await rpc_call("tenzro_nodeProfile", [])
        return f"Node hardware profile:\n{json.dumps(result, indent=2)}"

    if "peer" in t or "discover" in t or "local" in t:
        result = await rpc_call("tenzro_localPeers", [])
        return f"Local peers:\n{json.dumps(result, indent=2)}"

    return (
        "Local-discovery & cluster operations:\n"
        "  - 'Local peers'\n"
        "  - 'Node reachability'\n"
        "  - 'Node hardware profile'\n"
        "  - 'Cluster preview <model_id>' (metadata: model_id, user_forced?, force_single? — live node view, derives shape from GGUF + discovers members)\n"
        "  - 'Cluster plan' (metadata: model {layers, hidden_dim, total_vram_gb}, members, user_forced?)"
    )


# ---------------------------------------------------------------------------
# Decentralized app hosting (static sites / functions / machines)
# ---------------------------------------------------------------------------


def _with_env(params: dict, md: dict) -> dict:
    """Attach a signed DID envelope to mutation params when present in
    metadata. The node verifies env.did == owner_did before mutating."""
    env = md.get("did_envelope")
    if env is not None:
        params = dict(params)
        params["did_envelope"] = env
    return params


async def handle_hosting(text: str, metadata: dict | None = None) -> str:
    """Publish and serve apps under *.apps.tenzro.xyz: static sites,
    wasi:http functions, and Firecracker machines. Route maps, capability
    manifests, resource requests, and sealed env vars carry structured
    fields, so they read from `metadata`. Mutations require a signed
    `did_envelope` (metadata) whose did equals `owner_did`.
    """
    t = text.lower()
    md = metadata or {}

    # ── Machines (check before "machine sealing key" collides with site) ──
    if "sealing key" in t or ("sealing" in t and "key" in t):
        result = await rpc_call("tenzro_machineSealingKey", {})
        return f"Machine sealing key:\n{json.dumps(result, indent=2)}"

    if "machine" in t:
        machine_id = md.get("id") or _extract_id(text, "machine-")
        if (
            "deploy" in t
            and md.get("name")
            and md.get("owner_did")
            and md.get("artifact_caid")
        ):
            params = {
                "name": md["name"],
                "owner_did": md["owner_did"],
                "artifact_caid": md["artifact_caid"],
                "internal_port": md.get("internal_port", 8080),
            }
            for k in (
                "resources",
                "sealed_env",
                "tee_required",
                "price_per_request",
                "replicas",
                "region_hint",
                "max_price_per_hour",
            ):
                if md.get(k) is not None:
                    params[k] = md[k]
            result = await rpc_call("tenzro_machineDeploy", _with_env(params, md))
            return f"Machine deployed:\n{json.dumps(result, indent=2)}"
        if "status" in t and machine_id:
            result = await rpc_call("tenzro_machineStatus", {"id": machine_id})
            return f"Machine status:\n{json.dumps(result, indent=2)}"
        if "remove" in t and machine_id and md.get("owner_did"):
            params = {"id": machine_id, "owner_did": md["owner_did"]}
            result = await rpc_call("tenzro_machineRemove", _with_env(params, md))
            return f"Machine removed:\n{json.dumps(result, indent=2)}"
        if machine_id and ("get" in t or "show" in t or "read" in t):
            result = await rpc_call("tenzro_machineGet", {"id": machine_id})
            return f"Machine:\n{json.dumps(result, indent=2)}"
        if "list" in t:
            params = {"owner_did": md["owner_did"]} if md.get("owner_did") else {}
            result = await rpc_call("tenzro_listMachines", params)
            return f"Machines:\n{json.dumps(result, indent=2)}"

    # ── Functions (wasi:http components) ──
    if "function" in t:
        fn_id = md.get("id") or _extract_id(text, "function-")
        if (
            "deploy" in t
            and md.get("name")
            and md.get("owner_did")
            and md.get("wasm_blob_hash")
        ):
            params = {
                "name": md["name"],
                "owner_did": md["owner_did"],
                "wasm_blob_hash": md["wasm_blob_hash"],
            }
            for k in (
                "capabilities",
                "fuel_limit",
                "deadline_ms",
                "price_per_request",
                "replicas",
                "region_hint",
                "max_price_per_hour",
            ):
                if md.get(k) is not None:
                    params[k] = md[k]
            result = await rpc_call("tenzro_functionDeploy", _with_env(params, md))
            return f"Function deployed:\n{json.dumps(result, indent=2)}"
        if "remove" in t and fn_id and md.get("owner_did"):
            params = {"id": fn_id, "owner_did": md["owner_did"]}
            result = await rpc_call("tenzro_functionRemove", _with_env(params, md))
            return f"Function removed:\n{json.dumps(result, indent=2)}"
        if fn_id and ("get" in t or "show" in t or "read" in t):
            result = await rpc_call("tenzro_functionGet", {"id": fn_id})
            return f"Function:\n{json.dumps(result, indent=2)}"
        if "list" in t:
            params = {"owner_did": md["owner_did"]} if md.get("owner_did") else {}
            result = await rpc_call("tenzro_listFunctions", params)
            return f"Functions:\n{json.dumps(result, indent=2)}"

    # ── Placement leases ──
    if "lease" in t:
        if md.get("app_id"):
            result = await rpc_call("tenzro_getLeasesForApp", {"app_id": md["app_id"]})
            return f"Leases for app:\n{json.dumps(result, indent=2)}"
        result = await rpc_call("tenzro_listLeases", {})
        return f"Active leases:\n{json.dumps(result, indent=2)}"

    # ── Custom domains ──
    if "domain" in t:
        hostname = md.get("hostname")
        if "claim" in t and hostname and md.get("site_id") and md.get("owner_did"):
            params = {
                "hostname": hostname,
                "site_id": md["site_id"],
                "owner_did": md["owner_did"],
            }
            result = await rpc_call("tenzro_siteClaimDomain", _with_env(params, md))
            return f"Domain claimed (publish the DNS TXT proof, then verify):\n{json.dumps(result, indent=2)}"
        if "verify" in t and hostname and md.get("owner_did"):
            params = {"hostname": hostname, "owner_did": md["owner_did"]}
            result = await rpc_call("tenzro_siteVerifyDomain", _with_env(params, md))
            return f"Domain verified:\n{json.dumps(result, indent=2)}"
        if "remove" in t and hostname and md.get("owner_did"):
            params = {"hostname": hostname, "owner_did": md["owner_did"]}
            result = await rpc_call("tenzro_siteRemoveDomain", _with_env(params, md))
            return f"Domain removed:\n{json.dumps(result, indent=2)}"
        if "list" in t:
            result = await rpc_call("tenzro_listSiteDomains", {})
            return f"Custom domains:\n{json.dumps(result, indent=2)}"
        if hostname:
            result = await rpc_call("tenzro_siteGetDomain", {"hostname": hostname})
            return f"Domain:\n{json.dumps(result, indent=2)}"

    # ── Hostname aliases ──
    if "alias" in t or "hostname" in t:
        hostname = md.get("hostname")
        if (
            ("set" in t or "map" in t)
            and hostname
            and md.get("site_id")
            and md.get("owner_did")
        ):
            params = {
                "hostname": hostname,
                "site_id": md["site_id"],
                "owner_did": md["owner_did"],
            }
            result = await rpc_call("tenzro_siteSetAlias", _with_env(params, md))
            return f"Alias set:\n{json.dumps(result, indent=2)}"
        if "remove" in t and hostname and md.get("owner_did"):
            params = {"hostname": hostname, "owner_did": md["owner_did"]}
            result = await rpc_call("tenzro_siteRemoveAlias", _with_env(params, md))
            return f"Alias removed:\n{json.dumps(result, indent=2)}"
        if "list" in t:
            result = await rpc_call("tenzro_listSiteAliases", {})
            return f"Aliases:\n{json.dumps(result, indent=2)}"
        if hostname:
            result = await rpc_call("tenzro_siteGetAlias", {"hostname": hostname})
            return f"Alias:\n{json.dumps(result, indent=2)}"

    # ── Placement ──
    if "placement" in t or ("pin" in t and "site" in t):
        site_id = md.get("site_id") or _extract_id(text, "site-")
        if (
            ("set" in t or "pin" in t)
            and site_id
            and md.get("serving_nodes") is not None
        ):
            params = {"site_id": site_id, "serving_nodes": md["serving_nodes"]}
            result = await rpc_call("tenzro_siteSetPlacement", _with_env(params, md))
            return f"Placement set:\n{json.dumps(result, indent=2)}"
        if "remove" in t and site_id:
            params = {"site_id": site_id}
            result = await rpc_call("tenzro_siteRemovePlacement", _with_env(params, md))
            return f"Placement cleared (reverts to local serving):\n{json.dumps(result, indent=2)}"
        if "list" in t:
            result = await rpc_call("tenzro_listSitePlacements", {})
            return f"Placements:\n{json.dumps(result, indent=2)}"
        if site_id:
            result = await rpc_call("tenzro_siteGetPlacement", {"site_id": site_id})
            return f"Placement:\n{json.dumps(result, indent=2)}"

    # ── Static sites ──
    site_id = md.get("site_id") or _extract_id(text, "site-")
    if (
        ("publish" in t or "deploy" in t)
        and md.get("name")
        and md.get("owner_did")
        and md.get("routes")
    ):
        params = {
            "name": md["name"],
            "owner_did": md["owner_did"],
            "routes": md["routes"],
        }
        for k in (
            "index_path",
            "not_found_path",
            "spa",
            "price_per_request",
            "replicas",
            "region_hint",
            "max_price_per_hour",
        ):
            if md.get(k) is not None:
                params[k] = md[k]
        result = await rpc_call("tenzro_sitePublish", _with_env(params, md))
        return f"Site published:\n{json.dumps(result, indent=2)}"
    if "remove" in t and site_id and md.get("owner_did"):
        params = {"site_id": site_id, "owner_did": md["owner_did"]}
        result = await rpc_call("tenzro_siteRemove", _with_env(params, md))
        return f"Site removed:\n{json.dumps(result, indent=2)}"
    if site_id and ("get" in t or "show" in t or "read" in t):
        result = await rpc_call("tenzro_siteGet", {"site_id": site_id})
        return f"Site:\n{json.dumps(result, indent=2)}"
    if "list" in t and "site" in t:
        params = {"owner_did": md["owner_did"]} if md.get("owner_did") else {}
        result = await rpc_call("tenzro_listSites", params)
        return f"Sites:\n{json.dumps(result, indent=2)}"

    return (
        "Decentralized app hosting (*.apps.tenzro.xyz):\n"
        "Static sites:\n"
        "  - 'Publish site' (metadata: name, owner_did, routes[{path, blob_hash, content_type, size}], index_path?, not_found_path?, spa?, price_per_request?, did_envelope)\n"
        "  - 'Get site site-…' / 'List sites' (metadata: owner_did?) / 'Remove site site-…' (metadata: owner_did, did_envelope)\n"
        "  - 'Set alias' (metadata: hostname, site_id, owner_did, did_envelope) / 'Get alias', 'List aliases', 'Remove alias'\n"
        "  - 'Set placement' (metadata: site_id, serving_nodes[], did_envelope) / 'Get placement', 'List placements', 'Remove placement'\n"
        "  - 'Claim domain' (metadata: hostname, site_id, owner_did, did_envelope) → publish DNS TXT → 'Verify domain' (metadata: hostname, owner_did, did_envelope)\n"
        "Functions (wasi:http):\n"
        "  - 'Deploy function' (metadata: name, owner_did, wasm_blob_hash, capabilities?, fuel_limit?, deadline_ms?, did_envelope)\n"
        "  - 'Get function function-…' / 'List functions' / 'Remove function function-…'\n"
        "Machines (Firecracker microVM):\n"
        "  - 'Fetch machine sealing key' → wrap env ciphertext to it (x25519-hkdf-sha256-envelope-aes-256-gcm)\n"
        "  - 'Deploy machine' (metadata: name, owner_did, artifact_caid, internal_port, resources?, sealed_env?, tee_required?, did_envelope)\n"
        "  - 'Get/Status/Remove machine machine-…' / 'List machines'\n"
        "Leases:\n"
        "  - 'List leases' / 'Leases for app' (metadata: app_id)"
    )


# ---------------------------------------------------------------------------
# Managed databases
# ---------------------------------------------------------------------------


async def handle_database(text: str, metadata: dict | None = None) -> str:
    """Managed-database catalog, partition placement, access control, and
    engine-dialect query. Database descriptors, engine config, and query
    bodies carry structured fields, so they read from `metadata`.
    """
    t = text.lower()
    md = metadata or {}
    database_id = md.get("database_id")

    if "engine" in t and ("list" in t or "catalog" in t):
        result = await rpc_call("tenzro_listDatabaseEngines", [])
        return f"Database engine catalog:\n{json.dumps(result, indent=2)}"

    if "create" in t and md.get("engine_id"):
        params = {
            "database_id": md.get("database_id"),
            "engine_id": md["engine_id"],
            "placement": md.get("placement", "local"),
            "partitions": md.get("partitions", 1),
        }
        if (
            md.get("min_replication") is not None
            or md.get("max_replication") is not None
        ):
            params["replication"] = {
                "min_replication": md.get("min_replication", 2),
                "max_replication": md.get("max_replication", 4),
            }
        if md.get("owner_did"):
            params["owner_did"] = md["owner_did"]
        if md.get("access_policy"):
            params["access_policy"] = md["access_policy"]
        if md.get("engine_config"):
            params["engine_config"] = md["engine_config"]
        if md.get("confidential"):
            params["confidential"] = md["confidential"]
        result = await rpc_call("tenzro_createDatabase", params)
        return f"Database created:\n{json.dumps(result, indent=2)}"

    if "connection" in t and database_id and md.get("caller_did"):
        params = {
            "database_id": database_id,
            "caller_did": md["caller_did"],
            "write": md.get("write", False),
        }
        if md.get("bearer_did"):
            params["bearer_did"] = md["bearer_did"]
        if md.get("ttl_secs"):
            params["ttl_secs"] = md["ttl_secs"]
        if md.get("capability"):
            params["capability"] = md["capability"]
        result = await rpc_call("tenzro_issueDatabaseConnection", params)
        return f"Database connection issued:\n{json.dumps(result, indent=2)}"

    if (
        "query" in t
        and database_id
        and md.get("caller_did")
        and md.get("body") is not None
    ):
        params = {
            "database_id": database_id,
            "caller_did": md["caller_did"],
            "body": md["body"],
            "partition_index": md.get("partition_index", 0),
            "write": md.get("write", False),
        }
        if md.get("capability"):
            params["capability"] = md["capability"]
        if md.get("consistency"):
            params["consistency"] = md["consistency"]
        result = await rpc_call("tenzro_databaseQuery", params)
        return f"Database query:\n{json.dumps(result, indent=2)}"

    if ("authorize" in t or "access" in t) and database_id and md.get("caller_did"):
        params = {"database_id": database_id, "caller_did": md["caller_did"]}
        if md.get("capability"):
            params["capability"] = md["capability"]
        result = await rpc_call("tenzro_authorizeDatabaseRead", params)
        return f"Database access decision:\n{json.dumps(result, indent=2)}"

    if "rescale" in t and database_id and md.get("caller_did") and md.get("placement"):
        params = {
            "database_id": database_id,
            "caller_did": md["caller_did"],
            "placement": md["placement"],
        }
        if md.get("partitions") is not None:
            params["partitions"] = md["partitions"]
        if (
            md.get("min_replication") is not None
            and md.get("max_replication") is not None
        ):
            params["replication"] = {
                "min_replication": md["min_replication"],
                "max_replication": md["max_replication"],
            }
        if md.get("capability"):
            params["capability"] = md["capability"]
        result = await rpc_call("tenzro_rescaleDatabase", params)
        return f"Database rescaled:\n{json.dumps(result, indent=2)}"

    if "drop" in t and database_id:
        result = await rpc_call("tenzro_dropDatabase", {"database_id": database_id})
        return f"Database dropped:\n{json.dumps(result, indent=2)}"

    if "partition" in t and database_id and md.get("partition_index") is not None:
        result = await rpc_call(
            "tenzro_getDatabasePartition",
            {
                "database_id": database_id,
                "partition_index": md["partition_index"],
            },
        )
        return f"Database partition:\n{json.dumps(result, indent=2)}"

    if "partition" in t and database_id:
        result = await rpc_call(
            "tenzro_listDatabasePartitions", {"database_id": database_id}
        )
        return f"Database partitions:\n{json.dumps(result, indent=2)}"

    if database_id:
        result = await rpc_call("tenzro_getDatabase", {"database_id": database_id})
        return f"Database:\n{json.dumps(result, indent=2)}"

    if "list" in t:
        result = await rpc_call("tenzro_listDatabases", [])
        return f"Databases:\n{json.dumps(result, indent=2)}"

    return (
        "Managed-database operations:\n"
        "  - 'List database engines'\n"
        "  - 'List databases'\n"
        "  - 'Create database' (metadata: database_id, engine_id, owner_did|access_policy, "
        "placement?, partitions?, min_replication?, max_replication?, engine_config?, confidential?)\n"
        "  - 'Get database' (metadata: database_id)\n"
        "  - 'List database partitions' (metadata: database_id)\n"
        "  - 'Get database partition' (metadata: database_id, partition_index)\n"
        "  - 'Issue database connection' (metadata: database_id, caller_did, bearer_did?, "
        "write?, ttl_secs?, capability?)\n"
        "  - 'Database query' (metadata: database_id, caller_did, body, partition_index?, "
        "write?, consistency?, capability?)\n"
        "  - 'Authorize database read' (metadata: database_id, caller_did, capability?)\n"
        "  - 'Rescale database' (metadata: database_id, caller_did, placement, "
        "partitions?, min_replication?, max_replication?, capability?)\n"
        "  - 'Drop database' (metadata: database_id)"
    )


async def handle_oracle(text: str, metadata: dict | None = None) -> str:
    """Read asset prices from the node's price oracle (tenzro_getPrice).

    `price_usd_8dp` is the USD price as an integer scaled by 1e8. Symbols with
    no live feed come back under `unavailable`. Requires bridge.prices.enabled
    on the node.
    """
    md = metadata or {}
    params: dict = {}
    symbol = md.get("symbol")
    symbols = md.get("symbols")
    if symbol:
        params["symbol"] = symbol
    if symbols:
        params["symbols"] = symbols
    if not params:
        return (
            "Read asset prices from the node's price oracle:\n"
            "  metadata.symbol   (single symbol, e.g. 'TNZO')\n"
            "  metadata.symbols  (list, e.g. ['TNZO','ETH','USDC'])\n"
            "  RPC: tenzro_getPrice — price_usd_8dp is USD × 1e8."
        )
    result = await rpc_call("tenzro_getPrice", [params])
    return f"Asset prices:\n{json.dumps(result, indent=2)}"


async def handle_cortex(text: str, metadata: dict | None = None) -> str:
    """Run Cortex reasoning loops and inspect the Cortex worker pool.

    `tenzro_cortexReason` runs an iterative reasoning loop against a served
    model under a tier-derived budget. Workers are the sidecars that execute
    the loops; local and remote pools are listed separately.
    """
    t = text.lower()
    md = metadata or {}

    if "worker" in t and ("register" in t or "add" in t):
        if not md.get("model_id"):
            return (
                "Registering a Cortex worker requires metadata.model_id. "
                "Optional: sidecar_url, bearer_token, arch, max_loops, "
                "moe_experts, experts_per_token, attn_type, pricing, "
                "worker_did, timeout_secs."
            )
        params = {"model_id": md["model_id"]}
        for key in (
            "sidecar_url",
            "bearer_token",
            "arch",
            "max_loops",
            "moe_experts",
            "experts_per_token",
            "attn_type",
            "pricing",
            "worker_did",
            "timeout_secs",
        ):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_registerCortexWorker", params)
        return f"Cortex worker registered:\n{json.dumps(result, indent=2)}"

    if "worker" in t and "remote" in t:
        result = await rpc_call("tenzro_listRemoteCortexWorkers", [])
        return f"Remote Cortex workers:\n{json.dumps(result, indent=2)}"

    if "worker" in t:
        result = await rpc_call("tenzro_listCortexWorkers", [])
        return f"Cortex workers:\n{json.dumps(result, indent=2)}"

    model_id = md.get("model_id")
    reason_input = md.get("input") or (text if model_id else None)
    if model_id and reason_input:
        params = {
            "model_id": model_id,
            "input": reason_input,
            "tier": md.get("tier", "standard"),
        }
        for key in (
            "min_loops",
            "max_loops",
            "max_cost_wei",
            "deadline_ms",
            "attestation",
            "requester",
            "request_id",
        ):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_cortexReason", params)
        return f"Cortex reasoning:\n{json.dumps(result, indent=2)}"

    return (
        "Cortex reasoning operations:\n"
        "  - 'List cortex workers'\n"
        "  - 'List remote cortex workers'\n"
        "  - 'Register cortex worker' (metadata: model_id, sidecar_url?, "
        "bearer_token?, arch?, max_loops?, moe_experts?, experts_per_token?, "
        "attn_type?, pricing?, worker_did?, timeout_secs?)\n"
        "  - 'Reason' (metadata: model_id, input, tier ∈ fast|standard|deep|"
        "institutional, min_loops?, max_loops?, max_cost_wei?, deadline_ms?, "
        "attestation?, requester?, request_id?)"
    )


async def handle_settlement(text: str, metadata: dict | None = None) -> str:
    """Settle service payments, read receipts, and drive payment channels.

    Covers immediate settlement (`tenzro_settle`), receipt reads, escrow
    reads, micropayment channels, and the prepaid ledger that streaming
    storage / compute rentals bill against.
    """
    t = text.lower()
    md = metadata or {}

    if "channel" in t:
        channel_id = md.get("channel_id")
        if "open" in t:
            required = ("sender", "counterparty", "deposit")
            if not all(md.get(k) for k in required):
                return (
                    "Opening a payment channel requires metadata: sender "
                    "(hex address), counterparty (hex address), deposit "
                    "(decimal string)."
                )
            result = await rpc_call(
                "tenzro_openPaymentChannel",
                {
                    "sender": md["sender"],
                    "counterparty": md["counterparty"],
                    "deposit": str(md["deposit"]),
                },
            )
            return f"Payment channel opened:\n{json.dumps(result, indent=2)}"
        if "update" in t or "pay" in t:
            if (
                not channel_id
                or md.get("payment_amount") is None
                or not md.get("signature")
            ):
                return (
                    "Updating a payment channel requires metadata: "
                    "channel_id, payment_amount (decimal string), signature "
                    "(hex Ed25519 over nonce || payer_balance || "
                    "payee_balance of the next state, little-endian)."
                )
            result = await rpc_call(
                "tenzro_updatePaymentChannel",
                {
                    "channel_id": channel_id,
                    "payment_amount": str(md["payment_amount"]),
                    "signature": md["signature"],
                },
            )
            return f"Payment channel updated:\n{json.dumps(result, indent=2)}"
        if "close" in t and channel_id:
            result = await rpc_call(
                "tenzro_closePaymentChannel",
                {
                    "channel_id": channel_id,
                },
            )
            return f"Payment channel closed:\n{json.dumps(result, indent=2)}"
        return (
            "Payment channel operations:\n"
            "  - 'Open payment channel' (metadata: sender, counterparty, deposit)\n"
            "  - 'Update payment channel' (metadata: channel_id, payment_amount, signature)\n"
            "  - 'Close payment channel' (metadata: channel_id)"
        )

    if "prepaid" in t:
        renter = md.get("renter") or _extract_address(text)
        if not renter:
            return (
                "Prepaid ledger operations need metadata.renter (hex "
                "address). Deposit and withdraw also need metadata.amount "
                "(decimal string). Optional metadata.asset defaults to TNZO."
            )
        params = {"renter": renter}
        if md.get("asset"):
            params["asset"] = md["asset"]
        if "deposit" in t or "lock" in t:
            if md.get("amount") is None:
                return "Prepaid deposit requires metadata.amount (decimal string)."
            params["amount"] = str(md["amount"])
            result = await rpc_call("tenzro_prepaidDeposit", params)
            return f"Prepaid deposit:\n{json.dumps(result, indent=2)}"
        if "withdraw" in t:
            if md.get("amount") is None:
                return "Prepaid withdraw requires metadata.amount (decimal string)."
            params["amount"] = str(md["amount"])
            result = await rpc_call("tenzro_prepaidWithdraw", params)
            return f"Prepaid withdrawal:\n{json.dumps(result, indent=2)}"
        result = await rpc_call("tenzro_prepaidBalance", params)
        return f"Prepaid balance:\n{json.dumps(result, indent=2)}"

    if "escrow" in t:
        if md.get("escrow_id"):
            result = await rpc_call("tenzro_getEscrow", {"escrow_id": md["escrow_id"]})
            return f"Escrow:\n{json.dumps(result, indent=2)}"
        if md.get("payer"):
            result = await rpc_call("tenzro_listEscrowsByPayer", {"payer": md["payer"]})
            return f"Escrows by payer:\n{json.dumps(result, indent=2)}"
        if md.get("payee"):
            result = await rpc_call("tenzro_listEscrowsByPayee", {"payee": md["payee"]})
            return f"Escrows by payee:\n{json.dumps(result, indent=2)}"
        return (
            "Escrow reads: metadata.escrow_id, metadata.payer, or "
            "metadata.payee. Escrow writes go through signed "
            "CreateEscrow / ReleaseEscrow / RefundEscrow transactions, not "
            "this skill."
        )

    receipt_id = md.get("receipt_id") or _extract_id(text)
    if ("receipt" in t or "get" in t) and receipt_id:
        result = await rpc_call("tenzro_getSettlement", {"receipt_id": receipt_id})
        return f"Settlement receipt:\n{json.dumps(result, indent=2)}"

    if "unpaid" in t:
        result = await rpc_call("tenzro_listUnpaidSettlements", {})
        return f"Unpaid settlements:\n{json.dumps(result, indent=2)}"

    required = ("provider", "customer", "amount", "service_type")
    if all(md.get(k) is not None for k in required):
        params = {
            "provider": md["provider"],
            "customer": md["customer"],
            "amount": str(md["amount"]),
            "service_type": md["service_type"],
        }
        for key in (
            "model_id",
            "tokens",
            "computation_id",
            "compute_units",
            "agent_id",
            "task_id",
            "proof",
        ):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_settle", params)
        return f"Settlement:\n{json.dumps(result, indent=2)}"

    return (
        "Settlement operations:\n"
        "  - 'Settle' (metadata: provider, customer, amount, service_type, "
        "plus the service-specific fields: model_id + tokens, "
        "computation_id + compute_units, or agent_id + task_id; optional proof)\n"
        "  - 'Get settlement receipt' (metadata: receipt_id)\n"
        "  - 'List unpaid settlements'\n"
        "  - 'Get escrow' (metadata: escrow_id | payer | payee)\n"
        "  - 'Open/update/close payment channel'\n"
        "  - 'Prepaid balance/deposit/withdraw' (metadata: renter, amount?, asset?)"
    )


async def handle_dvp_netting(text: str, metadata: dict | None = None) -> str:
    """Run delivery-versus-payment sagas and multilateral netting batches.

    A DvP saga binds N legs so they settle atomically or not at all. Netting
    compresses a set of bilateral obligations into the minimum set of
    transfers. Saga open/execute/finalize and netting compute/settle are
    admin-gated on the node; the reads are open.
    """
    t = text.lower()
    md = metadata or {}

    if "netting" in t or "obligation" in t or "batch" in t:
        batch_id = md.get("batch_id")
        if "compute" in t and md.get("obligations"):
            result = await rpc_call(
                "tenzro_nettingCompute",
                {
                    "obligations": md["obligations"],
                },
            )
            return f"Netting batch computed:\n{json.dumps(result, indent=2)}"
        if "settle" in t and batch_id:
            result = await rpc_call("tenzro_nettingSettle", {"batch_id": batch_id})
            return f"Netting batch settled:\n{json.dumps(result, indent=2)}"
        if batch_id:
            result = await rpc_call("tenzro_nettingGetBatch", {"batch_id": batch_id})
            return f"Netting batch:\n{json.dumps(result, indent=2)}"
        if "list" in t:
            result = await rpc_call("tenzro_nettingListBatches", {})
            return f"Netting batches:\n{json.dumps(result, indent=2)}"
        return (
            "Netting operations:\n"
            "  - 'Compute netting batch' (metadata.obligations: list of "
            "{debtor, creditor, asset, amount} — amount is a decimal string; "
            "admin-gated)\n"
            "  - 'Settle netting batch' (metadata: batch_id; admin-gated)\n"
            "  - 'Get netting batch' (metadata: batch_id)\n"
            "  - 'List netting batches'"
        )

    saga_id = md.get("saga_id")
    if "open" in t and md.get("legs"):
        required = ("creator", "nonce", "expires_at_ms")
        if not all(md.get(k) is not None for k in required):
            return (
                "Opening a DvP saga requires metadata: creator (hex "
                "address), nonce (integer), legs, expires_at_ms (ms epoch)."
            )
        result = await rpc_call(
            "tenzro_dvpOpenSaga",
            {
                "creator": md["creator"],
                "nonce": md["nonce"],
                "legs": md["legs"],
                "expires_at_ms": md["expires_at_ms"],
            },
        )
        return f"DvP saga opened:\n{json.dumps(result, indent=2)}"

    if "execute" in t and saga_id:
        params = {"saga_id": saga_id}
        for key in ("proofs", "proof_type", "proof_data_hex"):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_dvpExecuteSaga", params)
        return f"DvP saga executed:\n{json.dumps(result, indent=2)}"

    if "finalize" in t and saga_id:
        result = await rpc_call("tenzro_dvpFinalizeSaga", {"saga_id": saga_id})
        return f"DvP saga finalized:\n{json.dumps(result, indent=2)}"

    if saga_id:
        result = await rpc_call("tenzro_dvpGetSaga", {"saga_id": saga_id})
        return f"DvP saga:\n{json.dumps(result, indent=2)}"

    creator = md.get("creator") or _extract_address(text)
    if "list" in t and creator:
        result = await rpc_call("tenzro_dvpListSagasByCreator", {"creator": creator})
        return f"DvP sagas by creator:\n{json.dumps(result, indent=2)}"

    return (
        "Delivery-versus-payment and netting operations:\n"
        "  - 'Open DvP saga' (metadata: creator, nonce, expires_at_ms, legs — "
        "each leg is {leg_id, payer, payee, asset, amount, venue} where venue "
        "is 'native' or {escrow:{escrow_id}} | {channel:{channel_id}} | "
        "{external:{reference}}; admin-gated)\n"
        "  - 'Execute DvP saga' (metadata: saga_id, proofs? | proof_type + "
        "proof_data_hex; admin-gated)\n"
        "  - 'Finalize DvP saga' (metadata: saga_id; admin-gated)\n"
        "  - 'Get DvP saga' (metadata: saga_id)\n"
        "  - 'List DvP sagas' (metadata: creator)\n"
        "  - 'Compute/settle/get/list netting batch'"
    )


async def handle_bond_insurance(text: str, metadata: dict | None = None) -> str:
    """Read agent bonds and file or inspect insurance claims.

    An agent bond is TNZO an agent's controller posts as recourse for
    counterparties. Claims draw against the shared insurance pool when a
    bonded agent causes loss. Posting, increasing, and withdrawing a bond
    move funds, so they go through signed transactions rather than this skill.
    """
    t = text.lower()
    md = metadata or {}

    if "claim" in t:
        claim_id = md.get("claim_id") or _extract_id(text)
        if claim_id:
            result = await rpc_call("tenzro_getInsuranceClaim", {"claim_id": claim_id})
            return f"Insurance claim:\n{json.dumps(result, indent=2)}"
        if "file" in t or "submit" in t:
            required = (
                "claimant_did",
                "claimant_address",
                "against_agent_did",
                "amount_requested",
                "narrative",
                "nonce",
            )
            missing = [k for k in required if md.get(k) is None]
            if missing:
                return (
                    "Filing an insurance claim requires metadata: "
                    f"{', '.join(required)} (missing: {', '.join(missing)}). "
                    "amount_requested is a decimal string; receipt_refs is an "
                    "optional list of settlement receipt ids backing the claim."
                )
            params = {
                "claimant_did": md["claimant_did"],
                "claimant_address": md["claimant_address"],
                "against_agent_did": md["against_agent_did"],
                "amount_requested": str(md["amount_requested"]),
                "narrative": md["narrative"],
                "nonce": md["nonce"],
            }
            if md.get("receipt_refs") is not None:
                params["receipt_refs"] = md["receipt_refs"]
            result = await rpc_call("tenzro_fileInsuranceClaim", params)
            return f"Insurance claim filed:\n{json.dumps(result, indent=2)}"
        result = await rpc_call("tenzro_listInsuranceClaims", [])
        return f"Insurance claims:\n{json.dumps(result, indent=2)}"

    if "pool" in t:
        result = await rpc_call("tenzro_getInsurancePoolBalance", [])
        return f"Insurance pool balance:\n{json.dumps(result, indent=2)}"

    controller_did = md.get("controller_did")
    if controller_did:
        result = await rpc_call(
            "tenzro_listAgentBondsByController",
            {
                "controller_did": controller_did,
            },
        )
        return f"Agent bonds by controller:\n{json.dumps(result, indent=2)}"

    agent_did = md.get("agent_did") or _extract_did(text)
    if agent_did:
        result = await rpc_call("tenzro_getAgentBond", {"agent_did": agent_did})
        return f"Agent bond:\n{json.dumps(result, indent=2)}"

    return (
        "Agent bond and insurance operations:\n"
        "  - 'Get agent bond' (metadata: agent_did)\n"
        "  - 'List agent bonds' (metadata: controller_did)\n"
        "  - 'File insurance claim' (metadata: claimant_did, "
        "claimant_address, against_agent_did, amount_requested, narrative, "
        "nonce, receipt_refs?)\n"
        "  - 'List insurance claims'\n"
        "  - 'Get insurance claim' (metadata: claim_id)\n"
        "  - 'Get insurance pool balance'\n"
        "Posting, increasing, or withdrawing a bond moves funds and is "
        "submitted as a signed transaction, not through this skill."
    )


async def handle_ccip(text: str, metadata: dict | None = None) -> str:
    """Quote, send, and track Chainlink CCIP messages from the node.

    Fees are quoted live from `Router.getFee()`; `tenzro_ccipSend` returns the
    `Router.ccipSend()` envelope (calldata plus msg.value) for the caller to
    sign. Track reads `OffRamp.getExecutionState()` on the destination.
    """
    t = text.lower()
    md = metadata or {}

    def _send_params() -> dict | None:
        required = ("source_chain", "dest_chain", "receiver")
        if not all(md.get(k) for k in required):
            return None
        params = {
            "source_chain": md["source_chain"],
            "dest_chain": md["dest_chain"],
            "receiver": md["receiver"],
        }
        for key in ("data_hex", "fee_token", "gas_limit", "token_amounts"):
            if md.get(key) is not None:
                params[key] = md[key]
        return params

    if "rate limit" in t or "ratelimit" in t:
        if not md.get("chain") or not md.get("pool_address"):
            return "CCIP rate limits need metadata: chain, pool_address, remote_chain?."
        params = {"chain": md["chain"], "pool_address": md["pool_address"]}
        if md.get("remote_chain"):
            params["remote_chain"] = md["remote_chain"]
        result = await rpc_call("tenzro_ccipRateLimits", params)
        return f"CCIP rate limits:\n{json.dumps(result, indent=2)}"

    if "pool" in t:
        if not md.get("chain") or not md.get("pool_address"):
            return "CCIP token pool inspection needs metadata: chain, pool_address."
        result = await rpc_call(
            "tenzro_ccipTokenPool",
            {
                "chain": md["chain"],
                "pool_address": md["pool_address"],
            },
        )
        return f"CCIP token pool:\n{json.dumps(result, indent=2)}"

    if "lane" in t:
        params = {}
        for key in ("source_chain_selector", "dest_chain_selector", "environment"):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_ccipLanes", params)
        return f"CCIP lanes:\n{json.dumps(result, indent=2)}"

    if "token" in t and ("support" in t or "list" in t):
        params = {"environment": md["environment"]} if md.get("environment") else {}
        result = await rpc_call("tenzro_ccipSupportedTokens", params)
        return f"CCIP supported tokens:\n{json.dumps(result, indent=2)}"

    if "chain" in t and ("support" in t or "list" in t):
        params = {"environment": md["environment"]} if md.get("environment") else {}
        result = await rpc_call("tenzro_ccipSupportedChains", params)
        return f"CCIP supported chains:\n{json.dumps(result, indent=2)}"

    if "track" in t or "status" in t or md.get("message_id"):
        if not md.get("message_id") or not md.get("dest_chain"):
            return (
                "Tracking a CCIP message needs metadata: message_id, "
                "dest_chain, offramp_address?."
            )
        params = {
            "message_id": md["message_id"],
            "dest_chain": md["dest_chain"],
        }
        if md.get("offramp_address"):
            params["offramp_address"] = md["offramp_address"]
        result = await rpc_call("tenzro_ccipTrack", params)
        return f"CCIP message status:\n{json.dumps(result, indent=2)}"

    if "bridge" in t or "transfer" in t:
        required = (
            "source_chain",
            "dest_chain",
            "sender",
            "recipient",
            "asset",
            "amount",
        )
        missing = [k for k in required if md.get(k) is None]
        if missing:
            return (
                "Bridging over CCIP needs metadata: "
                f"{', '.join(required)} (missing: {', '.join(missing)})."
            )
        result = await rpc_call(
            "tenzro_ccipBridge",
            {
                "source_chain": md["source_chain"],
                "dest_chain": md["dest_chain"],
                "sender": md["sender"],
                "recipient": md["recipient"],
                "asset": md["asset"],
                "amount": str(md["amount"]),
            },
        )
        return f"CCIP bridge:\n{json.dumps(result, indent=2)}"

    if "send" in t:
        params = _send_params()
        if params is None:
            return (
                "Sending a CCIP message needs metadata: source_chain, "
                "dest_chain, receiver, plus optional data_hex, fee_token, "
                "gas_limit, token_amounts."
            )
        result = await rpc_call("tenzro_ccipSend", params)
        return f"CCIP send envelope:\n{json.dumps(result, indent=2)}"

    params = _send_params()
    if params is not None:
        result = await rpc_call("tenzro_ccipGetFee", params)
        return f"CCIP fee quote:\n{json.dumps(result, indent=2)}"

    return (
        "Chainlink CCIP operations:\n"
        "  - 'Quote CCIP fee' (metadata: source_chain, dest_chain, receiver, "
        "data_hex?, fee_token?, gas_limit?, token_amounts? — each entry is "
        "{token, amount} with amount as a decimal string)\n"
        "  - 'Send CCIP message' (same metadata; returns unsigned calldata "
        "plus msg.value)\n"
        "  - 'Track CCIP message' (metadata: message_id, dest_chain, "
        "offramp_address?)\n"
        "  - 'List CCIP supported chains' / 'List CCIP supported tokens' "
        "(metadata: environment?)\n"
        "  - 'List CCIP lanes' (metadata: source_chain_selector?, "
        "dest_chain_selector?, environment?)\n"
        "  - 'Get CCIP token pool' (metadata: chain, pool_address)\n"
        "  - 'Get CCIP rate limits' (metadata: chain, pool_address, remote_chain?)\n"
        "  - 'Bridge over CCIP' (metadata: source_chain, dest_chain, sender, "
        "recipient, asset, amount)"
    )


def _modality_catalog_help(modality: str, run_hint: str) -> str:
    """Shared fallback text for the multi-modal skills."""
    return (
        f"{modality} operations:\n"
        f"  - 'List {modality.lower()} catalog' — models the node can serve\n"
        f"  - 'List {modality.lower()} models' — models currently loaded\n"
        f"  - {run_hint}\n"
        "Loading a model is an operator action: the artifact paths differ per "
        "model family, so it is driven from the node's own RPC or CLI rather "
        "than over A2A."
    )


async def handle_forecast(text: str, metadata: dict | None = None) -> str:
    """Run timeseries forecasts against a loaded forecast model.

    `history` is the observed series; `horizon` is how many steps ahead to
    predict. Supplying `quantiles` returns a quantile fan instead of a point
    forecast.
    """
    t = text.lower()
    md = metadata or {}

    if "catalog" in t:
        result = await rpc_call("tenzro_listForecastCatalog", [])
        return f"Forecast catalog:\n{json.dumps(result, indent=2)}"

    if md.get("model_id") and md.get("history") and md.get("horizon") is not None:
        params = {
            "model_id": md["model_id"],
            "history": md["history"],
            "horizon": md["horizon"],
        }
        if md.get("quantiles") is not None:
            params["quantiles"] = md["quantiles"]
        if md.get("frequency_seconds") is not None:
            params["frequency_seconds"] = md["frequency_seconds"]
        result = await rpc_call("tenzro_forecast", params)
        return f"Forecast:\n{json.dumps(result, indent=2)}"

    if "list" in t or "model" in t:
        result = await rpc_call("tenzro_listForecastModels", [])
        return f"Loaded forecast models:\n{json.dumps(result, indent=2)}"

    return _modality_catalog_help(
        "Forecast",
        "'Forecast' (metadata: model_id, history — array of numbers, horizon "
        "— integer, quantiles? — array of floats in (0,1), frequency_seconds?)",
    )


async def handle_vision_embed(text: str, metadata: dict | None = None) -> str:
    """Embed images and compare image embeddings against text embeddings.

    `image_base64` is the raw image (PNG / JPEG / WebP) base64-encoded.
    Similarity takes two already-computed embeddings and returns their
    cosine similarity.
    """
    t = text.lower()
    md = metadata or {}

    if "catalog" in t:
        result = await rpc_call("tenzro_listVisionCatalog", [])
        return f"Vision catalog:\n{json.dumps(result, indent=2)}"

    if md.get("image_embedding") and md.get("text_embedding"):
        result = await rpc_call(
            "tenzro_imageTextSimilarity",
            {
                "image_embedding": md["image_embedding"],
                "text_embedding": md["text_embedding"],
            },
        )
        return f"Image-text similarity:\n{json.dumps(result, indent=2)}"

    if md.get("model_id") and md.get("image_base64"):
        params = {
            "model_id": md["model_id"],
            "image_base64": md["image_base64"],
        }
        if md.get("normalize") is not None:
            params["normalize"] = md["normalize"]
        result = await rpc_call("tenzro_imageEmbed", params)
        return f"Image embedding:\n{json.dumps(result, indent=2)}"

    if "list" in t or "model" in t:
        result = await rpc_call("tenzro_listVisionModels", [])
        return f"Loaded vision models:\n{json.dumps(result, indent=2)}"

    return _modality_catalog_help(
        "Vision embedding",
        "'Embed image' (metadata: model_id, image_base64, normalize?) or "
        "'Image-text similarity' (metadata: image_embedding, text_embedding "
        "— both arrays of floats)",
    )


async def handle_text_embed(text: str, metadata: dict | None = None) -> str:
    """Embed text with a loaded text-embedding model.

    `inputs` is a non-empty list of strings. Matryoshka models accept
    `requested_dim` to truncate and re-normalize the output vector.
    """
    t = text.lower()
    md = metadata or {}

    if "catalog" in t:
        result = await rpc_call("tenzro_listTextEmbeddingCatalog", [])
        return f"Text-embedding catalog:\n{json.dumps(result, indent=2)}"

    inputs = md.get("inputs")
    if md.get("model_id") and inputs:
        params = {"model_id": md["model_id"], "inputs": inputs}
        if md.get("requested_dim") is not None:
            params["requested_dim"] = md["requested_dim"]
        if md.get("normalize") is not None:
            params["normalize"] = md["normalize"]
        result = await rpc_call("tenzro_textEmbed", params)
        return f"Text embeddings:\n{json.dumps(result, indent=2)}"

    if "list" in t or "model" in t:
        result = await rpc_call("tenzro_listTextEmbeddingModels", [])
        return f"Loaded text-embedding models:\n{json.dumps(result, indent=2)}"

    return _modality_catalog_help(
        "Text embedding",
        "'Embed text' (metadata: model_id, inputs — non-empty array of "
        "strings, requested_dim? — Matryoshka truncation, normalize?)",
    )


async def handle_segmentation(text: str, metadata: dict | None = None) -> str:
    """Segment an image from point and box prompts (SAM 2, EdgeSAM, MobileSAM).

    Prompts anchor the mask: a point marks a pixel as foreground or
    background, a box bounds the target. Text-promptable segmentation is a
    separate skill.
    """
    t = text.lower()
    md = metadata or {}

    if "catalog" in t:
        result = await rpc_call("tenzro_listSegmentationCatalog", [])
        return f"Segmentation catalog:\n{json.dumps(result, indent=2)}"

    if md.get("model_id") and md.get("image_base64") and md.get("prompts"):
        result = await rpc_call(
            "tenzro_segment",
            {
                "model_id": md["model_id"],
                "image_base64": md["image_base64"],
                "prompts": md["prompts"],
            },
        )
        return f"Segmentation:\n{json.dumps(result, indent=2)}"

    if "list" in t or "model" in t:
        result = await rpc_call("tenzro_listSegmentationModels", [])
        return f"Loaded segmentation models:\n{json.dumps(result, indent=2)}"

    return _modality_catalog_help(
        "Segmentation",
        "'Segment image' (metadata: model_id, image_base64, prompts — each "
        'prompt is {"type":"point","x":..,"y":..,"is_foreground":true} or '
        '{"type":"box","x0":..,"y0":..,"x1":..,"y1":..}; pass several point '
        "prompts to anchor a mask with both foreground and background hints)",
    )


async def handle_text_segmentation(text: str, metadata: dict | None = None) -> str:
    """Segment an image from a natural-language prompt (SAM 3 / SAM 3.1).

    Open-vocabulary: `text_prompt` names what to segment. An optional
    `box_prompt` narrows the search region and `score_threshold` filters
    low-confidence masks.
    """
    t = text.lower()
    md = metadata or {}

    if "catalog" in t:
        result = await rpc_call("tenzro_listTextSegmentationCatalog", [])
        return f"Text-segmentation catalog:\n{json.dumps(result, indent=2)}"

    if md.get("model_id") and md.get("image_base64") and md.get("text_prompt"):
        params = {
            "model_id": md["model_id"],
            "image_base64": md["image_base64"],
            "text_prompt": md["text_prompt"],
        }
        if md.get("box_prompt") is not None:
            params["box_prompt"] = md["box_prompt"]
        if md.get("score_threshold") is not None:
            params["score_threshold"] = md["score_threshold"]
        result = await rpc_call("tenzro_textSegment", params)
        return f"Text segmentation:\n{json.dumps(result, indent=2)}"

    if "list" in t or "model" in t:
        result = await rpc_call("tenzro_listTextSegmentationModels", [])
        return f"Loaded text-segmentation models:\n{json.dumps(result, indent=2)}"

    return _modality_catalog_help(
        "Text segmentation",
        "'Segment by text' (metadata: model_id, image_base64, text_prompt, "
        "box_prompt? — {x0,y0,x1,y1}, score_threshold?)",
    )


async def handle_detection(text: str, metadata: dict | None = None) -> str:
    """Detect objects in an image (RF-DETR, D-FINE).

    Both families are NMS-free. `score_threshold` filters weak detections;
    each result carries a bounding box, a label id, and a score.
    """
    t = text.lower()
    md = metadata or {}

    if "catalog" in t:
        result = await rpc_call("tenzro_listDetectionCatalog", [])
        return f"Detection catalog:\n{json.dumps(result, indent=2)}"

    if md.get("model_id") and md.get("image_base64"):
        params = {
            "model_id": md["model_id"],
            "image_base64": md["image_base64"],
        }
        if md.get("score_threshold") is not None:
            params["score_threshold"] = md["score_threshold"]
        result = await rpc_call("tenzro_detect", params)
        return f"Detections:\n{json.dumps(result, indent=2)}"

    if "list" in t or "model" in t:
        result = await rpc_call("tenzro_listDetectionModels", [])
        return f"Loaded detection models:\n{json.dumps(result, indent=2)}"

    return _modality_catalog_help(
        "Detection",
        "'Detect objects' (metadata: model_id, image_base64, "
        "score_threshold?). RF-DETR uses 90-class COCO indexing, D-FINE 80.",
    )


async def handle_audio_transcribe(text: str, metadata: dict | None = None) -> str:
    """Transcribe speech to text (Moonshine, Distil-Whisper, Parakeet, Canary).

    `audio_base64` is the raw audio file base64-encoded. `language` pins the
    source language for multilingual models; `timestamps` requests
    per-segment timing.
    """
    t = text.lower()
    md = metadata or {}

    if "catalog" in t:
        result = await rpc_call("tenzro_listAudioCatalog", [])
        return f"Audio catalog:\n{json.dumps(result, indent=2)}"

    if md.get("model_id") and md.get("audio_base64"):
        params = {
            "model_id": md["model_id"],
            "audio_base64": md["audio_base64"],
        }
        for key in ("language", "timestamps", "temperature"):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_transcribe", params)
        return f"Transcription:\n{json.dumps(result, indent=2)}"

    if "list" in t or "model" in t:
        result = await rpc_call("tenzro_listAudioModels", [])
        return f"Loaded audio models:\n{json.dumps(result, indent=2)}"

    return _modality_catalog_help(
        "Audio transcription",
        "'Transcribe' (metadata: model_id, audio_base64, language?, "
        "timestamps?, temperature?)",
    )


async def handle_video_embed(text: str, metadata: dict | None = None) -> str:
    """Embed a video by mean-pooling frame embeddings.

    Frames are extracted evenly across the clip — or at fixed `frame_stride`
    intervals when given — pushed through the image encoder the clip encoder
    was registered over, then mean-pooled into a single vector.
    """
    t = text.lower()
    md = metadata or {}

    if "catalog" in t:
        result = await rpc_call("tenzro_listVideoCatalog", [])
        return f"Video catalog:\n{json.dumps(result, indent=2)}"

    if md.get("model_id") and md.get("video_base64"):
        params = {
            "model_id": md["model_id"],
            "video_base64": md["video_base64"],
        }
        for key in ("frame_stride", "normalize"):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_videoEmbed", params)
        return f"Video embedding:\n{json.dumps(result, indent=2)}"

    if "list" in t or "model" in t:
        result = await rpc_call("tenzro_listVideoModels", [])
        return f"Loaded video models:\n{json.dumps(result, indent=2)}"

    return _modality_catalog_help(
        "Video embedding",
        "'Embed video' (metadata: model_id, video_base64, frame_stride?, normalize?)",
    )


async def handle_agent_memory(text: str, metadata: dict | None = None) -> str:
    """Grant, recall, archive and list persistent agent memory records.

    Recall runs over a Lance vector index and a Tantivy BM25 index; `mode` is
    `vector`, `text` or `hybrid` (hybrid merges both with reciprocal rank
    fusion). Archiving moves a record off-tier into the data-availability
    layer and leaves an `Archived` stub carrying the pointer.
    """
    t = text.lower()
    md = metadata or {}
    agent_did = md.get("agent_did")

    if "grant" in t or "remember" in t or "store" in t:
        if not agent_did or not md.get("text"):
            return (
                "Granting a memory needs metadata: agent_did, text "
                "(optional: kind, source, metadata)."
            )
        params = {"agent_did": agent_did, "text": md["text"]}
        for key in ("kind", "source", "metadata"):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_memoryGrant", params)
        return f"Memory granted:\n{json.dumps(result, indent=2)}"

    if "recall" in t or "search" in t or "query" in t:
        query = md.get("query") or text
        if not agent_did:
            return "Recall needs metadata: agent_did, query (optional: mode, k)."
        params = {
            "agent_did": agent_did,
            "query": query,
            "mode": md.get("mode", "hybrid"),
            "k": md.get("k", 10),
        }
        result = await rpc_call("tenzro_memoryRecall", params)
        return f"Recalled memories:\n{json.dumps(result, indent=2)}"

    if "archive" in t:
        if not agent_did or not md.get("record_id"):
            return "Archiving needs metadata: agent_did, record_id."
        result = await rpc_call(
            "tenzro_memoryArchive",
            {"agent_did": agent_did, "record_id": md["record_id"]},
        )
        return f"Memory archived:\n{json.dumps(result, indent=2)}"

    if agent_did:
        params = {"agent_did": agent_did}
        if md.get("limit") is not None:
            params["limit"] = md["limit"]
        result = await rpc_call("tenzro_listMemoryRecords", params)
        return f"Memory records:\n{json.dumps(result, indent=2)}"

    return (
        "Agent memory. Say:\n"
        "- 'Grant memory' (metadata: agent_did, text, kind?, source?, metadata?)\n"
        "- 'Recall' (metadata: agent_did, query, mode ∈ vector|text|hybrid, k?)\n"
        "- 'Archive memory' (metadata: agent_did, record_id)\n"
        "- 'List memories' (metadata: agent_did, limit?)"
    )


async def handle_adaptive_burn(text: str, metadata: dict | None = None) -> str:
    """Read the adaptive burn dial: config, supply metrics, recommendation.

    The dial compares the rolling supply delta against the governance-set
    targets and returns a bounded recommendation. Changing the rate is a
    governance action, not an RPC write — the recommendation feeds a proposal.
    """
    t = text.lower()

    if "metric" in t or "supply" in t:
        result = await rpc_call("tenzro_getSupplyMetrics", [])
        return f"Supply metrics:\n{json.dumps(result, indent=2)}"

    if "recommend" in t:
        result = await rpc_call("tenzro_getBurnRateRecommendation", [])
        return f"Burn rate recommendation:\n{json.dumps(result, indent=2)}"

    if "proposal" in t or "list" in t:
        result = await rpc_call("tenzro_listAdaptiveBurnProposals", [])
        return f"Adaptive burn proposals:\n{json.dumps(result, indent=2)}"

    result = await rpc_call("tenzro_getBurnRateConfig", [])
    return f"Burn rate config:\n{json.dumps(result, indent=2)}"


async def handle_seed_agent(text: str, metadata: dict | None = None) -> str:
    """Read the SeedAgent treasury earmark, charters, registry and activity.

    The earmark funds protocol-owned bootstrap agents on a decaying schedule.
    `tenzro_getNetworkActivity` separates organic traffic from seed traffic so
    the two can be compared during the earmark window.
    """
    t = text.lower()
    md = metadata or {}

    if "earmark" in t or "treasury" in t:
        params = {}
        if md.get("name"):
            params["name"] = md["name"]
        result = await rpc_call("tenzro_getTreasuryEarmark", params)
        return f"Treasury earmark:\n{json.dumps(result, indent=2)}"

    if "charter" in t:
        if md.get("charter_id"):
            result = await rpc_call(
                "tenzro_getSeedAgentCharter", {"charter_id": md["charter_id"]}
            )
            return f"Charter:\n{json.dumps(result, indent=2)}"
        result = await rpc_call("tenzro_listSeedAgentCharters", [])
        return f"Charters:\n{json.dumps(result, indent=2)}"

    if "activity" in t:
        params = {}
        for key in ("window", "exclude_seed"):
            if md.get(key) is not None:
                params[key] = md[key]
        result = await rpc_call("tenzro_getNetworkActivity", params)
        return f"Network activity:\n{json.dumps(result, indent=2)}"

    params = {}
    if md.get("charter_id"):
        params["charter_id"] = md["charter_id"]
    result = await rpc_call("tenzro_listSeedAgents", params)
    return f"Seed agents:\n{json.dumps(result, indent=2)}"


async def handle_erc7683(text: str, metadata: dict | None = None) -> str:
    """Read ERC-7683 cross-chain orders and record destination-side fills.

    Orders are opened by the swapper through a signed origin-settler
    transaction. This surface reads the resulting envelopes and records the
    fill once a filler has executed on the destination chain.
    """
    t = text.lower()
    md = metadata or {}

    if "fill" in t and ("record" in t or "submit" in t):
        required = (
            "order_id",
            "origin_chain_id",
            "origin_settler",
            "filler",
            "recipient",
            "fill_tx_hash",
            "filled_at_ms",
            "proof_route",
            "outputs",
        )
        missing = [k for k in required if md.get(k) is None]
        if missing:
            return (
                "Recording a fill needs metadata: "
                + ", ".join(required)
                + ". Missing: "
                + ", ".join(missing)
                + ". proof_route ∈ layerzero|wormhole|debridge|hyperlane; "
                'each output is {"token": 20-byte hex, "amount": 32-byte hex, '
                '"recipient": 32-byte hex, "chain_id": u32}.'
            )
        result = await rpc_call("tenzro_recordFill7683", {k: md[k] for k in required})
        return f"Fill recorded:\n{json.dumps(result, indent=2)}"

    if "fill" in t:
        if md.get("order_id"):
            result = await rpc_call("tenzro_getFill7683", {"order_id": md["order_id"]})
            return f"Fill:\n{json.dumps(result, indent=2)}"
        result = await rpc_call("tenzro_listFills7683", [])
        return f"Fills:\n{json.dumps(result, indent=2)}"

    if md.get("order_id"):
        result = await rpc_call("tenzro_get7683Order", {"order_id": md["order_id"]})
        return f"Order:\n{json.dumps(result, indent=2)}"

    params = {}
    for key in ("state", "dest_chain", "limit"):
        if md.get(key) is not None:
            params[key] = md[key]
    result = await rpc_call("tenzro_list7683Orders", params)
    return f"Orders:\n{json.dumps(result, indent=2)}"


async def handle_urwa(text: str, metadata: dict | None = None) -> str:
    """ERC-7943 regulated-asset controls: frozen amounts and kill switch.

    `token_id_hex` is 32 bytes, `account_hex` is 20 bytes, both with or
    without the `0x` prefix. Freezing and the kill switch are admin-gated —
    a call without the operator admin token is refused by the node.
    """
    t = text.lower()
    md = metadata or {}
    token_id = md.get("token_id_hex")

    if "kill" in t or "switch" in t:
        if not token_id:
            return "Kill-switch operations need metadata: token_id_hex (32 bytes)."
        if "trigger" in t or "activate" in t:
            params = {"token_id_hex": token_id}
            for key in ("triggered_by_did", "reason"):
                if md.get(key) is not None:
                    params[key] = md[key]
            result = await rpc_call("tenzro_urwaTriggerKillSwitch", params)
            return (
                f"Kill switch triggered (admin-gated):\n{json.dumps(result, indent=2)}"
            )
        if "clear" in t or "release" in t or "lift" in t:
            result = await rpc_call(
                "tenzro_urwaClearKillSwitch", {"token_id_hex": token_id}
            )
            return f"Kill switch cleared (admin-gated):\n{json.dumps(result, indent=2)}"
        result = await rpc_call("tenzro_urwaIsKillSwitched", {"token_id_hex": token_id})
        return f"Kill switch state:\n{json.dumps(result, indent=2)}"

    if "freeze" in t or "frozen" in t:
        if not token_id or not md.get("account_hex"):
            return (
                "Frozen-amount operations need metadata: token_id_hex "
                "(32 bytes), account_hex (20 bytes). Setting also needs amount."
            )
        if md.get("amount") is not None and ("set" in t or "freeze" in t):
            params = {
                "token_id_hex": token_id,
                "account_hex": md["account_hex"],
                "amount": str(md["amount"]),
            }
            if md.get("reason") is not None:
                params["reason"] = md["reason"]
            result = await rpc_call("tenzro_urwaSetFrozenTokens", params)
            return f"Frozen amount set (admin-gated):\n{json.dumps(result, indent=2)}"
        result = await rpc_call(
            "tenzro_urwaGetFrozenTokens",
            {"token_id_hex": token_id, "account_hex": md["account_hex"]},
        )
        return f"Frozen amount:\n{json.dumps(result, indent=2)}"

    return (
        "Regulated-asset controls (ERC-7943). Say:\n"
        "- 'Is kill switch active' (metadata: token_id_hex)\n"
        "- 'Trigger kill switch' (metadata: token_id_hex, triggered_by_did?, "
        "reason?) — admin-gated\n"
        "- 'Clear kill switch' (metadata: token_id_hex) — admin-gated\n"
        "- 'Get frozen tokens' (metadata: token_id_hex, account_hex)\n"
        "- 'Set frozen tokens' (metadata: token_id_hex, account_hex, amount, "
        "reason?) — admin-gated"
    )


async def handle_ivms101(text: str, metadata: dict | None = None) -> str:
    """Compute the canonical hash of an IVMS101 travel-rule envelope.

    Pass the envelope as `metadata.envelope`, or put the envelope fields at
    the top level of `metadata`. Originator and beneficiary VASPs bind the
    returned hash to their settlement receipt so a verifier can re-derive it.
    """
    md = metadata or {}
    envelope = md.get("envelope", md)
    if not envelope:
        return (
            "IVMS101 hashing needs the envelope in metadata "
            "(either metadata.envelope or the envelope fields directly)."
        )
    result = await rpc_call("tenzro_ivms101Hash", envelope)
    return f"IVMS101 envelope hash:\n{json.dumps(result, indent=2)}"


async def handle_attested_clock(text: str, metadata: dict | None = None) -> str:
    """Read the node's attested-clock envelope.

    Returns wall-clock milliseconds plus a monotonic reading. `tee_vendor`
    identifies the enclave that signed the envelope; when it is null the
    envelope is unsigned and must not be used to decide mandate expiry.
    """
    result = await rpc_call("tenzro_attestedClockNow", [])
    return f"Attested clock:\n{json.dumps(result, indent=2)}"


async def handle_signed_agent_card(text: str, metadata: dict | None = None) -> str:
    """Compute the canonical hash of an A2A Signed Agent Card.

    Pass the card as `metadata.card`, or put the card fields at the top level
    of `metadata`. A domain owner signs this hash with their JWS key; a
    verifier re-hashes the served card and compares.
    """
    md = metadata or {}
    card = md.get("card", md)
    if not card:
        return (
            "Signed Agent Card hashing needs the card in metadata "
            "(either metadata.card or the card fields directly)."
        )
    result = await rpc_call("tenzro_signedAgentCardCanonicalHash", card)
    return f"Canonical agent card hash:\n{json.dumps(result, indent=2)}"


async def handle_stripe_spt(text: str, metadata: dict | None = None) -> str:
    """Read the Stripe SharedPaymentToken surface, or dispatch a webhook event.

    With no metadata this returns the protocol description: the four ceilings
    a confirm must clear, the `SptStatus` lifecycle, and how a settled token
    reaches the ERC-8004 ReputationRegistry.

    Pass `machine_did` + `granted_token_id` to dispatch an event. `event_type`
    selects the settlement cross-write (`payment_intent.succeeded`,
    `payment_intent.payment_failed`, `charge.dispute.created`,
    `charge.dispute.closed` — the closed event also needs `dispute_status` of
    `won` or `lost`). Omit `event_type` to run the deactivation cascade, which
    revokes the DID's credential across the mesh. Both dispatches need a
    validator's signer, so they are refused on a non-validator node.
    """
    md = metadata or {}
    machine_did = md.get("machine_did")
    granted_token_id = md.get("granted_token_id")

    if not machine_did or not granted_token_id:
        result = await rpc_call("tenzro_stripeSptProtocolInfo", [])
        return f"Stripe SPT:\n{json.dumps(result, indent=2)}"

    event_type = md.get("event_type")
    if not event_type:
        params = {
            "machine_did": machine_did,
            "granted_token_id": granted_token_id,
        }
        if md.get("revoker_did"):
            params["revoker_did"] = md["revoker_did"]
        result = await rpc_call("tenzro_processSptGrantedTokenDeactivated", params)
        return f"SPT granted token deactivated:\n{json.dumps(result, indent=2)}"

    params = {
        "machine_did": machine_did,
        "granted_token_id": granted_token_id,
        "event_type": event_type,
    }
    if md.get("payment_intent_id"):
        params["payment_intent_id"] = md["payment_intent_id"]
    if md.get("dispute_status"):
        params["dispute_status"] = md["dispute_status"]
    result = await rpc_call("tenzro_processSptSettlementOutcome", params)
    return f"SPT settlement outcome:\n{json.dumps(result, indent=2)}"


async def handle_wormhole_ntt(text: str, metadata: dict | None = None) -> str:
    """List the Wormhole chain IDs carrying NTT manager metadata."""
    result = await rpc_call("tenzro_wormholeNttListChains", [])
    return f"Wormhole NTT chains:\n{json.dumps(result, indent=2)}"


async def handle_bridge_fee(text: str, metadata: dict | None = None) -> str:
    """Quote a destination-native bridge fee in TNZO, and list sponsorship pools.

    A quote converts the destination chain's native fee into TNZO at the
    governance-set or oracle-fed rate. Sponsorship pools hold the TNZO that
    covers native gas on the destination side.
    """
    t = text.lower()
    md = metadata or {}

    if "pool" in t or "sponsor" in t:
        result = await rpc_call("tenzro_listBridgeSponsorshipPools", [])
        return f"Bridge sponsorship pools:\n{json.dumps(result, indent=2)}"

    required = ("adapter", "dest_chain", "native_fee_smallest_unit")
    if all(md.get(k) is not None for k in required):
        result = await rpc_call(
            "tenzro_quoteBridgeFeeInTnzo",
            {
                "adapter": md["adapter"],
                "dest_chain": md["dest_chain"],
                "native_fee_smallest_unit": str(md["native_fee_smallest_unit"]),
            },
        )
        return f"Bridge fee quote:\n{json.dumps(result, indent=2)}"

    return (
        "Bridge fees in TNZO. Say:\n"
        "- 'Quote bridge fee' (metadata: adapter ∈ layerzero|ccip|wormhole|"
        "debridge|hyperlane|axelar|lifi|canton, dest_chain, "
        "native_fee_smallest_unit)\n"
        "- 'List sponsorship pools'"
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
    "cortex": handle_cortex,
    "settlement": handle_settlement,
    "dvp-netting": handle_dvp_netting,
    "bond-insurance": handle_bond_insurance,
    "staking": handle_staking,
    "validator-lifecycle": handle_validator_lifecycle,
    "provider": handle_provider,
    "payment": handle_payment,
    "verification": handle_verification,
    "bridge": handle_bridge,
    "join": handle_join,
    "token": handle_list_tokens,
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
    "capability_registry": handle_capability_registry,
    "swarm_orchestration": handle_swarm,
    "lifecycle": handle_lifecycle,
    "debridge": handle_debridge,
    "crypto": handle_crypto,
    "tee": handle_tee,
    "custody": handle_custody,
    "passkey-wallet": handle_passkey,
    "zk": handle_zk,
    "ap2-payments": handle_ap2,
    "stripe-spt": handle_stripe_spt,
    "erc8004": handle_erc8004,
    "ccip": handle_ccip,
    "wormhole": handle_wormhole,
    "wormhole-ntt": handle_wormhole_ntt,
    "cct": handle_cct,
    "auth": handle_auth,
    "approval": handle_approval,
    "capital": handle_capital,
    "workflow": handle_workflow,
    "eip7702": handle_eip7702,
    "permit2": handle_permit2,
    "secure-mint": handle_secure_mint,
    "treasury": handle_treasury,
    "stable-asset": handle_stable_asset,
    "hyperlane": handle_hyperlane,
    "axelar": handle_axelar,
    "babylon": handle_babylon,
    "caip": handle_caip,
    "oracle": handle_oracle,
    "erc7683": handle_erc7683,
    "urwa": handle_urwa,
    "ivms101": handle_ivms101,
    "attested-clock": handle_attested_clock,
    "signed-agent-card": handle_signed_agent_card,
    "bridge-fee-in-tnzo": handle_bridge_fee,
    "agent-memory": handle_agent_memory,
    "adaptive-burn": handle_adaptive_burn,
    "seed-agent": handle_seed_agent,
    "forecast": handle_forecast,
    "vision-embed": handle_vision_embed,
    "text-embed": handle_text_embed,
    "segmentation": handle_segmentation,
    "text-segmentation": handle_text_segmentation,
    "detection": handle_detection,
    "audio-transcribe": handle_audio_transcribe,
    "video-embed": handle_video_embed,
    "storage": handle_storage,
    "database": handle_database,
    "compute": handle_compute,
    "moe": handle_moe,
    "media-gen": handle_media_gen,
    "operability": handle_operability,
    "discovery": handle_discovery,
    "hosting": handle_hosting,
    "help": handle_help,
}
