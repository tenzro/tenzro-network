//! RPC handlers for AP2, ERC-8004, Wormhole, and TNZO CCT.
//!
//! This module centralizes JSON-RPC handlers for four cross-cutting
//! integrations that layer on top of the core chain RPC surface:
//!
//! - **AP2 (Agent Payments Protocol)** — verify `Vdc`-wrapped intent /
//!   cart mandates, and validate parent-child mandate pairs.
//! - **ERC-8004 (Trustless Agents Registry)** — build calldata for the
//!   IdentityRegistry, ReputationRegistry, and ValidationRegistry
//!   contracts, plus derive canonical `agentId` from a DID.
//! - **Wormhole** — parse a VAA identifier, return the associated
//!   Wormhole chain id for a chain name, and relay transfer requests
//!   through the bridge router when the Wormhole adapter is registered.
//! - **TNZO CCT (Chainlink Cross-Chain Token)** — list / lookup pools
//!   in the TNZO registry and build CCT messages for wTNZO transfers.
//!
//! The handlers do not sign anything — clients are expected to
//! produce Ed25519 signatures locally using their wallet. This keeps
//! the node stateless with respect to user keys and matches the
//! TDIP / AP2 "the principal signs" contract.
//!
//! Dispatched from `rpc.rs::handle_request` via explicit match arms.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

// ============================================================
// AP2 — Agent Payments Protocol
// ============================================================

/// `tenzro_ap2VerifyMandate` — verify the Ed25519 signature on a
/// `Vdc`-wrapped AP2 mandate (intent or cart).
///
/// Params:
/// ```json
/// { "vdc": { ...Vdc JSON... } }
/// ```
pub(crate) async fn handle_ap2_verify_mandate(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let vdc_val = params
        .get("vdc")
        .cloned()
        .ok_or_else(|| missing("Missing vdc"))?;

    let vdc: tenzro_payments::ap2::Vdc = serde_json::from_value(vdc_val)
        .map_err(|e| invalid_params(format!("invalid Vdc JSON: {e}")))?;

    match vdc.verify() {
        Ok(()) => Ok(json!({
            "valid": true,
            "mandate_id": vdc.mandate_id(),
            "kind": format!("{:?}", vdc.kind).to_lowercase(),
            "signer_did": vdc.signer_did,
            "alg": vdc.alg,
        })),
        Err(e) => Ok(json!({
            "valid": false,
            "error": format!("{e}"),
        })),
    }
}

/// `tenzro_ap2ValidateMandatePair` — cross-validate a cart mandate
/// against its parent intent mandate (signatures + scope + expiry +
/// principal/agent binding).
///
/// When `enforce_delegation: true` is set, additionally cross-checks the
/// agent's TDIP `DelegationScope` against the cart total via
/// `IdentityRegistry::enforce_operation(agent_did, "payment", total)`.
/// This is the "TDIP identifies. AP2 authorizes. Tenzro settles." gate
/// for AP2 carts whose agent is a TDIP machine identity.
///
/// Params:
/// ```json
/// {
///   "intent_vdc": { ... },
///   "cart_vdc": { ... },
///   "enforce_delegation": false   // optional, default false
/// }
/// ```
pub(crate) async fn handle_ap2_validate_mandate_pair(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let intent_val = params
        .get("intent_vdc")
        .cloned()
        .ok_or_else(|| missing("Missing intent_vdc"))?;
    let cart_val = params
        .get("cart_vdc")
        .cloned()
        .ok_or_else(|| missing("Missing cart_vdc"))?;
    let enforce_delegation = params
        .get("enforce_delegation")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let intent: tenzro_payments::ap2::Vdc = serde_json::from_value(intent_val)
        .map_err(|e| invalid_params(format!("invalid intent_vdc: {e}")))?;
    let cart: tenzro_payments::ap2::Vdc = serde_json::from_value(cart_val)
        .map_err(|e| invalid_params(format!("invalid cart_vdc: {e}")))?;

    let validator = tenzro_payments::ap2::MandateValidator::new();

    let outcome: std::result::Result<(), tenzro_payments::PaymentError> = if enforce_delegation {
        let registry = node
            .identity_registry()
            .ok_or_else(|| invalid_params(
                "enforce_delegation=true but node has no IdentityRegistry wired",
            ))?;
        // Phase C: when an `AgentRuntime` is wired, also consult its
        // per-machine SpendingPolicy registry so AP2 cart validation
        // enforces all three nested ceilings — IntentMandate, TDIP
        // DelegationScope, and runtime SpendingPolicy. When the runtime
        // is absent (e.g. a light client), only AP2 + TDIP are checked.
        let policy_resolver_storage;
        let policy_resolver: Option<&dyn tenzro_payments::SpendingPolicyResolver> =
            if let Some(rt) = node.agent_runtime() {
                policy_resolver_storage =
                    crate::spending_policy_bridge::AgentRuntimeSpendingPolicyResolver::new(
                        rt.clone(),
                    );
                Some(&policy_resolver_storage)
            } else {
                None
            };
        validator.validate_with_delegation_and_policy(
            &intent,
            &cart,
            registry.as_ref(),
            policy_resolver,
        )
    } else {
        validator.validate(&intent, &cart)
    };

    match outcome {
        Ok(()) => Ok(json!({
            "valid": true,
            "intent_mandate_id": intent.mandate_id(),
            "cart_mandate_id": cart.mandate_id(),
            "principal_did": intent.signer_did,
            "agent_did": cart.signer_did,
            "delegation_enforced": enforce_delegation,
        })),
        Err(e) => Ok(json!({
            "valid": false,
            "error": format!("{e}"),
            "delegation_enforced": enforce_delegation,
        })),
    }
}

/// `tenzro_ap2ProtocolInfo` — surface static AP2 metadata.
pub(crate) async fn handle_ap2_protocol_info(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "version": tenzro_payments::ap2::AP2_VERSION,
        "signing_alg": "ed25519",
        "mandate_kinds": ["intent", "cart"],
        "presence_modes": ["human_present", "human_not_present"],
        "position": "TDIP identifies. AP2 authorizes. Tenzro settles.",
    }))
}

// ============================================================
// ERC-8004 — Trustless Agents Registry
// ============================================================

/// `tenzro_erc8004DeriveAgentId` — compute canonical `agentId`
/// (`keccak256(did)`) from a Tenzro DID.
pub(crate) async fn handle_erc8004_derive_agent_id(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let did = params
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing did"))?;
    let agent_id = tenzro_identity::erc8004::derive_agent_id(did);
    Ok(json!({
        "did": did,
        "agent_id": format!("0x{}", hex::encode(agent_id)),
    }))
}

/// `tenzro_erc8004EncodeRegister` — produce calldata for
/// `registerAgent(bytes32, address, string)`.
pub(crate) async fn handle_erc8004_encode_register(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let did = params
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing did"))?;
    let address = params
        .get("agent_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing agent_address"))?;
    let metadata_uri = params
        .get("metadata_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let agent_id = tenzro_identity::erc8004::derive_agent_id(did);
    let addr_bytes = parse_eth_addr(address)?;

    let data = tenzro_identity::erc8004::abi::encode_register_agent(
        tenzro_identity::erc8004::selectors::REGISTER_AGENT,
        &agent_id,
        &addr_bytes,
        metadata_uri,
    );
    Ok(json!({
        "agent_id": format!("0x{}", hex::encode(agent_id)),
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeGetAgent` — produce calldata for `getAgent(bytes32)`.
pub(crate) async fn handle_erc8004_encode_get_agent(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_bytes32(
        params
            .get("agent_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_get_agent(
        tenzro_identity::erc8004::selectors::GET_AGENT,
        &agent_id,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004DecodeGetAgent` — decode ABI return of `getAgent()`.
pub(crate) async fn handle_erc8004_decode_get_agent(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let ret_hex = params
        .get("return_data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing return_data"))?;
    let bytes = hex::decode(ret_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid hex: {e}")))?;
    match tenzro_identity::erc8004::abi::decode_get_agent(&bytes) {
        Some((addr, uri)) => Ok(json!({
            "agent_address": format!("0x{}", hex::encode(addr)),
            "metadata_uri": uri,
        })),
        None => Err(invalid_params("failed to decode getAgent return")),
    }
}

/// `tenzro_erc8004EncodeFeedback` — produce calldata for
/// `submitFeedback(bytes32, int8, string)`.
pub(crate) async fn handle_erc8004_encode_feedback(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let subject = parse_bytes32(
        params
            .get("subject_agent_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing subject_agent_id"))?,
    )?;
    let rating: i8 = params
        .get("rating")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| missing("Missing rating"))?
        .clamp(i8::MIN as i64, i8::MAX as i64) as i8;
    let context_uri = params
        .get("context_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let data = tenzro_identity::erc8004::abi::encode_submit_feedback(
        tenzro_identity::erc8004::selectors::SUBMIT_FEEDBACK,
        &subject,
        rating,
        context_uri,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeRequestValidation` — produce calldata for
/// `requestValidation(bytes32, bytes32, string)`.
pub(crate) async fn handle_erc8004_encode_request_validation(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let subject = parse_bytes32(
        params
            .get("subject_agent_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing subject_agent_id"))?,
    )?;
    let work_hash = parse_bytes32(
        params
            .get("work_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing work_hash"))?,
    )?;
    let metadata_uri = params
        .get("metadata_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let data = tenzro_identity::erc8004::abi::encode_request_validation(
        tenzro_identity::erc8004::selectors::REQUEST_VALIDATION,
        &subject,
        &work_hash,
        metadata_uri,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeSubmitValidation` — produce calldata for
/// `submitValidation(bytes32, bool, string)`.
pub(crate) async fn handle_erc8004_encode_submit_validation(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let request_id = parse_bytes32(
        params
            .get("request_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing request_id"))?,
    )?;
    let valid = params
        .get("valid")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| missing("Missing valid"))?;
    let proof_uri = params
        .get("proof_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let data = tenzro_identity::erc8004::abi::encode_submit_validation(
        tenzro_identity::erc8004::selectors::SUBMIT_VALIDATION,
        &request_id,
        valid,
        proof_uri,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

// ============================================================
// Wormhole
// ============================================================

/// `tenzro_wormholeChainId` — look up the Wormhole-assigned numeric
/// chain id for a chain name.
pub(crate) async fn handle_wormhole_chain_id(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let chain = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing chain"))?;

    // Source chain/contract addresses aren't needed for a chain-ID lookup;
    // pass placeholders and rely on the default chain_id_map.
    let cfg = tenzro_bridge::WormholeConfig::new(0u16, "", "");
    match cfg.chain_id(chain) {
        Some(id) => Ok(json!({ "chain": chain, "wormhole_chain_id": id })),
        None => Err(invalid_params(format!("unknown Wormhole chain: {chain}"))),
    }
}

/// `tenzro_wormholeParseVaaId` — split a canonical VAA id
/// (`{chain}/{emitter}/{sequence}`) into its components.
pub(crate) async fn handle_wormhole_parse_vaa_id(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let id = params
        .get("vaa_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing vaa_id"))?;

    let parts: Vec<&str> = id.split('/').collect();
    if parts.len() != 3 {
        return Err(invalid_params("VAA id must be {chain}/{emitter}/{sequence}"));
    }
    let chain: u16 = parts[0]
        .parse()
        .map_err(|_| invalid_params("invalid chain id"))?;
    let emitter = parts[1].to_string();
    let sequence: u64 = parts[2]
        .parse()
        .map_err(|_| invalid_params("invalid sequence"))?;

    Ok(json!({
        "emitter_chain": chain,
        "emitter_address": emitter,
        "sequence": sequence,
    }))
}

/// `tenzro_wormholeBridge` — relay a token transfer through the
/// bridge router. The router selects an adapter per its configured
/// routing preferences; if Wormhole is registered and preferred, the
/// transfer goes over Wormhole.
pub(crate) async fn handle_wormhole_bridge(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let router = node.bridge_router().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "Bridge router not initialized".to_string(),
        data: None,
    })?;

    let source = params
        .get("source_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing source_chain"))?;
    let dest = params
        .get("dest_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing dest_chain"))?;
    let asset = params
        .get("asset")
        .and_then(|v| v.as_str())
        .unwrap_or("TNZO");
    let amount: u128 = parse_u128(params.get("amount"))
        .ok_or_else(|| invalid_params("Missing or invalid amount"))?;
    let sender = params
        .get("sender")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing sender"))?;
    let recipient = params
        .get("recipient")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing recipient"))?;

    // Verify the Wormhole adapter is registered before attempting.
    let adapters = router.list_adapters().await;
    let has_wormhole = adapters
        .iter()
        .any(|n| n.to_lowercase().contains("wormhole"));
    if !has_wormhole {
        return Ok(json!({
            "status": "unavailable",
            "error": "Wormhole adapter not registered in BridgeRouter",
            "registered_adapters": adapters,
        }));
    }

    let req = tenzro_bridge::BridgeTokenRequest::new(
        source.to_string(),
        dest.to_string(),
        asset.to_string(),
        amount,
        sender.to_string(),
        recipient.to_string(),
    );

    match router.bridge_tokens(req).await {
        Ok(receipt) => Ok(json!({
            "transfer_id": receipt.transfer_id,
            "source_chain": receipt.source_chain,
            "dest_chain": receipt.dest_chain,
            "tx_hash": format!("{}", receipt.tx_hash),
            "fee_paid": receipt.fee_paid.to_string(),
            "estimated_arrival_ms": receipt.estimated_arrival,
        })),
        Err(e) => Ok(json!({
            "status": "failed",
            "error": format!("{e}"),
        })),
    }
}

// ============================================================
// TNZO CCT — Chainlink Cross-Chain Token
// ============================================================

/// `tenzro_cctListPools` — return the canonical Tenzro mainnet TNZO
/// CCT topology (Ethereum, Base, Arbitrum, Optimism, Solana).
pub(crate) async fn handle_cct_list_pools(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let registry = tenzro_bridge::TnzoCctRegistry::tenzro_mainnet();
    let pools: Vec<Value> = registry
        .all()
        .into_iter()
        .map(pool_to_json)
        .collect();
    Ok(json!({
        "pools": pools,
        "count": registry.len(),
    }))
}

/// `tenzro_cctGetPool` — lookup a single TNZO CCT pool by chain id.
pub(crate) async fn handle_cct_get_pool(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let chain = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing chain"))?;

    let registry = tenzro_bridge::TnzoCctRegistry::tenzro_mainnet();
    match registry.get(chain) {
        Some(pool) => Ok(pool_to_json(pool)),
        None => Err(invalid_params(format!(
            "no TNZO CCT pool registered for {chain}"
        ))),
    }
}

// ============================================================
// EIP-7702 — EOA Code Delegation (stateless helpers)
// ============================================================

/// `tenzro_eip7702SigningHash` — compute the keccak256 signing hash
/// for an EIP-7702 authorization tuple. Clients sign this hash with
/// secp256k1 to produce the `signature` field.
///
/// Params:
/// ```json
/// { "chain_id": 1337, "delegate_address": "0x...", "nonce": 0 }
/// ```
pub(crate) async fn handle_eip7702_signing_hash(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let chain_id = params
        .get("chain_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing chain_id"))?;
    let delegate = params
        .get("delegate_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing delegate_address"))?;
    let nonce = params
        .get("nonce")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing nonce"))?;

    let delegate_bytes = parse_eth_addr(delegate)?;
    let auth = tenzro_vm::account_abstraction::Eip7702Authorization {
        chain_id,
        delegate_address: delegate_bytes.to_vec(),
        nonce,
        signature: Vec::new(),
    };

    let signing_hash = auth.signing_hash();
    let signing_data = auth.signing_data();

    Ok(json!({
        "signing_hash": format!("0x{}", hex::encode(signing_hash)),
        "signing_data": format!("0x{}", hex::encode(&signing_data)),
        "magic_byte": "0x05",
    }))
}

/// `tenzro_eip7702BuildDesignator` — build the 23-byte delegation
/// designator (`0xef0100 || delegate_address`) that gets written to
/// the EOA's code slot when an authorization is accepted.
pub(crate) async fn handle_eip7702_build_designator(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let delegate = params
        .get("delegate_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing delegate_address"))?;
    let delegate_bytes = parse_eth_addr(delegate)?;

    let designator = tenzro_vm::account_abstraction::build_7702_designator(&delegate_bytes)
        .map_err(|e| invalid_params(format!("build_7702_designator: {e}")))?;

    Ok(json!({
        "designator": format!("0x{}", hex::encode(&designator)),
        "length": designator.len(),
        "prefix": "0xef0100",
        "delegate_address": delegate,
    }))
}

/// `tenzro_eip7702ParseDesignator` — decode a 23-byte designator and
/// extract the delegate address. Returns `{ "delegate_address": null }`
/// for code that isn't a valid EIP-7702 designator.
pub(crate) async fn handle_eip7702_parse_designator(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let code_hex = params
        .get("code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing code"))?;
    let stripped = code_hex.trim_start_matches("0x");
    let code = hex::decode(stripped).map_err(|e| invalid_params(format!("invalid hex: {e}")))?;

    match tenzro_vm::account_abstraction::parse_7702_designator(&code) {
        Some(delegate) => Ok(json!({
            "is_designator": true,
            "delegate_address": format!("0x{}", hex::encode(&delegate)),
        })),
        None => Ok(json!({
            "is_designator": false,
            "delegate_address": serde_json::Value::Null,
        })),
    }
}

/// `tenzro_eip7702ProtocolInfo` — static metadata about the EIP-7702
/// support surface (tx type, magic byte, designator layout).
pub(crate) async fn handle_eip7702_protocol_info(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "tx_type": tenzro_vm::account_abstraction::EIP_7702_TX_TYPE,
        "magic_byte": tenzro_vm::account_abstraction::EIP_7702_MAGIC,
        "designator_prefix": format!(
            "0x{}",
            hex::encode(tenzro_vm::account_abstraction::EIP_7702_DESIGNATOR_PREFIX)
        ),
        "designator_length": tenzro_vm::account_abstraction::EIP_7702_DESIGNATOR_LEN,
        "signing_scheme": "secp256k1",
        "signature_format": "r(32) || s(32) || y_parity(1)",
        "preimage": "MAGIC(0x05) || rlp([chain_id, delegate_address, nonce])",
        "note": "Full txtype 0x04 RLP decoding in eth_sendRawTransaction is a separate mainnet task; use tenzro_eip7702SigningHash + client-side secp256k1 signing + tenzro_eip7702BuildDesignator for now.",
    }))
}

// ============================================================
// Helpers
// ============================================================

fn pool_to_json(pool: tenzro_bridge::TnzoCctPool) -> Value {
    json!({
        "chain_id": pool.chain_id,
        "chain_selector": pool.chain_selector.to_string(),
        "pool_address": pool.pool_address,
        "token_address": pool.token_address,
        "pool_type": match pool.pool_type {
            tenzro_bridge::CctPoolType::LockRelease => "LockRelease",
            tenzro_bridge::CctPoolType::BurnMint => "BurnMint",
        },
        "contract_name": pool.pool_type.contract_name(),
        "outbound_capacity": pool.outbound_capacity.to_string(),
        "inbound_capacity": pool.inbound_capacity.to_string(),
        "refill_rate": pool.refill_rate.to_string(),
    })
}

fn missing(msg: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.to_string(),
        data: None,
    }
}

fn invalid_params(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: msg.into(),
        data: None,
    }
}

fn unwrap_arr(params: Value) -> Value {
    if let Some(arr) = params.as_array() {
        arr.first().cloned().unwrap_or(params)
    } else {
        params
    }
}

fn parse_u128(v: Option<&Value>) -> Option<u128> {
    v.and_then(|v| {
        v.as_str()
            .and_then(|s| s.parse::<u128>().ok())
            .or_else(|| v.as_u64().map(|n| n as u128))
    })
}

fn parse_eth_addr(s: &str) -> std::result::Result<[u8; 20], JsonRpcError> {
    let hex_str = s.trim_start_matches("0x");
    let bytes = hex::decode(hex_str)
        .map_err(|e| invalid_params(format!("invalid address hex: {e}")))?;
    if bytes.len() != 20 {
        return Err(invalid_params(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_bytes32(s: &str) -> std::result::Result<[u8; 32], JsonRpcError> {
    let hex_str = s.trim_start_matches("0x");
    let bytes = hex::decode(hex_str)
        .map_err(|e| invalid_params(format!("invalid bytes32 hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(invalid_params(format!(
            "bytes32 must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_eth_addr_rejects_wrong_length() {
        assert!(parse_eth_addr("0x1234").is_err());
        assert!(parse_eth_addr("not-hex").is_err());
        assert!(parse_eth_addr("0x0000000000000000000000000000000000000000").is_ok());
    }

    #[tokio::test]
    async fn parse_bytes32_roundtrip() {
        let s = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let b = parse_bytes32(s).unwrap();
        assert_eq!(b[31], 1);
    }

    #[tokio::test]
    async fn unwrap_arr_extracts_first_element() {
        let v = json!([{ "a": 1 }]);
        let u = unwrap_arr(v);
        assert_eq!(u, json!({ "a": 1 }));
    }

    #[tokio::test]
    async fn unwrap_arr_passes_object_through() {
        let v = json!({ "a": 1 });
        let u = unwrap_arr(v.clone());
        assert_eq!(u, v);
    }
}
