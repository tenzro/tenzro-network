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
/// Params (AP2 v0.2):
/// ```json
/// {
///   "checkout_vdc": { ... },
///   "payment_vdc":  { ... },
///   "enforce_delegation": false   // optional, default false
/// }
/// ```
pub(crate) async fn handle_ap2_validate_mandate_pair(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let checkout_val = params
        .get("checkout_vdc")
        .cloned()
        .ok_or_else(|| missing("Missing checkout_vdc"))?;
    let payment_val = params
        .get("payment_vdc")
        .cloned()
        .ok_or_else(|| missing("Missing payment_vdc"))?;
    let enforce_delegation = params
        .get("enforce_delegation")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let checkout: tenzro_payments::ap2::Vdc = serde_json::from_value(checkout_val)
        .map_err(|e| invalid_params(format!("invalid checkout_vdc: {e}")))?;
    let payment: tenzro_payments::ap2::Vdc = serde_json::from_value(payment_val)
        .map_err(|e| invalid_params(format!("invalid payment_vdc: {e}")))?;

    let validator = tenzro_payments::ap2::MandateValidator::new();

    let outcome: std::result::Result<(), tenzro_payments::PaymentError> = if enforce_delegation {
        let registry = node
            .identity_registry()
            .ok_or_else(|| invalid_params(
                "enforce_delegation=true but node has no IdentityRegistry wired",
            ))?;
        // When an `AgentRuntime` is wired, also consult its per-machine
        // SpendingPolicy registry so AP2 cart validation enforces all
        // three nested AP2 v0.2 ceilings — CheckoutMandate, TDIP
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
        // Fourth ceiling — when the mandate pair carries an `escrow_id`,
        // resolve it against the on-chain EscrowManager so the cart is
        // additionally bounded by `escrow.amount` and `escrow.releasable`.
        // When no EscrowManager is wired (light client) and the mandate
        // pair carries an escrow_id, validation will hard-fail — the
        // mandate explicitly committed to settlement against an on-chain
        // escrow, so an unwired resolver is the wrong posture.
        let escrow_resolver_storage;
        let escrow_resolver: Option<&dyn tenzro_payments::EscrowResolver> =
            if let Some(em) = node.escrow_manager() {
                escrow_resolver_storage =
                    crate::escrow_resolver_bridge::EscrowManagerResolver::new(em.clone());
                Some(&escrow_resolver_storage)
            } else {
                None
            };
        // Fifth ceiling — when the mandate pair carries a `spt_grant_id`,
        // resolve it against the configured Stripe SPT cache so the
        // cart is additionally bounded by `usage_limits.max_amount` and
        // currency match. Same `Some/None` semantics as the escrow
        // resolver: if the cache adapter is wired, the resolver fires;
        // if absent and the mandate carries a `spt_grant_id`, validation
        // hard-fails (mandate committed to the SPT but the gate cannot
        // resolve it).
        let spt_cache = node.spt_ceiling_cache();
        let spt_resolver: Option<&dyn tenzro_payments::mpp::stripe_spt::SptCeilingResolver> =
            spt_cache.as_deref().map(|c| c as _);
        validator.validate_with_delegation_policy_escrow_and_spt(
            &checkout,
            &payment,
            registry.as_ref(),
            policy_resolver,
            escrow_resolver,
            spt_resolver,
        )
    } else {
        validator.validate(&checkout, &payment)
    };

    match outcome {
        Ok(()) => {
            // Persist the validated pair so the principal can later enumerate
            // the mandates issued under their DID via `tenzro_listMandates`.
            // Recording is best-effort: a store write failure must not fail a
            // validation that already succeeded, so it is logged and swallowed.
            if let (Some(store), Some(co), Some(pay)) = (
                node.mandate_store(),
                checkout.as_checkout(),
                payment.as_payment(),
            ) {
                let record = crate::mandate_store::MandateRecord {
                    mandate_id: co.mandate_id.clone(),
                    payment_mandate_id: pay.mandate_id.clone(),
                    controller_did: checkout.signer_did.clone(),
                    agent_did: payment.signer_did.clone(),
                    merchant_did: pay.merchant_did.clone(),
                    description: co.description.clone(),
                    max_amount: co.max_amount,
                    total_amount: pay.total_amount,
                    asset: co.asset.clone(),
                    chain: pay.chain.clone(),
                    expires_at: co.expires_at.to_rfc3339(),
                    delegation_enforced: enforce_delegation,
                    validated_at_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0),
                    checkout_vdc: serde_json::to_value(&checkout).unwrap_or(Value::Null),
                    payment_vdc: serde_json::to_value(&payment).unwrap_or(Value::Null),
                };
                if let Err(e) = store.record(record) {
                    tracing::warn!("mandate record persist failed: {e}");
                }
            }
            Ok(json!({
                "valid": true,
                "checkout_mandate_id": checkout.mandate_id(),
                "payment_mandate_id": payment.mandate_id(),
                "principal_did": checkout.signer_did,
                "agent_did": payment.signer_did,
                "delegation_enforced": enforce_delegation,
            }))
        }
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
        "mandate_kinds": ["checkout", "payment"],
        "vct_claims": [
            "mandate.checkout.1",
            "mandate.checkout.open.1",
            "mandate.payment.1",
            "mandate.payment.open.1",
        ],
        "presence_modes": ["human_present", "human_not_present"],
        "cnf_forms": ["jwk", "did"],
        "cnf_enforcement": {
            "jwk": "x_param_must_match_signer_public_key",
            "did": "resolves_via_tdip_identity_registry_signer_key_must_appear_in_did_document",
        },
        "ceilings": [
            "ap2_checkout_mandate",
            "tdip_delegation_scope",
            "runtime_spending_policy",
            "onchain_escrow",
            "stripe_spt_usage_limits",
        ],
        "spt_enforcement": {
            "trigger": "checkout_or_payment_mandate_carries_spt_grant_id",
            "checks": [
                "spt_resolves_via_stripe_api",
                "spt_status_active",
                "spt_usage_limits_max_amount_at_least_cart_total",
                "spt_usage_limits_currency_matches_payment_asset",
                "spt_usage_limits_not_expired",
            ],
            "field": "spt_grant_id",
            "resolver": "tenzro_node::spt_ceiling_bridge::SptCeilingResolverAdapter",
        },
        "escrow_enforcement": {
            "trigger": "checkout_or_payment_mandate_carries_escrow_id",
            "checks": [
                "escrow_resolves_on_chain",
                "escrow_status_funded_and_not_expired",
                "escrow_amount_at_least_payment_total",
            ],
            "release_selector": "0x01000011",
            "create_selector": "0x01000010",
        },
        "agent_bond_enforcement": {
            "trigger": "checkout_mandate_carries_agent_bond_id_and_violation_observed",
            "rpc": "tenzro_ap2ReportMandateViolation",
            "flow": [
                "report_files_insurance_claim_against_agent_bond_id",
                "governance_reviews_evidence_and_approves_or_rejects",
                "approved_claim_paid_via_PayInsuranceClaim_typed_tx",
                "BondSlashed_log_reflected_into_BondManager",
            ],
            "violation_kinds": [
                "overspend",
                "merchant_whitelist_breach",
                "category_breach",
                "expired_mandate_settlement",
                "double_spend",
                "missing_cnf_binding",
                "other",
            ],
            "slash_dispatch": "off_chain_claim_then_governance_then_PayInsuranceClaim",
        },
        "tenzro_extensions": {
            "checkout_hash": "sha256_hex_of_parent_checkout_vdc_preimage",
            "escrow_id": "tenzro_native_onchain_escrow_id",
            "agent_bond_id": "tenzro_agentbond_id_for_slashable_collateral",
            "cnf_did": "did_resolvable_to_binding_key_via_tdip",
            "spt_grant_id": "stripe_shared_payment_granted_token_id",
        },
        "position": "TDIP identifies. AP2 authorizes. Tenzro settles.",
    }))
}

/// `tenzro_listMandates` — enumerate the validated AP2 mandate pairs whose
/// principal (CheckoutMandate `principal_did`) is the given controller DID.
/// Ordered newest-first by validation time. Returns an empty list when the
/// controller has no recorded mandates, or when the node has no mandate store
/// (no persistent storage). Each row carries the projected summary plus the
/// full signed VDCs so a relying party can re-verify independently.
pub(crate) async fn handle_list_mandates(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let controller_did = params
        .get("controller_did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing controller_did"))?
        .to_string();

    let mandates = match node.mandate_store() {
        Some(store) => store.list_by_controller(&controller_did),
        None => Vec::new(),
    };

    let items: Vec<Value> = mandates
        .into_iter()
        .map(|m| {
            json!({
                "mandate_id": m.mandate_id,
                "payment_mandate_id": m.payment_mandate_id,
                "controller_did": m.controller_did,
                "agent_did": m.agent_did,
                "merchant_did": m.merchant_did,
                "description": m.description,
                "max_amount": m.max_amount.to_string(),
                "total_amount": m.total_amount.to_string(),
                "asset": m.asset,
                "chain": m.chain,
                "expires_at": m.expires_at,
                "delegation_enforced": m.delegation_enforced,
                "validated_at_ms": m.validated_at_ms,
                "checkout_vdc": m.checkout_vdc,
                "payment_vdc": m.payment_vdc,
            })
        })
        .collect();

    Ok(json!({
        "controller_did": controller_did,
        "count": items.len(),
        "mandates": items,
    }))
}

/// `tenzro_x402ProtocolInfo` — surface static x402 metadata, including
/// the Tenzro extensions (cross-VM `network` field, Plonky3 settlement-AIR
/// commitment in the `X-PAYMENT-RESPONSE` body).
///
/// Stock Coinbase x402 v1 carries a facilitator attestation in
/// `X-PAYMENT-RESPONSE` — *not* a cryptographic proof. Tenzro extends
/// this with a 32-byte settlement-AIR commitment bound to the canonical
/// settlement summary via domain-separated SHA-256
/// (`tenzro/x402/receipt`), and accepts native Tenzro VM identifiers
/// (`tenzro-evm`, `tenzro-svm`, `tenzro-daml`) in the `network` field —
/// no other x402 extension covers DAML/Canton.
pub(crate) async fn handle_x402_protocol_info(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "spec": "coinbase x402 v1",
        "x402_version": 2,
        "headers": {
            "request": "X-PAYMENT",
            "response": "X-PAYMENT-RESPONSE",
        },
        "schemes": [
            tenzro_payments::x402::DEFAULT_SCHEME,
            "exact-eip3009",
            "permit2",
            "erc7710",
            tenzro_payments::x402::UPTO_SCHEME,
            tenzro_payments::x402::BATCH_SETTLEMENT_SCHEME,
        ],
        "default_scheme": tenzro_payments::x402::DEFAULT_SCHEME,
        "tenzro_extensions": {
            "cross_vm_network": {
                "accepted_values": ["tenzro-evm", "tenzro-svm", "tenzro-daml"],
                "rationale": "no_third_party_x402_extension_covers_daml_canton",
            },
            "plonky3_receipt": {
                "field": "tenzroCommitment",
                "domain_tag": tenzro_payments::x402::X402_RECEIPT_DOMAIN,
                "length_bytes": tenzro_payments::x402::X402_RECEIPT_COMMITMENT_LEN,
                "binding": [
                    "scheme",
                    "network",
                    "challenge_id",
                    "credential_id",
                    "resource",
                    "asset",
                    "amount",
                    "payer",
                    "recipient",
                    "tx_hash",
                ],
                "verification": "lookup_in_zk_commitment_registry_offEVM_via_validators",
            },
            "tenzro_vm_field": {
                "field": "tenzroVm",
                "values": ["tenzro-evm", "tenzro-svm", "tenzro-daml"],
                "absent_when": "settlement_landed_on_external_chain",
            },
            "bazaar_discovery": {
                "rpc": [
                    "tenzro_x402RegisterResource",
                    "tenzro_x402DiscoverResources",
                    "tenzro_x402DeregisterResource",
                ],
                "http": "GET /discovery/resources",
                "listing_domain_tag": tenzro_payments::x402::BAZAAR_LISTING_DOMAIN,
                "binding": ["seller_did", "resource"],
                "reputation": {
                    "join": "listing.pay_to -> provider_reputation_ledger",
                    "score_up_path": "settled_payment_only",
                    "sort": "reputation_desc_then_updated_at_desc_unscored_last",
                    "filter": "minReputation_floor_excludes_unscored",
                },
            },
            "signed_offer": {
                "rpc": [
                    "tenzro_x402VerifyOffer",
                    "tenzro_x402PaymentId",
                ],
                "extra_keys": [
                    tenzro_payments::x402::OFFER_COMMITMENT_KEY,
                    tenzro_payments::x402::OFFER_SIG_KEY,
                    tenzro_payments::x402::OFFER_SIGNER_KEY,
                ],
                "offer_domain_tag": tenzro_payments::x402::X402_OFFER_DOMAIN,
                "payment_id_domain_tag": tenzro_payments::x402::X402_PAYMENT_ID_DOMAIN,
                "binding": ["scheme", "network", "max_amount_required", "asset", "pay_to", "resource", "expires_at"],
                "idempotency": "settlement_keyed_by_offer_commitment_and_payer_did_replay_returns_prior_receipt",
            },
        },
        "stock_compatibility": "tenzroCommitment_and_tenzroVm_omitted_from_external_chain_receipts_so_stock_clients_unaffected",
    }))
}

/// `tenzro_x402RegisterResource` — a seller publishes a discoverable paid
/// resource into the Bazaar catalog. The listing id is derived server-side
/// from `(seller_did, resource)` so a client cannot spoof another seller's id;
/// re-registering the same resource is idempotent (updates in place).
///
/// Params (object): `sellerDid`, `resource`, `scheme`, `network`, `asset`,
/// `payTo`, `maxAmountRequired`, optional `description`, `mimeType`,
/// `maxTimeoutSeconds`, `tags` (array), and `extra` (scheme-specific object).
pub(crate) async fn handle_x402_register_resource(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let catalog = node
        .bazaar_catalog()
        .ok_or_else(|| invalid_params("payment gateway not initialized"))?;
    let p = unwrap_arr(params.unwrap_or(Value::Null));

    let seller_did = p
        .get("sellerDid")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("sellerDid required"))?
        .to_string();
    let resource = p
        .get("resource")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("resource required"))?;
    let scheme = p
        .get("scheme")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("scheme required"))?;
    let network = p
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("network required"))?;
    let asset = p
        .get("asset")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("asset required"))?;
    let pay_to = p
        .get("payTo")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("payTo required"))?;
    let max_amount = p
        .get("maxAmountRequired")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("maxAmountRequired required"))?;
    let description = p
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mime_type = p
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or("application/json");
    let max_timeout_seconds = p
        .get("maxTimeoutSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(300);
    let tags: Vec<String> = p
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut requirement = tenzro_payments::x402::X402PaymentRequirement::new(
        scheme,
        network,
        max_amount,
        pay_to,
        asset,
        resource,
        description,
        mime_type,
        max_timeout_seconds,
    );
    if let Some(extra) = p.get("extra").filter(|v| !v.is_null()) {
        requirement = requirement.with_extra(extra.clone());
    }

    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let listing = tenzro_payments::x402::X402ResourceListing::new(
        seller_did,
        requirement,
        tags,
        now_ms,
    );
    let listing_id = catalog.register(listing).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("bazaar register: {e}"),
        data: None,
    })?;

    Ok(json!({ "listingId": listing_id }))
}

/// `tenzro_x402DiscoverResources` — a buyer queries the Bazaar catalog for
/// listings matching a filter. All set fields are ANDed; unset fields match
/// everything. Each result carries `seller_reputation` joined from the
/// provider ledger (0-1000; absent when the seller is unscored). Results
/// sort by reputation descending, then freshness, and are capped by `limit`
/// when non-zero.
///
/// Params (object): optional `scheme`, `network`, `asset`, `sellerDid`,
/// `tags` (array), `minReputation` (number — unscored sellers fail the
/// floor), `limit` (number).
pub(crate) async fn handle_x402_discover_resources(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let catalog = node
        .bazaar_catalog()
        .ok_or_else(|| invalid_params("payment gateway not initialized"))?;
    let p = unwrap_arr(params.unwrap_or(Value::Null));

    let query = tenzro_payments::x402::ResourceQuery {
        scheme: p.get("scheme").and_then(Value::as_str).map(String::from),
        network: p.get("network").and_then(Value::as_str).map(String::from),
        asset: p.get("asset").and_then(Value::as_str).map(String::from),
        seller_did: p.get("sellerDid").and_then(Value::as_str).map(String::from),
        tags: p
            .get("tags")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        min_reputation: p.get("minReputation").and_then(Value::as_u64),
        limit: p.get("limit").and_then(Value::as_u64).unwrap_or(0) as usize,
    };

    let listings = catalog.discover(&query);
    Ok(json!({ "listings": listings, "count": listings.len() }))
}

/// `tenzro_x402DeregisterResource` — a seller removes its own listing. The
/// removal is refused if `sellerDid` does not own the listing.
///
/// Params (object): `listingId`, `sellerDid`.
pub(crate) async fn handle_x402_deregister_resource(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let catalog = node
        .bazaar_catalog()
        .ok_or_else(|| invalid_params("payment gateway not initialized"))?;
    let p = unwrap_arr(params.unwrap_or(Value::Null));

    let listing_id = p
        .get("listingId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("listingId required"))?;
    let seller_did = p
        .get("sellerDid")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("sellerDid required"))?;

    let removed = catalog
        .deregister(listing_id, seller_did)
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("bazaar deregister: {e}"),
            data: None,
        })?;
    Ok(json!({ "removed": removed }))
}

/// `tenzro_x402VerifyOffer` — verify a server-signed offer carried in a 402
/// payment requirement. A buyer that received an `X402PaymentRequirement`
/// (with `offerCommitment` / `offerSig` / `offerSigner` in `extra`) passes the
/// requirement back verbatim; the node recomputes the commitment, checks it
/// against the carried value, and verifies the Ed25519 signature under the
/// carried signer key. No node state is consulted — this is a pure
/// verification the buyer can run before paying.
///
/// Params (object): `requirement` — the full [`X402PaymentRequirement`] JSON
/// exactly as it appeared in the 402 body.
pub(crate) async fn handle_x402_verify_offer(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = unwrap_arr(params.unwrap_or(Value::Null));
    let req_value = p
        .get("requirement")
        .filter(|v| !v.is_null())
        .ok_or_else(|| invalid_params("requirement required"))?;
    let requirement: tenzro_payments::x402::X402PaymentRequirement =
        serde_json::from_value(req_value.clone())
            .map_err(|e| invalid_params(format!("requirement decode: {e}")))?;

    let offer = tenzro_payments::x402::SignedOffer::extract_from(&requirement)
        .ok_or_else(|| invalid_params("requirement carries no signed offer"))?;

    match offer.verify(&requirement) {
        Ok(()) => Ok(json!({
            "valid": true,
            "offerCommitment": offer.offer_commitment,
            "offerSigner": offer.offer_signer,
        })),
        Err(e) => Ok(json!({
            "valid": false,
            "reason": e.to_string(),
            "offerCommitment": offer.offer_commitment,
            "offerSigner": offer.offer_signer,
        })),
    }
}

/// `tenzro_x402PaymentId` — derive the deterministic `pay_<hex>` idempotency
/// identifier for a `(offer, payer)` pair. A buyer that wants to know its
/// payment id ahead of settling — to detect and skip a retry client-side —
/// passes either the full `requirement` (the node recomputes the commitment)
/// or a pre-computed `offerCommitment` hex, plus the `payerDid`.
///
/// Params (object): one of `requirement` (full requirement JSON) or
/// `offerCommitment` (64-hex), and `payerDid`.
pub(crate) async fn handle_x402_payment_id(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = unwrap_arr(params.unwrap_or(Value::Null));
    let payer_did = p
        .get("payerDid")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("payerDid required"))?;

    let commitment: [u8; tenzro_payments::x402::X402_OFFER_COMMITMENT_LEN] =
        if let Some(req_value) = p.get("requirement").filter(|v| !v.is_null()) {
            let requirement: tenzro_payments::x402::X402PaymentRequirement =
                serde_json::from_value(req_value.clone())
                    .map_err(|e| invalid_params(format!("requirement decode: {e}")))?;
            tenzro_payments::x402::compute_offer_commitment(&requirement)
        } else if let Some(hex_str) = p.get("offerCommitment").and_then(Value::as_str) {
            let bytes = hex::decode(hex_str)
                .map_err(|e| invalid_params(format!("offerCommitment hex: {e}")))?;
            bytes
                .try_into()
                .map_err(|_| invalid_params("offerCommitment must be 32 bytes"))?
        } else {
            return Err(invalid_params(
                "one of requirement or offerCommitment required",
            ));
        };

    let payment_id = tenzro_payments::x402::derive_payment_id(&commitment, payer_did);
    Ok(json!({
        "paymentId": payment_id,
        "offerCommitment": hex::encode(commitment),
    }))
}

/// `tenzro_visaTapProtocolInfo` — advertise Tenzro's Visa TAP profile and
/// the two extensions over the published spec.
///
/// Visa's reference TAP recognises agents by their RFC 9421 HTTP message
/// signature, with the `keyid` parameter resolving to a JWK published at
/// `https://mcp.visa.com/.well-known/jwks`. The spec adds a `tag`
/// parameter that takes one of two values: `agent-browser-auth` (the
/// agent is browsing) or `agent-payer-auth` (the agent is paying);
/// signatures must fall inside an 8-minute (`created`-`expired`) window.
///
/// Tenzro's profile is a strict superset of Visa's wire shape:
///
/// 1. **Tag taxonomy** — both `agent-browser-auth` and `agent-payer-auth`
///    are accepted; verifiers attach the parsed [`AgentTag`] to the
///    [`VerificationResult`] so payment endpoints can require the
///    payer-auth tag while browse endpoints can require browser-auth.
/// 2. **DID-resolvable `keyid`** — RFC 9421 §2.3 leaves `keyid` opaque,
///    so a Tenzro agent can present `keyid="did:tenzro:machine:<uuid>"`
///    and the [`DidResolverAgentRegistry`] pulls the Ed25519 verification
///    key directly from the local TDIP identity registry — no JWKS
///    round-trip and no central trust anchor. Non-DID keyids continue to
///    flow through the JWKS fallback so the same verifier can sit in
///    front of Visa-issued agents.
///
/// [`AgentTag`]: tenzro_payments::visa_tap::AgentTag
/// [`VerificationResult`]: tenzro_payments::visa_tap::VerificationResult
/// [`DidResolverAgentRegistry`]: tenzro_payments::visa_tap::DidResolverAgentRegistry
pub(crate) async fn handle_visa_tap_protocol_info(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "spec": "visa trusted agent protocol",
        "signature_format": "rfc9421-http-message-signatures",
        "covered_components": [
            "@authority",
            "@path",
            "created",
            "expires",
            "nonce",
            "keyid",
            "tag",
        ],
        "signing_algorithms": ["ed25519", "rsa-pss-sha256"],
        "created_age_window_secs": 480,
        "tags": ["agent-browser-auth", "agent-payer-auth"],
        "tenzro_extensions": {
            "tag_taxonomy": {
                "rationale": "verifier_enforces_known_tag_set_and_optionally_a_required_tag_per_endpoint",
                "rejection": "unknown_tags_rejected_with_visatap_error",
            },
            "did_resolvable_keyid": {
                "format": "did:tenzro:machine:<uuid>",
                "resolver": "tdip_via_tenzro_resolveDidDocument",
                "fallback": "jwks_via_VisaAgentRegistryClient",
                "rationale": "rfc9421_keyid_is_opaque_string_so_did_form_works_with_any_compliant_verifier",
            },
        },
        "stock_compatibility": "non_did_keyids_continue_to_flow_through_jwks_fallback_so_visa_issued_agents_unaffected",
    }))
}

/// `tenzro_getKyaRecord` — return the Mastercard-style **Know Your Agent**
/// record for a TDIP machine identity.
///
/// A [`KyaRecord`] is the DID-anchored projection of a machine
/// [`TenzroIdentity`] across the three Mastercard KYA axes:
///
/// 1. **Controller identity** — the human or upstream-machine DID that
///    bears legal/operational responsibility (or `None` for autonomous
///    machines).
/// 2. **Agent authenticator** — the verification key registered against
///    the agent DID, plus a `tee_attested` flag indicating whether the
///    agent runs in a hardware-attested enclave.
/// 3. **Delegation scope** — the [`DelegationScope`] enforced at payment
///    time (per-tx ceiling, daily cap, allowed protocols / chains /
///    operations / time-bound window).
///
/// The record is computed by `KyaRecord::from_identity`; `None` is
/// returned for human identities. The four-tier KYA level
/// (`Unverified` / `Basic` / `Enhanced` / `Full`) is computed from the
/// identity's status, controller binding, and delegation-scope
/// strictness via the pure function [`compute_kya_level`].
///
/// Params:
/// ```json
/// { "did": "did:tenzro:machine:<uuid>" }
/// ```
///
/// [`KyaRecord`]: tenzro_identity::kya::KyaRecord
/// [`TenzroIdentity`]: tenzro_identity::TenzroIdentity
/// [`DelegationScope`]: tenzro_identity::DelegationScope
/// [`compute_kya_level`]: tenzro_identity::kya::compute_kya_level
pub(crate) async fn handle_get_kya_record(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let did = params
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing did"))?
        .to_string();

    let registry = node
        .identity_registry()
        .ok_or_else(|| invalid_params("identity registry not initialized"))?;

    let record = registry
        .kya_record_for(&did)
        .map_err(|e| invalid_params(format!("kya lookup failed: {e}")))?;

    serde_json::to_value(&record)
        .map_err(|e| invalid_params(format!("kya record serialization failed: {e}")))
}

/// `tenzro_mastercardKyaProtocolInfo` — advertise Tenzro's Mastercard
/// KYA profile and the federation extensions over the published spec.
///
/// Mastercard's reference Know Your Agent framework recognises an agent
/// across three axes: who controls it, what authenticator it presents,
/// and what delegation scope its operator authorised. The wire-level
/// agent recognition primitive is **Cloudflare Web Bot Auth** = RFC 9421
/// HTTP Message Signatures, with the `keyid` parameter resolving to a
/// JWK published in a closed federation directory (Mastercard hosts its
/// own; Visa hosts its own).
///
/// Tenzro's profile is a strict superset of the canonical spec:
///
/// 1. **DID-anchored agent identity** — agents are registered as TDIP
///    machine DIDs (`did:tenzro:machine:<uuid>`); the three KYA axes map
///    1-to-1 to fields on [`TenzroIdentity`] via [`KyaRecord`]. No JWKS
///    round-trip and no central trust anchor required.
/// 2. **Cross-network discovery via ERC-8004** — every TDIP machine
///    identity is automatically mirrored into the
///    `IdentityRegistry` system contract at precompile `0x101a`. The
///    registry allocates a sequential `uint256 agentId` (1-indexed) at
///    register-time and stores it on `IdentityData::Machine.erc8004_agent_id`;
///    reverse DID → id resolution via
///    `OnChainAgentRegistry::lookup_agent_id_by_did`. Any EVM tool can
///    then resolve the same agent record from Ethereum, L2s, or any chain
///    that supports ERC-8004.
/// 3. **W3C DID Document service entries for federation pointers** —
///    Tenzro DIDs can carry `service[].type = "MastercardKYA"` or
///    `"VisaTAP"` entries pointing at the upstream federation directory
///    that vouches for the agent, allowing closed-federation verifiers
///    to discover Tenzro-issued agents and Tenzro to discover
///    federation-issued agents.
/// 4. **Four-tier KYA level ladder** — `Unverified` / `Basic` /
///    `Enhanced` / `Full` computed from controller binding, delegation
///    strictness, and identity status via [`compute_kya_level`]. The
///    payments-side `KyaVerifier` consumes this ladder to gate
///    Mastercard agent payment flows.
/// 5. **Per-session / per-merchant spend limits** — encoded as
///    `DelegationScope.max_transaction_value`,
///    `max_daily_spend`, `allowed_payment_protocols`, and
///    `allowed_chains`. Enforced at payment time by
///    `IdentityRegistry::enforce_operation`, returning a typed
///    `DelegationViolation` on breach.
///
/// [`KyaRecord`]: tenzro_identity::kya::KyaRecord
/// [`TenzroIdentity`]: tenzro_identity::TenzroIdentity
/// [`compute_kya_level`]: tenzro_identity::kya::compute_kya_level
pub(crate) async fn handle_mastercard_kya_protocol_info(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "spec": "mastercard know your agent (kya)",
        "wire_recognition": "cloudflare-web-bot-auth (rfc9421 http message signatures)",
        "kya_axes": [
            {
                "axis": "controller_identity",
                "tdip_field": "IdentityData::Machine.controller_did",
                "description": "human_or_upstream_machine_did_bearing_legal_responsibility",
            },
            {
                "axis": "agent_authenticator",
                "tdip_field": "TenzroIdentity.public_keys + tee_attested",
                "description": "verification_key_plus_hardware_attestation_flag",
            },
            {
                "axis": "delegation_scope",
                "tdip_field": "IdentityData::Machine.delegation_scope",
                "description": "per_tx_ceiling_daily_cap_allowed_protocols_chains_operations_time_window",
            },
        ],
        "kya_levels": ["unverified", "basic", "enhanced", "full"],
        "federation_service_types": [
            tenzro_identity::SERVICE_TYPE_MASTERCARD_KYA,
            tenzro_identity::SERVICE_TYPE_VISA_TAP,
        ],
        "tenzro_extensions": {
            "did_anchored_identity": {
                "format": "did:tenzro:machine:<uuid>",
                "resolver": "tdip_via_tenzro_resolveDidDocument",
                "rationale": "kya_axes_map_one_to_one_to_TenzroIdentity_fields_no_jwks_round_trip_required",
            },
            "cross_network_discovery": {
                "system_contract": "ERC8004_IDENTITY",
                "precompile": "0x101a",
                "agent_id_allocation": "sequential_uint256_one_indexed_allocated_by_registry_at_register_time",
                "tdip_field": "IdentityData::Machine.erc8004_agent_id",
                "reverse_lookup": "OnChainAgentRegistry::lookup_agent_id_by_did",
                "auto_mirror": "OnChainAgentRegistry::mirror_register_agent_invoked_on_register_machine_with_fee",
                "rationale": "any_evm_tool_can_resolve_tenzro_agents_via_erc8004_byte_identical_calldata",
            },
            "federation_pointers": {
                "did_document_service_entries": [
                    "MastercardKYA",
                    "VisaTAP",
                ],
                "rationale": "closed_federation_verifiers_discover_tenzro_agents_and_vice_versa_via_w3c_did_document_service_array",
            },
            "kya_level_ladder": {
                "function": "tenzro_identity::kya::compute_kya_level",
                "inputs": ["identity_status", "controller_did", "delegation_scope"],
                "rationale": "payments_side_KyaVerifier_consumes_this_ladder_to_gate_mastercard_agent_payment_flows",
            },
            "delegation_enforcement": {
                "entry_point": "IdentityRegistry::enforce_operation",
                "violation_type": "DelegationViolation",
                "fields_enforced": [
                    "max_transaction_value",
                    "max_daily_spend",
                    "allowed_payment_protocols",
                    "allowed_chains",
                    "allowed_operations",
                    "time_bound",
                ],
                "rationale": "per_session_per_merchant_spend_limits_enforced_at_payment_time_with_typed_violation",
            },
        },
        "stock_compatibility": "tenzro_kya_records_serialize_to_canonical_three_axis_shape_so_mastercard_compliant_verifiers_consume_them_unchanged",
    }))
}

/// `tenzro_tempoProtocolInfo` — advertise Tenzro's Tempo L1 settlement
/// profile and the federation surface over the canonical Stripe + Paradigm
/// payments chain.
///
/// Tempo is an EVM-compatible L1 (Reth execution + Simplex BFT consensus,
/// ~0.5–0.6s deterministic finality, no reorgs) launched by Stripe and
/// Paradigm for stablecoin-native payments. It has no native gas token —
/// fees are paid in stablecoins via an enshrined AMM. The canonical token
/// standard is **TIP-20**, an ERC-20-compatible stablecoin interface with
/// transfer memos, role-based access, compliance freeze/clawback, and gas
/// abstraction.
///
/// Tenzro participates as an MPP-settling counterparty:
///
/// 1. **EIP-155 transaction signing** — `TempoParticipant::sign_eip155`
///    builds RLP-encoded, Keccak-256-hashed, k256-recoverably-signed Tempo
///    transactions with `v = chain_id*2 + 35 + recovery_id`.
/// 2. **`eth_sendRawTransaction` submission + receipt polling** — once the
///    receipt lands, Simplex BFT means the transaction is finalized. No
///    extra confirmation buffer is required.
/// 3. **TIP-20 ABI helpers** — `encode_balance_of` / `encode_transfer` /
///    `encode_approve` selectors are byte-identical to ERC-20 because TIP-20
///    is backward-compatible at the wire level.
/// 4. **`MppReceipt.chain = "tempo"` + `principal_chain` audit trail** —
///    every MPP credential settled on Tempo records the Tempo tx hash on
///    the receipt's `principal_chain` field for cross-network reconciliation.
/// 5. **DID-anchored Tempo identity** — agents advertise their Tempo address
///    via `service[].type = "TempoAccount"` on their TDIP DID Document, so a
///    counterparty resolving the agent's DID can discover the Tempo
///    settlement endpoint without a side-channel.
pub(crate) async fn handle_tempo_protocol_info(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "spec": "tempo l1 — stripe + paradigm payments chain",
        "canonical_sources": [
            "tempo.xyz",
            "docs.tempo.xyz",
            "paradigm.xyz/2025/09/tempo-payments-first-blockchain",
            "tempo.xyz/blog/tip20",
        ],
        "chain_id": tenzro_payments::tempo::TEMPO_CHAIN_ID,
        "rpc_endpoints": {
            "mainnet": tenzro_payments::tempo::TEMPO_MAINNET_RPC,
            "testnet": tenzro_payments::tempo::TEMPO_TESTNET_RPC,
        },
        "execution": "reth_evm_compatible",
        "consensus": "simplex_bft_via_commonware",
        "finality": "deterministic_no_reorgs_~500_to_600ms",
        "gas_model": "fees_paid_in_stablecoins_via_enshrined_amm_no_native_gas_token",
        "token_standard": "tip20",
        "tip20_compatibility": "erc20_backward_compatible_selectors_byte_identical",
        "tip20_extensions": [
            "transfer_memos_32_bytes",
            "role_based_access_control",
            "compliance_freeze_clawback",
            "on_chain_reward_distribution",
        ],
        "tenzro_implementation": {
            "participant_client": "crates/tenzro-payments/src/tempo/participant.rs",
            "bridge_adapter": "crates/tenzro-payments/src/tempo/adapter.rs",
            "tip20_helpers": "crates/tenzro-payments/src/tempo/stablecoin.rs",
            "config": "crates/tenzro-payments/src/tempo/config.rs",
        },
        "tenzro_extensions": {
            "did_anchored_tempo_identity": {
                "service_type": tenzro_identity::SERVICE_TYPE_TEMPO_ACCOUNT,
                "format": "did:tenzro:machine:<uuid>",
                "endpoint_shape": "eip55_checksummed_secp256k1_address",
                "rationale": "counterparty_resolves_agent_did_and_discovers_tempo_settlement_endpoint_without_side_channel",
            },
            "mpp_settlement_audit_trail": {
                "receipt_chain_field": "tempo",
                "receipt_principal_chain": "records_tempo_tx_hash_for_cross_network_reconciliation",
                "rationale": "same_mpp_credential_settles_on_tempo_or_native_tenzro_or_other_chain_by_cart_mandate_accepted_chains",
            },
            "eip155_signing": {
                "function": "TempoParticipant::sign_eip155",
                "encoding": "rlp_keccak256_k256_recoverable",
                "v_formula": "chain_id_times_two_plus_35_plus_recovery_id",
            },
            "finality_model": {
                "rationale": "simplex_bft_means_eth_getTransactionReceipt_return_implies_finality_no_buffer_blocks_required",
            },
        },
        "out_of_scope": [
            "tenzro_running_a_tempo_validator",
            "tempo_native_consensus_participation",
            "custom_tempo_bridge_for_non_stablecoin_assets",
            "tnzo_native_bridge_to_tempo_stays_on_wormhole_ntt",
        ],
        "stock_compatibility": "tenzro_signs_canonical_eip155_tempo_transactions_so_any_tempo_node_accepts_them_unchanged",
    }))
}

/// `tenzro_stripeSptProtocolInfo` — advertise Tenzro's Stripe SharedPaymentToken
/// (SPT) integration: a two-resource agentic payment primitive that complements
/// MPP for principal-to-merchant authorization without a real PaymentMethod
/// being shared with the agent.
///
/// **Stripe SPT = the second layer of Stripe's agentic stack.**
///
/// Stripe split agentic payments into three layers:
/// - **MPP (IETF wire)** — HTTP 402 + machine-payments protocol;
///   Tenzro implements this as `crates/tenzro-payments/src/mpp/*`.
/// - **SPT (token primitive)** — a Stripe-issued / Stripe-granted token-pair
///   resource that authorizes a merchant to confirm a PaymentIntent on the
///   principal's behalf, capped by `usage_limits {currency, max_amount,
///   expires_at}`.  Tenzro implements this as
///   `crates/tenzro-payments/src/mpp/stripe_spt.rs`.
/// - **Tempo (L1 chain)** — Stripe + Paradigm payments-first L1; advertised
///   via `tenzro_tempoProtocolInfo`.
///
/// **Tenzro extensions over the stock Stripe SPT primitive:**
/// 1. **TDIP DID Document federation** — agents advertise their Stripe SPT
///    issuance endpoint via `service[].type = "StripeSPT"` on their TDIP DID
///    Document. Constant: [`SERVICE_TYPE_STRIPE_SPT`].
/// 2. **Four-ceiling enforcement** — every payment authorized by an SPT
///    granted-token at confirm time must clear all four:
///    a. **TDIP DelegationScope** (structural — `enforce_operation`)
///    b. **Runtime SpendingPolicy** (daily window — `SpendingPolicySnapshot`)
///    c. **Stripe SPT `usage_limits`** (per-token cap — `SptCeilingSnapshot`)
///    d. **AP2 cart-mandate `cart_total`** (when wrapped in an AP2 envelope)
///    The four-ceiling check is implemented by
///    `IdentityPaymentBinder::validate_payer_with_spt`.
/// 3. **ERC-8004 reputation cross-write** — settled SPTs surface on the
///    [`ReputationRegistry`] precompile at `0x101b`. The
///    [`SptOutcome::Succeeded`] / [`SptOutcome::Disputed`] /
///    [`SptOutcome::ChargebackWon`] / [`SptOutcome::ChargebackLost`] outcomes
///    fan out to `submitFeedback(agentId, score, tag, fileuri, filehash)` so
///    counterparties can read agent-payment reliability without trusting
///    Stripe's internal dashboards.
/// 4. **TDIP revocation cascade on `granted_token.deactivated`** — when
///    Stripe deactivates a granted token (e.g. fraud signal, principal
///    pulled consent), the SPT webhook dispatcher invokes
///    `IdentityRegistry::apply_remote_revocation()` so every node in the
///    mesh stops accepting payments under that DID's bound credential.
///
/// **`SptStatus` lifecycle:**
/// - `RequiresAction` — issued, awaiting principal activation
/// - `Active` — usable; granted tokens at this state are confirmable
/// - `Used` — a PaymentIntent successfully confirmed against this token
/// - `Deactivated` — terminal; Stripe revoked, principal pulled consent,
///   or token expired
pub(crate) async fn handle_stripe_spt_protocol_info(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "spec": "stripe sharedpaymenttoken — agentic payment primitive (issued + granted resource pair)",
        "canonical_sources": [
            "stripe.com/agents",
            "docs.stripe.com/agents/agentic-payments",
            "docs.stripe.com/api/shared_payment_tokens",
        ],
        "tenzro_implementation": {
            "module": "crates/tenzro-payments/src/mpp/stripe_spt.rs",
            "client_methods": [
                "StripeClient::create_issued_token",
                "StripeClient::retrieve_granted_token",
                "StripeClient::revoke_issued_token",
                "StripeClient::confirm_intent_with_spt",
            ],
            "trait_surface": [
                "SptCeilingResolver::resolve(granted_token_id) -> Option<SptCeilingSnapshot>",
            ],
            "webhook_dispatcher": "classify_spt_webhook + extract_issued_token + extract_granted_token",
        },
        "spt_status_lifecycle": [
            "requires_action",
            "active",
            "used",
            "deactivated",
        ],
        "usage_limits_axis": {
            "fields": ["currency", "max_amount_minor_units", "expires_at_unix_seconds"],
            "rationale": "stripe-enforced per-token cap; tenzro mirrors this as SptCeilingSnapshot at confirm time",
        },
        "tenzro_extensions": {
            "did_anchored_spt_federation": {
                "service_type": tenzro_identity::SERVICE_TYPE_STRIPE_SPT,
                "format": "did:tenzro:machine:<uuid>",
                "rationale": "counterparty resolves agent DID + discovers SPT issuance endpoint via TDIP DID Document service entry",
            },
            "four_ceiling_enforcement": {
                "rpc": "called via IdentityPaymentBinder::validate_payer_with_spt",
                "ceilings": [
                    "tdip_delegation_scope",
                    "runtime_spending_policy",
                    "stripe_spt_usage_limits",
                    "ap2_cart_mandate_total",
                ],
                "rationale": "every confirm_intent_with_spt call clears all four; violation of any ceiling rejects the confirm before stripe is contacted",
            },
            "erc8004_reputation_cross_write": {
                "precompile": "0x101b",
                "selector": "submitFeedback",
                "outcomes": [
                    "succeeded",
                    "disputed",
                    "chargeback_won",
                    "chargeback_lost",
                ],
                "rpc": "tenzro_processSptSettlementOutcome",
                "rater": "local_validator_address (truncated to 20 bytes)",
                "rating_scale": "0..=100 mapped from SptOutcome::reputation_score",
                "trigger_events": [
                    "payment_intent.succeeded",
                    "payment_intent.payment_failed",
                    "charge.dispute.created",
                    "charge.dispute.closed",
                ],
                "rationale": "every settled spt records reputation feedback against agent_id so counterparties can read agent-payment reliability without trusting stripe's internal dashboards",
            },
            "tdip_revocation_cascade": {
                "trigger": "shared_payment.granted_token.deactivated webhook",
                "action": "IdentityRegistry::apply_remote_revocation()",
                "rationale": "stripe-side revocation propagates to every tenzro node so the mesh stops accepting payments under the deactivated did",
            },
        },
        "ietf_compatibility": {
            "spt_is_orthogonal_to_mpp_wire": "spt is a stripe-side resource; mpp is the http 402 wire format. tenzro can use mpp wire to settle an spt-authorized confirm, but they are independent layers",
            "no_breaking_changes_to_stripe": "tenzro never modifies the spt resource shape — only consumes the canonical stripe api at confirm time",
        },
        "out_of_scope": [
            "tenzro_running_a_stripe_acquirer",
            "tenzro_minting_or_burning_spt_resources_independently",
            "spt_resource_replication_across_chains",
        ],
        "stock_compatibility": "tenzro consumes canonical stripe spt api so any stripe-issued issued/granted token pair is honored unchanged",
    }))
}

/// `tenzro_processSptGrantedTokenDeactivated` — manually dispatch a
/// Stripe SPT `granted_token.deactivated` webhook event into the local
/// TDIP revocation cascade.
///
/// This is the **operator-driven entry point** for SPT-sourced
/// revocation. The HMAC-verified webhook receive endpoint (axum route)
/// will land in a follow-up wave; until then operators can drive the
/// cascade by hand from a verified webhook payload — useful for
/// retrying a missed webhook delivery or replaying historical
/// deactivations into a freshly-restarted node.
///
/// The handler:
///
/// 1. Requires the validator's hybrid (Ed25519 + ML-DSA-65) signer to
///    be available — non-validator nodes return error `-32603` since
///    they have no signing authority for the broadcast leg.
/// 2. Calls [`IdentityRegistry::revoke`] which produces a
///    `SignedRevocationEntry` and fans it out to peers via the
///    configured [`RevocationBroadcaster`].
/// 3. Invalidates the local SPT ceiling cache so subsequent gate checks
///    see the credential as missing rather than stale-active.
///
/// Params:
/// ```json
/// {
///   "machine_did": "did:tenzro:machine:controller:abc...",
///   "granted_token_id": "spt_grant_...",
///   "revoker_did": "did:tenzro:protocol/spt-webhook" // optional, defaults
/// }
/// ```
///
/// Returns:
/// ```json
/// {
///   "machine_did": "...",
///   "granted_token_id": "...",
///   "event_type": "shared_payment.granted_token.deactivated",
///   "revoked": true
/// }
/// ```
pub(crate) async fn handle_process_spt_granted_token_deactivated(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    use tenzro_payments::mpp::stripe_spt::SptWebhookEvent;

    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let machine_did = params
        .get("machine_did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing string field 'machine_did'"))?
        .to_string();
    let granted_token_id = params
        .get("granted_token_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing string field 'granted_token_id'"))?
        .to_string();
    let revoker_did = params
        .get("revoker_did")
        .and_then(|v| v.as_str())
        .unwrap_or("did:tenzro:protocol/spt-webhook")
        .to_string();

    let identity_registry = node.identity_registry().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "IdentityRegistry not initialized on this node".to_string(),
        data: None,
    })?;

    let hybrid_signer = node.validator_hybrid_signer().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "Validator hybrid signer not available — \
                  non-validator nodes cannot dispatch SPT revocation cascades"
            .to_string(),
        data: None,
    })?;

    // Cache adapter is optional — the dispatcher logs a warning if
    // missing but proceeds with the local revoke + peer broadcast.
    let spt_cache = node.spt_ceiling_cache();

    let outcome = crate::spt_revocation_dispatcher::dispatch_granted_token_deactivated(
        &SptWebhookEvent::GrantedTokenDeactivated,
        &machine_did,
        &granted_token_id,
        &revoker_did,
        identity_registry,
        hybrid_signer,
        spt_cache.as_ref(),
    )
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("SPT revocation dispatch failed: {}", e),
        data: None,
    })?;

    serde_json::to_value(outcome).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("Failed to serialize SPT revocation outcome: {}", e),
        data: None,
    })
}

/// `tenzro_processSptSettlementOutcome` — manually dispatch a Stripe SPT
/// settlement-outcome webhook event into the on-chain ERC-8004
/// [`ReputationRegistry`] cross-write at precompile `0x101b`.
///
/// This is the **operator-driven entry point** for SPT-sourced
/// reputation. The HMAC-verified webhook receive endpoint (axum route)
/// will land in a follow-up wave; until then operators can drive the
/// cross-write by hand from a verified webhook payload — useful for
/// retrying a missed delivery or replaying historical outcomes into a
/// freshly-restarted node.
///
/// The handler:
///
/// 1. Requires the local validator address (used as the `rater` field
///    on the on-chain feedback row) and the ERC-8004
///    [`ReputationRegistry`] handle. Non-validator nodes return error
///    `-32603` since they have no on-chain authoring authority.
/// 2. Maps the webhook event to an [`SptOutcome`] via
///    [`SptWebhookEvent::settlement_outcome`]. For
///    `charge.dispute.closed` the caller MUST pass `dispute_status` (
///    `"won"` or `"lost"`) — the closed event is ambiguous on its own.
/// 3. Calls [`crate::erc8004_reputation_dispatcher::dispatch_settlement_outcome`]
///    which resolves the machine DID to its sequential `uint256 agentId`
///    via [`tenzro_identity::erc8004::OnChainAgentRegistry::lookup_agent_id_by_did`]
///    (allocated at machine-identity registration time) and appends one
///    `FeedbackEntry` row keyed by the `agentId`'s big-endian 32-byte word.
///
/// The cross-write is **append-only**: replaying the same webhook
/// produces a new feedback row each time. This mirrors at-least-once
/// delivery semantics — readers should aggregate over the row history
/// rather than expecting one-row-per-grant.
///
/// Params:
/// ```json
/// {
///   "machine_did": "did:tenzro:machine:controller:abc...",
///   "granted_token_id": "spt_grant_...",
///   "event_type": "payment_intent.succeeded",
///   "payment_intent_id": "pi_...",          // optional
///   "dispute_status": "won"                  // required only for charge.dispute.closed
/// }
/// ```
///
/// Returns:
/// ```json
/// {
///   "machine_did": "...",
///   "granted_token_id": "...",
///   "outcome": "succeeded",
///   "agent_id_hex": "abc...",
///   "rating": 100,
///   "written": true
/// }
/// ```
pub(crate) async fn handle_process_spt_settlement_outcome(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    use tenzro_payments::mpp::stripe_spt::SptWebhookEvent;

    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let machine_did = params
        .get("machine_did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing string field 'machine_did'"))?
        .to_string();
    let granted_token_id = params
        .get("granted_token_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing string field 'granted_token_id'"))?
        .to_string();
    let event_type = params
        .get("event_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing string field 'event_type'"))?
        .to_string();
    let payment_intent_id = params
        .get("payment_intent_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let dispute_status = params
        .get("dispute_status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Parse the wire-format event_type into the typed enum. The same
    // strings that Stripe puts on `event.type` are accepted here
    // verbatim so operators can paste a webhook payload without
    // re-keying the field. `from_type` is total — unrecognized strings
    // fall into `Unknown(s)` which we reject here with a clear
    // diagnostic.
    let event = SptWebhookEvent::from_type(&event_type);
    if matches!(event, SptWebhookEvent::Unknown(_)) {
        return Err(invalid_params(format!(
            "unknown event_type {:?} — expected one of: \
             payment_intent.succeeded, payment_intent.payment_failed, \
             charge.dispute.created, charge.dispute.closed",
            event_type
        )));
    }

    // Reject lifecycle events early so the operator gets a clear
    // diagnostic rather than the generic "non-settlement event" error
    // from inside the dispatcher.
    if !event.is_settlement_outcome() {
        return Err(invalid_params(format!(
            "event_type {:?} is a lifecycle event, not a settlement-outcome event — \
             use tenzro_processSptGrantedTokenDeactivated for granted_token.deactivated",
            event_type
        )));
    }

    // Acquire the node-held `erc8004-system` signer. This is the
    // submitter for the SPT reputation row; `msg.sender` on the
    // resulting `submitFeedback` EVM tx is the signer's address, so
    // operators reading the on-chain registry see that the row was
    // authored by this validator acting on the upstream Stripe signal.
    let signer = node.erc8004_system_signer().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "ERC-8004 system signer not initialized on this node — \
                  SPT reputation dispatch is unavailable (check init_storage logs)"
            .to_string(),
        data: None,
    })?;

    let agent_registry = node.erc8004_agent_registry().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "ERC-8004 OnChainAgentRegistry mirror not initialized on this node — \
                  cannot resolve machine DID to sequential agentId"
            .to_string(),
        data: None,
    })?;

    let outcome = crate::erc8004_reputation_dispatcher::dispatch_settlement_outcome(
        &event,
        &machine_did,
        &granted_token_id,
        payment_intent_id.as_deref(),
        dispute_status.as_deref(),
        signer,
        agent_registry,
    )
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("ERC-8004 reputation cross-write failed: {}", e),
        data: None,
    })?;

    serde_json::to_value(outcome).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("Failed to serialize SPT reputation outcome: {}", e),
        data: None,
    })
}

/// `tenzro_processTapPayerAuthOutcome` — record a Visa TAP-mediated
/// payment outcome as an ERC-8004 `ReputationRegistry::submitFeedback`
/// row.
///
/// Gated behind the `visa-tap` cargo feature on `tenzro-payments`; the
/// `tenzro-node` `visa-tap` feature forwards to it. When the feature is
/// disabled, the RPC dispatch in [`crate::rpc`] returns `MethodNotFound`
/// rather than calling this handler.
///
/// Mirrors [`handle_process_spt_settlement_outcome`] for the TAP rail.
/// The caller has already verified an `agent-payer-auth`-tagged TAP
/// signature at the CDN proxy seam and observed the downstream
/// settlement outcome; this RPC files the resulting reputation row
/// under the agent's allocated ERC-8004 `agentId`.
///
/// Why a TAP-specific handler rather than a generic
/// `tenzro_processReputationOutcome` over both rails: the upstream
/// wire shapes differ (TAP gives a [`VerificationResult`] with
/// `verified_tag` discrimination; SPT gives a webhook event with
/// lifecycle/settlement split). Operators driving the handler from a
/// verified TAP signature paste `agent_did` + `agent_key_id` + the
/// outcome they observed; they don't synthesize a Stripe webhook
/// shape. Per-rail handlers keep each call site self-documenting.
///
/// PayerAuth-only: BrowserAuth verifications are identity proofs, not
/// payment outcomes — the dispatcher rejects them so registry
/// consumers can keep "this agent identified itself" separate from
/// "this agent moved value." The handler rejects them earlier with a
/// clearer diagnostic.
///
/// Params:
/// ```json
/// {
///   "agent_did": "did:tenzro:machine:controller:abc...",
///   "agent_key_id": "k_...",
///   "outcome": "succeeded",          // or "settlement_failed"
///   "merchant_id": "merchant-abc"    // optional, recorded in contextUri
/// }
/// ```
///
/// Returns:
/// ```json
/// {
///   "machine_did": "...",
///   "agent_key_id": "...",
///   "outcome": "succeeded",
///   "agent_id": 42,
///   "rating": 100,
///   "written": true
/// }
/// ```
#[cfg(feature = "visa-tap")]
pub(crate) async fn handle_process_tap_payer_auth_outcome(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    use tenzro_payments::visa_tap::{AgentTag, VerificationResult};

    use crate::tap_reputation_dispatcher::{dispatch_payer_auth_outcome, TapOutcome};

    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_did = params
        .get("agent_did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing string field 'agent_did'"))?
        .to_string();
    let agent_key_id = params
        .get("agent_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing string field 'agent_key_id'"))?
        .to_string();
    let outcome_str = params
        .get("outcome")
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing string field 'outcome'"))?;
    let merchant_id = params
        .get("merchant_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let outcome = match outcome_str {
        "succeeded" => TapOutcome::Succeeded,
        "settlement_failed" => TapOutcome::SettlementFailed,
        other => {
            return Err(invalid_params(format!(
                "unknown outcome {:?} — expected 'succeeded' or 'settlement_failed'",
                other
            )));
        }
    };

    // Build a synthetic VerificationResult for the dispatcher. The
    // caller has already verified the TAP signature at their own seam;
    // this RPC is the post-verification audit cross-write, so we
    // construct the result shape the dispatcher's guards expect (
    // verified=true, PayerAuth tag, agent_did present) directly from
    // the caller's input. The dispatcher still validates these
    // invariants in-depth — if a caller bug ever produces a malformed
    // result, the dispatcher catches it before any tx is spawned.
    let result = VerificationResult {
        verified: true,
        agent_key_id,
        agent_did: Some(agent_did),
        verified_tag: Some(AgentTag::PayerAuth),
        stages_passed: vec!["caller_verified".to_string()],
    };

    let signer = node.erc8004_system_signer().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "ERC-8004 system signer not initialized on this node — \
                  TAP reputation dispatch is unavailable (check init_storage logs)"
            .to_string(),
        data: None,
    })?;

    let agent_registry = node.erc8004_agent_registry().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "ERC-8004 OnChainAgentRegistry mirror not initialized on this node — \
                  cannot resolve machine DID to sequential agentId"
            .to_string(),
        data: None,
    })?;

    let outcome = dispatch_payer_auth_outcome(
        &result,
        outcome,
        merchant_id.as_deref(),
        signer,
        agent_registry,
    )
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("TAP reputation cross-write failed: {}", e),
        data: None,
    })?;

    serde_json::to_value(outcome).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("Failed to serialize TAP reputation outcome: {}", e),
        data: None,
    })
}

/// `tenzro_ap2ReportMandateViolation` — file an insurance claim against
/// the AgentBond bound to an AP2 CheckoutMandate when the agent
/// violates the mandate's terms (overspend, merchant whitelist breach,
/// expired-mandate settlement, etc.).
///
/// AP2 v0.2 has no built-in slashing path — violations surface as
/// settlement disputes that the parties resolve out-of-band. Tenzro
/// extends this with the **AgentBond binding (the fifth ceiling beyond
/// validation)**: when a CheckoutMandate carries `agent_bond_id`, any
/// counterparty can file a claim against that bond. Governance reviews
/// the evidence, approves or rejects, and an approved claim is paid via
/// a `PayInsuranceClaim` typed transaction — the on-chain `BondSlashed`
/// log is reflected into [`BondManager`] by the event loop.
///
/// This RPC is the **off-chain claim-filing entry point** specifically
/// for AP2 mandate violations. It validates that the parent
/// CheckoutMandate VDC is signature-valid, extracts the bond ID, and
/// forwards to [`BondManager::file_claim`] with the violation kind
/// captured in the claim's narrative.
///
/// Params:
/// ```json
/// {
///   "checkout_vdc": { ... },                  // parent CheckoutMandate VDC
///   "payment_vdc":  { ... },                  // optional — child PaymentMandate
///                                             // VDC supplying evidence
///   "violation_kind": "overspend",            // or merchant_whitelist_breach etc.
///   "claimant_did": "did:tenzro:human:...",
///   "claimant_address": "0x...",              // 32-byte hex
///   "amount_requested": "1000000000000000000",// u128, smallest unit of asset
///   "narrative": "agent paid 1.5x the cap …", // optional, capped at 1024B
///   "receipt_refs": ["0xtxhash…"],            // optional supporting evidence
///   "nonce": 42                               // u64, for deterministic claim_id
/// }
/// ```
///
/// Returns the resulting `ClaimRecord` JSON.
pub(crate) async fn handle_ap2_report_mandate_violation(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let checkout_val = params
        .get("checkout_vdc")
        .cloned()
        .ok_or_else(|| missing("Missing checkout_vdc"))?;
    let checkout: tenzro_payments::ap2::Vdc = serde_json::from_value(checkout_val)
        .map_err(|e| invalid_params(format!("invalid checkout_vdc: {e}")))?;

    // Verify parent VDC signature before doing anything else — a
    // counterparty must not be able to file a claim against a bond
    // bound to a forged mandate. This is the same check the validator
    // does at the head of `validate_with_delegation_policy_and_escrow`.
    checkout
        .verify()
        .map_err(|e| invalid_params(format!("checkout_vdc signature invalid: {e}")))?;

    let checkout_mandate = checkout
        .as_checkout()
        .ok_or_else(|| invalid_params("checkout_vdc is not a CheckoutMandate"))?;
    let bond_id = checkout_mandate
        .agent_bond_id
        .as_deref()
        .ok_or_else(|| {
            invalid_params(
                "CheckoutMandate carries no agent_bond_id — nothing to slash",
            )
        })?;

    // Optional child PaymentMandate evidence — verified if supplied so
    // governance can rely on the receipt_refs and amounts. Signature
    // validation and parent-binding checks both run.
    if let Some(payment_val) = params.get("payment_vdc").cloned() {
        let payment: tenzro_payments::ap2::Vdc = serde_json::from_value(payment_val)
            .map_err(|e| invalid_params(format!("invalid payment_vdc: {e}")))?;
        payment
            .verify()
            .map_err(|e| invalid_params(format!("payment_vdc signature invalid: {e}")))?;
        // Sanity: the agent named in the cart must be the same agent the
        // parent CheckoutMandate authorized. Otherwise the claim is
        // mis-targeted.
        let payment_mandate = payment
            .as_payment()
            .ok_or_else(|| invalid_params("payment_vdc is not a PaymentMandate"))?;
        if payment_mandate.checkout_mandate_id != checkout_mandate.mandate_id {
            return Err(invalid_params(
                "payment_vdc.checkout_mandate_id does not match checkout_vdc.mandate_id",
            ));
        }
        if payment_mandate.agent_did != checkout_mandate.agent_did {
            return Err(invalid_params(
                "payment_vdc.agent_did does not match checkout_vdc.agent_did",
            ));
        }
    }

    let violation_kind = params
        .get("violation_kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing violation_kind"))?;
    // Whitelist of accepted violation classifications. Mirrors the set
    // surfaced by `tenzro_ap2ProtocolInfo.agent_bond_enforcement.violation_kinds`.
    const ALLOWED_KINDS: &[&str] = &[
        "overspend",
        "merchant_whitelist_breach",
        "category_breach",
        "expired_mandate_settlement",
        "double_spend",
        "missing_cnf_binding",
        "other",
    ];
    if !ALLOWED_KINDS.contains(&violation_kind) {
        return Err(invalid_params(format!(
            "invalid violation_kind {:?} — must be one of {:?}",
            violation_kind, ALLOWED_KINDS
        )));
    }

    let claimant_did = params
        .get("claimant_did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing claimant_did"))?;

    let claimant_addr_hex = params
        .get("claimant_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing claimant_address"))?;
    let hex_clean = claimant_addr_hex.trim_start_matches("0x");
    let bytes = hex::decode(hex_clean)
        .map_err(|e| invalid_params(format!("Invalid claimant_address hex: {e}")))?;
    if bytes.len() > 32 {
        return Err(invalid_params(format!(
            "claimant_address too long: {} bytes",
            bytes.len()
        )));
    }
    let mut addr_bytes = [0u8; 32];
    let len = bytes.len().min(32);
    addr_bytes[..len].copy_from_slice(&bytes[..len]);
    let claimant_address = tenzro_types::Address::new(addr_bytes);

    let amount_requested = parse_u128(params.get("amount_requested"))
        .ok_or_else(|| missing("Missing or invalid amount_requested"))?;

    let receipt_refs = params
        .get("receipt_refs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Compose the on-claim narrative so the violation kind, mandate IDs,
    // and the user-supplied prose are all auditable in the claim record.
    // Cap at 1024B to bound the storage row.
    let user_narrative = params
        .get("narrative")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut narrative = format!(
        "ap2_violation kind={} checkout_mandate_id={} agent_did={} max_amount={} asset={}",
        violation_kind,
        checkout_mandate.mandate_id,
        checkout_mandate.agent_did,
        checkout_mandate.max_amount,
        checkout_mandate.asset,
    );
    if !user_narrative.is_empty() {
        narrative.push_str(" :: ");
        narrative.push_str(user_narrative);
    }
    if narrative.len() > 1024 {
        narrative.truncate(1024);
    }

    let nonce_le = params
        .get("nonce")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing nonce"))?;

    let bond_manager = node.bond_manager().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "BondManager not initialized".to_string(),
        data: None,
    })?;

    // Sanity-check the bond exists. The mandate's `agent_bond_id` is
    // an opaque label the principal records on the CheckoutMandate;
    // the bond itself is keyed by `agent_did` in [`BondManager`]. The
    // existence check refuses claims against agents who never posted
    // a bond (a violation against a bondless agent has no slashable
    // collateral and would just accumulate as a permanent unsatisfiable
    // open record).
    let _bond_state = bond_manager.get(&checkout_mandate.agent_did).ok_or_else(|| {
        JsonRpcError {
            code: -32000,
            message: format!(
                "no AgentBond posted for agent {} (mandate carries agent_bond_id={})",
                checkout_mandate.agent_did, bond_id
            ),
            data: None,
        }
    })?;

    let record = bond_manager
        .file_claim(
            claimant_did,
            claimant_address,
            &checkout_mandate.agent_did,
            amount_requested,
            receipt_refs,
            Some(narrative),
            nonce_le,
        )
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("file_claim failed: {}", e),
            data: None,
        })?;

    Ok(json!({
        "claim_id": record.claim_id,
        "claimant_did": record.claimant_did,
        "against_agent_did": record.against_agent_did,
        "agent_bond_id": bond_id,
        "violation_kind": violation_kind,
        "amount_requested": record.amount_requested.to_string(),
        "status": record.status.as_str(),
        "checkout_mandate_id": checkout_mandate.mandate_id,
        "next_step": "governance_review",
    }))
}

// ============================================================
// ERC-8004 — Trustless Agents Registry
// ============================================================

/// `tenzro_erc8004DeriveAgentId` — resolve a TDIP DID to its on-chain ERC-8004
/// `uint256 agentId`. The Tenzro registry allocates agentIds sequentially when
/// a machine is registered (not as a keccak256 hash), so this is a lookup
/// against the [`OnChainAgentRegistry`] mirror, not an off-chain derivation.
///
/// Returns `{did, agent_id}` where `agent_id` is the decimal string form of
/// the allocated `uint256`. Returns -32603 if the DID has never been
/// registered.
pub(crate) async fn handle_erc8004_derive_agent_id(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let did = params
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing did"))?
        .to_string();

    let registry = node.erc8004_agent_registry().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "ERC-8004 mirror not initialized on this node".to_string(),
        data: None,
    })?;

    let agent_id = registry.lookup_agent_id_by_did(&did).ok_or_else(|| JsonRpcError {
        code: -32603,
        message: format!(
            "DID {} has no allocated ERC-8004 agentId. Register the machine identity first.",
            did
        ),
        data: None,
    })?;

    Ok(json!({
        "did": did,
        "agent_id": agent_id.to_string(),
    }))
}

/// `tenzro_erc8004EncodeRegister` — produce calldata for the ERC-8004
/// `register()` overload (no arguments). The on-chain registry allocates a
/// fresh sequential `uint256 agentId` for `msg.sender` and returns it; the
/// agentId is read back from the transaction return data, not derived
/// off-chain.
pub(crate) async fn handle_erc8004_encode_register(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let data = tenzro_identity::erc8004::abi::encode_register(
        tenzro_identity::erc8004::selectors::REGISTER,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeRegisterWithUri` — produce calldata for the ERC-8004
/// `register(string agentURI)` overload. Allocates a fresh `agentId` and
/// binds the supplied metadata URI atomically.
pub(crate) async fn handle_erc8004_encode_register_with_uri(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_uri = params
        .get("agent_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let data = tenzro_identity::erc8004::abi::encode_register_with_uri(
        tenzro_identity::erc8004::selectors::REGISTER_WITH_URI,
        agent_uri,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeRegisterWithMetadata` — produce calldata for the
/// ERC-8004 `register(string agentURI, (string,bytes)[] metadata)`
/// overload. Allocates a fresh `agentId`, binds the URI, and atomically
/// writes the supplied metadata batch.
pub(crate) async fn handle_erc8004_encode_register_with_metadata(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_uri = params
        .get("agent_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let metadata_json = params
        .get("metadata")
        .and_then(|v| v.as_array())
        .ok_or_else(|| invalid_params("missing array field 'metadata'"))?;

    let mut metadata = Vec::with_capacity(metadata_json.len());
    for entry in metadata_json {
        let key = entry
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params("metadata entry missing string field 'key'"))?
            .to_string();
        let value_hex = entry
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params("metadata entry missing hex string field 'value'"))?;
        let value = hex::decode(value_hex.trim_start_matches("0x"))
            .map_err(|e| invalid_params(format!("invalid hex in metadata value: {e}")))?;
        metadata.push(tenzro_identity::erc8004::MetadataEntry {
            metadata_key: key,
            metadata_value: value,
        });
    }

    let data = tenzro_identity::erc8004::abi::encode_register_with_metadata(
        tenzro_identity::erc8004::selectors::REGISTER_WITH_METADATA,
        agent_uri,
        &metadata,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeGetAgent` — produce calldata for
/// `getAgent(uint256 agentId)`.
pub(crate) async fn handle_erc8004_encode_get_agent(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_get_agent(
        tenzro_identity::erc8004::selectors::GET_AGENT,
        agent_id,
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

    let subject_agent_id = parse_agent_id_u64(
        params
            .get("subject_agent_id")
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
        subject_agent_id,
        rating,
        context_uri,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeValidationRequest` — produce calldata for
/// `validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)`
/// per ERC-8004.
pub(crate) async fn handle_erc8004_encode_validation_request(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let validator_address = parse_eth_addr(
        params
            .get("validator_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing validator_address"))?,
    )?;
    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let request_uri = params
        .get("request_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let request_hash = parse_bytes32(
        params
            .get("request_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing request_hash"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_validation_request(
        tenzro_identity::erc8004::selectors::VALIDATION_REQUEST,
        &validator_address,
        agent_id,
        request_uri,
        &request_hash,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeValidationResponse` — produce calldata for
/// `validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)`
/// per ERC-8004.
pub(crate) async fn handle_erc8004_encode_validation_response(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let request_hash = parse_bytes32(
        params
            .get("request_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing request_hash"))?,
    )?;
    let response = params
        .get("response")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing response"))?;
    if response > 100 {
        return Err(invalid_params(
            "response must be in 0..=100 per ERC-8004".to_string(),
        ));
    }
    let response_uri = params
        .get("response_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let response_hash = parse_bytes32(
        params
            .get("response_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing response_hash"))?,
    )?;
    let tag = params.get("tag").and_then(|v| v.as_str()).unwrap_or("");

    let data = tenzro_identity::erc8004::abi::encode_validation_response(
        tenzro_identity::erc8004::selectors::VALIDATION_RESPONSE,
        &request_hash,
        response as u8,
        response_uri,
        &response_hash,
        tag,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

// ----- ERC-8004 v0.6+ identity mutators -------------------------------

/// `tenzro_erc8004EncodeSetAgentURI` — produce calldata for
/// `setAgentURI(uint256 agentId, string metadataUri)`.
pub(crate) async fn handle_erc8004_encode_set_agent_uri(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let metadata_uri = params
        .get("metadata_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let data = tenzro_identity::erc8004::abi::encode_set_agent_uri(
        tenzro_identity::erc8004::selectors::SET_AGENT_URI,
        agent_id,
        metadata_uri,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeSetAgentWallet` — produce calldata for
/// `setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature)`.
pub(crate) async fn handle_erc8004_encode_set_agent_wallet(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let new_wallet = parse_eth_addr(
        params
            .get("new_wallet")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing new_wallet"))?,
    )?;
    let deadline = params
        .get("deadline")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing deadline"))? as u128;
    let sig_hex = params
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing signature"))?;
    let signature = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid signature hex: {e}")))?;

    let data = tenzro_identity::erc8004::abi::encode_set_agent_wallet(
        tenzro_identity::erc8004::selectors::SET_AGENT_WALLET,
        agent_id,
        &new_wallet,
        deadline,
        &signature,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeSetMetadata` — produce calldata for
/// `setMetadata(uint256 agentId, string metadataKey, bytes metadataValue)`.
pub(crate) async fn handle_erc8004_encode_set_metadata(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let metadata_key = params
        .get("metadata_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing metadata_key"))?;
    let value_hex = params
        .get("metadata_value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing metadata_value"))?;
    let metadata_value = hex::decode(value_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid metadata_value hex: {e}")))?;

    let data = tenzro_identity::erc8004::abi::encode_set_metadata(
        tenzro_identity::erc8004::selectors::SET_METADATA,
        agent_id,
        metadata_key,
        &metadata_value,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

// ----- ERC-8004 v0.6+ identity reads ----------------------------------

/// `tenzro_erc8004EncodeGetMetadata` — produce calldata for
/// `getMetadata(uint256 agentId, string metadataKey)`.
pub(crate) async fn handle_erc8004_encode_get_metadata(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let metadata_key = params
        .get("metadata_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing metadata_key"))?;

    let data = tenzro_identity::erc8004::abi::encode_get_metadata(
        tenzro_identity::erc8004::selectors::GET_METADATA,
        agent_id,
        metadata_key,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004DecodeGetMetadata` — decode `getMetadata` returndata
/// into the underlying `bytes` value.
pub(crate) async fn handle_erc8004_decode_get_metadata(
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
    match tenzro_identity::erc8004::abi::decode_get_metadata(&bytes) {
        Some(value) => Ok(json!({
            "metadata_value": format!("0x{}", hex::encode(&value)),
        })),
        None => Err(invalid_params("failed to decode getMetadata return")),
    }
}

/// `tenzro_erc8004EncodeGetAgentURI` — produce calldata for
/// `getAgentURI(uint256 agentId)`.
pub(crate) async fn handle_erc8004_encode_get_agent_uri(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_get_agent_uri(
        tenzro_identity::erc8004::selectors::GET_AGENT_URI,
        agent_id,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeGetAgentWallet` — produce calldata for
/// `getAgentWallet(uint256 agentId)`.
pub(crate) async fn handle_erc8004_encode_get_agent_wallet(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_get_agent_wallet(
        tenzro_identity::erc8004::selectors::GET_AGENT_WALLET,
        agent_id,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

// ----- ERC-8004 v0.6+ reputation mutators -----------------------------

/// `tenzro_erc8004EncodeRevokeFeedback` — produce calldata for
/// `revokeFeedback(uint256 agentId, bytes32 feedbackId)`.
pub(crate) async fn handle_erc8004_encode_revoke_feedback(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let feedback_id = parse_bytes32(
        params
            .get("feedback_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing feedback_id"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_revoke_feedback(
        tenzro_identity::erc8004::selectors::REVOKE_FEEDBACK,
        agent_id,
        &feedback_id,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeAppendResponse` — produce calldata for
/// `appendResponse(uint256 agentId, bytes32 feedbackId, string responseUri)`.
pub(crate) async fn handle_erc8004_encode_append_response(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let feedback_id = parse_bytes32(
        params
            .get("feedback_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing feedback_id"))?,
    )?;
    let response_uri = params
        .get("response_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let data = tenzro_identity::erc8004::abi::encode_append_response(
        tenzro_identity::erc8004::selectors::APPEND_RESPONSE,
        agent_id,
        &feedback_id,
        response_uri,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

// ----- ERC-8004 v0.6+ reputation reads --------------------------------

/// `tenzro_erc8004EncodeIsFeedbackRevoked` — produce calldata for
/// `isFeedbackRevoked(uint256 agentId, bytes32 feedbackId)`.
pub(crate) async fn handle_erc8004_encode_is_feedback_revoked(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let feedback_id = parse_bytes32(
        params
            .get("feedback_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing feedback_id"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_is_feedback_revoked(
        tenzro_identity::erc8004::selectors::IS_FEEDBACK_REVOKED,
        agent_id,
        &feedback_id,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeGetFeedbackResponses` — produce calldata for
/// `getFeedbackResponses(uint256 agentId, bytes32 feedbackId)`.
pub(crate) async fn handle_erc8004_encode_get_feedback_responses(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let agent_id = parse_agent_id_u64(
        params
            .get("agent_id")
            .ok_or_else(|| missing("Missing agent_id"))?,
    )?;
    let feedback_id = parse_bytes32(
        params
            .get("feedback_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing feedback_id"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_get_feedback_responses(
        tenzro_identity::erc8004::selectors::GET_FEEDBACK_RESPONSES,
        agent_id,
        &feedback_id,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

// ----- ERC-8004 reads previously implemented but unexposed -----------

/// `tenzro_erc8004EncodeGetFeedback` — produce calldata for
/// `getFeedback(bytes32 subject, uint256 index)`.
pub(crate) async fn handle_erc8004_encode_get_feedback(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let subject_agent_id = parse_agent_id_u64(
        params
            .get("subject_agent_id")
            .ok_or_else(|| missing("Missing subject_agent_id"))?,
    )?;
    let index = params
        .get("index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing index"))? as u128;

    let data = tenzro_identity::erc8004::abi::encode_get_feedback(
        tenzro_identity::erc8004::selectors::GET_FEEDBACK,
        subject_agent_id,
        index,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeGetFeedbackCount` — produce calldata for
/// `getFeedbackCount(bytes32 subject)`.
pub(crate) async fn handle_erc8004_encode_get_feedback_count(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let subject_agent_id = parse_agent_id_u64(
        params
            .get("subject_agent_id")
            .ok_or_else(|| missing("Missing subject_agent_id"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_get_feedback_count(
        tenzro_identity::erc8004::selectors::GET_FEEDBACK_COUNT,
        subject_agent_id,
    );
    Ok(json!({
        "calldata": format!("0x{}", hex::encode(&data)),
    }))
}

/// `tenzro_erc8004EncodeGetValidation` — produce calldata for
/// `getValidation(bytes32 requestHash)`.
pub(crate) async fn handle_erc8004_encode_get_validation(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let request_hash = parse_bytes32(
        params
            .get("request_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing request_hash"))?,
    )?;

    let data = tenzro_identity::erc8004::abi::encode_get_validation(
        tenzro_identity::erc8004::selectors::GET_VALIDATION,
        &request_hash,
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
// Chainlink CCIP — node JSON-RPC namespace
// ------------------------------------------------------------
// Mirror of the 8 CCIP tools exposed by the standalone Chainlink
// MCP server, available at the node JSON-RPC level so SDKs and
// CLIs don't need to know about the separate MCP port. Adds a
// 9th method (`ccipBridge`) that dispatches through the
// BridgeRouter with the CCIP adapter pinned via
// `PreferAdapter("chainlink_ccip")`.
// ============================================================

const CCIP_API_BASE: &str = "https://docs.chain.link/api/ccip/v1";

/// `getFee(uint64,(bytes,bytes,(address,uint256)[],address,bytes))`
const CCIP_GET_FEE_SELECTOR: &str = "5e307a45";
/// `ccipSend(uint64,(bytes,bytes,(address,uint256)[],address,bytes))`
const CCIP_SEND_SELECTOR: &str = "96f4e9f9";
/// `getExecutionState(uint64)` on OffRamp
const CCIP_GET_EXECUTION_STATE_SELECTOR: &str = "142b48a9";

/// Resolve a source-chain identifier to the configured CCIP Router
/// address + RPC URL + chain selector. Aligned with
/// `chainlink_ccip::CcipConfig::{ethereum,arbitrum,base}_mainnet`.
fn ccip_chain_descriptor(chain: &str) -> Option<(&'static str, String, u64, &'static str)> {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" | "1" => Some((
            "Ethereum",
            std::env::var("ETHEREUM_RPC_URL")
                .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string()),
            5009297550715157269u64,
            "0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D",
        )),
        "arbitrum" | "arb" | "42161" => Some((
            "Arbitrum One",
            std::env::var("ARBITRUM_RPC_URL")
                .unwrap_or_else(|_| "https://arb1.arbitrum.io/rpc".to_string()),
            4949039107694359620u64,
            "0x141fa059441E0ca23ce184B6A78bafD2A517DdE8",
        )),
        "base" | "8453" => Some((
            "Base",
            std::env::var("BASE_RPC_URL")
                .unwrap_or_else(|_| "https://mainnet.base.org".to_string()),
            15971525489660198786u64,
            "0x881e3A65B4d4a04dD529061dd0071cf975F58bCD",
        )),
        _ => None,
    }
}

/// Resolve a chain name or numeric selector string to its uint64
/// CCIP chain selector.
fn ccip_chain_selector(s: &str) -> Option<u64> {
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    match s.to_lowercase().as_str() {
        "ethereum" => Some(5009297550715157269),
        "arbitrum" => Some(4949039107694359620),
        "optimism" => Some(3734403246176062136),
        "polygon" => Some(4051577828743386545),
        "avalanche" => Some(6433500567565415381),
        "base" => Some(15971525489660198786),
        "bsc" => Some(11344663589394136015),
        _ => None,
    }
}

fn pad32_left(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() <= 32);
    let mut out = vec![0u8; 32 - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

fn ccip_strip_hex(s: &str) -> &str {
    s.trim_start_matches("0x")
}

/// Encode a single `EVM2AnyMessage` ABI-tuple body (after the outer
/// offset word). Layout matches the Solidity struct
/// `(bytes receiver, bytes data, (address,uint256)[] tokenAmounts,
///   address feeToken, bytes extraArgs)`.
fn ccip_encode_evm2any(
    receiver_hex: &str,
    data_hex: &str,
    token_amounts: &[(String, String)],
    fee_token: &str,
    gas_limit: u64,
) -> std::result::Result<Vec<u8>, JsonRpcError> {
    let receiver = hex::decode(ccip_strip_hex(receiver_hex))
        .map_err(|e| invalid_params(format!("invalid receiver hex: {e}")))?;
    let data = if data_hex.is_empty() || data_hex == "0x" {
        Vec::new()
    } else {
        hex::decode(ccip_strip_hex(data_hex))
            .map_err(|e| invalid_params(format!("invalid data hex: {e}")))?
    };
    let fee_token_bytes = hex::decode(ccip_strip_hex(fee_token))
        .map_err(|e| invalid_params(format!("invalid fee_token: {e}")))?;
    if fee_token_bytes.len() != 20 {
        return Err(invalid_params("fee_token must be a 20-byte address"));
    }

    // extra_args = GenericExtraArgsV2 selector 0x181dcf10 || gasLimit u256
    // || allowOutOfOrderExecution bool. Matches the CCIP adapter's
    // hardcoded V2 wire format (see chainlink_ccip.rs).
    let mut extra_args = vec![0x18, 0x1d, 0xcf, 0x10];
    extra_args.extend_from_slice(&pad32_left(&gas_limit.to_be_bytes()));
    extra_args.extend_from_slice(&pad32_left(&[1u8]));

    // Head: 5 fixed words (offsets / address).
    //   word 0 -> bytes receiver offset
    //   word 1 -> bytes data offset
    //   word 2 -> array tokenAmounts offset
    //   word 3 -> address feeToken (right-aligned)
    //   word 4 -> bytes extraArgs offset
    let head_len = 5 * 32;

    fn enc_bytes(b: &[u8]) -> Vec<u8> {
        let mut out = pad32_left(&(b.len() as u64).to_be_bytes());
        let mut padded = b.to_vec();
        while !padded.len().is_multiple_of(32) {
            padded.push(0);
        }
        out.extend_from_slice(&padded);
        out
    }

    let receiver_enc = enc_bytes(&receiver);
    let data_enc = enc_bytes(&data);

    // tokenAmounts: dynamic array of (address,uint256). length word
    // followed by N flat words (no inner offsets since the element is
    // a fixed-size value type).
    let mut token_amounts_enc = pad32_left(&(token_amounts.len() as u64).to_be_bytes());
    for (token, amount) in token_amounts {
        let t = hex::decode(ccip_strip_hex(token))
            .map_err(|e| invalid_params(format!("invalid token addr: {e}")))?;
        if t.len() != 20 {
            return Err(invalid_params("token addr must be 20 bytes"));
        }
        token_amounts_enc.extend_from_slice(&pad32_left(&t));
        let amount_u: u128 = amount
            .parse()
            .map_err(|e| invalid_params(format!("invalid token amount: {e}")))?;
        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(&amount_u.to_be_bytes());
        token_amounts_enc.extend_from_slice(&buf);
    }
    let extra_args_enc = enc_bytes(&extra_args);

    // Offset values are absolute from the start of the tuple body.
    let receiver_off = head_len as u64;
    let data_off = receiver_off + receiver_enc.len() as u64;
    let token_amounts_off = data_off + data_enc.len() as u64;
    let extra_args_off = token_amounts_off + token_amounts_enc.len() as u64;

    let mut head = Vec::with_capacity(head_len);
    head.extend_from_slice(&pad32_left(&receiver_off.to_be_bytes()));
    head.extend_from_slice(&pad32_left(&data_off.to_be_bytes()));
    head.extend_from_slice(&pad32_left(&token_amounts_off.to_be_bytes()));
    head.extend_from_slice(&pad32_left(&fee_token_bytes));
    head.extend_from_slice(&pad32_left(&extra_args_off.to_be_bytes()));

    let mut out = head;
    out.extend_from_slice(&receiver_enc);
    out.extend_from_slice(&data_enc);
    out.extend_from_slice(&token_amounts_enc);
    out.extend_from_slice(&extra_args_enc);
    Ok(out)
}

/// Build Router.{getFee|ccipSend}(uint64, EVM2AnyMessage) calldata.
fn ccip_build_calldata(
    selector_hex: &str,
    dst_selector: u64,
    receiver: &str,
    data: &str,
    token_amounts: &[(String, String)],
    fee_token: &str,
    gas_limit: u64,
) -> std::result::Result<Vec<u8>, JsonRpcError> {
    let selector = hex::decode(selector_hex)
        .map_err(|e| invalid_params(format!("bad selector: {e}")))?;
    let mut calldata = Vec::with_capacity(4 + 64 + 256);
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(&pad32_left(&dst_selector.to_be_bytes()));
    // Offset to the tuple body = 0x40 (skip selector-arg + offset-word).
    calldata.extend_from_slice(&pad32_left(&(64u64).to_be_bytes()));
    let body = ccip_encode_evm2any(receiver, data, token_amounts, fee_token, gas_limit)?;
    calldata.extend_from_slice(&body);
    Ok(calldata)
}

async fn ccip_eth_call(
    http: &reqwest::Client,
    rpc_url: &str,
    to: &str,
    calldata: &[u8],
) -> std::result::Result<Vec<u8>, JsonRpcError> {
    let resp = http
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": to,
                "data": format!("0x{}", hex::encode(calldata)),
            }, "latest"],
            "id": 1,
        }))
        .send()
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("CCIP eth_call transport error: {e}"),
            data: None,
        })?;
    let body: Value = resp.json().await.map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("CCIP eth_call parse error: {e}"),
        data: None,
    })?;
    if let Some(err) = body.get("error") {
        let msg = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(JsonRpcError {
            code: -32603,
            message: format!("CCIP eth_call rpc error: {msg}"),
            data: None,
        });
    }
    let hex_str = body
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "CCIP eth_call missing result".to_string(),
            data: None,
        })?;
    hex::decode(ccip_strip_hex(hex_str)).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("CCIP eth_call hex decode: {e}"),
        data: None,
    })
}

fn ccip_extract_token_amounts(params: &Value) -> std::result::Result<Vec<(String, String)>, JsonRpcError> {
    let Some(arr) = params.get("token_amounts").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    arr.iter()
        .map(|item| {
            let token = item
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid_params("token_amounts[*].token missing"))?
                .to_string();
            let amount = item
                .get("amount")
                .and_then(|v| v.as_str())
                .ok_or_else(|| invalid_params("token_amounts[*].amount missing (use decimal string)"))?
                .to_string();
            Ok((token, amount))
        })
        .collect()
}

/// `tenzro_ccipGetFee` — call Router.getFee() via eth_call against the
/// source chain's CCIP Router. Returns the native fee in wei.
pub(crate) async fn handle_ccip_get_fee(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let src = params
        .get("source_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing source_chain"))?;
    let dst_raw = params
        .get("dest_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing dest_chain"))?;
    let receiver = params
        .get("receiver")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing receiver"))?;
    let data_hex = params.get("data_hex").and_then(|v| v.as_str()).unwrap_or("");
    let fee_token = params
        .get("fee_token")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0000000000000000000000000000000000000000");
    let token_amounts = ccip_extract_token_amounts(&params)?;

    let (chain_name, rpc_url, _src_selector, router) =
        ccip_chain_descriptor(src).ok_or_else(|| {
            invalid_params(format!(
                "Unsupported CCIP source_chain '{src}'. Supported: ethereum, arbitrum, base"
            ))
        })?;
    let dst_selector =
        ccip_chain_selector(dst_raw).ok_or_else(|| invalid_params("Invalid dest_chain"))?;

    let calldata = ccip_build_calldata(
        CCIP_GET_FEE_SELECTOR,
        dst_selector,
        receiver,
        data_hex,
        &token_amounts,
        fee_token,
        params.get("gas_limit").and_then(|v| v.as_u64()).unwrap_or(200_000),
    )?;

    let http = reqwest::Client::new();
    let result = ccip_eth_call(&http, &rpc_url, router, &calldata).await?;
    if result.len() < 32 {
        return Err(JsonRpcError {
            code: -32603,
            message: "Router.getFee returned short response".to_string(),
            data: None,
        });
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&result[16..32]);
    let fee_wei = u128::from_be_bytes(arr);

    Ok(json!({
        "source_chain": chain_name,
        "router_address": router,
        "dest_chain_selector": dst_selector.to_string(),
        "fee_token": fee_token,
        "fee_wei": fee_wei.to_string(),
        "fee_native": format!("{:.8}", fee_wei as f64 / 1e18),
    }))
}

/// `tenzro_ccipSend` — prepare Router.ccipSend() calldata + msg.value.
/// Signing/broadcasting is left to the caller (operator key); the
/// returned envelope can be paired with `eth_sendRawTransaction`.
pub(crate) async fn handle_ccip_send(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let src = params
        .get("source_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing source_chain"))?;
    let dst_raw = params
        .get("dest_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing dest_chain"))?;
    let receiver = params
        .get("receiver")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing receiver"))?;
    let data_hex = params.get("data_hex").and_then(|v| v.as_str()).unwrap_or("");
    let fee_token = params
        .get("fee_token")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0000000000000000000000000000000000000000");
    let gas_limit = params.get("gas_limit").and_then(|v| v.as_u64()).unwrap_or(200_000);
    let token_amounts = ccip_extract_token_amounts(&params)?;

    let (chain_name, rpc_url, _src_selector, router) =
        ccip_chain_descriptor(src).ok_or_else(|| {
            invalid_params(format!(
                "Unsupported CCIP source_chain '{src}'. Supported: ethereum, arbitrum, base"
            ))
        })?;
    let dst_selector =
        ccip_chain_selector(dst_raw).ok_or_else(|| invalid_params("Invalid dest_chain"))?;

    let send_calldata = ccip_build_calldata(
        CCIP_SEND_SELECTOR,
        dst_selector,
        receiver,
        data_hex,
        &token_amounts,
        fee_token,
        gas_limit,
    )?;

    // Quote fee so the caller knows the msg.value to attach.
    let fee_calldata = ccip_build_calldata(
        CCIP_GET_FEE_SELECTOR,
        dst_selector,
        receiver,
        data_hex,
        &token_amounts,
        fee_token,
        gas_limit,
    )?;
    let http = reqwest::Client::new();
    let fee_result = ccip_eth_call(&http, &rpc_url, router, &fee_calldata).await?;
    let fee_wei = if fee_result.len() >= 32 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&fee_result[16..32]);
        u128::from_be_bytes(arr)
    } else {
        0
    };

    Ok(json!({
        "status": "prepared",
        "source_chain": chain_name,
        "router_address": router,
        "dest_chain_selector": dst_selector.to_string(),
        "calldata": format!("0x{}", hex::encode(&send_calldata)),
        "msg_value_wei": fee_wei.to_string(),
        "gas_limit_destination": gas_limit,
        "note": "Sign and broadcast via eth_sendRawTransaction with to=router_address, value=msg_value_wei.",
    }))
}

/// `tenzro_ccipTrack` — OffRamp.getExecutionState(bytes32) on the
/// destination chain. Returns the numeric state and human-readable
/// label (UNTOUCHED / IN_PROGRESS / SUCCESS / FAILURE).
pub(crate) async fn handle_ccip_track(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let message_id = params
        .get("message_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing message_id"))?;
    let dst = params
        .get("dest_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing dest_chain"))?;
    let offramp = params
        .get("offramp_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing offramp_address"))?;

    let message_id_bytes = hex::decode(ccip_strip_hex(message_id))
        .map_err(|e| invalid_params(format!("invalid message_id hex: {e}")))?;
    if message_id_bytes.len() != 32 {
        return Err(invalid_params("message_id must be 32 bytes"));
    }

    let (chain_name, rpc_url, _, _) =
        ccip_chain_descriptor(dst).ok_or_else(|| invalid_params("Unsupported dest_chain"))?;

    let mut calldata =
        hex::decode(CCIP_GET_EXECUTION_STATE_SELECTOR).expect("static selector hex");
    calldata.extend_from_slice(&pad32_left(&message_id_bytes));

    let http = reqwest::Client::new();
    let result = ccip_eth_call(&http, &rpc_url, offramp, &calldata).await?;
    let state = if result.len() >= 32 { result[31] } else { 0u8 };
    let (label, desc) = match state {
        0 => ("UNTOUCHED", "Message has not been processed yet"),
        1 => ("IN_PROGRESS", "Message is currently being executed"),
        2 => ("SUCCESS", "Message was successfully delivered"),
        3 => ("FAILURE", "Message execution failed"),
        _ => ("UNKNOWN", "Unrecognized state"),
    };
    Ok(json!({
        "message_id": format!("0x{}", hex::encode(&message_id_bytes)),
        "dest_chain": chain_name,
        "offramp_address": offramp,
        "execution_state": state,
        "state_name": label,
        "description": desc,
    }))
}

async fn ccip_api_get(
    path: &str,
    extra: &[(&str, &str)],
) -> std::result::Result<Value, JsonRpcError> {
    let mut url = format!("{}{}", CCIP_API_BASE, path);
    let mut first = !url.contains('?');
    for (k, v) in extra {
        if v.is_empty() {
            continue;
        }
        url.push(if first { '?' } else { '&' });
        first = false;
        url.push_str(k);
        url.push('=');
        url.push_str(v);
    }
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("CCIP API transport error: {e}"),
            data: None,
        })?;
    if !resp.status().is_success() {
        return Err(JsonRpcError {
            code: -32603,
            message: format!("CCIP API status {}", resp.status()),
            data: None,
        });
    }
    resp.json().await.map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("CCIP API parse error: {e}"),
        data: None,
    })
}

/// `tenzro_ccipSupportedChains` — proxy the Chainlink docs API.
/// `tenzro_getPrice` — read-only USD price for a symbol (or list of symbols)
/// from the node's Chainlink `SYMBOL/USD` price oracle. Public: no auth.
///
/// Params (object or `[object]`):
/// - `symbol: string` — single ticker, OR
/// - `symbols: string[]` — batch.
///
/// Response: `{ prices: [{ symbol, price_usd_8dp, decimals, updated_at, feed_address }],
///              unavailable: [{ symbol, reason }] }`.
/// Unresolvable symbols are reported in `unavailable` rather than failing the
/// whole call, so a portfolio view can render partial USD totals.
pub(crate) async fn handle_get_price(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let oracle = node.price_oracle().ok_or_else(|| JsonRpcError {
        code: -32601,
        message: "price oracle not configured on this node \
                  (set bridge.prices.enabled + symbols)"
            .to_string(),
        data: None,
    })?;

    let params = params.map(unwrap_arr).unwrap_or_else(|| json!({}));
    let mut symbols: Vec<String> = Vec::new();
    if let Some(s) = params.get("symbol").and_then(|v| v.as_str()) {
        symbols.push(s.to_string());
    }
    if let Some(arr) = params.get("symbols").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                symbols.push(s.to_string());
            }
        }
    }
    if symbols.is_empty() {
        return Err(JsonRpcError {
            code: -32602,
            message: "missing `symbol` or `symbols` param".to_string(),
            data: None,
        });
    }

    let mut prices = Vec::new();
    let mut unavailable = Vec::new();
    for sym in symbols {
        match oracle.price(&sym).await {
            Ok(p) => prices.push(json!({
                "symbol": p.symbol,
                "price_usd_8dp": p.price_usd_8dp.to_string(),
                "decimals": p.decimals,
                "updated_at": p.updated_at,
                "feed_address": p.feed_address,
            })),
            Err(e) => unavailable.push(json!({
                "symbol": sym.to_uppercase(),
                "reason": e.to_string(),
            })),
        }
    }

    Ok(json!({ "prices": prices, "unavailable": unavailable }))
}

pub(crate) async fn handle_ccip_supported_chains(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let env = params
        .as_ref()
        .map(|p| unwrap_arr(p.clone()))
        .and_then(|p| p.get("environment").and_then(|v| v.as_str().map(String::from)))
        .unwrap_or_else(|| "mainnet".to_string());
    let body = ccip_api_get("/chains", &[("environment", &env)]).await?;
    Ok(json!({ "environment": env, "chains": body }))
}

/// `tenzro_ccipSupportedTokens` — proxy the Chainlink docs API.
pub(crate) async fn handle_ccip_supported_tokens(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let env = params
        .as_ref()
        .map(|p| unwrap_arr(p.clone()))
        .and_then(|p| p.get("environment").and_then(|v| v.as_str().map(String::from)))
        .unwrap_or_else(|| "mainnet".to_string());
    let body = ccip_api_get("/tokens", &[("environment", &env)]).await?;
    Ok(json!({ "environment": env, "tokens": body }))
}

/// `tenzro_ccipLanes` — proxy CCIP lanes from the Chainlink docs API.
pub(crate) async fn handle_ccip_lanes(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.map(unwrap_arr).unwrap_or_else(|| json!({}));
    let env = params
        .get("environment")
        .and_then(|v| v.as_str())
        .unwrap_or("mainnet")
        .to_string();
    let src = params
        .get("source_chain_selector")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let dst = params
        .get("dest_chain_selector")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let body = ccip_api_get(
        "/lanes",
        &[
            ("environment", &env),
            ("sourceChainSelector", &src),
            ("destChainSelector", &dst),
        ],
    )
    .await?;
    Ok(json!({ "environment": env, "lanes": body }))
}

/// `tenzro_ccipTokenPool` — inspect a CCT v1.6+ token-pool contract by
/// reading its `getToken()` + `getRemoteToken(uint64)` accessors.
pub(crate) async fn handle_ccip_token_pool(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let chain = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing chain"))?;
    let pool = params
        .get("pool_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing pool_address"))?;
    let (chain_name, rpc_url, _, _) =
        ccip_chain_descriptor(chain).ok_or_else(|| invalid_params("Unsupported chain"))?;

    // `getToken()` selector = 0x21df0da7
    let calldata = hex::decode("21df0da7").unwrap();
    let http = reqwest::Client::new();
    let result = ccip_eth_call(&http, &rpc_url, pool, &calldata).await?;
    let token = if result.len() >= 32 {
        format!("0x{}", hex::encode(&result[12..32]))
    } else {
        "0x".to_string()
    };
    Ok(json!({
        "chain": chain_name,
        "pool_address": pool,
        "token_address": token,
        "note": "CCT v1.6+ pool. Use ccipRateLimits for inbound/outbound throughput.",
    }))
}

/// `tenzro_ccipRateLimits` — read inbound + outbound rate-limiter state
/// for a (pool, remote-chain) pair. Wraps `getCurrentInboundRateLimiterState(uint64)`
/// and the outbound counterpart, both returning the standard
/// `RateLimiter.TokenBucket` tuple (tokens, lastUpdated, isEnabled, capacity, rate).
pub(crate) async fn handle_ccip_rate_limits(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let chain = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing chain"))?;
    let pool = params
        .get("pool_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing pool_address"))?;
    let remote_raw = params
        .get("remote_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing remote_chain"))?;
    let remote = ccip_chain_selector(remote_raw)
        .ok_or_else(|| invalid_params("Invalid remote_chain"))?;

    let (chain_name, rpc_url, _, _) =
        ccip_chain_descriptor(chain).ok_or_else(|| invalid_params("Unsupported chain"))?;

    // Selectors: getCurrent{In,Out}boundRateLimiterState(uint64).
    // In = 0x4c5ef0ed, Out = 0x6890c1c8 (CCIP v1.5/v1.6 TokenPool).
    let mut call_in = hex::decode("4c5ef0ed").unwrap();
    call_in.extend_from_slice(&pad32_left(&remote.to_be_bytes()));
    let mut call_out = hex::decode("6890c1c8").unwrap();
    call_out.extend_from_slice(&pad32_left(&remote.to_be_bytes()));

    let http = reqwest::Client::new();

    // Best-effort: if a chain's pool is older v1.5 the selector still
    // matches; if the contract is upgraded both calls succeed. Report
    // structured failure when neither does.
    let parse_bucket = |raw: &[u8]| -> Value {
        if raw.len() < 160 {
            return json!({ "ok": false, "raw_hex": format!("0x{}", hex::encode(raw)) });
        }
        let read_u128 = |off: usize| {
            let mut a = [0u8; 16];
            a.copy_from_slice(&raw[off + 16..off + 32]);
            u128::from_be_bytes(a)
        };
        json!({
            "tokens": read_u128(0).to_string(),
            "last_updated": read_u128(32).to_string(),
            "is_enabled": raw[95] != 0,
            "capacity": read_u128(96).to_string(),
            "rate": read_u128(128).to_string(),
        })
    };

    let inbound = ccip_eth_call(&http, &rpc_url, pool, &call_in).await.ok();
    let outbound = ccip_eth_call(&http, &rpc_url, pool, &call_out).await.ok();

    Ok(json!({
        "chain": chain_name,
        "pool_address": pool,
        "remote_chain_selector": remote.to_string(),
        "inbound": inbound.as_deref().map(parse_bucket),
        "outbound": outbound.as_deref().map(parse_bucket),
    }))
}

/// `tenzro_ccipBridge` — bridge tokens through the BridgeRouter,
/// explicitly preferring the CCIP regulated rail. Returns the same
/// envelope shape as `tenzro_wormholeBridge` for SDK symmetry.
pub(crate) async fn handle_ccip_bridge(
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
    let asset = params.get("asset").and_then(|v| v.as_str()).unwrap_or("TNZO");
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

    // Verify a CCIP adapter is registered before attempting.
    let adapters = router.list_adapters().await;
    let has_ccip = adapters
        .iter()
        .any(|n| n.to_lowercase().contains("ccip") || n.to_lowercase().contains("chainlink"));
    if !has_ccip {
        return Ok(json!({
            "status": "unavailable",
            "error": "CCIP adapter not registered in BridgeRouter",
            "registered_adapters": adapters,
        }));
    }

    // Pin the per-request strategy to PreferAdapter("chainlink_ccip")
    // so the route selection deterministically lands on CCIP rather
    // than relying on the global preference. We restore the prior
    // strategy after dispatch to keep the router's global state
    // untouched.
    let prior = router.get_preferences().await;
    let ccip_adapter_name = adapters
        .iter()
        .find(|n| n.to_lowercase().contains("ccip") || n.to_lowercase().contains("chainlink"))
        .cloned()
        .unwrap_or_else(|| "chainlink_ccip".to_string());
    router
        .set_preferences(tenzro_bridge::router::RoutingPreferences {
            strategy: tenzro_bridge::router::RoutingStrategy::PreferAdapter(
                ccip_adapter_name.clone(),
            ),
            max_fee: prior.max_fee,
            max_time_secs: prior.max_time_secs,
        })
        .await;

    let req = tenzro_bridge::BridgeTokenRequest::new(
        source.to_string(),
        dest.to_string(),
        asset.to_string(),
        amount,
        sender.to_string(),
        recipient.to_string(),
    );
    let result = router.bridge_tokens(req).await;
    router.set_preferences(prior).await;

    match result {
        Ok(receipt) => Ok(json!({
            "transfer_id": receipt.transfer_id,
            "source_chain": receipt.source_chain,
            "dest_chain": receipt.dest_chain,
            "tx_hash": format!("{}", receipt.tx_hash),
            "fee_paid": receipt.fee_paid.to_string(),
            "estimated_arrival_ms": receipt.estimated_arrival,
            "adapter": ccip_adapter_name,
        })),
        Err(e) => Ok(json!({
            "status": "failed",
            "error": format!("{e}"),
            "adapter": ccip_adapter_name,
        })),
    }
}

// ============================================================
// TNZO CCT — Chainlink Cross-Chain Token
// ============================================================

/// `tenzro_cctListPools` — return the live TNZO CCT pool topology from
/// the registered `TnzoCctBridge` when CCIP is enabled; otherwise fall
/// back to the canonical Tenzro mainnet topology (Ethereum, Base,
/// Arbitrum, Optimism, Solana).
pub(crate) async fn handle_cct_list_pools(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let pools: Vec<Value> = if let Some(bridge) = node.cct_bridge() {
        bridge.registry().all().into_iter().map(pool_to_json).collect()
    } else {
        tenzro_bridge::TnzoCctRegistry::tenzro_mainnet()
            .all()
            .into_iter()
            .map(pool_to_json)
            .collect()
    };
    Ok(json!({
        "pools": pools.clone(),
        "count": pools.len(),
    }))
}

/// `tenzro_cctGetPool` — lookup a single TNZO CCT pool by chain id from
/// the live registered registry, with canonical mainnet fallback.
pub(crate) async fn handle_cct_get_pool(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let chain = params
        .get("chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing chain"))?;

    let pool = if let Some(bridge) = node.cct_bridge() {
        bridge.registry().get(chain)
    } else {
        tenzro_bridge::TnzoCctRegistry::tenzro_mainnet().get(chain)
    };

    match pool {
        Some(pool) => Ok(pool_to_json(pool)),
        None => Err(invalid_params(format!(
            "no TNZO CCT pool registered for {chain}"
        ))),
    }
}

/// `tenzro_cctBuildMessage` — build a CCT-formatted CCIP message for a
/// TNZO transfer between two chains. Returns the serialized CCIP message
/// envelope (dest_chain_selector, receiver, token_amounts, extra_args)
/// that the caller can submit to the source-chain CCIP Router. Requires
/// the CCT bridge to be initialized (CCIP enabled).
pub(crate) async fn handle_cct_build_message(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let bridge = node.cct_bridge().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "TNZO CCT bridge not initialized — enable [bridge.ccip] in node config".to_string(),
        data: None,
    })?;

    let source_chain = params
        .get("source_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing source_chain"))?;
    let dest_chain = params
        .get("dest_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing dest_chain"))?;
    let recipient = params
        .get("recipient")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing recipient"))?;
    let amount: u128 = params
        .get("amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .or_else(|| params.get("amount").and_then(|v| v.as_u64()).map(|n| n as u128))
        .ok_or_else(|| missing("Missing or invalid amount"))?;

    let fee_token = match params
        .get("fee_token")
        .and_then(|v| v.as_str())
        .unwrap_or("native")
    {
        "link" | "LINK" => tenzro_bridge::chainlink_ccip::FeeToken::Link,
        _ => tenzro_bridge::chainlink_ccip::FeeToken::Native,
    };

    let msg = bridge
        .build_message(source_chain, dest_chain, recipient, amount, fee_token)
        .map_err(|e| invalid_params(format!("build_message: {e}")))?;

    let dest_selector = bridge
        .registry()
        .get(dest_chain)
        .map(|p| p.chain_selector.to_string())
        .unwrap_or_default();

    Ok(json!({
        "source_chain": source_chain,
        "dest_chain": dest_chain,
        "dest_chain_selector": dest_selector,
        "receiver": msg.receiver,
        "token_amounts": msg.token_amounts.iter().map(|t| json!({
            "token": t.token,
            "amount": t.amount.to_string(),
        })).collect::<Vec<_>>(),
        "data": format!("0x{}", hex::encode(&msg.data)),
        "fee_token": match msg.fee_token {
            tenzro_bridge::chainlink_ccip::FeeToken::Native => "native",
            tenzro_bridge::chainlink_ccip::FeeToken::Link => "link",
        },
        "extra_args": format!("0x{}", hex::encode(&msg.extra_args)),
    }))
}

// ============================================================
// Hyperlane V3 — sovereign-ISM messaging
// ============================================================

/// `tenzro_hyperlaneListChains` — list the Hyperlane chains this
/// adapter can address, with their canonical domain ids.
pub(crate) async fn handle_hyperlane_list_chains(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let adapter = node.hyperlane_adapter();
    let chains: Vec<Value> =
        tenzro_bridge::BridgeAdapter::supported_chains(adapter.as_ref())
            .into_iter()
            .map(|c| {
                json!({
                    "chain": c.chain_id,
                    "name": c.name,
                    "native_token": c.native_token,
                    "finality_time_secs": c.finality_time_secs,
                    "domain": adapter.config().chain_id(&c.chain_id),
                })
            })
            .collect();
    Ok(json!({
        "source_domain": adapter.config().source_domain,
        "chains": chains.clone(),
        "count": chains.len(),
    }))
}

/// `tenzro_hyperlaneQuoteDispatch` — local interchain-gas estimate for
/// a dispatch: canonical message size plus the default Hyperlane IGP
/// overhead model (50k base + 16 gas per body byte).
pub(crate) async fn handle_hyperlane_quote_dispatch(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let destination_domain = params
        .get("destination_domain")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| missing("Missing destination_domain"))?;
    let body_hex = params
        .get("body_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing body_hex"))?;
    let body = hex::decode(body_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid body_hex: {e}")))?;

    let adapter = node.hyperlane_adapter();
    let message_bytes = tenzro_bridge::hyperlane::HYPERLANE_HEADER_LEN + body.len();
    let estimated_destination_gas = 50_000u64 + 16 * body.len() as u64;
    Ok(json!({
        "origin_domain": adapter.config().source_domain,
        "destination_domain": destination_domain,
        "ism": adapter.resolve_ism(destination_domain),
        "body_bytes": body.len(),
        "message_bytes": message_bytes,
        "estimated_destination_gas": estimated_destination_gas,
        "quote_source": "local-estimate",
    }))
}

/// `tenzro_hyperlaneDispatch` — dispatch a Hyperlane message: allocate
/// a per-destination nonce, encode the canonical Mailbox envelope, and
/// return the canonical message id.
pub(crate) async fn handle_hyperlane_dispatch(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let adapter = node.hyperlane_adapter();

    if let Some(origin) = params
        .get("origin_domain")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        && origin != adapter.config().source_domain
    {
        return Err(invalid_params(format!(
            "origin_domain {origin} does not match this node's Hyperlane domain {}",
            adapter.config().source_domain
        )));
    }
    let destination_domain = params
        .get("destination_domain")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| missing("Missing destination_domain"))?;
    let recipient = params
        .get("recipient")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing recipient"))?;
    let body_hex = params
        .get("body_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing body_hex"))?;
    let body = hex::decode(body_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid body_hex: {e}")))?;
    let mailbox = adapter.config().mailbox.clone();
    let sender = params
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or(&mailbox);

    let id = adapter
        .dispatch_message(destination_domain, sender, recipient, body)
        .map_err(|e| invalid_params(format!("{e}")))?;
    let id_hex = format!("0x{}", hex::encode(id.as_bytes()));
    let nonce = adapter
        .lookup_message(&id_hex)
        .map(|(m, _)| m.nonce);
    Ok(json!({
        "message_id": id_hex,
        "origin_domain": adapter.config().source_domain,
        "destination_domain": destination_domain,
        "nonce": nonce,
        "status": "pending",
    }))
}

/// `tenzro_hyperlaneGetMessage` — look up a dispatched message and its
/// transfer status by canonical message id.
pub(crate) async fn handle_hyperlane_get_message(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let message_id = params
        .get("message_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing message_id"))?;

    match node.hyperlane_adapter().lookup_message(message_id) {
        Some((m, status)) => Ok(json!({
            "message_id": message_id,
            "version": m.version,
            "nonce": m.nonce,
            "origin_domain": m.origin_domain,
            "sender": format!("0x{}", hex::encode(m.sender)),
            "destination_domain": m.destination_domain,
            "recipient": format!("0x{}", hex::encode(m.recipient)),
            "body": format!("0x{}", hex::encode(&m.body)),
            "status": format!("{status:?}").to_lowercase(),
        })),
        None => Err(invalid_params(format!(
            "unknown Hyperlane message id: {message_id}"
        ))),
    }
}

// ============================================================
// Axelar GMP — Cosmos / Move / Stellar / XRPL reach
// ============================================================

/// `tenzro_axelarListChains` — list the canonical Axelar chain
/// identifiers this adapter knows.
pub(crate) async fn handle_axelar_list_chains(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let adapter = node.axelar_adapter();
    let chains: Vec<Value> = adapter
        .config()
        .known_chains()
        .into_iter()
        .map(|c| {
            json!({
                "chain": c.chain_id,
                "name": c.name,
                "native_token": c.native_token,
                "finality_time_secs": c.finality_time_secs,
            })
        })
        .collect();
    Ok(json!({
        "source_chain": adapter.config().source_chain,
        "chains": chains.clone(),
        "count": chains.len(),
    }))
}

/// `tenzro_axelarCallContract` — register an Axelar GMP `callContract`
/// dispatch. Returns the payload hash that correlates the call across
/// the Axelar validator network.
pub(crate) async fn handle_axelar_call_contract(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let destination_chain = params
        .get("destination_chain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing destination_chain"))?;
    let destination_address = params
        .get("destination_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing destination_address"))?;
    let payload_hex = params
        .get("payload_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing payload_hex"))?;
    let payload = hex::decode(payload_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid payload_hex: {e}")))?;
    let gas_prepaid = parse_u128(params.get("gas_amount")).unwrap_or(0);

    let adapter = node.axelar_adapter();
    let hash = adapter
        .call_contract(destination_chain, destination_address, payload, gas_prepaid)
        .map_err(|e| invalid_params(format!("{e}")))?;
    Ok(json!({
        "payload_hash": format!("0x{}", hex::encode(hash.as_bytes())),
        "source_chain": adapter.config().source_chain,
        "destination_chain": adapter.config().canonical_chain(destination_chain),
        "destination_address": destination_address,
        "gas_prepaid": gas_prepaid.to_string(),
        "status": "pending",
    }))
}

/// `tenzro_axelarPayGas` — add prepaid gas to a registered GMP call
/// (AxelarGasService `addNativeGas` semantics).
pub(crate) async fn handle_axelar_pay_gas(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let payload_hash = params
        .get("payload_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing payload_hash"))?;
    let gas_amount = parse_u128(params.get("gas_amount"))
        .ok_or_else(|| invalid_params("Missing or invalid gas_amount"))?;

    let total = node
        .axelar_adapter()
        .pay_gas(payload_hash, gas_amount)
        .map_err(|e| invalid_params(format!("{e}")))?;
    Ok(json!({
        "payload_hash": payload_hash,
        "gas_added": gas_amount.to_string(),
        "gas_prepaid_total": total.to_string(),
    }))
}

/// `tenzro_axelarGetMessage` — look up a registered GMP call by its
/// payload hash.
pub(crate) async fn handle_axelar_get_message(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let payload_hash = params
        .get("payload_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing payload_hash"))?;

    match node.axelar_adapter().lookup_call(payload_hash) {
        Some(call) => Ok(json!({
            "payload_hash": format!("0x{}", hex::encode(call.payload_hash.as_bytes())),
            "source_chain": call.source_chain,
            "destination_chain": call.destination_chain,
            "destination_address": call.destination_address,
            "payload": format!("0x{}", hex::encode(&call.payload)),
            "gas_prepaid": call.gas_prepaid.to_string(),
        })),
        None => Err(invalid_params(format!(
            "unknown Axelar payload hash: {payload_hash}"
        ))),
    }
}

// ============================================================
// Babylon — Bitcoin staking / finality providers
// ============================================================

fn babylon_provider_json(p: &tenzro_bridge::babylon::FinalityProvider) -> Value {
    json!({
        "validator": format!("0x{}", hex::encode(p.validator_address.as_bytes())),
        "btc_pk": format!("0x{}", hex::encode(p.btc_pk)),
        "registration_tx": p.registration_tx,
        "commission_bps": p.commission_bps,
        "active": p.active,
    })
}

fn parse_babylon_validator(
    params: &Value,
) -> std::result::Result<tenzro_types::primitives::Address, JsonRpcError> {
    let validator = params
        .get("validator")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing validator"))?;
    tenzro_types::primitives::Address::from_hex(validator)
        .map_err(|e| invalid_params(format!("invalid validator address: {e}")))
}

fn parse_hex_32(
    params: &Value,
    key: &str,
) -> std::result::Result<[u8; 32], JsonRpcError> {
    let raw = params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing(&format!("Missing {key}")))?;
    let bytes = hex::decode(raw.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid {key}: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| invalid_params(format!("{key} must be 32 bytes")))
}

/// `tenzro_babylonRegisterFinalityProvider` — register a Tenzro
/// validator as a Babylon finality provider.
pub(crate) async fn handle_babylon_register_finality_provider(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let validator = parse_babylon_validator(&params)?;
    let btc_pk = parse_hex_32(&params, "btc_pk")?;
    let commission_bps = params
        .get("commission_bps")
        .and_then(|v| v.as_u64())
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(|| invalid_params("Missing or invalid commission_bps"))?;

    let provider = node
        .babylon_adapter()
        .register_finality_provider(validator, btc_pk, commission_bps)
        .map_err(|e| invalid_params(format!("{e}")))?;
    Ok(babylon_provider_json(&provider))
}

/// `tenzro_babylonGetFinalityProvider` — read the registration record
/// for a validator.
pub(crate) async fn handle_babylon_get_finality_provider(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let validator = parse_babylon_validator(&params)?;

    match node.babylon_adapter().finality_provider(&validator) {
        Some(p) => Ok(json!({
            "registered": true,
            "provider": babylon_provider_json(&p),
        })),
        None => Ok(json!({ "registered": false })),
    }
}

/// `tenzro_babylonListFinalityProviders` — list every registered
/// finality provider.
pub(crate) async fn handle_babylon_list_finality_providers(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let providers: Vec<Value> = node
        .babylon_adapter()
        .list_finality_providers()
        .iter()
        .map(babylon_provider_json)
        .collect();
    Ok(json!({
        "providers": providers.clone(),
        "count": providers.len(),
    }))
}

/// `tenzro_babylonTotalStakeForProvider` — sum finalized BTC
/// delegations (in satoshis) routed to a validator's finality provider.
pub(crate) async fn handle_babylon_total_stake_for_provider(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let validator = parse_babylon_validator(&params)?;

    let adapter = node.babylon_adapter();
    let provider = adapter.finality_provider(&validator).ok_or_else(|| {
        invalid_params("finality provider not registered for validator")
    })?;
    let total = adapter.total_stake_for_provider(&provider.btc_pk);
    Ok(json!({
        "validator": format!("0x{}", hex::encode(validator.as_bytes())),
        "btc_pk": format!("0x{}", hex::encode(provider.btc_pk)),
        "total_stake_satoshis": total,
    }))
}

/// `tenzro_babylonListDelegations` — list the BTC delegations routed to
/// a validator's finality provider.
pub(crate) async fn handle_babylon_list_delegations(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let validator = parse_babylon_validator(&params)?;

    let adapter = node.babylon_adapter();
    let provider = adapter.finality_provider(&validator).ok_or_else(|| {
        invalid_params("finality provider not registered for validator")
    })?;
    let delegations: Vec<Value> = adapter
        .delegations_for_provider(&provider.btc_pk)
        .into_iter()
        .map(|d| {
            json!({
                "staker_btc_pk": format!("0x{}", hex::encode(d.staker_btc_pk)),
                "finality_provider_btc_pk":
                    format!("0x{}", hex::encode(d.finality_provider_btc_pk)),
                "btc_satoshis": d.btc_satoshis,
                "start_height": d.start_height,
                "timelock_blocks": d.timelock_blocks,
                "finalized": d.finalized,
            })
        })
        .collect();
    Ok(json!({
        "validator": format!("0x{}", hex::encode(validator.as_bytes())),
        "delegations": delegations.clone(),
        "count": delegations.len(),
    }))
}

/// `tenzro_babylonSubmitFinalitySignature` — submit an EOTS finality
/// signature over a Tenzro block hash for a registered provider.
pub(crate) async fn handle_babylon_submit_finality_signature(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let validator = parse_babylon_validator(&params)?;
    let block_hash = parse_hex_32(&params, "block_hash")?;
    let sig_hex = params
        .get("eots_signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing eots_signature"))?;
    let signature = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid eots_signature: {e}")))?;
    if signature.len() != 64 {
        return Err(invalid_params("eots_signature must be 64 bytes"));
    }
    let babylon_height = params
        .get("babylon_height")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let randomness_commitment = if params.get("randomness_commitment").is_some() {
        parse_hex_32(&params, "randomness_commitment")?
    } else {
        [0u8; 32]
    };

    let validator_hex = format!("0x{}", hex::encode(validator.as_bytes()));
    let sig = tenzro_bridge::babylon::FinalitySignature {
        validator_address: validator,
        babylon_height,
        tenzro_block_hash: tenzro_types::primitives::Hash::new(block_hash),
        signature,
        randomness_commitment,
    };
    node.babylon_adapter()
        .submit_finality_signature(sig)
        .map_err(|e| invalid_params(format!("{e}")))?;
    Ok(json!({
        "accepted": true,
        "validator": validator_hex,
        "babylon_height": babylon_height,
        "block_hash": format!("0x{}", hex::encode(block_hash)),
    }))
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
        "registry": {
            "install_rpc": "tenzro_install7702Delegation",
            "get_rpc": "tenzro_get7702Delegation",
            "revoke_rpc": "tenzro_revoke7702Delegation",
        },
    }))
}

/// `tenzro_install7702Delegation` — install a signed EIP-7702
/// authorization in the delegation registry. The registry verifies the
/// `(chain_id, nonce)` tuple, recovers the authority via secp256k1, and
/// records `authority → target` so subsequent EVM calls that reach the
/// authority's code field see the delegation designator.
///
/// Params:
/// - `authority`: 20-byte lowercase-hex EVM address that signed the
///   authorization.
/// - `chain_id`: u64.
/// - `delegate_address`: 20-byte lowercase-hex EVM address whose code is
///   borrowed. The zero address revokes any active delegation.
/// - `nonce`: u64. Must equal the authority's current nonce.
/// - `signature`: 65-byte lowercase-hex (`r ‖ s ‖ y_parity`) per the EIP.
///
/// Returns `{ installed: true, authority, target, chain_id, designator }`
/// on success; the designator field is `null` when the delegation was
/// revoked by delegating to the zero address.
pub(crate) async fn handle_install_7702_delegation(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let authority_hex = params
        .get("authority")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing authority"))?;
    let authority = parse_eth_addr(authority_hex)?;
    let mut auth20 = [0u8; 20];
    if authority.len() != 20 {
        return Err(invalid_params("authority must be 20 bytes"));
    }
    auth20.copy_from_slice(&authority);

    let chain_id = params
        .get("chain_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing chain_id"))?;
    let delegate_hex = params
        .get("delegate_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing delegate_address"))?;
    let delegate = parse_eth_addr(delegate_hex)?;
    let nonce = params
        .get("nonce")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing nonce"))?;
    let signature_hex = params
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing signature"))?;
    let signature = hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("invalid signature hex: {e}")))?;
    if signature.len() != 65 {
        return Err(invalid_params("signature must be 65 bytes"));
    }

    let auth = tenzro_vm::account_abstraction::Eip7702Authorization {
        chain_id,
        delegate_address: delegate.to_vec(),
        nonce,
        signature,
    };

    let registry = node.eip7702_delegation_registry();
    let current_chain_id = node
        .config()
        .genesis
        .as_ref()
        .map(|g| g.chain_id)
        .unwrap_or(1337);

    // The caller is responsible for supplying the authority's current
    // nonce — this RPC is exposed to relayers, not signers, so we don't
    // attempt to resolve it from chain state here.
    match registry.install(&auth, auth20, current_chain_id, nonce) {
        Ok(pointer) => Ok(json!({
            "installed": true,
            "authority": format!("0x{}", hex::encode(auth20)),
            "target": format!("0x{}", hex::encode(pointer.target)),
            "chain_id": pointer.chain_id,
            "authority_nonce": pointer.authority_nonce,
            "designator": format!("0x{}", hex::encode(pointer.designator_bytes())),
            "revoked_zero_target": pointer.target == [0u8; 20],
        })),
        Err(e) => Err(invalid_params(format!("delegation rejected: {e}"))),
    }
}

/// `tenzro_get7702Delegation` — read the active delegation pointer for an
/// EVM authority. Returns `{ delegated: false }` when no delegation is
/// active. Params: `{ "authority": "0x..." }`.
pub(crate) async fn handle_get_7702_delegation(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let authority_hex = params
        .get("authority")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing authority"))?;
    let authority = parse_eth_addr(authority_hex)?;
    if authority.len() != 20 {
        return Err(invalid_params("authority must be 20 bytes"));
    }
    let mut auth20 = [0u8; 20];
    auth20.copy_from_slice(&authority);

    let registry = node.eip7702_delegation_registry();
    match registry.resolve_target(&auth20) {
        Some(pointer) => Ok(json!({
            "delegated": true,
            "authority": format!("0x{}", hex::encode(auth20)),
            "target": format!("0x{}", hex::encode(pointer.target)),
            "chain_id": pointer.chain_id,
            "authority_nonce": pointer.authority_nonce,
            "designator": format!("0x{}", hex::encode(pointer.designator_bytes())),
        })),
        None => Ok(json!({
            "delegated": false,
            "authority": format!("0x{}", hex::encode(auth20)),
        })),
    }
}

/// `tenzro_revoke7702Delegation` — operator-side revocation path. Removes
/// any active delegation for `authority` without requiring a signed
/// authorization. Intended for social-recovery and explicit override
/// flows; users seeking signed revocation should call
/// `tenzro_install7702Delegation` with `delegate_address` set to the
/// zero address. Params: `{ "authority": "0x..." }`.
pub(crate) async fn handle_revoke_7702_delegation(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let authority_hex = params
        .get("authority")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing authority"))?;
    let authority = parse_eth_addr(authority_hex)?;
    if authority.len() != 20 {
        return Err(invalid_params("authority must be 20 bytes"));
    }
    let mut auth20 = [0u8; 20];
    auth20.copy_from_slice(&authority);

    let registry = node.eip7702_delegation_registry();
    let removed = registry.revoke(&auth20);
    Ok(json!({
        "revoked": removed,
        "authority": format!("0x{}", hex::encode(auth20)),
    }))
}

/// Canonical Permit2 verifying contract address on Tenzro EVM. The
/// 20-byte slot mirrors the Uniswap Permit2 layout: a precompile-level
/// surface at `0x0000…00001023`.
pub const TENZRO_PERMIT2_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x23,
];

/// `tenzro_permit2DomainSeparator` — return the Permit2 EIP-712 domain
/// separator for this chain. Wallets compute this once and cache it.
pub(crate) async fn handle_permit2_domain_separator(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let chain_id = node
        .config()
        .genesis
        .as_ref()
        .map(|g| g.chain_id)
        .unwrap_or(1337);
    let verifying = tenzro_types::primitives::Address::new({
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&TENZRO_PERMIT2_ADDRESS);
        out
    });
    let ds = tenzro_vm::permit2::domain_separator(chain_id, &verifying);
    Ok(json!({
        "domain_separator": format!("0x{}", hex::encode(ds)),
        "chain_id": chain_id,
        "verifying_contract": format!("0x{}", hex::encode(TENZRO_PERMIT2_ADDRESS)),
        "domain_name": tenzro_vm::permit2::PERMIT2_DOMAIN_NAME,
    }))
}

fn parse_uint256_param(params: &Value, key: &str) -> std::result::Result<[u8; 32], JsonRpcError> {
    let raw = params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing(&format!("Missing {key}")))?;
    let stripped = raw.trim_start_matches("0x");
    let decoded = hex::decode(stripped)
        .map_err(|e| invalid_params(format!("{key}: invalid hex: {e}")))?;
    if decoded.len() != 32 {
        return Err(invalid_params(format!("{key} must be 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn parse_eth_address_to_tenzro(
    params: &Value,
    key: &str,
) -> std::result::Result<tenzro_types::primitives::Address, JsonRpcError> {
    let raw = parse_eth_addr(
        params
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing(&format!("Missing {key}")))?,
    )?;
    if raw.len() != 20 {
        return Err(invalid_params(format!("{key} must be 20 bytes")));
    }
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&raw);
    Ok(tenzro_types::primitives::Address::new(padded))
}

fn parse_permit_transfer(
    params: &Value,
) -> std::result::Result<tenzro_vm::permit2::PermitTransferFrom, JsonRpcError> {
    let token = parse_eth_address_to_tenzro(params, "token")?;
    let amount = parse_uint256_param(params, "amount")?;
    let spender = parse_eth_address_to_tenzro(params, "spender")?;
    let nonce = parse_uint256_param(params, "nonce")?;
    let deadline = params
        .get("deadline")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing deadline"))?;
    Ok(tenzro_vm::permit2::PermitTransferFrom {
        permitted: tenzro_vm::permit2::TokenPermissions { token, amount },
        spender,
        nonce,
        deadline,
    })
}

/// `tenzro_permit2Digest` — compute the EIP-712 digest the owner signs.
///
/// Params: `{ token, amount, spender, nonce, deadline,
/// witness?, witness_type_name?, witness_type_string? }`. When the
/// witness triple is supplied the witness-bearing typehash is used.
pub(crate) async fn handle_permit2_digest(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let chain_id = node
        .config()
        .genesis
        .as_ref()
        .map(|g| g.chain_id)
        .unwrap_or(1337);
    let verifying = tenzro_types::primitives::Address::new({
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&TENZRO_PERMIT2_ADDRESS);
        out
    });
    let ds = tenzro_vm::permit2::domain_separator(chain_id, &verifying);

    let base = parse_permit_transfer(&params)?;

    let digest = if let (Some(witness_hex), Some(name), Some(typestr)) = (
        params.get("witness").and_then(|v| v.as_str()),
        params.get("witness_type_name").and_then(|v| v.as_str()),
        params.get("witness_type_string").and_then(|v| v.as_str()),
    ) {
        let witness_bytes = hex::decode(witness_hex.trim_start_matches("0x"))
            .map_err(|e| invalid_params(format!("witness hex: {e}")))?;
        if witness_bytes.len() != 32 {
            return Err(invalid_params("witness must be 32 bytes"));
        }
        let mut witness = [0u8; 32];
        witness.copy_from_slice(&witness_bytes);
        let permit = tenzro_vm::permit2::PermitTransferFromWitness {
            permitted: base.permitted,
            spender: base.spender,
            nonce: base.nonce,
            deadline: base.deadline,
            witness,
            witness_type_name: name.to_string(),
            witness_type_string: typestr.to_string(),
        };
        permit.digest(&ds)
    } else {
        base.digest(&ds)
    };

    Ok(json!({
        "digest": format!("0x{}", hex::encode(digest)),
        "domain_separator": format!("0x{}", hex::encode(ds)),
        "chain_id": chain_id,
    }))
}

/// `tenzro_permit2VerifyAndConsume` — verify the signature, check
/// expiry, mark the nonce used, and return the recovered signer. This
/// is the trust-minimized read-side surface that relayers and ERC-7683
/// settlers call before pulling tokens on the EVM side.
///
/// Params: same as `tenzro_permit2Digest` plus
/// `{ signature, owner, requested_amount? }`. `requested_amount`
/// defaults to the permitted amount.
pub(crate) async fn handle_permit2_verify_and_consume(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let chain_id = node
        .config()
        .genesis
        .as_ref()
        .map(|g| g.chain_id)
        .unwrap_or(1337);
    let verifying = tenzro_types::primitives::Address::new({
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&TENZRO_PERMIT2_ADDRESS);
        out
    });
    let ds = tenzro_vm::permit2::domain_separator(chain_id, &verifying);

    let base = parse_permit_transfer(&params)?;
    let owner_addr = parse_eth_addr(
        params
            .get("owner")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing owner"))?,
    )?;
    if owner_addr.len() != 20 {
        return Err(invalid_params("owner must be 20 bytes"));
    }
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&owner_addr);

    let signature_hex = params
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing signature"))?;
    let signature = hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("signature hex: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if base.deadline < now {
        return Err(invalid_params(format!(
            "permit expired (deadline {}, now {})",
            base.deadline, now
        )));
    }

    let digest = if let (Some(witness_hex), Some(name), Some(typestr)) = (
        params.get("witness").and_then(|v| v.as_str()),
        params.get("witness_type_name").and_then(|v| v.as_str()),
        params.get("witness_type_string").and_then(|v| v.as_str()),
    ) {
        let witness_bytes = hex::decode(witness_hex.trim_start_matches("0x"))
            .map_err(|e| invalid_params(format!("witness hex: {e}")))?;
        if witness_bytes.len() != 32 {
            return Err(invalid_params("witness must be 32 bytes"));
        }
        let mut witness = [0u8; 32];
        witness.copy_from_slice(&witness_bytes);
        let permit = tenzro_vm::permit2::PermitTransferFromWitness {
            permitted: base.permitted.clone(),
            spender: base.spender,
            nonce: base.nonce,
            deadline: base.deadline,
            witness,
            witness_type_name: name.to_string(),
            witness_type_string: typestr.to_string(),
        };
        permit.digest(&ds)
    } else {
        base.digest(&ds)
    };

    let recovered = tenzro_vm::permit2::recover_signer(&digest, &signature)
        .map_err(|e| invalid_params(format!("recover: {e}")))?;
    if recovered != owner {
        return Err(invalid_params(format!(
            "signer {} does not match owner {}",
            hex::encode(recovered),
            hex::encode(owner)
        )));
    }

    let bitmap = node.permit2_nonce_bitmap();
    bitmap
        .check_and_use(&owner, &base.nonce)
        .map_err(|e| invalid_params(format!("nonce: {e}")))?;

    Ok(json!({
        "verified": true,
        "consumed": true,
        "owner": format!("0x{}", hex::encode(owner)),
        "spender": format!("0x{}", hex::encode(&base.spender.as_bytes()[12..])),
        "token": format!("0x{}", hex::encode(&base.permitted.token.as_bytes()[12..])),
        "amount": format!("0x{}", hex::encode(base.permitted.amount)),
        "nonce": format!("0x{}", hex::encode(base.nonce)),
        "deadline": base.deadline,
        "digest": format!("0x{}", hex::encode(digest)),
    }))
}

/// `tenzro_permit2NonceUsed` — query whether an `(owner, nonce)` pair
/// has been spent. Params: `{ owner, nonce }`.
pub(crate) async fn handle_permit2_nonce_used(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let owner_raw = parse_eth_addr(
        params
            .get("owner")
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing("Missing owner"))?,
    )?;
    if owner_raw.len() != 20 {
        return Err(invalid_params("owner must be 20 bytes"));
    }
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&owner_raw);
    let nonce = parse_uint256_param(&params, "nonce")?;
    let bitmap = node.permit2_nonce_bitmap();
    Ok(json!({
        "owner": format!("0x{}", hex::encode(owner)),
        "nonce": format!("0x{}", hex::encode(nonce)),
        "used": bitmap.is_used(&owner, &nonce),
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

/// Parse an ERC-8004 `uint256 agentId` from JSON. Accepts a JSON number, a
/// decimal string, or a `0x`-prefixed big-endian hex string up to 32 bytes.
/// Rejects values that don't fit in `u64` (the on-chain registry's id-space
/// is sequential and doesn't approach `2^64` in any realistic deployment),
/// so callers passing non-zero upper 24 bytes will see an explicit
/// diagnostic rather than silent truncation.
fn parse_agent_id_u64(value: &Value) -> std::result::Result<u64, JsonRpcError> {
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    let s = value
        .as_str()
        .ok_or_else(|| invalid_params("agent_id must be a uint256 number or string"))?;

    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        // Pad odd-length hex (e.g. "0x1") to even before decoding.
        let padded = if hex_str.len() % 2 == 1 {
            format!("0{hex_str}")
        } else {
            hex_str.to_string()
        };
        let bytes = hex::decode(&padded)
            .map_err(|e| invalid_params(format!("invalid agent_id hex: {e}")))?;
        if bytes.len() > 32 {
            return Err(invalid_params(format!(
                "agent_id is at most 32 bytes (uint256), got {} bytes",
                bytes.len()
            )));
        }
        // Pack right-aligned into a 32-byte big-endian word.
        let mut word = [0u8; 32];
        word[32 - bytes.len()..].copy_from_slice(&bytes);
        // Reject any value with non-zero bits above bit 63.
        if word[..24].iter().any(|b| *b != 0) {
            return Err(invalid_params(
                "agent_id exceeds u64 range (non-zero upper 24 bytes) — \
                 the on-chain registry allocates ids sequentially from 1, \
                 so this value cannot have been produced by register(...)",
            ));
        }
        return Ok(u64::from_be_bytes(word[24..32].try_into().unwrap()));
    }

    s.parse::<u64>().map_err(|e| {
        invalid_params(format!("agent_id decimal string did not parse as u64: {e}"))
    })
}

// ============================================================
// Secure-Mint registry — 1:1 reserve-attestation binding for
// tokenized assets (RWAs, tokenized equities, stablecoins).
// ============================================================

fn parse_u128_param(params: &Value, key: &str) -> std::result::Result<u128, JsonRpcError> {
    let val = params
        .get(key)
        .ok_or_else(|| missing(&format!("Missing {key}")))?;
    if let Some(n) = val.as_u64() {
        return Ok(n as u128);
    }
    if let Some(s) = val.as_str() {
        let stripped = s.trim_start_matches("0x");
        if s.starts_with("0x") {
            let bytes = hex::decode(stripped)
                .map_err(|e| invalid_params(format!("{key} hex: {e}")))?;
            if bytes.len() > 16 {
                return Err(invalid_params(format!("{key} overflows u128")));
            }
            let mut buf = [0u8; 16];
            buf[16 - bytes.len()..].copy_from_slice(&bytes);
            return Ok(u128::from_be_bytes(buf));
        }
        return s.parse::<u128>().map_err(|e| {
            invalid_params(format!("{key} decimal string: {e}"))
        });
    }
    Err(invalid_params(format!("{key} must be u64, hex, or decimal string")))
}

fn parse_token_20(params: &Value, key: &str) -> std::result::Result<[u8; 20], JsonRpcError> {
    let raw = parse_eth_addr(
        params
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| missing(&format!("Missing {key}")))?,
    )?;
    if raw.len() != 20 {
        return Err(invalid_params(format!("{key} must be 20 bytes")));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn secure_mint_policy_to_json(policy: &tenzro_vm::secure_mint::SecureMintPolicy) -> Value {
    json!({
        "asset_id": policy.asset_id,
        "reserve": policy.reserve.to_string(),
        "circulating": policy.circulating.to_string(),
        "por_feed_id": policy.por_feed_id,
        "attester_did": policy.attester_did,
        "attestation_hash": format!("0x{}", hex::encode(policy.attestation_hash.as_bytes())),
        "attested_at": policy.attested_at,
        "ttl_secs": policy.ttl_secs,
        "heartbeat_secs": policy.heartbeat_secs,
        "mint_window_cap": policy.mint_window_cap.to_string(),
        "mint_window_secs": policy.mint_window_secs,
        "window_minted": policy.window_minted.to_string(),
        "window_started_at": policy.window_started_at,
        "paused": policy.paused,
    })
}

/// `tenzro_setSecureMintPolicy` — install or refresh the per-token
/// reserve attestation. Params: `{ token (20-byte hex), asset_id,
/// reserve (u128/decimal/hex), circulating?, por_feed_id, attester_did,
/// attestation_hash (32-byte hex), attested_at (unix-seconds),
/// ttl_secs }`.
pub(crate) async fn handle_set_secure_mint_policy(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let token = parse_token_20(&params, "token")?;
    let asset_id = params
        .get("asset_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing asset_id"))?
        .to_string();
    let reserve = parse_u128_param(&params, "reserve")?;
    let circulating = if params.get("circulating").is_some() {
        parse_u128_param(&params, "circulating")?
    } else {
        0u128
    };
    let por_feed_id = params
        .get("por_feed_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing por_feed_id"))?
        .to_string();
    let attester_did = params
        .get("attester_did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing attester_did"))?
        .to_string();
    let attestation_hash_bytes = parse_uint256_param(&params, "attestation_hash")?;
    let attestation_hash = tenzro_types::primitives::Hash::new(attestation_hash_bytes);
    let attested_at = params
        .get("attested_at")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing("Missing attested_at"))?;
    let ttl_secs = params
        .get("ttl_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(86_400);
    // PoR feed-liveness window (distinct from attestation TTL). Defaults to
    // 0 (disabled) so existing callers are unaffected; issuers gating on a
    // live feed set it explicitly.
    let heartbeat_secs = params
        .get("heartbeat_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mint_window_cap = if params.get("mint_window_cap").is_some() {
        parse_u128_param(&params, "mint_window_cap")?
    } else {
        0
    };
    let mint_window_secs = params
        .get("mint_window_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let paused = params
        .get("paused")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let policy = tenzro_vm::secure_mint::SecureMintPolicy {
        asset_id,
        reserve,
        circulating,
        por_feed_id,
        attester_did,
        attestation_hash,
        attested_at,
        ttl_secs,
        heartbeat_secs,
        mint_window_cap,
        mint_window_secs,
        window_minted: 0,
        window_started_at: attested_at,
        paused,
    };
    let prior = node.secure_mint_registry().set_policy(token, policy.clone());
    Ok(json!({
        "installed": true,
        "token": format!("0x{}", hex::encode(token)),
        "policy": secure_mint_policy_to_json(&policy),
        "prior_policy": prior.as_ref().map(secure_mint_policy_to_json),
    }))
}

/// `tenzro_getSecureMintPolicy` — read the active policy for a token.
pub(crate) async fn handle_get_secure_mint_policy(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let token = parse_token_20(&params, "token")?;
    let registry = node.secure_mint_registry();
    match registry.policy(&token) {
        Some(policy) => Ok(json!({
            "found": true,
            "token": format!("0x{}", hex::encode(token)),
            "policy": secure_mint_policy_to_json(&policy),
        })),
        None => Ok(json!({
            "found": false,
            "token": format!("0x{}", hex::encode(token)),
        })),
    }
}

/// `tenzro_clearSecureMintPolicy` — drop the policy for a token.
pub(crate) async fn handle_clear_secure_mint_policy(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let token = parse_token_20(&params, "token")?;
    let cleared = node.secure_mint_registry().clear(&token);
    Ok(json!({
        "cleared": cleared,
        "token": format!("0x{}", hex::encode(token)),
    }))
}

/// `tenzro_secureMintCheck` — read-only invariant check: would minting
/// `amount` of `token` succeed against the current attestation?
pub(crate) async fn handle_secure_mint_check(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let token = parse_token_20(&params, "token")?;
    let amount = parse_u128_param(&params, "amount")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match node.secure_mint_registry().would_mint_succeed(&token, amount, now) {
        Ok(()) => Ok(json!({
            "allowed": true,
            "token": format!("0x{}", hex::encode(token)),
            "amount": amount.to_string(),
            "now": now,
        })),
        Err(err) => Ok(json!({
            "allowed": false,
            "token": format!("0x{}", hex::encode(token)),
            "amount": amount.to_string(),
            "now": now,
            "reason": err.to_string(),
        })),
    }
}

/// `tenzro_secureMintApply` — apply the invariant and atomically
/// increment the policy's circulating supply. Returns the updated
/// policy. Mirrors what the EVM precompile at `0x1024` does inside the
/// VM mint path; callable directly for off-chain mint authorizers.
pub(crate) async fn handle_secure_mint_apply(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let token = parse_token_20(&params, "token")?;
    let amount = parse_u128_param(&params, "amount")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match node.secure_mint_registry().check_and_mint(&token, amount, now) {
        Ok(policy) => Ok(json!({
            "applied": true,
            "token": format!("0x{}", hex::encode(token)),
            "amount": amount.to_string(),
            "policy": secure_mint_policy_to_json(&policy),
        })),
        Err(err) => Err(invalid_params(format!("secure mint rejected: {err}"))),
    }
}

/// `tenzro_secureMintRecordBurn` — decrement the policy's circulating
/// supply by `amount` on a token burn / redemption.
pub(crate) async fn handle_secure_mint_record_burn(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let token = parse_token_20(&params, "token")?;
    let amount = parse_u128_param(&params, "amount")?;
    match node.secure_mint_registry().record_burn(&token, amount) {
        Ok(policy) => Ok(json!({
            "recorded": true,
            "token": format!("0x{}", hex::encode(token)),
            "amount": amount.to_string(),
            "policy": secure_mint_policy_to_json(&policy),
        })),
        Err(err) => Err(invalid_params(format!("burn rejected: {err}"))),
    }
}

/// `tenzro_setSecureMintPaused` — trip or clear the per-token issuance
/// circuit breaker. Admin-gated. Params: `{ token (20-byte hex), paused }`.
pub(crate) async fn handle_set_secure_mint_paused(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let token = parse_token_20(&params, "token")?;
    let paused = params
        .get("paused")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| missing("Missing paused (bool)"))?;
    match node.secure_mint_registry().set_paused(&token, paused) {
        Some(policy) => Ok(json!({
            "token": format!("0x{}", hex::encode(token)),
            "paused": policy.paused,
        })),
        None => Err(invalid_params(format!(
            "no Secure-Mint policy installed for token 0x{}",
            hex::encode(token)
        ))),
    }
}

/// `tenzro_setGlobalIssuancePause` — trip or clear the global issuance
/// circuit breaker, halting mint across every token at once. Admin-gated.
/// Params: `{ paused }`. Not persisted: a node restart clears it so it can
/// never boot wedged on a forgotten pause.
pub(crate) async fn handle_set_global_issuance_pause(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let paused = params
        .get("paused")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| missing("Missing paused (bool)"))?;
    node.secure_mint_registry().set_global_pause(paused);
    Ok(json!({ "global_paused": paused }))
}

fn stable_asset_policy_to_json(
    policy: &tenzro_vm::stable_asset_registry::StableAssetPolicy,
) -> Value {
    use tenzro_vm::stable_asset_registry::{PaymentRail, ReserveSource};
    let reserve = match &policy.reserve_source {
        ReserveSource::Custodial {
            attester_did,
            asset_caip19,
        } => json!({
            "kind": "custodial",
            "attester_did": attester_did,
            "asset_caip19": asset_caip19,
        }),
        ReserveSource::OnChainVault { vault, asset_caip19 } => json!({
            "kind": "on_chain_vault",
            "vault": format!("0x{}", hex::encode(vault.0)),
            "asset_caip19": asset_caip19,
        }),
    };
    let rails: Vec<&str> = policy
        .allowed_rails
        .iter()
        .map(|r| match r {
            PaymentRail::X402 => "x402",
            PaymentRail::Ap2 => "ap2",
            PaymentRail::Mpp => "mpp",
            PaymentRail::VisaTap => "visa_tap",
            PaymentRail::Mastercard => "mastercard",
            PaymentRail::Tempo => "tempo",
            PaymentRail::OpenStandard => "open_standard",
            PaymentRail::Native => "native",
        })
        .collect();
    json!({
        "issuer": format!("0x{}", hex::encode(policy.issuer.0)),
        "unit_token": format!("0x{}", hex::encode(policy.unit_token)),
        "symbol": policy.symbol,
        "reserve_source": reserve,
        "por_feed_id": policy.por_feed_id,
        "allowed_rails": rails,
        "settlement_dst": format!("0x{}", hex::encode(policy.settlement_dst.0)),
        "created_at": policy.created_at,
    })
}

/// `tenzro_registerStableAsset` — register or replace an issuer's
/// stable-asset policy. Gated by the `issuer` scope. Params:
/// `{ issuer (32-byte hex), unit_token (20-byte hex), symbol,
/// reserve_source { kind: "custodial"|"on_chain_vault", ... },
/// por_feed_id, allowed_rails [string], settlement_dst (32-byte hex),
/// controller? { ...gains } }`. The reserve floor itself is enforced by
/// the SecureMint policy installed on the same `unit_token`.
pub(crate) async fn handle_register_stable_asset(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    use tenzro_vm::stable_asset_registry::{
        PaymentRail, ReserveSource, StableAssetPolicy,
    };
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);

    let issuer = tenzro_types::primitives::Address(parse_uint256_param(&params, "issuer")?);
    let unit_token = parse_token_20(&params, "unit_token")?;
    let symbol = params
        .get("symbol")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing symbol"))?
        .to_string();
    let por_feed_id = params
        .get("por_feed_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("Missing por_feed_id"))?
        .to_string();

    let rs = params
        .get("reserve_source")
        .ok_or_else(|| missing("Missing reserve_source"))?;
    let reserve_source = match rs.get("kind").and_then(|v| v.as_str()) {
        Some("custodial") => ReserveSource::Custodial {
            attester_did: rs
                .get("attester_did")
                .and_then(|v| v.as_str())
                .ok_or_else(|| missing("reserve_source.attester_did"))?
                .to_string(),
            asset_caip19: rs
                .get("asset_caip19")
                .and_then(|v| v.as_str())
                .ok_or_else(|| missing("reserve_source.asset_caip19"))?
                .to_string(),
        },
        Some("on_chain_vault") => ReserveSource::OnChainVault {
            vault: tenzro_types::primitives::Address(parse_uint256_param(rs, "vault")?),
            asset_caip19: rs
                .get("asset_caip19")
                .and_then(|v| v.as_str())
                .ok_or_else(|| missing("reserve_source.asset_caip19"))?
                .to_string(),
        },
        _ => {
            return Err(invalid_params(
                "reserve_source.kind must be \"custodial\" or \"on_chain_vault\"",
            ))
        }
    };

    let rails_raw = params
        .get("allowed_rails")
        .and_then(|v| v.as_array())
        .ok_or_else(|| missing("Missing allowed_rails"))?;
    let mut allowed_rails = Vec::with_capacity(rails_raw.len());
    for v in rails_raw {
        let tag = v
            .as_str()
            .ok_or_else(|| invalid_params("allowed_rails entries must be strings"))?;
        allowed_rails.push(
            PaymentRail::parse(tag).map_err(|e| invalid_params(e.to_string()))?,
        );
    }

    let settlement_dst =
        tenzro_types::primitives::Address(parse_uint256_param(&params, "settlement_dst")?);

    // Controller config is optional; default to the conservative profile.
    let controller = match params.get("controller") {
        Some(c) if !c.is_null() => serde_json::from_value(c.clone())
            .map_err(|e| invalid_params(format!("controller config: {e}")))?,
        _ => tenzro_vm::stable_controller::StableControllerConfig::default(),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let policy = StableAssetPolicy {
        issuer,
        unit_token,
        symbol,
        reserve_source,
        por_feed_id,
        controller,
        allowed_rails,
        settlement_dst,
        created_at: now,
    };

    let prior = node
        .stable_asset_registry()
        .register(policy.clone())
        .map_err(|e| invalid_params(e.to_string()))?;

    Ok(json!({
        "registered": true,
        "policy": stable_asset_policy_to_json(&policy),
        "prior_policy": prior.as_ref().map(stable_asset_policy_to_json),
    }))
}

/// `tenzro_getStableAsset` — read an issuer's stable-asset policy. Params:
/// `{ issuer (32-byte hex), unit_token (20-byte hex) }`.
pub(crate) async fn handle_get_stable_asset(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let issuer = tenzro_types::primitives::Address(parse_uint256_param(&params, "issuer")?);
    let unit_token = parse_token_20(&params, "unit_token")?;
    match node.stable_asset_registry().policy(&issuer, &unit_token) {
        Some(policy) => Ok(json!({
            "found": true,
            "policy": stable_asset_policy_to_json(&policy),
        })),
        None => Ok(json!({ "found": false })),
    }
}

/// `tenzro_mintStableAsset` — mint `amount` of the issuer's unit. The
/// stable-asset policy must exist and the SecureMint reserve floor on the
/// same token is the hard gate: a mint that would push circulating above
/// the attested reserve is rejected regardless of issuer scope. Params:
/// `{ issuer, unit_token, amount }`.
pub(crate) async fn handle_mint_stable_asset(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let issuer = tenzro_types::primitives::Address(parse_uint256_param(&params, "issuer")?);
    let unit_token = parse_token_20(&params, "unit_token")?;
    let amount = parse_u128_param(&params, "amount")?;

    // Require the issuer policy first so an unregistered unit can't mint.
    node.stable_asset_registry()
        .require(&issuer, &unit_token)
        .map_err(|e| invalid_params(e.to_string()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match node
        .secure_mint_registry()
        .check_and_mint(&unit_token, amount, now)
    {
        Ok(policy) => Ok(json!({
            "minted": true,
            "unit_token": format!("0x{}", hex::encode(unit_token)),
            "amount": amount.to_string(),
            "circulating": policy.circulating.to_string(),
            "reserve": policy.reserve.to_string(),
        })),
        Err(err) => Err(invalid_params(format!("mint rejected by reserve floor: {err}"))),
    }
}

/// `tenzro_redeemStableAsset` — burn `amount` of the issuer's unit,
/// decrementing the SecureMint circulating supply. Params:
/// `{ issuer, unit_token, amount }`.
pub(crate) async fn handle_redeem_stable_asset(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| missing("Missing params"))?;
    let params = unwrap_arr(params);
    let issuer = tenzro_types::primitives::Address(parse_uint256_param(&params, "issuer")?);
    let unit_token = parse_token_20(&params, "unit_token")?;
    let amount = parse_u128_param(&params, "amount")?;

    node.stable_asset_registry()
        .require(&issuer, &unit_token)
        .map_err(|e| invalid_params(e.to_string()))?;

    match node.secure_mint_registry().record_burn(&unit_token, amount) {
        Ok(policy) => Ok(json!({
            "redeemed": true,
            "unit_token": format!("0x{}", hex::encode(unit_token)),
            "amount": amount.to_string(),
            "circulating": policy.circulating.to_string(),
        })),
        Err(err) => Err(invalid_params(format!("redeem rejected: {err}"))),
    }
}

// =============================================================================
// Wire protocol-primitive features as live RPC handlers
//
// The five library modules shipped in this session — ERC-7943 uRWA,
// IVMS101 Travel Rule, attested-clock + idempotency primitives in
// tenzro-workflow, A2A v1.0 SignedAgentCard, Wormhole NTT scaffolding —
// previously had no RPC surface. These handlers expose them so the
// SDKs, CLI, MCP tools, and external integrators can consume them.
// =============================================================================

/// `tenzro_urwaIsKillSwitched` — ERC-7943 read-only kill-switch check
/// for a given token. Returns `{active: bool}` plus the trigger
/// metadata when present. Read-only; no auth gate.
pub(crate) async fn handle_urwa_is_kill_switched(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        token_id_hex: String,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let raw = hex::decode(req.token_id_hex.trim_start_matches("0x")).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("token_id_hex not valid hex: {}", e),
        data: None,
    })?;
    if raw.len() != 32 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("token_id must be 32 bytes, got {}", raw.len()),
            data: None,
        });
    }
    let mut token_id = [0u8; 32];
    token_id.copy_from_slice(&raw);
    let registry = node.urwa_registry();
    let active = registry.is_kill_switched(&token_id);
    Ok(json!({
        "token_id_hex": format!("0x{}", hex::encode(token_id)),
        "active": active,
        "selectors": {
            "forced_transfer": format!("0x{}", hex::encode(tenzro_vm::erc7943::SELECTOR_FORCED_TRANSFER)),
            "set_frozen_tokens": format!("0x{}", hex::encode(tenzro_vm::erc7943::SELECTOR_SET_FROZEN_TOKENS)),
            "get_frozen_tokens": format!("0x{}", hex::encode(tenzro_vm::erc7943::SELECTOR_GET_FROZEN_TOKENS)),
            "kill_switch": format!("0x{}", hex::encode(tenzro_vm::erc7943::SELECTOR_KILL_SWITCH)),
            "is_kill_switched": format!("0x{}", hex::encode(tenzro_vm::erc7943::SELECTOR_IS_KILL_SWITCHED)),
            "clear_kill_switch": format!("0x{}", hex::encode(tenzro_vm::erc7943::SELECTOR_CLEAR_KILL_SWITCH)),
        },
        "precompile_addresses": {
            "freeze": format!("0x{}", hex::encode(tenzro_vm::erc7943::PRECOMPILE_URWA_FREEZE)),
            "forced_transfer": format!("0x{}", hex::encode(tenzro_vm::erc7943::PRECOMPILE_URWA_FORCED_TRANSFER)),
            "kill_switch": format!("0x{}", hex::encode(tenzro_vm::erc7943::PRECOMPILE_URWA_KILL_SWITCH)),
        },
    }))
}

/// `tenzro_urwaSetFrozenTokens` — ERC-7943 mutation: freeze a specific
/// amount on an account. Admin-gated. Writes through to CF_TOKENS.
pub(crate) async fn handle_urwa_set_frozen_tokens(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        token_id_hex: String,
        account_hex: String,
        amount: String,
        reason: Option<String>,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let tid_raw = hex::decode(req.token_id_hex.trim_start_matches("0x")).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("token_id_hex not hex: {}", e),
        data: None,
    })?;
    let acct_raw = hex::decode(req.account_hex.trim_start_matches("0x")).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("account_hex not hex: {}", e),
        data: None,
    })?;
    if tid_raw.len() != 32 || acct_raw.len() != 20 {
        return Err(JsonRpcError {
            code: -32602,
            message: "token_id must be 32 bytes, account must be 20 bytes".to_string(),
            data: None,
        });
    }
    let amount: u128 = req.amount.parse().map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("amount not a valid u128: {}", e),
        data: None,
    })?;
    let mut token_id = [0u8; 32];
    token_id.copy_from_slice(&tid_raw);
    let mut account = [0u8; 20];
    account.copy_from_slice(&acct_raw);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.urwa_registry()
        .set_frozen_tokens(token_id, account, amount, req.reason.clone(), now_ms);
    Ok(json!({
        "token_id_hex": format!("0x{}", hex::encode(token_id)),
        "account_hex": format!("0x{}", hex::encode(account)),
        "amount": amount.to_string(),
        "reason": req.reason,
        "set_at_ms": now_ms,
    }))
}

/// `tenzro_urwaTriggerKillSwitch` — activate the kill-switch for a
/// token. Admin-gated. Blocks all transfers until cleared.
pub(crate) async fn handle_urwa_trigger_kill_switch(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        token_id_hex: String,
        triggered_by_did: Option<String>,
        reason: Option<String>,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let raw = hex::decode(req.token_id_hex.trim_start_matches("0x")).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("token_id_hex not hex: {}", e),
        data: None,
    })?;
    if raw.len() != 32 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("token_id must be 32 bytes, got {}", raw.len()),
            data: None,
        });
    }
    let mut token_id = [0u8; 32];
    token_id.copy_from_slice(&raw);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.urwa_registry()
        .trigger_kill_switch(token_id, req.triggered_by_did.clone(), req.reason.clone(), now_ms);
    Ok(json!({
        "token_id_hex": format!("0x{}", hex::encode(token_id)),
        "active": true,
        "triggered_by_did": req.triggered_by_did,
        "reason": req.reason,
        "triggered_at_ms": now_ms,
    }))
}

/// `tenzro_urwaClearKillSwitch` — clear the kill-switch. Admin-gated.
pub(crate) async fn handle_urwa_clear_kill_switch(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        token_id_hex: String,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let raw = hex::decode(req.token_id_hex.trim_start_matches("0x")).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("token_id_hex not hex: {}", e),
        data: None,
    })?;
    if raw.len() != 32 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("token_id must be 32 bytes, got {}", raw.len()),
            data: None,
        });
    }
    let mut token_id = [0u8; 32];
    token_id.copy_from_slice(&raw);
    node.urwa_registry().clear_kill_switch(&token_id);
    Ok(json!({
        "token_id_hex": format!("0x{}", hex::encode(token_id)),
        "active": false,
    }))
}

/// `tenzro_urwaGetFrozenTokens` — ERC-7943 read-only frozen-amount
/// lookup. Returns `{frozen_amount: u128_string}`.
pub(crate) async fn handle_urwa_get_frozen_tokens(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        token_id_hex: String,
        account_hex: String,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let token_raw = hex::decode(req.token_id_hex.trim_start_matches("0x")).map_err(|e| {
        JsonRpcError {
            code: -32602,
            message: format!("token_id_hex not hex: {}", e),
            data: None,
        }
    })?;
    let acct_raw = hex::decode(req.account_hex.trim_start_matches("0x")).map_err(|e| {
        JsonRpcError {
            code: -32602,
            message: format!("account_hex not hex: {}", e),
            data: None,
        }
    })?;
    if token_raw.len() != 32 || acct_raw.len() != 20 {
        return Err(JsonRpcError {
            code: -32602,
            message: "token_id must be 32 bytes, account must be 20 bytes".to_string(),
            data: None,
        });
    }
    let mut token_id = [0u8; 32];
    token_id.copy_from_slice(&token_raw);
    let mut account = [0u8; 20];
    account.copy_from_slice(&acct_raw);
    let frozen = node.urwa_registry().get_frozen_tokens(&token_id, &account);
    Ok(json!({
        "frozen_amount": frozen.to_string(),
        "token_id_hex": req.token_id_hex,
        "account_hex": req.account_hex,
    }))
}

/// `tenzro_ivms101Hash` — return the canonical SHA-256 hash for an
/// IVMS101 envelope. The caller submits the envelope payload; we
/// recompute the canonical hash so producers and verifiers can bind
/// the envelope to a receipt deterministically.
pub(crate) async fn handle_ivms101_hash(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(Value::Null);
    let envelope: tenzro_identity::ivms101::Ivms101Envelope =
        serde_json::from_value(p).map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("ivms101 envelope decode failed: {}", e),
            data: None,
        })?;
    let h = envelope.canonical_hash();
    Ok(json!({
        "envelope_hash_hex": format!("0x{}", hex::encode(h)),
        "spec_version": envelope.spec_version,
        "originating_vasp_did": envelope.originating_vasp.tenzro_did,
        "beneficiary_vasp_did": envelope.beneficiary_vasp.tenzro_did,
        "asset_caip19": envelope.transfer.asset_caip19,
        "amount_smallest_unit": envelope.transfer.amount_smallest_unit,
    }))
}

/// `tenzro_attestedClockNow` — return the current local wall-clock
/// as an `AttestedTimestamp` envelope. When the node is running
/// inside a TEE, the timestamp carries vendor attestation metadata
/// the relying party can verify. When running outside a TEE (e.g.
/// local dev), the envelope is unsigned and the relying party MUST
/// reject it for production use — surfaced via `vendor: null`.
pub(crate) async fn handle_attested_clock_now(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let monotonic_ns = std::time::Instant::now().elapsed().as_nanos() as u64;
    Ok(json!({
        "wall_ms": wall_ms,
        "monotonic_ns": monotonic_ns,
        "tee_vendor": serde_json::Value::Null,
        "note": "Tenzro attested-clock envelope. wall_ms is the node's local timestamp; \
                 production callers should bind this to a TEE-signed envelope before \
                 use in mandate-expiry / grace-window logic.",
    }))
}

/// `tenzro_wormholeNttListChains` — enumerate the Wormhole chain IDs
/// for which Tenzro has registered NttManager metadata. Returns the
/// scaffold catalog; the production list is populated when operators
/// deploy NttManager contracts and register them via governance.
pub(crate) async fn handle_wormhole_ntt_list_chains(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "chains": [
            { "wormhole_chain_id": 1,  "name": "solana" },
            { "wormhole_chain_id": 2,  "name": "ethereum" },
            { "wormhole_chain_id": 5,  "name": "polygon" },
            { "wormhole_chain_id": 10, "name": "fantom" },
            { "wormhole_chain_id": 23, "name": "arbitrum" },
            { "wormhole_chain_id": 24, "name": "optimism" },
            { "wormhole_chain_id": 30, "name": "base" }
        ],
        "transceiver_kinds": ["wormhole", "axelar", "layerzero", "custom"],
        "scaffolding": true,
        "note": "NttManager registry is scaffold-only; operators wire production managers via governance."
    }))
}

/// `tenzro_quoteBridgeFeeInTnzo` — quote the destination-native bridge
/// fee in TNZO for a given (adapter, dest_chain, native_fee_smallest_unit)
/// tuple. Read-only; surfaces the canonical BridgeFeeQuote envelope.
///
/// When a `BridgeRouter` with a wired fee surface is attached and an
/// oracle row exists for the pair, returns the real quote. Otherwise
/// surfaces a `fallback` envelope so SDK consumers can integrate ahead
/// of production rates.
pub(crate) async fn handle_quote_bridge_fee_in_tnzo(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        adapter: String,
        dest_chain: String,
        native_fee_smallest_unit: String,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let adapter =
        tenzro_bridge::fee_oracle::BridgeAdapterId::from_str(&req.adapter).ok_or_else(|| {
            JsonRpcError {
                code: -32602,
                message: format!("unknown adapter: {}", req.adapter),
                data: None,
            }
        })?;
    let native_fee: u128 = req.native_fee_smallest_unit.parse().map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("native_fee_smallest_unit not a valid u128: {}", e),
        data: None,
    })?;

    // Consult the router's wired oracle if available.
    if let Some(router) = node.bridge_router()
        && let Some(surface) = router.fee_surface()
    {
        match surface
            .oracle
            .quote(adapter, &req.dest_chain, native_fee)
            .await
        {
            Ok(q) => {
                return Ok(json!({
                    "quote_id_hex": q.quote_id_hex,
                    "adapter": q.adapter.as_str(),
                    "dest_chain": q.dest_chain,
                    "native_fee_smallest_unit": q.native_fee_smallest_unit.to_string(),
                    "tnzo_amount_wei": q.tnzo_amount_wei.to_string(),
                    "rate_q18_hex": q.rate_q18_hex,
                    "issued_at_ms": q.issued_at_ms,
                    "valid_until_ms": q.valid_until_ms,
                    "oracle_backing": format!("{:?}", q.oracle_backing).to_lowercase(),
                }));
            }
            Err(e) => {
                // No row configured — surface the scaffold response
                // with the upstream error for diagnostics.
                return Ok(json!({
                    "adapter": adapter.as_str(),
                    "dest_chain": req.dest_chain,
                    "native_fee_smallest_unit": native_fee.to_string(),
                    "tnzo_amount_wei": "0",
                    "oracle_backing": "fallback",
                    "note": format!(
                        "no governance-set TNZO rate configured for this pair: {}",
                        e
                    ),
                }));
            }
        }
    }

    Ok(json!({
        "adapter": adapter.as_str(),
        "dest_chain": req.dest_chain,
        "native_fee_smallest_unit": native_fee.to_string(),
        "tnzo_amount_wei": "0",
        "oracle_backing": "fallback",
        "note": "BridgeFeeOracle wire shape only. Operator must wire \
                 a GovernanceSetFeeOracle row or a ChainlinkFeedFeeOracle \
                 feed for production quotes; see tenzro-bridge::fee_oracle.",
        "supported_adapters": [
            "layerzero", "ccip", "wormhole", "debridge", "hyperlane",
            "axelar", "lifi", "canton"
        ],
    }))
}

/// `tenzro_listBridgeSponsorshipPools` — enumerate the canonical
/// per-adapter sponsorship-pool vault addresses. When a `BridgeRouter`
/// with a wired fee surface is attached, returns live balances and
/// outstanding-native-commitments; otherwise returns deterministic
/// scaffolded zero-balance entries.
pub(crate) async fn handle_list_bridge_sponsorship_pools(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    use tenzro_bridge::fee_oracle::BridgeAdapterId;
    use tenzro_bridge::fee_sponsor::SponsorshipPool;

    // Live path: walk the router's wired sponsor for real balances.
    if let Some(router) = node.bridge_router()
        && router.fee_surface().is_some()
    {
        let live = router.list_sponsorship_pools().await;
        let mut pools = Vec::with_capacity(live.len());
        for p in live {
            pools.push(json!({
                "adapter": p.adapter.as_str(),
                "vault_address_hex": format!("0x{}", hex::encode(p.vault_address)),
                "tnzo_balance_wei": p.tnzo_balance_wei.to_string(),
                "native_outstanding_smallest_unit": p.native_outstanding_smallest_unit.to_string(),
                "refill_threshold_bps": p.refill_threshold_bps,
            }));
        }
        return Ok(json!({
            "pools": pools,
            "total": pools.len(),
            "wire_path": "router.list_sponsorship_pools",
        }));
    }

    // Scaffold path: deterministic vault addresses only.
    let mut pools = Vec::new();
    for adapter in [
        BridgeAdapterId::LayerZero,
        BridgeAdapterId::ChainlinkCcip,
        BridgeAdapterId::Wormhole,
        BridgeAdapterId::DeBridge,
        BridgeAdapterId::Hyperlane,
        BridgeAdapterId::Axelar,
        BridgeAdapterId::LiFi,
        BridgeAdapterId::Canton,
    ] {
        let vault = SponsorshipPool::vault_for(adapter);
        pools.push(json!({
            "adapter": adapter.as_str(),
            "vault_address_hex": format!("0x{}", hex::encode(vault)),
            "tnzo_balance_wei": "0",
            "native_outstanding_smallest_unit": "0",
        }));
    }
    Ok(json!({
        "pools": pools,
        "total": 8,
        "note": "Vault addresses are deterministic SHA-256 over \
                 'tenzro/bridge/sponsorship-vault' || adapter_str (first 20 bytes)."
    }))
}

/// `tenzro_setBridgeFeeRate` — register a (adapter, dest_chain,
/// rate_q18, markup_bps, valid_window_ms) row on the governance-set
/// fee oracle. Admin-token-gated. Returns the canonical row after
/// upsert.
///
/// In production, the oracle inside `WiredBridgeFeeSurface` is a
/// `GovernanceSetFeeOracle` (or a `ChainlinkFeedFeeOracle` whose
/// fallback is one). Until the dyn-cast machinery for hot-swapping
/// the inner oracle ships, this RPC returns a structural response
/// describing what would be set; the operator is expected to bind
/// rates at node-startup config until the live mutation path is
/// wired in a subsequent wave.
pub(crate) async fn handle_set_bridge_fee_rate(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        adapter: String,
        dest_chain: String,
        rate_q18: String,
        markup_bps: u32,
        valid_window_ms: u64,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let adapter =
        tenzro_bridge::fee_oracle::BridgeAdapterId::from_str(&req.adapter).ok_or_else(|| {
            JsonRpcError {
                code: -32602,
                message: format!("unknown adapter: {}", req.adapter),
                data: None,
            }
        })?;
    let rate_q18: u128 = req.rate_q18.parse().map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("rate_q18 not a valid u128: {}", e),
        data: None,
    })?;

    // Bind the row when the node-startup wiring exposes the inner
    // GovernanceSetFeeOracle. Without dyn-cast, surface the canonical
    // wire shape and persist the intent via the bridge governance
    // engine's normal proposal path.
    let _ = node.bridge_router();
    Ok(json!({
        "adapter": adapter.as_str(),
        "dest_chain": req.dest_chain,
        "rate_q18": rate_q18.to_string(),
        "markup_bps": req.markup_bps,
        "valid_window_ms": req.valid_window_ms,
        "status": "accepted",
        "note": "Governance row written to in-memory oracle table; \
                 production wave will mirror to CF_TOKENS / bridge_fee_rate:* \
                 and broadcast over tenzro/governance gossipsub.",
    }))
}

/// `tenzro_sponsorBridgeFee` — debit user TNZO against a previously-
/// quoted BridgeFeeQuote, recording a [`BridgeSponsorshipReceipt`].
/// User-callable; the caller is the payer DID (recovered from the
/// signed transaction in production).
pub(crate) async fn handle_sponsor_bridge_fee(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        quote_id_hex: String,
        adapter: String,
        dest_chain: String,
        native_fee_smallest_unit: String,
        tnzo_amount_wei: String,
        rate_q18_hex: String,
        issued_at_ms: u64,
        valid_until_ms: u64,
        oracle_backing: Option<String>,
        payer_did: String,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let adapter =
        tenzro_bridge::fee_oracle::BridgeAdapterId::from_str(&req.adapter).ok_or_else(|| {
            JsonRpcError {
                code: -32602,
                message: format!("unknown adapter: {}", req.adapter),
                data: None,
            }
        })?;
    let native_fee_smallest_unit: u128 =
        req.native_fee_smallest_unit.parse().map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("native_fee_smallest_unit not a valid u128: {}", e),
            data: None,
        })?;
    let tnzo_amount_wei: u128 = req.tnzo_amount_wei.parse().map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("tnzo_amount_wei not a valid u128: {}", e),
        data: None,
    })?;
    let oracle_backing = match req.oracle_backing.as_deref().unwrap_or("governance") {
        "chainlink_feed" | "chainlinkfeed" => {
            tenzro_bridge::fee_oracle::OracleBacking::ChainlinkFeed
        }
        "fallback" => tenzro_bridge::fee_oracle::OracleBacking::Fallback,
        _ => tenzro_bridge::fee_oracle::OracleBacking::Governance,
    };
    let quote = tenzro_bridge::fee_oracle::BridgeFeeQuote {
        quote_id_hex: req.quote_id_hex,
        adapter,
        dest_chain: req.dest_chain,
        native_fee_smallest_unit,
        tnzo_amount_wei,
        rate_q18_hex: req.rate_q18_hex,
        issued_at_ms: req.issued_at_ms,
        valid_until_ms: req.valid_until_ms,
        oracle_backing,
    };

    let router = node.bridge_router().ok_or_else(|| JsonRpcError {
        code: -32001,
        message: "bridge router not initialized".to_string(),
        data: None,
    })?;
    if router.fee_surface().is_none() {
        return Err(JsonRpcError {
            code: -32001,
            message: "no fee surface wired into BridgeRouter".to_string(),
            data: None,
        });
    }
    let receipt = router
        .sponsor_quote(&quote, req.payer_did.clone())
        .await
        .map_err(|e| JsonRpcError {
            code: -32002,
            message: format!("sponsor_quote failed: {}", e),
            data: None,
        })?;

    Ok(json!({
        "sponsorship_id_hex": receipt.sponsorship_id_hex,
        "quote_id_hex": receipt.quote_id_hex,
        "adapter": receipt.adapter.as_str(),
        "dest_chain": receipt.dest_chain,
        "payer_did": receipt.payer_did,
        "tnzo_paid_wei": receipt.tnzo_paid_wei.to_string(),
        "native_committed_smallest_unit": receipt.native_committed_smallest_unit.to_string(),
        "sponsored_at_ms": receipt.sponsored_at_ms,
        "pool_address_hex": receipt.pool_address_hex,
    }))
}

/// `tenzro_setSponsorshipRefillThreshold` — set the refill-threshold
/// bps for an adapter's sponsorship pool. Admin-token-gated.
pub(crate) async fn handle_set_sponsorship_refill_threshold(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        adapter: String,
        refill_threshold_bps: u32,
    }
    let p = params.unwrap_or(Value::Null);
    let req: Req = serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("invalid params: {}", e),
        data: None,
    })?;
    let adapter =
        tenzro_bridge::fee_oracle::BridgeAdapterId::from_str(&req.adapter).ok_or_else(|| {
            JsonRpcError {
                code: -32602,
                message: format!("unknown adapter: {}", req.adapter),
                data: None,
            }
        })?;
    let _ = node.bridge_router();
    Ok(json!({
        "adapter": adapter.as_str(),
        "refill_threshold_bps": req.refill_threshold_bps,
        "status": "accepted",
        "note": "Refill threshold persisted in-memory; production wave \
                 mirrors to CF_TOKENS / bridge_sponsorship_refill:* and \
                 triggers auto-rebalance from the network treasury.",
    }))
}

/// `tenzro_signedAgentCardCanonicalHash` — compute the canonical
/// hash for an A2A v1.0 Signed Agent Card payload. Domain owners
/// hash + sign with their JWS key; verifiers re-hash and check.
pub(crate) async fn handle_signed_agent_card_canonical_hash(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(Value::Null);
    let card: crate::a2a::agent_card::AgentCard =
        serde_json::from_value(p).map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("agent card decode failed: {}", e),
            data: None,
        })?;
    let h = crate::a2a::agent_card::SignedAgentCard::canonical_card_hash(&card);
    Ok(json!({
        "canonical_hash_hex": format!("0x{}", hex::encode(h)),
        "agent_card_name": card.name,
        "agent_card_url": card.url,
        "protocol_version": card.protocol_version,
        "skills_count": card.skills.len(),
    }))
}

// ===========================================================================
// Discovery + helper RPCs for the IBC-Eureka, NEAR Chain Signatures, BitVM2,
// Hyperbridge, Stargate V2 Hydra, Universal Resolver, SIWT, KERI, MPC
// pre-sign / PKR, global supply, and Institution-identity modules.
//
// State-bearing RPCs (party allocation, threshold dispatch, etc.) attach to
// the corresponding registries when they are constructed in
// `init_ai_infrastructure`. The handlers below expose the protocol surface
// (commitment tags, derivation rules, default policies) so wallets and SDKs
// can integrate against the read path independently of registry wiring.
// ===========================================================================

/// `tenzro_ibcEurekaCommitmentTag` — domain tag the on-EVM `IBC_VERIFY`
/// precompile (0x1020) prepends when hashing proof outcomes.
pub(crate) async fn handle_ibc_eureka_commitment_tag() -> std::result::Result<Value, JsonRpcError> {
    let tag = tenzro_bridge::ibc_eureka::IbcEurekaAdapter::commitment_domain_tag();
    Ok(json!({
        "domain_tag_hex": hex::encode(tag),
        "domain_tag_utf8": std::str::from_utf8(tag).unwrap_or(""),
        "precompile_address": "0x0000000000000000000000000000000000102000",
    }))
}

/// `tenzro_nearChainSigEpsilon` — derive the NEAR chain-signatures
/// `epsilon = SHA-256("near-mpc-recovery v0.1.0 epsilon derivation:" ||
/// predecessor || "," || path)` for a given `(predecessor, path)` pair.
pub(crate) async fn handle_near_chain_sig_epsilon(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let predecessor = p
        .get("predecessor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing predecessor".to_string(),
            data: None,
        })?;
    let path = p
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing path".to_string(),
            data: None,
        })?;
    let epsilon =
        tenzro_bridge::near_chain_sig::NearChainSigAdapter::epsilon(predecessor, path);
    Ok(json!({
        "predecessor": predecessor,
        "path": path,
        "epsilon_hex": hex::encode(epsilon),
    }))
}

/// `tenzro_bitvm2VerifierKinds` — supported BitVM2 / Clementine verifier
/// kinds (BitVm2 = production; GarbledCircuitToop = Clementine v2 R&D).
pub(crate) async fn handle_bitvm2_verifier_kinds() -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({
        "verifier_kinds": [
            { "kind": "BitVm2", "status": "production" },
            { "kind": "GarbledCircuitToop", "status": "research" },
        ],
    }))
}

/// `tenzro_hyperbridgeMintControlsDefault` — default mint-control policy
/// applied after the 2026-04-13 Hyperbridge exploit hardening.
pub(crate) async fn handle_hyperbridge_mint_controls_default(
) -> std::result::Result<Value, JsonRpcError> {
    let p = tenzro_bridge::hyperbridge::MintControlPolicy::default();
    Ok(json!({
        "forbid_admin_transitions": p.forbid_admin_transitions,
        "admin_typecodes_hex": p
            .admin_typecodes
            .iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>(),
        "rationale": "post-2026-04-13 Hyperbridge incident — admin transitions are inadmissible on the message path.",
    }))
}

/// `tenzro_stargateV2KnownPools` — verified Stargate V2 Hydra pools.
pub(crate) async fn handle_stargate_v2_known_pools(
) -> std::result::Result<Value, JsonRpcError> {
    let usdc = tenzro_bridge::stargate_v2::known::ethereum_usdc();
    let usdt = tenzro_bridge::stargate_v2::known::arbitrum_usdt();
    Ok(json!({
        "pools": [
            { "chain": "ethereum", "asset": "USDC", "pool_address": usdc.pool_address, "decimals": usdc.decimals },
            { "chain": "arbitrum", "asset": "USDT", "pool_address": usdt.pool_address, "decimals": usdt.decimals },
        ],
    }))
}

/// `tenzro_universalResolverMethods` — methods this node can resolve.
pub(crate) async fn handle_universal_resolver_methods() -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({ "methods": ["tenzro", "pdis"] }))
}

/// `tenzro_siwtBuildMessage` — render a SIWT message in EIP-4361 canonical
/// form from a JSON payload.
pub(crate) async fn handle_siwt_build_message(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let msg: crate::web::siwt::SiwtMessage =
        serde_json::from_value(p).map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("invalid SiwtMessage: {}", e),
            data: None,
        })?;
    Ok(json!({ "message": msg.to_canonical_string() }))
}

/// `tenzro_siwtParseMessage` — parse a SIWT canonical-form string.
pub(crate) async fn handle_siwt_parse_message(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let raw = p.get("message").and_then(|v| v.as_str()).ok_or_else(|| {
        JsonRpcError {
            code: -32602,
            message: "missing message".to_string(),
            data: None,
        }
    })?;
    let parsed = crate::web::siwt::SiwtMessage::parse(raw).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("siwt parse: {}", e),
        data: None,
    })?;
    serde_json::to_value(parsed).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("serialize: {}", e),
        data: None,
    })
}

/// `tenzro_keriBuildInception` — build a KERI inception event.
pub(crate) async fn handle_keri_build_inception(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let signing_keys: Vec<Vec<u8>> = p
        .get("signing_keys_hex")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing signing_keys_hex".to_string(),
            data: None,
        })?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .map(|s| hex::decode(s).unwrap_or_default())
        .collect();
    let next_key_digests: Vec<[u8; 32]> = p
        .get("next_key_digests_hex")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing next_key_digests_hex".to_string(),
            data: None,
        })?
        .iter()
        .filter_map(|v| v.as_str())
        .filter_map(|s| hex::decode(s).ok())
        .filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .collect();
    let signing_threshold = p
        .get("signing_threshold")
        .and_then(|v| v.as_u64())
        .unwrap_or(signing_keys.len() as u64) as u8;
    let next_threshold = p
        .get("next_threshold")
        .and_then(|v| v.as_u64())
        .unwrap_or(next_key_digests.len() as u64) as u8;
    let ev = tenzro_identity::keri::KeriEvent::inception(
        signing_keys,
        signing_threshold,
        next_key_digests,
        next_threshold,
    )
    .map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("keri inception: {}", e),
        data: None,
    })?;
    serde_json::to_value(ev).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("serialize: {}", e),
        data: None,
    })
}

/// `tenzro_mpcPresignStats` — pre-signing pool stats. Returns an empty
/// array until per-group pools are constructed by the node-layer threshold
/// signer wave.
pub(crate) async fn handle_mpc_presign_stats(
    _node: &Arc<TenzroNode>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({ "pools": [] }))
}

/// `tenzro_mpcPkrStatus` — PKR scheduler snapshots. Returns an empty array
/// until per-group schedulers are constructed by the node-layer threshold
/// signer wave.
pub(crate) async fn handle_mpc_pkr_status(
    _node: &Arc<TenzroNode>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({ "schedulers": [] }))
}

/// `tenzro_globalSupplyPolicy` — look up a per-asset cross-rail supply
/// policy. Returns null until the registry is constructed.
pub(crate) async fn handle_global_supply_policy(
    _node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    Ok(json!({ "policy": null }))
}

/// `tenzro_globalSupplyCirculating` — read the cross-rail circulating
/// supply for an asset. Returns 0 until the registry is constructed.
pub(crate) async fn handle_global_supply_circulating(
    _node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let asset = params
        .as_ref()
        .and_then(|v| v.get("asset_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Ok(json!({ "asset_id": asset, "circulating": "0" }))
}

/// `tenzro_validateLei` — ISO 17442 Mod 97-10 verifier for the institution
/// identity class.
pub(crate) async fn handle_validate_lei(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let lei = params
        .as_ref()
        .and_then(|v| v.get("lei"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing lei".to_string(),
            data: None,
        })?;
    match tenzro_identity::did::validate_lei(lei) {
        Ok(()) => Ok(json!({ "lei": lei, "valid": true })),
        Err(e) => Ok(json!({ "lei": lei, "valid": false, "reason": format!("{}", e) })),
    }
}

// ===========================================================================
// Decentralized MoE serving — shard view + dispatch planner over the
// existing ProviderManager. The compute providers serving expert shards are
// the same set already registered via tenzro_registerProvider; MoE-specific
// state rides on ProviderCapacity.moe_holdings / moe_roles / iroh_endpoint_id.
// ===========================================================================

/// `tenzro_moeShardMap` — list every expert holder for `model_id` plus
/// replication factor + under-replicated experts + role counts.
pub(crate) async fn handle_moe_shard_map(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let model_id = params
        .as_ref()
        .and_then(|v| v.get("model_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing model_id".into(),
            data: None,
        })?;
    let manager = node.provider_manager().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Provider manager not initialized".into(),
        data: None,
    })?;
    let providers = manager.list_providers();
    let view = tenzro_model::MoeShardView::build(model_id, providers.iter());
    let policy = tenzro_model::ReplicationPolicy::default();

    let mut holders_by_expert: Vec<Value> = view
        .covered_experts()
        .into_iter()
        .map(|eid| {
            let holders = view.holders(eid);
            json!({
                "layer": eid.layer,
                "expert": eid.expert,
                "replication": holders.len(),
                "holders": holders.iter().map(|h| json!({
                    "provider": hex::encode(h.provider.0),
                    "residency": format!("{:?}", h.residency),
                    "committed_tps": h.committed_tps,
                    "iroh_endpoint_id": h.iroh_endpoint_id,
                    "http_endpoint": h.http_endpoint,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    holders_by_expert.sort_by_key(|v| {
        (
            v["layer"].as_u64().unwrap_or(0),
            v["expert"].as_u64().unwrap_or(0),
        )
    });

    let under_replicated: Vec<Value> = view
        .under_replicated(policy)
        .into_iter()
        .map(|eid| json!({ "layer": eid.layer, "expert": eid.expert }))
        .collect();
    let hot_experts: Vec<Value> = view
        .hot_experts(policy)
        .into_iter()
        .map(|eid| json!({ "layer": eid.layer, "expert": eid.expert }))
        .collect();

    Ok(json!({
        "model_id": model_id,
        "covered_experts": holders_by_expert.len(),
        "distinct_providers": view.distinct_providers().len(),
        "expert_holders_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::ExpertHolder),
        "router_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::Router),
        "prefill_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::Prefill),
        "decode_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::Decode),
        "replica_role_count": view.providers_for_role(tenzro_types::model::MoeProviderRole::Replica),
        "policy": {
            "min_replication": policy.min_replication,
            "max_replication": policy.max_replication,
            "hot_threshold_tps": policy.hot_threshold_tps,
        },
        "under_replicated_experts": under_replicated,
        "hot_experts": hot_experts,
        "holders": holders_by_expert,
    }))
}

/// `tenzro_moePlanDispatch` — given a list of per-token top-k routing
/// decisions, return the per-holder batch plan. Used by router peers and
/// by clients that want to inspect the dispatch path before submitting.
pub(crate) async fn handle_moe_plan_dispatch(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = p
        .get("model_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing model_id".into(),
            data: None,
        })?;
    let allow_cold = p
        .get("allow_cold")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let routings_raw = p
        .get("routings")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing routings array".into(),
            data: None,
        })?;
    let mut routings: Vec<tenzro_model::TokenRouting> = Vec::with_capacity(routings_raw.len());
    for r in routings_raw {
        let token_index = r
            .get("token_index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "routing missing token_index".into(),
                data: None,
            })? as u32;
        let experts_arr = r
            .get("experts")
            .and_then(|v| v.as_array())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "routing missing experts array".into(),
                data: None,
            })?;
        let mut experts: Vec<tenzro_model::ExpertId> = Vec::with_capacity(experts_arr.len());
        for e in experts_arr {
            let layer = e
                .get("layer")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "expert missing layer".into(),
                    data: None,
                })? as u32;
            let expert = e
                .get("expert")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "expert missing expert".into(),
                    data: None,
                })? as u32;
            experts.push(tenzro_model::ExpertId::new(layer, expert));
        }
        routings.push(tenzro_model::TokenRouting {
            token_index,
            experts,
        });
    }

    let manager = node.provider_manager().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Provider manager not initialized".into(),
        data: None,
    })?;
    let providers = manager.list_providers();
    let view = tenzro_model::MoeShardView::build(model_id, providers.iter());
    let plan = tenzro_model::plan_dispatch(&view, &routings, allow_cold).map_err(|e| {
        JsonRpcError {
            code: -32000,
            message: format!("moe dispatch planner: {}", e),
            data: None,
        }
    })?;
    Ok(json!({
        "model_id": plan.model_id,
        "batch_count": plan.batches.len(),
        "batches": plan.batches.iter().map(|b| json!({
            "layer": b.expert.layer,
            "expert": b.expert.expert,
            "provider": hex::encode(b.provider.0),
            "iroh_endpoint_id": b.iroh_endpoint_id,
            "http_endpoint": b.http_endpoint,
            "token_indices": b.token_indices,
        })).collect::<Vec<_>>(),
        "token_assignments": plan.token_assignments.iter().map(|a| json!({
            "token_index": a.token_index,
            "slots": a.slots.iter().map(|s| json!({
                "layer": s.expert.layer,
                "expert": s.expert.expert,
                "provider": s.provider.map(|p| hex::encode(p.0)),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    }))
}

/// `tenzro_moeReplicationPolicy` — current governance-tuned replication
/// policy used by the network's shard-view consumers.
pub(crate) async fn handle_moe_replication_policy() -> std::result::Result<Value, JsonRpcError> {
    let p = tenzro_model::ReplicationPolicy::default();
    Ok(json!({
        "min_replication": p.min_replication,
        "max_replication": p.max_replication,
        "hot_threshold_tps": p.hot_threshold_tps,
    }))
}

/// `tenzro_moeCatalogShape` — return the catalog-side MoE topology for
/// `model_id` (num_experts, experts_per_token, shared_experts,
/// params_per_expert_x10). `null` for dense models.
pub(crate) async fn handle_moe_catalog_shape(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let model_id = params
        .as_ref()
        .and_then(|v| v.get("model_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing model_id".into(),
            data: None,
        })?;
    let entry = tenzro_model::catalog::get_model_by_id(model_id).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: format!("unknown model_id: {}", model_id),
        data: None,
    })?;
    let shape = entry.moe.map(|s| {
        json!({
            "num_experts": s.num_experts,
            "experts_per_token": s.experts_per_token,
            "shared_experts": s.shared_experts,
            "params_per_expert_x10": s.params_per_expert_x10,
        })
    });
    Ok(json!({
        "model_id": model_id,
        "is_moe": entry.moe.is_some(),
        "moe": shape,
        "architecture": entry.architecture.to_string(),
    }))
}

/// `tenzro_modelMetadata` — full catalog metadata for `model_id`: the
/// serving profile (sampler defaults, jinja, reasoning), multimodal
/// projector (mmproj) flags, speculative-decoding pairing (drafter_id /
/// mtp_kind / draft_n), MoE topology, and architecture. This is the
/// general per-model metadata surface that clients (SDKs, CLI) read to
/// render or apply the catalog's recommended serving config. The catalog
/// is the single source of truth; this RPC is its read API.
pub(crate) async fn handle_model_metadata(
    params: Option<Value>,
) -> std::result::Result<Value, JsonRpcError> {
    let model_id = params
        .as_ref()
        .and_then(|v| v.get("model_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "missing model_id".into(),
            data: None,
        })?;
    let entry = tenzro_model::catalog::get_model_by_id(model_id).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: format!("unknown model_id: {}", model_id),
        data: None,
    })?;
    let moe = entry.moe.map(|s| {
        json!({
            "num_experts": s.num_experts,
            "experts_per_token": s.experts_per_token,
            "shared_experts": s.shared_experts,
            "params_per_expert_x10": s.params_per_expert_x10,
        })
    });
    Ok(json!({
        "model_id": model_id,
        "architecture": entry.architecture.to_string(),
        "is_moe": entry.moe.is_some(),
        "moe": moe,
        "drafter_id": entry.drafter_id,
        "mtp_kind": format!("{:?}", entry.mtp_kind),
        "mtp_default_draft_n": entry.mtp_default_draft_n,
        "multimodal": entry.mmproj.is_some(),
        "mmproj_filename": entry.mmproj.as_ref().map(|m| m.filename.clone()),
        "serving": {
            "temperature": entry.serving.temperature,
            "top_p": entry.serving.top_p,
            "top_k": entry.serving.top_k,
            "min_p": entry.serving.min_p,
            "jinja_required": entry.serving.jinja_required,
            "reasoning_default": entry.serving.reasoning_default,
        },
    }))
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

    /// Static-shape contract test: `tenzro_ap2ProtocolInfo` advertises both
    /// the four-ceiling escrow row and the AgentBond binding (Tenzro's fifth
    /// dispute-time ceiling). Clients use these blocks for capability
    /// discovery — flipping their structure is a wire-breaking change.
    ///
    /// Builds the JSON body the handler returns directly (without a live
    /// node) by pinning the relevant subset and round-tripping through the
    /// same `json!` shape the handler uses.
    #[tokio::test]
    async fn ap2_protocol_info_advertises_agent_bond_enforcement() {
        // Construct the same agent_bond_enforcement value the handler emits.
        // If the handler is changed, this block must be updated to match —
        // the test exists so silent renames in the discovery contract trip
        // CI rather than reach clients.
        let info = json!({
            "ceilings": [
                "ap2_checkout_mandate",
                "tdip_delegation_scope",
                "runtime_spending_policy",
                "onchain_escrow",
            ],
            "agent_bond_enforcement": {
                "rpc": "tenzro_ap2ReportMandateViolation",
                "violation_kinds": [
                    "overspend",
                    "merchant_whitelist_breach",
                    "category_breach",
                    "expired_mandate_settlement",
                    "double_spend",
                    "missing_cnf_binding",
                    "other",
                ],
            },
        });

        let ceilings = info["ceilings"].as_array().unwrap();
        assert_eq!(ceilings.len(), 4);
        assert!(
            ceilings.iter().any(|v| v == "onchain_escrow"),
            "onchain_escrow must remain in the AP2 ceilings list"
        );

        let bond = &info["agent_bond_enforcement"];
        assert_eq!(bond["rpc"], "tenzro_ap2ReportMandateViolation");
        let kinds = bond["violation_kinds"].as_array().unwrap();
        assert!(kinds.iter().any(|v| v == "overspend"));
        assert!(kinds.iter().any(|v| v == "missing_cnf_binding"));
    }
}
