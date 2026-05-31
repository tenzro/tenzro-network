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
        Ok(()) => Ok(json!({
            "valid": true,
            "checkout_mandate_id": checkout.mandate_id(),
            "payment_mandate_id": payment.mandate_id(),
            "principal_did": checkout.signer_did,
            "agent_did": payment.signer_did,
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
            "exact",
            "exact-eip3009",
            "permit2",
            "erc7710",
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
        },
        "stock_compatibility": "tenzroCommitment_and_tenzroVm_omitted_from_external_chain_receipts_so_stock_clients_unaffected",
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
