//! Agent Authorization Profile (AAP) — IETF draft-aap-oauth-profile-01.
//!
//! AAP is a profile of OAuth 2.1 + DPoP that adds seven `aap_*` JWT
//! claims describing **what** an agent token authorizes, **who** issued
//! it, **how** it should be overseen, and **what** delegation chain
//! produced it. The profile complements (does not replace) RAR
//! ([`crate::AuthorizationDetails`]) — RAR pins typed scopes, AAP pins
//! purpose, oversight, delegation, and audit.
//!
//! ## The seven claims
//!
//! | Claim | Role |
//! |-------|------|
//! | `aap_agent` | Identity and runtime metadata for the bearing agent |
//! | `aap_task` | The specific purpose this token authorizes (RS verifies request matches) |
//! | `aap_capabilities` | List of `{action, constraints}` grants — refines RAR with per-action constraints |
//! | `aap_oversight` | Which actions require human approval before signing |
//! | `aap_delegation` | Position in act-chain: depth, max_depth, chain[], parent_jti |
//! | `aap_context` | Network zone, time window, geo restriction |
//! | `aap_audit` | Trace id, session id, log level for observability |
//!
//! ## Why both RAR and AAP?
//!
//! RAR answers "is this action *type* in scope?" — Transfer, CreateEscrow,
//! Inference, etc. with per-type constraints (max_amount, allowed_chains,
//! allowed_counterparties).
//!
//! AAP adds three orthogonal layers RAR doesn't model:
//!
//! 1. **Purpose binding** (`aap_task`) — even if RAR permits Transfer up
//!    to 100 TNZO, AAP can pin "this token is for paying invoice
//!    INV-2026-0042" so a stolen token can't be drained on unrelated
//!    transfers.
//! 2. **Oversight policy** (`aap_oversight`) — a token can permit Stake
//!    in RAR but require human approval per AAP. The engine surfaces
//!    `AuthorityDecision::RequireApproval` for any action listed in
//!    `aap_oversight.requires_human_approval_for`.
//! 3. **Delegation chain** (`aap_delegation`) — depth, parent_jti, full
//!    chain. Token Exchange (RFC 8693) increments depth and enforces
//!    capability subset.
//!
//! All AAP fields are **optional**. A token without any `aap_*` claims is
//! a plain RAR token — fully valid for callers that don't need AAP
//! semantics.

use crate::rar::AuthorizationDetail;
use serde::{Deserialize, Serialize};

/// `aap_agent` — identity and runtime metadata.
///
/// Captured at issuance from the bearer's TDIP DID record. The RS does
/// **not** trust these fields independently — they're descriptive, used
/// for audit. The cryptographic binding lives in `cnf.jkt` + `sub`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AapAgentClaim {
    /// Bearer DID (mirror of `claims.sub` for self-contained tokens).
    pub id: String,

    /// One of `"human" | "delegated_agent" | "autonomous_agent"`.
    /// Mirrors the discriminator in TDIP `IdentityData`.
    #[serde(rename = "type")]
    pub agent_type: String,

    /// Operator DID — the human or upstream agent that this agent acts
    /// on behalf of. Mirror of `claims.controller_did`. Equal to `id`
    /// for autonomous agents.
    pub operator: String,

    /// Optional model identifier — the AI model backing this agent.
    /// Free-form (e.g., `"gemma3-270m"`, `"claude-opus-4-7"`); used by
    /// observability tooling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Optional runtime identifier — what software stack the agent runs
    /// on (e.g., `"tenzro-agent-runtime/0.1"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

/// `aap_task` — purpose binding.
///
/// **Mandatory in production AAP tokens.** The RS verifies that the
/// inbound request matches the declared purpose: e.g., a token whose
/// `aap_task.id = "pay-invoice-INV-2026-0042"` should not be used to
/// trigger an unrelated outbound bridge transfer. Verification is policy
/// — the RS picks how strict the match is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AapTaskClaim {
    /// Stable identifier for the task (e.g., `"pay-invoice-INV-2026-0042"`,
    /// `"forecast-stock-AAPL"`, `"settle-channel-0xabc"`). RS-defined.
    pub id: String,

    /// Free-form short description of the task in human terms.
    /// Surfaced to oversight UIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional URI pointing at the canonical task record (e.g., an
    /// invoice URL, a spec doc, a project ticket).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// Optional opaque correlation id for cross-system tracing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// `aap_capabilities` — a single action grant with constraints.
///
/// AAP capability `action` strings follow the ABNF
/// `component *("." component)`, no wildcards. Examples:
/// `"payments.transfer"`, `"inference.invoke"`, `"escrow.create"`.
///
/// `constraints` is RS-defined free-form JSON. Tenzro maps it to
/// `ResourceConstraint`-style fields when adjudicating against a
/// concrete request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AapCapabilityClaim {
    /// Dotted action name. Must not contain wildcards (`*`, `?`).
    pub action: String,

    /// Per-action constraints. Shape is RS-defined; Tenzro recognizes
    /// the keys documented in [`AapConstraints`].
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub constraints: serde_json::Value,
}

/// Tenzro's recognized constraint keys for `aap_capabilities[].constraints`.
///
/// All fields are optional. Unknown keys are ignored at adjudication
/// time — the engine only enforces what it understands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AapConstraints {
    /// Maximum value per single action invocation, in base units of the
    /// associated asset. Encoded as decimal string for u128 safety.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value: Option<String>,

    /// Whitelist of asset ids permitted by this capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_assets: Option<Vec<String>>,

    /// Whitelist of chain ids (numeric) the action may target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_chains: Option<Vec<u64>>,

    /// Whitelist of payment-protocol identifiers (e.g.,
    /// `["mpp", "x402", "ap2"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_protocols: Option<Vec<String>>,

    /// Whitelist of counterparty addresses (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_counterparties: Option<Vec<String>>,

    /// Whitelist of resource ids — e.g., model_ids for inference,
    /// proposal_ids for vote, escrow_ids for discharge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_resources: Option<Vec<String>>,
}

impl AapConstraints {
    /// Decode constraints from a `serde_json::Value`. Returns `Default`
    /// (all `None`) if the value is `null` or shape doesn't match.
    pub fn from_value(v: &serde_json::Value) -> Self {
        serde_json::from_value(v.clone()).unwrap_or_default()
    }
}

/// `aap_oversight` — which actions require human approval.
///
/// When a request matches an action listed in
/// `requires_human_approval_for`, the engine creates an
/// [`crate::ApprovalRecord`] and returns
/// [`crate::AuthorityDecision::RequireApproval`] instead of `Permit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AapOversightClaim {
    /// List of dotted action names that always require approval, even
    /// if RAR + AAP capabilities permit them. Subset of the
    /// `aap_capabilities[].action` set.
    #[serde(default)]
    pub requires_human_approval_for: Vec<String>,

    /// DID of the approver (typically a human). If unset, the engine
    /// defaults to `claims.controller_did`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_did: Option<String>,

    /// How long approval requests stay open before auto-expiring.
    /// Defaults to 3600s if unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ttl_secs: Option<u64>,
}

/// `aap_delegation` — position in the act-chain.
///
/// Token Exchange (RFC 8693) is the only mechanism for incrementing
/// `depth`. Every exchange MUST: increment `depth` by 1, append the
/// child's bearer DID to `chain`, set `parent_jti` to the parent token's
/// `jti`, ensure `depth <= max_depth`, ensure the child's capabilities
/// are a strict subset of the parent's, and ensure the child's `exp` is
/// `<=` the parent's `exp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AapDelegationClaim {
    /// Current depth in the chain. `0` for the root token.
    pub depth: u32,

    /// Maximum depth permitted by the root issuer. Children are
    /// rejected at the AS once `depth + 1 > max_depth`.
    pub max_depth: u32,

    /// Ordered list of bearer DIDs from root to current bearer
    /// (inclusive of both). `chain[0]` is the root issuer's principal,
    /// `chain[depth] == claims.sub`.
    #[serde(default)]
    pub chain: Vec<String>,

    /// `jti` of the parent token. `None` for the root token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_jti: Option<String>,
}

impl AapDelegationClaim {
    /// Build a root-token delegation claim (depth=0, no parent).
    pub fn root(bearer_did: impl Into<String>, max_depth: u32) -> Self {
        let did = bearer_did.into();
        Self {
            depth: 0,
            max_depth,
            chain: vec![did],
            parent_jti: None,
        }
    }

    /// Build a child delegation claim from a parent. Returns `Err` if
    /// `parent.depth + 1 > parent.max_depth`.
    pub fn child(
        parent: &AapDelegationClaim,
        child_bearer_did: impl Into<String>,
        parent_jti: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let new_depth = parent.depth.saturating_add(1);
        if new_depth > parent.max_depth {
            return Err("delegation depth would exceed max_depth");
        }
        let mut chain = parent.chain.clone();
        chain.push(child_bearer_did.into());
        Ok(Self {
            depth: new_depth,
            max_depth: parent.max_depth,
            chain,
            parent_jti: Some(parent_jti.into()),
        })
    }
}

/// `aap_context` — operational context.
///
/// Informational unless explicitly enforced by the RS. Tenzro enforces
/// `time_window.exp` (must be `<= claims.exp`); other fields are
/// surfaced to audit logs only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AapContextClaim {
    /// Free-form network zone identifier (e.g., `"testnet"`, `"prod-eu"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_zone: Option<String>,

    /// Optional inner time window — narrows the validity from
    /// `(claims.nbf, claims.exp)` to `(time_window.nbf, time_window.exp)`.
    /// Both bounds are Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<AapTimeWindow>,

    /// Optional ISO-3166 country code list — RS may reject if the
    /// request's source IP geolocates outside the list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_restriction: Option<Vec<String>>,
}

/// Inner time window inside `aap_context`. Tenzro enforces the
/// invariant `time_window.exp <= claims.exp` on issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AapTimeWindow {
    /// Lower bound, Unix seconds.
    pub nbf: u64,
    /// Upper bound, Unix seconds.
    pub exp: u64,
}

/// `aap_audit` — observability hooks.
///
/// All fields are informational. The engine forwards them to
/// `tracing::span` so logs and traces correlate across systems.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AapAuditClaim {
    /// `"trace" | "debug" | "info" | "warn" | "error"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,

    /// W3C Trace Context trace-id (32 hex chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    /// Application-defined session id — typically maps onto an
    /// `MppSession` or external workflow run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Validate that an action name follows AAP ABNF: `component *("." component)`,
/// no wildcards, no whitespace, ASCII-printable.
pub fn is_valid_action_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    let mut prev_dot = false;
    for c in s.chars() {
        match c {
            '.' => {
                if prev_dot {
                    return false; // no consecutive dots
                }
                prev_dot = true;
            }
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => {
                prev_dot = false;
            }
            _ => return false,
        }
    }
    true
}

/// Look up the AAP action name corresponding to a RAR
/// [`AuthorizationDetail`] — used when adjudicating an
/// [`crate::AuthorityRequest`] against `aap_capabilities`.
///
/// Mapping is fixed:
/// - `Transfer` → `"payments.transfer"`
/// - `CreateEscrow` → `"escrow.create"`
/// - `DischargeEscrow` → `"escrow.discharge"`
/// - `Inference` → `"inference.invoke"`
/// - `Stake` → `"staking.stake"`
/// - `Vote` → `"governance.vote"`
/// - `Contract` → `"contract.call"`
/// - `RegisterIdentity` → `"identity.register"`
pub fn rar_to_aap_action(detail: &AuthorizationDetail) -> &'static str {
    match detail {
        AuthorizationDetail::Transfer { .. } => "payments.transfer",
        AuthorizationDetail::CreateEscrow { .. } => "escrow.create",
        AuthorizationDetail::DischargeEscrow { .. } => "escrow.discharge",
        AuthorizationDetail::Inference { .. } => "inference.invoke",
        AuthorizationDetail::Stake { .. } => "staking.stake",
        AuthorizationDetail::Vote { .. } => "governance.vote",
        AuthorizationDetail::Contract { .. } => "contract.call",
        AuthorizationDetail::RegisterIdentity { .. } => "identity.register",
    }
}

/// Look up the AAP action name for a [`crate::AuthorityAction`] —
/// the inbound-request flavor of [`rar_to_aap_action`].
pub fn authority_action_to_aap(action: crate::AuthorityAction) -> &'static str {
    use crate::AuthorityAction as A;
    match action {
        A::Transfer => "payments.transfer",
        A::CreateEscrow => "escrow.create",
        A::DischargeEscrow => "escrow.discharge",
        A::Inference => "inference.invoke",
        A::Stake => "staking.stake",
        A::Vote => "governance.vote",
        A::Contract => "contract.call",
        A::RegisterIdentity => "identity.register",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_name_abnf_accepts_valid() {
        assert!(is_valid_action_name("payments.transfer"));
        assert!(is_valid_action_name("inference.invoke"));
        assert!(is_valid_action_name("a"));
        assert!(is_valid_action_name("a.b.c.d"));
        assert!(is_valid_action_name("snake_case.kebab-case"));
    }

    #[test]
    fn action_name_abnf_rejects_invalid() {
        assert!(!is_valid_action_name(""));
        assert!(!is_valid_action_name("."));
        assert!(!is_valid_action_name(".leading"));
        assert!(!is_valid_action_name("trailing."));
        assert!(!is_valid_action_name("double..dot"));
        assert!(!is_valid_action_name("has space"));
        assert!(!is_valid_action_name("wildcard.*"));
        assert!(!is_valid_action_name("wildcard.?"));
        assert!(!is_valid_action_name("special!chars"));
    }

    #[test]
    fn delegation_root_starts_at_depth_zero() {
        let root = AapDelegationClaim::root("did:tenzro:human:abc", 5);
        assert_eq!(root.depth, 0);
        assert_eq!(root.max_depth, 5);
        assert_eq!(root.chain, vec!["did:tenzro:human:abc"]);
        assert!(root.parent_jti.is_none());
    }

    #[test]
    fn delegation_child_increments_and_appends() {
        let root = AapDelegationClaim::root("did:tenzro:human:abc", 3);
        let child = AapDelegationClaim::child(&root, "did:tenzro:machine:def", "parent-jti-1").unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.max_depth, 3);
        assert_eq!(child.chain, vec!["did:tenzro:human:abc", "did:tenzro:machine:def"]);
        assert_eq!(child.parent_jti.as_deref(), Some("parent-jti-1"));
    }

    #[test]
    fn delegation_child_rejects_past_max_depth() {
        let mut current = AapDelegationClaim::root("did:tenzro:human:abc", 1);
        current = AapDelegationClaim::child(&current, "did:tenzro:machine:def", "p1").unwrap();
        // depth=1, max=1 — one more should fail.
        let err = AapDelegationClaim::child(&current, "did:tenzro:machine:ghi", "p2");
        assert!(err.is_err());
    }

    #[test]
    fn rar_to_aap_action_covers_all_variants() {
        use tenzro_types::{AssetId, Address};
        // Smoke test — instantiate every variant and check mapping.
        let asset = AssetId::tnzo();
        let addr = Address::new([0u8; 32]);
        let cases: Vec<(AuthorizationDetail, &str)> = vec![
            (
                AuthorizationDetail::Transfer {
                    asset: asset.clone(),
                    max_amount: 100,
                    max_daily_amount: None,
                    allowed_counterparties: None,
                },
                "payments.transfer",
            ),
            (
                AuthorizationDetail::CreateEscrow {
                    asset: asset.clone(),
                    max_amount: 100,
                    allowed_payees: None,
                },
                "escrow.create",
            ),
            (
                AuthorizationDetail::DischargeEscrow {
                    allowed_escrow_ids: None,
                },
                "escrow.discharge",
            ),
            (
                AuthorizationDetail::Inference {
                    max_amount_per_call: 100,
                    max_daily_amount: None,
                    allowed_model_ids: None,
                },
                "inference.invoke",
            ),
            (
                AuthorizationDetail::Stake {
                    max_amount: 100,
                    allowed_validators: None,
                },
                "staking.stake",
            ),
            (
                AuthorizationDetail::Vote {
                    allowed_proposals: None,
                },
                "governance.vote",
            ),
            (
                AuthorizationDetail::Contract {
                    allowed_contracts: Some(vec![addr]),
                    allow_deploy: false,
                },
                "contract.call",
            ),
            (
                AuthorizationDetail::RegisterIdentity { max_children: None },
                "identity.register",
            ),
        ];
        for (detail, expected) in cases {
            assert_eq!(rar_to_aap_action(&detail), expected);
        }
    }

    #[test]
    fn aap_constraints_round_trip_via_value() {
        let original = AapConstraints {
            max_value: Some("1000000000000000000".to_string()),
            allowed_assets: Some(vec!["TNZO".to_string()]),
            allowed_chains: Some(vec![1337, 1]),
            allowed_protocols: Some(vec!["mpp".to_string(), "x402".to_string()]),
            allowed_counterparties: None,
            allowed_resources: None,
        };
        let v = serde_json::to_value(&original).unwrap();
        let decoded = AapConstraints::from_value(&v);
        assert_eq!(decoded, original);
    }

    #[test]
    fn aap_constraints_unknown_keys_decode_as_default() {
        let v = serde_json::json!({"unknown_field": 42});
        let decoded = AapConstraints::from_value(&v);
        // Unknown keys ignored; fields default to None.
        assert!(decoded.max_value.is_none());
        assert!(decoded.allowed_chains.is_none());
    }
}
