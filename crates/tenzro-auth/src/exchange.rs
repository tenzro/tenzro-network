//! RFC 8693 OAuth 2.0 Token Exchange — delegated child-token issuance.
//!
//! Token Exchange is **the only mechanism** by which an agent's
//! authority is passed onwards to another agent. A bearer of a parent
//! JWT calls [`AuthEngine::exchange_token`] (defined in
//! `crate::engine`) supplying a *requested* RAR envelope and AAP
//! capability set; the engine validates that the request is a strict
//! subset of the parent's authority, then mints a child JWT with:
//!
//! - `controller_did = parent.sub` (the parent agent acts as
//!   controller of the child token),
//! - `aap_delegation` advanced via
//!   [`crate::aap::AapDelegationClaim::child`] (depth+1, chain
//!   appended, `parent_jti` set),
//! - `authorization_details` and `aap_capabilities` narrowed to the
//!   requested subset (cannot widen the parent),
//! - `exp <= parent.exp` so the child cannot outlive the parent.
//!
//! Token exchange is **monotonic**: a child can never grant more than
//! its parent. If a parent is revoked, every child issued under it is
//! transitively revoked via the existing cascading-revocation index
//! ([`crate::AuthEngine::revoke`]).
//!
//! ## Why a separate module
//!
//! Subset enforcement is non-trivial — `AuthorizationDetail` has eight
//! variants each with optional whitelist/limit fields. Rather than
//! inlining the comparison into `AuthEngine`, we split the
//! variant-by-variant logic into pure functions that are
//! independently testable and documented. The HTTP-layer
//! `/oauth/token?grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
//! handler in `tenzro-node::web::oauth` parses the RFC 8693 request
//! body, pulls the parent JWT + DPoP proof off the wire, and forwards
//! into [`AuthEngine::exchange_token`].
//!
//! ## RFC 8693 mapping
//!
//! | RFC 8693 field | Tenzro mapping |
//! |---|---|
//! | `subject_token` | Parent JWT (validated via `validate_jwt`) |
//! | `subject_token_type` | Always `urn:ietf:params:oauth:token-type:jwt` |
//! | `requested_token_type` | Always `urn:ietf:params:oauth:token-type:jwt` |
//! | `actor_token` | Unused — we encode delegation in `aap_delegation.chain` instead |
//! | `audience` | Mirrored to child's `aud`; must match parent's `aud` |
//! | `scope` | Rejected — Tenzro tokens have no `scope`, only RAR + AAP |
//! | `resource` | Rejected — V1 has a single resource server (`aud`) |
//!
//! `actor_token` is the RFC 8693 way to express "agent A is acting on
//! behalf of agent B" via two nested tokens. Tenzro encodes the same
//! information lossless-ly in a single token's `aap_delegation.chain`,
//! so we drop `actor_token` and use the cleaner representation.

use crate::aap::{rar_to_aap_action, AapCapabilityClaim, AapDelegationClaim};
use crate::error::{AuthError, Result};
use crate::rar::{AuthorizationDetail, AuthorizationDetails};
use tenzro_types::Address;

/// Inputs to [`crate::AuthEngine::exchange_token`].
///
/// Construct with [`Self::new`] and apply the optional fields via the
/// builder methods. The engine pulls the parent JWT + DPoP proof from
/// its own validation path; this struct describes only the *requested*
/// child token.
#[derive(Debug, Clone)]
pub struct TokenExchangeRequest {
    /// DID of the child agent that will bear the new token. Must
    /// already be registered in the local TDIP identity registry; the
    /// engine looks up its delegation scope.
    pub child_bearer_did: String,

    /// SHA-256 thumbprint (RFC 7638) of the child's DPoP key.
    pub child_dpop_jkt: String,

    /// RAR envelope the child wants. Each detail must be covered by
    /// some detail in the parent's
    /// [`AuthClaims::authorization_details`](crate::AuthClaims::authorization_details).
    pub requested_rar: AuthorizationDetails,

    /// AAP capability subset the child wants. Each requested
    /// capability `action` must appear in the parent's
    /// `aap_capabilities`, and each requested constraint must be
    /// narrower than (or equal to) the parent's constraint for the
    /// same action.
    pub requested_aap_capabilities: Vec<AapCapabilityClaim>,

    /// Requested child TTL in seconds. Clamped to the engine's
    /// `[1, max_ttl_secs]` window **and** capped at
    /// `parent.exp - now`. If `None`, the engine uses
    /// `min(default_ttl_secs, parent.exp - now)`.
    pub requested_ttl_secs: Option<u64>,
}

impl TokenExchangeRequest {
    /// Build a new request with required fields. Capabilities default
    /// to empty (RAR-only child); add via
    /// [`Self::with_aap_capabilities`].
    pub fn new(
        child_bearer_did: impl Into<String>,
        child_dpop_jkt: impl Into<String>,
        requested_rar: AuthorizationDetails,
    ) -> Self {
        Self {
            child_bearer_did: child_bearer_did.into(),
            child_dpop_jkt: child_dpop_jkt.into(),
            requested_rar,
            requested_aap_capabilities: Vec::new(),
            requested_ttl_secs: None,
        }
    }

    /// Set the AAP capability subset the child should bear.
    pub fn with_aap_capabilities(mut self, caps: Vec<AapCapabilityClaim>) -> Self {
        self.requested_aap_capabilities = caps;
        self
    }

    /// Set the requested child lifetime.
    pub fn with_ttl(mut self, ttl_secs: u64) -> Self {
        self.requested_ttl_secs = Some(ttl_secs);
        self
    }
}

/// Successful output of a token exchange.
#[derive(Debug, Clone)]
pub struct TokenExchangeOutcome {
    /// The newly minted child JWT.
    pub access_token: String,
    /// Child token lifetime, in seconds.
    pub expires_in: u64,
    /// Child's `aap_delegation` claim — surface to callers that need
    /// to know the new depth without re-decoding the JWT.
    pub delegation: AapDelegationClaim,
}

/// Verify that `child_rar` is a subset of `parent_rar` — every grant
/// in the child must be **strictly covered** by some grant in the
/// parent.
///
/// "Strictly covered" depends on the variant; see
/// [`detail_covers`] for the per-variant rules. An empty child RAR
/// is always a valid subset (a token that can do nothing privileged
/// is trivially narrower than any parent).
pub fn rar_is_subset(parent: &AuthorizationDetails, child: &AuthorizationDetails) -> Result<()> {
    for (i, child_detail) in child.details.iter().enumerate() {
        let covered = parent
            .details
            .iter()
            .any(|parent_detail| detail_covers(parent_detail, child_detail));
        if !covered {
            return Err(AuthError::DelegationViolation(format!(
                "child authorization_details[{}] ({}) not covered by any parent grant",
                i,
                rar_to_aap_action(child_detail),
            )));
        }
    }
    Ok(())
}

/// Returns `true` iff `parent` strictly covers `child` — i.e. every
/// concrete request the child can authorize, the parent could already
/// have authorized.
///
/// Rules per variant:
///
/// - **Same variant required.** A `Transfer` parent does not cover a
///   `Stake` child even if dollar-equivalent.
/// - **`max_amount` / `max_amount_per_call` / `max_daily_amount`:**
///   child's value must be `<= parent's`. Parent `None` means
///   "unbounded" (everything covered); child `None` against parent
///   `Some(v)` means "child is unbounded, parent is bounded" → fails.
/// - **Allowlists (counterparties, payees, validators, model_ids,
///   contracts, escrow_ids, proposals):** child's allowlist must be
///   a subset of parent's. Parent `None` means "unrestricted"
///   (everything covered); child `None` against parent `Some(_)`
///   means "child has no restriction, parent does" → fails.
/// - **`Inference`:** if parent has `allowed_model_ids`, child must
///   too, and child's set ⊆ parent's set.
/// - **`Contract.allow_deploy`:** child may deploy only if parent may.
/// - **`RegisterIdentity.max_children`:** same `<=` semantics as
///   amount fields.
/// - **`ResourceInvocation.class`:** parent `None` covers any class;
///   otherwise child must name the same class.
pub fn detail_covers(parent: &AuthorizationDetail, child: &AuthorizationDetail) -> bool {
    use AuthorizationDetail as D;
    match (parent, child) {
        (
            D::Transfer {
                asset: pa,
                max_amount: pm,
                max_daily_amount: pdm,
                allowed_counterparties: pcp,
            },
            D::Transfer {
                asset: ca,
                max_amount: cm,
                max_daily_amount: cdm,
                allowed_counterparties: ccp,
            },
        ) => {
            pa == ca
                && cm <= pm
                && covers_optional_max(*pdm, *cdm)
                && covers_optional_allowlist(pcp, ccp)
        }
        (
            D::CreateEscrow {
                asset: pa,
                max_amount: pm,
                allowed_payees: ppayees,
            },
            D::CreateEscrow {
                asset: ca,
                max_amount: cm,
                allowed_payees: cpayees,
            },
        ) => pa == ca && cm <= pm && covers_optional_allowlist(ppayees, cpayees),
        (
            D::DischargeEscrow {
                allowed_escrow_ids: pe,
            },
            D::DischargeEscrow {
                allowed_escrow_ids: ce,
            },
        ) => covers_optional_allowlist_bytes32(pe, ce),
        (
            D::Inference {
                max_amount_per_call: pmc,
                max_daily_amount: pdm,
                allowed_model_ids: pmids,
            },
            D::Inference {
                max_amount_per_call: cmc,
                max_daily_amount: cdm,
                allowed_model_ids: cmids,
            },
        ) => {
            cmc <= pmc
                && covers_optional_max(*pdm, *cdm)
                && covers_optional_allowlist_str(pmids, cmids)
        }
        (
            D::Stake {
                max_amount: pm,
                allowed_validators: pv,
            },
            D::Stake {
                max_amount: cm,
                allowed_validators: cv,
            },
        ) => cm <= pm && covers_optional_allowlist(pv, cv),
        (
            D::Vote {
                allowed_proposals: pp,
            },
            D::Vote {
                allowed_proposals: cp,
            },
        ) => covers_optional_allowlist_str(pp, cp),
        (
            D::Contract {
                allowed_contracts: pc,
                allow_deploy: pdep,
            },
            D::Contract {
                allowed_contracts: cc,
                allow_deploy: cdep,
            },
        ) => {
            covers_optional_allowlist(pc, cc)
                && (!*cdep || *pdep) // child may deploy only if parent may
        }
        (
            D::RegisterIdentity {
                max_children: pmc,
            },
            D::RegisterIdentity {
                max_children: cmc,
            },
        ) => match (pmc, cmc) {
            (None, _) => true,             // parent unbounded → covers any child
            (Some(_), None) => false,      // child unbounded but parent bounded → fail
            (Some(p), Some(c)) => c <= p,
        },
        (
            D::ResourceInvocation {
                max_amount_per_call: pmc,
                class: pclass,
                allowed_resource_ids: pids,
            },
            D::ResourceInvocation {
                max_amount_per_call: cmc,
                class: cclass,
                allowed_resource_ids: cids,
            },
        ) => {
            cmc <= pmc
                && match (pclass, cclass) {
                    (None, _) => true,
                    (Some(_), None) => false,
                    (Some(p), Some(c)) => p == c,
                }
                && covers_optional_allowlist_str(pids, cids)
        }
        // Variants don't match.
        _ => false,
    }
}

/// `parent.None` covers any child; otherwise `child <= parent`,
/// with child `None` against parent `Some(_)` rejected.
fn covers_optional_max(parent: Option<u128>, child: Option<u128>) -> bool {
    match (parent, child) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(c)) => c <= p,
    }
}

/// Allowlist subset check for `Vec<Address>`-style fields. `parent
/// None` = unrestricted (covers anything); child `None` against
/// `parent Some(_)` is rejected.
fn covers_optional_allowlist(parent: &Option<Vec<Address>>, child: &Option<Vec<Address>>) -> bool {
    match (parent, child) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(c)) => c.iter().all(|x| p.contains(x)),
    }
}

/// Allowlist subset check for `Vec<String>`-style fields (model_ids,
/// proposal ids, …).
fn covers_optional_allowlist_str(parent: &Option<Vec<String>>, child: &Option<Vec<String>>) -> bool {
    match (parent, child) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(c)) => c.iter().all(|x| p.contains(x)),
    }
}

/// Allowlist subset check for `Vec<[u8; 32]>` fields (escrow ids).
fn covers_optional_allowlist_bytes32(
    parent: &Option<Vec<[u8; 32]>>,
    child: &Option<Vec<[u8; 32]>>,
) -> bool {
    match (parent, child) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(c)) => c.iter().all(|x| p.contains(x)),
    }
}

/// Verify that `child_caps` is a subset of `parent_caps` for AAP
/// purposes — every requested action must appear in the parent set,
/// and the parent's constraint object must "permit" the child's
/// constraint object.
///
/// The parent → child constraint comparison is conservative: we only
/// check the four numeric/list keys recognized by [`crate::aap::AapConstraints`]:
/// `max_value`, `allowed_assets`, `allowed_chains`, `allowed_protocols`,
/// `allowed_counterparties`, `allowed_resources`. Unknown keys in the
/// child object are passed through verbatim — Tenzro doesn't enforce
/// what it doesn't understand. (RS extensions can layer their own
/// checks on top.)
///
/// Empty `child_caps` always passes.
pub fn aap_capabilities_is_subset(
    parent_caps: &[AapCapabilityClaim],
    child_caps: &[AapCapabilityClaim],
) -> Result<()> {
    for (i, child_cap) in child_caps.iter().enumerate() {
        let matching_parent = parent_caps.iter().find(|p| p.action == child_cap.action);
        let parent_cap = match matching_parent {
            Some(p) => p,
            None => {
                return Err(AuthError::DelegationViolation(format!(
                    "child aap_capabilities[{}] action {:?} not in parent capabilities",
                    i, child_cap.action,
                )));
            }
        };
        constraints_cover(&parent_cap.constraints, &child_cap.constraints).map_err(|msg| {
            AuthError::DelegationViolation(format!(
                "child aap_capabilities[{}] action {:?}: {}",
                i, child_cap.action, msg,
            ))
        })?;
    }
    Ok(())
}

/// Returns `Ok(())` iff `parent_constraints` permits everything
/// `child_constraints` permits.
///
/// Rules:
///
/// - If parent is null/missing/empty → unrestricted, covers anything.
/// - For each recognized key the parent declares, the child's value
///   must be a tighter or equal restriction. Specifically:
///   - `max_value` (decimal-string u128): child's value `<= parent's`.
///   - `allowed_*` arrays: child's array ⊆ parent's array.
/// - Unknown keys on the child are accepted (Tenzro doesn't enforce
///   what it doesn't model).
fn constraints_cover(
    parent: &serde_json::Value,
    child: &serde_json::Value,
) -> std::result::Result<(), String> {
    use crate::aap::AapConstraints;

    if parent.is_null() {
        return Ok(()); // unrestricted parent
    }

    let parent = AapConstraints::from_value(parent);
    let child = AapConstraints::from_value(child);

    // max_value
    match (&parent.max_value, &child.max_value) {
        (None, _) => {}
        (Some(_), None) => {
            return Err("parent caps max_value, child does not".to_string());
        }
        (Some(p), Some(c)) => {
            let p_v: u128 = p
                .parse()
                .map_err(|e| format!("parent max_value not a u128: {}", e))?;
            let c_v: u128 = c
                .parse()
                .map_err(|e| format!("child max_value not a u128: {}", e))?;
            if c_v > p_v {
                return Err(format!("child max_value {} exceeds parent {}", c_v, p_v));
            }
        }
    }

    // allowed_assets
    if let Some(p_assets) = &parent.allowed_assets {
        match &child.allowed_assets {
            None => {
                return Err("parent restricts allowed_assets, child does not".to_string());
            }
            Some(c_assets) => {
                if !c_assets.iter().all(|a| p_assets.contains(a)) {
                    return Err("child allowed_assets not subset of parent".to_string());
                }
            }
        }
    }

    // allowed_chains
    if let Some(p_chains) = &parent.allowed_chains {
        match &child.allowed_chains {
            None => {
                return Err("parent restricts allowed_chains, child does not".to_string());
            }
            Some(c_chains) => {
                if !c_chains.iter().all(|c| p_chains.contains(c)) {
                    return Err("child allowed_chains not subset of parent".to_string());
                }
            }
        }
    }

    // allowed_protocols
    if let Some(p_protos) = &parent.allowed_protocols {
        match &child.allowed_protocols {
            None => {
                return Err("parent restricts allowed_protocols, child does not".to_string());
            }
            Some(c_protos) => {
                if !c_protos.iter().all(|p| p_protos.contains(p)) {
                    return Err("child allowed_protocols not subset of parent".to_string());
                }
            }
        }
    }

    // allowed_counterparties
    if let Some(p_cps) = &parent.allowed_counterparties {
        match &child.allowed_counterparties {
            None => {
                return Err("parent restricts allowed_counterparties, child does not".to_string());
            }
            Some(c_cps) => {
                if !c_cps.iter().all(|c| p_cps.contains(c)) {
                    return Err("child allowed_counterparties not subset of parent".to_string());
                }
            }
        }
    }

    // allowed_resources
    if let Some(p_res) = &parent.allowed_resources {
        match &child.allowed_resources {
            None => {
                return Err("parent restricts allowed_resources, child does not".to_string());
            }
            Some(c_res) => {
                if !c_res.iter().all(|r| p_res.contains(r)) {
                    return Err("child allowed_resources not subset of parent".to_string());
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::AssetId;

    fn addr(b: u8) -> Address {
        let mut bytes = [0u8; 32];
        bytes[31] = b;
        Address::new(bytes)
    }

    #[test]
    fn empty_child_rar_is_subset_of_anything() {
        let parent = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 1000,
            max_daily_amount: None,
            allowed_counterparties: None,
        });
        let child = AuthorizationDetails::empty();
        assert!(rar_is_subset(&parent, &child).is_ok());
    }

    #[test]
    fn transfer_subset_amount_decreases() {
        let parent = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 1000,
            max_daily_amount: None,
            allowed_counterparties: None,
        });
        let child = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 500,
            max_daily_amount: None,
            allowed_counterparties: None,
        });
        assert!(rar_is_subset(&parent, &child).is_ok());
    }

    #[test]
    fn transfer_subset_amount_increase_rejected() {
        let parent = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 1000,
            max_daily_amount: None,
            allowed_counterparties: None,
        });
        let child = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 5000,
            max_daily_amount: None,
            allowed_counterparties: None,
        });
        assert!(rar_is_subset(&parent, &child).is_err());
    }

    #[test]
    fn transfer_subset_counterparty_narrows() {
        let parent = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 1000,
            max_daily_amount: None,
            allowed_counterparties: Some(vec![addr(1), addr(2), addr(3)]),
        });
        let child_ok = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 500,
            max_daily_amount: None,
            allowed_counterparties: Some(vec![addr(1), addr(2)]),
        });
        assert!(rar_is_subset(&parent, &child_ok).is_ok());

        let child_widens = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 500,
            max_daily_amount: None,
            allowed_counterparties: Some(vec![addr(1), addr(99)]), // 99 not in parent
        });
        assert!(rar_is_subset(&parent, &child_widens).is_err());
    }

    #[test]
    fn child_unbounded_against_bounded_parent_rejected() {
        let parent = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 1000,
            max_daily_amount: None,
            allowed_counterparties: Some(vec![addr(1)]),
        });
        let child_no_list = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 500,
            max_daily_amount: None,
            allowed_counterparties: None, // unbounded
        });
        assert!(rar_is_subset(&parent, &child_no_list).is_err());
    }

    #[test]
    fn variant_mismatch_rejected() {
        let parent = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: 1000,
            max_daily_amount: None,
            allowed_counterparties: None,
        });
        let child = AuthorizationDetails::single(AuthorizationDetail::Stake {
            max_amount: 100,
            allowed_validators: None,
        });
        assert!(rar_is_subset(&parent, &child).is_err());
    }

    #[test]
    fn contract_deploy_inheritance() {
        let parent_no_deploy = AuthorizationDetails::single(AuthorizationDetail::Contract {
            allowed_contracts: None,
            allow_deploy: false,
        });
        let child_with_deploy = AuthorizationDetails::single(AuthorizationDetail::Contract {
            allowed_contracts: None,
            allow_deploy: true,
        });
        assert!(rar_is_subset(&parent_no_deploy, &child_with_deploy).is_err());

        let parent_can_deploy = AuthorizationDetails::single(AuthorizationDetail::Contract {
            allowed_contracts: None,
            allow_deploy: true,
        });
        assert!(rar_is_subset(&parent_can_deploy, &child_with_deploy).is_ok());
    }

    #[test]
    fn inference_model_id_subset() {
        let parent = AuthorizationDetails::single(AuthorizationDetail::Inference {
            max_amount_per_call: 1_000_000,
            max_daily_amount: None,
            allowed_model_ids: Some(vec!["gemma3-270m".into(), "claude-opus-4-7".into()]),
        });
        let child = AuthorizationDetails::single(AuthorizationDetail::Inference {
            max_amount_per_call: 500_000,
            max_daily_amount: None,
            allowed_model_ids: Some(vec!["gemma3-270m".into()]),
        });
        assert!(rar_is_subset(&parent, &child).is_ok());

        let child_widens = AuthorizationDetails::single(AuthorizationDetail::Inference {
            max_amount_per_call: 500_000,
            max_daily_amount: None,
            allowed_model_ids: Some(vec!["gpt-4".into()]),
        });
        assert!(rar_is_subset(&parent, &child_widens).is_err());
    }

    #[test]
    fn aap_capabilities_subset_action_must_be_in_parent() {
        let parent = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::Value::Null,
        }];
        let child_ok = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::Value::Null,
        }];
        assert!(aap_capabilities_is_subset(&parent, &child_ok).is_ok());

        let child_other_action = vec![AapCapabilityClaim {
            action: "staking.stake".into(),
            constraints: serde_json::Value::Null,
        }];
        assert!(aap_capabilities_is_subset(&parent, &child_other_action).is_err());
    }

    #[test]
    fn aap_capabilities_constraint_max_value_decreases() {
        let parent = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::json!({ "max_value": "1000" }),
        }];
        let child_ok = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::json!({ "max_value": "500" }),
        }];
        assert!(aap_capabilities_is_subset(&parent, &child_ok).is_ok());

        let child_widens = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::json!({ "max_value": "5000" }),
        }];
        assert!(aap_capabilities_is_subset(&parent, &child_widens).is_err());
    }

    #[test]
    fn aap_capabilities_allowlist_subset() {
        let parent = vec![AapCapabilityClaim {
            action: "inference.invoke".into(),
            constraints: serde_json::json!({
                "allowed_resources": ["gemma3-270m", "claude-opus-4-7"]
            }),
        }];
        let child_ok = vec![AapCapabilityClaim {
            action: "inference.invoke".into(),
            constraints: serde_json::json!({
                "allowed_resources": ["gemma3-270m"]
            }),
        }];
        assert!(aap_capabilities_is_subset(&parent, &child_ok).is_ok());

        let child_widens = vec![AapCapabilityClaim {
            action: "inference.invoke".into(),
            constraints: serde_json::json!({
                "allowed_resources": ["gpt-4"]
            }),
        }];
        assert!(aap_capabilities_is_subset(&parent, &child_widens).is_err());
    }

    #[test]
    fn aap_capabilities_unrestricted_parent_covers_anything() {
        let parent = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::Value::Null,
        }];
        let child = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::json!({
                "max_value": "999999999999",
                "allowed_chains": [1, 137, 8453],
            }),
        }];
        assert!(aap_capabilities_is_subset(&parent, &child).is_ok());
    }

    #[test]
    fn aap_capabilities_child_unbounded_against_bounded_parent_rejected() {
        let parent = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::json!({ "max_value": "1000" }),
        }];
        let child = vec![AapCapabilityClaim {
            action: "payments.transfer".into(),
            constraints: serde_json::Value::Null,
        }];
        assert!(aap_capabilities_is_subset(&parent, &child).is_err());
    }
}
