//! [`AuthEngine`] — the singleton that owns JWT issuance, DPoP-bound
//! validation, RAR enforcement, cascading revocation, audit logging,
//! and HITL approval bookkeeping.
//!
//! # Mental model
//!
//! ```text
//! caller ──issue_jwt──▶ AuthEngine ──issued AuditEvent──▶ CF_AUDIT
//!                                          │
//!                                          ├──HS256──▶ JWT string
//!                                          │
//! agent runs, holds JWT + DPoP private key
//!                                          │
//! caller ──validate_jwt(jwt, dpop)──▶ AuthEngine
//!                                          │
//!                                          ├──ok──▶ AuthClaims
//!                                          └──err──▶ AuthError + ValidationFailed event
//!
//! caller ──resolve_authority(claims, intent)──▶ AuthEngine
//!                                          │
//!                                          ├──Permit{wallet_id}──▶ caller signs
//!                                          ├──RequireApproval{approval_id}──▶ surface to human
//!                                          └──Deny(reason)──▶ caller returns 403
//!
//! human ──record_approval(approval_id, decision)──▶ AuthEngine
//!                                          │
//!                                          ├──CF_APPROVALS update
//!                                          └──Approval AuditEvent
//!
//! caller ──revoke(jti, reason)──▶ AuthEngine
//!                                          │
//!                                          ├──Revoked AuditEvent (direct)
//!                                          └──cascade through controller_did edges
//! ```
//!
//! # Concurrency
//!
//! `AuthEngine` is `Send + Sync`. All methods take `&self`. Hot caches
//! live in `dashmap::DashMap`; durable state — including the DPoP `jti`
//! replay window — is written through to RocksDB via
//! [`tenzro_storage::KvStore::write_batch_sync`] and hydrated back into
//! memory at construction.

use crate::aap::{
    AapAgentClaim, AapAuditClaim, AapCapabilityClaim, AapContextClaim, AapDelegationClaim,
    AapOversightClaim, AapTaskClaim,
};
use crate::claims::{AuthClaims, Cnf};
use crate::dpop::{DpopProof, DpopVerification, DPOP_REPLAY_CACHE_TTL_SECS};
use crate::error::{AuthError, Result};
use crate::exchange::{TokenExchangeOutcome, TokenExchangeRequest};
use crate::rar::{AuthorizationDetail, AuthorizationDetails, ResourceConstraint};
use crate::storage::{
    approval_key, approval_pending_key, audit_did_key, audit_jti_key, audit_key, ApprovalRecord,
    ApprovalStatus, AuditEvent, AuditEventKind,
};
use dashmap::DashMap;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tenzro_storage::{KvStore, WriteOp, CF_APPROVALS, CF_AUDIT};

/// Configuration for [`AuthEngine`].
#[derive(Debug, Clone)]
pub struct AuthEngineConfig {
    /// JWT issuer identifier — typically the node's DID. Embedded as
    /// the `iss` claim of every issued token; required to match on
    /// validation.
    pub issuer: String,

    /// JWT audience identifier — typically the public RPC URL. Embedded
    /// as the `aud` claim and required to match on validation.
    pub audience: String,

    /// HS256 signing secret. Per the crate-level invariant "issuer is
    /// the node," this is derived from the node's identity keypair (so
    /// it survives node restart but is not shared with any other
    /// node). 32 bytes minimum.
    pub signing_secret: Vec<u8>,

    /// Default token lifetime, in seconds. Caller may override
    /// per-issuance via [`AuthEngine::issue_jwt`]'s `ttl_secs`
    /// argument.
    pub default_ttl_secs: u64,

    /// Maximum token lifetime, in seconds. Caller cannot exceed this
    /// even via the per-issuance override; protects against absurdly
    /// long-lived tokens slipping through misconfigured callers.
    pub max_ttl_secs: u64,

    /// Refresh-token lifetime, in seconds. Refresh tokens are opaque
    /// UUIDs (not JWTs) that callers exchange at the `/token`
    /// (`grant_type=refresh_token`) endpoint or the
    /// `tenzro_refreshToken` RPC for a fresh access token. Default 30
    /// days.
    pub refresh_ttl_secs: u64,
}

impl AuthEngineConfig {
    /// Build a config with sane defaults for the V1 testnet.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, signing_secret: Vec<u8>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            signing_secret,
            default_ttl_secs: 3600,        // 1 hour
            max_ttl_secs: 24 * 3600,       // 24 hours absolute ceiling
            refresh_ttl_secs: 30 * 24 * 3600, // 30 days
        }
    }
}

/// What the engine wants the caller to do for a given (claims, intent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityDecision {
    /// Caller is authorized to proceed. The engine returns the wallet
    /// id to use for signing — looked up from the controller_did via
    /// the wallet binding registry.
    Permit {
        /// Wallet id (DID-suffixed string per `tenzro-wallet`) bound to
        /// the resolved controller DID. Caller hands this to the
        /// signing path.
        wallet_id: String,
    },
    /// The action is permitted by the RAR envelope but the engine
    /// requires explicit human approval before signing. The caller
    /// must surface `approval_id` to the human approver.
    RequireApproval {
        /// Pending [`ApprovalRecord`] id in `CF_APPROVALS`.
        approval_id: String,
    },
    /// The action is denied. `reason` is suitable for inclusion in a
    /// JSON-RPC error response.
    Deny {
        /// Human-readable denial reason.
        reason: String,
    },
}

/// What the caller wants to do, framed in a way the engine can
/// adjudicate against the bearer's RAR envelope and delegation scope.
///
/// This is a thin wrapper over [`ResourceConstraint`] plus the action
/// type — it exists so callers don't need to construct
/// `AuthorizationDetail` variants just to ask "is X permitted?"
#[derive(Debug, Clone)]
pub struct AuthorityRequest {
    /// The kind of action being attempted, as the engine sees it.
    pub action: AuthorityAction,
    /// Per-action constraint payload (asset, amount, counterparty, …).
    pub constraint: ResourceConstraint,
    /// Approval granted out-of-band for *this* attempt, if the caller is
    /// retrying an action that previously returned
    /// [`AuthorityDecision::RequireApproval`].
    ///
    /// When set, oversight adjudication looks the record up and — if it
    /// is `Approved` and describes the same action and constraint —
    /// permits the action and marks the approval consumed. Approvals are
    /// single-use, so a second retry with the same id is refused.
    pub approval_id: Option<String>,
}

/// Result of a successful refresh-token exchange. Surfaces enough state
/// for the calling RPC handler to honestly report whether the freshly
/// minted access token is DPoP-bound (so the response shape doesn't lie
/// to the client about whether DPoP proofs are required on subsequent
/// calls).
#[derive(Debug, Clone)]
pub struct RefreshOutcome {
    /// Newly minted access JWT.
    pub access_token: String,
    /// Lifetime of the access token in seconds.
    pub expires_in: u64,
    /// `true` iff the access token carries a non-empty `cnf.jkt` claim
    /// — i.e. DPoP proofs are required on subsequent authenticated
    /// requests.
    pub dpop_bound: bool,
}

/// Optional AAP claim overrides supplied to
/// [`AuthEngine::issue_jwt_with_aap`]. Every field is optional and
/// defaults to `None` (claim omitted from the token).
///
/// `delegation` defaults to a root claim
/// `AapDelegationClaim::root(bearer_did, default_max_depth.unwrap_or(5))`
/// when not overridden — every AAP-bearing token carries a
/// well-formed `aap_delegation` so the engine never has to
/// reconstruct it during exchange.
#[derive(Debug, Clone, Default)]
pub struct AapOverrides {
    /// `aap_agent` claim — bearer agent identity metadata.
    pub agent: Option<AapAgentClaim>,
    /// `aap_task` claim — purpose binding.
    pub task: Option<AapTaskClaim>,
    /// `aap_capabilities` claim — typed action grants.
    pub capabilities: Option<Vec<AapCapabilityClaim>>,
    /// `aap_oversight` claim — actions requiring human approval.
    pub oversight: Option<AapOversightClaim>,
    /// `aap_delegation` claim. If `None`, the engine constructs a
    /// root claim (`depth=0`, chain=[bearer_did]).
    pub delegation: Option<AapDelegationClaim>,
    /// `aap_context` claim — operational context.
    pub context: Option<AapContextClaim>,
    /// `aap_audit` claim — observability hooks.
    pub audit: Option<AapAuditClaim>,
    /// Default `max_depth` to use when `delegation` is `None` and
    /// the engine builds a root claim. Defaults to 5 in code if also
    /// `None` here.
    pub default_max_depth: Option<u32>,
}

/// Action discriminator for [`AuthorityRequest`]. One enum value per
/// privileged operation the node knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityAction {
    /// Plain wallet transfer.
    Transfer,
    /// On-chain escrow create.
    CreateEscrow,
    /// On-chain escrow release/refund.
    DischargeEscrow,
    /// Pay for an inference call.
    Inference,
    /// Stake or unstake TNZO.
    Stake,
    /// Cast a governance vote.
    Vote,
    /// Deploy or call a contract.
    Contract,
    /// Spawn a child identity under the bearer's act-chain.
    RegisterIdentity,
    /// Pay for a marketplace resource invocation (skill, tool, workflow
    /// template, knowledge base, agent template).
    InvokeResource,
}

/// The OAuth/DPoP/RAR engine. Wrap in `Arc` and share across the node.
pub struct AuthEngine {
    cfg: AuthEngineConfig,
    storage: Arc<dyn KvStore>,
    /// Replay cache: DPoP `jti` → expiry instant (Unix seconds). Written
    /// through to `CF_AUDIT` (`auth_dpop_jti:` rows) and hydrated at
    /// construction; swept opportunistically inside `validate_jwt`.
    dpop_replay: DashMap<String, u64>,
    /// Direct revocation set: JWT `jti` → reason. Populated by
    /// [`Self::revoke`]. Cascading revocation also tags entries here
    /// during the recursive walk.
    revoked_jtis: DashMap<String, String>,
    /// Revoked controller DIDs (for cascade). Populated by
    /// [`Self::revoke`] when revocation is applied to a `controller_did`
    /// rather than a single JTI.
    revoked_controllers: DashMap<String, String>,
    /// Encoding key (HS256), held in cleartext for the engine lifetime.
    encoding_key: EncodingKey,
    /// Decoding key — the same secret, in the
    /// `jsonwebtoken::DecodingKey` shape.
    decoding_key: DecodingKey,
}

impl AuthEngine {
    /// Construct a new engine with the given configuration and
    /// durable backing store. Hydrates the in-memory revocation set
    /// and the DPoP replay window from `CF_AUDIT` so both survive
    /// node restart.
    pub fn new(cfg: AuthEngineConfig, storage: Arc<dyn KvStore>) -> Result<Self> {
        if cfg.signing_secret.len() < 32 {
            return Err(AuthError::Internal(format!(
                "signing_secret must be >= 32 bytes, got {}",
                cfg.signing_secret.len()
            )));
        }
        let encoding_key = EncodingKey::from_secret(&cfg.signing_secret);
        let decoding_key = DecodingKey::from_secret(&cfg.signing_secret);

        let engine = Self {
            cfg,
            storage,
            dpop_replay: DashMap::new(),
            revoked_jtis: DashMap::new(),
            revoked_controllers: DashMap::new(),
            encoding_key,
            decoding_key,
        };
        engine.hydrate_revocations()?;
        engine.hydrate_dpop_replay()?;
        Ok(engine)
    }

    /// Returns a reference to the engine's configuration. Read-only —
    /// the config is fixed at construction time.
    pub fn config(&self) -> &AuthEngineConfig {
        &self.cfg
    }

    /// Walk `audit:` events at startup and rebuild the revocation set,
    /// including the transitive controller closure.
    ///
    /// Two-pass:
    ///   1. Replay every `Revoked` row to repopulate `revoked_jtis` and
    ///      seed `revoked_controllers` with directly-revoked DIDs (both
    ///      JTI-anchored revocations — whose `bearer_did` becomes a
    ///      revoked controller — and `revoke_did`-anchored ones).
    ///   2. Re-cascade across the issued-events snapshot so descendants
    ///      come back into the closure even though their cascaded audit
    ///      rows were already written. (The audit rows are a permanent
    ///      record; the in-memory closure is rebuilt on every boot.)
    fn hydrate_revocations(&self) -> Result<()> {
        let entries = self
            .storage
            .scan_prefix(CF_AUDIT, b"audit:")
            .map_err(|e| AuthError::Storage(format!("audit hydrate: {}", e)))?;

        let mut seed_dids: Vec<String> = Vec::new();
        let mut latest_reason = String::from("hydrated");

        for (_k, v) in entries {
            let event: AuditEvent = match serde_json::from_slice(&v) {
                Ok(e) => e,
                Err(_) => continue, // skip malformed rows; do not block startup
            };
            if let AuditEventKind::Revoked { reason, .. } = &event.kind {
                if let Some(jti) = &event.jti {
                    self.revoked_jtis.insert(jti.clone(), reason.clone());
                }
                // A JTI-anchored revocation makes the bearer DID a
                // revoked controller (so its children are rejected).
                if !event.bearer_did.is_empty() {
                    self.revoked_controllers
                        .insert(event.bearer_did.clone(), reason.clone());
                    seed_dids.push(event.bearer_did.clone());
                }
                // A `revoke_did` event is recorded with jti=None and
                // controller_did=did; capture that DID too.
                if event.jti.is_none() && !event.controller_did.is_empty() {
                    self.revoked_controllers
                        .insert(event.controller_did.clone(), reason.clone());
                    seed_dids.push(event.controller_did.clone());
                }
                latest_reason = reason.clone();
            }
        }

        if !seed_dids.is_empty() {
            // Re-expand the transitive closure. We pass a placeholder
            // parent_event_id ("hydrated") because the cascade audit
            // rows were already written at the time of the original
            // revocation; the BFS here is a no-op on the audit log
            // (cascade only writes when revoked_jtis newly inserts a
            // JTI, and all already-cascaded JTIs were re-inserted
            // above).
            self.cascade_revocations(&seed_dids, &latest_reason, "hydrated")?;
        }
        Ok(())
    }

    /// Issue a new JWT bound to the holder's public-key thumbprint.
    ///
    /// `ttl_secs` is clamped to `[1, max_ttl_secs]`; passing `None`
    /// uses `default_ttl_secs`.
    pub fn issue_jwt(
        &self,
        bearer_did: &str,
        controller_did: &str,
        cnf_jkt: &str,
        authorization_details: AuthorizationDetails,
        ttl_secs: Option<u64>,
    ) -> Result<String> {
        let now = unix_now();
        let ttl = ttl_secs
            .unwrap_or(self.cfg.default_ttl_secs)
            .clamp(1, self.cfg.max_ttl_secs);
        let exp = now + ttl;
        let jti = uuid::Uuid::new_v4().simple().to_string();

        // Per RFC 9449 §6, the `cnf` claim is omitted entirely for
        // bearer-only (non-DPoP-bound) tokens. Encode `Some(Cnf{...})`
        // only when the caller supplied a non-empty thumbprint.
        let cnf = if cnf_jkt.is_empty() {
            None
        } else {
            Some(Cnf {
                jkt: cnf_jkt.to_string(),
            })
        };

        let claims = AuthClaims {
            sub: bearer_did.to_string(),
            iss: self.cfg.issuer.clone(),
            aud: self.cfg.audience.clone(),
            iat: now,
            nbf: now,
            exp,
            jti: jti.clone(),
            cnf,
            controller_did: controller_did.to_string(),
            authorization_details: authorization_details.clone(),
            // Plain RAR token — no AAP layer. Tokens that opt in to
            // AAP are minted via `issue_jwt_with_aap` (added in
            // a follow-up; for now AAP-bearing tokens are produced
            // by the token-exchange path).
            aap_agent: None,
            aap_task: None,
            aap_capabilities: None,
            aap_oversight: None,
            aap_delegation: None,
            aap_context: None,
            aap_audit: None,
        };

        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &self.encoding_key)?;

        // Append-only audit row for the issuance.
        self.record_audit(AuditEvent {
            event_id: new_ulid(),
            timestamp_ms: unix_now_ms(),
            bearer_did: bearer_did.to_string(),
            controller_did: controller_did.to_string(),
            jti: Some(jti.clone()),
            kind: AuditEventKind::Issued {
                authorization_details,
                expires_at: exp,
            },
        })?;

        Ok(token)
    }

    /// Issue a JWT with the full AAP claim set in addition to RAR.
    ///
    /// `aap_overrides` carries the optional `aap_*` fields; `None` for
    /// any field means "omit it from the token". The engine still
    /// constructs the standard `aap_delegation` automatically when
    /// `aap_overrides.delegation` is `None` — defaulting to a root
    /// delegation chain `[bearer_did]` with `depth = 0`.
    ///
    /// Use this when the caller is the *root issuer* of an agent
    /// token (e.g., onboarding RPCs producing autonomous-agent
    /// tokens). For child tokens minted via Token Exchange, use
    /// [`Self::exchange_token`] instead — it computes the right
    /// delegation claim from the parent.
    pub fn issue_jwt_with_aap(
        &self,
        bearer_did: &str,
        controller_did: &str,
        cnf_jkt: &str,
        authorization_details: AuthorizationDetails,
        ttl_secs: Option<u64>,
        aap_overrides: AapOverrides,
    ) -> Result<String> {
        let now = unix_now();
        let ttl = ttl_secs
            .unwrap_or(self.cfg.default_ttl_secs)
            .clamp(1, self.cfg.max_ttl_secs);
        let exp = now + ttl;
        let jti = uuid::Uuid::new_v4().simple().to_string();

        let cnf = if cnf_jkt.is_empty() {
            None
        } else {
            Some(Cnf {
                jkt: cnf_jkt.to_string(),
            })
        };

        // Default delegation to a root chain when not overridden.
        let aap_delegation = aap_overrides.delegation.or_else(|| {
            Some(crate::aap::AapDelegationClaim::root(
                bearer_did,
                aap_overrides.default_max_depth.unwrap_or(5),
            ))
        });

        // Validate AAP capability action names up-front — we reject
        // tokens with malformed action strings rather than failing
        // silently at adjudication time.
        if let Some(caps) = &aap_overrides.capabilities {
            for cap in caps {
                if !crate::aap::is_valid_action_name(&cap.action) {
                    return Err(AuthError::InvalidScope(format!(
                        "AAP capability action {:?} is not a valid ABNF action name",
                        cap.action
                    )));
                }
            }
        }

        // Validate that the inner time window (if any) does not
        // outlive the JWT itself.
        if let Some(ctx) = &aap_overrides.context
            && let Some(tw) = &ctx.time_window
            && tw.exp > exp
        {
            return Err(AuthError::InvalidScope(format!(
                "aap_context.time_window.exp {} exceeds jwt exp {}",
                tw.exp, exp
            )));
        }

        let claims = AuthClaims {
            sub: bearer_did.to_string(),
            iss: self.cfg.issuer.clone(),
            aud: self.cfg.audience.clone(),
            iat: now,
            nbf: now,
            exp,
            jti: jti.clone(),
            cnf,
            controller_did: controller_did.to_string(),
            authorization_details: authorization_details.clone(),
            aap_agent: aap_overrides.agent,
            aap_task: aap_overrides.task,
            aap_capabilities: aap_overrides.capabilities,
            aap_oversight: aap_overrides.oversight,
            aap_delegation,
            aap_context: aap_overrides.context,
            aap_audit: aap_overrides.audit,
        };

        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &self.encoding_key)?;

        self.record_audit(AuditEvent {
            event_id: new_ulid(),
            timestamp_ms: unix_now_ms(),
            bearer_did: bearer_did.to_string(),
            controller_did: controller_did.to_string(),
            jti: Some(jti.clone()),
            kind: AuditEventKind::Issued {
                authorization_details,
                expires_at: exp,
            },
        })?;

        Ok(token)
    }

    /// RFC 8693 OAuth 2.0 Token Exchange — mint a child JWT under a
    /// parent's authority.
    ///
    /// The caller presents a validated `parent_claims` (already
    /// returned by [`Self::validate_jwt`]) along with a
    /// [`TokenExchangeRequest`] describing the requested child
    /// authority. The engine:
    ///
    /// 1. Verifies the requested RAR is a subset of the parent's
    ///    via [`crate::rar_is_subset`].
    /// 2. Verifies the requested AAP capabilities are a subset of
    ///    the parent's via [`crate::aap_capabilities_is_subset`].
    /// 3. Enforces `child.exp <= parent.exp`.
    /// 4. Enforces delegation depth (`parent.depth + 1 <= max_depth`).
    /// 5. Constructs the child `aap_delegation` claim via
    ///    [`crate::AapDelegationClaim::child`].
    /// 6. Sets `controller_did = parent_claims.sub` so revoking the
    ///    parent cascades to the child via the existing
    ///    `controller_did` revocation index.
    /// 7. Mints + audits the child JWT.
    ///
    /// Inheritable AAP claims (`agent`, `task`, `oversight`,
    /// `context`, `audit`) are inherited from the parent unless the
    /// request explicitly overrides them — except `oversight` which
    /// is always inherited (a child cannot widen oversight).
    pub fn exchange_token(
        &self,
        parent_claims: &AuthClaims,
        request: TokenExchangeRequest,
    ) -> Result<TokenExchangeOutcome> {
        // 1. RAR subset.
        crate::exchange::rar_is_subset(
            &parent_claims.authorization_details,
            &request.requested_rar,
        )?;

        // 2. AAP capability subset (if either side has caps).
        let parent_caps: Vec<crate::aap::AapCapabilityClaim> = parent_claims
            .aap_capabilities
            .clone()
            .unwrap_or_default();
        crate::exchange::aap_capabilities_is_subset(
            &parent_caps,
            &request.requested_aap_capabilities,
        )?;

        // 3. TTL bound by parent.exp.
        let now = unix_now();
        if parent_claims.exp <= now {
            return Err(AuthError::TokenExpired);
        }
        let parent_remaining = parent_claims.exp.saturating_sub(now);
        let requested_ttl = request
            .requested_ttl_secs
            .unwrap_or(self.cfg.default_ttl_secs);
        let ttl = requested_ttl.min(parent_remaining).clamp(1, self.cfg.max_ttl_secs);

        // 4. Delegation chain.
        let parent_delegation = parent_claims.aap_delegation.clone().unwrap_or_else(|| {
            // Parent didn't carry a delegation claim (legacy / root
            // tokens minted before AAP). Treat parent as depth 0 with
            // a default max_depth.
            crate::aap::AapDelegationClaim::root(parent_claims.sub.clone(), 5)
        });
        let child_delegation = crate::aap::AapDelegationClaim::child(
            &parent_delegation,
            &request.child_bearer_did,
            &parent_claims.jti,
        )
        .map_err(|m| AuthError::DelegationViolation(m.to_string()))?;

        // 5. Inherited AAP claims. Oversight is *always* inherited:
        // a child cannot relax oversight set by an ancestor. `agent`,
        // `task`, `context`, `audit` aren't overridable in this V1
        // path either — child agents get the parent's purpose
        // binding by default. (Refining `task` per child is a Phase
        // B feature once AP2 mandates land.)
        let token = self.issue_jwt_with_aap(
            &request.child_bearer_did,
            &parent_claims.sub, // controller = parent's bearer DID
            &request.child_dpop_jkt,
            request.requested_rar,
            Some(ttl),
            AapOverrides {
                agent: parent_claims.aap_agent.clone(),
                task: parent_claims.aap_task.clone(),
                capabilities: if request.requested_aap_capabilities.is_empty() {
                    None
                } else {
                    Some(request.requested_aap_capabilities)
                },
                oversight: parent_claims.aap_oversight.clone(),
                delegation: Some(child_delegation.clone()),
                context: parent_claims.aap_context.clone(),
                audit: parent_claims.aap_audit.clone(),
                default_max_depth: None,
            },
        )?;

        Ok(TokenExchangeOutcome {
            access_token: token,
            expires_in: ttl,
            delegation: child_delegation,
        })
    }

    /// Validate a JWT and (optionally) a DPoP proof against the
    /// current request context.
    ///
    /// Pass `None` for `dpop_context` only on flows where DPoP is not
    /// applicable (e.g., the /token endpoint itself, where the proof is
    /// consumed before token issuance). Every protected RPC call
    /// **must** provide it; bearer-only requests are rejected.
    pub fn validate_jwt(
        &self,
        token: &str,
        dpop_context: Option<DpopValidation<'_>>,
    ) -> Result<AuthClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.cfg.issuer]);
        validation.set_audience(&[&self.cfg.audience]);
        validation.set_required_spec_claims(&["sub", "iss", "aud", "exp", "iat", "nbf", "jti"]);

        let data = decode::<AuthClaims>(token, &self.decoding_key, &validation)
            .map_err(AuthError::from)?;
        let claims = data.claims;

        // Direct revocation.
        if let Some(reason) = self.revoked_jtis.get(&claims.jti) {
            self.record_validation_failure(&claims, &format!("revoked: {}", *reason));
            return Err(AuthError::TokenRevoked(reason.clone()));
        }
        // Cascaded revocation by controller_did.
        if let Some(reason) = self.revoked_controllers.get(&claims.controller_did) {
            self.record_validation_failure(&claims, &format!("controller revoked: {}", *reason));
            return Err(AuthError::TokenRevoked(format!(
                "controller {} revoked: {}",
                claims.controller_did, *reason
            )));
        }

        if let Some(ctx) = dpop_context {
            // Bearer-only tokens (no `cnf` claim) cannot be paired with a
            // DPoP proof — per RFC 9449 §7.1, only DPoP-bound tokens can
            // satisfy a DPoP-protected resource. Reject the request rather
            // than silently accept the bearer.
            let bound_jkt = claims
                .cnf
                .as_ref()
                .map(|c| c.jkt.as_str())
                .ok_or_else(|| {
                    self.record_validation_failure(&claims, "bearer-only token used at DPoP endpoint");
                    AuthError::InvalidDpop(
                        "token has no cnf.jkt claim — bearer-only tokens cannot satisfy DPoP-protected requests".into(),
                    )
                })?;
            let verification = ctx.proof.verify(
                ctx.expected_htm,
                ctx.expected_htu,
                ctx.now_unix,
                ctx.signed_input,
                ctx.signature,
            )?;
            if verification.jkt != bound_jkt {
                self.record_validation_failure(&claims, "DPoP jkt mismatch");
                return Err(AuthError::InvalidDpop(format!(
                    "DPoP key thumbprint {} does not match token cnf.jkt {}",
                    verification.jkt, bound_jkt
                )));
            }
            self.guard_replay(&verification)?;
        }

        Ok(claims)
    }

    /// Decide whether `request` is permitted for the bearer of `claims`.
    ///
    /// In V1, this only checks the RAR envelope and revocation; the
    /// caller is responsible for resolving the wallet handle (via the
    /// not-yet-implemented `WalletService::find_by_did`, subtask #50)
    /// and surfacing the resulting `wallet_id` in
    /// `wallet_id_for_controller`. Passing `None` returns
    /// [`AuthorityDecision::Permit`] with `wallet_id: ""` for callers
    /// that just want a yes/no.
    pub fn resolve_authority(
        &self,
        claims: &AuthClaims,
        request: &AuthorityRequest,
        wallet_id_for_controller: Option<String>,
    ) -> Result<AuthorityDecision> {
        // Cheap check first: revocation could have happened between
        // validate_jwt() and this call.
        if self.revoked_jtis.contains_key(&claims.jti) {
            return Ok(AuthorityDecision::Deny {
                reason: format!("token {} revoked", claims.jti),
            });
        }
        if self.revoked_controllers.contains_key(&claims.controller_did) {
            return Ok(AuthorityDecision::Deny {
                reason: format!("controller {} revoked", claims.controller_did),
            });
        }

        // Step 1: RAR — at least one detail must cover the request.
        let rar_covers = claims
            .authorization_details
            .details
            .iter()
            .any(|d| detail_covers(d, request));
        if !rar_covers {
            return Ok(AuthorityDecision::Deny {
                reason: format!(
                    "no authorization_details grant covers action {:?}",
                    request.action
                ),
            });
        }

        // Step 2: AAP capabilities (when present) — request action
        // must appear in the capability list AND its constraints must
        // permit the requested resource. Tokens without aap_capabilities
        // skip this layer (RAR is sufficient).
        if let Some(caps) = &claims.aap_capabilities {
            let action_name = crate::aap::authority_action_to_aap(request.action);
            let matching = caps.iter().find(|c| c.action == action_name);
            let cap = match matching {
                Some(c) => c,
                None => {
                    return Ok(AuthorityDecision::Deny {
                        reason: format!(
                            "aap_capabilities does not include action {:?}",
                            action_name
                        ),
                    });
                }
            };
            if let Err(reason) = aap_constraints_permit(&cap.constraints, &request.constraint) {
                return Ok(AuthorityDecision::Deny {
                    reason: format!("aap constraint denied: {}", reason),
                });
            }
        }

        // Step 3: AAP oversight — if the action is on the
        // requires_human_approval_for list, either honour an approval the
        // caller already holds or surface RequireApproval with a fresh
        // ApprovalRecord.
        if let Some(oversight) = &claims.aap_oversight {
            let action_name = crate::aap::authority_action_to_aap(request.action);
            if oversight
                .requires_human_approval_for
                .iter()
                .any(|a| a == action_name)
            {
                // Retry path: the caller is presenting an approval granted
                // out-of-band. Spend it if it genuinely authorizes this
                // action, so an approved action executes instead of
                // parking again.
                if let Some(id) = &request.approval_id {
                    self.spend_approval_for(id, &claims.sub, request)?;
                    return Ok(AuthorityDecision::Permit {
                        wallet_id: wallet_id_for_controller.unwrap_or_default(),
                    });
                }
                let approver_did = oversight
                    .approver_did
                    .clone()
                    .unwrap_or_else(|| claims.controller_did.clone());
                let ttl_secs = oversight.approval_ttl_secs.unwrap_or(3600);
                let now_ms = unix_now_ms();
                let approval = ApprovalRecord {
                    approval_id: uuid::Uuid::new_v4().simple().to_string(),
                    requester_did: claims.sub.clone(),
                    approver_did,
                    created_at_ms: now_ms,
                    expires_at_ms: now_ms + ttl_secs * 1000,
                    action: authority_request_to_detail(request),
                    summary: format!(
                        "AAP oversight: action {} requires approval",
                        action_name
                    ),
                    status: ApprovalStatus::Pending,
                    decided_at_ms: None,
                    deny_reason: None,
                };
                let approval_id = self.record_approval(approval)?;
                return Ok(AuthorityDecision::RequireApproval { approval_id });
            }
        }

        Ok(AuthorityDecision::Permit {
            wallet_id: wallet_id_for_controller.unwrap_or_default(),
        })
    }

    /// Append an audit event. This always uses
    /// [`tenzro_storage::KvStore::write_batch_sync`] — audit durability
    /// is the entire point of the column family.
    pub fn record_audit(&self, event: AuditEvent) -> Result<()> {
        let primary = audit_key(&event.event_id);
        let did_idx = audit_did_key(&event.bearer_did, &event.event_id);
        let body = serde_json::to_vec(&event)?;

        let mut ops = vec![
            WriteOp::Put {
                cf: CF_AUDIT.to_string(),
                key: primary.into_bytes(),
                value: body,
            },
            WriteOp::Put {
                cf: CF_AUDIT.to_string(),
                key: did_idx.into_bytes(),
                value: Vec::new(),
            },
        ];
        // Index issuance events by JTI so revoke-by-JTI can find the
        // controller_did to cascade against.
        if let (Some(jti), AuditEventKind::Issued { .. }) = (&event.jti, &event.kind) {
            ops.push(WriteOp::Put {
                cf: CF_AUDIT.to_string(),
                key: audit_jti_key(jti).into_bytes(),
                value: event.event_id.as_bytes().to_vec(),
            });
        }
        self.storage
            .write_batch_sync(ops)
            .map_err(|e| AuthError::Storage(format!("audit write: {}", e)))?;
        Ok(())
    }

    /// Create a HITL approval request and return its id. The engine
    /// records both the [`ApprovalRecord`] in `CF_APPROVALS` and a
    /// matching audit event in `CF_AUDIT`.
    pub fn record_approval(&self, record: ApprovalRecord) -> Result<String> {
        let approval_id = record.approval_id.clone();
        let primary = approval_key(&approval_id);
        let pending_idx = approval_pending_key(&record.approver_did, &approval_id);
        let body = serde_json::to_vec(&record)?;

        let mut ops = vec![WriteOp::Put {
            cf: CF_APPROVALS.to_string(),
            key: primary.into_bytes(),
            value: body,
        }];
        if matches!(record.status, ApprovalStatus::Pending) {
            ops.push(WriteOp::Put {
                cf: CF_APPROVALS.to_string(),
                key: pending_idx.into_bytes(),
                value: Vec::new(),
            });
        }
        self.storage
            .write_batch_sync(ops)
            .map_err(|e| AuthError::Storage(format!("approval write: {}", e)))?;

        self.record_audit(AuditEvent {
            event_id: new_ulid(),
            timestamp_ms: unix_now_ms(),
            bearer_did: record.requester_did.clone(),
            controller_did: record.approver_did.clone(),
            jti: None,
            kind: AuditEventKind::Approval {
                approval_id: approval_id.clone(),
                new_status: record.status,
            },
        })?;
        Ok(approval_id)
    }

    /// Look up an approval by id. Performs lazy expiry: if the record
    /// is `Pending` and `expires_at_ms` has passed, the record is
    /// transitioned to `Expired` (with audit event + pending-index drop)
    /// before being returned.
    pub fn get_approval(&self, approval_id: &str) -> Result<Option<ApprovalRecord>> {
        let raw = self
            .storage
            .get(CF_APPROVALS, approval_key(approval_id).as_bytes())
            .map_err(|e| AuthError::Storage(format!("approval read: {}", e)))?;
        let mut record: ApprovalRecord = match raw {
            Some(b) => serde_json::from_slice(&b)?,
            None => return Ok(None),
        };
        if matches!(record.status, ApprovalStatus::Pending)
            && record.expires_at_ms <= unix_now_ms()
        {
            record.status = ApprovalStatus::Expired;
            record.decided_at_ms = Some(unix_now_ms());
            self.persist_approval_status_change(&record, /*was_pending=*/ true)?;
        }
        Ok(Some(record))
    }

    /// Approver decides a pending approval. `expected_approver_did`, if
    /// supplied, must match the record's `approver_did` — used so the
    /// JSON-RPC layer can enforce "only the named approver may decide
    /// this request" against the bearer of the approver's JWT.
    ///
    /// `decision` must be [`ApprovalStatus::Approved`] or
    /// [`ApprovalStatus::Denied`]. Any other variant returns
    /// [`AuthError::Internal`].
    ///
    /// `deny_reason` is recorded on the request and surfaced to the
    /// requesting agent when the decision is `Denied`, so the agent can
    /// act on *why* it was refused. It is ignored for `Approved`.
    pub fn decide_approval(
        &self,
        approval_id: &str,
        decision: ApprovalStatus,
        expected_approver_did: Option<&str>,
        deny_reason: Option<String>,
    ) -> Result<ApprovalRecord> {
        if !matches!(decision, ApprovalStatus::Approved | ApprovalStatus::Denied) {
            return Err(AuthError::Internal(format!(
                "decide_approval: decision must be Approved or Denied, got {:?}",
                decision
            )));
        }

        let mut record = self
            .get_approval(approval_id)?
            .ok_or_else(|| AuthError::Internal(format!("approval {} not found", approval_id)))?;

        if let Some(expected) = expected_approver_did
            && record.approver_did != expected
        {
            return Err(AuthError::Forbidden(format!(
                "approval {} is for approver {}, not {}",
                approval_id, record.approver_did, expected
            )));
        }

        match record.status {
            ApprovalStatus::Pending => { /* fall through */ }
            ApprovalStatus::Approved | ApprovalStatus::Denied | ApprovalStatus::Expired
            | ApprovalStatus::Consumed => {
                return Err(AuthError::Internal(format!(
                    "approval {} is already in terminal state {:?}",
                    approval_id, record.status
                )));
            }
        }

        record.status = decision;
        record.decided_at_ms = Some(unix_now_ms());
        if matches!(decision, ApprovalStatus::Denied) {
            record.deny_reason = deny_reason;
        }
        self.persist_approval_status_change(&record, /*was_pending=*/ true)?;
        Ok(record)
    }

    /// Mark an approval as `Consumed` — i.e. the underlying action has
    /// been carried out. Approvals are single-use; once consumed they
    /// cannot be reused. Returns `Forbidden` if the approval is not in
    /// `Approved` state.
    pub fn consume_approval(&self, approval_id: &str) -> Result<ApprovalRecord> {
        let mut record = self
            .get_approval(approval_id)?
            .ok_or_else(|| AuthError::Internal(format!("approval {} not found", approval_id)))?;

        if !matches!(record.status, ApprovalStatus::Approved) {
            return Err(AuthError::Forbidden(format!(
                "approval {} cannot be consumed from state {:?}",
                approval_id, record.status
            )));
        }

        record.status = ApprovalStatus::Consumed;
        // decided_at_ms already set when approver acted; do not overwrite.
        self.persist_approval_status_change(&record, /*was_pending=*/ false)?;
        Ok(record)
    }

    /// Spend an approval that the caller is presenting to retry an action
    /// which previously returned [`AuthorityDecision::RequireApproval`].
    ///
    /// The approval only authorizes the action it was minted for, so this
    /// re-checks every binding before consuming it:
    ///
    /// - the requester must be the bearer now retrying (`sub`), so one
    ///   agent cannot spend another's approval;
    /// - the recorded [`crate::rar::AuthorizationDetail`] must equal the
    ///   detail this request projects to, so an approval for a 10 TNZO
    ///   transfer cannot be redeemed against a 10,000 TNZO one;
    /// - the status must be `Approved` — `Denied`, `Expired`, `Pending`
    ///   and the already-spent `Consumed` all refuse.
    fn spend_approval_for(
        &self,
        approval_id: &str,
        requester_did: &str,
        request: &AuthorityRequest,
    ) -> Result<ApprovalRecord> {
        let record = self.get_approval(approval_id)?.ok_or_else(|| {
            AuthError::Forbidden(format!("approval {} not found", approval_id))
        })?;

        if record.requester_did != requester_did {
            return Err(AuthError::Forbidden(format!(
                "approval {} was requested by {}, not {}",
                approval_id, record.requester_did, requester_did
            )));
        }

        match record.status {
            ApprovalStatus::Approved => {}
            ApprovalStatus::Denied => {
                let reason = record
                    .deny_reason
                    .as_deref()
                    .unwrap_or("no reason given by approver");
                return Err(AuthError::Forbidden(format!(
                    "approval {} was denied: {}",
                    approval_id, reason
                )));
            }
            other => {
                return Err(AuthError::Forbidden(format!(
                    "approval {} is not usable from state {:?}",
                    approval_id, other
                )));
            }
        }

        if record.action != authority_request_to_detail(request) {
            return Err(AuthError::Forbidden(format!(
                "approval {} authorizes a different action than the one being retried",
                approval_id
            )));
        }

        self.consume_approval(approval_id)
    }

    /// List approvals currently in `Pending` state for the given
    /// approver DID. Lazy-expiry is applied to each record before it is
    /// returned, so the caller never sees stale Pending entries.
    pub fn list_pending_for_approver(&self, approver_did: &str) -> Result<Vec<ApprovalRecord>> {
        let prefix = format!("approval_pending:{}:", approver_did);
        let keys = self
            .storage
            .get_keys_with_prefix(CF_APPROVALS, prefix.as_bytes())
            .map_err(|e| AuthError::Storage(format!("approval index scan: {}", e)))?;

        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            // Key shape: "approval_pending:<did>:<approval_id>" — the
            // suffix after the prefix is the approval id.
            let key_str = match std::str::from_utf8(&k) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let Some(approval_id) = key_str.strip_prefix(&prefix) else {
                continue;
            };
            if let Some(rec) = self.get_approval(approval_id)?
                && matches!(rec.status, ApprovalStatus::Pending)
            {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Persist a status transition. Always rewrites the primary
    /// `approval:<id>` row, drops the `approval_pending:<approver>:<id>`
    /// secondary index iff the record was Pending before this call, and
    /// appends an [`AuditEventKind::Approval`] event.
    fn persist_approval_status_change(
        &self,
        record: &ApprovalRecord,
        was_pending: bool,
    ) -> Result<()> {
        let body = serde_json::to_vec(record)?;
        let mut ops = vec![WriteOp::Put {
            cf: CF_APPROVALS.to_string(),
            key: approval_key(&record.approval_id).into_bytes(),
            value: body,
        }];
        if was_pending {
            ops.push(WriteOp::Delete {
                cf: CF_APPROVALS.to_string(),
                key: approval_pending_key(&record.approver_did, &record.approval_id).into_bytes(),
            });
        }
        self.storage
            .write_batch_sync(ops)
            .map_err(|e| AuthError::Storage(format!("approval status write: {}", e)))?;

        self.record_audit(AuditEvent {
            event_id: new_ulid(),
            timestamp_ms: unix_now_ms(),
            bearer_did: record.requester_did.clone(),
            controller_did: record.approver_did.clone(),
            jti: None,
            kind: AuditEventKind::Approval {
                approval_id: record.approval_id.clone(),
                new_status: record.status,
            },
        })?;
        Ok(())
    }

    /// Revoke a JWT by its JTI, then cascade through the act-chain.
    ///
    /// The JTI itself is marked revoked; the bearer DID is added to
    /// `revoked_controllers`; and the engine walks the audit log
    /// transitively, revoking every issued JWT whose `controller_did`
    /// is (now) revoked. Each affected JTI gets its own
    /// `AuditEventKind::Revoked { cascaded: true, parent_event_id: ... }`
    /// row pointing back at the original revocation event, so the
    /// cascade is fully reconstructible from the audit log.
    ///
    /// `revoked_controllers` is maintained as the *transitive closure*
    /// of revoked DIDs, so subsequent validations need only an O(1)
    /// lookup against `claims.controller_did` to reject any descendant.
    pub fn revoke(&self, jti: &str, reason: impl Into<String>) -> Result<()> {
        let reason = reason.into();
        let (bearer_did, controller_did) = self.lookup_jti_dids(jti)?;

        self.revoked_jtis.insert(jti.to_string(), reason.clone());

        // Direct revocation event (the act-chain root).
        let root_event_id = new_ulid();
        self.record_audit(AuditEvent {
            event_id: root_event_id.clone(),
            timestamp_ms: unix_now_ms(),
            bearer_did: bearer_did.clone(),
            controller_did,
            jti: Some(jti.to_string()),
            kind: AuditEventKind::Revoked {
                cascaded: false,
                parent_event_id: None,
                reason: reason.clone(),
            },
        })?;

        // Cascade from the bearer DID — any descendant JTI / DID is
        // revoked transitively. Skipped iff the original JWT had no
        // recoverable issuance record (bearer_did empty), in which case
        // there's no DID to cascade from.
        if !bearer_did.is_empty() {
            self.cascade_revocations(&[bearer_did], &reason, &root_event_id)?;
        }

        Ok(())
    }

    /// Revoke a DID directly (without naming a specific JTI). All JWTs
    /// issued to this DID *and* every JWT in its act-chain descendants
    /// are revoked, with audit events recorded for each. Use this when
    /// the caller wants to revoke an entire identity (e.g. compromised
    /// agent) rather than one token.
    ///
    /// Returns the count of JTIs touched by the cascade (not counting
    /// JTIs that were already in `revoked_jtis`).
    pub fn revoke_did(&self, did: &str, reason: impl Into<String>) -> Result<usize> {
        if did.is_empty() {
            return Err(AuthError::Internal(
                "revoke_did: did must not be empty".into(),
            ));
        }
        let reason = reason.into();

        // Root event for the DID-level revocation. Stored with
        // `controller_did = did` and `jti = None` so the hydration path
        // recognizes it as a controller-level revocation (see
        // `hydrate_revocations`).
        let root_event_id = new_ulid();
        self.record_audit(AuditEvent {
            event_id: root_event_id.clone(),
            timestamp_ms: unix_now_ms(),
            bearer_did: did.to_string(),
            controller_did: did.to_string(),
            jti: None,
            kind: AuditEventKind::Revoked {
                cascaded: false,
                parent_event_id: None,
                reason: reason.clone(),
            },
        })?;

        let count = self.cascade_revocations(&[did.to_string()], &reason, &root_event_id)?;
        Ok(count)
    }

    /// Issue an opaque refresh token bound to `bearer_did` /
    /// `controller_did` / `dpop_jkt`. The token is a UUIDv4 string —
    /// not a JWT — and is persisted to `CF_AUDIT` under the prefix
    /// `auth_refresh:<token>` via `write_batch_sync`.
    ///
    /// Callers exchange the refresh token for a fresh access JWT via
    /// [`Self::exchange_refresh_token`]. Lifetime is governed by
    /// [`AuthEngineConfig::refresh_ttl_secs`] (default 30 days).
    pub fn issue_refresh_token(
        &self,
        bearer_did: &str,
        controller_did: &str,
        dpop_jkt: Option<&str>,
        authorization_details: AuthorizationDetails,
    ) -> Result<(String, u64)> {
        let token = uuid::Uuid::new_v4().to_string();
        let expires_at = unix_now() + self.cfg.refresh_ttl_secs;
        let entry = crate::storage::RefreshTokenEntry {
            token: token.clone(),
            bearer_did: bearer_did.to_string(),
            controller_did: controller_did.to_string(),
            dpop_jkt: dpop_jkt.map(str::to_string),
            authorization_details,
            expires_at,
        };
        let body = serde_json::to_vec(&entry)?;
        self.storage
            .write_batch_sync(vec![WriteOp::Put {
                cf: CF_AUDIT.to_string(),
                key: crate::storage::refresh_token_key(&token).into_bytes(),
                value: body,
            }])
            .map_err(|e| AuthError::Storage(format!("refresh token write: {}", e)))?;
        Ok((token, self.cfg.refresh_ttl_secs))
    }

    /// Exchange a refresh token for a fresh access JWT. The new JWT is
    /// pinned to the DPoP thumbprint stored on the refresh entry (or to
    /// `override_dpop_jkt` when the caller supplies one — for example,
    /// when the client rotated its DPoP key alongside the refresh).
    ///
    /// Returns the newly minted JWT plus the access-token lifetime in
    /// seconds. On any failure (unknown token, expired, controller
    /// revoked) the engine returns the appropriate
    /// [`AuthError`] variant; the refresh entry itself is **not**
    /// rotated in V1 — it remains valid until its absolute expiry. (V2
    /// will add rotation + reuse-detection.)
    pub fn exchange_refresh_token(
        &self,
        token: &str,
        override_dpop_jkt: Option<&str>,
    ) -> Result<RefreshOutcome> {
        let key = crate::storage::refresh_token_key(token);
        let raw = self
            .storage
            .get(CF_AUDIT, key.as_bytes())
            .map_err(|e| AuthError::Storage(format!("refresh token read: {}", e)))?
            .ok_or_else(|| AuthError::InvalidToken("unknown refresh token".into()))?;

        let entry: crate::storage::RefreshTokenEntry = serde_json::from_slice(&raw)
            .map_err(|e| AuthError::Storage(format!("refresh token decode: {}", e)))?;

        let now = unix_now();
        if now >= entry.expires_at {
            // Best-effort cleanup; ignore delete error.
            let _ = self.storage.delete(CF_AUDIT, key.as_bytes());
            return Err(AuthError::TokenExpired);
        }

        // The controller could have been revoked between issuance and
        // refresh — refuse the exchange in that case.
        if self.revoked_controllers.contains_key(&entry.controller_did) {
            return Err(AuthError::TokenRevoked(format!(
                "controller {} revoked",
                entry.controller_did
            )));
        }

        // The refresh token may or may not be DPoP-bound. Onboarding flows
        // mint a non-DPoP refresh alongside a non-DPoP access token (the
        // server has no DPoP key from the caller at that point); the access
        // token's `cnf.jkt` is empty in that case. To stay consistent, we
        // accept three combinations:
        //   1. entry has jkt + caller supplies override → caller wins
        //      (key rotation).
        //   2. entry has jkt + no override → reuse stored jkt.
        //   3. entry has no jkt + no override → issue a non-DPoP access
        //      token (empty jkt). This matches the original issuance.
        // A caller MAY supply an override against a non-DPoP entry to
        // upgrade to DPoP-bound from this point forward.
        let jkt = override_dpop_jkt
            .map(str::to_string)
            .or_else(|| entry.dpop_jkt.clone())
            .unwrap_or_default();

        let access_token = self.issue_jwt(
            &entry.bearer_did,
            &entry.controller_did,
            &jkt,
            entry.authorization_details.clone(),
            None,
        )?;
        Ok(RefreshOutcome {
            access_token,
            expires_in: self.cfg.default_ttl_secs,
            dpop_bound: !jkt.is_empty(),
        })
    }

    /// Look up a stored refresh token without exchanging it. Returns
    /// `None` if absent or if the entry deserialization fails. Used by
    /// the OAuth `/token` (`grant_type=refresh_token`) flow which needs
    /// to inspect the bound `did` / `scope` before minting.
    pub fn lookup_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::storage::RefreshTokenEntry>> {
        let key = crate::storage::refresh_token_key(token);
        let raw = self
            .storage
            .get(CF_AUDIT, key.as_bytes())
            .map_err(|e| AuthError::Storage(format!("refresh token read: {}", e)))?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                let entry: crate::storage::RefreshTokenEntry = serde_json::from_slice(&bytes)
                    .map_err(|e| AuthError::Storage(format!("refresh token decode: {}", e)))?;
                Ok(Some(entry))
            }
        }
    }

    /// Revoke a refresh token by deleting it from storage. Idempotent
    /// — calling on an unknown token is not an error.
    pub fn revoke_refresh_token(&self, token: &str) -> Result<()> {
        let key = crate::storage::refresh_token_key(token);
        self.storage
            .delete(CF_AUDIT, key.as_bytes())
            .map_err(|e| AuthError::Storage(format!("refresh token delete: {}", e)))
    }

    /// Walk the audit log transitively, expanding the revocation
    /// frontier from `seed_dids` until no new descendants are found.
    /// Each (DID frontier element) is added to `revoked_controllers`,
    /// and every JTI ever issued under such a DID is added to
    /// `revoked_jtis` with a fresh audit event.
    ///
    /// Returns the number of JTIs newly added to `revoked_jtis`.
    fn cascade_revocations(
        &self,
        seed_dids: &[String],
        reason: &str,
        parent_event_id: &str,
    ) -> Result<usize> {
        // Snapshot the audit log once. Cascade operates entirely in
        // memory against this snapshot, then writes a single batch of
        // cascaded audit events at the end.
        let issued_events = self.scan_issued_events()?;

        // Frontier-expansion BFS. `to_visit` are DIDs we just added to
        // `revoked_controllers`; we look for any issuance whose
        // `controller_did` matches, mark its bearer as revoked, and
        // queue that bearer for the next round. Each DID is visited at
        // most once even on tangled act-chains (cycle-safe).
        use std::collections::HashSet;
        let mut visited: HashSet<String> = HashSet::new();
        let mut frontier: Vec<String> = Vec::new();

        for did in seed_dids {
            if did.is_empty() {
                continue;
            }
            // Always (re)assert membership in revoked_controllers — the
            // closure must include every seed DID. `visited` controls
            // BFS termination; we only enqueue each DID once per run.
            self.revoked_controllers
                .insert(did.clone(), reason.to_string());
            if visited.insert(did.clone()) {
                frontier.push(did.clone());
            }
        }

        let mut cascaded_audit_ops: Vec<AuditEvent> = Vec::new();
        let mut new_jti_count: usize = 0;

        while let Some(controller) = frontier.pop() {
            for ev in &issued_events {
                if ev.controller_did != controller {
                    continue;
                }
                let bearer = &ev.bearer_did;
                let Some(jti) = ev.jti.as_ref() else { continue };

                // Mark every descendant JTI as revoked, even if the
                // bearer was already in revoked_controllers — sibling
                // tokens under the same controller all need their own
                // audit row.
                if self
                    .revoked_jtis
                    .insert(jti.clone(), reason.to_string())
                    .is_none()
                {
                    new_jti_count += 1;
                    cascaded_audit_ops.push(AuditEvent {
                        event_id: new_ulid(),
                        timestamp_ms: unix_now_ms(),
                        bearer_did: bearer.clone(),
                        controller_did: ev.controller_did.clone(),
                        jti: Some(jti.clone()),
                        kind: AuditEventKind::Revoked {
                            cascaded: true,
                            parent_event_id: Some(parent_event_id.to_string()),
                            reason: reason.to_string(),
                        },
                    });
                }

                // Cascade through the bearer DID itself — its children
                // become revoked too. Only enqueue once per BFS run to
                // avoid quadratic re-walks of cyclic chains.
                if !bearer.is_empty() && visited.insert(bearer.clone()) {
                    self.revoked_controllers
                        .insert(bearer.clone(), reason.to_string());
                    frontier.push(bearer.clone());
                }
            }
        }

        // Write all cascaded audit events. We could batch into a single
        // RocksDB write but `record_audit` handles the secondary
        // indices for us; the cost is ≤ one fsync per cascaded JTI,
        // which is acceptable for the rare revoke-by-compromise case.
        for ev in cascaded_audit_ops {
            self.record_audit(ev)?;
        }
        Ok(new_jti_count)
    }

    /// Reverse-lookup the (bearer_did, controller_did) pair for a JTI
    /// by walking the `audit_jti:` secondary index. Returns empty
    /// strings if no issuance event was ever recorded for this JTI
    /// (which can happen for tokens minted before
    /// [`Self::record_audit`] was wired in).
    fn lookup_jti_dids(&self, jti: &str) -> Result<(String, String)> {
        let event_id_bytes = self
            .storage
            .get(CF_AUDIT, audit_jti_key(jti).as_bytes())
            .map_err(|e| AuthError::Storage(format!("audit jti idx: {}", e)))?;
        let Some(eid_bytes) = event_id_bytes else {
            return Ok((String::new(), String::new()));
        };
        let eid = String::from_utf8(eid_bytes)
            .map_err(|e| AuthError::Storage(format!("audit jti idx not utf8: {}", e)))?;
        let row = self
            .storage
            .get(CF_AUDIT, audit_key(&eid).as_bytes())
            .map_err(|e| AuthError::Storage(format!("audit row read: {}", e)))?
            .ok_or_else(|| AuthError::Storage(format!("audit row missing: {}", eid)))?;
        let issued: AuditEvent = serde_json::from_slice(&row)?;
        Ok((issued.bearer_did, issued.controller_did))
    }

    /// Scan all `Issued` audit events. Used by [`Self::cascade_revocations`]
    /// — we materialize the snapshot once per cascade so the BFS
    /// doesn't re-hit storage on every frontier expansion.
    fn scan_issued_events(&self) -> Result<Vec<AuditEvent>> {
        let raw = self
            .storage
            .scan_prefix(CF_AUDIT, b"audit:")
            .map_err(|e| AuthError::Storage(format!("audit scan: {}", e)))?;
        let mut out = Vec::with_capacity(raw.len());
        for (_k, v) in raw {
            let Ok(ev) = serde_json::from_slice::<AuditEvent>(&v) else {
                continue;
            };
            if matches!(ev.kind, AuditEventKind::Issued { .. }) {
                out.push(ev);
            }
        }
        Ok(out)
    }

    fn record_validation_failure(&self, claims: &AuthClaims, reason: &str) {
        // Best-effort; we never let an audit failure mask the original
        // validation error.
        let _ = self.record_audit(AuditEvent {
            event_id: new_ulid(),
            timestamp_ms: unix_now_ms(),
            bearer_did: claims.sub.clone(),
            controller_did: claims.controller_did.clone(),
            jti: Some(claims.jti.clone()),
            kind: AuditEventKind::ValidationFailed {
                reason: reason.to_string(),
            },
        });
    }

    fn guard_replay(&self, verification: &DpopVerification) -> Result<()> {
        let now = unix_now();
        // Opportunistic GC: drop any expired entries before inserting,
        // and delete their durable rows so the cache and CF_AUDIT stay
        // in step. Iterating a DashMap and removing within the same
        // iter is ok because retain takes a closure.
        let mut swept: Vec<String> = Vec::new();
        self.dpop_replay.retain(|jti, exp| {
            let live = *exp > now;
            if !live {
                swept.push(jti.clone());
            }
            live
        });
        for jti in &swept {
            // Best-effort — a stale row is re-swept on the next call.
            let _ = self
                .storage
                .delete(CF_AUDIT, crate::storage::dpop_replay_key(jti).as_bytes());
        }

        let exp = now.saturating_add(DPOP_REPLAY_CACHE_TTL_SECS);
        if let Some(prev) = self.dpop_replay.insert(verification.jti.clone(), exp) {
            // If the previous entry was still live, this is a replay.
            if prev > now {
                // Roll back the insertion so we don't extend the TTL of
                // the original entry.
                self.dpop_replay.insert(verification.jti.clone(), prev);
                return Err(AuthError::InvalidDpop(format!(
                    "DPoP jti {} replayed within {}s window",
                    verification.jti, DPOP_REPLAY_CACHE_TTL_SECS
                )));
            }
        }
        // Write-through so a node restart inside the replay window
        // cannot be used to replay a previously-seen proof.
        self.storage
            .write_batch_sync(vec![WriteOp::Put {
                cf: CF_AUDIT.to_string(),
                key: crate::storage::dpop_replay_key(&verification.jti).into_bytes(),
                value: exp.to_le_bytes().to_vec(),
            }])
            .map_err(|e| AuthError::Storage(format!("dpop replay write: {}", e)))?;
        Ok(())
    }

    /// Rebuild the DPoP replay window from `CF_AUDIT` at construction
    /// so proofs seen before a restart stay rejected for the remainder
    /// of [`DPOP_REPLAY_CACHE_TTL_SECS`]. Expired rows are deleted as
    /// they are encountered; malformed rows are skipped.
    fn hydrate_dpop_replay(&self) -> Result<()> {
        let now = unix_now();
        let entries = self
            .storage
            .scan_prefix(CF_AUDIT, crate::storage::DPOP_REPLAY_PREFIX)
            .map_err(|e| AuthError::Storage(format!("dpop replay hydrate: {}", e)))?;
        for (key, value) in entries {
            let Some(suffix) = key.strip_prefix(crate::storage::DPOP_REPLAY_PREFIX) else {
                continue;
            };
            let Ok(jti) = std::str::from_utf8(suffix) else {
                continue;
            };
            let raw: [u8; 8] = match value.as_slice().try_into() {
                Ok(r) => r,
                Err(_) => {
                    let _ = self.storage.delete(CF_AUDIT, &key);
                    continue;
                }
            };
            let exp = u64::from_le_bytes(raw);
            if exp > now {
                self.dpop_replay.insert(jti.to_string(), exp);
            } else {
                let _ = self.storage.delete(CF_AUDIT, &key);
            }
        }
        Ok(())
    }
}

/// DPoP context for [`AuthEngine::validate_jwt`].
#[derive(Debug)]
pub struct DpopValidation<'a> {
    /// Parsed DPoP proof.
    pub proof: &'a DpopProof,
    /// Expected HTTP method (uppercase).
    pub expected_htm: &'a str,
    /// Expected HTTP target URI (origin + path, query stripped).
    pub expected_htu: &'a str,
    /// Current Unix time in seconds.
    pub now_unix: i64,
    /// Bytes the holder signed (the `<header>.<payload>` JWS prefix).
    pub signed_input: &'a [u8],
    /// 64-byte Ed25519 signature.
    pub signature: &'a [u8],
}

/// Returns `true` iff `detail` covers the action described by `request`.
fn detail_covers(detail: &AuthorizationDetail, request: &AuthorityRequest) -> bool {
    use AuthorityAction as A;
    match (detail, request.action) {
        (
            AuthorizationDetail::Transfer {
                asset,
                max_amount,
                allowed_counterparties,
                ..
            },
            A::Transfer,
        ) => {
            asset_matches(asset, request.constraint.asset.as_ref())
                && amount_within(*max_amount, request.constraint.amount)
                && counterparty_allowed(allowed_counterparties, &request.constraint.counterparty)
        }
        (
            AuthorizationDetail::CreateEscrow {
                asset,
                max_amount,
                allowed_payees,
            },
            A::CreateEscrow,
        ) => {
            asset_matches(asset, request.constraint.asset.as_ref())
                && amount_within(*max_amount, request.constraint.amount)
                && counterparty_allowed(allowed_payees, &request.constraint.counterparty)
        }
        (
            AuthorizationDetail::DischargeEscrow { allowed_escrow_ids },
            A::DischargeEscrow,
        ) => {
            // If the grant is unrestricted, any escrow is fine.
            // Otherwise the request must name an escrow id (32 bytes
            // hex-encoded into ResourceConstraint::resource_id) that
            // appears in the allow-list.
            match allowed_escrow_ids {
                None => true,
                Some(ids) => {
                    let Some(rid) = request.constraint.resource_id.as_ref() else {
                        return false;
                    };
                    let Ok(bytes) = hex::decode(rid.trim_start_matches("0x")) else {
                        return false;
                    };
                    if bytes.len() != 32 {
                        return false;
                    }
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&bytes);
                    ids.iter().any(|id| id == &buf)
                }
            }
        }
        (
            AuthorizationDetail::Inference {
                max_amount_per_call,
                allowed_model_ids,
                ..
            },
            A::Inference,
        ) => {
            amount_within(*max_amount_per_call, request.constraint.amount)
                && match (allowed_model_ids, request.constraint.resource_id.as_ref()) {
                    (None, _) => true,
                    (Some(_), None) => false,
                    (Some(ids), Some(model_id)) => ids.iter().any(|m| m == model_id),
                }
        }
        (
            AuthorizationDetail::Stake {
                max_amount,
                allowed_validators,
            },
            A::Stake,
        ) => {
            amount_within(*max_amount, request.constraint.amount)
                && counterparty_allowed(allowed_validators, &request.constraint.counterparty)
        }
        (
            AuthorizationDetail::Vote { allowed_proposals },
            A::Vote,
        ) => match (allowed_proposals, request.constraint.resource_id.as_ref()) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(ids), Some(p)) => ids.iter().any(|id| id == p),
        },
        (
            AuthorizationDetail::Contract {
                allowed_contracts,
                allow_deploy,
            },
            A::Contract,
        ) => {
            // Deploy is permitted iff the grant explicitly allows it
            // *and* the request does not name a target address (deploy
            // requests have no target). For call requests we check the
            // allow-list.
            match &request.constraint.counterparty {
                None => *allow_deploy,
                Some(addr) => match allowed_contracts {
                    None => true,
                    Some(list) => list.iter().any(|a| a == addr),
                },
            }
        }
        (
            AuthorizationDetail::RegisterIdentity { .. },
            A::RegisterIdentity,
        ) => {
            // Counter enforcement (max_children) is the engine's
            // responsibility but lives outside the cover-check — the
            // engine tracks issuance counts in the audit log.
            true
        }
        (
            AuthorizationDetail::ResourceInvocation {
                max_amount_per_call,
                class,
                allowed_resource_ids,
            },
            A::InvokeResource,
        ) => {
            amount_within(*max_amount_per_call, request.constraint.amount)
                && match request
                    .constraint
                    .resource_id
                    .as_deref()
                    .and_then(|rid| rid.split_once(':'))
                {
                    Some((req_class, req_id)) => {
                        class.as_deref().is_none_or(|c| c == req_class)
                            && allowed_resource_ids
                                .as_ref()
                                .is_none_or(|ids| ids.iter().any(|i| i == req_id))
                    }
                    // The caller did not qualify the resource by class, so
                    // neither allow-list can be checked — only a grant that
                    // restricts nothing covers it.
                    None => class.is_none() && allowed_resource_ids.is_none(),
                }
        }
        _ => false,
    }
}

fn asset_matches(grant: &tenzro_types::AssetId, request: Option<&tenzro_types::AssetId>) -> bool {
    match request {
        None => false,
        Some(a) => a == grant,
    }
}

fn amount_within(max: u128, request: Option<u128>) -> bool {
    match request {
        None => false,
        Some(a) => a <= max,
    }
}

fn counterparty_allowed(
    allowed: &Option<Vec<tenzro_types::Address>>,
    request: &Option<tenzro_types::Address>,
) -> bool {
    match (allowed, request) {
        (None, _) => true,                       // unrestricted grant
        (Some(_), None) => false,                // grant restricts but request unspecified
        (Some(list), Some(addr)) => list.iter().any(|a| a == addr),
    }
}

/// Build an [`AuthorizationDetail`] reflecting an in-flight
/// [`AuthorityRequest`]. Used when persisting an HITL approval record
/// so the approver UI sees the same RAR shape that an actual grant
/// would carry. The asset/amount/counterparty fields are pulled from
/// `request.constraint`; missing values fall back to TNZO and 0
/// respectively (the approver still sees the original `summary` and
/// can refuse on insufficient detail).
fn authority_request_to_detail(request: &AuthorityRequest) -> AuthorizationDetail {
    let asset = request
        .constraint
        .asset
        .clone()
        .unwrap_or_else(tenzro_types::AssetId::tnzo);
    let amount = request.constraint.amount.unwrap_or(0);
    let counterparty = request.constraint.counterparty;
    match request.action {
        AuthorityAction::Transfer => AuthorizationDetail::Transfer {
            asset,
            max_amount: amount,
            max_daily_amount: None,
            allowed_counterparties: counterparty.map(|c| vec![c]),
        },
        AuthorityAction::CreateEscrow => AuthorizationDetail::CreateEscrow {
            asset,
            max_amount: amount,
            allowed_payees: counterparty.map(|c| vec![c]),
        },
        AuthorityAction::DischargeEscrow => {
            let allowed_escrow_ids = request
                .constraint
                .resource_id
                .as_ref()
                .and_then(|rid| hex::decode(rid.trim_start_matches("0x")).ok())
                .and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut buf = [0u8; 32];
                        buf.copy_from_slice(&bytes);
                        Some(vec![buf])
                    } else {
                        None
                    }
                });
            AuthorizationDetail::DischargeEscrow { allowed_escrow_ids }
        }
        AuthorityAction::Inference => AuthorizationDetail::Inference {
            max_amount_per_call: amount,
            max_daily_amount: None,
            allowed_model_ids: request.constraint.resource_id.clone().map(|m| vec![m]),
        },
        AuthorityAction::Stake => AuthorizationDetail::Stake {
            max_amount: amount,
            allowed_validators: counterparty.map(|c| vec![c]),
        },
        AuthorityAction::Vote => AuthorizationDetail::Vote {
            allowed_proposals: request.constraint.resource_id.clone().map(|p| vec![p]),
        },
        AuthorityAction::Contract => AuthorizationDetail::Contract {
            allowed_contracts: counterparty.map(|c| vec![c]),
            allow_deploy: request.constraint.counterparty.is_none(),
        },
        AuthorityAction::RegisterIdentity => AuthorizationDetail::RegisterIdentity {
            max_children: None,
        },
        AuthorityAction::InvokeResource => {
            let (class, allowed_resource_ids) = match request
                .constraint
                .resource_id
                .as_deref()
                .and_then(|rid| rid.split_once(':'))
            {
                Some((c, id)) => (Some(c.to_string()), Some(vec![id.to_string()])),
                None => (None, None),
            };
            AuthorizationDetail::ResourceInvocation {
                max_amount_per_call: amount,
                class,
                allowed_resource_ids,
            }
        }
    }
}

/// Returns `Ok(())` iff `constraints` (an AAP capability constraint
/// object, as `serde_json::Value`) permits the inbound `request`.
/// Returns `Err(reason)` describing the first violation otherwise.
///
/// `constraints` `null` is treated as "unrestricted" — every request
/// is permitted. Recognized keys (per
/// [`crate::AapConstraints`]): `max_value`, `allowed_assets`,
/// `allowed_chains` (not enforced here — chain selection is a
/// transaction-builder concern), `allowed_protocols` (likewise),
/// `allowed_counterparties`, `allowed_resources`.
fn aap_constraints_permit(
    constraints: &serde_json::Value,
    request: &ResourceConstraint,
) -> std::result::Result<(), String> {
    if constraints.is_null() {
        return Ok(());
    }
    let cs = crate::aap::AapConstraints::from_value(constraints);

    // max_value
    if let Some(max_v_str) = &cs.max_value {
        let max_v: u128 = max_v_str
            .parse()
            .map_err(|e| format!("max_value not a u128: {}", e))?;
        match request.amount {
            None => return Err("constraint sets max_value but request has no amount".to_string()),
            Some(req) if req > max_v => {
                return Err(format!("amount {} exceeds max_value {}", req, max_v));
            }
            Some(_) => {}
        }
    }

    // allowed_assets — check the request's asset id stringification
    // matches one entry. We compare on the asset's display form to
    // avoid leaking AssetId internals into the constraint vocabulary.
    if let Some(allowed) = &cs.allowed_assets {
        let req_asset = match &request.asset {
            Some(a) => a.as_str().to_string(),
            None => return Err("constraint restricts allowed_assets but request has no asset".to_string()),
        };
        if !allowed.iter().any(|a| a == &req_asset) {
            return Err(format!("asset {} not in allowed_assets", req_asset));
        }
    }

    // allowed_counterparties — request.counterparty must be in the
    // list (when the constraint sets one). Compared on hex form.
    if let Some(allowed) = &cs.allowed_counterparties {
        let req_cp = match &request.counterparty {
            Some(c) => format!("{}", c),
            None => return Err(
                "constraint restricts allowed_counterparties but request has no counterparty".to_string()
            ),
        };
        if !allowed.iter().any(|a| a == &req_cp) {
            return Err(format!("counterparty {} not in allowed_counterparties", req_cp));
        }
    }

    // allowed_resources — request.resource_id must be in the list.
    if let Some(allowed) = &cs.allowed_resources {
        let req_res = match &request.resource_id {
            Some(r) => r.clone(),
            None => return Err(
                "constraint restricts allowed_resources but request has no resource_id".to_string()
            ),
        };
        if !allowed.iter().any(|a| a == &req_res) {
            return Err(format!("resource {} not in allowed_resources", req_res));
        }
    }

    // allowed_chains and allowed_protocols are not enforced here:
    // chain selection lives at the transaction-builder layer (the
    // AuthorityRequest doesn't carry a chain id), and protocol
    // selection is a payment-gateway concern. They survive in the
    // token for downstream consumers.

    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Generate a new ULID (Crockford-base32, 26 chars). We don't pull in
/// the `ulid` crate just for one call site; instead we synthesize from
/// 48-bit ms timestamp + 80-bit randomness, encoded with the standard
/// alphabet.
fn new_ulid() -> String {
    use rand::RngCore;
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    let ts_ms = unix_now_ms() & ((1u64 << 48) - 1);
    let mut rand_bytes = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut rand_bytes);

    // 128-bit value: high 48 bits = ts, low 80 bits = randomness.
    let mut bytes = [0u8; 16];
    bytes[0..6].copy_from_slice(&ts_ms.to_be_bytes()[2..8]);
    bytes[6..16].copy_from_slice(&rand_bytes);

    // Encode 128 bits to 26 base32 chars (130 bits, top 2 bits are 0).
    let mut acc: u128 = 0;
    for &b in &bytes {
        acc = (acc << 8) | (b as u128);
    }
    let mut out = [0u8; 26];
    for i in (0..26).rev() {
        out[i] = ALPHABET[(acc & 0x1f) as usize];
        acc >>= 5;
    }
    String::from_utf8(out.to_vec()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn engine() -> AuthEngine {
        let cfg = AuthEngineConfig::new(
            "did:tenzro:node:test",
            "https://rpc.test",
            vec![0x42; 32],
        );
        AuthEngine::new(cfg, Arc::new(MemoryStore::new())).expect("engine")
    }

    #[test]
    fn issue_then_validate_roundtrip_without_dpop() {
        let e = engine();
        let token = e
            .issue_jwt(
                "did:tenzro:human:abc",
                "did:tenzro:human:abc",
                "fake-jkt",
                AuthorizationDetails::empty(),
                None,
            )
            .expect("issue");
        let claims = e.validate_jwt(&token, None).expect("validate");
        assert_eq!(claims.sub, "did:tenzro:human:abc");
        assert_eq!(claims.cnf.as_ref().map(|c| c.jkt.as_str()), Some("fake-jkt"));
    }

    #[test]
    fn revocation_blocks_subsequent_validation() {
        let e = engine();
        let token = e
            .issue_jwt(
                "did:tenzro:human:def",
                "did:tenzro:human:def",
                "jkt2",
                AuthorizationDetails::empty(),
                None,
            )
            .unwrap();
        let claims = e.validate_jwt(&token, None).unwrap();
        e.revoke(&claims.jti, "test").unwrap();
        let err = e.validate_jwt(&token, None).unwrap_err();
        assert!(matches!(err, AuthError::TokenRevoked(_)));
    }

    #[test]
    fn rar_denies_action_outside_envelope() {
        let e = engine();
        let token = e
            .issue_jwt(
                "did:tenzro:human:ghi",
                "did:tenzro:human:ghi",
                "jkt3",
                AuthorizationDetails::empty(),
                None,
            )
            .unwrap();
        let claims = e.validate_jwt(&token, None).unwrap();
        let req = AuthorityRequest {
            action: AuthorityAction::Transfer,
            constraint: ResourceConstraint {
                asset: Some(tenzro_types::AssetId("TNZO".into())),
                amount: Some(1_000),
                counterparty: None,
                resource_id: None,
            },
            approval_id: None,
        };
        let decision = e.resolve_authority(&claims, &req, None).unwrap();
        assert!(matches!(decision, AuthorityDecision::Deny { .. }));
    }

    #[test]
    fn rar_permits_action_within_envelope() {
        let e = engine();
        let details = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: tenzro_types::AssetId("TNZO".into()),
            max_amount: 10_000,
            max_daily_amount: None,
            allowed_counterparties: None,
        });
        let token = e
            .issue_jwt(
                "did:tenzro:machine:jkl",
                "did:tenzro:human:parent",
                "jkt4",
                details,
                None,
            )
            .unwrap();
        let claims = e.validate_jwt(&token, None).unwrap();
        let req = AuthorityRequest {
            action: AuthorityAction::Transfer,
            constraint: ResourceConstraint {
                asset: Some(tenzro_types::AssetId("TNZO".into())),
                amount: Some(5_000),
                counterparty: None,
                resource_id: None,
            },
            approval_id: None,
        };
        let decision = e
            .resolve_authority(&claims, &req, Some("wallet-1".into()))
            .unwrap();
        match decision {
            AuthorityDecision::Permit { wallet_id } => assert_eq!(wallet_id, "wallet-1"),
            other => panic!("expected Permit, got {:?}", other),
        }
    }

    fn make_pending_record(id: &str, approver: &str, ttl_ms: u64) -> ApprovalRecord {
        let now = unix_now_ms();
        ApprovalRecord {
            approval_id: id.into(),
            requester_did: "did:tenzro:machine:agent".into(),
            approver_did: approver.into(),
            created_at_ms: now,
            expires_at_ms: now + ttl_ms,
            action: AuthorizationDetail::Transfer {
                asset: tenzro_types::AssetId("TNZO".into()),
                max_amount: 1_000_000,
                max_daily_amount: None,
                allowed_counterparties: None,
            },
            summary: "Transfer 1 TNZO".into(),
            status: ApprovalStatus::Pending,
            decided_at_ms: None,
            deny_reason: None,
        }
    }

    #[test]
    fn approval_lifecycle_pending_to_approved_to_consumed() {
        let e = engine();
        let rec = make_pending_record("apv-1", "did:tenzro:human:alice", 60_000);
        e.record_approval(rec).unwrap();

        let listed = e.list_pending_for_approver("did:tenzro:human:alice").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].approval_id, "apv-1");

        let decided = e
            .decide_approval("apv-1", ApprovalStatus::Approved, Some("did:tenzro:human:alice"), None)
            .unwrap();
        assert_eq!(decided.status, ApprovalStatus::Approved);
        assert!(decided.decided_at_ms.is_some());

        // Pending index dropped.
        assert!(e
            .list_pending_for_approver("did:tenzro:human:alice")
            .unwrap()
            .is_empty());

        let consumed = e.consume_approval("apv-1").unwrap();
        assert_eq!(consumed.status, ApprovalStatus::Consumed);

        // Cannot consume twice.
        let err = e.consume_approval("apv-1").unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
    }

    /// Issues a token whose controller has put `transfer` on the
    /// always-ask list, and returns the engine plus validated claims.
    fn oversight_engine_and_claims(approver: &str) -> (AuthEngine, AuthClaims) {
        let e = engine();
        let details = AuthorizationDetails::single(AuthorizationDetail::Transfer {
            asset: tenzro_types::AssetId("TNZO".into()),
            max_amount: 10_000,
            max_daily_amount: None,
            allowed_counterparties: None,
        });
        let token = e
            .issue_jwt_with_aap(
                "did:tenzro:machine:overseen",
                approver,
                "jkt-oversight",
                details,
                None,
                AapOverrides {
                    oversight: Some(AapOversightClaim {
                        requires_human_approval_for: vec!["transfer".into()],
                        approver_did: Some(approver.into()),
                        approval_ttl_secs: Some(600),
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        let claims = e.validate_jwt(&token, None).unwrap();
        (e, claims)
    }

    fn transfer_request(amount: u128, approval_id: Option<String>) -> AuthorityRequest {
        AuthorityRequest {
            action: AuthorityAction::Transfer,
            constraint: ResourceConstraint {
                asset: Some(tenzro_types::AssetId("TNZO".into())),
                amount: Some(amount),
                counterparty: None,
                resource_id: None,
            },
            approval_id,
        }
    }

    #[test]
    fn oversight_approved_retry_permits_and_spends_the_approval() {
        let approver = "did:tenzro:human:alice";
        let (e, claims) = oversight_engine_and_claims(approver);

        // First attempt parks on the always-ask list.
        let approval_id = match e
            .resolve_authority(&claims, &transfer_request(5_000, None), None)
            .unwrap()
        {
            AuthorityDecision::RequireApproval { approval_id } => approval_id,
            other => panic!("expected RequireApproval, got {:?}", other),
        };

        e.decide_approval(&approval_id, ApprovalStatus::Approved, Some(approver), None)
            .unwrap();

        // Retry carrying the approval now executes rather than re-parking.
        let decision = e
            .resolve_authority(
                &claims,
                &transfer_request(5_000, Some(approval_id.clone())),
                Some("wallet-overseen".into()),
            )
            .unwrap();
        match decision {
            AuthorityDecision::Permit { wallet_id } => assert_eq!(wallet_id, "wallet-overseen"),
            other => panic!("expected Permit, got {:?}", other),
        }

        // The approval is single-use, so a replay is refused.
        assert_eq!(
            e.get_approval(&approval_id).unwrap().unwrap().status,
            ApprovalStatus::Consumed
        );
        let err = e
            .resolve_authority(
                &claims,
                &transfer_request(5_000, Some(approval_id)),
                Some("wallet-overseen".into()),
            )
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
    }

    #[test]
    fn oversight_approval_does_not_authorize_a_different_action() {
        let approver = "did:tenzro:human:alice";
        let (e, claims) = oversight_engine_and_claims(approver);

        let approval_id = match e
            .resolve_authority(&claims, &transfer_request(10, None), None)
            .unwrap()
        {
            AuthorityDecision::RequireApproval { approval_id } => approval_id,
            other => panic!("expected RequireApproval, got {:?}", other),
        };
        e.decide_approval(&approval_id, ApprovalStatus::Approved, Some(approver), None)
            .unwrap();

        // Approved for 10 TNZO; redeeming against 9_000 must refuse, and
        // the approval must survive unspent.
        let err = e
            .resolve_authority(
                &claims,
                &transfer_request(9_000, Some(approval_id.clone())),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
        assert_eq!(
            e.get_approval(&approval_id).unwrap().unwrap().status,
            ApprovalStatus::Approved
        );
    }

    #[test]
    fn oversight_denial_reason_reaches_the_requesting_agent() {
        let approver = "did:tenzro:human:alice";
        let (e, claims) = oversight_engine_and_claims(approver);

        let approval_id = match e
            .resolve_authority(&claims, &transfer_request(5_000, None), None)
            .unwrap()
        {
            AuthorityDecision::RequireApproval { approval_id } => approval_id,
            other => panic!("expected RequireApproval, got {:?}", other),
        };

        e.decide_approval(
            &approval_id,
            ApprovalStatus::Denied,
            Some(approver),
            Some("wrong counterparty — route through escrow".into()),
        )
        .unwrap();

        let err = e
            .resolve_authority(&claims, &transfer_request(5_000, Some(approval_id)), None)
            .unwrap_err();
        match err {
            AuthError::Forbidden(msg) => {
                assert!(msg.contains("route through escrow"), "got: {}", msg)
            }
            other => panic!("expected Forbidden, got {:?}", other),
        }
    }

    #[test]
    fn oversight_approval_cannot_be_spent_by_another_agent() {
        let approver = "did:tenzro:human:alice";
        let (e, claims) = oversight_engine_and_claims(approver);

        let approval_id = match e
            .resolve_authority(&claims, &transfer_request(5_000, None), None)
            .unwrap()
        {
            AuthorityDecision::RequireApproval { approval_id } => approval_id,
            other => panic!("expected RequireApproval, got {:?}", other),
        };
        e.decide_approval(&approval_id, ApprovalStatus::Approved, Some(approver), None)
            .unwrap();

        // A different bearer under the same controller and the same
        // always-ask list must not be able to redeem it.
        let mut impostor = claims.clone();
        impostor.sub = "did:tenzro:machine:impostor".into();
        let err = e
            .resolve_authority(
                &impostor,
                &transfer_request(5_000, Some(approval_id)),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
    }

    #[test]
    fn approval_decide_rejects_wrong_approver() {
        let e = engine();
        let rec = make_pending_record("apv-2", "did:tenzro:human:alice", 60_000);
        e.record_approval(rec).unwrap();

        let err = e
            .decide_approval("apv-2", ApprovalStatus::Approved, Some("did:tenzro:human:eve"), None)
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
    }

    #[test]
    fn approval_decide_rejects_terminal_state() {
        let e = engine();
        let rec = make_pending_record("apv-3", "did:tenzro:human:alice", 60_000);
        e.record_approval(rec).unwrap();
        e.decide_approval("apv-3", ApprovalStatus::Denied, None, None)
            .unwrap();

        let err = e
            .decide_approval("apv-3", ApprovalStatus::Approved, None, None)
            .unwrap_err();
        assert!(matches!(err, AuthError::Internal(_)));
    }

    #[test]
    fn approval_decide_rejects_invalid_decision() {
        let e = engine();
        let rec = make_pending_record("apv-4", "did:tenzro:human:alice", 60_000);
        e.record_approval(rec).unwrap();

        let err = e
            .decide_approval("apv-4", ApprovalStatus::Pending, None, None)
            .unwrap_err();
        assert!(matches!(err, AuthError::Internal(_)));
    }

    #[test]
    fn approval_get_lazy_expires_pending() {
        let e = engine();
        // ttl=0 → expires_at_ms is now; the lazy-expiry branch fires
        // on the next get_approval.
        let rec = make_pending_record("apv-5", "did:tenzro:human:alice", 0);
        e.record_approval(rec).unwrap();

        // Sleep one ms to guarantee strict inequality.
        std::thread::sleep(std::time::Duration::from_millis(2));

        let got = e.get_approval("apv-5").unwrap().unwrap();
        assert_eq!(got.status, ApprovalStatus::Expired);
        assert!(got.decided_at_ms.is_some());

        // Pending index should be gone too.
        assert!(e
            .list_pending_for_approver("did:tenzro:human:alice")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn approval_consume_rejects_non_approved() {
        let e = engine();
        let rec = make_pending_record("apv-6", "did:tenzro:human:alice", 60_000);
        e.record_approval(rec).unwrap();
        // Still Pending — cannot consume.
        let err = e.consume_approval("apv-6").unwrap_err();
        assert!(matches!(err, AuthError::Forbidden(_)));
    }

    /// Issue a JWT for `bearer` under `controller`, then return its
    /// claims (which carries the JTI we'll later revoke).
    fn issue_and_validate(
        e: &AuthEngine,
        bearer: &str,
        controller: &str,
        jkt: &str,
    ) -> AuthClaims {
        let token = e
            .issue_jwt(
                bearer,
                controller,
                jkt,
                AuthorizationDetails::empty(),
                None,
            )
            .unwrap();
        e.validate_jwt(&token, None).unwrap()
    }

    #[test]
    fn revoke_jti_cascades_one_level() {
        let e = engine();
        let parent = issue_and_validate(&e, "did:tenzro:human:p", "did:tenzro:human:p", "jkt-p");
        let _child = issue_and_validate(&e, "did:tenzro:machine:c", "did:tenzro:human:p", "jkt-c");

        // Before revocation, both validate.
        // (Already validated at issue_and_validate time.)

        e.revoke(&parent.jti, "compromised").unwrap();

        // Child's controller_did is the parent's bearer DID, which is
        // now revoked → child should be rejected.
        let child_jti_revoked = e
            .revoked_controllers
            .contains_key("did:tenzro:human:p");
        assert!(
            child_jti_revoked,
            "parent bearer should be in revoked_controllers"
        );
    }

    #[test]
    fn revoke_jti_cascades_multiple_levels() {
        let e = engine();
        // Chain: A → B → C → D
        let a = issue_and_validate(&e, "A", "A", "jkt-a");
        let _b = issue_and_validate(&e, "B", "A", "jkt-b");
        let _c = issue_and_validate(&e, "C", "B", "jkt-c");
        let _d = issue_and_validate(&e, "D", "C", "jkt-d");

        e.revoke(&a.jti, "root compromise").unwrap();

        // All four DIDs should be in revoked_controllers (transitive
        // closure).
        for did in &["A", "B", "C", "D"] {
            assert!(
                e.revoked_controllers.contains_key(*did),
                "expected {} to be in revoked_controllers after cascade",
                did
            );
        }

        // All four JTIs should be in revoked_jtis (each affected JTI
        // was directly added).
        assert!(e.revoked_jtis.contains_key(&a.jti));
        // We don't have b/c/d's JTIs because they were issued via
        // issue_and_validate which discards the claims — but the
        // controller-level cascade is what validation actually cares
        // about, so the next test confirms validation rejects them.
    }

    #[test]
    fn revoke_jti_cascade_rejects_descendant_validation() {
        let e = engine();
        let a = issue_and_validate(&e, "A2", "A2", "jkt-a2");
        let token_b = e
            .issue_jwt("B2", "A2", "jkt-b2", AuthorizationDetails::empty(), None)
            .unwrap();
        // Sanity: B2 validates before revocation.
        e.validate_jwt(&token_b, None).unwrap();

        e.revoke(&a.jti, "x").unwrap();

        // B2's controller is A2, which is now revoked. Validation
        // should fail with TokenRevoked.
        let err = e.validate_jwt(&token_b, None).unwrap_err();
        assert!(matches!(err, AuthError::TokenRevoked(_)));
    }

    #[test]
    fn revoke_jti_cascades_to_all_siblings() {
        let e = engine();
        let parent = issue_and_validate(&e, "P", "P", "jkt-p");
        let token_s1 = e
            .issue_jwt("S1", "P", "jkt-s1", AuthorizationDetails::empty(), None)
            .unwrap();
        let token_s2 = e
            .issue_jwt("S2", "P", "jkt-s2", AuthorizationDetails::empty(), None)
            .unwrap();

        e.revoke(&parent.jti, "x").unwrap();

        // Both siblings under P should be rejected.
        assert!(matches!(
            e.validate_jwt(&token_s1, None).unwrap_err(),
            AuthError::TokenRevoked(_)
        ));
        assert!(matches!(
            e.validate_jwt(&token_s2, None).unwrap_err(),
            AuthError::TokenRevoked(_)
        ));
    }

    #[test]
    fn revoke_did_revokes_all_descendants_without_parent_jti() {
        let e = engine();
        // Issue a child token but never the parent's own — we still
        // want revoke_did(parent) to take down the child.
        let token_c = e
            .issue_jwt("X-c", "X", "jkt-xc", AuthorizationDetails::empty(), None)
            .unwrap();
        e.validate_jwt(&token_c, None).unwrap();

        let count = e.revoke_did("X", "lost keys").unwrap();
        assert_eq!(count, 1, "should mark exactly one JTI revoked");

        assert!(e.revoked_controllers.contains_key("X"));
        assert!(matches!(
            e.validate_jwt(&token_c, None).unwrap_err(),
            AuthError::TokenRevoked(_)
        ));
    }

    #[test]
    fn cascade_writes_audit_rows_for_each_descendant() {
        let e = engine();
        let parent = issue_and_validate(&e, "AUD-P", "AUD-P", "jkt-aud-p");
        let _ = e
            .issue_jwt("AUD-C1", "AUD-P", "jkt-c1", AuthorizationDetails::empty(), None)
            .unwrap();
        let _ = e
            .issue_jwt("AUD-C2", "AUD-P", "jkt-c2", AuthorizationDetails::empty(), None)
            .unwrap();

        e.revoke(&parent.jti, "audit-test").unwrap();

        // Walk the audit log and count cascaded Revoked events that
        // point back at the parent revocation.
        let entries = e.storage.scan_prefix(CF_AUDIT, b"audit:").unwrap();
        let mut cascaded_count = 0usize;
        for (_k, v) in entries {
            let ev: AuditEvent = match serde_json::from_slice(&v) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if let AuditEventKind::Revoked {
                cascaded,
                parent_event_id,
                ..
            } = ev.kind
                && cascaded
                && parent_event_id.is_some()
            {
                cascaded_count += 1;
            }
        }
        assert_eq!(
            cascaded_count, 2,
            "expected one cascaded audit event per descendant JTI"
        );
    }

    #[test]
    fn cascade_is_cycle_safe() {
        // A cycle in the act-chain shouldn't loop forever. We construct
        // one by hand: token_a issued under controller_did=B, token_b
        // issued under controller_did=A. Both are valid until either
        // is revoked.
        let e = engine();
        let token_a = e
            .issue_jwt("CYC-A", "CYC-B", "jkt-ca", AuthorizationDetails::empty(), None)
            .unwrap();
        let token_b = e
            .issue_jwt("CYC-B", "CYC-A", "jkt-cb", AuthorizationDetails::empty(), None)
            .unwrap();
        let claims_a = e.validate_jwt(&token_a, None).unwrap();
        e.validate_jwt(&token_b, None).unwrap();

        // Should terminate.
        e.revoke(&claims_a.jti, "cycle test").unwrap();

        assert!(e.revoked_controllers.contains_key("CYC-A"));
        assert!(e.revoked_controllers.contains_key("CYC-B"));
    }

    #[test]
    fn cascade_closure_survives_restart() {
        // Use a shared MemoryStore so a second engine sees the same
        // audit log.
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let cfg = AuthEngineConfig::new("did:tenzro:node:test", "https://rpc.test", vec![0x42; 32]);

        let e1 = AuthEngine::new(cfg.clone(), storage.clone()).unwrap();
        let parent = issue_and_validate(&e1, "RHY-P", "RHY-P", "jkt-rp");
        let token_c = e1
            .issue_jwt(
                "RHY-C",
                "RHY-P",
                "jkt-rc",
                AuthorizationDetails::empty(),
                None,
            )
            .unwrap();
        e1.revoke(&parent.jti, "x").unwrap();
        drop(e1);

        // Reopen with the same storage — hydration must rebuild the
        // closure.
        let e2 = AuthEngine::new(cfg, storage).unwrap();
        assert!(e2.revoked_controllers.contains_key("RHY-P"));
        assert!(matches!(
            e2.validate_jwt(&token_c, None).unwrap_err(),
            AuthError::TokenRevoked(_)
        ));
    }

    fn invoke_request(resource_id: Option<&str>, amount: u128) -> AuthorityRequest {
        AuthorityRequest {
            action: AuthorityAction::InvokeResource,
            constraint: ResourceConstraint {
                asset: Some(tenzro_types::AssetId::tnzo()),
                amount: Some(amount),
                counterparty: None,
                resource_id: resource_id.map(|s| s.to_string()),
            },
            approval_id: None,
        }
    }

    #[test]
    fn resource_invocation_grant_restricts_class_id_and_ceiling() {
        let grant = AuthorizationDetail::ResourceInvocation {
            max_amount_per_call: 1_000,
            class: Some("skill".to_string()),
            allowed_resource_ids: Some(vec!["web-search".to_string()]),
        };

        assert!(detail_covers(&grant, &invoke_request(Some("skill:web-search"), 1_000)));
        // Ceiling is per call.
        assert!(!detail_covers(&grant, &invoke_request(Some("skill:web-search"), 1_001)));
        // Wrong class.
        assert!(!detail_covers(&grant, &invoke_request(Some("tool:web-search"), 10)));
        // Id outside the allow-list.
        assert!(!detail_covers(&grant, &invoke_request(Some("skill:code-review"), 10)));
        // Unqualified id cannot be checked against either allow-list.
        assert!(!detail_covers(&grant, &invoke_request(Some("web-search"), 10)));
    }

    #[test]
    fn unrestricted_resource_invocation_grant_covers_any_resource() {
        let grant = AuthorizationDetail::ResourceInvocation {
            max_amount_per_call: 500,
            class: None,
            allowed_resource_ids: None,
        };

        assert!(detail_covers(&grant, &invoke_request(Some("tool:code-executor"), 500)));
        assert!(detail_covers(&grant, &invoke_request(None, 1)));
        assert!(!detail_covers(&grant, &invoke_request(Some("tool:code-executor"), 501)));
    }

    #[test]
    fn resource_invocation_request_round_trips_into_a_grant() {
        let detail = authority_request_to_detail(&invoke_request(Some("skill:web-search"), 250));
        match detail {
            AuthorizationDetail::ResourceInvocation {
                max_amount_per_call,
                class,
                allowed_resource_ids,
            } => {
                assert_eq!(max_amount_per_call, 250);
                assert_eq!(class.as_deref(), Some("skill"));
                assert_eq!(allowed_resource_ids, Some(vec!["web-search".to_string()]));
            }
            other => panic!("expected ResourceInvocation, got {other:?}"),
        }
    }

    #[test]
    fn ttl_clamped_to_max() {
        let e = engine();
        let token = e
            .issue_jwt(
                "did:tenzro:human:mno",
                "did:tenzro:human:mno",
                "jkt5",
                AuthorizationDetails::empty(),
                Some(u64::MAX),
            )
            .unwrap();
        let claims = e.validate_jwt(&token, None).unwrap();
        // exp - iat must equal max_ttl_secs (24h)
        assert_eq!(claims.exp - claims.iat, 24 * 3600);
    }
}
