//! Operator-set admission gate for a node's service surfaces.
//!
//! Lets an operator require a key before their node serves anyone, across
//! JSON-RPC, MCP, A2A and the HTTP web API — rather than only the
//! operator-class RPCs the admin token already covers.
//!
//! # Three credentials, three questions
//!
//! Tenzro has three ways a caller earns access, and they answer different
//! questions. Conflating them is what made a gated node unable to serve a
//! model it had published to the network.
//!
//! | Credential | Question it answers | Scope lives on |
//! | --- | --- | --- |
//! | **Service key** (this module) | *May you use this machine's raw resources?* — a confined shell, storage, memory, compute | [`ServiceKeyGrant`] here, plus `AccessLease`/`AccessScope` in `tenzro_node::remote_access` for capacity |
//! | **API key** | *May you use this resource, on these terms?* — per-resource scopes, tier ceilings, rate budget, Canton bindings | `ApiKeyRecord.scopes` in `tenzro_node::api_key` |
//! | **Payment** | *Have you paid for this call?* — x402 / TNZO settlement, on demand, no prior relationship | the model's own price and the settlement path |
//!
//! A service key is a **rental credential**: it is bought for a period, up to
//! a capacity, over named resources. It is emphatically *not* a licence to
//! decide what the node serves — an operator renting out a GPU has not thereby
//! said anything about which models are public.
//!
//! # Model serving does not answer to this gate
//!
//! Which callers may invoke a model is a property of the model, expressed by
//! `ModelVisibility`:
//!
//! - `Network` — published to the network, reachable by **payment alone**. No
//!   service key, no prior relationship; a peer that found the offer over
//!   gossip has no way to obtain either.
//! - `Gated` — servable, but to callers holding an API key whose policy the
//!   operator pre-agreed.
//! - `Private` — never offered off-node.
//!
//! So a node may be gated at this layer and still serve a `Network` model to
//! anyone who pays. That is the point: the two decisions are unrelated, and
//! the previous design forced them to agree.
//!
//! # One registry
//!
//! There used to be two things called a "service key": the scoped, expiring,
//! lease-bound credential in `remote_access`, and a flat set of bare digests
//! here that gated all four surfaces with no scope, expiry or subject. An
//! operator could not tell which one they held. They are now one registry —
//! every accepted key carries a [`ServiceKeyGrant`], and a bare digest in
//! config is simply an unrestricted grant, so existing configuration keeps
//! working unchanged.
//!
//! # What this deliberately does not gate
//!
//! **Consensus and P2P.** A gated node still validates blocks, votes, and
//! gossips. The gate is on the *service* surface only. A node that stopped
//! participating in consensus because its operator wanted to restrict who can
//! call its inference API would be withholding from the network something it
//! is staked to provide, and the two decisions are unrelated.
//!
//! This is structural rather than a rule to remember: [`ServiceSurface`] has no
//! variant for consensus or gossip, so there is no way to ask this type whether
//! a block proposal should be admitted.
//!
//! **Liveness probes.** `/health` and `/ready` are never gated. Operators put
//! nodes behind load balancers and orchestrators that cannot present
//! credentials, and a gate that makes a node look dead to its own supervisor
//! causes an outage rather than preventing one.
//!
//! # Off by default
//!
//! The network is permissionless. [`AdmissionPolicy::default`] admits
//! everything, so a node that never configures a gate behaves exactly as
//! before.
//!
//! # Keys are hashed at rest
//!
//! Only SHA-256 digests are stored, and comparison is constant-time. The
//! plaintext key exists in the operator's hands and in the request header,
//! never in the node's config file, logs, or memory beyond the comparison.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Which service surface a request arrived on.
///
/// Note the absence of consensus and gossip variants — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceSurface {
    /// JSON-RPC (`:8545`).
    JsonRpc,
    /// Model Context Protocol (`:3001`).
    Mcp,
    /// Agent-to-Agent protocol (`:3002`).
    A2a,
    /// HTTP web/verification API (`:8080`).
    WebApi,
}

impl ServiceSurface {
    /// Stable label for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceSurface::JsonRpc => "json_rpc",
            ServiceSurface::Mcp => "mcp",
            ServiceSurface::A2a => "a2a",
            ServiceSurface::WebApi => "web_api",
        }
    }
}

/// Paths that are never gated, whatever the policy says.
///
/// Kept as data rather than scattered `if` checks so the exemption is auditable
/// in one place, and so adding a surface cannot accidentally start gating them.
pub const NEVER_GATED_PATHS: &[&str] = &["/health", "/ready", "/verify/health", "/verify/ready"];

/// Whether `path` is a liveness probe that must always be reachable.
pub fn is_never_gated(path: &str) -> bool {
    // Compare the path only; a query string does not change what is being asked.
    let path = path.split('?').next().unwrap_or(path);
    NEVER_GATED_PATHS.contains(&path)
}

/// A service key, stored as its digest.
///
/// Constructed from plaintext once, at configuration time. There is no accessor
/// for the plaintext because nothing downstream needs it, and an accessor is how
/// a secret ends up in a log line.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceKeyHash(String);

impl ServiceKeyHash {
    /// Hash a plaintext key.
    pub fn from_plaintext(key: &str) -> Self {
        Self(hex::encode(Sha256::digest(key.as_bytes())))
    }

    /// Adopt an already-computed hex digest, e.g. read from a config file.
    pub fn from_hex(hex_digest: impl Into<String>) -> Self {
        Self(hex_digest.into().to_ascii_lowercase())
    }

    /// The hex digest. Safe to log — this is not the key.
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Constant-time comparison against a presented plaintext key.
    ///
    /// Constant-time because a byte-by-byte comparison that returns early leaks
    /// how much of a guess was right, which turns key recovery into a linear
    /// search instead of an exhaustive one.
    pub fn matches(&self, presented: &str) -> bool {
        let presented = hex::encode(Sha256::digest(presented.as_bytes()));
        presented.as_bytes().ct_eq(self.0.as_bytes()).into()
    }
}

/// What one service key is permitted to reach, and until when.
///
/// # Why a grant rather than a bare digest
///
/// A service key is a **machine-level rental credential**: it buys access to
/// raw resources — a confined shell, storage, memory, compute — for a period,
/// up to a capacity. `remote_access::AccessLease` already models exactly that,
/// with `AccessScope` (devices, workspace, network, reserved inference slots)
/// and `expires_at_ms`.
///
/// This gate previously kept a *second*, unrelated set of "service keys" that
/// were bare digests with no scope, no expiry and no subject, and which gated
/// all four service surfaces at once. Two disjoint registries under one name
/// is a trap: an operator who issued a scoped rental key had no way to know it
/// was unrelated to the thing gating their node, and the unscoped door ended up
/// standing in front of model serving, which is not a raw machine resource and
/// was never what a rental key was for.
///
/// So there is one registry now, and every accepted key carries a grant.
///
/// # Capacity lives on the lease
///
/// This type carries the *reachability* half — which surfaces, until when, and
/// which lease the key belongs to. Resource capacity (devices, cores, memory,
/// reserved slots) stays on [`AccessLease`](../../tenzro_node/remote_access)
/// because that is where it is enforced; duplicating it here would give two
/// answers to one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceKeyGrant {
    /// Digest of the key this grant belongs to.
    pub hash: ServiceKeyHash,
    /// Surfaces the key admits on. `None` means every surface.
    ///
    /// `None` is what a bare digest in `node.toml` means, so an operator who
    /// configured a key before grants existed keeps exactly the access they
    /// had. A narrowed grant is opt-in.
    pub surfaces: Option<HashSet<ServiceSurface>>,
    /// Unix milliseconds after which the key no longer admits. `None` never
    /// expires — again the historical config behaviour.
    pub expires_at_ms: Option<u64>,
    /// The rental lease this key was minted for, when it came from one. An
    /// operator-configured key has none.
    pub lease_id: Option<String>,
}

impl ServiceKeyGrant {
    /// A grant with no restrictions — every surface, no expiry, no lease.
    ///
    /// The shape a bare configured digest takes.
    pub fn unrestricted(hash: ServiceKeyHash) -> Self {
        Self {
            hash,
            surfaces: None,
            expires_at_ms: None,
            lease_id: None,
        }
    }

    /// Narrow this grant to a set of surfaces.
    pub fn on_surfaces(mut self, surfaces: impl IntoIterator<Item = ServiceSurface>) -> Self {
        self.surfaces = Some(surfaces.into_iter().collect());
        self
    }

    /// Bind this grant to a lease and its expiry.
    pub fn for_lease(mut self, lease_id: impl Into<String>, expires_at_ms: u64) -> Self {
        self.lease_id = Some(lease_id.into());
        self.expires_at_ms = Some(expires_at_ms);
        self
    }

    /// Whether this grant admits on `surface` at `now_ms`.
    pub fn admits(&self, surface: ServiceSurface, now_ms: u64) -> bool {
        if let Some(expiry) = self.expires_at_ms
            && now_ms >= expiry
        {
            return false;
        }
        match &self.surfaces {
            None => true,
            Some(set) => set.contains(&surface),
        }
    }
}

/// The operator's admission policy for this node.
#[derive(Debug, Clone, Default)]
pub struct AdmissionPolicy {
    /// Accepted service keys and what each may reach. Empty means the gate
    /// is off.
    accepted: Vec<ServiceKeyGrant>,
    /// Revoked key digests, checked before acceptance.
    ///
    /// A separate set rather than removal from `accepted` so revocation is
    /// explicit and survives a config reload that would otherwise re-add the
    /// key.
    revoked: HashSet<ServiceKeyHash>,
}

impl AdmissionPolicy {
    /// An open policy — the permissionless default.
    pub fn open() -> Self {
        Self::default()
    }

    /// Whether the gate is active. Off when no key has been configured.
    pub fn is_enabled(&self) -> bool {
        !self.accepted.is_empty()
    }

    /// Accept a key with no restrictions — every surface, no expiry.
    ///
    /// What a bare digest in `node.toml` or `TENZRO_SERVICE_KEYS` means.
    pub fn accept_key(&mut self, key: ServiceKeyHash) {
        self.accept_grant(ServiceKeyGrant::unrestricted(key));
    }

    /// Accept a key given as plaintext, unrestricted.
    pub fn accept_plaintext(&mut self, key: &str) {
        self.accept_key(ServiceKeyHash::from_plaintext(key));
    }

    /// Accept a key with an explicit grant — scoped surfaces, an expiry, or a
    /// binding to the rental lease it was minted for.
    ///
    /// Re-accepting the same digest replaces the previous grant rather than
    /// stacking a second one, so re-opening a lease under the same key
    /// narrows or extends it instead of leaving a stale wider grant behind.
    pub fn accept_grant(&mut self, grant: ServiceKeyGrant) {
        self.accepted.retain(|g| g.hash != grant.hash);
        self.accepted.push(grant);
    }

    /// The grant for a digest, if the key is accepted.
    pub fn grant_for(&self, hash: &ServiceKeyHash) -> Option<&ServiceKeyGrant> {
        self.accepted.iter().find(|g| &g.hash == hash)
    }

    /// Revoke a key. Takes precedence over acceptance.
    pub fn revoke_key(&mut self, key: ServiceKeyHash) {
        self.revoked.insert(key);
    }

    /// Drop a key's acceptance without recording a revocation.
    ///
    /// Pairs with [`Self::revoke_key`]: revocation says "this key must never
    /// work again", acceptance is what keeps the gate switched on. Revoking
    /// without also forgetting leaves a gate that is enabled by a key which
    /// can no longer open it — a node nobody can reach and nobody can un-gate.
    pub fn forget_key(&mut self, key: &ServiceKeyHash) {
        self.accepted.retain(|g| &g.hash != key);
    }

    /// Turn the gate off entirely, returning to permissionless.
    pub fn disable(&mut self) {
        self.accepted.clear();
    }

    /// Number of accepted keys.
    pub fn accepted_len(&self) -> usize {
        self.accepted.len()
    }
}

/// The gate's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Serve the request.
    Allow,
    /// Refuse, with a reason safe to return to the caller.
    ///
    /// The reason never distinguishes "no key given" from "wrong key" beyond
    /// what the caller already knows, and never echoes the presented key.
    Deny(&'static str),
}

impl Admission {
    /// Whether the request may proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Admission::Allow)
    }
}

/// Decide whether one request is admitted.
///
/// `presented_key` is whatever the caller supplied, if anything.
///
/// # Order
///
/// 1. Liveness probes are always admitted.
/// 2. A policy with no keys admits everything.
/// 3. A presented key that is revoked is refused, even if also accepted.
/// 4. A presented key that is accepted is admitted.
/// 5. Anything else is refused — including a missing key, which is the
///    default-deny direction.
pub fn admit(
    policy: &AdmissionPolicy,
    surface: ServiceSurface,
    path: &str,
    presented_key: Option<&str>,
    now_ms: u64,
) -> Admission {
    if is_never_gated(path) {
        return Admission::Allow;
    }
    if !policy.is_enabled() {
        return Admission::Allow;
    }

    let Some(presented) = presented_key else {
        return Admission::Deny("this node requires a service key");
    };

    // Revocation is checked first so a key that is both revoked and accepted
    // is refused. Acceptance is a list an operator edits; revocation is a
    // statement that a key has leaked, and that has to win.
    if policy.revoked.iter().any(|k| k.matches(presented)) {
        return Admission::Deny("service key has been revoked");
    }

    let Some(grant) = policy.accepted.iter().find(|g| g.hash.matches(presented)) else {
        return Admission::Deny("service key is not recognised");
    };

    // Expiry and scope are separate refusals because they are separate
    // operator mistakes with different remedies: one reopens a lapsed rental,
    // the other widens a grant that was narrowed on purpose.
    if let Some(expiry) = grant.expires_at_ms
        && now_ms >= expiry
    {
        return Admission::Deny("service key has expired");
    }
    if !grant.admits(surface, now_ms) {
        return Admission::Deny("service key is not scoped to this surface");
    }

    Admission::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed clock. Admission is time-dependent now that a grant may expire;
    /// pinning it keeps these tests about policy rather than about the wall.
    const T0: u64 = 1_700_000_000_000;

    fn admit_now(
        policy: &AdmissionPolicy,
        surface: ServiceSurface,
        path: &str,
        presented_key: Option<&str>,
    ) -> Admission {
        admit(policy, surface, path, presented_key, T0)
    }

    fn gated() -> AdmissionPolicy {
        let mut p = AdmissionPolicy::open();
        p.accept_plaintext("correct-horse-battery-staple");
        p
    }

    // ---- off by default ---------------------------------------------------

    /// The network is permissionless. A node that configures nothing must
    /// behave exactly as it did before the gate existed.
    #[test]
    fn an_unconfigured_policy_admits_everything() {
        let p = AdmissionPolicy::open();
        assert!(!p.is_enabled());
        for surface in [
            ServiceSurface::JsonRpc,
            ServiceSurface::Mcp,
            ServiceSurface::A2a,
            ServiceSurface::WebApi,
        ] {
            assert!(admit_now(&p, surface, "/anything", None).is_allowed());
        }
    }

    #[test]
    fn disabling_returns_to_permissionless() {
        let mut p = gated();
        assert!(p.is_enabled());
        p.disable();
        assert!(!p.is_enabled());
        assert!(admit_now(&p, ServiceSurface::JsonRpc, "/", None).is_allowed());
    }

    // ---- default-deny ------------------------------------------------------

    /// The direction that matters: with a gate configured, a request with no
    /// key is refused rather than admitted. A new endpoint therefore starts
    /// gated instead of starting open and needing to be remembered.
    #[test]
    fn a_gated_node_refuses_a_request_with_no_key() {
        assert_eq!(
            admit_now(&gated(), ServiceSurface::JsonRpc, "/", None),
            Admission::Deny("this node requires a service key")
        );
    }

    #[test]
    fn a_gated_node_refuses_an_unrecognised_key() {
        assert_eq!(
            admit_now(&gated(), ServiceSurface::Mcp, "/mcp", Some("guess")),
            Admission::Deny("service key is not recognised")
        );
    }

    #[test]
    fn a_gated_node_admits_the_configured_key() {
        assert!(
            admit_now(
                &gated(),
                ServiceSurface::A2a,
                "/a2a",
                Some("correct-horse-battery-staple")
            )
            .is_allowed()
        );
    }

    #[test]
    fn the_gate_applies_to_every_service_surface() {
        let p = gated();
        for surface in [
            ServiceSurface::JsonRpc,
            ServiceSurface::Mcp,
            ServiceSurface::A2a,
            ServiceSurface::WebApi,
        ] {
            assert!(
                !admit_now(&p, surface, "/some/path", None).is_allowed(),
                "{surface:?} was not gated"
            );
        }
    }

    // ---- liveness probes ---------------------------------------------------

    /// A gate that makes a node look dead to its own load balancer causes an
    /// outage rather than preventing one.
    #[test]
    fn liveness_probes_are_never_gated() {
        let p = gated();
        for path in ["/health", "/ready", "/verify/health", "/verify/ready"] {
            assert!(
                admit_now(&p, ServiceSurface::WebApi, path, None).is_allowed(),
                "{path} must never be gated"
            );
        }
    }

    #[test]
    fn a_query_string_does_not_bypass_or_break_the_probe_exemption() {
        let p = gated();
        assert!(admit_now(&p, ServiceSurface::WebApi, "/health?verbose=1", None).is_allowed());
        // …and a path that merely starts with a probe name is still gated.
        assert!(!admit_now(&p, ServiceSurface::WebApi, "/healthz", None).is_allowed());
        assert!(!admit_now(&p, ServiceSurface::WebApi, "/health/secret", None).is_allowed());
    }

    // ---- revocation --------------------------------------------------------

    /// Revocation is a statement that a key has leaked, so it must beat the
    /// acceptance list an operator edits.
    #[test]
    fn revocation_beats_acceptance() {
        let mut p = gated();
        p.revoke_key(ServiceKeyHash::from_plaintext(
            "correct-horse-battery-staple",
        ));
        assert_eq!(
            admit_now(
                &p,
                ServiceSurface::JsonRpc,
                "/",
                Some("correct-horse-battery-staple")
            ),
            Admission::Deny("service key has been revoked")
        );
    }

    #[test]
    fn revoking_one_key_leaves_others_working() {
        let mut p = AdmissionPolicy::open();
        p.accept_plaintext("key-a");
        p.accept_plaintext("key-b");
        p.revoke_key(ServiceKeyHash::from_plaintext("key-a"));

        assert!(!admit_now(&p, ServiceSurface::JsonRpc, "/", Some("key-a")).is_allowed());
        assert!(admit_now(&p, ServiceSurface::JsonRpc, "/", Some("key-b")).is_allowed());
    }

    // ---- key handling ------------------------------------------------------

    #[test]
    fn keys_are_stored_only_as_digests() {
        let h = ServiceKeyHash::from_plaintext("super-secret");
        assert_eq!(h.as_hex().len(), 64, "SHA-256 hex is 64 chars");
        assert!(
            !h.as_hex().contains("super-secret"),
            "the plaintext must not survive into the stored form"
        );
        assert!(h.matches("super-secret"));
        assert!(!h.matches("super-secre"));
        assert!(!h.matches("super-secrett"));
    }

    #[test]
    fn a_hex_digest_round_trips_from_config() {
        let a = ServiceKeyHash::from_plaintext("k");
        let b = ServiceKeyHash::from_hex(a.as_hex());
        assert_eq!(a, b);
        assert!(b.matches("k"));
    }

    #[test]
    fn hex_digests_from_config_are_case_insensitive() {
        let a = ServiceKeyHash::from_plaintext("k");
        let upper = ServiceKeyHash::from_hex(a.as_hex().to_ascii_uppercase());
        assert_eq!(a, upper);
    }

    /// The denial reason is returned to callers, so it must not echo what was
    /// presented.
    #[test]
    fn denial_reasons_never_echo_the_presented_key() {
        let secret = "leak-me-please";
        if let Admission::Deny(reason) =
            admit_now(&gated(), ServiceSurface::JsonRpc, "/", Some(secret))
        {
            assert!(!reason.contains(secret));
        } else {
            panic!("expected a denial");
        }
    }

    // ---- grants: scope and expiry ----------------------------------------

    /// The historical shape. An operator who wrote a bare digest into
    /// `node.toml` before grants existed must keep exactly the access they
    /// had, or an upgrade silently locks them out of their own node.
    #[test]
    fn a_bare_configured_digest_is_unrestricted() {
        let p = gated();
        let hash = ServiceKeyHash::from_plaintext("correct-horse-battery-staple");
        let grant = p.grant_for(&hash).expect("configured key has a grant");

        assert!(grant.surfaces.is_none(), "no surface restriction");
        assert!(grant.expires_at_ms.is_none(), "no expiry");
        assert!(grant.lease_id.is_none(), "not bound to a lease");
    }

    /// A rental key issued for one surface must not open the others. This is
    /// the whole point of the unification: a key bought for a confined shell
    /// is not also a key to the operator's JSON-RPC.
    #[test]
    fn a_grant_narrowed_to_one_surface_refuses_the_others() {
        let mut p = AdmissionPolicy::open();
        p.accept_grant(
            ServiceKeyGrant::unrestricted(ServiceKeyHash::from_plaintext("shell-only"))
                .on_surfaces([ServiceSurface::WebApi]),
        );

        assert!(
            admit_now(&p, ServiceSurface::WebApi, "/status", Some("shell-only")).is_allowed(),
            "admitted on its own surface"
        );
        for other in [
            ServiceSurface::JsonRpc,
            ServiceSurface::Mcp,
            ServiceSurface::A2a,
        ] {
            assert!(
                !admit_now(&p, other, "/", Some("shell-only")).is_allowed(),
                "{other:?} must be refused"
            );
        }
    }

    /// A rental has a period. Past it the key stops admitting without the
    /// operator having to remember to revoke it — an expiry nobody enforces
    /// is a rental that never ends.
    #[test]
    fn an_expired_grant_no_longer_admits() {
        let mut p = AdmissionPolicy::open();
        p.accept_grant(
            ServiceKeyGrant::unrestricted(ServiceKeyHash::from_plaintext("rental"))
                .for_lease("lease-1", T0 + 1_000),
        );

        assert!(
            admit(&p, ServiceSurface::JsonRpc, "/", Some("rental"), T0).is_allowed(),
            "inside the term"
        );
        assert!(
            !admit(&p, ServiceSurface::JsonRpc, "/", Some("rental"), T0 + 1_000).is_allowed(),
            "at the boundary the term is over"
        );
        assert!(
            !admit(
                &p,
                ServiceSurface::JsonRpc,
                "/",
                Some("rental"),
                T0 + 60_000
            )
            .is_allowed(),
            "well past the term"
        );
    }

    /// Re-opening a lease under the same key must replace its grant, not
    /// leave the older, wider one in place behind it.
    #[test]
    fn re_accepting_a_digest_replaces_its_grant() {
        let mut p = AdmissionPolicy::open();
        let hash = ServiceKeyHash::from_plaintext("reissued");

        p.accept_grant(ServiceKeyGrant::unrestricted(hash.clone()));
        assert!(admit_now(&p, ServiceSurface::Mcp, "/mcp", Some("reissued")).is_allowed());

        p.accept_grant(
            ServiceKeyGrant::unrestricted(hash.clone()).on_surfaces([ServiceSurface::WebApi]),
        );
        assert_eq!(p.accepted_len(), 1, "replaced rather than stacked");
        assert!(
            !admit_now(&p, ServiceSurface::Mcp, "/mcp", Some("reissued")).is_allowed(),
            "the narrowed grant wins"
        );
    }

    /// Revocation still beats a live, in-term grant.
    #[test]
    fn revocation_beats_an_unexpired_grant() {
        let mut p = AdmissionPolicy::open();
        p.accept_grant(
            ServiceKeyGrant::unrestricted(ServiceKeyHash::from_plaintext("leaked"))
                .for_lease("lease-2", T0 + 60_000),
        );
        p.revoke_key(ServiceKeyHash::from_plaintext("leaked"));

        assert!(!admit_now(&p, ServiceSurface::JsonRpc, "/", Some("leaked")).is_allowed());
    }
}
