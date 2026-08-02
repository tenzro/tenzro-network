//! Operator-set admission gate for a node's whole service surface.
//!
//! Lets an operator require a key before their node serves anyone, across
//! JSON-RPC, MCP, A2A and the HTTP web API — rather than only the
//! operator-class RPCs the admin token already covers.
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

/// The operator's admission policy for this node.
#[derive(Debug, Clone, Default)]
pub struct AdmissionPolicy {
    /// Accepted service keys, by digest. Empty means the gate is off.
    accepted: HashSet<ServiceKeyHash>,
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

    /// Accept a key.
    pub fn accept_key(&mut self, key: ServiceKeyHash) {
        self.accepted.insert(key);
    }

    /// Accept a key given as plaintext.
    pub fn accept_plaintext(&mut self, key: &str) {
        self.accept_key(ServiceKeyHash::from_plaintext(key));
    }

    /// Revoke a key. Takes precedence over acceptance.
    pub fn revoke_key(&mut self, key: ServiceKeyHash) {
        self.revoked.insert(key);
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
    _surface: ServiceSurface,
    path: &str,
    presented_key: Option<&str>,
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
    if policy.accepted.iter().any(|k| k.matches(presented)) {
        return Admission::Allow;
    }

    Admission::Deny("service key is not recognised")
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert!(admit(&p, surface, "/anything", None).is_allowed());
        }
    }

    #[test]
    fn disabling_returns_to_permissionless() {
        let mut p = gated();
        assert!(p.is_enabled());
        p.disable();
        assert!(!p.is_enabled());
        assert!(admit(&p, ServiceSurface::JsonRpc, "/", None).is_allowed());
    }

    // ---- default-deny ------------------------------------------------------

    /// The direction that matters: with a gate configured, a request with no
    /// key is refused rather than admitted. A new endpoint therefore starts
    /// gated instead of starting open and needing to be remembered.
    #[test]
    fn a_gated_node_refuses_a_request_with_no_key() {
        assert_eq!(
            admit(&gated(), ServiceSurface::JsonRpc, "/", None),
            Admission::Deny("this node requires a service key")
        );
    }

    #[test]
    fn a_gated_node_refuses_an_unrecognised_key() {
        assert_eq!(
            admit(&gated(), ServiceSurface::Mcp, "/mcp", Some("guess")),
            Admission::Deny("service key is not recognised")
        );
    }

    #[test]
    fn a_gated_node_admits_the_configured_key() {
        assert!(
            admit(
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
                !admit(&p, surface, "/some/path", None).is_allowed(),
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
                admit(&p, ServiceSurface::WebApi, path, None).is_allowed(),
                "{path} must never be gated"
            );
        }
    }

    #[test]
    fn a_query_string_does_not_bypass_or_break_the_probe_exemption() {
        let p = gated();
        assert!(admit(&p, ServiceSurface::WebApi, "/health?verbose=1", None).is_allowed());
        // …and a path that merely starts with a probe name is still gated.
        assert!(!admit(&p, ServiceSurface::WebApi, "/healthz", None).is_allowed());
        assert!(!admit(&p, ServiceSurface::WebApi, "/health/secret", None).is_allowed());
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
            admit(
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

        assert!(!admit(&p, ServiceSurface::JsonRpc, "/", Some("key-a")).is_allowed());
        assert!(admit(&p, ServiceSurface::JsonRpc, "/", Some("key-b")).is_allowed());
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
        if let Admission::Deny(reason) = admit(&gated(), ServiceSurface::JsonRpc, "/", Some(secret))
        {
            assert!(!reason.contains(secret));
        } else {
            panic!("expected a denial");
        }
    }
}
