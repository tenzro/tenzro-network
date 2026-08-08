//! Node aliases — the human-readable name a node is addressed by.
//!
//! A node's identity is its DID (a UUID). An alias is the readable handle
//! mapped onto it, the same relationship a `@username` has to a human DID and
//! an agent name has to an agent DID — three separate namespaces over one
//! address space, never one shared field.
//!
//! # Why a claim is a transaction, not an RPC write
//!
//! The network is permissionless: no node operator may gatekeep a name. A
//! registry held in one node's `DashMap` would mean whoever you asked
//! decides, and two operators on two nodes could each believe they own
//! `alice`. So a claim is a **consensus-mediated typed transaction**
//! (`ClaimNodeAlias`, executed by the native VM into `SYSTEM_ADDRESS`
//! storage): HotStuff-2 orders it, every node applies the identical state
//! transition, and first-claim-wins falls out of block order rather than out
//! of which RPC endpoint the claimant happened to reach.
//!
//! # Why a bare label, never a hostname
//!
//! WebAuthn requires a registrable domain for its RP ID, which is the only
//! reason a public domain is in the picture at all during testnet. That
//! domain is a *presentation* detail and is expected to change. So the claim
//! records the **bare label** (`alice`) and never the suffix; a node renders
//! `alice.<suffix>` at presentation time from its own configuration. Swapping
//! or retiring the domain must not invalidate a single claim.

use serde::{Deserialize, Serialize};

/// Maximum length of a single DNS label (RFC 1035 §2.3.4).
pub const MAX_ALIAS_LEN: usize = 63;

/// Minimum length. One-character labels are legal DNS but are reserved here —
/// the space is tiny, contested, and better allocated deliberately later than
/// consumed first-come during testnet.
pub const MIN_ALIAS_LEN: usize = 3;

/// Labels no one may claim.
///
/// Two groups, both load-bearing. Infrastructure names (`api`, `rpc`, `www`)
/// would let the first claimant sit on a hostname the network itself needs to
/// serve. Security-sensitive names (`wallet`, `keys`, `auth`, `login`) would
/// let them stand up a plausible-looking credential-collection page on the
/// same registrable domain every real passkey is scoped to — which is exactly
/// the phishing surface a shared RP ID creates. `_acme-challenge` would let
/// them interfere with certificate issuance for the parent domain.
pub const RESERVED_ALIASES: &[&str] = &[
    "_acme-challenge",
    "admin",
    "api",
    "auth",
    "cdn",
    "dashboard",
    "edge",
    "faucet",
    "ftp",
    "gateway",
    "id",
    "identity",
    "keys",
    "localhost",
    "login",
    "mail",
    "mcp",
    "ns",
    "ns1",
    "ns2",
    "rpc",
    "signin",
    "signup",
    "smtp",
    "ssl",
    "status",
    "support",
    "test",
    "tenzro",
    "wallet",
    "web",
    "www",
];

/// Why a proposed alias was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AliasNameError {
    /// Shorter than [`MIN_ALIAS_LEN`].
    TooShort,
    /// Longer than [`MAX_ALIAS_LEN`].
    TooLong,
    /// Contains a byte outside `[a-z0-9-]`.
    IllegalCharacter(char),
    /// Starts or ends with `-`, which no DNS label may do.
    LeadingOrTrailingHyphen,
    /// Reserved for the network — see [`RESERVED_ALIASES`].
    Reserved,
}

impl core::fmt::Display for AliasNameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "alias must be at least {MIN_ALIAS_LEN} characters"),
            Self::TooLong => write!(f, "alias must be at most {MAX_ALIAS_LEN} characters"),
            Self::IllegalCharacter(c) => write!(
                f,
                "alias may only contain lowercase letters, digits and hyphens (found {c:?})"
            ),
            Self::LeadingOrTrailingHyphen => {
                write!(f, "alias must not start or end with a hyphen")
            }
            Self::Reserved => write!(f, "alias is reserved by the network"),
        }
    }
}

impl std::error::Error for AliasNameError {}

/// Validate a proposed alias as a DNS label.
///
/// Deliberately **not** the `validate_username` rule used for human handles:
/// that one permits `_` and forbids `-`, which is precisely backwards for a
/// hostname. A name accepted there would claim successfully and then be
/// unroutable, so the two namespaces need two validators.
///
/// Callers must pass an already-lowercased string; this refuses uppercase
/// rather than silently normalising, so the claimed bytes and the requested
/// bytes are always the same thing.
pub fn validate_alias(name: &str) -> Result<(), AliasNameError> {
    if name.len() < MIN_ALIAS_LEN {
        return Err(AliasNameError::TooShort);
    }
    if name.len() > MAX_ALIAS_LEN {
        return Err(AliasNameError::TooLong);
    }
    for c in name.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(AliasNameError::IllegalCharacter(c));
        }
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(AliasNameError::LeadingOrTrailingHyphen);
    }
    if RESERVED_ALIASES.contains(&name) {
        return Err(AliasNameError::Reserved);
    }
    Ok(())
}

/// A claimed node alias, as held in consensus state.
///
/// `machine_did` / `endpoint_id` are `None` between claim and bind: a name is
/// claimed from the setup wizard, which runs before the node has ever
/// started and therefore before either value exists. An unbound alias
/// resolves to nothing and simply 404s, which needs no special-casing
/// anywhere downstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAlias {
    /// The bare DNS label. Never carries a domain suffix.
    pub name: String,
    /// Hex account address that paid for the claim, and the **sole
    /// authority** over it — only this address may bind, re-claim or release
    /// the name.
    ///
    /// The authority is the address rather than the DID because the VM
    /// executes without a DID resolver: `tx.from` is a fact it already has
    /// and can check deterministically on every node, whereas resolving a
    /// DID inside a transaction handler would make the outcome depend on
    /// registry state the VM does not own.
    pub owner_address: String,
    /// DID the claimant declared as owner. Informational — carried so
    /// readers can display the identity behind a name without a second
    /// lookup. Never used for authorization; see `owner_address`.
    pub owner_did: String,
    /// The node this name points at. `None` until the first bind.
    pub machine_did: Option<String>,
    /// The node's iroh `EndpointId`, which peers dial. `None` until bind.
    pub endpoint_id: Option<String>,
    /// Request paths the node will serve publicly under this name.
    /// Fail-closed: an empty list exposes nothing.
    pub exposed_prefixes: Vec<String>,
    /// Claim time (ms since epoch).
    pub claimed_at: u64,
    /// Last mutation time (ms since epoch).
    pub updated_at: u64,
}

impl NodeAlias {
    /// True once the alias names a reachable node.
    pub fn is_bound(&self) -> bool {
        self.machine_did.is_some() && self.endpoint_id.is_some()
    }

    /// Render the public hostname under `suffix`.
    ///
    /// The suffix is supplied by the caller from node configuration and is
    /// deliberately not stored on the record — see the module docs.
    pub fn hostname(&self, suffix: &str) -> String {
        format!("{}.{}", self.name, suffix)
    }

    /// Whether `path` is within the publicly exposed set.
    ///
    /// Fail-closed by construction: an empty `exposed_prefixes` matches
    /// nothing. `"/"` is treated as "everything", so it must be set
    /// deliberately rather than arrived at by accident.
    pub fn allows_path(&self, path: &str) -> bool {
        self.exposed_prefixes.iter().any(|p| {
            if p == "/" {
                true
            } else {
                // Match on a path-segment boundary so `/v1` cannot also
                // authorise `/v1secret`.
                path == p.trim_end_matches('/')
                    || path.starts_with(&format!("{}/", p.trim_end_matches('/')))
            }
        })
    }
}

/// Domain tag for the bind-consent preimage.
const BIND_CONSENT_DOMAIN: &[u8] = b"tenzro/node-alias/bind";

/// The exact bytes a machine signs to consent to being bound to a name.
///
/// Binding is the step that decides which physical node a public name
/// resolves to, so it needs proof that the machine agreed — otherwise anyone
/// could claim a name and point it at somebody else's node, and on a
/// registrable domain shared by every node that is a phishing primitive, not
/// merely a misconfiguration.
///
/// The signature is verified against the `endpoint_id`, which *is* the node's
/// Ed25519 public key. That keeps the check deterministic inside the VM with
/// no DID resolution, so every validator reaches the same verdict.
///
/// In practice the signing key is held by exactly the two things the operator
/// chose between at setup: a TPM-sealed machine key (autonomous) or the node
/// key of a machine whose account is passkey-controlled (self-operated).
///
/// Every field is length-prefixed. Without that, `name="ab"` + `owner="c"`
/// and `name="a"` + `owner="bc"` would produce identical bytes, so one
/// consent signature would authorise a different binding.
pub fn bind_consent_preimage(
    name: &str,
    owner_address: &str,
    machine_did: &str,
    endpoint_id: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        BIND_CONSENT_DOMAIN.len()
            + 16
            + name.len()
            + owner_address.len()
            + machine_did.len()
            + endpoint_id.len(),
    );
    out.extend_from_slice(BIND_CONSENT_DOMAIN);
    for field in [name, owner_address, machine_did, endpoint_id] {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// The default public surface for a node that opts into being reachable.
///
/// Deliberately narrow. A node's local web server also carries `/wallet/`,
/// `/auth/passkey`, `/faucet` and the operator's own status plane; publishing
/// those to the internet because the operator ticked "public" would be a
/// surprise, and on a shared registrable domain an exposed `/auth/passkey`
/// is a phishing vector against every other node's users.
pub fn default_exposed_prefixes() -> Vec<String> {
    vec![
        "/health".to_string(),
        "/status".to_string(),
        "/v1/".to_string(),
        "/models".to_string(),
        "/providers".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_labels() {
        for name in ["alice", "node-1", "gb10-tokyo", "a1b2c3"] {
            assert!(validate_alias(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn rejects_underscores_that_the_username_rule_would_allow() {
        // The human-handle validator permits `_`; a hostname may not. A name
        // accepted by that rule would claim fine and then never resolve.
        assert_eq!(
            validate_alias("my_node"),
            Err(AliasNameError::IllegalCharacter('_'))
        );
    }

    #[test]
    fn rejects_uppercase_rather_than_normalising() {
        // Claiming bytes other than the ones requested would make the
        // on-chain record disagree with what the user typed.
        assert_eq!(
            validate_alias("Alice"),
            Err(AliasNameError::IllegalCharacter('A'))
        );
    }

    #[test]
    fn rejects_hyphen_at_either_end() {
        assert_eq!(
            validate_alias("-alice"),
            Err(AliasNameError::LeadingOrTrailingHyphen)
        );
        assert_eq!(
            validate_alias("alice-"),
            Err(AliasNameError::LeadingOrTrailingHyphen)
        );
    }

    #[test]
    fn rejects_length_extremes() {
        assert_eq!(validate_alias("ab"), Err(AliasNameError::TooShort));
        assert_eq!(
            validate_alias(&"a".repeat(MAX_ALIAS_LEN + 1)),
            Err(AliasNameError::TooLong)
        );
        assert!(validate_alias(&"a".repeat(MAX_ALIAS_LEN)).is_ok());
    }

    /// The first claimant must not be able to take a name the network needs,
    /// nor one that impersonates a credential page on the shared RP ID.
    #[test]
    fn rejects_reserved_infrastructure_and_phishing_labels() {
        for name in ["api", "rpc", "www", "wallet", "keys", "auth", "login"] {
            assert_eq!(
                validate_alias(name),
                Err(AliasNameError::Reserved),
                "{name} must be reserved"
            );
        }
    }

    #[test]
    fn unbound_alias_is_not_resolvable() {
        let a = NodeAlias {
            name: "alice".to_string(),
            owner_address: "0xaa".to_string(),
            owner_did: "did:tenzro:human:x".to_string(),
            machine_did: None,
            endpoint_id: None,
            exposed_prefixes: default_exposed_prefixes(),
            claimed_at: 1,
            updated_at: 1,
        };
        assert!(!a.is_bound());
    }

    #[test]
    fn hostname_is_rendered_not_stored() {
        let a = NodeAlias {
            name: "alice".to_string(),
            owner_address: "0xaa".to_string(),
            owner_did: "did:tenzro:human:x".to_string(),
            machine_did: Some("did:tenzro:machine:y".to_string()),
            endpoint_id: Some("ep".to_string()),
            exposed_prefixes: vec![],
            claimed_at: 1,
            updated_at: 1,
        };
        // The same claim renders under whatever suffix is configured — the
        // record itself is domain-agnostic, so retiring a domain cannot
        // invalidate it.
        assert_eq!(a.hostname("network.tenzro.com"), "alice.network.tenzro.com");
        assert_eq!(a.hostname("example.test"), "alice.example.test");
        assert!(!a.name.contains('.'));
    }

    #[test]
    fn exposed_prefixes_are_fail_closed() {
        let mut a = NodeAlias {
            name: "alice".to_string(),
            owner_address: "0xaa".to_string(),
            owner_did: "d".to_string(),
            machine_did: None,
            endpoint_id: None,
            exposed_prefixes: vec![],
            claimed_at: 1,
            updated_at: 1,
        };
        assert!(!a.allows_path("/health"), "empty list must expose nothing");

        a.exposed_prefixes = default_exposed_prefixes();
        assert!(a.allows_path("/health"));
        assert!(a.allows_path("/v1/chat/completions"));
        // The private control plane is not in the default set.
        assert!(!a.allows_path("/wallet/transfer"));
        assert!(!a.allows_path("/auth/passkey"));
        assert!(!a.allows_path("/faucet"));
    }

    /// A prefix must not authorise a longer sibling that merely starts with
    /// the same characters.
    #[test]
    fn prefix_match_respects_segment_boundaries() {
        let a = NodeAlias {
            name: "alice".to_string(),
            owner_address: "0xaa".to_string(),
            owner_did: "d".to_string(),
            machine_did: None,
            endpoint_id: None,
            exposed_prefixes: vec!["/v1".to_string()],
            claimed_at: 1,
            updated_at: 1,
        };
        assert!(a.allows_path("/v1"));
        assert!(a.allows_path("/v1/chat"));
        assert!(!a.allows_path("/v1secret"));
    }

    /// Length prefixes are what stop one consent signature authorising a
    /// different binding: without them `name="ab"`+`owner="c"` and
    /// `name="a"`+`owner="bc"` serialise to the same bytes, so a signature
    /// collected for one name would silently bind another.
    #[test]
    fn bind_consent_preimage_is_unambiguous_across_field_boundaries() {
        let a = bind_consent_preimage("ab", "c", "m", "e");
        let b = bind_consent_preimage("a", "bc", "m", "e");
        assert_ne!(a, b, "field boundaries must not be ambiguous");
    }

    /// Every field must be covered, or a signature gathered for one machine
    /// would authorise binding the name to a different one.
    #[test]
    fn bind_consent_preimage_covers_every_field() {
        let base = bind_consent_preimage("alice", "aa", "did:tenzro:machine:m1", "ep1");
        for variant in [
            bind_consent_preimage("bob", "aa", "did:tenzro:machine:m1", "ep1"),
            bind_consent_preimage("alice", "bb", "did:tenzro:machine:m1", "ep1"),
            bind_consent_preimage("alice", "aa", "did:tenzro:machine:m2", "ep1"),
            bind_consent_preimage("alice", "aa", "did:tenzro:machine:m1", "ep2"),
        ] {
            assert_ne!(base, variant, "changing any field must change the preimage");
        }
    }

    /// The domain tag keeps a signature collected for some other Tenzro
    /// operation from being replayed as a bind consent.
    #[test]
    fn bind_consent_preimage_is_domain_separated() {
        let p = bind_consent_preimage("alice", "aa", "m", "e");
        assert!(p.starts_with(BIND_CONSENT_DOMAIN));
    }

    #[test]
    fn root_prefix_exposes_everything() {
        let a = NodeAlias {
            name: "alice".to_string(),
            owner_address: "0xaa".to_string(),
            owner_did: "d".to_string(),
            machine_did: None,
            endpoint_id: None,
            exposed_prefixes: vec!["/".to_string()],
            claimed_at: 1,
            updated_at: 1,
        };
        assert!(a.allows_path("/wallet/transfer"));
    }
}
