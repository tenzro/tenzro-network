//! The three ways to use a node, and the credential each one carries.
//!
//! A node is reachable by three distinct relationships, and the distinction is
//! economic before it is technical — each pays differently, so each has to be
//! nameable at settlement time.
//!
//! | Tier | Credential | Pays | What they get |
//! |---|---|---|---|
//! | [`AccessTier::User`] | none | per request, on demand | whatever the node serves publicly |
//! | [`AccessTier::Subscriber`] | API key | a subscription the operator sets | scoped resources on the node |
//! | [`AccessTier::Renter`] | service key | locked or prepaid up front | raw capacity — compute, storage, memory, security |
//!
//! # A user is anyone on the network, and not necessarily a person
//!
//! Humans, agents and machines are all first-class here: each holds its own
//! identity and its own wallet, so each can pay for itself. A [`AccessTier::User`]
//! is whoever presents payment, without any prior relationship with the operator
//! — the network introduced them, they paid, they were served.
//!
//! # A subscriber holds an API key; a renter holds a service key
//!
//! The difference is *what is being sold*. A subscriber buys **access to
//! resources the node serves** — inference on a model, queries against a
//! database, objects in storage — under a scope the operator wrote. A renter
//! buys **the raw capacity itself**, for a term, having locked or prepaid the
//! funds; the node hands over confined use of the hardware rather than answers
//! from it.
//!
//! That is why the credentials differ rather than being one credential with a
//! flag. An API key names scopes on services; a service key names a lease over a
//! machine, and is bounded by that lease's term.
//!
//! # The operator is the admin
//!
//! Every credential on this page is issued by the node's operator, who writes
//! its policy and its scope and can revoke it. No tier is self-service against
//! someone else's hardware.
//!
//! # An RPC provider's own tenants are not on this page
//!
//! [`RpcServiceGrant`] is a separate relationship: an RPC provider selling
//! access to **external networks they broker** — Canton, and other chains
//! beyond Tenzro — to their own tenants, on their own terms, the way every
//! other chain's RPC operators do. That revenue is theirs and never enters a
//! node's revenue split. It is modelled here only so the two cannot be
//! confused at a call site.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How a caller reaches a node's resources, and therefore how they pay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTier {
    /// Pays per request, on demand, with no prior relationship. A human, an
    /// agent or a machine — each holding its own identity and wallet.
    User,
    /// Subscribes to resources the node serves, and reaches them with an
    /// operator-issued API key carrying a scope.
    Subscriber,
    /// Has locked or prepaid funds for raw capacity on the machine, and reaches
    /// it with an operator-issued service key bounded by the lease term.
    Renter,
}

impl AccessTier {
    /// Every tier, in a stable order.
    pub const ALL: [AccessTier; 3] = [AccessTier::User, AccessTier::Subscriber, AccessTier::Renter];

    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessTier::User => "user",
            AccessTier::Subscriber => "subscriber",
            AccessTier::Renter => "renter",
        }
    }

    /// Parse the wire form. Unknown values are refused rather than defaulted:
    /// a typo that silently became "user" would let a caller through on a
    /// payment path they never satisfied.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(AccessTier::User),
            "subscriber" => Some(AccessTier::Subscriber),
            "renter" => Some(AccessTier::Renter),
            _ => None,
        }
    }

    /// The credential a caller in this tier presents.
    pub fn credential(&self) -> CredentialKind {
        match self {
            AccessTier::User => CredentialKind::Payment,
            AccessTier::Subscriber => CredentialKind::ApiKey,
            AccessTier::Renter => CredentialKind::ServiceKey,
        }
    }

    /// Whether a call in this tier is charged at the moment it is served.
    ///
    /// Only a [`AccessTier::User`] is: the other two settled up front, when the
    /// subscription was taken or the lease was funded. Metering still runs for
    /// all three — an operator needs to know what a subscriber consumed even
    /// when the consumption does not move money on that call.
    pub fn charges_per_request(&self) -> bool {
        matches!(self, AccessTier::User)
    }
}

impl fmt::Display for AccessTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The kind of credential a tier presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// A settled payment, presented per request. No prior relationship.
    Payment,
    /// An operator-issued API key naming scopes on this node's services.
    ApiKey,
    /// An operator-issued service key bound to a lease over raw capacity.
    ServiceKey,
}

impl CredentialKind {
    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialKind::Payment => "payment",
            CredentialKind::ApiKey => "api_key",
            CredentialKind::ServiceKey => "service_key",
        }
    }

    /// Parse the wire form; unknown values are refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "payment" => Some(CredentialKind::Payment),
            "api_key" => Some(CredentialKind::ApiKey),
            "service_key" => Some(CredentialKind::ServiceKey),
            _ => None,
        }
    }

    /// The tier that presents this credential.
    pub fn tier(&self) -> AccessTier {
        match self {
            CredentialKind::Payment => AccessTier::User,
            CredentialKind::ApiKey => AccessTier::Subscriber,
            CredentialKind::ServiceKey => AccessTier::Renter,
        }
    }
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of principal is holding an identity and paying.
///
/// All three are first-class: each holds its own DID and its own wallet, so a
/// machine or an agent pays for itself rather than borrowing a human's
/// credential. Recorded on a charge so an operator can tell agent traffic from
/// human traffic without inferring it from call shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayerKind {
    /// A person.
    Human,
    /// A machine — a node, a device, a piece of hardware with its own identity.
    Machine,
    /// An agent, delegated by a human or by a machine that owns it.
    Agent,
}

impl PayerKind {
    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            PayerKind::Human => "human",
            PayerKind::Machine => "machine",
            PayerKind::Agent => "agent",
        }
    }

    /// Parse the wire form; unknown values are refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "human" => Some(PayerKind::Human),
            "machine" => Some(PayerKind::Machine),
            "agent" => Some(PayerKind::Agent),
            _ => None,
        }
    }

    /// Whether this payer acts without a person in the loop on each payment.
    ///
    /// Both machines and agents do. Surfaced because the payment path differs:
    /// an autonomous payer settles against a standing mandate rather than a
    /// per-payment confirmation.
    pub fn is_autonomous(&self) -> bool {
        matches!(self, PayerKind::Machine | PayerKind::Agent)
    }
}

impl fmt::Display for PayerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A raw resource a renter can lease.
///
/// Distinct from a *service* a subscriber reaches: a renter is buying the
/// capacity, not answers produced with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RentableResource {
    /// Accelerator and CPU time.
    Compute,
    /// Persistent object and block storage.
    Storage,
    /// Resident memory.
    Memory,
    /// Confidential compute and key custody inside an enclave.
    Security,
    /// Outbound and inbound network transfer.
    Bandwidth,
}

impl RentableResource {
    /// Every rentable resource, in a stable order.
    pub const ALL: [RentableResource; 5] = [
        RentableResource::Compute,
        RentableResource::Storage,
        RentableResource::Memory,
        RentableResource::Security,
        RentableResource::Bandwidth,
    ];

    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            RentableResource::Compute => "compute",
            RentableResource::Storage => "storage",
            RentableResource::Memory => "memory",
            RentableResource::Security => "security",
            RentableResource::Bandwidth => "bandwidth",
        }
    }

    /// Parse the wire form; unknown values are refused.
    pub fn parse(s: &str) -> Option<Self> {
        RentableResource::ALL
            .into_iter()
            .find(|r| r.as_str().eq_ignore_ascii_case(s))
    }
}

impl fmt::Display for RentableResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a renter funded their lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RentalFunding {
    /// Funds locked in escrow for the lease term and released as it is
    /// consumed. The renter can reclaim what the term did not use.
    Locked,
    /// Paid in full up front. Nothing is reclaimable; the term is bought.
    Prepaid,
}

impl RentalFunding {
    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            RentalFunding::Locked => "locked",
            RentalFunding::Prepaid => "prepaid",
        }
    }

    /// Parse the wire form; unknown values are refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "locked" => Some(RentalFunding::Locked),
            "prepaid" => Some(RentalFunding::Prepaid),
            _ => None,
        }
    }

    /// Whether unused funds return to the renter at the end of the term.
    pub fn is_refundable(&self) -> bool {
        matches!(self, RentalFunding::Locked)
    }
}

impl fmt::Display for RentalFunding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An RPC provider's grant to one of *their* tenants, for external networks
/// they broker.
///
/// This is the RPC provider's own business — the same model every other chain's
/// RPC operators run: they hold the upstream credential (a Canton participant,
/// an archive node, a data-feed subscription), they sell scoped access to it,
/// and they bill for it on terms they set.
///
/// **It is deliberately not part of any node's revenue split.** An RPC provider
/// is paid out of a serving node's revenue only in
/// [`crate::economics::NodeEconomicMode::PublicDelegated`], and only for
/// *validating* on that node's behalf. Charging here as well would be charging
/// twice for two different things and calling it one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcServiceGrant {
    /// The RPC provider's DID.
    pub provider_did: String,
    /// The tenant's DID.
    pub tenant_did: String,
    /// External networks this grant reaches — `canton`, and other chains beyond
    /// Tenzro. Empty means the grant reaches none, which is refused at issuance
    /// rather than defaulting to all.
    pub networks: Vec<String>,
    /// Requests per minute the tenant is entitled to.
    pub rate_limit_per_minute: u32,
    /// When the grant expires, in milliseconds since the Unix epoch.
    pub expires_at_ms: u64,
}

impl RpcServiceGrant {
    /// Whether the grant is usable at `now_ms` and reaches `network`.
    ///
    /// Both conditions, never one: an expired grant naming the right network,
    /// and a live grant naming the wrong one, are equally refused.
    pub fn permits(&self, network: &str, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms && self.networks.iter().any(|n| n == network)
    }

    /// Whether this grant is coherent enough to issue.
    ///
    /// A grant reaching no network is refused rather than stored, because the
    /// natural reading of an empty list at a call site is "unrestricted", and
    /// that reading would hand a tenant every upstream credential the provider
    /// holds.
    pub fn is_issuable(&self) -> bool {
        !self.networks.is_empty()
            && !self.provider_did.is_empty()
            && !self.tenant_did.is_empty()
            && self.rate_limit_per_minute > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_tier_carries_its_own_credential() {
        assert_eq!(AccessTier::User.credential(), CredentialKind::Payment);
        assert_eq!(AccessTier::Subscriber.credential(), CredentialKind::ApiKey);
        assert_eq!(AccessTier::Renter.credential(), CredentialKind::ServiceKey);

        // And the mapping is a bijection, so a call site can go either way.
        for tier in AccessTier::ALL {
            assert_eq!(tier.credential().tier(), tier);
        }
    }

    /// Subscribers and renters settled up front; only an on-demand user is
    /// charged at serve time.
    #[test]
    fn only_an_on_demand_user_is_charged_per_request() {
        assert!(AccessTier::User.charges_per_request());
        assert!(!AccessTier::Subscriber.charges_per_request());
        assert!(!AccessTier::Renter.charges_per_request());
    }

    #[test]
    fn humans_machines_and_agents_are_all_payers() {
        assert!(!PayerKind::Human.is_autonomous());
        assert!(PayerKind::Machine.is_autonomous());
        assert!(PayerKind::Agent.is_autonomous());
    }

    #[test]
    fn locked_funding_is_reclaimable_and_prepaid_is_not() {
        assert!(RentalFunding::Locked.is_refundable());
        assert!(!RentalFunding::Prepaid.is_refundable());
    }

    #[test]
    fn an_rpc_grant_needs_both_a_live_term_and_the_named_network() {
        let grant = RpcServiceGrant {
            provider_did: "did:tenzro:machine:rpc".into(),
            tenant_did: "did:tenzro:human:tenant".into(),
            networks: vec!["canton".into()],
            rate_limit_per_minute: 600,
            expires_at_ms: 2_000,
        };
        assert!(grant.permits("canton", 1_999));
        // Expired, right network.
        assert!(!grant.permits("canton", 2_000));
        // Live, wrong network.
        assert!(!grant.permits("ethereum", 1_000));
    }

    /// An empty network list reads as "unrestricted" at a call site, which would
    /// hand a tenant every upstream credential the provider holds.
    #[test]
    fn a_grant_reaching_no_network_is_not_issuable() {
        let mut grant = RpcServiceGrant {
            provider_did: "did:tenzro:machine:rpc".into(),
            tenant_did: "did:tenzro:human:tenant".into(),
            networks: vec![],
            rate_limit_per_minute: 600,
            expires_at_ms: 2_000,
        };
        assert!(!grant.is_issuable());
        grant.networks.push("canton".into());
        assert!(grant.is_issuable());
        grant.rate_limit_per_minute = 0;
        assert!(!grant.is_issuable());
    }

    #[test]
    fn wire_forms_round_trip() {
        for tier in AccessTier::ALL {
            assert_eq!(AccessTier::parse(tier.as_str()), Some(tier));
        }
        for resource in RentableResource::ALL {
            assert_eq!(RentableResource::parse(resource.as_str()), Some(resource));
        }
        for kind in [PayerKind::Human, PayerKind::Machine, PayerKind::Agent] {
            assert_eq!(PayerKind::parse(kind.as_str()), Some(kind));
        }
        for funding in [RentalFunding::Locked, RentalFunding::Prepaid] {
            assert_eq!(RentalFunding::parse(funding.as_str()), Some(funding));
        }
        // Unknown values are refused, never defaulted.
        assert_eq!(AccessTier::parse("tenant"), None);
        assert_eq!(RentableResource::parse("gpu"), None);
        assert_eq!(PayerKind::parse("robot"), None);
        assert_eq!(RentalFunding::parse("free"), None);
    }
}
