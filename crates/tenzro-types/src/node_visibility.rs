//! Whether each of a node's capabilities is advertised to the network.
//!
//! # Private is not the same as absent
//!
//! An operator may want to run a fully capable node — validating, serving
//! models, holding storage, hosting apps, answering RPC — without appearing in
//! anyone's discovery. Their users reach it by its address; nobody browsing the
//! network finds it.
//!
//! That is a *discovery* property, not a capability one. A private node
//! validates exactly as a public one does, serves the same models at the same
//! speed, and answers the same 900-odd methods. What changes is that it stops
//! publishing "here is what I have" to peers.
//!
//! # Per capability, not per node
//!
//! The interesting configurations are mixed. An operator hosting a public web
//! app on a machine whose GPUs are reserved for their own team wants hosting
//! advertised and AI private. A validator earning consensus rewards while
//! renting its storage to three named customers wants the opposite. Making this
//! a single node-wide switch would force those operators to run two nodes to
//! express one intent.
//!
//! # What private does *not* do
//!
//! It is not an access-control mechanism, and must not be mistaken for one.
//! Suppressing an advertisement stops a stranger *finding* the node; it does
//! not stop them *using* it if they learn the address anyway. Access control is
//! the API-key scopes, the service-key admission gate, and the per-resource
//! access policies — all of which apply identically whether a capability is
//! advertised or not.
//!
//! Stated plainly because the failure mode is an operator marking something
//! private and believing it is therefore protected. Privacy reduces the set of
//! people who know you exist. It does not authenticate the ones who do.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A capability a node can offer, and independently choose to advertise.
///
/// Deliberately not the same enum as `NetworkRole`. A role is what a node *is*
/// (and what it stakes against); a capability is what it *offers*, which is the
/// granularity an operator reasons about when deciding what to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Consensus participation.
    ///
    /// Listed for completeness and reported like the others, but a validator
    /// cannot meaningfully hide: consensus requires peers to reach it, and a
    /// validator nobody can reach is a validator not doing its job. Setting
    /// this private is refused rather than silently ignored — see
    /// [`NodeVisibility::set`].
    Validator,
    /// Model serving and inference.
    Ai,
    /// Object storage and storage deals.
    Storage,
    /// Managed databases.
    Database,
    /// Web-app hosting.
    Hosting,
    /// Public JSON-RPC / REST service for other people's clients.
    Rpc,
    /// Confidential compute and attestation.
    Tee,
    /// Rentable CPU/GPU capacity.
    Compute,
}

impl Capability {
    /// Every capability, in a stable order.
    pub const ALL: [Capability; 8] = [
        Capability::Validator,
        Capability::Ai,
        Capability::Storage,
        Capability::Database,
        Capability::Hosting,
        Capability::Rpc,
        Capability::Tee,
        Capability::Compute,
    ];

    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Validator => "validator",
            Capability::Ai => "ai",
            Capability::Storage => "storage",
            Capability::Database => "database",
            Capability::Hosting => "hosting",
            Capability::Rpc => "rpc",
            Capability::Tee => "tee",
            Capability::Compute => "compute",
        }
    }

    /// Parse the wire form. Unknown values are refused rather than defaulted:
    /// a typo that silently became "advertise everything" is the wrong way to
    /// be wrong.
    pub fn parse(s: &str) -> Option<Self> {
        Capability::ALL
            .into_iter()
            .find(|c| c.as_str().eq_ignore_ascii_case(s))
    }

    /// Whether hiding this capability is coherent.
    ///
    /// Consensus is the one that is not: a validator must be reachable by its
    /// peers to vote, so "private validator" describes a node that has taken on
    /// an obligation it has arranged to be unable to meet.
    pub fn can_be_private(&self) -> bool {
        !matches!(self, Capability::Validator)
    }
}

/// Whether a capability is published to the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Announced to peers; discoverable; appears in network-wide listings.
    #[default]
    Network,
    /// Not announced. Reachable only by callers who already know this node's
    /// address or machine id — and who hold whatever credential the capability
    /// requires, exactly as they would if it were public.
    Private,
}

impl Visibility {
    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Network => "network",
            Visibility::Private => "private",
        }
    }

    /// Parse the wire form; unknown values are refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "network" => Some(Visibility::Network),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }

    /// Whether this capability may be announced.
    pub fn is_advertised(&self) -> bool {
        matches!(self, Visibility::Network)
    }
}

/// Why a visibility change was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisibilityError {
    /// A capability that cannot coherently be hidden.
    CannotBePrivate {
        /// The capability in question.
        capability: Capability,
        /// Why not.
        reason: &'static str,
    },
}

impl std::fmt::Display for VisibilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CannotBePrivate { capability, reason } => {
                write!(f, "{} cannot be private: {reason}", capability.as_str())
            }
        }
    }
}

impl std::error::Error for VisibilityError {}

/// A node's per-capability advertisement policy.
///
/// Defaults to fully public. An operator who has expressed no preference is
/// running an ordinary network participant, and defaulting to private would
/// mean a node that joins and is never found — a confusing silence rather than
/// a safe default, because privacy here protects discoverability, not secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeVisibility {
    /// Explicit per-capability settings. Absent entries are
    /// [`Visibility::Network`].
    #[serde(default)]
    settings: BTreeMap<Capability, Visibility>,
}

impl Default for NodeVisibility {
    fn default() -> Self {
        Self::public()
    }
}

impl NodeVisibility {
    /// Everything advertised.
    pub fn public() -> Self {
        Self {
            settings: BTreeMap::new(),
        }
    }

    /// Everything that can be private, is.
    ///
    /// The one-flag answer for an operator who wants a node nobody finds.
    /// `Validator` stays public because it cannot be otherwise.
    pub fn private() -> Self {
        let settings = Capability::ALL
            .into_iter()
            .filter(|c| c.can_be_private())
            .map(|c| (c, Visibility::Private))
            .collect();
        Self { settings }
    }

    /// How `capability` is currently published.
    pub fn get(&self, capability: Capability) -> Visibility {
        self.settings.get(&capability).copied().unwrap_or_default()
    }

    /// Whether `capability` may be announced to peers.
    ///
    /// The single question every advertisement path asks.
    pub fn is_advertised(&self, capability: Capability) -> bool {
        self.get(capability).is_advertised()
    }

    /// Set one capability's visibility.
    ///
    /// Refuses a combination that cannot hold, rather than accepting it and
    /// behaving differently from what was asked. An operator who set
    /// `validator = private` and got silence would reasonably believe their
    /// validator was hidden and still earning.
    pub fn set(
        &mut self,
        capability: Capability,
        visibility: Visibility,
    ) -> Result<(), VisibilityError> {
        if visibility == Visibility::Private && !capability.can_be_private() {
            return Err(VisibilityError::CannotBePrivate {
                capability,
                reason: "consensus requires peers to reach this node, so a hidden validator \
                         cannot vote",
            });
        }
        self.settings.insert(capability, visibility);
        Ok(())
    }

    /// Whether any capability is private.
    ///
    /// What an operator's status display asks to decide whether to say
    /// "private node" at all.
    pub fn has_private_capabilities(&self) -> bool {
        Capability::ALL.into_iter().any(|c| !self.is_advertised(c))
    }

    /// Every capability with its current visibility, in a stable order.
    pub fn all(&self) -> Vec<(Capability, Visibility)> {
        Capability::ALL
            .into_iter()
            .map(|c| (c, self.get(c)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_is_public_unless_told_otherwise() {
        // An operator who expressed no preference is running an ordinary
        // participant. Defaulting to private would mean a node that joins and
        // is never found.
        let v = NodeVisibility::default();
        for c in Capability::ALL {
            assert!(v.is_advertised(c), "{} defaulted to private", c.as_str());
        }
        assert!(!v.has_private_capabilities());
    }

    #[test]
    fn private_hides_everything_that_can_be_hidden() {
        let v = NodeVisibility::private();
        assert!(v.has_private_capabilities());
        for c in Capability::ALL {
            if c.can_be_private() {
                assert!(!v.is_advertised(c), "{} was still advertised", c.as_str());
            }
        }
        // Consensus is the exception, and it is not silently included.
        assert!(
            v.is_advertised(Capability::Validator),
            "a hidden validator cannot be reached by its peers, so it cannot vote"
        );
    }

    #[test]
    fn capabilities_are_independent() {
        // The interesting configurations are mixed: a public web app on a
        // machine whose GPUs are reserved for the operator's own team.
        let mut v = NodeVisibility::public();
        v.set(Capability::Ai, Visibility::Private).expect("allowed");
        assert!(!v.is_advertised(Capability::Ai));
        assert!(v.is_advertised(Capability::Hosting));
        assert!(v.is_advertised(Capability::Storage));
    }

    #[test]
    fn hiding_a_validator_is_refused_rather_than_ignored() {
        // Accepting it and behaving differently would leave an operator
        // believing their validator was hidden and still earning.
        let mut v = NodeVisibility::public();
        let err = v
            .set(Capability::Validator, Visibility::Private)
            .expect_err("must refuse");
        assert!(matches!(err, VisibilityError::CannotBePrivate { .. }));
        assert!(err.to_string().contains("cannot vote"));
        assert!(v.is_advertised(Capability::Validator), "state unchanged");
    }

    #[test]
    fn a_capability_can_be_made_public_again() {
        let mut v = NodeVisibility::private();
        assert!(!v.is_advertised(Capability::Storage));
        v.set(Capability::Storage, Visibility::Network)
            .expect("allowed");
        assert!(v.is_advertised(Capability::Storage));
    }

    #[test]
    fn wire_forms_round_trip() {
        for c in Capability::ALL {
            assert_eq!(Capability::parse(c.as_str()), Some(c));
        }
        // Case-insensitive on the way in, canonical on the way out.
        assert_eq!(Capability::parse("AI"), Some(Capability::Ai));
        // An unknown value is refused, not defaulted — a typo that silently
        // became "advertise everything" is the wrong way to be wrong.
        assert_eq!(Capability::parse("gpu"), None);
        assert_eq!(Visibility::parse("network"), Some(Visibility::Network));
        assert_eq!(Visibility::parse("hidden"), None);
    }

    #[test]
    fn the_policy_survives_serialization() {
        let mut v = NodeVisibility::public();
        v.set(Capability::Ai, Visibility::Private).unwrap();
        v.set(Capability::Rpc, Visibility::Private).unwrap();
        let json = serde_json::to_string(&v).expect("serializes");
        let back: NodeVisibility = serde_json::from_str(&json).expect("parses");
        assert_eq!(back, v);
        assert!(!back.is_advertised(Capability::Ai));
        assert!(back.is_advertised(Capability::Hosting));
    }

    #[test]
    fn every_capability_is_reported_even_when_unset() {
        // An operator's status view must show the whole picture, not only the
        // entries someone happened to change.
        let v = NodeVisibility::public();
        assert_eq!(v.all().len(), Capability::ALL.len());
    }
}
