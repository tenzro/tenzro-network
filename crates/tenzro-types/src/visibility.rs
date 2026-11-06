//! Who can find a resource on the network, and who may use it.
//!
//! One vocabulary for every resource a node offers: models of every type,
//! compute, storage, databases, hosting and tools.
//!
//! - [`Visibility::Public`]: announced to the network. Any caller may use the
//!   resource by paying the operator's per-use price (a price of `0` makes it
//!   free). An API key or service key the operator issued also admits.
//! - [`Visibility::Gated`]: announced to the network, marked as requiring a
//!   key. Reachable only with an API key (models) or a service key (compute and
//!   other resources). There is no pay-per-use path.
//! - [`Visibility::Private`]: never announced and never heartbeated. Served to
//!   this node's own callers only.
//!
//! # One setting per node, overridable per resource
//!
//! The operator sets one node visibility. It applies to every resource the node
//! offers unless that resource carries an explicit override, so the effective
//! visibility of a resource is [`Visibility::resolve`]: the override when one is
//! set, otherwise the node's setting.
//!
//! A private node still takes part in consensus. Private describes what the
//! node publishes about its resources, not whether it participates.

use serde::{Deserialize, Serialize};

/// The visibility of a node or of one resource on it. See the module docs.
///
/// Defaults to [`Visibility::Public`]: an operator who expressed no preference
/// runs an ordinary network participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Announced; usable by anyone who pays the operator's per-use price.
    #[default]
    Public,
    /// Announced as key-required; usable only with an API key or service key.
    Gated,
    /// Not announced; usable only by this node's own callers.
    Private,
}

impl Visibility {
    /// Stable wire form: `"public"`, `"gated"` or `"private"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Gated => "gated",
            Visibility::Private => "private",
        }
    }

    /// Parses the wire form. Unknown values are refused rather than defaulted,
    /// so a typo cannot silently open a resource.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Visibility::Public),
            "gated" => Some(Visibility::Gated),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }

    /// The effective visibility of a resource: its own override when it has
    /// one, otherwise the node's setting.
    pub fn resolve(resource_override: Option<Visibility>, node: Visibility) -> Visibility {
        resource_override.unwrap_or(node)
    }

    /// Whether the resource is announced to peers and heartbeated.
    ///
    /// `Public` and `Gated` are; the wire string tells callers whether a key is
    /// required.
    pub fn is_announced(&self) -> bool {
        matches!(self, Visibility::Public | Visibility::Gated)
    }

    /// Whether a caller holding no key may use the resource by paying the
    /// operator's per-use price.
    pub fn is_payable(&self) -> bool {
        matches!(self, Visibility::Public)
    }

    /// Whether reaching the resource requires an API key or service key.
    pub fn requires_key(&self) -> bool {
        matches!(self, Visibility::Gated)
    }
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_is_public_unless_told_otherwise() {
        assert_eq!(Visibility::default(), Visibility::Public);
    }

    #[test]
    fn a_resource_without_an_override_follows_the_node() {
        for node in [Visibility::Public, Visibility::Gated, Visibility::Private] {
            assert_eq!(Visibility::resolve(None, node), node);
        }
    }

    #[test]
    fn an_explicit_override_wins_in_both_directions() {
        assert_eq!(
            Visibility::resolve(Some(Visibility::Public), Visibility::Private),
            Visibility::Public
        );
        assert_eq!(
            Visibility::resolve(Some(Visibility::Private), Visibility::Public),
            Visibility::Private
        );
    }

    #[test]
    fn gated_is_announced_but_not_payable() {
        assert!(Visibility::Gated.is_announced());
        assert!(!Visibility::Gated.is_payable());
        assert!(Visibility::Gated.requires_key());
        assert!(Visibility::Public.is_announced());
        assert!(Visibility::Public.is_payable());
        assert!(!Visibility::Private.is_announced());
        assert!(!Visibility::Private.is_payable());
    }

    #[test]
    fn wire_forms_round_trip_and_unknown_values_are_refused() {
        for v in [Visibility::Public, Visibility::Gated, Visibility::Private] {
            assert_eq!(Visibility::parse(v.as_str()), Some(v));
            let json = serde_json::to_string(&v).expect("serializes");
            assert_eq!(json, format!("\"{}\"", v.as_str()));
        }
        assert_eq!(Visibility::parse("network"), None);
        assert_eq!(Visibility::parse("hidden"), None);
    }
}
