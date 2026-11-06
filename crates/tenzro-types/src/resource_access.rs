//! The operator-set *serving mode* for a cloud resource — database or storage.
//!
//! This is the second, orthogonal axis of access control, sitting above
//! [`crate::access_policy::AccessPolicy`]. Where an `AccessPolicy` answers
//! *"which DID may read and administer this resource"*, a [`ResourceAccess`]
//! answers the operator's prior question: *"do I expose this resource off the
//! box at all, and on what terms"*. The two compose — a resource may be served
//! `Public` (pay-per-use) yet still carry an `AccessPolicy` that names who the
//! bytes belong to.
//!
//! It is a [`Visibility`] with the per-request price attached, so models,
//! compute, hosting, databases and storage all speak one vocabulary:
//!
//! - **`Public`** — announced; served to anyone who pays per request. Carries a
//!   `price_per_request` (`0` = free).
//! - **`Gated`** — announced as key-required; served only to callers holding
//!   the resource's scoped API key. No pay-per-use path.
//! - **`Private`** — never announced and never served off the box. Refused
//!   unless the request is loopback / on-node.
//!
//! A resource with no serving mode of its own follows the node's visibility:
//! [`ResourceAccess::resolve`] turns the optional override plus the node's
//! setting into the mode that is enforced.
//!
//! Wire form is internally tagged on `mode` (`{"mode":"public",...}`), matching
//! [`crate::access_policy::AccessPolicy`]'s `kind`-tagging convention, and is
//! carried as JSON everywhere it is persisted or gossiped.

use serde::{Deserialize, Serialize};

use crate::visibility::Visibility;

/// The operator's serving decision for one resource. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ResourceAccess {
    /// Served to anyone who settles a payment for the request. No API key is
    /// required. `price_per_request` is the amount in the smallest unit of the
    /// operator's settlement asset; `0` means free.
    Public {
        /// Amount charged per served request, in the settlement asset's
        /// smallest unit. `0` = free (served to anyone, no payment). Omitted
        /// means `0`.
        #[serde(default, with = "crate::primitives::u128_serde")]
        price_per_request: u128,
    },
    /// Served only to callers presenting the resource's scoped API key. Reads
    /// and writes both require the credential; there is no payment path.
    Gated,
    /// Never served off the box. Refused unless the caller is loopback/on-node.
    Private,
}

impl ResourceAccess {
    /// Stable lowercase string form of the mode (without the price), for logs,
    /// error messages, and the bare-string operator surface.
    pub fn as_str(&self) -> &'static str {
        self.visibility().as_str()
    }

    /// Parse a bare mode string into a mode, defaulting the `Public` price to
    /// `0`. Unknown values are refused rather than defaulted, so a typo can
    /// never silently open a resource. The caller layers the price on
    /// afterwards.
    pub fn parse(s: &str) -> Option<Self> {
        Visibility::parse(&s.trim().to_ascii_lowercase()).map(|v| Self::from_visibility(v, 0))
    }

    /// The visibility this mode expresses.
    pub fn visibility(&self) -> Visibility {
        match self {
            ResourceAccess::Public { .. } => Visibility::Public,
            ResourceAccess::Gated => Visibility::Gated,
            ResourceAccess::Private => Visibility::Private,
        }
    }

    /// The mode for a visibility, with `price_per_request` applied when it is
    /// `Public`.
    pub fn from_visibility(visibility: Visibility, price_per_request: u128) -> Self {
        match visibility {
            Visibility::Public => ResourceAccess::Public { price_per_request },
            Visibility::Gated => ResourceAccess::Gated,
            Visibility::Private => ResourceAccess::Private,
        }
    }

    /// The mode enforced for a resource: its own override when it has one,
    /// otherwise the node's visibility at the operator's per-use price.
    pub fn resolve(
        resource_override: Option<ResourceAccess>,
        node: Visibility,
        operator_price: u128,
    ) -> Self {
        resource_override.unwrap_or_else(|| Self::from_visibility(node, operator_price))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_mode_is_refused_not_defaulted() {
        assert!(ResourceAccess::parse("openn").is_none());
        assert!(ResourceAccess::parse("open").is_none());
        assert!(ResourceAccess::parse("").is_none());
    }

    #[test]
    fn parse_round_trips_the_bare_modes() {
        assert_eq!(
            ResourceAccess::parse("public"),
            Some(ResourceAccess::Public {
                price_per_request: 0
            })
        );
        assert_eq!(ResourceAccess::parse("GATED"), Some(ResourceAccess::Gated));
        assert_eq!(
            ResourceAccess::parse("private"),
            Some(ResourceAccess::Private)
        );
    }

    #[test]
    fn a_resource_without_a_mode_follows_the_node_at_the_operator_price() {
        assert_eq!(
            ResourceAccess::resolve(None, Visibility::Public, 7),
            ResourceAccess::Public {
                price_per_request: 7
            }
        );
        assert_eq!(
            ResourceAccess::resolve(None, Visibility::Private, 7),
            ResourceAccess::Private
        );
        assert_eq!(
            ResourceAccess::resolve(None, Visibility::Gated, 7),
            ResourceAccess::Gated
        );
    }

    #[test]
    fn an_explicit_mode_wins_in_both_directions() {
        assert_eq!(
            ResourceAccess::resolve(Some(ResourceAccess::Private), Visibility::Public, 0),
            ResourceAccess::Private
        );
        let public = ResourceAccess::Public {
            price_per_request: 3,
        };
        assert_eq!(
            ResourceAccess::resolve(Some(public), Visibility::Private, 0),
            public
        );
    }

    #[test]
    fn json_is_internally_tagged_on_mode() {
        let public = ResourceAccess::Public {
            price_per_request: 1000,
        };
        let v = serde_json::to_value(public).unwrap();
        assert_eq!(v["mode"], "public");
        // Round-trips through JSON (the format every descriptor is stored in).
        let back: ResourceAccess = serde_json::from_value(v).unwrap();
        assert_eq!(back, public);

        let gated: ResourceAccess =
            serde_json::from_value(serde_json::json!({"mode":"gated"})).unwrap();
        assert_eq!(gated, ResourceAccess::Gated);
    }

    #[test]
    fn a_large_price_round_trips_as_a_string() {
        let big = ResourceAccess::Public {
            price_per_request: u128::MAX,
        };
        let s = serde_json::to_string(&big).unwrap();
        let back: ResourceAccess = serde_json::from_str(&s).unwrap();
        assert_eq!(back, big);
    }
}
