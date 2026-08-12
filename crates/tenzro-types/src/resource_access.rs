//! The operator-set *serving mode* for a cloud resource — database or storage.
//!
//! This is the second, orthogonal axis of access control, sitting above
//! [`crate::access_policy::AccessPolicy`]. Where an `AccessPolicy` answers
//! *"which DID may read and administer this resource"*, a [`ResourceAccess`]
//! answers the operator's prior question: *"do I expose this resource off the
//! box at all, and on what terms"*. The two compose — a resource may be served
//! `Open` (pay-per-use) yet still carry an `AccessPolicy` that names who the
//! bytes belong to.
//!
//! It mirrors [`crate::model::ModelVisibility`] so Compute (models),
//! Web-hosting, Database and Storage all speak one vocabulary:
//!
//! - **`Open`** — served to anyone who pays per request over x402; no API key
//!   and no prior relationship. Carries an optional `price_per_request`
//!   (`0` = free-public). This is the operator's explicit decision to serve the
//!   network on-demand.
//! - **`Gated`** — served only to callers holding the resource's scoped API key
//!   (Database / Storage). "I serve this, but on my terms." (the prior
//!   behaviour of both surfaces.)
//! - **`Private`** — never served off the box. Refused unless the request is
//!   loopback / on-node. This is the fail-closed default: an unset or unknown
//!   mode is `Private`, so a resource is never accidentally exposed.
//!
//! Wire form is internally tagged on `mode` (`{"mode":"open",...}`), matching
//! [`crate::access_policy::AccessPolicy`]'s `kind`-tagging convention, and is
//! carried as JSON everywhere it is persisted or gossiped.

use serde::{Deserialize, Serialize};

/// The operator's serving decision for one resource. See the module docs.
///
/// [`Default`] is [`ResourceAccess::Private`] — unset means not-exposed, so the
/// safe posture is the one you fall into when nobody chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ResourceAccess {
    /// Served to anyone who settles an x402 payment for the request. No API key
    /// is required. `price_per_request` is the amount in the smallest unit of
    /// the operator's settlement asset; `0` means free-public.
    Open {
        /// Amount charged per served request, in the settlement asset's
        /// smallest unit. `0` = free-public (served to anyone, no payment).
        #[serde(default, with = "crate::primitives::u128_serde")]
        price_per_request: u128,
    },
    /// Served only to callers presenting the resource's scoped API key. Reads
    /// and writes both require the credential; there is no payment fallback.
    Gated,
    /// Never served off the box. Refused unless the caller is loopback/on-node.
    Private,
}

impl Default for ResourceAccess {
    fn default() -> Self {
        // Fail-closed: an unset access mode exposes nothing.
        ResourceAccess::Private
    }
}

impl ResourceAccess {
    /// Stable lowercase string form of the mode (without the price), for logs,
    /// error messages, and the bare-string operator surface.
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceAccess::Open { .. } => "open",
            ResourceAccess::Gated => "gated",
            ResourceAccess::Private => "private",
        }
    }

    /// Parse a bare mode string into a mode, defaulting the `Open` price to `0`.
    /// Unknown values are refused rather than defaulted, so a typo can never
    /// silently open a resource. The caller layers the price on afterwards.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" => Some(ResourceAccess::Open {
                price_per_request: 0,
            }),
            "gated" => Some(ResourceAccess::Gated),
            "private" => Some(ResourceAccess::Private),
            _ => None,
        }
    }

    /// Per-request price for an [`Open`](Self::Open) resource; `None` for every
    /// other mode (which are not priced per request).
    pub fn price_per_request(&self) -> Option<u128> {
        match self {
            ResourceAccess::Open { price_per_request } => Some(*price_per_request),
            _ => None,
        }
    }

    /// Whether this resource is served on-demand for x402 payment.
    pub fn is_open(&self) -> bool {
        matches!(self, ResourceAccess::Open { .. })
    }

    /// Whether reaching this resource requires the scoped credential (as opposed
    /// to payment or being on-box).
    pub fn requires_credential(&self) -> bool {
        matches!(self, ResourceAccess::Gated)
    }

    /// Whether this resource is served off the box at all. The inverse of
    /// "loopback-only". Classify a mode added later here rather than at each
    /// call site, so it cannot silently inherit a branch.
    pub fn is_offered(&self) -> bool {
        matches!(self, ResourceAccess::Open { .. } | ResourceAccess::Gated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_is_private_fail_closed() {
        assert_eq!(ResourceAccess::default(), ResourceAccess::Private);
    }

    #[test]
    fn unknown_mode_is_refused_not_defaulted() {
        assert!(ResourceAccess::parse("openn").is_none());
        assert!(ResourceAccess::parse("").is_none());
    }

    #[test]
    fn parse_round_trips_the_bare_modes() {
        assert_eq!(
            ResourceAccess::parse("open"),
            Some(ResourceAccess::Open {
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
    fn open_carries_a_price_others_do_not() {
        assert_eq!(
            ResourceAccess::Open {
                price_per_request: 5
            }
            .price_per_request(),
            Some(5)
        );
        assert_eq!(ResourceAccess::Gated.price_per_request(), None);
        assert_eq!(ResourceAccess::Private.price_per_request(), None);
    }

    #[test]
    fn json_is_internally_tagged_on_mode() {
        let open = ResourceAccess::Open {
            price_per_request: 1000,
        };
        let v = serde_json::to_value(open).unwrap();
        assert_eq!(v["mode"], "open");
        // Round-trips through JSON (the format every descriptor is stored in).
        let back: ResourceAccess = serde_json::from_value(v).unwrap();
        assert_eq!(back, open);

        let gated: ResourceAccess =
            serde_json::from_value(serde_json::json!({"mode":"gated"})).unwrap();
        assert_eq!(gated, ResourceAccess::Gated);
    }

    #[test]
    fn a_large_price_round_trips_as_a_string() {
        let big = ResourceAccess::Open {
            price_per_request: u128::MAX,
        };
        let s = serde_json::to_string(&big).unwrap();
        let back: ResourceAccess = serde_json::from_str(&s).unwrap();
        assert_eq!(back, big);
    }
}
