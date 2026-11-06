//! A node operator's access policy: who may use this node's service surfaces.
//!
//! Gating is local node policy. It decides who may call the node's RPC, MCP,
//! A2A, OpenAI-compatible, file, web and iroh service surfaces; it never
//! touches consensus, gossip or voting, and it can only refuse. What an agent
//! may do is decided by its consensus Terms, and no rule here grants beyond
//! them.
//!
//! The policy maps a (surface, method class) pair to a [`Rule`]. A rule is a
//! matcher or a combination of matchers. The first entry in
//! [`NodeAccessPolicy::rules`] that names the surface (or any surface) and the
//! class applies; when none does, [`NodeAccessPolicy::default_rule`] applies.
//! Owner-class methods still require the owner's proof whatever the rule says,
//! and admin-class methods are reachable only by the operator and the DIDs
//! named in [`NodeAccessPolicy::admins`].

use serde::{Deserialize, Serialize};

/// A service surface a caller reaches the node through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// JSON-RPC.
    Rpc,
    /// The node's MCP server.
    Mcp,
    /// The A2A server.
    A2a,
    /// The OpenAI-compatible `/v1/*` routes.
    Openai,
    /// The web surface.
    Web,
    /// Service ALPNs on iroh (never consensus or gossip).
    Iroh,
}

impl Surface {
    /// Every surface.
    pub const ALL: [Surface; 6] = [
        Surface::Rpc,
        Surface::Mcp,
        Surface::A2a,
        Surface::Openai,
        Surface::Web,
        Surface::Iroh,
    ];

    /// The surface's name in the policy file.
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Rpc => "rpc",
            Surface::Mcp => "mcp",
            Surface::A2a => "a2a",
            Surface::Openai => "openai",
            Surface::Web => "web",
            Surface::Iroh => "iroh",
        }
    }

    /// The surface named `s`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

/// What a method does, for gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodClass {
    /// Reads of chain state and node status.
    Read,
    /// Writes whose handler checks a proof from the owner of what changes.
    OwnerWrite,
    /// The operator's own machine policy.
    Admin,
    /// Language-model inference.
    Inference,
    /// Image, video, audio and other media models.
    Media,
    /// Storage-provider deals and objects.
    Storage,
    /// Event and index queries.
    Index,
    /// Payments, channels and settlement.
    Payments,
    /// Identity, credentials and sign-in.
    Identity,
}

impl MethodClass {
    /// Every class.
    pub const ALL: [MethodClass; 9] = [
        MethodClass::Read,
        MethodClass::OwnerWrite,
        MethodClass::Admin,
        MethodClass::Inference,
        MethodClass::Media,
        MethodClass::Storage,
        MethodClass::Index,
        MethodClass::Payments,
        MethodClass::Identity,
    ];

    /// The class's name in the policy file and in token claims.
    pub fn as_str(self) -> &'static str {
        match self {
            MethodClass::Read => "read",
            MethodClass::OwnerWrite => "owner_write",
            MethodClass::Admin => "admin",
            MethodClass::Inference => "inference",
            MethodClass::Media => "media",
            MethodClass::Storage => "storage",
            MethodClass::Index => "index",
            MethodClass::Payments => "payments",
            MethodClass::Identity => "identity",
        }
    }

    /// The class named `s`.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

/// How a paid request settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaidVia {
    /// HTTP 402 with an x402 payment.
    X402,
    /// A voucher on an open payment channel.
    Channel,
}

/// A kind of credential a caller presents when it signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// A Know-Your-Agent credential: the agent DID is controlled by a known
    /// key, attested by a hardware-rooted issuer.
    Kya,
}

/// Who a rule admits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum Rule {
    /// Anyone.
    Open,
    /// Nobody (except the operator and admins on admin-class methods).
    Closed,
    /// A request that settles a payment of `price` (smallest units of
    /// `asset`).
    Paid {
        via: PaidVia,
        price: String,
        asset: String,
    },
    /// The named DIDs, and every identity whose root is one of `orgs`.
    Allow {
        #[serde(default)]
        dids: Vec<String>,
        #[serde(default)]
        orgs: Vec<String>,
    },
    /// A caller holding a verified credential of `kind` from one of
    /// `issuers` (any issuer when empty).
    Credential {
        kind: CredentialKind,
        #[serde(default)]
        issuers: Vec<String>,
    },
    /// An agent whose consensus Terms allow `action` now.
    Terms { action: String },
    /// A signed-in caller, held to the rate and quota of tier `name`.
    Tier { name: String },
    /// Every rule must admit.
    All { rules: Vec<Rule> },
    /// One rule must admit.
    Any { rules: Vec<Rule> },
    /// The inner rule must not admit.
    Not { inner: Box<Rule> },
}

impl Rule {
    /// The presets an operator picks from, by name.
    pub fn preset(name: &str) -> Option<Rule> {
        Some(match name {
            "open" => Rule::Open,
            "closed" => Rule::Closed,
            "signed_in" => Rule::Tier {
                name: "standard".to_string(),
            },
            "agents_with_terms" => Rule::Terms {
                action: "use".to_string(),
            },
            _ => return None,
        })
    }

    /// Check the rule's own shape: combinations are not empty, nesting is
    /// bounded, prices are integers, and tiers name a defined tier.
    pub fn validate(&self, tiers: &[TierDef], depth: usize) -> Result<(), String> {
        if depth > MAX_RULE_DEPTH {
            return Err(format!("rules nest at most {MAX_RULE_DEPTH} deep"));
        }
        match self {
            Rule::Open | Rule::Closed | Rule::Credential { .. } => Ok(()),
            Rule::Paid { price, asset, .. } => {
                price
                    .parse::<u128>()
                    .map_err(|_| format!("price {price:?} is not an integer amount"))?;
                if asset.trim().is_empty() {
                    return Err("a paid rule names its asset".to_string());
                }
                Ok(())
            }
            Rule::Allow { dids, orgs } => {
                if dids.is_empty() && orgs.is_empty() {
                    return Err("an allow rule names at least one DID or org".to_string());
                }
                for d in dids.iter().chain(orgs) {
                    if !d.starts_with("did:") {
                        return Err(format!("{d:?} is not a DID"));
                    }
                }
                Ok(())
            }
            Rule::Terms { action } => {
                if action.trim().is_empty() {
                    return Err("a terms rule names its action".to_string());
                }
                Ok(())
            }
            Rule::Tier { name } => {
                if tiers.iter().any(|t| &t.name == name) {
                    Ok(())
                } else {
                    Err(format!("tier {name:?} is not defined"))
                }
            }
            Rule::All { rules } | Rule::Any { rules } => {
                if rules.is_empty() {
                    return Err("a combination holds at least one rule".to_string());
                }
                rules.iter().try_for_each(|r| r.validate(tiers, depth + 1))
            }
            Rule::Not { inner } => inner.validate(tiers, depth + 1),
        }
    }
}

/// How deep rules may nest.
pub const MAX_RULE_DEPTH: usize = 8;

/// A rate and quota tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierDef {
    /// The tier's name.
    pub name: String,
    /// Sustained requests per minute.
    pub rate_per_minute: u32,
    /// Requests allowed in a burst above the sustained rate.
    pub burst: u32,
    /// Requests allowed per period; `0` for no quota.
    #[serde(default)]
    pub quota_per_period: u64,
    /// The quota period, in seconds.
    #[serde(default = "default_period_secs")]
    pub period_secs: u64,
}

fn default_period_secs() -> u64 {
    86_400
}

/// The rule for one surface (or every surface) and method class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceRule {
    /// The surface; every surface when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<Surface>,
    /// The method class.
    pub class: MethodClass,
    /// Who it admits.
    pub rule: Rule,
}

/// A rule for one resource (a database, a file bucket) that applies on top
/// of the class rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRule {
    /// The resource id.
    pub resource: String,
    /// Who may reach it.
    pub rule: Rule,
}

/// The node's access policy, stored as `access.toml` in the data directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAccessPolicy {
    /// Bumped on every accepted change.
    #[serde(default)]
    pub version: u64,
    /// DIDs besides the operator that may call admin-class methods.
    #[serde(default)]
    pub admins: Vec<String>,
    /// The rule when no entry of `rules` matches.
    pub default_rule: Rule,
    /// Rules by surface and class, first match wins.
    #[serde(default)]
    pub rules: Vec<SurfaceRule>,
    /// Rate and quota tiers.
    #[serde(default)]
    pub tiers: Vec<TierDef>,
    /// Per-resource rules.
    #[serde(default)]
    pub resources: Vec<ResourceRule>,
    /// Lifetime of issued access tokens, in seconds.
    #[serde(default = "default_token_ttl_secs")]
    pub token_ttl_secs: u64,
}

fn default_token_ttl_secs() -> u64 {
    DEFAULT_TOKEN_TTL_SECS
}

/// Default access-token lifetime: 15 minutes.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 15 * 60;
/// Longest access-token lifetime a policy may set: one day.
pub const MAX_TOKEN_TTL_SECS: u64 = 24 * 60 * 60;

impl Default for NodeAccessPolicy {
    /// Open, as a node with no policy has always been: every surface admits
    /// anyone, admin-class methods only the operator.
    fn default() -> Self {
        Self {
            version: 0,
            admins: Vec::new(),
            default_rule: Rule::Open,
            rules: Vec::new(),
            tiers: vec![TierDef {
                name: "standard".to_string(),
                rate_per_minute: 600,
                burst: 100,
                quota_per_period: 0,
                period_secs: default_period_secs(),
            }],
            resources: Vec::new(),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
        }
    }
}

impl NodeAccessPolicy {
    /// The rule for `class` on `surface`.
    pub fn rule_for(&self, surface: Surface, class: MethodClass) -> &Rule {
        self.rules
            .iter()
            .find(|r| r.class == class && r.surface.is_none_or(|s| s == surface))
            .map_or(&self.default_rule, |r| &r.rule)
    }

    /// The rule for `resource`, when one is set.
    pub fn resource_rule(&self, resource: &str) -> Option<&Rule> {
        self.resources
            .iter()
            .find(|r| r.resource == resource)
            .map(|r| &r.rule)
    }

    /// The tier named `name`.
    pub fn tier(&self, name: &str) -> Option<&TierDef> {
        self.tiers.iter().find(|t| t.name == name)
    }

    /// Check the whole policy.
    pub fn validate(&self) -> Result<(), String> {
        let mut names = std::collections::BTreeSet::new();
        for t in &self.tiers {
            if t.name.trim().is_empty() {
                return Err("a tier has a name".to_string());
            }
            if !names.insert(t.name.as_str()) {
                return Err(format!("tier {:?} is defined twice", t.name));
            }
            if t.rate_per_minute == 0 {
                return Err(format!("tier {:?} allows no requests", t.name));
            }
            if t.quota_per_period > 0 && t.period_secs == 0 {
                return Err(format!("tier {:?} has a quota with no period", t.name));
            }
        }
        for a in &self.admins {
            if !a.starts_with("did:") {
                return Err(format!("admin {a:?} is not a DID"));
            }
        }
        if self.token_ttl_secs == 0 || self.token_ttl_secs > MAX_TOKEN_TTL_SECS {
            return Err(format!(
                "token_ttl_secs must be between 1 and {MAX_TOKEN_TTL_SECS}"
            ));
        }
        self.default_rule.validate(&self.tiers, 0)?;
        for r in &self.rules {
            r.rule
                .validate(&self.tiers, 0)
                .map_err(|e| format!("{} rule: {e}", r.class.as_str()))?;
        }
        for r in &self.resources {
            r.rule
                .validate(&self.tiers, 0)
                .map_err(|e| format!("resource {}: {e}", r.resource))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_matching_rule_wins_and_the_default_covers_the_rest() {
        let mut p = NodeAccessPolicy::default();
        p.rules.push(SurfaceRule {
            surface: Some(Surface::Openai),
            class: MethodClass::Inference,
            rule: Rule::Closed,
        });
        p.rules.push(SurfaceRule {
            surface: None,
            class: MethodClass::Inference,
            rule: Rule::Tier {
                name: "standard".into(),
            },
        });
        assert_eq!(
            p.rule_for(Surface::Openai, MethodClass::Inference),
            &Rule::Closed
        );
        assert_eq!(
            p.rule_for(Surface::Rpc, MethodClass::Inference),
            &Rule::Tier {
                name: "standard".into()
            }
        );
        assert_eq!(p.rule_for(Surface::Rpc, MethodClass::Read), &Rule::Open);
        p.validate().unwrap();
    }

    #[test]
    fn validation_refuses_undefined_tiers_empty_combinations_and_bad_prices() {
        let mut p = NodeAccessPolicy {
            default_rule: Rule::Tier {
                name: "gold".into(),
            },
            ..Default::default()
        };
        assert!(p.validate().is_err());
        p.default_rule = Rule::Any { rules: vec![] };
        assert!(p.validate().is_err());
        p.default_rule = Rule::Paid {
            via: PaidVia::X402,
            price: "1.5".into(),
            asset: "TNZO".into(),
        };
        assert!(p.validate().is_err());
        p.default_rule = Rule::Allow {
            dids: vec!["alice".into()],
            orgs: vec![],
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn nesting_is_bounded() {
        let mut r = Rule::Open;
        for _ in 0..=MAX_RULE_DEPTH {
            r = Rule::Not { inner: Box::new(r) };
        }
        assert!(r.validate(&[], 0).is_err());
    }
}
