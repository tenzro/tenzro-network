//! Typed MCP tool outputs for the node's access policy.

use serde::{Deserialize, Serialize};

/// A service surface a caller reaches the node through.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessSurface {
    Rpc,
    Mcp,
    A2a,
    Openai,
}

/// What a method does, for gating.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessMethodClass {
    Read,
    OwnerWrite,
    Admin,
    Inference,
    Media,
    Storage,
    Index,
    Payments,
    Identity,
}

/// How a paid rule is paid.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessPaidVia {
    X402,
    Channel,
}

/// The credential a credential rule asks for.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessCredentialKind {
    Kya,
}

/// An access rule. `all`, `any` and `not` combine rules, at most eight deep.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum AccessRule {
    Open,
    Closed,
    Paid {
        via: AccessPaidVia,
        /// Integer amount in the asset's smallest unit.
        price: String,
        asset: String,
    },
    Allow {
        #[serde(default)]
        dids: Vec<String>,
        #[serde(default)]
        orgs: Vec<String>,
    },
    Credential {
        kind: AccessCredentialKind,
        #[serde(default)]
        issuers: Vec<String>,
    },
    Terms {
        action: String,
    },
    Tier {
        name: String,
    },
    All {
        rules: Vec<AccessRule>,
    },
    Any {
        rules: Vec<AccessRule>,
    },
    Not {
        inner: Box<AccessRule>,
    },
}

/// A rate tier.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessTier {
    pub name: String,
    pub rate_per_minute: u32,
    pub burst: u32,
    #[serde(default)]
    pub quota_per_period: u64,
    pub period_secs: u64,
}

/// The rule for one method class, on one surface or on all of them.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessSurfaceRule {
    /// All surfaces when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<AccessSurface>,
    pub class: AccessMethodClass,
    pub rule: AccessRule,
}

/// The rule for one resource.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessResourceRule {
    pub resource: String,
    pub rule: AccessRule,
}

/// The node's access policy.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessPolicy {
    pub version: u64,
    /// DIDs of the node's administrators.
    pub admins: Vec<String>,
    pub default_rule: AccessRule,
    pub rules: Vec<AccessSurfaceRule>,
    pub tiers: Vec<AccessTier>,
    pub resources: Vec<AccessResourceRule>,
    pub token_ttl_secs: u64,
}

/// The access policy, as data and as access.toml text.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AccessPolicyOutput {
    pub policy: AccessPolicy,
    pub toml: String,
}
