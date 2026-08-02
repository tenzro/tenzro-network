//! RFC 9396 Rich Authorization Requests — typed scope envelopes.
//!
//! RAR replaces OAuth's flat `scope: "wallet identity inference"` string
//! with a typed list of grants. A token's
//! [`AuthorizationDetails`] is a `Vec<AuthorizationDetail>`; the engine
//! permits an action iff *some* detail in the list strictly covers it.
//! There is no implicit fallback, no `"all"` shorthand — anything not
//! covered is denied. This is the core "additive scopes" invariant from
//! the crate-level docs.
//!
//! ## What we model
//!
//! `tenzro-node` distinguishes a small, fixed set of privileged actions:
//!
//! 1. **Transfer** — debit a wallet to send `asset` to a counterparty.
//! 2. **CreateEscrow** — lock funds in an on-chain escrow vault.
//! 3. **ReleaseEscrow / RefundEscrow** — discharge an existing escrow.
//! 4. **Inference** — pay a model provider for an inference call.
//! 5. **Stake / Unstake** — bond or unbond TNZO with a validator/provider.
//! 6. **Vote** — cast governance vote.
//! 7. **DeployContract / CallContract** — submit EVM/SVM/DAML bytecode
//!    or invoke a deployed contract.
//! 8. **RegisterIdentity** — spawn a new TDIP identity (delegated agent
//!    or autonomous agent) under the bearer's act-chain.
//!
//! Each grant pins the action *type* plus per-type
//! [`ResourceConstraint`]s (asset id, max amount per call, max amount
//! per day, allowed counterparty list, allowed contract address list,
//! …). Constraints are *and*-ed within a detail; details are *or*-ed
//! across the list.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tenzro_types::{Address, AssetId};

/// Serialize a `u128` as a decimal string. `serde_json` rejects `u128`
/// directly because JSON has no integer-precision contract beyond
/// IEEE-754 doubles; encoding as a string preserves the full 128-bit
/// range round-trippably.
fn ser_u128_str<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

fn de_u128_str<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
    use serde::de::Error;
    let s: String = Deserialize::deserialize(d)?;
    s.parse::<u128>()
        .map_err(|e| Error::custom(format!("invalid u128: {}", e)))
}

fn ser_opt_u128_str<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(n) => s.serialize_some(&n.to_string()),
        None => s.serialize_none(),
    }
}

fn de_opt_u128_str<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
    use serde::de::Error;
    let s: Option<String> = Deserialize::deserialize(d)?;
    match s {
        None => Ok(None),
        Some(s) => s
            .parse::<u128>()
            .map(Some)
            .map_err(|e| Error::custom(format!("invalid u128: {}", e))),
    }
}

/// Top-level RAR envelope: an ordered list of grants. Order is not
/// semantically meaningful — the engine searches all grants — but the
/// list is preserved verbatim for audit purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuthorizationDetails {
    /// Individual grants. Empty = a token that can do nothing privileged.
    /// (Such a token is still valid for read-only RPCs.)
    pub details: Vec<AuthorizationDetail>,
}

impl AuthorizationDetails {
    /// Construct an empty (read-only) envelope.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct from a single grant.
    pub fn single(detail: AuthorizationDetail) -> Self {
        Self {
            details: vec![detail],
        }
    }

    /// Append a grant to the envelope and return self for chaining.
    pub fn with(mut self, detail: AuthorizationDetail) -> Self {
        self.details.push(detail);
        self
    }
}

/// One grant within a RAR envelope. Tagged by `type` per RFC 9396 §2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthorizationDetail {
    /// Permission to debit a wallet to transfer `asset`.
    #[serde(rename = "transfer")]
    Transfer {
        /// The asset that may be transferred.
        asset: AssetId,
        /// Maximum value of any *single* transfer (in base units of `asset`).
        #[serde(serialize_with = "ser_u128_str", deserialize_with = "de_u128_str")]
        max_amount: u128,
        /// Optional rolling-24h cap (in base units of `asset`).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_opt_u128_str",
            deserialize_with = "de_opt_u128_str"
        )]
        max_daily_amount: Option<u128>,
        /// Optional whitelist of permitted counterparty addresses. If
        /// `None`, any counterparty is allowed up to `max_amount`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_counterparties: Option<Vec<Address>>,
    },

    /// Permission to create an on-chain escrow.
    #[serde(rename = "create_escrow")]
    CreateEscrow {
        /// Asset that may be locked in the escrow vault.
        asset: AssetId,
        /// Maximum locked amount per single CreateEscrow call.
        #[serde(serialize_with = "ser_u128_str", deserialize_with = "de_u128_str")]
        max_amount: u128,
        /// Optional whitelist of permitted escrow payees.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_payees: Option<Vec<Address>>,
    },

    /// Permission to release or refund an existing escrow.
    /// Release/refund are bundled because the on-chain authorization
    /// rules are identical (payer-only) — distinguishing them at the
    /// RAR level adds no security value.
    #[serde(rename = "discharge_escrow")]
    DischargeEscrow {
        /// Optional whitelist of escrow ids the bearer may discharge.
        /// `None` means "any escrow whose payer the bearer controls."
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_escrow_ids: Option<Vec<[u8; 32]>>,
    },

    /// Permission to pay for AI inference calls.
    #[serde(rename = "inference")]
    Inference {
        /// Maximum spend per single inference call (in TNZO base units).
        #[serde(serialize_with = "ser_u128_str", deserialize_with = "de_u128_str")]
        max_amount_per_call: u128,
        /// Optional rolling-24h spend cap.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            serialize_with = "ser_opt_u128_str",
            deserialize_with = "de_opt_u128_str"
        )]
        max_daily_amount: Option<u128>,
        /// Optional whitelist of model ids the bearer may invoke.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_model_ids: Option<Vec<String>>,
    },

    /// Permission to stake or unstake TNZO with a validator/provider.
    #[serde(rename = "stake")]
    Stake {
        /// Maximum amount the bearer may stake (or unstake) in a single op.
        #[serde(serialize_with = "ser_u128_str", deserialize_with = "de_u128_str")]
        max_amount: u128,
        /// Optional whitelist of validator addresses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_validators: Option<Vec<Address>>,
    },

    /// Permission to cast governance votes on behalf of the bearer.
    #[serde(rename = "vote")]
    Vote {
        /// Optional whitelist of proposal ids the bearer may vote on.
        /// `None` means "any active proposal."
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_proposals: Option<Vec<String>>,
    },

    /// Permission to deploy or invoke contracts.
    #[serde(rename = "contract")]
    Contract {
        /// Optional whitelist of contract addresses the bearer may call.
        /// `None` permits any contract.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_contracts: Option<Vec<Address>>,
        /// Whether the bearer may *deploy* new contracts in addition to
        /// calling existing ones.
        #[serde(default)]
        allow_deploy: bool,
    },

    /// Permission to spawn child identities under the bearer's act-chain.
    /// This is what an autonomous agent uses to fork helper agents.
    #[serde(rename = "register_identity")]
    RegisterIdentity {
        /// Maximum number of children the bearer may spawn within the
        /// token's lifetime. `None` = unlimited (within the bearer's
        /// existing TDIP delegation scope).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_children: Option<u32>,
    },

    /// Permission to pay for marketplace resource invocations — skills,
    /// tools, workflow templates, knowledge bases, agent templates.
    #[serde(rename = "resource_invocation")]
    ResourceInvocation {
        /// Maximum spend per single invocation (in TNZO base units).
        #[serde(serialize_with = "ser_u128_str", deserialize_with = "de_u128_str")]
        max_amount_per_call: u128,
        /// Optional restriction to a single resource class, as spelled by
        /// `tenzro_types::ResourceClass::as_str` (`"skill"`, `"tool"`, …).
        /// `None` permits any class.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        class: Option<String>,
        /// Optional whitelist of resource ids the bearer may invoke, bare
        /// (unqualified by class). `None` permits any id in the class.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_resource_ids: Option<Vec<String>>,
    },
}

/// Free-standing constraint envelope — used internally by the engine
/// when comparing a *requested* action against a stored grant. Public
/// so external callers can construct an "intent" and ask the engine
/// `is_permitted(intent)` without knowing the JWT structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceConstraint {
    /// Asset involved in the requested action, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<AssetId>,
    /// Amount requested (in base units of `asset`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_opt_u128_str",
        deserialize_with = "de_opt_u128_str"
    )]
    pub amount: Option<u128>,
    /// Counterparty / payee / contract address involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<Address>,
    /// Free-form discriminator for typed actions where the grant has
    /// allow-lists (e.g., model_id for `Inference`, escrow_id for
    /// `DischargeEscrow`, proposal_id for `Vote`). For `InvokeResource`
    /// it is qualified by class as `"<class>:<id>"` (e.g.
    /// `"skill:web-search"`) because the grant restricts on both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
}
