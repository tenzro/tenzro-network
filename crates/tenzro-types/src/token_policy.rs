//! What a token's issuer may do, and who may hold the token.
//!
//! Both are data in the token's consensus record, evaluated by one rule
//! engine in the ledger for every view of the token (native operations, the
//! EVM factory and its ERC-20 facades, and the SVM token programs).
//!
//! - The [`PowerManifest`] is fixed when the token is created and can only be
//!   narrowed afterwards.
//! - The [`TokenPolicy`] lists eligibility rules. Changing it queues for the
//!   token's policy timelock, during which holders can still move out under
//!   the policy in force.
//! - Freeze, halt and forced transfer on specific accounts act at once but
//!   must carry a reason code and an evidence hash.

use serde::{Deserialize, Serialize};

/// Most eligibility rules one policy may carry.
pub const MAX_RULES: usize = 16;
/// Most claim issuers or jurisdictions one rule may name.
pub const MAX_RULE_ENTRIES: usize = 32;
/// Most members of an issuer council.
pub const MAX_SET_MEMBERS: usize = 16;

/// Who may exercise one issuer power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    /// Nobody: the power is gone for good.
    Disabled,
    /// The issuer account alone.
    Issuer,
    /// `k` distinct members of the token's issuer council, each approving
    /// with its own signed transaction.
    IssuerCouncil {
        /// Approvals needed.
        k: u8,
    },
}

impl Authority {
    /// Rank for narrowing: a power may move only to a rank no higher than
    /// its current one, and within a council only to a larger `k`.
    fn narrows_to(&self, next: &Authority) -> bool {
        match (self, next) {
            (_, Authority::Disabled) => true,
            (Authority::Disabled, _) => false,
            (Authority::Issuer, Authority::Issuer) => true,
            (Authority::Issuer, Authority::IssuerCouncil { .. }) => true,
            (Authority::IssuerCouncil { .. }, Authority::Issuer) => false,
            (Authority::IssuerCouncil { k: a }, Authority::IssuerCouncil { k: b }) => b >= a,
        }
    }
}

/// One issuer power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Power {
    /// Issue new units.
    Mint,
    /// Freeze part of an account's balance.
    Freeze,
    /// Halt all holder transfers.
    Halt,
    /// Move units out of an account without its holder.
    Force,
    /// Change the eligibility policy or the reserve backing.
    PolicyChange,
}

/// Every issuer power and who holds it. Fixed at creation; only narrows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerManifest {
    /// Who may mint.
    pub mint: Authority,
    /// Who may freeze.
    pub freeze: Authority,
    /// Who may halt.
    pub halt: Authority,
    /// Who may force a transfer.
    pub force: Authority,
    /// Who may change the policy or reserve backing.
    pub policy_change: Authority,
}

impl PowerManifest {
    /// A manifest granting no issuer power at all.
    pub const NONE: PowerManifest = PowerManifest {
        mint: Authority::Disabled,
        freeze: Authority::Disabled,
        halt: Authority::Disabled,
        force: Authority::Disabled,
        policy_change: Authority::Disabled,
    };

    /// Who holds `power`.
    pub fn get(&self, power: Power) -> Authority {
        match power {
            Power::Mint => self.mint,
            Power::Freeze => self.freeze,
            Power::Halt => self.halt,
            Power::Force => self.force,
            Power::PolicyChange => self.policy_change,
        }
    }

    /// The manifest with `power` held by `to`, if that narrows it.
    pub fn narrowed(&self, power: Power, to: Authority) -> Option<PowerManifest> {
        if !self.get(power).narrows_to(&to) {
            return None;
        }
        let mut next = *self;
        match power {
            Power::Mint => next.mint = to,
            Power::Freeze => next.freeze = to,
            Power::Halt => next.halt = to,
            Power::Force => next.force = to,
            Power::PolicyChange => next.policy_change = to,
        }
        Some(next)
    }

    /// Largest council threshold the manifest names.
    pub fn max_council_k(&self) -> u8 {
        [
            self.mint,
            self.freeze,
            self.halt,
            self.force,
            self.policy_change,
        ]
        .iter()
        .map(|a| match a {
            Authority::IssuerCouncil { k } => *k,
            _ => 0,
        })
        .max()
        .unwrap_or(0)
    }
}

/// What kind of account may hold the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderKind {
    /// An account whose registered identity is a human.
    HumanRoot,
    /// An agent acting under live consensus Terms.
    AgentUnderTerms,
    /// A machine identity.
    Machine,
    /// Any account.
    Any,
}

/// One eligibility rule. A transfer's recipient must satisfy every rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    /// The recipient holds a live claim of `kind` from one of `issuers`.
    RequireClaim {
        /// Claim kind (for example `kyc`, `accredited`).
        kind: String,
        /// Claim issuer DIDs the token accepts.
        issuers: Vec<String>,
    },
    /// The recipient holds no live `jurisdiction` claim naming one of
    /// `blocs`.
    DenyJurisdiction {
        /// Jurisdiction codes refused.
        blocs: Vec<String>,
    },
    /// The recipient holds a live `jurisdiction` claim, from an issuer the
    /// token's claim rules name, naming one of `blocs`: an issuer that may
    /// only serve some jurisdictions lists them here.
    AllowJurisdiction {
        /// Jurisdiction codes served.
        blocs: Vec<String>,
    },
    /// The recipient is of this kind.
    HolderKind {
        /// The kind.
        kind: HolderKind,
    },
    /// At most `max` accounts hold a non-zero balance.
    MaxHolders {
        /// The ceiling.
        max: u64,
    },
    /// No account holds more than `bps` of the supply.
    MaxBalanceBps {
        /// The ceiling, in basis points of the total supply.
        bps: u16,
    },
    /// Holder transfers are refused until block time `until_ms`.
    Lockup {
        /// End of the lockup.
        until_ms: i64,
    },
    /// An agent recipient's Terms verification level is at least `level`
    /// (1: live Terms; 2: every serving node's key is hardware-certified;
    /// 3: also served by at least two distinct operators).
    MinTermsVerification {
        /// The floor.
        level: u8,
    },
    /// The recipient holds a live `kyc` claim, from an issuer the token's
    /// claim rules name, graded at least `tier` (1 basic, 2 enhanced,
    /// 3 full).
    MinKycTier {
        /// The floor.
        tier: u8,
    },
}

/// The eligibility policy of a token and the delays that guard changing it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TokenPolicy {
    /// Rules every recipient must satisfy.
    pub eligibility: Vec<Rule>,
    /// How long a policy or attestor-set change waits before it may take
    /// effect; at least the governed floor `token.policy_timelock_floor_ms`.
    pub policy_timelock_ms: u64,
}

impl TokenPolicy {
    /// Shape checks that need no state.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.eligibility.len() > MAX_RULES {
            return Err("a policy carries at most 16 rules");
        }
        for r in &self.eligibility {
            match r {
                Rule::RequireClaim { kind, issuers } => {
                    if kind.is_empty()
                        || kind.len() > 64
                        || issuers.is_empty()
                        || issuers.len() > MAX_RULE_ENTRIES
                    {
                        return Err("a claim rule names a 1 to 64 byte kind and 1 to 32 issuers");
                    }
                }
                Rule::DenyJurisdiction { blocs } => {
                    if blocs.is_empty() || blocs.len() > MAX_RULE_ENTRIES {
                        return Err("a jurisdiction rule names 1 to 32 codes");
                    }
                }
                Rule::AllowJurisdiction { blocs } => {
                    if blocs.is_empty() || blocs.len() > MAX_RULE_ENTRIES {
                        return Err("a jurisdiction rule names 1 to 32 codes");
                    }
                    if !self
                        .eligibility
                        .iter()
                        .any(|r| matches!(r, Rule::RequireClaim { .. }))
                    {
                        return Err(
                            "a jurisdiction allow-list needs a claim rule naming who attests jurisdictions",
                        );
                    }
                }
                Rule::MaxBalanceBps { bps } if *bps == 0 || *bps > 10_000 => {
                    return Err("a balance ceiling is 1 to 10000 bps");
                }
                Rule::MinTermsVerification { level } if *level == 0 || *level > 3 => {
                    return Err("a Terms verification level is 1 to 3");
                }
                Rule::MinKycTier { tier } => {
                    if *tier == 0 || *tier > 3 {
                        return Err("a KYC tier is 1 to 3");
                    }
                    if !self
                        .eligibility
                        .iter()
                        .any(|r| matches!(r, Rule::RequireClaim { .. }))
                    {
                        return Err("a KYC tier rule needs a claim rule naming who grades it");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// What stands behind every mint of a reserve-backed token: reserve
/// attestations signed by accounts bonded as attestors, whose attestor stake
/// together is at least `min_attestor_stake_tnzo`. Any bonded attestor may
/// attest; the issuer chooses only how much bonded stake a mint needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveBacking {
    /// Attestor stake, whole TNZO, the attestations behind a mint must hold
    /// between them.
    pub min_attestor_stake_tnzo: u64,
}

impl ReserveBacking {
    /// Shape checks: a mint needs some bonded stake behind it.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.min_attestor_stake_tnzo == 0 {
            return Err("a reserve-backed token needs attestor stake behind each mint");
        }
        Ok(())
    }
}

/// A k-of-n set of keys: an issuer council, whose members are accounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySet {
    /// Distinct members required.
    pub k: u8,
    /// Members, hex.
    pub members: Vec<String>,
}

impl KeySet {
    /// Shape checks that need no state.
    pub fn validate(&self) -> Result<(), &'static str> {
        let mut seen = std::collections::BTreeSet::new();
        if self.k == 0
            || usize::from(self.k) > self.members.len()
            || self.members.len() > MAX_SET_MEMBERS
        {
            return Err("a key set needs 1 <= k <= n <= 16");
        }
        for m in &self.members {
            let bytes =
                hex::decode(m.trim_start_matches("0x")).map_err(|_| "a key set member is hex")?;
            if !(bytes.len() == 20 || bytes.len() == 32) {
                return Err("a key set member is 20 or 32 bytes");
            }
            if !seen.insert(bytes) {
                return Err("key set members are distinct");
            }
        }
        Ok(())
    }

    /// Members as bytes.
    pub fn member_bytes(&self) -> Vec<Vec<u8>> {
        self.members
            .iter()
            .filter_map(|m| hex::decode(m.trim_start_matches("0x")).ok())
            .collect()
    }
}

/// Why an issuer froze, halted or forced: a reason code and the hash of the
/// evidence, both required and both recorded on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerAction {
    /// Issuer-defined reason code; zero is refused.
    pub reason_code: u16,
    /// Hash of the evidence held off-chain; all zeroes is refused.
    #[serde(with = "hex32")]
    pub evidence_hash: [u8; 32],
}

impl IssuerAction {
    /// Refuses a missing reason or evidence.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.reason_code == 0 {
            return Err("an issuer action carries a non-zero reason code");
        }
        if self.evidence_hash == [0u8; 32] {
            return Err("an issuer action carries an evidence hash");
        }
        Ok(())
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        <[u8; 32]>::try_from(v.as_slice())
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_all() -> PowerManifest {
        PowerManifest {
            mint: Authority::Issuer,
            freeze: Authority::Issuer,
            halt: Authority::Issuer,
            force: Authority::Issuer,
            policy_change: Authority::Issuer,
        }
    }

    #[test]
    fn a_manifest_narrows_and_never_widens() {
        let m = issuer_all();
        let council = m
            .narrowed(Power::Force, Authority::IssuerCouncil { k: 2 })
            .expect("issuer to council narrows");
        assert!(
            council.narrowed(Power::Force, Authority::Issuer).is_none(),
            "council back to issuer widens"
        );
        assert!(
            council
                .narrowed(Power::Force, Authority::IssuerCouncil { k: 1 })
                .is_none(),
            "smaller k widens"
        );
        let off = council.narrowed(Power::Force, Authority::Disabled).unwrap();
        assert!(
            off.narrowed(Power::Force, Authority::Issuer).is_none(),
            "a renounced power stays gone"
        );
        assert!(
            PowerManifest::NONE
                .narrowed(Power::Mint, Authority::Issuer)
                .is_none()
        );
    }

    #[test]
    fn an_issuer_action_needs_reason_and_evidence() {
        assert!(
            IssuerAction {
                reason_code: 0,
                evidence_hash: [1; 32]
            }
            .validate()
            .is_err()
        );
        assert!(
            IssuerAction {
                reason_code: 3,
                evidence_hash: [0; 32]
            }
            .validate()
            .is_err()
        );
        assert!(
            IssuerAction {
                reason_code: 3,
                evidence_hash: [1; 32]
            }
            .validate()
            .is_ok()
        );
    }
}
