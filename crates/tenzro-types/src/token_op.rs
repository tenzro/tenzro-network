//! Operations on token-factory tokens, as consensus transactions.
//!
//! Every fungible token other than TNZO lives in one ledger in chain state
//! (the token factory's storage). These operations create tokens, change
//! their supply, and carry an issuer's compliance controls; holder transfers
//! go through any of the ledger's views (the factory precompile, the SPL
//! token program, or [`TokenOp::Transfer`]).

use serde::{Deserialize, Serialize};

use crate::reserve::ReserveAttestation;
use crate::token_policy::{
    Authority, IssuerAction, KeySet, Power, PowerManifest, ReserveBacking, TokenPolicy,
};

/// Longest token name or symbol.
pub const MAX_TOKEN_NAME_LEN: usize = 64;

/// One operation on a token-factory token. The sender is the actor: the
/// issuer for issuer operations, the holder for its own balance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenOp {
    /// Create a token issued by the sender, crediting it `initial_supply`.
    Create {
        /// Display name.
        name: String,
        /// Ticker symbol.
        symbol: String,
        /// Decimal places.
        decimals: u8,
        /// Units credited to the issuer.
        #[serde(with = "crate::primitives::u128_serde")]
        initial_supply: u128,
        /// Ceiling on the supply, if any.
        #[serde(with = "opt_u128")]
        max_supply: Option<u128>,
        /// Who holds each issuer power; only narrows after creation.
        powers: PowerManifest,
        /// Who may hold the token.
        policy: TokenPolicy,
        /// Issuer council, required when the manifest names one.
        council: Option<KeySet>,
        /// For a token backed one to one by reserves held elsewhere: the
        /// bonded attestor stake every mint's reserve attestations must hold.
        reserve_backing: Option<ReserveBacking>,
    },
    /// Issue `amount` to `to`, by the mint authority, within the maximum
    /// supply; a reserve-backed token's mint carries attestations from
    /// bonded attestors, holding the token's required stake between them,
    /// each covering the supply after the mint.
    Mint {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// Recipient account.
        #[serde(with = "crate::payment_authorization::hex_bytes")]
        to: Vec<u8>,
        /// Units.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// The reserve attestations a reserve-backed token requires.
        reserves: Vec<ReserveAttestation>,
    },
    /// Retire `amount` of the sender's own balance.
    Burn {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// Units.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Move `amount` of the sender's balance to `to`.
    Transfer {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// Recipient account.
        #[serde(with = "crate::payment_authorization::hex_bytes")]
        to: Vec<u8>,
        /// Units.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
    },
    /// Freeze `amount` of `account`'s balance (zero unfreezes it), by the
    /// freeze authority, at once, with a reason and evidence.
    SetFrozen {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// Holder account.
        #[serde(with = "crate::payment_authorization::hex_bytes")]
        account: Vec<u8>,
        /// Units frozen.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// Reason code and evidence hash.
        action: IssuerAction,
    },
    /// Halt (`true`) or resume holder transfers of the token, by the halt
    /// authority, at once, with a reason and evidence.
    SetHalted {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// Whether transfers are halted.
        halted: bool,
        /// Reason code and evidence hash.
        action: IssuerAction,
    },
    /// Narrow who holds one issuer power (to a council, a larger council
    /// threshold, or nobody). Never widens.
    RenouncePower {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// The power.
        power: Power,
        /// Who holds it afterwards.
        to: Authority,
    },
    /// Queue a new eligibility policy, by the policy authority. It may take
    /// effect with [`TokenOp::ExecutePolicy`] once the current policy's
    /// timelock has passed; holders move under the policy in force until
    /// then.
    SetPolicy {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// The new policy.
        policy: TokenPolicy,
    },
    /// Queue new reserve backing (or none), by the policy authority, under
    /// the same timelock as a policy change.
    SetReserveBacking {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// The new backing.
        backing: Option<ReserveBacking>,
    },
    /// Apply a queued policy or reserve-backing change whose timelock has
    /// passed. Anyone may submit it.
    ExecutePolicy {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
    },
    /// Record a claim about `subject` for this token, by a claim issuer the
    /// token's policy names.
    AddClaim {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// Account the claim is about.
        #[serde(with = "crate::payment_authorization::hex_bytes")]
        subject: Vec<u8>,
        /// Claim kind (`kyc`, `jurisdiction`, ...).
        kind: String,
        /// Claim value (a jurisdiction code, a level, ...).
        value: String,
        /// Block time the claim lapses at.
        expires_ms: i64,
    },
    /// Withdraw the sender's claim of `kind` about `subject`.
    RevokeClaim {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// Account the claim is about.
        #[serde(with = "crate::payment_authorization::hex_bytes")]
        subject: Vec<u8>,
        /// Claim kind.
        kind: String,
    },
    /// One issuer-council member's approval of `op`. The op executes once
    /// the council threshold its power names has approved the same op.
    Approve {
        /// The issuer operation approved. Decoding refuses an approval
        /// nested inside another, so the encoding cannot recurse.
        #[serde(deserialize_with = "approved_op")]
        op: Box<TokenOp>,
    },
    /// Move `amount` from `from` to `to` by the force authority, past a halt
    /// and frozen amounts (an ERC-7943 forced transfer), with a reason and
    /// evidence.
    ForcedTransfer {
        /// Token id.
        #[serde(with = "hex32")]
        token_id: [u8; 32],
        /// Holder debited.
        #[serde(with = "crate::payment_authorization::hex_bytes")]
        from: Vec<u8>,
        /// Account credited.
        #[serde(with = "crate::payment_authorization::hex_bytes")]
        to: Vec<u8>,
        /// Units.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// Reason code and evidence hash.
        action: IssuerAction,
    },
}

fn account_ok(a: &[u8]) -> bool {
    a.len() == 20 || a.len() == 32
}

impl TokenOp {
    /// Whether the operation exercises an issuer power over other holders
    /// rather than the sender's own balance.
    pub fn is_issuer_power(&self) -> bool {
        !matches!(
            self,
            Self::Create { .. }
                | Self::Burn { .. }
                | Self::Transfer { .. }
                | Self::ExecutePolicy { .. }
        )
    }

    /// The token the operation acts on, if it names one.
    pub fn token_id(&self) -> Option<[u8; 32]> {
        match self {
            Self::Create { .. } => None,
            Self::Approve { op } => op.token_id(),
            Self::Mint { token_id, .. }
            | Self::Burn { token_id, .. }
            | Self::Transfer { token_id, .. }
            | Self::SetFrozen { token_id, .. }
            | Self::SetHalted { token_id, .. }
            | Self::RenouncePower { token_id, .. }
            | Self::SetPolicy { token_id, .. }
            | Self::SetReserveBacking { token_id, .. }
            | Self::ExecutePolicy { token_id }
            | Self::AddClaim { token_id, .. }
            | Self::RevokeClaim { token_id, .. }
            | Self::ForcedTransfer { token_id, .. } => Some(*token_id),
        }
    }

    /// The issuer power the operation exercises, if any.
    pub fn power(&self) -> Option<Power> {
        match self {
            Self::Mint { .. } => Some(Power::Mint),
            Self::SetFrozen { .. } => Some(Power::Freeze),
            Self::SetHalted { .. } => Some(Power::Halt),
            Self::ForcedTransfer { .. } => Some(Power::Force),
            Self::RenouncePower { power, .. } => Some(*power),
            Self::SetPolicy { .. } | Self::SetReserveBacking { .. } => Some(Power::PolicyChange),
            _ => None,
        }
    }

    /// Shape checks that need no state.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Create {
                name,
                symbol,
                powers,
                policy,
                council,
                reserve_backing,
                ..
            } => {
                if name.is_empty()
                    || symbol.is_empty()
                    || name.len() > MAX_TOKEN_NAME_LEN
                    || symbol.len() > MAX_TOKEN_NAME_LEN
                {
                    return Err("a token name and symbol are 1 to 64 bytes");
                }
                policy.validate()?;
                if let Some(c) = council {
                    c.validate()?;
                }
                if let Some(b) = reserve_backing {
                    b.validate()?;
                }
                let k = powers.max_council_k();
                if k > 0
                    && council
                        .as_ref()
                        .is_none_or(|c| usize::from(k) > c.members.len())
                {
                    return Err("a council threshold needs a council at least that large");
                }
            }
            Self::SetFrozen {
                account, action, ..
            } => {
                if !account_ok(account) {
                    return Err("an account is 20 or 32 bytes");
                }
                action.validate()?;
            }
            Self::SetHalted { action, .. } => action.validate()?,
            Self::SetPolicy { policy, .. } => policy.validate()?,
            Self::SetReserveBacking {
                backing: Some(b), ..
            } => b.validate()?,
            Self::AddClaim {
                subject,
                kind,
                value,
                ..
            } => {
                if !account_ok(subject) {
                    return Err("an account is 20 or 32 bytes");
                }
                if kind.is_empty() || kind.len() > 64 || value.len() > 64 {
                    return Err("a claim kind is 1 to 64 bytes and its value at most 64");
                }
            }
            Self::Approve { op } => {
                if matches!(**op, Self::Approve { .. }) || op.power().is_none() {
                    return Err("a council approves one issuer operation");
                }
                op.validate()?;
            }
            Self::Mint { to, amount, .. } | Self::Transfer { to, amount, .. } => {
                if !account_ok(to) {
                    return Err("an account is 20 or 32 bytes");
                }
                if *amount == 0 {
                    return Err("the amount must be positive");
                }
            }
            Self::Burn { amount, .. } if *amount == 0 => return Err("the amount must be positive"),
            Self::ForcedTransfer {
                from,
                to,
                amount,
                action,
                ..
            } => {
                if !account_ok(from) || !account_ok(to) {
                    return Err("an account is 20 or 32 bytes");
                }
                action.validate()?;
                if *amount == 0 {
                    return Err("the amount must be positive");
                }
            }
            _ => {}
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

mod opt_u128 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_some(&v.to_string()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| s.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

thread_local! {
    static DECODING_APPROVAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Decodes the operation inside [`TokenOp::Approve`], refusing a nested
/// approval before reading it. Without this, every four bytes of input add
/// a level of recursion to the decoder, and a message of a few hundred
/// kilobytes overflows the decoding thread's stack.
fn approved_op<'de, D>(deserializer: D) -> Result<Box<TokenOp>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DECODING_APPROVAL.with(|f| f.set(false));
        }
    }
    if DECODING_APPROVAL.with(|f| f.replace(true)) {
        return Err(serde::de::Error::custom(
            "an approval cannot approve an approval",
        ));
    }
    let _reset = Reset;
    TokenOp::deserialize(deserializer).map(Box::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_create_round_trips_and_refuses_an_empty_symbol() {
        let op = TokenOp::Create {
            name: "Gold".into(),
            symbol: "GLD".into(),
            decimals: 6,
            initial_supply: 10,
            max_supply: Some(1_000),
            powers: PowerManifest {
                mint: Authority::Issuer,
                freeze: Authority::Issuer,
                halt: Authority::Issuer,
                force: Authority::IssuerCouncil { k: 2 },
                policy_change: Authority::Issuer,
            },
            policy: TokenPolicy::default(),
            council: Some(KeySet {
                k: 2,
                members: vec!["11".repeat(32), "22".repeat(32)],
            }),
            reserve_backing: Some(ReserveBacking {
                min_attestor_stake_tnzo: 100_000,
            }),
        };
        let back: TokenOp = serde_json::from_slice(&serde_json::to_vec(&op).unwrap()).unwrap();
        assert_eq!(back, op);
        assert!(op.validate().is_ok());
        let bad = TokenOp::Create {
            name: "Gold".into(),
            symbol: String::new(),
            decimals: 6,
            initial_supply: 10,
            max_supply: None,
            powers: PowerManifest::NONE,
            policy: TokenPolicy::default(),
            council: None,
            reserve_backing: None,
        };
        assert!(bad.validate().is_err());
        let no_council = TokenOp::Create {
            name: "Gold".into(),
            symbol: "GLD".into(),
            decimals: 6,
            initial_supply: 10,
            max_supply: None,
            powers: PowerManifest {
                force: Authority::IssuerCouncil { k: 2 },
                ..PowerManifest::NONE
            },
            policy: TokenPolicy::default(),
            council: None,
            reserve_backing: None,
        };
        assert!(
            no_council.validate().is_err(),
            "a council power needs a council"
        );
    }

    #[test]
    fn accounts_and_amounts_are_checked() {
        let op = TokenOp::Transfer {
            token_id: [1; 32],
            to: vec![1; 7],
            amount: 1,
        };
        assert!(op.validate().is_err());
        let op = TokenOp::Burn {
            token_id: [1; 32],
            amount: 0,
        };
        assert!(op.validate().is_err());
        let forced = TokenOp::ForcedTransfer {
            token_id: [1; 32],
            from: vec![1; 32],
            to: vec![2; 32],
            amount: 1,
            action: IssuerAction {
                reason_code: 0,
                evidence_hash: [0; 32],
            },
        };
        assert!(
            forced.validate().is_err(),
            "a forced transfer carries reason and evidence"
        );
    }

    #[test]
    fn an_approval_of_an_approval_does_not_decode() {
        let burn = TokenOp::Burn {
            token_id: [3; 32],
            amount: 5,
        };
        let once = TokenOp::Approve {
            op: Box::new(burn.clone()),
        };
        let twice = TokenOp::Approve {
            op: Box::new(once.clone()),
        };

        let b = bincode::serialize(&once).unwrap();
        assert_eq!(bincode::deserialize::<TokenOp>(&b).unwrap(), once);
        assert!(bincode::deserialize::<TokenOp>(&bincode::serialize(&twice).unwrap()).is_err());
        // A refused decode leaves the next one on the thread unaffected.
        assert_eq!(bincode::deserialize::<TokenOp>(&b).unwrap(), once);

        let j = serde_json::to_vec(&once).unwrap();
        assert_eq!(serde_json::from_slice::<TokenOp>(&j).unwrap(), once);
        assert!(serde_json::from_slice::<TokenOp>(&serde_json::to_vec(&twice).unwrap()).is_err());
        assert_eq!(serde_json::from_slice::<TokenOp>(&j).unwrap(), once);
    }
}
