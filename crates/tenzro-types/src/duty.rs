//! Network duties: work the chain itself pays for, to whoever proves it
//! first.
//!
//! A duty holds its reward in a vault no key controls. The transaction that
//! proves the work (a verified reconciliation of a route's settlement lock,
//! the proven install of a voided agent grant on another chain) pays the
//! reward to its sender and closes the duty; nobody awards it. A duty the
//! work never arrived for closes at its expiry and its reward returns to
//! whoever funded it. What a duty pays is a governed parameter or a deposit
//! its funder made, never a value in code.
//!
//! A proof of the epoch handover chain is such work: whoever wants a chain's
//! handovers proven to an epoch (a node operator that keeps the proof in
//! place of the handovers, anyone serving light clients) funds a duty for it,
//! and the first Groth16 proof of the governed handover program that reaches
//! that epoch of that chain is paid.

use serde::{Deserialize, Serialize};

use crate::agent_audit::hex32;

/// The work a duty pays for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DutyKind {
    /// Reconcile a route's settlement lock for one epoch. Funded by the
    /// treasury at `settlement.reconciliation_reward`.
    Reconciliation {
        /// The route's storage key.
        route: String,
        /// The epoch.
        epoch: u64,
    },
    /// Install a voided agent grant on another chain. Funded by the grant's
    /// relay deposit.
    GrantRelay {
        /// The agent whose grant was voided.
        agent_did: String,
        /// The chain, CAIP-2.
        chain: String,
        /// The grant sequence the install must carry.
        seq: u64,
    },
    /// Prove the epoch handover chain of one chain to at least `epoch`.
    /// Funded by whoever opens it.
    HandoverProof {
        /// Chain id.
        chain_id: u64,
        /// Genesis block hash.
        #[serde(with = "hex32")]
        genesis_hash: [u8; 32],
        /// Root of the genesis committee.
        #[serde(with = "hex32")]
        genesis_root: [u8; 32],
        /// The epoch the proven chain must reach.
        epoch: u64,
    },
}

/// An operation on a handover proof duty (the `HandoverDuty` transaction).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HandoverDutyOp {
    /// Open the duty, moving `reward` from the sender into its vault.
    Open {
        /// Chain id.
        chain_id: u64,
        /// Genesis block hash.
        #[serde(with = "hex32")]
        genesis_hash: [u8; 32],
        /// Root of the genesis committee.
        #[serde(with = "hex32")]
        genesis_root: [u8; 32],
        /// The epoch the proven chain must reach.
        epoch: u64,
        /// The reward, wei.
        #[serde(with = "crate::primitives::u128_serde")]
        reward: u128,
        /// When it closes unpaid, ms.
        expires_at_ms: i64,
    },
    /// Deliver the proof: the chain journal the handover program committed
    /// and the Groth16 seal proving it. Pays the sender.
    Deliver {
        /// The duty.
        #[serde(with = "hex32")]
        duty_id: [u8; 32],
        /// The chain journal, as the handover program encodes it.
        #[serde(with = "crate::agent_audit::hex_bytes")]
        journal: Vec<u8>,
        /// The 256-byte Groth16 seal.
        #[serde(with = "crate::agent_audit::hex_bytes")]
        seal: Vec<u8>,
    },
    /// Close an expired duty, returning its reward to the funder.
    Close {
        /// The duty.
        #[serde(with = "hex32")]
        duty_id: [u8; 32],
    },
}

impl DutyKind {
    /// The duty's id: SHA-256 over a domain tag and the kind's fields.
    pub fn id(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tenzro/duty/v1");
        let field = |h: &mut Sha256, s: &str| {
            h.update((s.len() as u64).to_be_bytes());
            h.update(s.as_bytes());
        };
        match self {
            Self::Reconciliation { route, epoch } => {
                h.update([0u8]);
                field(&mut h, route);
                h.update(epoch.to_be_bytes());
            }
            Self::GrantRelay {
                agent_did,
                chain,
                seq,
            } => {
                h.update([1u8]);
                field(&mut h, agent_did);
                field(&mut h, chain);
                h.update(seq.to_be_bytes());
            }
            Self::HandoverProof {
                chain_id,
                genesis_hash,
                genesis_root,
                epoch,
            } => {
                h.update([2u8]);
                h.update(chain_id.to_be_bytes());
                h.update(genesis_hash);
                h.update(genesis_root);
                h.update(epoch.to_be_bytes());
            }
        }
        h.finalize().into()
    }
}

/// Where a duty stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DutyState {
    /// Waiting for the proof.
    Open,
    /// Paid to the first sender whose proof the chain verified.
    Paid,
    /// Closed unpaid; the reward went back to the funder.
    Expired,
}

/// A duty in chain state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Duty {
    /// The duty id.
    #[serde(with = "hex32")]
    pub id: [u8; 32],
    /// The work.
    pub kind: DutyKind,
    /// The vault holding the reward.
    #[serde(with = "hex32")]
    pub vault: [u8; 32],
    /// The account an unpaid reward returns to.
    #[serde(with = "hex32")]
    pub funder: [u8; 32],
    /// The reward, wei.
    #[serde(with = "crate::primitives::u128_serde")]
    pub reward: u128,
    /// When it opened, ms.
    pub opened_at_ms: i64,
    /// When it closes unpaid, ms; `None` while its funder keeps it open.
    pub expires_at_ms: Option<i64>,
    /// Where it stands.
    pub state: DutyState,
    /// Who it paid, once paid.
    #[serde(default, with = "crate::settlement::opt_hex32")]
    pub paid_to: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_separate_kinds_and_fields() {
        let a = DutyKind::Reconciliation {
            route: "r".into(),
            epoch: 1,
        };
        let b = DutyKind::Reconciliation {
            route: "r".into(),
            epoch: 2,
        };
        let c = DutyKind::GrantRelay {
            agent_did: "r".into(),
            chain: String::new(),
            seq: 1,
        };
        assert_ne!(a.id(), b.id());
        assert_ne!(a.id(), c.id());
        assert_eq!(a.id(), a.clone().id());
    }

    #[test]
    fn a_duty_round_trips() {
        let d = Duty {
            id: [1; 32],
            kind: DutyKind::GrantRelay {
                agent_did: "did:tenzro:agent:a".into(),
                chain: "eip155:1".into(),
                seq: 4,
            },
            vault: [2; 32],
            funder: [2; 32],
            reward: 5,
            opened_at_ms: 9,
            expires_at_ms: None,
            state: DutyState::Paid,
            paid_to: Some([3; 32]),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<Duty>(&json).unwrap(), d);
    }
}
