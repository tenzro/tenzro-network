//! Per-block value invariants, each guarding one module, and the freeze of
//! the module whose invariant breaks.
//!
//! Every transaction already conserves value (`ledger::conserves_value`) and
//! every block's balance writes net to its recorded supply change
//! (`ledger::verify_block`). Neither catches value that moves between
//! accounts by a logic bug in a module: a vault paying out more than it owes
//! conserves supply. So at the end of every block ([`check_block`], run from
//! `ledger::settle_block`) each guarded module's vault is checked against
//! what the module's own records say it owes:
//!
//! * staking: the staking vault holds at least every bond and every amount
//!   unbonding;
//! * insurance: the insurance pool holds at least what its record says was
//!   credited (fees and slashed bonds) less what it paid out;
//! * escrow and payment channels: each escrow vault holds at least what its
//!   escrow record still owes (the amount less what was claimed, while it is
//!   funded);
//! * bridge: each TNZO route vault holds at least what the route's supply
//!   record says is locked.
//!
//! Escrow, channel and bridge vaults are one per escrow or route, too many to
//! read every block. Those modules record, each time they move value through
//! a vault, what the vault owes ([`record_owed`]); the record also marks the
//! vault as touched in this block, and the end-of-block check reads only the
//! touched vaults. A module that moves value through a vault without
//! recording it leaves the vault unchecked, so every path that pays out of
//! one records it.
//!
//! A module whose vault holds less is frozen in the same block: each of its
//! entry points refuses ([`require_unfrozen`]) until governance lifts the
//! freeze (`ProposalAction::LiftModuleFreeze`). Every other module keeps
//! working, and what the broken module can lose is bounded by what one block
//! moved before the check. A lifted freeze whose invariant still fails is
//! put back at the end of the next block, so governance restores the vault
//! first.

use serde::{Deserialize, Serialize};

use crate::error::{Result, VmError};
use crate::traits::VmState;

/// A module whose vault the monitor checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardedModule {
    /// Validator bonds and unbonding stake, held by the staking vault.
    Staking,
    /// The insurance pool.
    Insurance,
    /// Escrows: creation, release and refund.
    Escrow,
    /// Payment channels: voucher, preimage and stream claims on an escrow.
    PaymentChannel,
    /// Bridge routes: TNZO locked in a route's vault and released from it.
    Bridge,
}

impl GuardedModule {
    /// Every guarded module, in check order.
    pub const ALL: [GuardedModule; 5] = [
        GuardedModule::Staking,
        GuardedModule::Insurance,
        GuardedModule::Escrow,
        GuardedModule::PaymentChannel,
        GuardedModule::Bridge,
    ];

    /// Stable name, used in storage keys and messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::Staking => "staking",
            Self::Insurance => "insurance",
            Self::Escrow => "escrow",
            Self::PaymentChannel => "payment_channel",
            Self::Bridge => "bridge",
        }
    }

    /// Whether the module's vaults are per escrow or route, checked from
    /// the records of the vaults touched in the block.
    fn per_vault(self) -> bool {
        matches!(self, Self::Escrow | Self::PaymentChannel | Self::Bridge)
    }

    fn touched_key(self) -> String {
        format!("invariant_touched/{}", self.name())
    }

    fn freeze_key(self) -> String {
        format!("invariant_freeze/{}", self.name())
    }

    /// What the module's vault holds and what its records say it owes; for
    /// a per-vault module, the first touched vault that holds less than it
    /// owes, or the touched vaults' totals when none does.
    fn held_and_owed(self, state: &dyn VmState) -> (u128, u128) {
        match self {
            Self::Escrow | Self::PaymentChannel | Self::Bridge => {
                let (mut held, mut owed) = (0u128, 0u128);
                for v in touched(state, self) {
                    let h = crate::token_ledger::balance(state, &v.token, &v.vault);
                    let o = read_owed(state, &v);
                    if h < o {
                        return (h, o);
                    }
                    held = held.saturating_add(h);
                    owed = owed.saturating_add(o);
                }
                (held, owed)
            }
            Self::Staking => (
                state.get_balance(&crate::native::staking_vault_address()),
                crate::native::staking::vault_liabilities(state),
            ),
            Self::Insurance => {
                let t = crate::native::insurance::read_totals(state);
                (
                    state.get_balance(crate::native::insurance::pool_address().as_bytes()),
                    t.from_fees
                        .saturating_add(t.from_slashes)
                        .saturating_sub(t.total_paid),
                )
            }
        }
    }
}

/// The record of a frozen module: what its vault held and what it owed when
/// the monitor froze it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleFreeze {
    /// The vault's balance.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub held: u128,
    /// What the module's records said it owed.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub owed: u128,
}

/// A vault a per-vault module moved value through, in one asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TouchedVault {
    #[serde(with = "hex_bytes")]
    vault: Vec<u8>,
    #[serde(with = "hex_bytes32")]
    token: [u8; 32],
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        hex::decode(String::deserialize(d)?)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("a token id is 32 bytes"))
    }
}

/// What a vault owes in one asset. One record per vault and asset: escrow
/// and payment channels pay out of the same escrow vaults, and whichever
/// moved value last wrote what the escrow record then said it owed.
fn owed_key(v: &TouchedVault) -> String {
    format!(
        "invariant_owed/{}/{}",
        hex::encode(&v.vault),
        hex::encode(v.token)
    )
}

fn read_owed(state: &dyn VmState, v: &TouchedVault) -> u128 {
    state
        .get_storage(&crate::native::SYSTEM_ADDRESS, owed_key(v).as_bytes())
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
        .map(u128::from_be_bytes)
        .unwrap_or(0)
}

fn touched(state: &dyn VmState, module: GuardedModule) -> Vec<TouchedVault> {
    state
        .get_storage(
            &crate::native::SYSTEM_ADDRESS,
            module.touched_key().as_bytes(),
        )
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_touched(state: &mut dyn VmState, module: GuardedModule, list: &[TouchedVault]) {
    let blob = if list.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(list).expect("touched vaults encode")
    };
    state.set_storage(
        &crate::native::SYSTEM_ADDRESS,
        module.touched_key().as_bytes(),
        blob,
    );
}

/// Records that `vault` owes `owed` of `token` by the records of `module`,
/// which just moved value through it, and marks the vault for the
/// end-of-block check.
pub fn record_owed(
    state: &mut dyn VmState,
    module: GuardedModule,
    vault: &[u8],
    token: &[u8; 32],
    owed: u128,
) {
    debug_assert!(module.per_vault(), "{} has one vault", module.name());
    let v = TouchedVault {
        vault: vault.to_vec(),
        token: *token,
    };
    state.set_storage(
        &crate::native::SYSTEM_ADDRESS,
        owed_key(&v).as_bytes(),
        owed.to_be_bytes().to_vec(),
    );
    let mut list = touched(state, module);
    if !list.contains(&v) {
        list.push(v);
        write_touched(state, module, &list);
    }
}

/// The freeze on `module`, if it is frozen.
pub fn frozen(state: &dyn VmState, module: GuardedModule) -> Option<ModuleFreeze> {
    state
        .get_storage(
            &crate::native::SYSTEM_ADDRESS,
            module.freeze_key().as_bytes(),
        )
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// Refuses while `module` is frozen.
///
/// # Errors
///
/// `VmError::InvalidTransaction` naming the freeze.
pub fn require_unfrozen(state: &dyn VmState, module: GuardedModule) -> Result<()> {
    match frozen(state, module) {
        None => Ok(()),
        Some(f) => Err(VmError::InvalidTransaction(format!(
            "{} is frozen: its vault held {} against {} owed; governance must lift the freeze",
            module.name(),
            f.held,
            f.owed
        ))),
    }
}

/// Checks every guarded module that is not frozen and freezes each whose
/// vault holds less than it owes. Returns the modules frozen by this call.
pub fn check_block(state: &mut dyn VmState) -> Vec<(GuardedModule, ModuleFreeze)> {
    let mut out = Vec::new();
    for module in GuardedModule::ALL {
        // A frozen module keeps its touched vaults, so the check after
        // governance lifts the freeze reads the vault that was short.
        if frozen(state, module).is_some() {
            continue;
        }
        let (held, owed) = module.held_and_owed(state);
        if held >= owed {
            if module.per_vault() {
                write_touched(state, module, &[]);
            }
            continue;
        }
        let freeze = ModuleFreeze { held, owed };
        tracing::error!(
            module = module.name(),
            held,
            owed,
            "value invariant broken: the module is frozen until governance lifts it"
        );
        state.set_storage(
            &crate::native::SYSTEM_ADDRESS,
            module.freeze_key().as_bytes(),
            serde_json::to_vec(&freeze).expect("freeze record encodes"),
        );
        out.push((module, freeze));
    }
    out
}

/// Lifts the freeze on `module`; the governance action's effect. Returns
/// the storage key and its prior value, for the action's state changes.
///
/// # Errors
///
/// `VmError::InvalidTransaction` when the module is not frozen.
pub(crate) fn lift(state: &mut dyn VmState, module: GuardedModule) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = module.freeze_key().into_bytes();
    let prior = state
        .get_storage(&crate::native::SYSTEM_ADDRESS, &key)
        .filter(|b| !b.is_empty())
        .ok_or_else(|| VmError::InvalidTransaction(format!("{} is not frozen", module.name())))?;
    state.set_storage(&crate::native::SYSTEM_ADDRESS, &key, Vec::new());
    Ok((key, prior))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::staking;
    use crate::state_adapter::StateAdapter;

    const STAKE: u128 = 1_000_000;
    const ALICE: [u8; 20] = [0xa1; 20];
    const BOB: [u8; 20] = [0xb0; 20];

    /// A state with one bond held by the staking vault and an insurance
    /// pool whose record matches its balance.
    fn funded() -> StateAdapter {
        let mut state = StateAdapter::new();
        staking::add_bond(&mut state, &ALICE, STAKE, 0).unwrap();
        let vault = crate::native::staking_vault_address();
        state.set_balance(&vault, STAKE);
        let pool = crate::native::insurance::pool_address();
        state.set_balance(pool.as_bytes(), 500);
        crate::native::insurance::note_credit(
            &mut state,
            500,
            crate::native::insurance::PoolSource::Fees,
            &mut Vec::new(),
        )
        .unwrap();
        state.set_balance(&BOB, 1_000);
        state
    }

    #[test]
    fn a_block_whose_vaults_cover_what_they_owe_freezes_nothing() {
        let mut state = funded();
        assert!(check_block(&mut state).is_empty());
        for m in GuardedModule::ALL {
            assert!(require_unfrozen(&state, m).is_ok(), "{}", m.name());
        }
    }

    #[test]
    fn a_forced_value_leak_freezes_only_its_module() {
        let mut state = funded();
        // A planted bug in the staking module pays out of the vault without
        // touching any bond: supply is conserved, the vault no longer covers
        // what it owes.
        let vault = crate::native::staking_vault_address();
        state.set_balance(&vault, STAKE - 250_000);
        state.set_balance(&BOB, 1_000 + 250_000);

        let frozen_now = check_block(&mut state);
        assert_eq!(
            frozen_now,
            vec![(
                GuardedModule::Staking,
                ModuleFreeze {
                    held: STAKE - 250_000,
                    owed: STAKE
                }
            )],
            "the leak was not caught in the block it happened"
        );
        // Staking refuses everything that would move value.
        assert!(staking::add_bond(&mut state, &BOB, 10, 0).is_err());
        assert!(staking::begin_unbonding(&mut state, &ALICE, 0).is_err());
        assert!(staking::withdraw_unbonded(&mut state, &ALICE, i64::MAX).is_err());
        // Every other module keeps working.
        assert!(require_unfrozen(&state, GuardedModule::Insurance).is_ok());
        crate::native::insurance::note_credit(
            &mut state,
            0,
            crate::native::insurance::PoolSource::Fees,
            &mut Vec::new(),
        )
        .unwrap();
        // The leak is bounded by the one block: the vault cannot be drained
        // further through the module.
        assert_eq!(state.get_balance(&vault), STAKE - 250_000);
        // A later block does not freeze it twice, nor freeze anything else.
        assert!(check_block(&mut state).is_empty());
    }

    #[test]
    fn a_lifted_freeze_returns_while_the_vault_is_short_and_stays_off_once_restored() {
        let mut state = funded();
        let vault = crate::native::staking_vault_address();
        state.set_balance(&vault, STAKE - 1);
        assert_eq!(check_block(&mut state).len(), 1);
        lift(&mut state, GuardedModule::Staking).unwrap();
        assert!(require_unfrozen(&state, GuardedModule::Staking).is_ok());
        // Still short: frozen again at the end of the next block.
        assert_eq!(check_block(&mut state).len(), 1);
        // Governance restores the vault, then lifts.
        state.set_balance(&vault, STAKE);
        lift(&mut state, GuardedModule::Staking).unwrap();
        assert!(check_block(&mut state).is_empty());
        staking::add_bond(&mut state, &BOB, 10, 0).unwrap();
        assert!(
            lift(&mut state, GuardedModule::Staking).is_err(),
            "lifted a freeze that is not there"
        );
    }

    #[test]
    fn a_leak_from_the_insurance_pool_freezes_insurance_only() {
        let mut state = funded();
        let pool = crate::native::insurance::pool_address();
        state.set_balance(pool.as_bytes(), 100);
        let frozen_now = check_block(&mut state);
        assert_eq!(frozen_now.len(), 1);
        assert_eq!(frozen_now[0].0, GuardedModule::Insurance);
        assert!(require_unfrozen(&state, GuardedModule::Staking).is_ok());
        staking::add_bond(&mut state, &BOB, 10, 0).unwrap();
    }
}
