//! Validators and the per-epoch validator set.

use serde::{Deserialize, Serialize};
use tenzro_types::primitives::{Address, Timestamp};

use crate::error::{ConsensusError, Result};
use crate::validator_key::ValidatorPublicKey;

/// Maximum normalized voting weight any single validator may hold, in basis
/// points of the active set's total weight (anti-domination cap). Excess
/// above this cap is redistributed proportionally across the uncapped
/// validators. 1,000 bps = 10%.
pub const MAX_VALIDATOR_WEIGHT_BPS: u32 = 1_000;

/// A validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// The validator's account address.
    pub address: Address,
    /// The validator's hardware-held composite key.
    pub public_key: ValidatorPublicKey,
    /// The node's Ed25519 key, derived from its hardware. It signs the
    /// node's peer bindings and availability attestations, and it signed the
    /// validator's registration. It is not a network address: where to
    /// reach the validator is a per-boot endpoint it announces signed by
    /// `public_key` (see [`crate::announce`]).
    pub node_key: [u8; 32],
    /// Bonded stake.
    pub stake: u128,
    /// Lifecycle status.
    pub status: ValidatorStatus,
    /// Registration time.
    pub registered_at: Timestamp,
}

impl ValidatorInfo {
    /// An active validator.
    pub fn new(
        address: Address,
        public_key: ValidatorPublicKey,
        node_key: [u8; 32],
        stake: u128,
    ) -> Self {
        Self {
            address,
            public_key,
            node_key,
            stake,
            status: ValidatorStatus::Active,
            registered_at: Timestamp::now(),
        }
    }

    /// Whether the validator participates.
    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    /// Stake counted toward voting weight: zero unless active.
    pub fn voting_power(&self) -> u128 {
        if self.is_active() { self.stake } else { 0 }
    }
}

/// Validator operational status, as reflected from the validator registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Active and participating in consensus
    Active,
    /// Temporarily inactive
    Inactive,
    /// Jailed due to misbehavior
    Jailed,
    /// Unbonding (pending removal)
    Unbonding,
}

/// The validators of one epoch, in canonical order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// Epoch number.
    pub epoch: u64,
    validators: Vec<ValidatorInfo>,
    total_stake: u128,
    /// Epoch start time.
    pub epoch_start: Timestamp,
}

impl ValidatorSet {
    /// A validator set for `epoch`. Refuses an empty set, a duplicate
    /// address or key, and a malformed key.
    pub fn new(epoch: u64, validators: Vec<ValidatorInfo>) -> Result<Self> {
        if validators.is_empty() {
            return Err(ConsensusError::InvalidValidatorSet(
                "validator set cannot be empty".to_string(),
            ));
        }
        let mut addresses = std::collections::HashSet::new();
        let mut keys = std::collections::HashSet::new();
        for v in &validators {
            v.public_key.check_well_formed()?;
            if !addresses.insert(v.address) {
                return Err(ConsensusError::InvalidValidatorSet(format!(
                    "duplicate validator address {}",
                    v.address
                )));
            }
            if !keys.insert(v.public_key.fingerprint()) {
                return Err(ConsensusError::InvalidValidatorSet(
                    "two validators share one key".to_string(),
                ));
            }
        }
        let total_stake = validators.iter().map(|v| v.voting_power()).sum();
        Ok(Self {
            epoch,
            validators,
            total_stake,
            epoch_start: Timestamp::now(),
        })
    }

    /// The validator at `index`.
    pub fn get(&self, index: usize) -> Option<&ValidatorInfo> {
        self.validators.get(index)
    }

    /// The validator with `address`.
    pub fn get_by_address(&self, address: &Address) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| &v.address == address)
    }

    /// The canonical index of `address`, stable for one epoch.
    pub fn index_of(&self, address: &Address) -> Option<usize> {
        self.validators.iter().position(|v| &v.address == address)
    }

    /// The validators in canonical order.
    pub fn active_validators(&self) -> &[ValidatorInfo] {
        &self.validators
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Iterates the validators in canonical order.
    pub fn iter(&self) -> std::slice::Iter<'_, ValidatorInfo> {
        self.validators.iter()
    }

    /// Total active stake.
    pub fn total_stake(&self) -> u128 {
        self.total_stake
    }

    /// Whether `address` is in the set.
    pub fn is_validator(&self, address: &Address) -> bool {
        self.get_by_address(address).is_some()
    }

    /// Per-validator normalized voting power, in canonical order: stake,
    /// capped at [`MAX_VALIDATOR_WEIGHT_BPS`] of the total with the excess
    /// spread over the uncapped validators in proportion to their stake, so
    /// that none of them is lifted past the cap. Integer math, so every node
    /// computes the same weights; the weights add up to the total less a
    /// rounding remainder below one per validator.
    pub fn normalized_weights(&self) -> Vec<u128> {
        let raw: Vec<u128> = self.validators.iter().map(|v| v.voting_power()).collect();
        let total: u128 = raw.iter().sum();
        if total == 0 {
            return raw;
        }
        let cap = total.saturating_mul(MAX_VALIDATOR_WEIGHT_BPS as u128) / 10_000u128;
        // The cap cannot hold for every validator of a set too small for it
        // (fewer than 10 validators under a 10% cap); weights stay uncapped.
        if cap == 0 || (raw.len() as u128).saturating_mul(cap) < total {
            return raw;
        }
        // Water-filling: the k largest stakes are capped once spreading the
        // rest of the total over the others in proportion would lift the
        // next largest past the cap.
        let mut order: Vec<usize> = (0..raw.len()).collect();
        order.sort_by(|a, b| raw[*b].cmp(&raw[*a]).then(a.cmp(b)));
        let mut capped = 0usize;
        let mut rest = total;
        let mut rest_raw = total;
        while capped < order.len() {
            let next = raw[order[capped]];
            // Next is capped when next * rest / rest_raw > cap.
            if rest_raw == 0 || wide_mul(next, rest) <= wide_mul(cap, rest_raw) {
                break;
            }
            rest -= cap;
            rest_raw -= next;
            capped += 1;
        }
        let mut weights = raw.clone();
        for (rank, i) in order.iter().enumerate() {
            weights[*i] = if rank < capped {
                cap
            } else {
                mul_div(raw[*i], rest, rest_raw)
            };
        }
        weights
    }
}

/// `a * b` as a 256-bit `(high, low)` pair.
fn wide_mul(a: u128, b: u128) -> (u128, u128) {
    let (a1, a0) = (a >> 64, a & u128::from(u64::MAX));
    let (b1, b0) = (b >> 64, b & u128::from(u64::MAX));
    let lo = a0 * b0;
    let mid1 = a0 * b1;
    let mid2 = a1 * b0;
    let hi = a1 * b1;
    let (mid, mid_carry) = mid1.overflowing_add(mid2);
    let (low, low_carry) = lo.overflowing_add(mid << 64);
    let high = hi + (mid >> 64) + (u128::from(mid_carry) << 64) + u128::from(low_carry);
    (high, low)
}

/// `floor(a * b / c)` for a result that fits 128 bits, without overflow.
fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    let (high, low) = wide_mul(a, b);
    let mut rem: u128 = 0;
    let mut q: u128 = 0;
    for i in (0..256).rev() {
        let bit = if i >= 128 {
            (high >> (i - 128)) & 1
        } else {
            (low >> i) & 1
        };
        let carry = rem >> 127;
        rem = (rem << 1) | bit;
        q <<= 1;
        if carry == 1 || rem >= c {
            rem = rem.wrapping_sub(c);
            q |= 1;
        }
    }
    q
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::validator_key::ValidatorSigner;
    use crate::validator_key::test_signer::SoftwareTestSigner;

    /// `n` validators with equal stake and their test signers.
    pub(crate) fn validators(
        n: usize,
        stake: u128,
    ) -> (Vec<ValidatorInfo>, Vec<SoftwareTestSigner>) {
        let signers: Vec<SoftwareTestSigner> =
            (0..n as u64).map(SoftwareTestSigner::from_seed).collect();
        let infos = signers
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut a = [0u8; 32];
                a[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                ValidatorInfo::new(Address::new(a), s.public_key().clone(), a, stake)
            })
            .collect();
        (infos, signers)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::validators;
    use super::*;

    #[test]
    fn a_set_with_a_duplicate_address_or_key_is_refused() {
        let (mut v, _) = validators(3, 10);
        v[1].address = v[0].address;
        assert!(ValidatorSet::new(0, v).is_err());
        let (mut v, _) = validators(3, 10);
        v[2].public_key = v[0].public_key.clone();
        assert!(ValidatorSet::new(0, v).is_err());
    }

    /// Redistributing a capped validator's excess never lifts another
    /// validator past the cap, and the weights still add up to the total
    /// less a rounding remainder of at most one per validator.
    #[test]
    fn redistribution_never_lifts_a_validator_past_the_cap() {
        let (mut v, _) = validators(19, 5);
        v[0].stake = 100;
        v[1].stake = 15;
        let set = ValidatorSet::new(0, v).unwrap();
        let w = set.normalized_weights();
        let total: u128 = set.iter().map(|v| v.voting_power()).sum();
        let cap = total * MAX_VALIDATOR_WEIGHT_BPS as u128 / 10_000;
        assert!(w.iter().all(|x| *x <= cap), "{w:?} above {cap}");
        let sum: u128 = w.iter().sum();
        assert!(
            sum <= total && total - sum <= w.len() as u128,
            "{sum} of {total}"
        );

        // Stakes in wei: the shares are computed without overflow.
        let (mut v, _) = validators(19, 5 * 10u128.pow(27));
        v[0].stake = 100 * 10u128.pow(27);
        v[1].stake = 15 * 10u128.pow(27);
        let set = ValidatorSet::new(0, v).unwrap();
        let w = set.normalized_weights();
        let total: u128 = set.iter().map(|v| v.voting_power()).sum();
        let cap = total * MAX_VALIDATOR_WEIGHT_BPS as u128 / 10_000;
        assert!(w.iter().all(|x| *x <= cap));
        let sum: u128 = w.iter().sum();
        assert!(sum <= total && total - sum <= w.len() as u128);
    }

    #[test]
    fn one_validator_cannot_exceed_the_weight_cap() {
        let (mut v, _) = validators(20, 10);
        v[0].stake = 1_000;
        let set = ValidatorSet::new(0, v).unwrap();
        let w = set.normalized_weights();
        let total: u128 = set.iter().map(|v| v.stake).sum();
        assert!(w[0] <= total / 10);
    }
}
