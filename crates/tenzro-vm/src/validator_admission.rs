//! Validator admission: who may bond as a validator and sit on a committee.
//!
//! The network starts with the genesis validators and is gated until the
//! network is stable; governance then opens it without a new genesis. The
//! rule is two governed things that already exist, both changed by an
//! ordinary governance proposal (24 hour voting period and 4 hour timelock on
//! the rebuilt network):
//!
//! - the mode, the governed parameter
//!   [`VALIDATOR_ADMISSION_APPROVAL_PARAM`] (`validator.admission_approval`,
//!   set by `parameter_change`): `1` closed, `0` open. The launch genesis
//!   file sets it to `1`. A state that carries no value reads the registry
//!   value, `0`: a release that adds the rule never locks out the validators
//!   a chain already has. Opening applies from the next epoch; closing is a
//!   tightening and applies after the governed tightening grace window.
//! - the admitted set, the approvals an `ApproveValidators` proposal writes
//!   (`approve` true adds the accounts, false takes them off). A genesis that
//!   seats validators writes an approval for each of them
//!   ([`genesis_entries`]), so the set starts as the genesis validators.
//!
//! In closed mode a `RegisterValidator` from an account that is not admitted
//! is refused with [`REFUSAL_CODE`], and the node never stages a non-admitted
//! account into a committee even when it holds a bond (see
//! `tenzro_node::validator_admission`). In open mode neither check applies and
//! the bond rules in force before this rule apply.
//!
//! Both are chain state, so every node reads the same mode and the same set.

use crate::error::{Result, VmError};
use crate::native::{
    VALIDATOR_ADMISSION_APPROVAL_PARAM, network_param, validator_approval_key, validator_approved,
};
use crate::traits::VmState;

/// The mode parameter: `1` closed, `0` open.
pub const MODE_KEY: &str = VALIDATOR_ADMISSION_APPROVAL_PARAM;

/// The machine-readable reason a refused validator receives.
pub const REFUSAL_CODE: &str = "validator_admission_closed";

/// The JSON-RPC error code the node returns for [`REFUSAL_CODE`].
pub const REFUSAL_RPC_CODE: i32 = -32060;

/// Where to ask to be admitted.
pub const CONTACT: &str = "team@tenzro.com";

/// Whether validator admission is closed in `state`.
pub fn is_closed(state: &dyn VmState) -> bool {
    network_param(state, MODE_KEY) != 0
}

/// Whether `account` is on the admitted set in `state`, whatever the mode.
pub fn is_on_admitted_set(state: &dyn VmState, account: &[u8]) -> bool {
    validator_approved(state, account)
}

/// Whether `account` may bond as a validator and sit on a committee now:
/// admission is open, or the account is on the admitted set.
pub fn is_admitted(state: &dyn VmState, account: &[u8]) -> bool {
    !is_closed(state) || is_on_admitted_set(state, account)
}

/// The refusal text for `account`, led by [`REFUSAL_CODE`].
pub fn refusal_message(account: &[u8]) -> String {
    format!(
        "{REFUSAL_CODE}: {} is not admitted as a validator. Validator admission is closed while \
         the network stabilises; run as an operator or a participant now. To ask to be admitted, \
         write to {CONTACT}",
        hex::encode(account)
    )
}

/// The account that registered the consensus key with `fingerprint`, if any.
pub fn account_of_key(state: &dyn VmState, fingerprint: &[u8; 32]) -> Option<Vec<u8>> {
    crate::native::staking::account_of_consensus_key(state, fingerprint)
}

/// Refuses `account` when admission is closed and it is not admitted.
pub fn check(state: &dyn VmState, account: &[u8]) -> Result<()> {
    if is_admitted(state, account) {
        Ok(())
    } else {
        Err(VmError::InvalidTransaction(refusal_message(account)))
    }
}

/// The state entries a genesis writes to admit `accounts`, as `(key, value)`
/// pairs in the system account's storage, like
/// [`crate::native::genesis_validator_bonds`]: one approval per account, the
/// record an enacted `ApproveValidators` writes.
pub fn genesis_entries(accounts: &[[u8; 32]]) -> Vec<(Vec<u8>, Vec<u8>)> {
    accounts
        .iter()
        .map(|a| (validator_approval_key(a).into_bytes(), vec![1u8]))
        .collect()
}
