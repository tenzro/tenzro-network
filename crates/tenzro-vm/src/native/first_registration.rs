//! A first registration that pays no fee.
//!
//! A new machine's account holds nothing, and registering its identity and
//! enrolling its first ML-DSA-65 key both cost gas, so without help it can
//! never join a network that requires a registered identity. Once [`GATE`]
//! is live, a registration (`RegisterIdentity` or an account key enrolment)
//! from an account that cannot pay its fee owes none, within three bounds:
//!
//! - every waived registration that executes counts, kept or reverted; one
//!   the runtime or the executor refuses (a bad signature, a payload that
//!   does not parse, a proof that does not verify) is dropped from the block
//!   and counts against nothing;
//! - an account has at most [`WAIVERS_PER_ACCOUNT`] waived transactions,
//!   its identity's registration and its first key enrolment;
//! - a block of an epoch waives only while the epoch's waivers are below
//!   [`WAIVERS_PER_EPOCH_PARAM`].
//!
//! A registration executes only with the identity's own proof (a machine's
//! TPM activation and quote, a person's passkey), so the waivers an epoch
//! spends go to identities with hardware behind them; the epoch bound caps
//! what any rarer revert after that could spend.
//!
//! The fee a sender "cannot pay" is the chain's: the block base fee on its
//! gas limit (at most the default gas limit), never the price or the limit
//! the sender declares, so a funded account cannot make itself eligible by
//! declaring a price it cannot afford.
//!
//! Known limit: free account creation with two waivers each means one actor
//! with many identities can spend an epoch's waivers, and honest newcomers
//! then pay that epoch. The epoch bound caps the subsidy; it does not make
//! its sharing fair. A pool holds the registrations it keeps for waived fees
//! to the waivers left ([`waiver_room`]), so a registration that fails after
//! it was pooled cannot be sent again without end.
//!
//! Dormant until governance sets [`GATE`].

use super::*;

/// The gate of the waiver: from its epoch a first registration from an
/// account that cannot pay pays no fee.
pub const GATE: &str = "feature.first_registration_free.activation_epoch";

/// How many registrations an epoch waives the fee of.
pub const WAIVERS_PER_EPOCH_PARAM: &str = "feature.first_registration_free.waivers_per_epoch";

/// How many waived transactions one account may have: its identity's
/// registration and its first key enrolment.
pub const WAIVERS_PER_ACCOUNT: u64 = 2;

fn epoch_slot(epoch: u64) -> String {
    format!("fee_waivers:epoch:{epoch}")
}

fn account_slot(account: &[u8]) -> String {
    format!("fee_waivers:account:{}", hex::encode(account))
}

fn read_count(state: &dyn VmState, slot: &str) -> u64 {
    state
        .get_storage(&SYSTEM_ADDRESS, slot.as_bytes())
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map_or(0, u64::from_be_bytes)
}

fn bump(state: &mut dyn VmState, slot: &str) {
    let next = read_count(state, slot).saturating_add(1);
    state.set_storage(
        &SYSTEM_ADDRESS,
        slot.as_bytes(),
        next.to_be_bytes().to_vec(),
    );
}

/// Whether `tx` is a registration.
fn is_registration(tx: &VmTransaction) -> bool {
    tx.vm_type == VmType::Tenzro
        && tx.data.len() >= 4
        && (tx.data[..4] == SELECTOR_IDENTITY_REGISTER
            || tx.data[..4] == crate::account_keys::SELECTOR_ACCOUNT_KEYS)
}

/// Whether `tx`, about to run in a block, owes no fee if it succeeds: a
/// registration, while the gate is live, from an account that cannot pay
/// the fee the chain asks for its gas, within the account's and the epoch's
/// bounds. Reads only chain state, so every validator decides alike.
pub fn waives(state: &dyn VmState, tx: &VmTransaction) -> bool {
    is_registration(tx) && waives_sender(state, &tx.from, tx.gas_limit)
}

/// The fee the chain asks of a registration with gas limit `gas_limit`: the
/// block base fee, the least price any transaction can pay, on the gas
/// limit, at most the default gas limit. Neither factor is the sender's own
/// choice: a funded account that declares an unaffordable price or an
/// enormous gas limit owes the same fee as one that does not.
fn asked_fee(state: &dyn VmState, gas_limit: u64) -> u128 {
    u128::from(gas_limit.min(crate::DEFAULT_GAS_LIMIT))
        .saturating_mul(crate::ledger::block_base_fee(state))
}

/// Whether a registration from `sender` with gas limit `gas_limit` owes
/// none: the gate is live, `sender` cannot pay the fee the chain asks, and
/// neither its own nor the epoch's bound is spent. What admission asks
/// before a registration reaches a block.
pub fn waives_sender(state: &dyn VmState, sender: &[u8], gas_limit: u64) -> bool {
    crate::feature_gate::is_live_now(state, GATE)
        && state.get_balance(sender) < asked_fee(state, gas_limit)
        && read_count(state, &account_slot(sender)) < WAIVERS_PER_ACCOUNT
        && read_count(state, &epoch_slot(params_epoch(state)))
            < network_param(state, WAIVERS_PER_EPOCH_PARAM)
}

/// How many more waivers `sender` and the epoch have: what a pool holds
/// the registrations it keeps for waived fees to, so it never keeps more
/// than the chain will waive.
pub fn waiver_room(state: &dyn VmState, sender: &[u8]) -> (u64, u64) {
    let account = WAIVERS_PER_ACCOUNT.saturating_sub(read_count(state, &account_slot(sender)));
    let epoch = network_param(state, WAIVERS_PER_EPOCH_PARAM)
        .saturating_sub(read_count(state, &epoch_slot(params_epoch(state))));
    (account, epoch)
}

/// Whether `tx` may run at gas price 0 because block execution waived its
/// fee: block execution runs a waived registration at price 0 and refuses
/// any other transaction below the base fee before it runs.
pub fn runs_waived(state: &dyn VmState, tx: &VmTransaction) -> bool {
    tx.gas_price == 0 && is_registration(tx) && crate::feature_gate::is_live_now(state, GATE)
}

/// Records that the waived `tx` executed, against its account's and its
/// epoch's bounds.
pub fn record(state: &mut dyn VmState, tx: &VmTransaction) {
    let epoch = params_epoch(state);
    bump(state, &account_slot(&tx.from));
    bump(state, &epoch_slot(epoch));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    const GAS_LIMIT: u64 = 100_000;
    const GAS_PRICE: u128 = 1_000_000_000;

    fn tx(from: u8, data: Vec<u8>) -> VmTransaction {
        VmTransaction::new(
            vec![from; 32],
            None,
            0,
            data,
            GAS_LIMIT,
            GAS_PRICE,
            0,
            VmType::Tenzro,
            1337,
        )
    }

    fn registration(from: u8) -> VmTransaction {
        tx(from, SELECTOR_IDENTITY_REGISTER.to_vec())
    }

    fn live(state: &mut StateAdapter, per_epoch: u64) {
        set_governed_param_for_test(state, GATE, 0);
        set_governed_param_for_test(state, WAIVERS_PER_EPOCH_PARAM, per_epoch);
    }

    #[test]
    fn nothing_is_waived_while_the_gate_is_dormant() {
        let state = StateAdapter::new();
        assert!(!waives(&state, &registration(1)));
    }

    #[test]
    fn only_a_registration_from_an_account_that_cannot_pay_is_waived() {
        let mut state = StateAdapter::new();
        live(&mut state, 8);
        assert!(waives(&state, &registration(1)));
        let enrolment = tx(1, crate::account_keys::SELECTOR_ACCOUNT_KEYS.to_vec());
        assert!(waives(&state, &enrolment));
        assert!(!waives(&state, &tx(1, Vec::new())), "not a registration");
        let fee = u128::from(GAS_LIMIT) * crate::ledger::block_base_fee(&state);
        assert!(fee > 0, "the chain asks a fee");
        state.set_balance(&[2; 32], fee);
        assert!(!waives(&state, &registration(2)), "it can pay");
        state.set_balance(&[3; 32], fee - 1);
        assert!(waives(&state, &registration(3)), "it is a unit short");
    }

    /// The price and the gas limit a sender declares do not decide whether
    /// it can pay: a funded account declaring a price it cannot afford, or a
    /// gas limit past the default, is not waived.
    #[test]
    fn what_a_sender_declares_does_not_make_it_unable_to_pay() {
        let mut state = StateAdapter::new();
        live(&mut state, 8);
        let base = crate::ledger::block_base_fee(&state);
        let funded = u128::from(GAS_LIMIT) * base;
        state.set_balance(&[4; 32], funded);
        let mut dear = registration(4);
        dear.gas_price = u128::MAX;
        assert!(!waives(&state, &dear), "a huge declared price");
        let mut huge_limit = registration(4);
        huge_limit.gas_limit = u64::MAX;
        state.set_balance(&[5; 32], u128::from(crate::DEFAULT_GAS_LIMIT) * base);
        huge_limit.from = vec![5; 32];
        assert!(!waives(&state, &huge_limit), "a huge declared gas limit");
    }

    #[test]
    fn the_room_left_is_the_account_and_the_epoch_remainder() {
        let mut state = StateAdapter::new();
        live(&mut state, 3);
        assert_eq!(waiver_room(&state, &[1; 32]), (WAIVERS_PER_ACCOUNT, 3));
        record(&mut state, &registration(1));
        assert_eq!(waiver_room(&state, &[1; 32]), (WAIVERS_PER_ACCOUNT - 1, 2));
        assert_eq!(waiver_room(&state, &[2; 32]), (WAIVERS_PER_ACCOUNT, 2));
    }

    /// In a block, a waived registration the executor refuses (here, one
    /// with no payload) is dropped: it charges its empty account nothing,
    /// collects no fee and spends no waiver.
    #[tokio::test]
    async fn a_refused_waived_registration_charges_nothing_and_spends_no_waiver() {
        let runtime = crate::MultiVmRuntime::new(VmConfig::default())
            .await
            .unwrap();
        let mut state = StateAdapter::new();
        live(&mut state, 1);
        let mut fees = crate::ledger::BlockFees::default();
        let outcome =
            crate::ledger::execute_in_block(&runtime, &mut state, &registration(1), 1, &mut fees)
                .await;
        assert!(
            matches!(outcome, crate::ledger::TxOutcome::Rejected(_)),
            "{outcome:?}"
        );
        assert_eq!(state.get_balance(&[1; 32]), 0);
        assert_eq!(state.get_nonce(&[1; 32]), 0);
        assert_eq!(fees.collected, 0);
        assert!(
            waives(&state, &registration(2)),
            "the epoch's one waiver is unspent"
        );
    }

    #[test]
    fn an_account_and_an_epoch_are_bounded() {
        let mut state = StateAdapter::new();
        live(&mut state, 3);
        let first = registration(1);
        record(&mut state, &first);
        assert!(
            waives(&state, &first),
            "the first key enrolment is still waived"
        );
        record(&mut state, &first);
        assert!(!waives(&state, &first), "an account has two waivers");

        record(&mut state, &registration(2));
        assert!(
            !waives(&state, &registration(3)),
            "the epoch spent its three"
        );
    }
}
