//! Token ledger: conservation, frozen <= balance, supply <= max, no overflow.
//!
//! The ledger operations in `token_ledger` read and write chain state; their
//! arithmetic is the helpers proved here, composed exactly as `mint`,
//! `burn`, `transfer`, `forced_transfer` and `set_frozen` compose them. The
//! model holds two accounts, which covers a transfer to a different account
//! and to oneself.

use crate::token_ledger::{
    freeze_within, frozen_after, initial_supply_within, spendable, supply_after_mint,
    within_balance_ceiling,
};

#[derive(Clone, Copy)]
struct Ledger {
    bal: [u128; 2],
    frozen: [u128; 2],
    supply: u128,
    max: Option<u128>,
}

impl Ledger {
    fn any() -> Self {
        Self {
            bal: kani::any(),
            frozen: kani::any(),
            supply: kani::any(),
            max: kani::any(),
        }
    }

    /// Conservation, frozen within balance, supply within the maximum.
    fn holds(&self) -> bool {
        self.bal[0].checked_add(self.bal[1]) == Some(self.supply)
            && self.frozen[0] <= self.bal[0]
            && self.frozen[1] <= self.bal[1]
            && self.max.is_none_or(|m| self.supply <= m)
    }

    /// `move_balance`: debit, then credit the recipient as read after the
    /// debit, so a transfer to oneself nets to zero.
    fn move_balance(&mut self, from: usize, to: usize, amount: u128) -> Option<()> {
        self.bal[from] = self.bal[from].checked_sub(amount)?;
        self.bal[to] = self.bal[to].checked_add(amount)?;
        Some(())
    }

    fn mint(&mut self, to: usize, amount: u128) -> Option<()> {
        self.supply = supply_after_mint(self.supply, self.max, amount)?;
        self.bal[to] = self.bal[to].checked_add(amount)?;
        Some(())
    }

    /// A holder burn spends only the part that is not frozen.
    fn burn(&mut self, from: usize, amount: u128) -> Option<()> {
        if spendable(self.bal[from], self.frozen[from]) < amount {
            return None;
        }
        self.bal[from] -= amount;
        self.supply = self.supply.saturating_sub(amount);
        Some(())
    }

    /// A holder transfer: `can_transfer` refuses one reaching into the
    /// frozen part.
    fn transfer(&mut self, from: usize, to: usize, amount: u128) -> Option<()> {
        if self.bal[from] >= amount && spendable(self.bal[from], self.frozen[from]) < amount {
            return None;
        }
        self.move_balance(from, to, amount)
    }

    fn forced_transfer(&mut self, from: usize, to: usize, amount: u128) -> Option<()> {
        self.move_balance(from, to, amount)?;
        self.frozen[from] = frozen_after(self.frozen[from], self.bal[from]);
        Some(())
    }

    fn set_frozen(&mut self, who: usize, amount: u128) -> Option<()> {
        self.frozen[who] = freeze_within(amount, self.bal[who])?;
        Some(())
    }
}

/// Any one ledger operation, successful or refused, keeps every invariant.
/// A refused operation leaves the state as it was (the transaction reverts).
#[kani::proof]
fn every_ledger_operation_keeps_the_invariants() {
    let before = Ledger::any();
    kani::assume(before.holds());
    let mut after = before;
    let a: usize = if kani::any() { 1 } else { 0 };
    let b: usize = if kani::any() { 1 } else { 0 };
    let amount: u128 = kani::any();
    let op: u8 = kani::any();
    let applied = match op % 5 {
        0 => after.mint(a, amount),
        1 => after.burn(a, amount),
        2 => after.transfer(a, b, amount),
        3 => after.forced_transfer(a, b, amount),
        _ => after.set_frozen(a, amount),
    };
    let end = if applied.is_some() { after } else { before };
    assert!(end.holds());
}

/// Only an issuer action moves frozen value: a holder burn or transfer that
/// succeeds leaves the holder's freeze in place and still covered.
#[kani::proof]
fn a_holder_never_spends_the_frozen_part() {
    let before = Ledger::any();
    kani::assume(before.holds());
    let mut after = before;
    let b: usize = if kani::any() { 1 } else { 0 };
    let amount: u128 = kani::any();
    let applied = if kani::any() {
        after.burn(0, amount)
    } else {
        after.transfer(0, b, amount)
    };
    if applied.is_some() {
        assert!(after.frozen[0] == before.frozen[0]);
        assert!(after.bal[0] >= after.frozen[0]);
    }
}

/// A mint never takes the supply past the maximum or wraps it.
#[kani::proof]
fn a_mint_stays_within_the_maximum_supply() {
    let (total, max, amount): (u128, Option<u128>, u128) = kani::any();
    if let Some(s) = supply_after_mint(total, max, amount) {
        assert!(s >= total && s - total == amount);
        assert!(max.is_none_or(|m| s <= m));
    } else {
        assert!(total.checked_add(amount).is_none() || max.is_some_and(|m| total + amount > m));
    }
}

/// A token is created only with an initial supply within its maximum, and
/// every initial supply within it is admitted.
#[kani::proof]
fn a_token_is_created_only_within_its_maximum_supply() {
    let (total, max): (u128, Option<u128>) = kani::any();
    let admitted = initial_supply_within(total, max);
    match max {
        Some(m) => assert!(admitted == (total <= m)),
        None => assert!(admitted),
    }
}

/// A holder ceiling of `bps` basis points of the supply admits a credit only
/// when the balance it leaves is within that share, and admits every such
/// credit; a balance that would wrap is never admitted.
#[kani::proof]
fn a_credit_never_passes_the_holder_ceiling() {
    let (held, amount, supply): (u128, u128, u128) = kani::any();
    let bps: u16 = kani::any();
    kani::assume(bps <= 10_000);
    let ceiling = supply.saturating_mul(u128::from(bps)) / 10_000;
    let admitted = within_balance_ceiling(held, amount, supply, bps);
    match held.checked_add(amount) {
        Some(after) => assert!(admitted == (after <= ceiling)),
        None => assert!(!admitted),
    }
}

/// The spendable part and the effective freeze add up to the balance.
#[kani::proof]
fn the_spendable_part_and_the_freeze_add_up_to_the_balance() {
    let (held, frozen): (u128, u128) = kani::any();
    let free = spendable(held, frozen);
    assert!(free <= held);
    assert!(free + frozen.min(held) == held);
    assert!(frozen_after(frozen, held) <= held);
}
