//! Token ledger: conservation, supply <= max, a freeze only an issuer action
//! lowers, no overflow; and, until the final ERC-7943 rules are live
//! (`feature.erc7943_final`), frozen <= balance. Each proof names the side
//! of that gate it models.
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

    /// Conservation and supply within the maximum. Under the final rules a
    /// frozen amount is absolute and may exceed its balance; before them it
    /// stays within it.
    fn holds(&self, final_rules: bool) -> bool {
        self.bal[0].checked_add(self.bal[1]) == Some(self.supply)
            && self.max.is_none_or(|m| self.supply <= m)
            && (final_rules || (self.frozen[0] <= self.bal[0] && self.frozen[1] <= self.bal[1]))
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
        let held = self.bal[from];
        self.move_balance(from, to, amount)?;
        self.frozen[from] = frozen_after(self.frozen[from], held, self.bal[from]);
        Some(())
    }

    fn set_frozen(&mut self, who: usize, amount: u128, final_rules: bool) -> Option<()> {
        self.frozen[who] = if final_rules {
            amount
        } else {
            freeze_within(amount, self.bal[who])?
        };
        Some(())
    }
}

/// Any one ledger operation, successful or refused, keeps every invariant of
/// its side of the gate. A refused operation leaves the state as it was (the
/// transaction reverts).
fn any_operation_keeps_the_invariants(final_rules: bool) {
    let before = Ledger::any();
    kani::assume(before.holds(final_rules));
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
        _ => after.set_frozen(a, amount, final_rules),
    };
    let end = if applied.is_some() { after } else { before };
    assert!(end.holds(final_rules));
}

/// Under the final rules.
#[kani::proof]
fn every_ledger_operation_keeps_the_invariants() {
    any_operation_keeps_the_invariants(true);
}

/// Before the final rules: the same, with frozen <= balance kept by every
/// operation, the forced transfer included.
#[kani::proof]
fn every_ledger_operation_keeps_frozen_within_the_balance_before_the_final_rules() {
    any_operation_keeps_the_invariants(false);
}

/// Only an issuer action moves frozen value: a holder burn or transfer that
/// succeeds leaves the holder's freeze in place and still covered.
#[kani::proof]
fn a_holder_never_spends_the_frozen_part() {
    let final_rules: bool = kani::any();
    let before = Ledger::any();
    kani::assume(before.holds(final_rules));
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
        assert!(after.bal[0] >= before.frozen[0].min(before.bal[0]));
        if !final_rules {
            assert!(after.bal[0] >= after.frozen[0]);
        }
    }
}

/// A forced transfer lowers the freeze by exactly the part of the move that
/// reached past the spendable balance, and never raises it; one to the
/// holder itself changes nothing.
#[kani::proof]
fn a_forced_transfer_takes_from_the_freeze_only_what_it_must() {
    let before = Ledger::any();
    kani::assume(before.holds(true));
    let mut after = before;
    let b: usize = if kani::any() { 1 } else { 0 };
    let amount: u128 = kani::any();
    if after.forced_transfer(0, b, amount).is_some() {
        let free = spendable(before.bal[0], before.frozen[0]);
        if b == 0 {
            assert!(after.frozen[0] == before.frozen[0]);
        } else {
            assert!(after.frozen[0] == before.frozen[0] - amount.saturating_sub(free));
        }
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
}
