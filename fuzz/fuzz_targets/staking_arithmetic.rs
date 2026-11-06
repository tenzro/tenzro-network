//! Fuzzes validator staking arithmetic with attacker-chosen u128 amounts,
//! times and checkpoint indexes: bonding, unbonding, withdrawal and the
//! correlated equivocation slash, in any order, over a few accounts.
//!
//! Properties:
//! - no operation panics; overflow is a typed error;
//! - after every operation that succeeds, the recorded total bonded stake is
//!   the sum of the accounts' bonds, and the vault owes at least that much;
//! - the correlated slash rate never exceeds 100%.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_vm::StateAdapter;
use tenzro_vm::native::{
    add_bond, begin_unbonding, bonded_stake_of, correlated_slash_bps, slash_for_equivocation,
    total_bonded_stake, vault_liabilities, withdraw_unbonded,
};

const ACCOUNTS: u8 = 4;

fuzz_target!(|ops: Vec<(u8, u8, u128, u64)>| {
    let mut state = StateAdapter::default();
    for (op, who, amount, at) in ops.into_iter().take(64) {
        let addr = [who % ACCOUNTS + 1; 20];
        let now_ms = (at % (1 << 50)) as i64;
        let ok = match op % 4 {
            0 => add_bond(&mut state, &addr, amount, now_ms).is_ok(),
            1 => begin_unbonding(&mut state, &addr, now_ms).is_ok(),
            2 => withdraw_unbonded(&mut state, &addr, now_ms).is_ok(),
            _ => slash_for_equivocation(&mut state, &addr, at, &mut Vec::new()).is_ok(),
        };
        // A failed operation is a failed transaction, whose writes the
        // executor discards; only a state reached by successes is checked.
        if !ok {
            return;
        }
        let sum = (1..=ACCOUNTS).fold(0u128, |t, i| t.saturating_add(bonded_stake_of(&state, &[i; 20])));
        assert_eq!(total_bonded_stake(&state), sum);
        assert!(vault_liabilities(&state) >= sum);
        let bps = correlated_slash_bps(amount, sum.max(1), (at % 10_001) as u32, (at % 101) as u32);
        assert!(bps <= 10_000);
    }
});
