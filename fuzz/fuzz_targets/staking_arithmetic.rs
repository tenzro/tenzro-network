//! Fuzzes staking and liquid-staking arithmetic with attacker-chosen
//! u128 amounts across the full range.
//!
//! Properties:
//! - `StakingManager::{stake, slash, unstake}` return typed errors on
//!   overflow/underflow (checked_add / checked_sub) — never panic.
//! - `LiquidStakingPool::{deposit, request_withdrawal, exchange_rate,
//!   distribute_rewards}` hold the quotient/remainder decomposition
//!   contract: no multiplication of two 10^18-scaled values may
//!   overflow or panic for any input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_token::liquid_staking::{LiquidStakingConfig, LiquidStakingPool};
use tenzro_token::staking::StakingManager;
use tenzro_types::primitives::Address;
use tenzro_types::token::ProviderType;

fuzz_target!(|input: (u128, u128, u128, [u8; 32], [u8; 32])| {
    let (amount_a, amount_b, amount_c, s1, s2) = input;
    let staker = Address::new(s1);
    let other = Address::new(s2);

    let manager = StakingManager::new();
    let _ = manager.stake(staker, amount_a, ProviderType::Validator);
    let _ = manager.slash(&staker, amount_b, "fuzz".to_string(), other);
    let _ = manager.unstake(&staker);

    let pool = LiquidStakingPool::new(LiquidStakingConfig::default())
        .expect("default liquid staking config is valid");
    let _ = pool.exchange_rate();
    if pool.deposit(staker, amount_a).is_ok() {
        let _ = pool.request_withdrawal(staker, amount_c);
    }
    let _ = pool.distribute_rewards(amount_b);
    let _ = pool.exchange_rate();
});
