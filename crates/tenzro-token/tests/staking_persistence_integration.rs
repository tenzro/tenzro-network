//! Integration test for staking persistence
//!
//! This test demonstrates the full lifecycle of persistent staking:
//! 1. Create a staking manager with storage
//! 2. Perform staking operations (stake, unstake, slash)
//! 3. Restart the system (drop and recreate manager)
//! 4. Verify all state was persisted and restored correctly

use std::sync::Arc;
use tenzro_storage::RocksDbStore;
use tenzro_token::{StakingManager, StakeStatus, DEFAULT_MIN_STAKE};
use tenzro_types::primitives::Address;
use tenzro_types::token::ProviderType;

#[test]
fn test_complete_staking_lifecycle_with_persistence() {
    // Create a temporary directory for this test
    let temp_dir = std::env::temp_dir().join(format!(
        "tenzro_integration_test_{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Phase 1: Initial setup and staking
    {
        println!("Phase 1: Setting up staking with persistence");
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage);

        // Create three validators with different stakes
        let validator1 = Address::new([1u8; 32]);
        let validator2 = Address::new([2u8; 32]);
        let validator3 = Address::new([3u8; 32]);

        let stake1 = DEFAULT_MIN_STAKE;
        let stake2 = DEFAULT_MIN_STAKE * 2;
        let stake3 = DEFAULT_MIN_STAKE * 3;

        manager
            .stake(validator1, stake1, ProviderType::Validator)
            .unwrap();
        manager
            .stake(validator2, stake2, ProviderType::Validator)
            .unwrap();
        manager
            .stake(validator3, stake3, ProviderType::TeeProvider)
            .unwrap();

        // Verify initial state
        assert_eq!(manager.get_all_stakes().len(), 3);
        assert_eq!(
            manager.get_total_staked(ProviderType::Validator),
            stake1 + stake2
        );
        assert_eq!(manager.get_total_staked(ProviderType::TeeProvider), stake3);

        println!("  ✓ Created 3 stakes");
        println!("  ✓ Total validator stake: {}", stake1 + stake2);
        println!("  ✓ Total TEE provider stake: {}", stake3);
    } // Manager dropped here, simulating node shutdown

    // Phase 2: Restart and verify persistence
    {
        println!("\nPhase 2: Restarting node and verifying persistence");
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage);

        // Verify all stakes were loaded
        let all_stakes = manager.get_all_stakes();
        assert_eq!(all_stakes.len(), 3);
        println!("  ✓ Loaded {} stakes from storage", all_stakes.len());

        // Verify totals were recomputed
        let stake1 = DEFAULT_MIN_STAKE;
        let stake2 = DEFAULT_MIN_STAKE * 2;
        let stake3 = DEFAULT_MIN_STAKE * 3;

        assert_eq!(
            manager.get_total_staked(ProviderType::Validator),
            stake1 + stake2
        );
        assert_eq!(manager.get_total_staked(ProviderType::TeeProvider), stake3);
        println!("  ✓ Total stakes verified");

        // Perform operations on loaded state
        let validator2 = Address::new([2u8; 32]);
        manager.unstake(&validator2).unwrap();
        println!("  ✓ Initiated unstaking for validator2");

        // Slash a validator
        let validator1 = Address::new([1u8; 32]);
        let slasher = Address::new([99u8; 32]);
        let slash_amount = DEFAULT_MIN_STAKE / 10; // 10%
        manager
            .slash(
                &validator1,
                slash_amount,
                "Test misbehavior".to_string(),
                slasher,
            )
            .unwrap();
        println!("  ✓ Slashed validator1 by 10%");
    } // Manager dropped here again

    // Phase 3: Final verification
    {
        println!("\nPhase 3: Final restart and verification");
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage);

        // Verify validator2 is unbonding
        let validator2 = Address::new([2u8; 32]);
        let stake2_info = manager.get_stake(&validator2).unwrap();
        assert_eq!(stake2_info.status, StakeStatus::Unbonding);
        assert!(stake2_info.unbonding_at.is_some());
        println!("  ✓ Validator2 unbonding state persisted");

        // Verify validator1 was slashed
        let validator1 = Address::new([1u8; 32]);
        let stake1_info = manager.get_stake(&validator1).unwrap();
        assert_eq!(
            stake1_info.amount,
            DEFAULT_MIN_STAKE - (DEFAULT_MIN_STAKE / 10)
        );
        assert_eq!(stake1_info.slashing_history.len(), 1);
        assert_eq!(stake1_info.slashing_history[0].reason, "Test misbehavior");
        println!("  ✓ Validator1 slash history persisted");

        // Verify final totals
        let expected_validator_total =
            DEFAULT_MIN_STAKE - (DEFAULT_MIN_STAKE / 10) + DEFAULT_MIN_STAKE * 2;
        assert_eq!(
            manager.get_total_staked(ProviderType::Validator),
            expected_validator_total
        );
        println!("  ✓ Final totals correct");

        println!("\n✓ All persistence tests passed!");
    }

    // Clean up
    std::fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_config_persistence_across_restarts() {
    let temp_dir = std::env::temp_dir().join(format!(
        "tenzro_config_test_{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // Set custom config
    {
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage);

        let custom_min_stake = DEFAULT_MIN_STAKE * 5;
        let custom_unbonding = 14 * 24 * 60 * 60 * 1000; // 14 days

        manager.set_min_stake(custom_min_stake);
        manager.set_unbonding_period(custom_unbonding);

        println!("Set custom config:");
        println!("  Min stake: {}", custom_min_stake);
        println!("  Unbonding period: {} ms", custom_unbonding);
    }

    // Verify config persisted
    {
        let storage = Arc::new(RocksDbStore::open_default(&temp_dir).unwrap());
        let manager = StakingManager::with_storage(storage);

        // The config should be loaded from storage
        let staker = Address::new([1u8; 32]);
        let result = manager.stake(staker, DEFAULT_MIN_STAKE, ProviderType::Validator);

        // Should fail because min stake is now 5x default
        assert!(result.is_err());
        println!("✓ Min stake requirement persisted and enforced");
    }

    // Clean up
    std::fs::remove_dir_all(&temp_dir).ok();
}
