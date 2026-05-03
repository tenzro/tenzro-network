//! Portfolio rebalancer agent walkthrough
//!
//! Builds an autonomous rebalancing agent that:
//!
//!   1. Provisions a human controller identity via TDIP
//!   2. Provisions a machine identity under the human, with a fine-grained
//!      delegation scope (max trade size, allowed operations, daily cap)
//!   3. Pre-installs three "asset price oracle" contracts on a Tenzro EVM
//!      state adapter, each with an EVM runtime that records the latest
//!      price into storage slot 0
//!   4. Reads target allocations vs. current allocations from a portfolio
//!      definition, computes drift, and submits real EVM trade transactions
//!      whose calldata is the target weight for that asset
//!   5. Verifies that every trade was authorised by the delegation scope
//!      *before* dispatching it through the EVM, so the agent cannot
//!      exceed its daily spending cap or invoke disallowed operations
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example portfolio_rebalancer -p tenzro-node
//! ```

use std::sync::Arc;

use tenzro_crypto::keys::{KeyPair, KeyType};

use tenzro_identity::{DelegationScope, IdentityRegistry, TimeBound, WalletBinder};
use tenzro_types::identity::KycTier;

use tenzro_vm::{
    EvmExecutor, GasOracle, PrecompileRegistry, StateAdapter, VmConfig, VmState, VmTransaction,
    VmType,
};

const TRADING_RUNTIME_CODE: &[u8] = &[
    0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00,
];

/// 1 TNZO in base units (10^18).
const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

#[derive(Debug, Clone, Copy)]
struct AssetTarget {
    /// 20-byte EVM address that hosts the asset's price oracle runtime.
    address_byte: u8,
    /// Symbol used for printing.
    symbol: &'static str,
    /// Current basis-points weight in the portfolio (out of 10_000).
    current_bps: u16,
    /// Target basis-points weight after rebalance.
    target_bps: u16,
    /// Latest oracle price in TNZO base units.
    price_base: u128,
}

fn fresh_evm_executor() -> EvmExecutor {
    EvmExecutor::new(
        VmConfig::default(),
        Arc::new(GasOracle::new()),
        Arc::new(PrecompileRegistry::new()),
    )
    .expect("EvmExecutor::new should succeed")
}

fn mk_evm_address(byte: u8) -> Vec<u8> {
    vec![byte; 20]
}

fn fresh_state() -> StateAdapter {
    StateAdapter::new()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Tenzro portfolio rebalancer walkthrough");
    println!("=======================================");

    // ------------------------------------------------------------------
    // Step 1: provision the human controller via TDIP
    // ------------------------------------------------------------------
    println!("\n=== Step 1: Provision human controller identity ===");
    let registry = IdentityRegistry::with_wallet_binder(Arc::new(WalletBinder::new()?));

    let human_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let human_pubkey = human_keypair.public_key().as_bytes().to_vec();
    let human = registry
        .register_human_with_fee(
            human_pubkey,
            "Portfolio Owner".to_string(),
            KycTier::Enhanced,
        )
        .await?
        .identity;
    let human_did = human.did_string();
    println!("→ controller DID: {}", human_did);
    println!("  wallet         : {}", human.wallet_id);

    // ------------------------------------------------------------------
    // Step 2: provision the machine agent with a delegation scope
    // ------------------------------------------------------------------
    println!("\n=== Step 2: Provision rebalancer agent under controller ===");
    let agent_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let agent_pubkey = agent_keypair.public_key().as_bytes().to_vec();

    let now = chrono::Utc::now();
    let scope = DelegationScope::unrestricted()
        .with_max_transaction_value(50 * ONE_TNZO)
        .with_max_daily_spend(200 * ONE_TNZO)
        .with_allowed_operations(vec![
            "rebalance".to_string(),
            "trade".to_string(),
        ])
        .with_time_bound(TimeBound::new(now, now + chrono::Duration::days(7)));

    let agent = registry
        .register_machine_with_fee(
            &human_did,
            agent_pubkey,
            vec!["chain:tenzro".to_string(), "rebalance".to_string()],
            scope,
        )
        .await?
        .identity;
    let agent_did = agent.did_string();
    println!("→ agent DID         : {}", agent_did);
    println!("  agent wallet      : {}", agent.wallet_id);
    println!("  max trade value   : 50 TNZO");
    println!("  max daily spend   : 200 TNZO");
    println!("  allowed ops       : rebalance, trade");
    println!("  time bound        : 7 days");

    // ------------------------------------------------------------------
    // Step 3: pre-install the three asset price oracle runtimes
    // ------------------------------------------------------------------
    println!("\n=== Step 3: Pre-install asset price oracles on EVM ===");
    let evm = fresh_evm_executor();
    let mut state = fresh_state();

    let trader = mk_evm_address(0x99);
    state.set_balance(&trader, 1_000 * ONE_TNZO);

    let assets = [
        AssetTarget {
            address_byte: 0xA1,
            symbol: "TNZO",
            current_bps: 6_000,
            target_bps: 4_000,
            price_base: 10 * ONE_TNZO,
        },
        AssetTarget {
            address_byte: 0xB2,
            symbol: "USDC",
            current_bps: 2_000,
            target_bps: 4_000,
            price_base: ONE_TNZO,
        },
        AssetTarget {
            address_byte: 0xC3,
            symbol: "ETH",
            current_bps: 2_000,
            target_bps: 2_000,
            price_base: 3_500 * ONE_TNZO,
        },
    ];

    for asset in &assets {
        let addr = mk_evm_address(asset.address_byte);
        state.set_code(&addr, TRADING_RUNTIME_CODE.to_vec());
        println!(
            "→ installed price oracle for {} at 0x{} (price: {} base units)",
            asset.symbol,
            hex::encode(&addr),
            asset.price_base
        );
    }

    // ------------------------------------------------------------------
    // Step 4: compute drift, enforce delegation, dispatch trades
    // ------------------------------------------------------------------
    println!("\n=== Step 4: Compute drift and submit rebalance trades ===");

    // Total portfolio value = 200 TNZO worth. With max_transaction_value = 50
    // TNZO, the per-leg cap is 50/200 = 25% drift, so any individual rebalance
    // up to 2_500 bps fits within the delegation scope.
    let portfolio_value = 200 * ONE_TNZO;
    let mut nonce = 0u64;
    let mut total_traded = 0u128;

    for asset in &assets {
        let drift_bps = (asset.target_bps as i32) - (asset.current_bps as i32);
        if drift_bps == 0 {
            println!("→ {} already on target ({}bps)", asset.symbol, asset.target_bps);
            continue;
        }

        let trade_value = (portfolio_value / 10_000) * (drift_bps.unsigned_abs() as u128);
        let direction = if drift_bps > 0 { "buy" } else { "sell" };

        // Enforce the delegation scope BEFORE dispatching the trade.
        match registry.enforce_operation(&agent_did, "trade", Some(trade_value)) {
            Ok(()) => {
                println!(
                    "→ {} {}: {} base units (drift {}bps) — delegation OK",
                    direction, asset.symbol, trade_value, drift_bps
                );
            }
            Err(e) => {
                println!(
                    "→ {} {}: BLOCKED by delegation ({})",
                    direction, asset.symbol, e
                );
                continue;
            }
        }

        // Encode the trade by writing the new target weight (in bps) into
        // storage slot 0 of the asset's oracle runtime. The TRADING_RUNTIME
        // copies calldata[0..32] -> storage[0].
        let mut weight_bytes = vec![0u8; 32];
        weight_bytes[30] = (asset.target_bps >> 8) as u8;
        weight_bytes[31] = (asset.target_bps & 0xFF) as u8;

        let tx = VmTransaction::new(
            trader.clone(),
            Some(mk_evm_address(asset.address_byte)),
            0,
            weight_bytes,
            200_000,
            1_000_000_000,
            nonce,
            VmType::Evm,
            1337,
        );
        let result = evm.execute_with_state_adapter(&tx, &mut state).await?;
        println!(
            "  EVM trade tx success = {}, gas used = {}",
            result.success, result.gas_used
        );

        let stored = state
            .get_storage(&mk_evm_address(asset.address_byte), &[0u8; 32])
            .expect("oracle slot 0 should be set");
        let stored_bps = ((*stored.get(30).unwrap_or(&0) as u16) << 8)
            | (*stored.get(31).unwrap_or(&0) as u16);
        println!(
            "  on-chain target weight for {} = {}bps",
            asset.symbol, stored_bps
        );

        total_traded += trade_value;
        nonce += 1;
    }

    println!(
        "\n→ total traded value = {} base units ({} TNZO)",
        total_traded,
        total_traded / ONE_TNZO
    );
    println!("→ trader nonce = {}", state.get_nonce(&trader));

    // ------------------------------------------------------------------
    // Step 5: demonstrate that the delegation scope rejects an oversized trade
    // ------------------------------------------------------------------
    println!("\n=== Step 5: Confirm delegation rejects an oversized trade ===");
    let oversized = 250 * ONE_TNZO; // exceeds max_transaction_value (50 TNZO)
    match registry.enforce_operation(&agent_did, "trade", Some(oversized)) {
        Ok(()) => println!("→ unexpected: oversized trade was allowed"),
        Err(err) => println!("→ oversized trade rejected by delegation: {err}"),
    }

    println!("\nPortfolio rebalancer walkthrough complete.");
    Ok(())
}
