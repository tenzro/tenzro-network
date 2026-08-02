//! Cross-chain arbitrage agent walkthrough
//!
//! Builds an autonomous arbitrage agent that:
//!
//! 1. Provisions a human controller identity via TDIP
//! 2. Provisions a machine identity under the human, with a fine-grained
//!    delegation scope (per-trade cap, daily cap, allowed operations,
//!    allowed chains)
//! 3. Pre-installs a "DEX quote" runtime on a Tenzro EVM state adapter
//!    so the agent can read prices from local storage slots and write the
//!    executed trade as a real EVM transaction
//! 4. Constructs a `BridgeRouter` with LayerZero V2 + deBridge adapters
//!    so the agent can move capital between chains for cross-chain legs
//! 5. For each detected price spread:
//!    a. Enforces the delegation scope BEFORE doing anything
//!    b. Bridges base asset from the buy chain to the sell chain
//!    (when chains differ)
//!    c. Submits a real EVM trade transaction whose calldata is the
//!    executed price into storage slot 0
//!    d. Computes net profit after fees
//! 6. Demonstrates that the delegation scope rejects oversized trades
//!    and that an unprofitable spread is filtered out by the agent
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example cross_chain_arbitrage -p tenzro-node
//! ```

use std::sync::Arc;

use tenzro_crypto::keys::{KeyPair, KeyType};

use tenzro_identity::{DelegationScope, IdentityRegistry, TimeBound, WalletBinder};
use tenzro_types::identity::KycTier;

use tenzro_bridge::{
    BridgeRouter,
    debridge::{DeBridgeAdapter, DeBridgeConfig},
    layerzero::{LayerZeroAdapter, LayerZeroConfig},
};

use tenzro_vm::{
    EvmExecutor, GasOracle, PrecompileRegistry, StateAdapter, VmConfig, VmState, VmTransaction,
    VmType,
};

/// 1 USDC in 6-decimal base units.
const ONE_USDC: u128 = 1_000_000;

/// EVM bytecode that copies calldata[0..32] -> storage[0]
/// PUSH1 0x00, CALLDATALOAD, PUSH1 0x00, SSTORE, STOP
const DEX_RUNTIME_CODE: &[u8] = &[0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00];

#[derive(Debug, Clone, Copy)]
struct ArbOpportunity {
    asset: &'static str,
    /// Chain where we'd buy.
    buy_chain: &'static str,
    /// Chain where we'd sell.
    sell_chain: &'static str,
    /// Price on buy chain (in USDC, scaled by 1e6).
    buy_price: u128,
    /// Price on sell chain.
    sell_price: u128,
    /// Trade size in base USDC.
    size_usdc: u128,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Tenzro cross-chain arbitrage walkthrough");
    println!("========================================");

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
            "Arb Strategist".to_string(),
            KycTier::Enhanced,
        )
        .await?
        .identity;
    let human_did = human.did_string();
    println!("→ controller DID: {}", human_did);
    println!("  wallet         : {}", human.wallet_id);

    // ------------------------------------------------------------------
    // Step 2: provision the arbitrage agent with a delegation scope
    // ------------------------------------------------------------------
    println!("\n=== Step 2: Provision arbitrage agent under controller ===");
    let agent_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let agent_pubkey = agent_keypair.public_key().as_bytes().to_vec();

    let now = chrono::Utc::now();
    let scope = DelegationScope::unrestricted()
        .with_max_transaction_value(1_000 * ONE_USDC)
        .with_max_daily_spend(5_000 * ONE_USDC)
        .with_allowed_operations(vec![
            "arbitrage".to_string(),
            "bridge".to_string(),
            "trade".to_string(),
        ])
        .with_allowed_chains(vec![
            "ethereum".to_string(),
            "arbitrum".to_string(),
            "base".to_string(),
        ])
        .with_time_bound(TimeBound::new(now, now + chrono::Duration::days(7)));

    let agent = registry
        .register_machine_with_fee(
            &human_did,
            agent_pubkey,
            vec![
                "arbitrage".to_string(),
                "chain:ethereum".to_string(),
                "chain:arbitrum".to_string(),
                "chain:base".to_string(),
            ],
            scope,
        )
        .await?
        .identity;
    let agent_did = agent.did_string();
    println!("→ agent DID         : {}", agent_did);
    println!("  agent wallet      : {}", agent.wallet_id);
    println!("  max trade value   : 1000 USDC");
    println!("  max daily spend   : 5000 USDC");
    println!("  allowed ops       : arbitrage, bridge, trade");
    println!("  allowed chains    : ethereum, arbitrum, base");
    println!("  time bound        : 7 days");

    // ------------------------------------------------------------------
    // Step 3: pre-install DEX quote runtimes on the Tenzro EVM state
    // ------------------------------------------------------------------
    println!("\n=== Step 3: Pre-install DEX runtimes on EVM ===");
    let evm = fresh_evm_executor();
    let mut state = StateAdapter::new();

    let trader = mk_evm_address(0x99);
    state.set_balance(&trader, 1_000_000_000_000_000_000_000u128); // plenty of gas

    // Three DEX addresses, one per asset.
    let dex_eth = mk_evm_address(0xD1);
    let dex_arb = mk_evm_address(0xD2);
    let dex_base = mk_evm_address(0xD3);
    state.set_code(&dex_eth, DEX_RUNTIME_CODE.to_vec());
    state.set_code(&dex_arb, DEX_RUNTIME_CODE.to_vec());
    state.set_code(&dex_base, DEX_RUNTIME_CODE.to_vec());
    println!(
        "→ installed DEX runtime on ethereum   = 0x{}",
        hex::encode(&dex_eth)
    );
    println!(
        "→ installed DEX runtime on arbitrum   = 0x{}",
        hex::encode(&dex_arb)
    );
    println!(
        "→ installed DEX runtime on base       = 0x{}",
        hex::encode(&dex_base)
    );

    // ------------------------------------------------------------------
    // Step 4: build the BridgeRouter and register adapters
    // ------------------------------------------------------------------
    println!("\n=== Step 4: Register cross-chain bridge adapters ===");
    let router = BridgeRouter::new();

    let lz_config = LayerZeroConfig::new(
        "0x1a44076050125825900e736c501f859c50fE728c",
        30101,
        "0x0000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000002",
    );
    let lz_adapter = LayerZeroAdapter::new(lz_config);
    lz_adapter.set_peer("arbitrum", "0x0000000000000000000000000000000000000010");
    lz_adapter.set_peer("base", "0x0000000000000000000000000000000000000020");
    router
        .register_adapter("layerzero", Box::new(lz_adapter))
        .await;

    let debridge_config = DeBridgeConfig::new(
        "https://dln.debridge.finance",
        1,
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000",
    );
    let debridge_adapter = DeBridgeAdapter::new(debridge_config);
    router
        .register_adapter("debridge", Box::new(debridge_adapter))
        .await;
    println!("→ adapters registered: {:?}", router.list_adapters().await);

    // ------------------------------------------------------------------
    // Step 5: scan opportunities, enforce delegation, execute legs
    // ------------------------------------------------------------------
    println!("\n=== Step 5: Scan and execute arbitrage opportunities ===");

    let opportunities = [
        // ETH cheaper on arbitrum than ethereum — bridge ETH from arbitrum
        // to ethereum and sell on ethereum.
        ArbOpportunity {
            asset: "ETH",
            buy_chain: "arbitrum",
            sell_chain: "ethereum",
            buy_price: 2_500 * ONE_USDC,
            sell_price: 2_525 * ONE_USDC,
            size_usdc: 500 * ONE_USDC,
        },
        // USDC.e on base trading at a discount vs USDC on arbitrum — same
        // chain group but cross-chain spread.
        ArbOpportunity {
            asset: "USDC",
            buy_chain: "base",
            sell_chain: "arbitrum",
            buy_price: 999_500,    // 0.9995 USDC
            sell_price: 1_002_000, // 1.0020 USDC
            size_usdc: 800 * ONE_USDC,
        },
        // Unprofitable: spread is too thin to cover bridge fees.
        ArbOpportunity {
            asset: "ETH",
            buy_chain: "ethereum",
            sell_chain: "base",
            buy_price: 2_500 * ONE_USDC,
            sell_price: 2_501 * ONE_USDC,
            size_usdc: 200 * ONE_USDC,
        },
    ];

    let payload_size = 64;
    let mut nonce = 0u64;
    let mut realized_profit_micros: i128 = 0;
    let mut executed = 0;

    for (i, opp) in opportunities.iter().enumerate() {
        println!(
            "\n→ Opportunity #{}: buy {} on {} @ {}, sell on {} @ {}, size {} USDC",
            i + 1,
            opp.asset,
            opp.buy_chain,
            opp.buy_price,
            opp.sell_chain,
            opp.sell_price,
            opp.size_usdc / ONE_USDC
        );

        let raw_spread_micros: i128 = (opp.sell_price as i128) - (opp.buy_price as i128);
        let units = (opp.size_usdc / opp.buy_price) as i128;
        let gross_profit_micros: i128 = raw_spread_micros * units;
        println!(
            "  raw spread = {} micros/unit, units = {}, gross profit = {} micros",
            raw_spread_micros, units, gross_profit_micros
        );

        // (5a) Enforce delegation BEFORE doing anything.
        match registry.enforce_operation(&agent_did, "arbitrage", Some(opp.size_usdc)) {
            Ok(()) => println!(
                "  delegation OK ({} USDC ≤ 1000 USDC cap)",
                opp.size_usdc / ONE_USDC
            ),
            Err(e) => {
                println!("  BLOCKED by delegation: {e}");
                continue;
            }
        }

        // (5b) Compute bridge cost via the router (best fee).
        let bridge_cost_micros: i128 = if opp.buy_chain == opp.sell_chain {
            0
        } else {
            match router
                .compare_fees(opp.buy_chain, opp.sell_chain, payload_size)
                .await
            {
                Ok(comparisons) if !comparisons.is_empty() => {
                    let cheapest = &comparisons[0];
                    println!(
                        "  cheapest bridge: {} @ {} {}",
                        cheapest.adapter_name, cheapest.fee, cheapest.currency
                    );
                    // Convert native fee to USDC micros at a mock 1 ETH = 2500 USDC.
                    // The native fee is in wei (1e18), so:
                    //   fee_usdc_micros = fee_wei * 2500 * 1e6 / 1e18
                    //                   = fee_wei * 2500 / 1e12
                    let fee_wei = cheapest.fee;
                    (fee_wei as i128) * 2_500 / 1_000_000_000_000
                }
                Ok(_) => {
                    println!(
                        "  no adapters support {} → {}",
                        opp.buy_chain, opp.sell_chain
                    );
                    continue;
                }
                Err(e) => {
                    println!("  compare_fees failed: {e}");
                    continue;
                }
            }
        };

        // Apply a 5 bps DEX taker fee on each leg of the trade.
        let taker_fee_micros: i128 = (opp.size_usdc as i128) * 5 / 10_000 * 2;

        let net_profit_micros = gross_profit_micros - bridge_cost_micros - taker_fee_micros;
        println!(
            "  bridge cost = {} micros, taker fees = {} micros, NET profit = {} micros",
            bridge_cost_micros, taker_fee_micros, net_profit_micros
        );

        if net_profit_micros <= 0 {
            println!("  spread unprofitable after fees — skipping");
            continue;
        }

        // (5c) Submit a real EVM trade transaction encoding the executed
        // sell price into storage slot 0 of the sell-chain DEX.
        let sell_dex = match opp.sell_chain {
            "ethereum" => dex_eth.clone(),
            "arbitrum" => dex_arb.clone(),
            "base" => dex_base.clone(),
            _ => continue,
        };

        let mut price_bytes = vec![0u8; 32];
        let price = opp.sell_price.min(u64::MAX as u128) as u64;
        price_bytes[24..32].copy_from_slice(&price.to_be_bytes());

        let tx = VmTransaction::new(
            trader.clone(),
            Some(sell_dex.clone()),
            0,
            price_bytes,
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
            .get_storage(&sell_dex, &[0u8; 32])
            .expect("dex slot 0 should be set");
        let stored_price = u64::from_be_bytes(
            stored[24..32]
                .try_into()
                .expect("32-byte slot has 8 trailing bytes"),
        );
        println!("  on-chain executed price = {}", stored_price);

        nonce += 1;
        executed += 1;
        realized_profit_micros += net_profit_micros;
    }

    println!(
        "\n→ executed {} trades, realized net profit = {} USDC micros (~{} USDC)",
        executed,
        realized_profit_micros,
        realized_profit_micros / (ONE_USDC as i128)
    );

    // ------------------------------------------------------------------
    // Step 6: demonstrate that the delegation scope rejects an oversized trade
    // ------------------------------------------------------------------
    println!("\n=== Step 6: Confirm delegation rejects an oversized trade ===");
    let oversized = 5_000 * ONE_USDC; // exceeds max_transaction_value (1000 USDC)
    match registry.enforce_operation(&agent_did, "arbitrage", Some(oversized)) {
        Ok(()) => println!("→ unexpected: oversized trade was allowed"),
        Err(err) => println!(
            "→ oversized {} USDC trade rejected: {err}",
            oversized / ONE_USDC
        ),
    }

    println!("\nCross-chain arbitrage walkthrough complete.");
    Ok(())
}
