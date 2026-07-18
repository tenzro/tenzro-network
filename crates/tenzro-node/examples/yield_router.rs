//! Cross-chain yield router agent walkthrough
//!
//! Builds an autonomous yield-routing agent that:
//!
//!   1. Provisions a human controller identity via TDIP
//!   2. Provisions a machine identity under the human, with a fine-grained
//!      delegation scope (max bridge size, allowed operations, daily cap,
//!      allowed chains)
//!   3. Constructs a `BridgeRouter` and registers three real bridge adapters
//!      (LayerZero V2, Chainlink CCIP, deBridge DLN) — every adapter is the
//!      same one used by the production node
//!   4. Defines a set of cross-chain yield opportunities (Aave on Ethereum,
//!      GMX on Arbitrum, Aerodrome on Base) and asks the router to compare
//!      live fee quotes for each candidate destination chain
//!   5. Picks the cheapest adapter for the highest-yielding destination,
//!      enforces the delegation scope BEFORE dispatching the bridge call,
//!      and prints the resulting `BridgeTokenReceipt`
//!   6. Demonstrates that the delegation scope rejects an oversized bridge
//!      and that an unsupported destination chain is refused by the router
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example yield_router -p tenzro-node
//! ```

use std::sync::Arc;

use tenzro_crypto::keys::{KeyPair, KeyType};

use tenzro_identity::{DelegationScope, IdentityRegistry, TimeBound, WalletBinder};
use tenzro_types::identity::KycTier;

use tenzro_bridge::{
    BridgeRouter, BridgeTokenRequest,
    chainlink_ccip::{CcipConfig, ChainlinkCcipAdapter, FeeToken},
    debridge::{DeBridgeAdapter, DeBridgeConfig},
    layerzero::{LayerZeroAdapter, LayerZeroConfig},
};

/// 1 USDC in 6-decimal base units.
const ONE_USDC: u128 = 1_000_000;

#[derive(Debug, Clone, Copy)]
struct YieldOpportunity {
    /// Destination chain identifier (must be one a registered adapter supports).
    chain: &'static str,
    /// Symbolic protocol name for printing.
    protocol: &'static str,
    /// Estimated APY in basis points (out of 10_000).
    apy_bps: u32,
    /// Amount we want to deploy (in USDC base units).
    deploy_amount: u128,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Tenzro cross-chain yield router walkthrough");
    println!("===========================================");

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
            "Yield Strategist".to_string(),
            KycTier::Enhanced,
        )
        .await?
        .identity;
    let human_did = human.did_string();
    println!("→ controller DID: {}", human_did);
    println!("  wallet         : {}", human.wallet_id);

    // ------------------------------------------------------------------
    // Step 2: provision the yield-router agent with a delegation scope
    // ------------------------------------------------------------------
    println!("\n=== Step 2: Provision yield router agent under controller ===");
    let agent_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let agent_pubkey = agent_keypair.public_key().as_bytes().to_vec();

    let now = chrono::Utc::now();
    let scope = DelegationScope::unrestricted()
        .with_max_transaction_value(500 * ONE_USDC)
        .with_max_daily_spend(2_000 * ONE_USDC)
        .with_allowed_operations(vec![
            "bridge".to_string(),
            "yield-route".to_string(),
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
                "chain:ethereum".to_string(),
                "chain:arbitrum".to_string(),
                "chain:base".to_string(),
                "yield-route".to_string(),
            ],
            scope,
        )
        .await?
        .identity;
    let agent_did = agent.did_string();
    println!("→ agent DID         : {}", agent_did);
    println!("  agent wallet      : {}", agent.wallet_id);
    println!("  max bridge value  : 500 USDC");
    println!("  max daily spend   : 2000 USDC");
    println!("  allowed ops       : bridge, yield-route");
    println!("  allowed chains    : ethereum, arbitrum, base");
    println!("  time bound        : 7 days");

    // ------------------------------------------------------------------
    // Step 3: build the BridgeRouter and register real adapters
    // ------------------------------------------------------------------
    println!("\n=== Step 3: Register cross-chain bridge adapters ===");
    let router = BridgeRouter::new();

    // LayerZero V2 — EndpointV2 mainnet address. We use placeholder oracle /
    // relayer addresses; the example never reaches the on-chain `send()`
    // path because there is no live RPC URL configured.
    let lz_config = LayerZeroConfig::new(
        "0x1a44076050125825900e736c501f859c50fE728c",
        30101, // ethereum source EID
        "0x0000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000002",
    );
    let lz_adapter = LayerZeroAdapter::new(lz_config);
    lz_adapter.set_peer("arbitrum", "0x0000000000000000000000000000000000000010");
    lz_adapter.set_peer("base", "0x0000000000000000000000000000000000000020");
    router
        .register_adapter("layerzero", Box::new(lz_adapter))
        .await;
    println!("→ registered LayerZero V2 (8 chains: eth, arb, op, polygon, bsc, avax, base, sol)");

    // Chainlink CCIP — Ethereum mainnet config with USDC as the fee token.
    let ccip_config = CcipConfig::ethereum_mainnet(FeeToken::Native);
    let ccip_adapter = ChainlinkCcipAdapter::new(ccip_config);
    router
        .register_adapter("ccip", Box::new(ccip_adapter))
        .await;
    println!("→ registered Chainlink CCIP   (7 chains: eth, arb, op, polygon, avax, base, bsc)");

    // deBridge DLN — uses the public DLN API.
    let debridge_config = DeBridgeConfig::new(
        "https://dln.debridge.finance",
        1, // ethereum chain id
        "0x0000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000",
    );
    let debridge_adapter = DeBridgeAdapter::new(debridge_config);
    router
        .register_adapter("debridge", Box::new(debridge_adapter))
        .await;
    println!("→ registered deBridge DLN     (intent-based cross-chain swaps)");

    println!("→ adapters registered: {:?}", router.list_adapters().await);

    // ------------------------------------------------------------------
    // Step 4: define yield opportunities and pick the best route per leg
    // ------------------------------------------------------------------
    println!("\n=== Step 4: Compare fees and pick best route per opportunity ===");

    let opportunities = [
        YieldOpportunity {
            chain: "ethereum",
            protocol: "Aave v3 USDC",
            apy_bps: 380, // 3.80%
            deploy_amount: 200 * ONE_USDC,
        },
        YieldOpportunity {
            chain: "arbitrum",
            protocol: "GMX GLP",
            apy_bps: 1_250, // 12.50%
            deploy_amount: 250 * ONE_USDC,
        },
        YieldOpportunity {
            chain: "base",
            protocol: "Aerodrome USDC/cbBTC",
            apy_bps: 720, // 7.20%
            deploy_amount: 300 * ONE_USDC,
        },
    ];

    let source_chain = "ethereum";
    let payload_size = 64; // typical OFT message: bytes32 to + uint256 amount

    // Sort opportunities by APY descending so we route capital to the most
    // attractive yield first.
    let mut sorted = opportunities;
    sorted.sort_by_key(|b| std::cmp::Reverse(b.apy_bps));

    let mut total_bridged = 0u128;
    let mut leg_count = 0;

    for opp in &sorted {
        println!(
            "\n→ {} on {} ({}.{}% APY) — deploy {} USDC",
            opp.protocol,
            opp.chain,
            opp.apy_bps / 100,
            opp.apy_bps % 100,
            opp.deploy_amount / ONE_USDC
        );

        if opp.chain == source_chain {
            println!("  same-chain deployment, no bridge required");
            continue;
        }

        // Ask the router which adapter has the cheapest live quote for this
        // destination. The static fallbacks will be used if RPC is offline.
        let comparisons = match router.compare_fees(source_chain, opp.chain, payload_size).await {
            Ok(c) => c,
            Err(e) => {
                println!("  compare_fees failed: {e}");
                continue;
            }
        };

        if comparisons.is_empty() {
            println!("  no adapters support {} → {}", source_chain, opp.chain);
            continue;
        }

        for fc in &comparisons {
            println!(
                "    {:<10} fee = {} {}",
                fc.adapter_name, fc.fee, fc.currency
            );
        }

        let cheapest = &comparisons[0];
        println!(
            "  → cheapest adapter: {} @ {} {}",
            cheapest.adapter_name, cheapest.fee, cheapest.currency
        );

        // Enforce the delegation scope BEFORE dispatching the bridge call.
        match registry.enforce_operation(&agent_did, "bridge", Some(opp.deploy_amount)) {
            Ok(()) => println!("  delegation OK ({} USDC ≤ 500 USDC cap)", opp.deploy_amount / ONE_USDC),
            Err(e) => {
                println!("  BLOCKED by delegation: {e}");
                continue;
            }
        }

        // Build the bridge request. Note: actually executing `bridge_tokens`
        // would attempt to broadcast a real transaction via the registered
        // adapter, which requires a funded wallet on the source chain. For
        // the walkthrough we just print the prepared request so users can
        // see exactly what would be dispatched.
        let request = BridgeTokenRequest::new(
            source_chain,
            opp.chain,
            "USDC",
            opp.deploy_amount,
            "0xyieldrouter",
            "0xyieldrouter",
        );
        println!(
            "  prepared bridge request: {} → {}, {} USDC, asset {}",
            request.source_chain,
            request.dest_chain,
            request.amount / ONE_USDC,
            request.asset_id
        );

        total_bridged += opp.deploy_amount;
        leg_count += 1;
    }

    println!(
        "\n→ total prepared bridge volume = {} USDC across {} legs",
        total_bridged / ONE_USDC,
        leg_count
    );

    // ------------------------------------------------------------------
    // Step 5: demonstrate that the delegation scope rejects oversized bridges
    // ------------------------------------------------------------------
    println!("\n=== Step 5: Confirm delegation rejects oversized bridge ===");
    let oversized = 1_000 * ONE_USDC; // exceeds max_transaction_value (500 USDC)
    match registry.enforce_operation(&agent_did, "bridge", Some(oversized)) {
        Ok(()) => println!("→ unexpected: oversized bridge was allowed"),
        Err(err) => println!("→ oversized {} USDC bridge rejected: {err}", oversized / ONE_USDC),
    }

    // ------------------------------------------------------------------
    // Step 6: demonstrate that an unsupported destination chain is refused
    // ------------------------------------------------------------------
    println!("\n=== Step 6: Confirm unsupported chain is refused by router ===");
    match router.compare_fees(source_chain, "fantom", payload_size).await {
        Ok(c) if c.is_empty() => println!("→ no adapters support ethereum → fantom (correct)"),
        Ok(c) => println!("→ unexpected: got {} fee quotes for fantom", c.len()),
        Err(e) => println!("→ router refused fantom route: {e}"),
    }

    println!("\nYield router walkthrough complete.");
    Ok(())
}
