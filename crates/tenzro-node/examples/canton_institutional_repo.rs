//! Canton institutional repo walkthrough
//!
//! Builds an institutional tri-party repo (sale-and-repurchase) workflow on
//! the Tenzro Canton/DAML execution backend. This is the canonical pattern
//! used by tier-1 banks and central counterparties for collateralised
//! short-term funding.
//!
//! The walkthrough:
//!
//!   1. Provisions a human controller identity (the institutional client)
//!      via TDIP
//!   2. Provisions a machine identity for the trading desk agent under the
//!      controller, with a fine-grained delegation scope (max trade notional,
//!      daily cap, allowed operations)
//!   3. Constructs a `DamlExecutor` pointing at the local Canton participant
//!      and probes whether the participant is reachable
//!   4. Submits five DAML commands that model the full repo lifecycle:
//!      a. Counterparty onboarding (KYC contract)
//!      b. Collateral pledge (bond posted into the tri-party agent)
//!      c. Cash leg (the cash buyer purchases the collateral)
//!      d. Margin call (intra-day mark-to-market top-up)
//!      e. Reverse repo at maturity (collateral returned, cash + interest paid)
//!   5. For each command, enforces the delegation scope BEFORE dispatch,
//!      so the agent cannot exceed its max trade notional
//!   6. Demonstrates that the delegation scope rejects an oversized repo
//!
//! When the local Canton participant is offline (the default in dev), the
//! example still runs every step, prints the constructed `DamlCommand`,
//! and notes that the dispatch was skipped — so the workflow itself is
//! always exercised in full against the concrete types.
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example canton_institutional_repo -p tenzro-node
//! ```

use std::sync::Arc;

use tenzro_crypto::keys::{KeyPair, KeyType};

use tenzro_identity::{DelegationScope, IdentityRegistry, TimeBound, WalletBinder};
use tenzro_types::identity::KycTier;

use tenzro_vm::{DamlExecutor, StateAdapter, VmConfig, VmExecutor, VmState, VmTransaction, VmType};

use tenzro_types::canton::{DamlCommand, DamlParty, DamlTemplateId, DamlValue};

/// 1 USD in 2-decimal cents.
const ONE_USD: u128 = 100;

#[derive(Debug, Clone)]
struct RepoLeg {
    label: &'static str,
    notional_usd: u128,
    command: DamlCommand,
}

fn fresh_daml_executor() -> DamlExecutor {
    DamlExecutor::new(VmConfig::default(), "localhost", 5001u16)
        .expect("DamlExecutor::new should succeed")
}

async fn canton_available(daml: &DamlExecutor) -> bool {
    daml.is_canton_connected().await
}

fn party(name: &str) -> DamlValue {
    DamlValue::Party(DamlParty::new(name))
}

fn text(s: &str) -> DamlValue {
    DamlValue::Text(s.to_string())
}

fn int(n: i64) -> DamlValue {
    DamlValue::Int64(n)
}

fn record(fields: Vec<(&str, DamlValue)>) -> DamlValue {
    DamlValue::Record {
        record_id: None,
        fields: fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    }
}

fn create_cmd(module: &str, entity: &str, fields: Vec<(&str, DamlValue)>) -> DamlCommand {
    DamlCommand::Create {
        template_id: DamlTemplateId::new("tenzro-repo-pkg", module, entity),
        create_arguments: record(fields),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Tenzro Canton institutional repo walkthrough");
    println!("============================================");

    // ------------------------------------------------------------------
    // Step 1: provision the human controller via TDIP
    // ------------------------------------------------------------------
    println!("\n=== Step 1: Provision institutional client identity ===");
    let registry = IdentityRegistry::with_wallet_binder(Arc::new(WalletBinder::new()?));

    let human_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let human_pubkey = human_keypair.public_key().as_bytes().to_vec();
    let human = registry
        .register_human_with_fee(
            human_pubkey,
            "Acme Asset Management".to_string(),
            KycTier::Full,
        )
        .await?
        .identity;
    let human_did = human.did_string();
    println!("→ controller DID: {}", human_did);
    println!("  wallet         : {}", human.wallet_id);

    // ------------------------------------------------------------------
    // Step 2: provision the trading desk agent with a delegation scope
    // ------------------------------------------------------------------
    println!("\n=== Step 2: Provision trading desk agent under controller ===");
    let agent_keypair = KeyPair::generate(KeyType::Ed25519)?;
    let agent_pubkey = agent_keypair.public_key().as_bytes().to_vec();

    let now = chrono::Utc::now();
    let scope = DelegationScope::unrestricted()
        .with_max_transaction_value(50_000_000 * ONE_USD) // $50M per leg
        .with_max_daily_spend(200_000_000 * ONE_USD) // $200M daily
        .with_allowed_operations(vec![
            "repo".to_string(),
            "collateral-pledge".to_string(),
            "margin-call".to_string(),
            "reverse-repo".to_string(),
        ])
        .with_time_bound(TimeBound::new(now, now + chrono::Duration::days(1)));

    let agent = registry
        .register_machine_with_fee(
            &human_did,
            agent_pubkey,
            vec![
                "repo".to_string(),
                "canton".to_string(),
                "fixed-income".to_string(),
            ],
            scope,
        )
        .await?
        .identity;
    let agent_did = agent.did_string();
    println!("→ agent DID         : {}", agent_did);
    println!("  agent wallet      : {}", agent.wallet_id);
    println!("  max per-leg notional : $50M");
    println!("  max daily notional   : $200M");
    println!("  allowed ops       : repo, collateral-pledge, margin-call, reverse-repo");
    println!("  time bound        : 1 day");

    // ------------------------------------------------------------------
    // Step 3: construct the DamlExecutor and probe Canton availability
    // ------------------------------------------------------------------
    println!("\n=== Step 3: Probe Canton participant ===");
    let daml = fresh_daml_executor();
    let canton_live = canton_available(&daml).await;
    if canton_live {
        println!("→ Canton participant at localhost:5001 is REACHABLE");
    } else {
        println!("→ Canton participant at localhost:5001 is offline (dev default)");
        println!("  All commands will still be constructed and the walkthrough will run in full;");
        println!("  the actual ledger dispatch will be skipped per leg.");
    }

    // ------------------------------------------------------------------
    // Step 4: construct the full repo lifecycle as DAML commands
    // ------------------------------------------------------------------
    println!("\n=== Step 4: Construct tri-party repo lifecycle ===");

    let triparty_agent = "BNYM-Triparty";
    let cash_buyer = "Goldman-Repo-Desk";
    let collateral_seller = "Acme-AM";

    // 4a — onboarding KYC contract
    let onboarding = RepoLeg {
        label: "Counterparty Onboarding (KYC)",
        notional_usd: 0,
        command: create_cmd(
            "Onboarding",
            "KycContract",
            vec![
                ("client", party(collateral_seller)),
                ("counterparty", party(cash_buyer)),
                ("triparty", party(triparty_agent)),
                ("kycLevel", text("Tier3-Full")),
                ("jurisdiction", text("US")),
            ],
        ),
    };

    // 4b — collateral pledge (10y UST $25M face value)
    let pledge = RepoLeg {
        label: "Collateral Pledge (UST-10Y, $25M face)",
        notional_usd: 25_000_000 * ONE_USD,
        command: create_cmd(
            "Repo",
            "CollateralPledge",
            vec![
                ("pledger", party(collateral_seller)),
                ("custodian", party(triparty_agent)),
                ("isin", text("US91282CKY32")),
                ("faceValueCents", int(25_000_000 * 100)),
                ("haircutBps", int(200)), // 2%
                ("maturityDate", text("2034-11-15")),
            ],
        ),
    };

    // 4c — cash leg ($24.5M after 2% haircut)
    let cash_leg = RepoLeg {
        label: "Cash Leg (USD 24.5M after 2% haircut)",
        notional_usd: 24_500_000 * ONE_USD,
        command: create_cmd(
            "Repo",
            "CashLeg",
            vec![
                ("payer", party(cash_buyer)),
                ("payee", party(collateral_seller)),
                ("triparty", party(triparty_agent)),
                ("amountCents", int(24_500_000 * 100)),
                ("currency", text("USD")),
                ("repoRateBps", int(525)), // 5.25%
                ("tenorDays", int(7)),
            ],
        ),
    };

    // 4d — intra-day margin call (collateral mark-down requires $500K top-up)
    let margin_call = RepoLeg {
        label: "Margin Call (top-up $500K)",
        notional_usd: 500_000 * ONE_USD,
        command: create_cmd(
            "Repo",
            "MarginCall",
            vec![
                ("triparty", party(triparty_agent)),
                ("pledger", party(collateral_seller)),
                ("topUpCents", int(500_000 * 100)),
                ("reason", text("MTM markdown 0.20%")),
            ],
        ),
    };

    // 4e — reverse repo (return collateral, pay back cash + interest)
    // Interest: $24.5M * 5.25% * 7/360 = ~$25,010
    let reverse_repo = RepoLeg {
        label: "Reverse Repo (collateral return + cash+interest)",
        notional_usd: 24_525_010 * ONE_USD,
        command: create_cmd(
            "Repo",
            "ReverseRepo",
            vec![
                ("triparty", party(triparty_agent)),
                ("cashBuyer", party(cash_buyer)),
                ("collateralSeller", party(collateral_seller)),
                ("principalCents", int(24_500_000 * 100)),
                ("interestCents", int(25_010 * 100)),
                ("settlementDate", text("2026-04-14")),
            ],
        ),
    };

    let lifecycle = vec![onboarding, pledge, cash_leg, margin_call, reverse_repo];

    // ------------------------------------------------------------------
    // Step 5: enforce delegation, then dispatch each leg
    // ------------------------------------------------------------------
    println!("\n=== Step 5: Enforce delegation and dispatch each leg ===");
    let mut state = StateAdapter::new();
    let party_bytes = hex::encode(collateral_seller).into_bytes();

    let mut nonce = 0u64;
    let mut dispatched = 0;
    let mut total_notional_usd = 0u128;

    for leg in &lifecycle {
        println!("\n→ Leg: {}", leg.label);
        println!("  notional = ${}", leg.notional_usd / ONE_USD);

        // Enforce delegation BEFORE constructing the transaction.
        if leg.notional_usd > 0 {
            match registry.enforce_operation(&agent_did, "repo", Some(leg.notional_usd)) {
                Ok(()) => println!(
                    "  delegation OK (${} ≤ $50M per-leg cap)",
                    leg.notional_usd / ONE_USD
                ),
                Err(e) => {
                    println!("  BLOCKED by delegation: {e}");
                    continue;
                }
            }
        } else {
            println!("  no notional — onboarding leg, delegation check skipped");
        }

        // Serialize the DamlCommand into transaction calldata.
        let data = serde_json::to_vec(&leg.command)?;

        let tx = VmTransaction::new(
            party_bytes.clone(),
            None,
            0,
            data,
            200_000,
            1_000_000_000,
            nonce,
            VmType::Daml,
            1337,
        )
        .with_signature(vec![0xAAu8; 65]);

        if canton_live {
            match daml
                .execute_transaction(&tx, &mut state as &mut dyn VmState)
                .await
            {
                Ok(result) => {
                    println!("  Canton dispatch success = {}", result.success);
                    dispatched += 1;
                }
                Err(err) => println!("  Canton participant rejected: {err}"),
            }
        } else {
            println!("  Canton offline — would dispatch DamlCommand variant `{}`", leg_variant(&leg.command));
            println!("  prepared tx: from={} bytes, calldata={} bytes, vm={:?}",
                party_bytes.len(),
                tx.data.len(),
                tx.vm_type,
            );
        }

        total_notional_usd += leg.notional_usd;
        nonce += 1;
    }

    println!(
        "\n→ lifecycle complete: {} legs prepared, {} actually dispatched, total notional = ${}",
        lifecycle.len(),
        dispatched,
        total_notional_usd / ONE_USD
    );

    // ------------------------------------------------------------------
    // Step 6: demonstrate that the delegation scope rejects an oversized repo
    // ------------------------------------------------------------------
    println!("\n=== Step 6: Confirm delegation rejects an oversized repo ===");
    let oversized = 75_000_000 * ONE_USD; // exceeds $50M per-leg cap
    match registry.enforce_operation(&agent_did, "repo", Some(oversized)) {
        Ok(()) => println!("→ unexpected: oversized $75M repo was allowed"),
        Err(err) => println!("→ oversized ${}M repo rejected: {err}", oversized / ONE_USD / 1_000_000),
    }

    println!("\nCanton institutional repo walkthrough complete.");
    Ok(())
}

fn leg_variant(cmd: &DamlCommand) -> &'static str {
    match cmd {
        DamlCommand::Create { .. } => "Create",
        DamlCommand::Exercise { .. } => "Exercise",
        DamlCommand::CreateAndExercise { .. } => "CreateAndExercise",
        DamlCommand::ExerciseByKey { .. } => "ExerciseByKey",
    }
}
