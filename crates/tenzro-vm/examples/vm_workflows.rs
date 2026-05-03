//! Multi-VM commerce workflows example
//!
//! Walks through complete commerce, trading, payments, and automation
//! flows on Tenzro's three execution backends:
//!
//!   * EVM   (revm)         — full bytecode execution, storage, logs
//!   * SVM   (solana_rbpf)  — dispatch-level routing for non-ELF payloads
//!   * Canton (DAML / gRPC) — gated on a live participant
//!
//! Run it with:
//!
//! ```bash
//! cargo run --example vm_workflows -p tenzro-vm
//! ```
//!
//! Every step prints what it just executed against the multi-VM runtime
//! so you can read it as a step-by-step walkthrough rather than a batch
//! of opaque calls.

use std::sync::Arc;

use tenzro_vm::{
    DamlExecutor, EvmExecutor, GasOracle, MultiVmRuntime, PrecompileRegistry, StateAdapter,
    SvmExecutor, VmConfig, VmExecutor, VmState, VmTransaction, VmType,
};

use tenzro_types::canton::{
    DamlCommand, DamlContractId, DamlParty, DamlTemplateId, DamlValue,
};

// ----------------------------------------------------------------------
// Hand-rolled bytecode used by the EVM walkthroughs.
// ----------------------------------------------------------------------

/// Init code that copies its 11-byte runtime suffix into return-data,
/// installs slot 0 = 0x42, and emits a LOG0 on every runtime invocation.
const COMMERCE_INIT_CODE: &[u8] = &[
    0x60, 0x0B, 0x60, 0x0C, 0x60, 0x00, 0x39, 0x60, 0x0B, 0x60, 0x00, 0xF3,
    0x60, 0x42, 0x60, 0x00, 0x55, 0x60, 0x20, 0x60, 0x00, 0xA0, 0x00,
];

/// Runtime that pushes 0x42 to memory and emits a LOG0 over the first
/// 32 bytes — used as the "token" runtime in the trading walkthrough.
const LOG_RUNTIME_CODE: &[u8] = &[
    0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xA0, 0x00,
];

/// Runtime that copies the first 32 bytes of calldata into storage
/// slot 0 — used as the "DEX" runtime in the trading walkthrough.
const TRADING_RUNTIME_CODE: &[u8] = &[
    0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00,
];

/// Runtime that pushes 0x42 to memory and emits a LOG1 with topic 0x01
/// — used as the "release event" runtime in the payments walkthrough.
const PAYMENTS_RUNTIME_CODE: &[u8] = &[
    0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x01, 0x60, 0x20, 0x60, 0x00, 0xA1, 0x00,
];

/// Runtime that sets storage slot 1 to 1 and emits a LOG0 — used as
/// the "escrow release" runtime in the automation walkthrough.
const AUTOMATION_RUNTIME_CODE: &[u8] = &[
    0x60, 0x01, 0x60, 0x01, 0x55, 0x60, 0x20, 0x60, 0x00, 0xA0, 0x00,
];

/// Minimal non-ELF "program" stub installed at SVM target addresses.
/// `SvmExecutor` requires program bytes to exist at the call target;
/// non-ELF payloads exercise the dispatch path without invoking rbpf.
const NON_ELF_PROGRAM_STUB: &[u8] = &[0x00, 0x61, 0x73, 0x6D];

/// 10 TNZO seed balance (10 * 10^18 base units).
const SEED_BALANCE: u128 = 10_000_000_000_000_000_000u128;

// ----------------------------------------------------------------------
// Helper builders
// ----------------------------------------------------------------------

fn fresh_evm_executor() -> EvmExecutor {
    EvmExecutor::new(
        VmConfig::default(),
        Arc::new(GasOracle::new()),
        Arc::new(PrecompileRegistry::new()),
    )
    .expect("EvmExecutor::new should succeed")
}

fn fresh_svm_executor() -> SvmExecutor {
    SvmExecutor::new(VmConfig::default(), Arc::new(GasOracle::new()))
        .expect("SvmExecutor::new should succeed")
}

fn fresh_daml_executor() -> DamlExecutor {
    DamlExecutor::new(VmConfig::default(), "localhost", 5001u16)
        .expect("DamlExecutor::new should succeed")
}

fn fresh_state() -> StateAdapter {
    StateAdapter::new()
}

fn mk_evm_address(byte: u8) -> Vec<u8> {
    vec![byte; 20]
}

fn mk_svm_pubkey(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn seed(state: &mut StateAdapter, addr: &[u8]) {
    state.set_balance(addr, SEED_BALANCE);
}

fn signed_tx(
    from: Vec<u8>,
    to: Option<Vec<u8>>,
    value: u128,
    data: Vec<u8>,
    gas_limit: u64,
    nonce: u64,
    vm_type: VmType,
) -> VmTransaction {
    // No signature — unsigned transactions are allowed in testnet mode
    VmTransaction::new(from, to, value, data, gas_limit, 1_000_000_000u128, nonce, vm_type, 1337)
}

async fn canton_available() -> bool {
    let daml = fresh_daml_executor();
    daml.is_canton_connected().await
}

// ----------------------------------------------------------------------
// EVM walkthroughs
// ----------------------------------------------------------------------

async fn evm_commerce_erc20_full_flow() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== EVM commerce: deploy and invoke a value-store contract ===");

    let evm = fresh_evm_executor();
    let mut state = fresh_state();

    let issuer = mk_evm_address(0x11);
    seed(&mut state, &issuer);

    println!("→ deploying COMMERCE_INIT_CODE from issuer 0x11..11");
    let deploy_tx = VmTransaction::new(
        issuer.clone(),
        None,
        0,
        COMMERCE_INIT_CODE.to_vec(),
        500_000,
        1_000_000_000,
        0,
        VmType::Evm,
        1337,
    );
    let deploy_result = evm
        .execute_with_state_adapter(&deploy_tx, &mut state)
        .await?;
    println!("  deploy success = {}", deploy_result.success);

    let contract_addr = deploy_result
        .contract_address
        .clone()
        .expect("deploy must return contract address");
    println!("  contract address = 0x{}", hex::encode(&contract_addr));

    let code = state
        .get_code(&contract_addr)
        .expect("runtime code should be installed");
    println!("  runtime code length = {} bytes", code.len());

    println!("→ invoking the deployed runtime to write slot 0 and emit a log");
    let call_tx = VmTransaction::new(
        issuer.clone(),
        Some(contract_addr.clone()),
        0,
        Vec::new(),
        200_000,
        1_000_000_000,
        1,
        VmType::Evm,
        1337,
    );
    let call_result = evm
        .execute_with_state_adapter(&call_tx, &mut state)
        .await?;
    println!("  invoke success = {}", call_result.success);
    println!("  logs emitted   = {}", call_result.logs.len());

    let slot0 = state
        .get_storage(&contract_addr, &[0u8; 32])
        .expect("slot 0 should be set by SSTORE");
    println!(
        "  slot 0 last byte = 0x{:02X} (expected 0x42)",
        slot0.last().copied().unwrap_or(0)
    );

    println!("  issuer nonce = {}", state.get_nonce(&issuer));
    Ok(())
}

async fn evm_trading_dex_swap() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== EVM trading: write a DEX price and emit token swap logs ===");

    let evm = fresh_evm_executor();
    let mut state = fresh_state();

    let trader = mk_evm_address(0x22);
    seed(&mut state, &trader);

    let token_a = mk_evm_address(0xA1);
    let token_b = mk_evm_address(0xB1);
    let dex = mk_evm_address(0xDE);
    state.set_code(&token_a, LOG_RUNTIME_CODE.to_vec());
    state.set_code(&token_b, LOG_RUNTIME_CODE.to_vec());
    state.set_code(&dex, TRADING_RUNTIME_CODE.to_vec());
    println!("→ pre-installed token_a, token_b, and DEX runtimes");

    let mut price_bytes = vec![0u8; 32];
    price_bytes[31] = 0x64;
    let price_tx = VmTransaction::new(
        trader.clone(),
        Some(dex.clone()),
        0,
        price_bytes,
        200_000,
        1_000_000_000,
        0,
        VmType::Evm,
        1337,
    );
    let price_result = evm
        .execute_with_state_adapter(&price_tx, &mut state)
        .await?;
    println!("→ recorded price (0x64 = 100) on DEX, success = {}", price_result.success);
    let slot0 = state
        .get_storage(&dex, &[0u8; 32])
        .expect("DEX should have price in slot 0");
    println!(
        "  DEX slot 0 last byte = 0x{:02X} (expected 0x64)",
        slot0.last().copied().unwrap_or(0)
    );

    for (nonce, label, token) in [(1u64, "token_a", &token_a), (2u64, "token_b", &token_b)] {
        let swap_tx = VmTransaction::new(
            trader.clone(),
            Some(token.clone()),
            0,
            Vec::new(),
            200_000,
            1_000_000_000,
            nonce,
            VmType::Evm,
            1337,
        );
        let r = evm
            .execute_with_state_adapter(&swap_tx, &mut state)
            .await?;
        println!(
            "→ swap log on {label}: success = {}, logs = {}",
            r.success,
            r.logs.len()
        );
    }
    println!("  trader nonce = {}", state.get_nonce(&trader));
    Ok(())
}

async fn evm_payments_splitter_release() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== EVM payments: release a splitter event for three payees ===");

    let evm = fresh_evm_executor();
    let mut state = fresh_state();

    let payer = mk_evm_address(0x33);
    seed(&mut state, &payer);

    let splitter = mk_evm_address(0x5A);
    state.set_code(&splitter, PAYMENTS_RUNTIME_CODE.to_vec());
    println!("→ pre-installed splitter runtime at 0x5A..5A");

    for nonce in 0..3u64 {
        let release_tx = VmTransaction::new(
            payer.clone(),
            Some(splitter.clone()),
            0,
            Vec::new(),
            200_000,
            1_000_000_000,
            nonce,
            VmType::Evm,
            1337,
        );
        let r = evm
            .execute_with_state_adapter(&release_tx, &mut state)
            .await?;
        let topic = r
            .logs
            .first()
            .and_then(|l| l.topics.first())
            .and_then(|t| t.last().copied())
            .unwrap_or(0);
        println!(
            "→ release #{nonce}: success = {}, logs = {}, topic last byte = 0x{:02X} (expected 0x01)",
            r.success,
            r.logs.len(),
            topic
        );
    }
    println!("  payer nonce = {}", state.get_nonce(&payer));
    Ok(())
}

async fn evm_automation_escrow_release() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== EVM automation: arbiter releases an escrow contract ===");

    let evm = fresh_evm_executor();
    let mut state = fresh_state();

    let arbiter = mk_evm_address(0x44);
    seed(&mut state, &arbiter);

    let escrow = mk_evm_address(0xE5);
    state.set_code(&escrow, AUTOMATION_RUNTIME_CODE.to_vec());
    println!("→ pre-installed escrow runtime at 0xE5..E5");

    let release_tx = VmTransaction::new(
        arbiter.clone(),
        Some(escrow.clone()),
        0,
        Vec::new(),
        200_000,
        1_000_000_000,
        0,
        VmType::Evm,
        1337,
    );
    let r = evm
        .execute_with_state_adapter(&release_tx, &mut state)
        .await?;
    println!("→ release call: success = {}, logs = {}", r.success, r.logs.len());

    let mut slot1_key = [0u8; 32];
    slot1_key[31] = 0x01;
    let slot1 = state
        .get_storage(&escrow, &slot1_key)
        .expect("slot 1 should be set after release");
    println!(
        "  escrow slot 1 last byte = 0x{:02X} (expected 0x01)",
        slot1.last().copied().unwrap_or(0)
    );

    println!("→ idempotent retry — re-releasing the same escrow");
    let retry_tx = VmTransaction::new(
        arbiter.clone(),
        Some(escrow.clone()),
        0,
        Vec::new(),
        200_000,
        1_000_000_000,
        1,
        VmType::Evm,
        1337,
    );
    let r2 = evm
        .execute_with_state_adapter(&retry_tx, &mut state)
        .await?;
    println!("  retry success = {}", r2.success);
    println!("  arbiter nonce = {}", state.get_nonce(&arbiter));
    Ok(())
}

// ----------------------------------------------------------------------
// SVM walkthroughs (dispatch-level only — non-ELF payloads)
// ----------------------------------------------------------------------

async fn svm_dispatch(label: &str, payload: &[u8], sender_byte: u8)
    -> Result<(), Box<dyn std::error::Error>>
{
    let svm = fresh_svm_executor();
    let mut state = fresh_state();

    let sender = mk_svm_pubkey(sender_byte);
    let program = mk_svm_pubkey(sender_byte.wrapping_add(0x80));
    state.set_balance(&sender, SEED_BALANCE);
    state.set_code(&program, NON_ELF_PROGRAM_STUB.to_vec());

    let tx = signed_tx(
        sender.clone(),
        Some(program.clone()),
        0,
        payload.to_vec(),
        200_000,
        0,
        VmType::Svm,
    );

    let result = svm.execute_transaction(&tx, &mut state as &mut dyn VmState).await?;
    println!(
        "→ {label}: dispatch success = {}, sender nonce = {}",
        result.success,
        state.get_nonce(&sender)
    );
    Ok(())
}

async fn svm_workflows_walk() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== SVM dispatch: route four agent payloads through SvmExecutor ===");
    svm_dispatch("commerce token program", b"transfer:alice:bob:100", 0x10).await?;
    svm_dispatch("trading orderbook match", b"match:bid=100,ask=95", 0x20).await?;
    svm_dispatch("payments channel lifecycle", b"channel:open;update=10;update=20;close", 0x30).await?;
    svm_dispatch("automation scheduler tick", b"scheduler:tick=1;tasks=[a,b,c]", 0x40).await?;
    Ok(())
}

// ----------------------------------------------------------------------
// Canton / DAML walkthroughs (gated on live participant)
// ----------------------------------------------------------------------

fn mk_inventory_create() -> DamlCommand {
    DamlCommand::Create {
        template_id: DamlTemplateId::new("tenzro-pkg", "Inventory", "Item"),
        create_arguments: DamlValue::Record {
            record_id: None,
            fields: vec![
                ("owner".to_string(), DamlValue::Party(DamlParty::new("alice"))),
                ("sku".to_string(), DamlValue::Text("SKU-001".to_string())),
                ("quantity".to_string(), DamlValue::Int64(10)),
            ],
        },
    }
}

fn mk_consume_exercise() -> DamlCommand {
    DamlCommand::Exercise {
        contract_id: DamlContractId::new("cid-001"),
        template_id: DamlTemplateId::new("tenzro-pkg", "Inventory", "Item"),
        choice: "Consume".to_string(),
        choice_argument: DamlValue::Record {
            record_id: None,
            fields: vec![("amount".to_string(), DamlValue::Int64(1))],
        },
    }
}

async fn run_canton_command(label: &str, cmd: DamlCommand) -> Result<(), Box<dyn std::error::Error>> {
    if !canton_available().await {
        println!("→ {label}: Canton participant unavailable, skipping");
        return Ok(());
    }
    let daml = fresh_daml_executor();
    let mut state = fresh_state();

    let party_bytes = hex::encode("alice").into_bytes();
    let data = serde_json::to_vec(&cmd)?;

    let tx = VmTransaction::new(
        party_bytes,
        None,
        0,
        data,
        200_000,
        1_000_000_000,
        0,
        VmType::Daml,
        1337,
    )
    .with_signature(vec![0xAAu8; 65]);

    match daml.execute_transaction(&tx, &mut state as &mut dyn VmState).await {
        Ok(result) => println!("→ {label}: dispatched, success = {}", result.success),
        Err(err) => println!("→ {label}: participant rejected ({err})"),
    }
    Ok(())
}

async fn canton_workflows_walk() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Canton / DAML: dispatch four contract commands (gated on live node) ===");

    run_canton_command("inventory create", mk_inventory_create()).await?;
    run_canton_command("inventory consume", mk_consume_exercise()).await?;

    let trading = DamlCommand::Create {
        template_id: DamlTemplateId::new("tenzro-pkg", "Trading", "Proposal"),
        create_arguments: DamlValue::Record {
            record_id: None,
            fields: vec![
                ("buyer".to_string(), DamlValue::Party(DamlParty::new("alice"))),
                ("seller".to_string(), DamlValue::Party(DamlParty::new("bob"))),
                ("asset".to_string(), DamlValue::Text("TNZO".to_string())),
                ("price".to_string(), DamlValue::Int64(500)),
            ],
        },
    };
    run_canton_command("dvp proposal", trading).await?;

    let payments = DamlCommand::Create {
        template_id: DamlTemplateId::new("tenzro-pkg", "Payments", "Obligation"),
        create_arguments: DamlValue::Record {
            record_id: None,
            fields: vec![
                ("payer".to_string(), DamlValue::Party(DamlParty::new("alice"))),
                ("payee".to_string(), DamlValue::Party(DamlParty::new("bob"))),
                ("amount".to_string(), DamlValue::Int64(1_000)),
            ],
        },
    };
    run_canton_command("payment obligation", payments).await?;

    let automation = DamlCommand::Create {
        template_id: DamlTemplateId::new("tenzro-pkg", "Automation", "Workflow"),
        create_arguments: DamlValue::Record {
            record_id: None,
            fields: vec![
                ("owner".to_string(), DamlValue::Party(DamlParty::new("alice"))),
                (
                    "steps".to_string(),
                    DamlValue::List(vec![
                        DamlValue::Text("step1".to_string()),
                        DamlValue::Text("step2".to_string()),
                        DamlValue::Text("step3".to_string()),
                    ]),
                ),
            ],
        },
    };
    run_canton_command("automation workflow", automation).await?;

    Ok(())
}

// ----------------------------------------------------------------------
// Cross-VM walkthrough — single shared StateAdapter
// ----------------------------------------------------------------------

async fn cross_vm_full_stack() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Cross-VM: dispatch EVM + SVM legs through one MultiVmRuntime ===");

    let runtime = MultiVmRuntime::new(VmConfig::default()).await?;
    let mut state = fresh_state();

    // EVM leg: deploy the commerce contract
    let evm_sender = mk_evm_address(0x55);
    state.set_balance(&evm_sender, SEED_BALANCE);
    let evm_tx = signed_tx(
        evm_sender.clone(),
        None,
        0,
        COMMERCE_INIT_CODE.to_vec(),
        500_000,
        0,
        VmType::Evm,
    );
    let evm_result = runtime.execute_transaction(&evm_tx, &mut state).await?;
    println!("→ EVM leg (commerce deploy): success = {}", evm_result.success);

    // SVM leg: dispatch a non-ELF payload to a pre-installed program
    let svm_sender = mk_svm_pubkey(0x66);
    let svm_program = mk_svm_pubkey(0xFB);
    state.set_balance(&svm_sender, SEED_BALANCE);
    state.set_code(&svm_program, NON_ELF_PROGRAM_STUB.to_vec());
    let svm_tx = signed_tx(
        svm_sender.clone(),
        Some(svm_program.clone()),
        0,
        b"agent:commerce".to_vec(),
        200_000,
        0,
        VmType::Svm,
    );
    let svm_result = runtime.execute_transaction(&svm_tx, &mut state).await?;
    println!("→ SVM leg (agent dispatch): success = {}", svm_result.success);

    println!(
        "  EVM nonce = {}, SVM nonce = {}",
        state.get_nonce(&evm_sender),
        state.get_nonce(&svm_sender)
    );

    if canton_available().await {
        println!("→ Canton leg available — see canton_workflows_walk()");
    } else {
        println!("→ Canton leg skipped (participant unavailable)");
    }
    Ok(())
}

async fn cross_vm_settlement_inference_escrow() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Cross-VM: SVM inference followed by EVM escrow release ===");

    let runtime = MultiVmRuntime::new(VmConfig::default()).await?;
    let mut state = fresh_state();

    // EVM: pre-install escrow runtime + fund the arbiter
    let arbiter = mk_evm_address(0x77);
    state.set_balance(&arbiter, SEED_BALANCE);
    let escrow_addr = mk_evm_address(0xE7);
    state.set_code(&escrow_addr, AUTOMATION_RUNTIME_CODE.to_vec());

    // SVM: dispatch the inference payload
    let agent = mk_svm_pubkey(0x88);
    let inference_program = mk_svm_pubkey(0xFC);
    state.set_balance(&agent, SEED_BALANCE);
    state.set_code(&inference_program, NON_ELF_PROGRAM_STUB.to_vec());
    let inference_tx = signed_tx(
        agent.clone(),
        Some(inference_program.clone()),
        0,
        b"inference:result=ok".to_vec(),
        200_000,
        0,
        VmType::Svm,
    );
    let inference_result = runtime.execute_transaction(&inference_tx, &mut state).await?;
    println!("→ inference dispatch: success = {}", inference_result.success);

    // EVM: arbiter releases the escrow
    let release_tx = signed_tx(
        arbiter.clone(),
        Some(escrow_addr.clone()),
        0,
        Vec::new(),
        200_000,
        0,
        VmType::Evm,
    );
    let release_result = runtime.execute_transaction(&release_tx, &mut state).await?;
    println!(
        "→ escrow release: success = {}, logs = {}",
        release_result.success,
        release_result.logs.len()
    );

    let mut slot1_key = [0u8; 32];
    slot1_key[31] = 0x01;
    let slot1 = state
        .get_storage(&escrow_addr, &slot1_key)
        .expect("escrow slot 1 should be set after release");
    println!(
        "  escrow slot 1 last byte = 0x{:02X} (expected 0x01)",
        slot1.last().copied().unwrap_or(0)
    );

    Ok(())
}

// ----------------------------------------------------------------------
// Entry point
// ----------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Tenzro multi-VM workflows walkthrough");
    println!("=====================================");

    // EVM
    evm_commerce_erc20_full_flow().await?;
    evm_trading_dex_swap().await?;
    evm_payments_splitter_release().await?;
    evm_automation_escrow_release().await?;

    // SVM
    svm_workflows_walk().await?;

    // Canton (gated)
    canton_workflows_walk().await?;

    // Cross-VM
    cross_vm_full_stack().await?;
    cross_vm_settlement_inference_escrow().await?;

    println!("\nAll walkthroughs completed.");
    Ok(())
}
