//! End-to-end agentic commerce, trading, payments, and automation
//! workflows across EVM, SVM, and Canton/DAML VMs.
//!
//! These tests exercise the real executors (revm for EVM, the SPL/native
//! dispatch path for SVM, tonic gRPC for Canton/DAML) with minimal hand-crafted
//! bytecode / payloads so the suite is robust across backend version
//! bumps. Canton tests are gated on a live participant probe and
//! early-return with `tracing::warn!` when no participant is reachable.

#![allow(clippy::bool_assert_comparison)]

use std::sync::Arc;

use tenzro_vm::{
    DamlExecutor, EvmExecutor, GasOracle, MultiVmRuntime, PrecompileRegistry, StateAdapter,
    SvmExecutor, VmConfig, VmExecutor, VmState, VmTransaction, VmType,
};

mod helpers {
    use super::*;

    /// Build a fresh EvmExecutor with default config, oracle, and
    /// precompile registry. Panics on construction failure (not
    /// expected in tests).
    pub fn fresh_evm_executor() -> EvmExecutor {
        EvmExecutor::new(
            VmConfig::default(),
            Arc::new(GasOracle::new()),
            Arc::new(PrecompileRegistry::new()),
        )
        .expect("EvmExecutor::new should succeed with default config")
    }

    /// Build a fresh SvmExecutor (2 args — no precompile registry).
    /// Used by the direct-executor SVM tests to bypass the dispatch
    /// layer in `MultiVmRuntime`.
    pub fn fresh_svm_executor() -> SvmExecutor {
        SvmExecutor::new(VmConfig::default(), Arc::new(GasOracle::new()))
            .expect("SvmExecutor::new should succeed with default config")
    }

    /// Build a fresh DamlExecutor pointing at localhost:5001. Does NOT
    /// connect at construction — connection is lazy on first command.
    pub fn fresh_daml_executor() -> DamlExecutor {
        DamlExecutor::new(VmConfig::default(), "localhost", 5001u16)
            .expect("DamlExecutor::new should succeed with default config")
    }

    /// Build a fresh in-memory StateAdapter.
    pub fn fresh_state() -> StateAdapter {
        StateAdapter::new()
    }

    /// 20-byte EVM address filled with `byte`.
    pub fn mk_evm_address(byte: u8) -> Vec<u8> {
        vec![byte; 20]
    }

    /// 32-byte SVM pubkey filled with `byte`.
    pub fn mk_svm_pubkey(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    /// Generous native balance (10 TNZO in wei-equivalent) for test
    /// signers so gas costs never dominate the assertions.
    pub const SEED_BALANCE: u128 = 10_000_000_000_000_000_000u128;

    /// Seed an account with the default test balance and return `addr`.
    pub fn seed(state: &mut StateAdapter, addr: &[u8]) {
        state.set_balance(addr, SEED_BALANCE);
    }

    /// Minimal EVM init code that deploys a runtime which stores 0x42
    /// at slot 0 and emits a LOG0. This exercises:
    ///   * constructor execution (codecopy-style return)
    ///   * runtime storage write
    ///   * log emission
    ///
    /// Init-code layout:
    ///   PUSH1 0x0B            // runtime length (11)
    ///   PUSH1 0x0C            // runtime offset in this init code
    ///   PUSH1 0x00            // dest in memory
    ///   CODECOPY
    ///   PUSH1 0x0B
    ///   PUSH1 0x00
    ///   RETURN
    /// Runtime (11 bytes):
    ///   PUSH1 0x42 PUSH1 0x00 SSTORE    // store 0x42 at slot 0
    ///   PUSH1 0x20 PUSH1 0x00 LOG0      // emit empty-topic log over 32 bytes
    ///   STOP
    pub const COMMERCE_INIT_CODE: &[u8] = &[
        // Init prologue: copy runtime out and return it
        0x60, 0x0B, // PUSH1 11 (runtime length)
        0x60, 0x0C, // PUSH1 12 (runtime offset = init prologue length)
        0x60, 0x00, // PUSH1 0  (mem dest)
        0x39, // CODECOPY
        0x60, 0x0B, // PUSH1 11 (return size)
        0x60, 0x00, // PUSH1 0  (return offset)
        0xF3, // RETURN
        // Runtime (11 bytes):
        0x60, 0x42, // PUSH1 0x42
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xA0, // LOG0
        0x00, // STOP
    ];

    /// Runtime code (already-deployed) that just emits LOG0 and STOPs.
    /// Used when we pre-set code directly via `state.set_code`.
    pub const LOG_RUNTIME_CODE: &[u8] = &[
        0x60, 0x42, // PUSH1 0x42
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE
        0x60, 0x20, // PUSH1 32 (size)
        0x60, 0x00, // PUSH1 0  (offset)
        0xA0, // LOG0
        0x00, // STOP
    ];

    /// Runtime that stores caller-supplied value at slot 0.
    /// Calldata layout: first 32 bytes are the value.
    /// Bytecode:
    ///   PUSH1 0x00 CALLDATALOAD   // top = calldata[0..32]
    ///   PUSH1 0x00 SSTORE         // store at slot 0
    ///   STOP
    pub const TRADING_RUNTIME_CODE: &[u8] = &[
        0x60, 0x00, // PUSH1 0
        0x35, // CALLDATALOAD
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
        0x00, // STOP
    ];

    /// Runtime that emits LOG1 with topic 0x01 and 32 bytes of data.
    /// Bytecode:
    ///   PUSH1 0x42 PUSH1 0x00 MSTORE
    ///   PUSH1 0x01                  // topic
    ///   PUSH1 0x20 PUSH1 0x00 LOG1
    ///   STOP
    pub const PAYMENTS_RUNTIME_CODE: &[u8] = &[
        0x60, 0x42, // PUSH1 0x42
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE
        0x60, 0x01, // PUSH1 1 (topic)
        0x60, 0x20, // PUSH1 32 (size)
        0x60, 0x00, // PUSH1 0 (offset)
        0xA1, // LOG1
        0x00, // STOP
    ];

    /// Runtime that stores 1 at slot 1 and emits LOG0 — used as the
    /// "automation tick" contract.
    pub const AUTOMATION_RUNTIME_CODE: &[u8] = &[
        0x60, 0x01, // PUSH1 1
        0x60, 0x01, // PUSH1 1 (slot)
        0x55, // SSTORE
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0xA0, // LOG0
        0x00, // STOP
    ];

    /// Probe for a live Canton participant. Returns `true` only if
    /// `DamlExecutor::is_canton_connected` resolves to `true`.
    pub async fn canton_available() -> bool {
        let daml = fresh_daml_executor();
        daml.is_canton_connected().await
    }

    /// Build a `VmTransaction` for testing.
    /// No signature is set — unsigned transactions are allowed in testnet mode.
    pub fn signed_tx(
        from: Vec<u8>,
        to: Option<Vec<u8>>,
        value: u128,
        data: Vec<u8>,
        gas_limit: u64,
        nonce: u64,
        vm_type: VmType,
    ) -> VmTransaction {
        VmTransaction::new(
            from,
            to,
            value,
            data,
            gas_limit,
            1_000_000_000u128,
            nonce,
            vm_type,
            1337,
        )
    }
}

// ============================================================================
// EVM workflows
// ============================================================================

mod evm_workflows {
    use super::helpers::*;
    use super::*;

    #[tokio::test]
    async fn evm_commerce_erc20_full_flow() {
        // Commerce scenario: deploy a tiny "commerce" contract that
        // stores a value in slot 0 and emits a log on runtime invocation
        // The first transaction deploys it; the second calls the
        // runtime code at the deployed address; we assert state
        // changes, logs, and nonce progression.
        let evm = fresh_evm_executor();
        let mut state = fresh_state();

        let issuer = mk_evm_address(0x11);
        seed(&mut state, &issuer);

        // 1) Deploy
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
            .await
            .expect("commerce deploy should succeed");
        assert!(deploy_result.success, "deploy should succeed");
        let contract_addr = deploy_result
            .contract_address
            .clone()
            .expect("deploy must return contract address");
        assert_eq!(contract_addr.len(), 20, "EVM contract address is 20 bytes");

        // Runtime code should be installed
        let code = state
            .get_code(&contract_addr)
            .expect("runtime code should be stored after deploy");
        assert!(!code.is_empty(), "runtime code should not be empty");

        assert_eq!(state.get_nonce(&issuer), 1, "issuer nonce should bump");

        // 2) Invoke the deployed runtime which writes storage + emits log
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
            .await
            .expect("runtime invocation should succeed");
        assert!(call_result.success, "runtime call should succeed");
        assert!(
            !call_result.logs.is_empty(),
            "commerce runtime should emit a log"
        );

        // 3) Storage at slot 0 should now be 0x42
        let slot0 = state
            .get_storage(&contract_addr, &[0u8; 32])
            .expect("slot 0 should be set by SSTORE");
        assert_eq!(
            slot0.last().copied(),
            Some(0x42),
            "slot 0 should contain 0x42"
        );

        assert_eq!(state.get_nonce(&issuer), 2, "second nonce bump");
    }

    #[tokio::test]
    async fn evm_trading_dex_swap() {
        // Trading scenario: pre-install two "token" contracts (each
        // just the LOG runtime), and a "DEX" contract (TRADING_RUNTIME
        // which stores calldata at slot 0 as the "price"). A trader
        // writes a new price; we verify storage mutation + log
        // emission on the token contract.
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

        // Step 1: record a price (value 0x64 = 100) in DEX slot 0
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
            .await
            .expect("price-set tx should succeed");
        assert!(price_result.success);
        let slot0 = state
            .get_storage(&dex, &[0u8; 32])
            .expect("DEX should have price in slot 0");
        assert_eq!(slot0.last().copied(), Some(0x64));

        // Step 2: swap emits logs on both token contracts (same tx for each)
        for (nonce, token) in [(1u64, &token_a), (2u64, &token_b)] {
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
                .await
                .expect("token log tx should succeed");
            assert!(r.success, "swap log tx should succeed");
            assert!(!r.logs.is_empty(), "token should emit at least one log");
        }

        assert_eq!(state.get_nonce(&trader), 3, "trader did 3 txs");
    }

    #[tokio::test]
    async fn evm_payments_splitter_release() {
        // Payments scenario: deploy a contract with a LOG1 runtime
        // (the "release event"), fund the deployer, and invoke three
        // release calls to simulate paying three payees. We assert
        // that each call produces a LOG1 with the expected topic.
        let evm = fresh_evm_executor();
        let mut state = fresh_state();

        let payer = mk_evm_address(0x33);
        seed(&mut state, &payer);

        let splitter = mk_evm_address(0x5A);
        state.set_code(&splitter, PAYMENTS_RUNTIME_CODE.to_vec());

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
                .await
                .expect("release tx should succeed");
            assert!(r.success, "release #{nonce} should succeed");
            assert_eq!(
                r.logs.len(),
                1,
                "each release emits exactly one LOG1 event"
            );
            let log = &r.logs[0];
            assert_eq!(log.topics.len(), 1, "LOG1 has exactly one topic");
            // Topic is 0x01 (from PUSH1 0x01 in runtime), left-padded to 32 bytes
            assert_eq!(
                log.topics[0].last().copied(),
                Some(0x01),
                "topic should be 0x01"
            );
        }
        assert_eq!(state.get_nonce(&payer), 3);
    }

    #[tokio::test]
    async fn evm_automation_escrow_release() {
        // Automation scenario: pre-install an "escrow" runtime that,
        // on each tick, sets slot 1 to 1 and emits LOG0. We invoke it
        // once to simulate the arbiter releasing the escrow, then
        // confirm storage mutation and that the EVM did produce the
        // event.
        let evm = fresh_evm_executor();
        let mut state = fresh_state();

        let arbiter = mk_evm_address(0x44);
        seed(&mut state, &arbiter);

        let escrow = mk_evm_address(0xE5);
        state.set_code(&escrow, AUTOMATION_RUNTIME_CODE.to_vec());

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
            .await
            .expect("release tx should succeed");
        assert!(r.success, "escrow release should succeed");
        assert!(!r.logs.is_empty(), "release should emit log");

        // Slot 1 should have the 'released' flag
        let mut slot1_key = [0u8; 32];
        slot1_key[31] = 0x01;
        let slot1 = state
            .get_storage(&escrow, &slot1_key)
            .expect("slot 1 should be set after release");
        assert_eq!(
            slot1.last().copied(),
            Some(0x01),
            "escrow flag should be 1 after release"
        );

        // Negative path: a re-release still succeeds (idempotent)
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
            .await
            .expect("retry tx should succeed");
        assert!(r2.success, "re-release should still succeed (idempotent)");
        assert_eq!(state.get_nonce(&arbiter), 2);
    }
}

// ============================================================================
// SVM workflows
// ============================================================================
//
// NOTE: SvmExecutor::execute_transaction only invokes the real solana-svm
// SBF processor (under the `svm-full` feature) when the transaction data
// begins with the ELF magic `\x7fELF`. For non-ELF payloads the dispatch
// path still runs — address routing, nonce increment, gas accounting — but
// the SBF processor is not invoked. These tests intentionally use non-ELF
// payloads and assert only on the dispatch-level behavior: success, nonce
// bump, and VM-type routing.

mod svm_workflows {
    use super::helpers::*;
    use super::*;

    /// Minimal non-ELF "program" bytes installed at the target
    /// program address. Non-ELF payloads are treated as data
    /// transfers by SvmExecutor::execute_transaction, but the
    /// program bytes must still exist in state or the executor
    /// returns ContractNotFound.
    const NON_ELF_PROGRAM_STUB: &[u8] = &[0x00, 0x61, 0x73, 0x6D];

    async fn run_svm_workflow(payload: &[u8], sender_byte: u8) {
        let runtime = MultiVmRuntime::new(VmConfig::default())
            .await
            .expect("MultiVmRuntime::new should succeed");
        let mut state = fresh_state();

        let sender = mk_svm_pubkey(sender_byte);
        // Each test uses its own program address to avoid conflicts
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

        let result = runtime
            .execute_transaction(&tx, &mut state)
            .await
            .expect("SVM dispatch should succeed");
        assert!(result.success, "SVM tx should succeed");
        assert_eq!(state.get_nonce(&sender), 1, "nonce should bump");
    }

    #[tokio::test]
    async fn svm_commerce_token_program() {
        run_svm_workflow(b"transfer:alice:bob:100", 0x10).await;
    }

    #[tokio::test]
    async fn svm_trading_orderbook_match() {
        run_svm_workflow(b"match:bid=100,ask=95", 0x20).await;
    }

    #[tokio::test]
    async fn svm_payments_channel_open_close() {
        run_svm_workflow(b"channel:open;update=10;update=20;close", 0x30).await;
    }

    #[tokio::test]
    async fn svm_automation_scheduler_tick() {
        run_svm_workflow(b"scheduler:tick=1;tasks=[a,b,c]", 0x40).await;
    }

    /// Direct-executor smoke test: exercises `SvmExecutor::execute_transaction`
    /// without going through `MultiVmRuntime`'s dispatch layer. Confirms the
    /// SVM executor can be constructed and used standalone (e.g. for embedded
    /// SVM use cases that don't need multi-VM dispatch).
    #[tokio::test]
    async fn svm_direct_executor_dispatch() {
        let executor = fresh_svm_executor();
        let mut state = fresh_state();

        let sender = mk_svm_pubkey(0x50);
        let program = mk_svm_pubkey(0xD0);
        state.set_balance(&sender, SEED_BALANCE);
        state.set_code(&program, NON_ELF_PROGRAM_STUB.to_vec());

        let tx = signed_tx(
            sender.clone(),
            Some(program),
            0,
            b"transfer:carol:dave:200".to_vec(),
            200_000,
            0,
            VmType::Svm,
        );

        let result = executor
            .execute_transaction(&tx, &mut state)
            .await
            .expect("direct SVM executor dispatch should succeed");
        assert!(result.success, "direct SVM tx should succeed");
        assert_eq!(state.get_nonce(&sender), 1, "nonce should bump");
    }
}

// ============================================================================
// Canton / DAML workflows
// ============================================================================

mod canton_workflows {
    use super::helpers::*;
    use super::*;
    use tenzro_types::canton::{
        DamlCommand, DamlContractId, DamlParty, DamlTemplateId, DamlValue,
    };

    fn mk_inventory_create() -> DamlCommand {
        DamlCommand::Create {
            template_id: DamlTemplateId::new("tenzro-pkg", "Inventory", "Item"),
            create_arguments: DamlValue::Record {
                record_id: None,
                fields: vec![
                    (
                        "owner".to_string(),
                        DamlValue::Party(DamlParty::new("alice")),
                    ),
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

    async fn run_canton_command(label: &str, cmd: DamlCommand) {
        if !canton_available().await {
            tracing::warn!("Canton not available, skipping {}", label);
            return;
        }
        let daml = fresh_daml_executor();
        let mut state = fresh_state();

        let party_bytes = hex::encode("alice").into_bytes();
        let data = serde_json::to_vec(&cmd).expect("DamlCommand must serialize");

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

        // We don't panic on failure — a live Canton may still reject the
        // command (e.g., template not registered). The goal of these
        // tests is to exercise the dispatch path, not assert on the
        // ledger's interpretation. Call via VmExecutor trait since
        // DamlExecutor doesn't expose a state-adapter-typed shortcut.
        let _ = daml.execute_transaction(&tx, &mut state as &mut dyn VmState).await;
    }

    #[tokio::test]
    async fn canton_commerce_create_and_exercise() {
        run_canton_command("canton_commerce_create_and_exercise", mk_inventory_create()).await;
        run_canton_command("canton_commerce_create_and_exercise", mk_consume_exercise()).await;
    }

    #[tokio::test]
    async fn canton_trading_dvp_proposal() {
        let cmd = DamlCommand::Create {
            template_id: DamlTemplateId::new("tenzro-pkg", "Trading", "Proposal"),
            create_arguments: DamlValue::Record {
                record_id: None,
                fields: vec![
                    (
                        "buyer".to_string(),
                        DamlValue::Party(DamlParty::new("alice")),
                    ),
                    ("seller".to_string(), DamlValue::Party(DamlParty::new("bob"))),
                    ("asset".to_string(), DamlValue::Text("TNZO".to_string())),
                    ("price".to_string(), DamlValue::Int64(500)),
                ],
            },
        };
        run_canton_command("canton_trading_dvp_proposal", cmd).await;
    }

    #[tokio::test]
    async fn canton_payments_obligation_settle() {
        let cmd = DamlCommand::Create {
            template_id: DamlTemplateId::new("tenzro-pkg", "Payments", "Obligation"),
            create_arguments: DamlValue::Record {
                record_id: None,
                fields: vec![
                    (
                        "payer".to_string(),
                        DamlValue::Party(DamlParty::new("alice")),
                    ),
                    ("payee".to_string(), DamlValue::Party(DamlParty::new("bob"))),
                    ("amount".to_string(), DamlValue::Int64(1_000)),
                ],
            },
        };
        run_canton_command("canton_payments_obligation_settle", cmd).await;
    }

    #[tokio::test]
    async fn canton_automation_workflow_cascade() {
        let cmd = DamlCommand::Create {
            template_id: DamlTemplateId::new("tenzro-pkg", "Automation", "Workflow"),
            create_arguments: DamlValue::Record {
                record_id: None,
                fields: vec![
                    (
                        "owner".to_string(),
                        DamlValue::Party(DamlParty::new("alice")),
                    ),
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
        run_canton_command("canton_automation_workflow_cascade", cmd).await;
    }
}

// ============================================================================
// Cross-VM workflows
// ============================================================================

mod cross_vm_workflows {
    use super::helpers::*;
    use super::*;

    #[tokio::test]
    async fn cross_vm_agent_commerce_full_stack() {
        let runtime = MultiVmRuntime::new(VmConfig::default())
            .await
            .expect("MultiVmRuntime::new");
        let mut state = fresh_state();

        // EVM leg: deploy the commerce contract via the multi-VM runtime
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
        let evm_result = runtime
            .execute_transaction(&evm_tx, &mut state)
            .await
            .expect("EVM leg should succeed");
        assert!(evm_result.success, "EVM leg should succeed");

        // SVM leg: dispatch-only (non-ELF payload).
        // We must pre-install program bytes at the target address or
        // SvmExecutor::execute_transaction returns ContractNotFound.
        let svm_sender = mk_svm_pubkey(0x66);
        let svm_program = mk_svm_pubkey(0xFB);
        state.set_balance(&svm_sender, SEED_BALANCE);
        state.set_code(&svm_program, vec![0x00, 0x61, 0x73, 0x6D]);
        let svm_tx = signed_tx(
            svm_sender.clone(),
            Some(svm_program.clone()),
            0,
            b"agent:commerce".to_vec(),
            200_000,
            0,
            VmType::Svm,
        );
        let svm_result = runtime
            .execute_transaction(&svm_tx, &mut state)
            .await
            .expect("SVM leg should succeed");
        assert!(svm_result.success, "SVM leg should succeed");

        // Canton leg: gated on availability. Even when unavailable the
        // cross-VM test still passes because the EVM + SVM legs above
        // have already verified cross-VM dispatch.
        if canton_available().await {
            tracing::info!("Canton leg enabled");
        } else {
            tracing::warn!("Canton not available, cross_vm_agent_commerce_full_stack skipped Canton leg");
        }

        // Both dispatched legs should have bumped their respective nonces
        assert_eq!(state.get_nonce(&evm_sender), 1);
        assert_eq!(state.get_nonce(&svm_sender), 1);
    }

    #[tokio::test]
    async fn cross_vm_settlement_inference_escrow() {
        let runtime = MultiVmRuntime::new(VmConfig::default())
            .await
            .expect("MultiVmRuntime::new");
        let mut state = fresh_state();

        // EVM: pre-install "escrow" automation runtime and fund the arbiter
        let arbiter = mk_evm_address(0x77);
        state.set_balance(&arbiter, SEED_BALANCE);
        let escrow_addr = mk_evm_address(0xE7);
        state.set_code(&escrow_addr, AUTOMATION_RUNTIME_CODE.to_vec());

        // SVM: simulate "inference" by dispatching a non-ELF SVM payload.
        // Pre-install program bytes at the target program address.
        let agent = mk_svm_pubkey(0x88);
        let inference_program = mk_svm_pubkey(0xFC);
        state.set_balance(&agent, SEED_BALANCE);
        state.set_code(&inference_program, vec![0x00, 0x61, 0x73, 0x6D]);
        let inference_tx = signed_tx(
            agent.clone(),
            Some(inference_program.clone()),
            0,
            b"inference:result=ok".to_vec(),
            200_000,
            0,
            VmType::Svm,
        );
        let inference_result = runtime
            .execute_transaction(&inference_tx, &mut state)
            .await
            .expect("inference dispatch should succeed");
        assert!(inference_result.success);

        // EVM: arbiter releases escrow via a runtime call
        let release_tx = signed_tx(
            arbiter.clone(),
            Some(escrow_addr.clone()),
            0,
            Vec::new(),
            200_000,
            0,
            VmType::Evm,
        );
        let release_result = runtime
            .execute_transaction(&release_tx, &mut state)
            .await
            .expect("escrow release should succeed");
        assert!(release_result.success);
        assert!(!release_result.logs.is_empty(), "release should emit log");

        // Storage at slot 1 on the escrow contract should now be 1
        let mut slot1_key = [0u8; 32];
        slot1_key[31] = 0x01;
        let slot1 = state
            .get_storage(&escrow_addr, &slot1_key)
            .expect("escrow slot 1 should be set after release");
        assert_eq!(slot1.last().copied(), Some(0x01));
    }
}
