//! Ordered calls across the EVM and the SVM, executed as one transaction.
//!
//! A contract-call transaction carries a list of calls, each addressed to
//! one VM. The runtime runs them in order against the one native state, for
//! one caller, inside the single undo log block execution opens for the
//! transaction. Each call sees every earlier call's writes. If any call
//! fails, the transaction fails, and block execution undoes the writes of
//! every call in every VM and charges the gas used. Gas is the sum over the
//! calls, each VM charging the caller for its own at the transaction's gas
//! price, and the logs of all calls, in call order, are the transaction's
//! logs, so they carry its one transaction id into receipts and the event
//! commitment.
//!
//! A delegated agent's action may carry calls too. They run from the agent's
//! wallet, and each is held to the agent's terms on its own: its VM, the
//! code it calls and the value it carries are checked before it runs, and
//! the TNZO it moved out of the wallet is checked against the spending
//! limits after, whichever VM it ran in.

use tenzro_types::agent_terms::{AgentAction, agent_wallet};
use tenzro_types::transaction::{CallVm, VmCall};

use crate::error::{Result, VmError};
use crate::native::agent_terms;
use crate::runtime::MultiVmRuntime;
use crate::traits::{VmExecutor, VmState, VmType};
use crate::types::{ExecutionResult, VmTransaction};

/// Who the calls act for.
pub(crate) enum Caller<'a> {
    /// The transaction's sender.
    Sender,
    /// A delegated agent, from its wallet, within its terms.
    Agent(&'a AgentAction),
}

fn vm_type(vm: CallVm) -> VmType {
    match vm {
        CallVm::Evm => VmType::Evm,
        CallVm::Svm => VmType::Svm,
    }
}

/// Each call's output, length-prefixed: `count: u8`, then per call
/// `len: u32 BE | output`.
fn encode_outputs(outputs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![outputs.len() as u8];
    for o in outputs {
        out.extend_from_slice(&(o.len() as u32).to_be_bytes());
        out.extend_from_slice(o);
    }
    out
}

impl MultiVmRuntime {
    /// Run `calls` in order for `caller` under `tx`'s gas limit and price.
    ///
    /// Returns a failed result naming the first call that failed, with the
    /// gas used up to and including it; the caller of this function (block
    /// execution) undoes every write.
    pub(crate) async fn execute_calls(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        calls: &[VmCall],
        gas_limit: u64,
        caller: Caller<'_>,
    ) -> Result<ExecutionResult> {
        VmCall::validate_list(calls).map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
        let from = match &caller {
            Caller::Sender => tx.from.clone(),
            Caller::Agent(action) => agent_wallet(&action.agent_did).to_vec(),
        };
        let now_ms = crate::native::deterministic_now_ms(tx).max(0) as u64;

        let mut gas_used: u64 = 0;
        let mut supply_change: i128 = 0;
        let mut logs = Vec::new();
        let mut state_changes = Vec::new();
        let mut outputs = Vec::with_capacity(calls.len());

        for (i, call) in calls.iter().enumerate() {
            let label = format!("call {i} ({})", call.vm.name());
            let remaining = gas_limit.saturating_sub(gas_used);
            if remaining == 0 {
                return Ok(ExecutionResult::failed(
                    gas_used,
                    format!("{label}: out of gas"),
                ));
            }
            if let Caller::Agent(action) = &caller
                && let Err(why) = agent_terms::check_agent_call(state, action, call, now_ms)
            {
                return Ok(ExecutionResult::failed(gas_used, format!("{label}: {why}")));
            }

            // The EVM names an account by its 20-byte address, the SVM by
            // its 32-byte key; both are the one ledger account.
            let sender = match call.vm {
                CallVm::Evm => crate::state_adapter::ledger_account(&from).to_vec(),
                CallVm::Svm => from.clone(),
            };
            let mut sub = VmTransaction::new(
                sender.clone(),
                Some(call.to.clone()),
                call.value,
                call.data.clone(),
                remaining,
                tx.gas_price,
                state.get_nonce(&sender),
                vm_type(call.vm),
                tx.chain_id,
            );
            sub.block_timestamp_ms = tx.block_timestamp_ms;
            sub.block_height = tx.block_height;
            sub.block_base_fee = tx.block_base_fee;

            let before = state.get_balance(&from);
            let outcome = match self.get_executor(sub.vm_type) {
                Ok(executor) => executor.execute_transaction(&sub, state).await,
                Err(e) => Err(e),
            };
            let r = match outcome {
                Ok(r) => r,
                Err(e) => {
                    let charged = remaining.min(crate::gas::evm_gas_costs::TRANSACTION);
                    return Ok(ExecutionResult::failed(
                        gas_used.saturating_add(charged),
                        format!("{label}: {e}"),
                    ));
                }
            };
            gas_used = gas_used.saturating_add(r.gas_used);
            if !r.success {
                let reason = r.revert_reason.unwrap_or_else(|| "reverted".to_string());
                return Ok(ExecutionResult::failed(
                    gas_used,
                    format!("{label}: {reason}"),
                ));
            }

            // The EVM meters calldata and new storage itself; the SVM charges
            // for compute only, so its bandwidth and state growth are
            // metered here, at the same rates.
            let metered = match call.vm {
                CallVm::Evm => 0,
                CallVm::Svm => crate::ledger::bandwidth_gas(&call.data)
                    .saturating_add(crate::ledger::state_growth_gas(&r.state_changes)),
            };
            if metered > 0 {
                if gas_used.saturating_add(metered) > gas_limit {
                    return Ok(ExecutionResult::failed(
                        gas_limit,
                        format!("{label}: out of gas"),
                    ));
                }
                let fee = tx.gas_price.saturating_mul(metered as u128);
                let balance = state.get_balance(&from);
                if balance < fee {
                    return Ok(ExecutionResult::failed(
                        gas_used,
                        format!("{label}: insufficient balance for bandwidth and state growth"),
                    ));
                }
                state.set_balance(&from, balance - fee);
                gas_used = gas_used.saturating_add(metered);
            }

            if let Caller::Agent(action) = &caller {
                let fee = tx
                    .gas_price
                    .saturating_mul(r.gas_used.saturating_add(metered) as u128);
                let outflow = before
                    .saturating_sub(state.get_balance(&from))
                    .saturating_sub(fee);
                match agent_terms::record_agent_call_outflow(state, action, call, outflow, now_ms) {
                    Ok(changes) => state_changes.extend(changes),
                    Err(why) => {
                        return Ok(ExecutionResult::failed(gas_used, format!("{label}: {why}")));
                    }
                }
            }

            supply_change = supply_change.saturating_add(r.supply_change);
            logs.extend(r.logs);
            state_changes.extend(r.state_changes);
            outputs.push(r.output);
        }

        if gas_used > gas_limit {
            return Ok(ExecutionResult::failed(gas_used, "out of gas".to_string()));
        }
        let mut result =
            ExecutionResult::success(gas_used, encode_outputs(&outputs), logs, state_changes);
        result.supply_change = supply_change;
        Ok(result)
    }

    /// Execute a delegated agent's action and then its calls, as one
    /// transaction: the calls run only when the action itself is accepted,
    /// and a refused call fails the whole of it.
    pub(crate) async fn execute_agent_act(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
    ) -> Result<ExecutionResult> {
        let act = self
            .native_executor()
            .execute_transaction(tx, state)
            .await?;
        if !act.success {
            return Ok(act);
        }
        let (action, _) = agent_terms::decode_act(&tx.data[4..])?;
        if action.calls.is_empty() {
            return Ok(act);
        }
        let limit = tx.gas_limit.saturating_sub(act.gas_used);
        let calls = self
            .execute_calls(tx, state, &action.calls, limit, Caller::Agent(&action))
            .await?;
        if !calls.success {
            let mut failed = calls;
            failed.gas_used = failed.gas_used.saturating_add(act.gas_used);
            return Ok(failed);
        }
        let mut logs = act.logs;
        logs.extend(calls.logs);
        let mut state_changes = act.state_changes;
        state_changes.extend(calls.state_changes);
        let mut result = ExecutionResult::success(
            act.gas_used.saturating_add(calls.gas_used),
            calls.output,
            logs,
            state_changes,
        );
        result.supply_change = act.supply_change.saturating_add(calls.supply_change);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VmConfig;
    use crate::ledger::{BlockFees, TxOutcome, block_base_fee, execute_in_block};
    use crate::native::{SELECTOR_AGENT_ACT, SELECTOR_CONTRACT_CALL};
    use crate::precompiles::PRECOMPILE_TNZO_BRIDGE;
    use crate::state_adapter::StateAdapter;
    use crate::svm::spl_adapter::SPL_TOKEN_PROGRAM_ID;
    use tenzro_types::agent_terms::{AgentTerms, ServingNode, TermsScope};

    const ONE: u128 = 1_000_000_000_000_000_000;
    const GAS_PRICE: u128 = 20_000_000_000;
    const BLOCK_MS: i64 = 1_700_000_000_000;

    fn slot(a: [u8; 20]) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[..20].copy_from_slice(&a);
        s
    }

    fn erc20_transfer(to: [u8; 20], amount: u128) -> Vec<u8> {
        let mut d = crate::evm::wtnzo::selectors::TRANSFER.to_vec();
        d.extend_from_slice(&[0u8; 12]);
        d.extend_from_slice(&to);
        d.extend_from_slice(&[0u8; 16]);
        d.extend_from_slice(&amount.to_be_bytes());
        d
    }

    fn spl_transfer(source: [u8; 32], dest: [u8; 32], amount_spl: u64) -> Vec<u8> {
        let mut d = vec![3u8];
        for a in [source, dest, source] {
            d.extend_from_slice(&a);
        }
        d.push(3u8);
        d.extend_from_slice(&amount_spl.to_le_bytes());
        d
    }

    /// Token-2022 `TransferChecked` of `amount` of a 0-decimal `token` from
    /// `from` to `to`, accounts prefixed.
    fn token_2022_transfer(token: [u8; 32], from: [u8; 32], to: [u8; 32], amount: u64) -> Vec<u8> {
        let accounts = [from, token, to, from];
        let mut d = vec![accounts.len() as u8];
        accounts.iter().for_each(|a| d.extend_from_slice(a));
        d.push(12u8);
        d.extend_from_slice(&amount.to_le_bytes());
        d.push(0);
        d
    }

    fn call(vm: CallVm, to: &[u8], data: Vec<u8>) -> VmCall {
        VmCall {
            vm,
            to: to.to_vec(),
            value: 0,
            data,
        }
    }

    fn tenzro_tx(rt: &MultiVmRuntime, from: &[u8], data: Vec<u8>, nonce: u64) -> VmTransaction {
        VmTransaction::new(
            from.to_vec(),
            Some(from.to_vec()),
            0,
            data,
            3_000_000,
            GAS_PRICE,
            nonce,
            VmType::Tenzro,
            rt.config().chain_id,
        )
        .with_block_height(100)
        .with_block_timestamp_ms(BLOCK_MS)
    }

    fn contract_call(rt: &MultiVmRuntime, from: &[u8], calls: &[VmCall]) -> VmTransaction {
        let mut data = SELECTOR_CONTRACT_CALL.to_vec();
        data.extend_from_slice(&VmCall::encode_list(calls));
        tenzro_tx(rt, from, data, 0)
    }

    async fn run(rt: &MultiVmRuntime, state: &mut StateAdapter, tx: &VmTransaction) -> TxOutcome {
        let base = block_base_fee(state);
        let mut fees = BlockFees::default();
        execute_in_block(rt, state, tx, base, &mut fees).await
    }

    struct Accounts {
        alice: [u8; 32],
        bob: [u8; 20],
        svm: [u8; 32],
        carol: [u8; 20],
    }

    fn accounts(state: &mut StateAdapter) -> Accounts {
        let a = Accounts {
            alice: slot([0xA1; 20]),
            bob: [0xB0; 20],
            svm: [0x5A; 32],
            carol: [0xC4; 20],
        };
        state.set_balance(&a.alice, 10 * ONE);
        a
    }

    /// An EVM call, an SVM call and an EVM call again, each moving TNZO out
    /// of the same account through that VM's own token interface: 1 TNZO to
    /// Bob, 1 TNZO to an SVM key, then `last_amount` to Carol.
    fn evm_svm_evm_calls(a: &Accounts, last_amount: u128) -> Vec<VmCall> {
        vec![
            call(
                CallVm::Evm,
                &PRECOMPILE_TNZO_BRIDGE,
                erc20_transfer(a.bob, ONE),
            ),
            call(
                CallVm::Svm,
                &SPL_TOKEN_PROGRAM_ID,
                spl_transfer(a.alice, a.svm, 1_000_000_000),
            ),
            call(
                CallVm::Evm,
                &PRECOMPILE_TNZO_BRIDGE,
                erc20_transfer(a.carol, last_amount),
            ),
        ]
    }

    #[tokio::test]
    async fn an_evm_svm_evm_sequence_commits_as_one_transaction() {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let a = accounts(&mut state);

        let tx = contract_call(&rt, &a.alice, &evm_svm_evm_calls(&a, ONE));
        let (result, fee) = match run(&rt, &mut state, &tx).await {
            TxOutcome::Applied { result, fee } => (result, fee),
            other => panic!("expected the calls to apply, got {other:?}"),
        };

        assert_eq!(state.get_balance(&a.bob), ONE);
        assert_eq!(state.get_balance(&a.svm), ONE);
        assert_eq!(state.get_balance(&a.carol), ONE);
        assert_eq!(state.get_balance(&a.alice), 7 * ONE - fee);
        // The fee is the sum of what every call charged in its VM.
        assert_eq!(fee, GAS_PRICE * result.gas_used as u128);
        // Every VM's events are this one transaction's, in call order.
        let emitters: Vec<&[u8]> = result.logs.iter().map(|l| l.address.as_slice()).collect();
        let first_evm = emitters
            .iter()
            .position(|e| *e == PRECOMPILE_TNZO_BRIDGE.as_slice());
        let svm = emitters
            .iter()
            .position(|e| *e == SPL_TOKEN_PROGRAM_ID.as_slice());
        let last_evm = emitters
            .iter()
            .rposition(|e| *e == PRECOMPILE_TNZO_BRIDGE.as_slice());
        assert!(
            first_evm.is_some() && first_evm < svm && svm < last_evm,
            "{emitters:?}"
        );
        // The sender's nonce advanced once.
        assert_eq!(state.get_nonce(&a.alice), 1);
    }

    #[tokio::test]
    async fn a_failure_in_the_last_call_reverts_every_vm() {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let a = accounts(&mut state);

        // The last EVM call asks for more than is left after the first two.
        let tx = contract_call(&rt, &a.alice, &evm_svm_evm_calls(&a, 9 * ONE));
        let (fee, reason) = match run(&rt, &mut state, &tx).await {
            TxOutcome::Reverted {
                fee,
                reason,
                result,
            } => {
                assert!(result.logs.is_empty());
                (fee, reason)
            }
            other => panic!("expected a revert, got {other:?}"),
        };
        assert!(reason.contains("call 2 (evm)"), "{reason}");
        assert_eq!(state.get_balance(&a.bob), 0);
        assert_eq!(state.get_balance(&a.svm), 0);
        assert_eq!(state.get_balance(&a.carol), 0);
        assert_eq!(state.get_balance(&a.alice), 10 * ONE - fee);
        assert_eq!(state.get_nonce(&a.alice), 1);
    }

    #[tokio::test]
    async fn a_token_moves_through_every_vm_view_of_one_balance() {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let a = accounts(&mut state);
        let token = crate::token_ledger::test_token(&mut state, Vec::new());
        let factory = crate::precompiles::PRECOMPILE_TOKEN_FACTORY;
        let slot_of = |owner: &[u8]| crate::evm::token_factory::balance_slot(&token, owner);
        state.set_storage(
            &factory,
            &slot_of(&a.bob),
            crate::evm::precompile_host::u128_to_word(500).to_vec(),
        );

        // Bob's EVM address and its 32-byte form name the same balance, and
        // the SVM view moves it to an SVM key.
        let bob = slot(a.bob);
        state.set_balance(&bob, ONE);
        let tx = contract_call(
            &rt,
            &bob,
            &[call(
                CallVm::Svm,
                &crate::svm::spl_adapter::TOKEN_2022_PROGRAM_ID,
                token_2022_transfer(token, bob, a.svm, 200),
            )],
        );
        assert!(matches!(
            run(&rt, &mut state, &tx).await,
            TxOutcome::Applied { .. }
        ));
        assert_eq!(crate::token_ledger::balance(&state, &token, &a.bob), 300);
        assert_eq!(crate::token_ledger::balance(&state, &token, &bob), 300);
        assert_eq!(crate::token_ledger::balance(&state, &token, &a.svm), 200);
    }

    #[test]
    fn svm_calls_pay_for_bandwidth_and_new_state() {
        use crate::gas::evm_gas_costs::{SSTORE_SET, TXDATA_NONZERO, TXDATA_ZERO};
        use crate::ledger::{bandwidth_gas, state_growth_gas};
        use crate::types::StateChange;
        assert_eq!(bandwidth_gas(&[0, 1, 2]), TXDATA_ZERO + 2 * TXDATA_NONZERO);
        let change = |key: &[u8], old: u128, new: u128| {
            StateChange::new(
                vec![1],
                key.to_vec(),
                Some(old.to_le_bytes().to_vec()),
                Some(new.to_le_bytes().to_vec()),
            )
        };
        let changes = [
            change(b"balance", 0, 5),
            change(b"balance", 9, 4),
            change(b"nonce", 0, 1),
        ];
        assert_eq!(state_growth_gas(&changes), SSTORE_SET);
    }

    // ---- Delegated agents ---------------------------------------------------

    const CONTROLLER: &str = "did:tenzro:human:abc";
    const MACHINE: &str = "did:tenzro:machine:node";

    fn node_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
    }

    /// An agent allowed to "call" on the EVM, up to 2 TNZO
    /// a transaction, with a funded wallet and bond. Returns its DID.
    fn agent(state: &mut StateAdapter) -> String {
        let did = tenzro_types::agent_terms::agent_did(CONTROLLER, "buyer").unwrap();
        let point = node_key().verifying_key().to_sec1_point(false);
        let terms = AgentTerms {
            controller_did: CONTROLLER.into(),
            agent_name: "buyer".into(),
            delegation_scope: TermsScope {
                max_transaction_value: Some((2 * ONE).to_string()),
                max_daily_spend: Some((5 * ONE).to_string()),
                allowed_operations: vec!["call".into()],
                allowed_chains: vec!["evm".into()],
                ..Default::default()
            },
            capabilities: Vec::new(),
            serving_nodes: vec![ServingNode {
                machine_did: MACHINE.into(),
                operator_did: "did:tenzro:human:op".into(),
                dpop_public_key: hex::encode(&point.as_bytes()[1..]),
                dpop_jkt: String::new(),
                key_certification: String::new(),
                sealing_public_key: String::new(),
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        };
        crate::native::economy::count_wei_as_units_for_tests(state);
        agent_terms::store_terms_unapproved(
            state,
            &did,
            &agent_terms::StoredAgentTerms {
                terms,
                root: tenzro_types::agent_terms::RootKind::Passkey,
                version: 1,
                approval_digest: String::new(),
                updated_at_ms: 0,
                renewed_at_ms: Some(BLOCK_MS),
            },
        );
        state.set_balance(&agent_wallet(&did), 10 * ONE);
        state.set_balance(
            tenzro_token::bond::derive_bond_vault_address(&did).as_bytes(),
            1_000_000_000 * ONE,
        );
        did
    }

    fn agent_act(
        rt: &MultiVmRuntime,
        submitter: &[u8],
        did: &str,
        calls: Vec<VmCall>,
    ) -> VmTransaction {
        agent_act_n(rt, submitter, did, calls, 0)
    }

    fn agent_act_n(
        rt: &MultiVmRuntime,
        submitter: &[u8],
        did: &str,
        calls: Vec<VmCall>,
        nonce: u64,
    ) -> VmTransaction {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let action = AgentAction {
            asset: None,
            usd_e6: 0,
            payment: None,
            agent_did: did.to_string(),
            machine_did: MACHINE.into(),
            operation: "call".into(),
            counterparty: String::new(),
            amount: 0,
            chain: String::new(),
            payment_protocol: None,
            model: None,
            calls,
            escrow: None,
            remote_grant: None,
            ballot: None,
            veto_signal: None,
            nonce,
            tainted: false,
            step_up: None,
        };
        let sig: p256::ecdsa::Signature = node_key().sign_prehash(&action.digest()).unwrap();
        let mut data = SELECTOR_AGENT_ACT.to_vec();
        data.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({
                "action": action,
                "signature": sig.to_bytes().to_vec(),
            }))
            .unwrap(),
        );
        tenzro_tx(rt, submitter, data, 0)
    }

    /// A released escrow settles in a block: the payee is paid less the
    /// settlement fee, and the burned share is declared.
    #[tokio::test]
    async fn a_released_escrow_settles_in_a_block_with_its_fee_burned() {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let payer = slot([0x5E; 20]);
        let shop = slot([0xC0; 20]);
        state.set_balance(&payer, 10 * ONE);
        let mut create = crate::native::SELECTOR_ESCROW_CREATE.to_vec();
        create.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({
                "payee": tenzro_types::primitives::Address::new(shop),
                "amount": ONE as u64,
                "asset_id": tenzro_types::AssetId::tnzo(),
                "expires_at": (BLOCK_MS + 3_600_000) as u64,
                "release_conditions": tenzro_types::settlement::ReleaseConditions::ConsumerSignature,
            }))
            .unwrap(),
        );
        match run(&rt, &mut state, &tenzro_tx(&rt, &payer, create, 0)).await {
            TxOutcome::Applied { .. } => {}
            other => panic!("expected the escrow to open, got {other:?}"),
        }
        let escrow =
            crate::native::derive_escrow_id(&tenzro_types::primitives::Address::new(payer), 0);
        let proof = tenzro_types::settlement::ServiceProof::new(
            tenzro_types::settlement::ProofType::Cryptographic,
            Vec::new(),
        );
        let mut release = crate::native::SELECTOR_ESCROW_RELEASE.to_vec();
        release.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({ "escrow_id": escrow, "proof": proof }))
                .unwrap(),
        );
        match run(&rt, &mut state, &tenzro_tx(&rt, &payer, release, 1)).await {
            TxOutcome::Applied { .. } => {}
            other => panic!("expected the release to apply, got {other:?}"),
        }
        let got = state.get_balance(&shop);
        assert!(
            got > 0 && got < ONE,
            "the payee is paid less the settlement fee: {got}"
        );
    }

    /// A stream stopped by its payer settles what accrued in a block like a
    /// claim: the payee is paid less the settlement fee, and the burned share
    /// is declared.
    #[tokio::test]
    async fn a_stopped_stream_pays_the_settlement_fee_on_what_accrued() {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let payer = slot([0x5E; 20]);
        let host = slot([0xC1; 20]);
        state.set_balance(&payer, 10 * ONE);
        let epoch_ms = 60_000u64;
        let mut create = crate::native::SELECTOR_ESCROW_CREATE.to_vec();
        create.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({
                "payee": tenzro_types::primitives::Address::new(host),
                "amount": ONE as u64,
                "asset_id": tenzro_types::AssetId::tnzo(),
                "expires_at": (BLOCK_MS + 3_600_000) as u64,
                "release_conditions": tenzro_types::settlement::ReleaseConditions::Stream {
                    rate_per_epoch: ONE / 4,
                    epoch_ms,
                },
            }))
            .unwrap(),
        );
        match run(&rt, &mut state, &tenzro_tx(&rt, &payer, create, 0)).await {
            TxOutcome::Applied { .. } => {}
            other => panic!("expected the stream to open, got {other:?}"),
        }
        let escrow =
            crate::native::derive_escrow_id(&tenzro_types::primitives::Address::new(payer), 0);
        let mut refund = crate::native::SELECTOR_ESCROW_REFUND.to_vec();
        refund.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({ "escrow_id": escrow })).unwrap(),
        );
        // Two whole epochs have passed: half the stream accrued.
        let stop = tenzro_tx(&rt, &payer, refund, 1)
            .with_block_timestamp_ms(BLOCK_MS + 2 * epoch_ms as i64);
        match run(&rt, &mut state, &stop).await {
            TxOutcome::Applied { .. } => {}
            other => panic!("expected the stop to apply, got {other:?}"),
        }
        let got = state.get_balance(&host);
        assert!(
            got > 0 && got < ONE / 2,
            "the payee is paid what accrued less the settlement fee: {got}"
        );
    }

    /// An hour of a compute claim judged available settles in a block: the
    /// writer is paid the strike less the settlement fee, and the fee's
    /// burned share is declared, so the block's value check passes.
    #[tokio::test]
    async fn a_claim_hour_settles_in_a_block_with_its_fee_burned() {
        use tenzro_types::transaction::ComputeClaimOp;
        const H: i64 = crate::native::MARKET_EPOCH_MS;
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let writer = slot([0x6A; 20]);
        let buyer = slot([0x5E; 20]);
        state.set_balance(&writer, 100 * ONE);
        state.set_balance(&buyer, 100 * ONE);
        state.set_storage(
            &crate::native::SYSTEM_ADDRESS,
            b"compute_bond:did:gpu",
            serde_json::to_vec(&serde_json::json!({ "provider_address": hex::encode(writer) }))
                .unwrap(),
        );
        let start = (BLOCK_MS / H + 1) * H;
        let claim_tx = |from: &[u8], op: ComputeClaimOp, nonce: u64, at: i64| {
            let mut data = crate::native::SELECTOR_COMPUTE_CLAIM.to_vec();
            data.extend_from_slice(&serde_json::to_vec(&op).unwrap());
            tenzro_tx(&rt, from, data, nonce).with_block_timestamp_ms(at)
        };
        let offer = ComputeClaimOp::Offer {
            hardware_class: 3,
            region: "SG".into(),
            delivery_start_ms: start,
            epochs: 1,
            strike_per_epoch: ONE,
            collateral: ONE,
            provider_did: "did:gpu".into(),
            storage_descriptor: None,
            unit: None,
            units_per_epoch: 0,
        };
        for (from, op, nonce) in [
            (&writer, offer, 0),
            (
                &buyer,
                ComputeClaimOp::Accept {
                    claim_id: crate::native::compute_claim::claim_id_for(&writer, 0),
                    max_total: ONE,
                },
                0,
            ),
        ] {
            match run(&rt, &mut state, &claim_tx(from, op, nonce, BLOCK_MS)).await {
                TxOutcome::Applied { .. } => {}
                other => panic!("expected the claim to apply, got {other:?}"),
            }
        }
        let verdict = crate::native::SlaVerdict {
            available: true,
            up_stake: 1,
            down_stake: 0,
            attesters: 1,
            measured_capacity: None,
        };
        state.set_storage(
            &crate::native::SYSTEM_ADDRESS,
            format!("sla:{}:did:gpu", start / H).as_bytes(),
            serde_json::to_vec(&verdict).unwrap(),
        );
        let held = state.get_balance(&writer);
        let settle = ComputeClaimOp::Settle {
            claim_id: crate::native::compute_claim::claim_id_for(&writer, 0),
        };
        match run(&rt, &mut state, &claim_tx(&buyer, settle, 1, start + H + 1)).await {
            TxOutcome::Applied { .. } => {}
            other => panic!("expected the settlement to apply, got {other:?}"),
        }
        // The hour's strike less its fee, and the collateral back.
        let got = state.get_balance(&writer) - held;
        assert!(
            got > ONE && got < 2 * ONE,
            "the writer is paid the strike less the settlement fee: {got}"
        );
    }

    /// An agent allowed to pay on Tenzro, with a funded wallet and bond.
    fn paying_agent(state: &mut StateAdapter) -> String {
        let did = agent(state);
        let mut stored = agent_terms::read_agent_terms(state, &did).unwrap();
        stored.terms.delegation_scope.allowed_operations = vec!["pay".into()];
        stored.terms.delegation_scope.allowed_chains = vec!["tenzro".into()];
        agent_terms::store_terms_unapproved(state, &did, &stored);
        did
    }

    /// An agent's payment, settled in a block: the settlement fee's burned
    /// share leaves supply, and the block's value check must see it declared.
    #[tokio::test]
    async fn an_agents_payment_settles_in_a_block_with_its_fee_burned() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let did = paying_agent(&mut state);
        let submitter = slot([0x5E; 20]);
        state.set_balance(&submitter, ONE);
        let shop = slot([0xC0; 20]);
        let action = AgentAction {
            asset: None,
            usd_e6: 0,
            payment: Some(tenzro_types::agent_terms::AgentPayment {
                payment_id: "p1".into(),
                request_digest: [1u8; 32],
                quote_digest: [0u8; 32],
            }),
            agent_did: did.clone(),
            machine_did: MACHINE.into(),
            operation: "pay".into(),
            counterparty: hex::encode(shop),
            amount: ONE,
            chain: "tenzro".into(),
            payment_protocol: None,
            model: None,
            calls: Vec::new(),
            escrow: None,
            remote_grant: None,
            ballot: None,
            veto_signal: None,
            nonce: 0,
            tainted: false,
            step_up: None,
        };
        let sig: p256::ecdsa::Signature = node_key().sign_prehash(&action.digest()).unwrap();
        let mut data = SELECTOR_AGENT_ACT.to_vec();
        data.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({
                "action": action,
                "signature": sig.to_bytes().to_vec(),
            }))
            .unwrap(),
        );
        let tx = tenzro_tx(&rt, &submitter, data, 0);
        match run(&rt, &mut state, &tx).await {
            TxOutcome::Applied { .. } => {}
            other => panic!("expected the agent payment to apply, got {other:?}"),
        }
        let got = state.get_balance(&shop);
        assert!(
            got > 0 && got < ONE,
            "the payee is paid less the settlement fee: {got}"
        );
    }

    #[tokio::test]
    async fn an_agents_calls_run_from_its_wallet_within_its_terms() {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let did = agent(&mut state);
        let wallet = agent_wallet(&did);
        let submitter = slot([0x5E; 20]);
        state.set_balance(&submitter, ONE);
        let shop = [0xC0u8; 20];

        let tx = agent_act(
            &rt,
            &submitter,
            &did,
            vec![call(
                CallVm::Evm,
                &PRECOMPILE_TNZO_BRIDGE,
                erc20_transfer(shop, ONE),
            )],
        );
        match run(&rt, &mut state, &tx).await {
            TxOutcome::Applied { .. } => {}
            other => panic!("expected the in-scope call to apply, got {other:?}"),
        }
        assert_eq!(state.get_balance(&shop), ONE);
        assert!(state.get_balance(&wallet) < 9 * ONE + 1);
        assert_eq!(
            crate::native::read_agent_spent(&state, &did, BLOCK_MS as u64),
            ONE,
            "a call's outflow counts toward the agent's daily total"
        );
    }

    #[tokio::test]
    async fn an_agents_call_outside_its_terms_is_refused_in_any_vm() {
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let shop = [0xC0u8; 20];
        let receiver = [0xD5u8; 32];

        // The SVM is not among the agent's chains: the whole action is
        // refused, its in-scope EVM call included.
        let mut state = StateAdapter::new();
        let did = agent(&mut state);
        let wallet = agent_wallet(&did);
        let submitter = slot([0x5E; 20]);
        state.set_balance(&submitter, ONE);
        let tx = agent_act(
            &rt,
            &submitter,
            &did,
            vec![
                call(
                    CallVm::Evm,
                    &PRECOMPILE_TNZO_BRIDGE,
                    erc20_transfer(shop, ONE),
                ),
                call(
                    CallVm::Svm,
                    &SPL_TOKEN_PROGRAM_ID,
                    spl_transfer(wallet, receiver, 1),
                ),
            ],
        );
        match run(&rt, &mut state, &tx).await {
            TxOutcome::Reverted { reason, .. } => {
                assert!(reason.contains("call 1 (svm)"), "{reason}");
                assert!(
                    reason.contains("outside the agent's approved terms: chain"),
                    "{reason}"
                );
            }
            other => panic!("expected the out-of-scope call to be refused, got {other:?}"),
        }
        assert_eq!(state.get_balance(&shop), 0);
        assert_eq!(state.get_balance(&wallet), 10 * ONE);

        // A token transfer carries no value of its own, but what it moves
        // out of the wallet is held to the same per-transaction limit.
        let mut state = StateAdapter::new();
        let did = agent(&mut state);
        let wallet = agent_wallet(&did);
        state.set_balance(&submitter, ONE);
        let tx = agent_act(
            &rt,
            &submitter,
            &did,
            vec![call(
                CallVm::Evm,
                &PRECOMPILE_TNZO_BRIDGE,
                erc20_transfer(shop, 3 * ONE),
            )],
        );
        match run(&rt, &mut state, &tx).await {
            TxOutcome::Reverted { reason, .. } => {
                assert!(reason.contains("per-transaction limit"), "{reason}");
            }
            other => panic!("expected the over-limit call to be refused, got {other:?}"),
        }
        assert_eq!(state.get_balance(&shop), 0);
        assert_eq!(state.get_balance(&wallet), 10 * ONE);
    }

    /// The token views of the three VMs, driven by one random sequence of
    /// 10 000 operations. Holder transfers go through each VM's own view
    /// (the native Token transaction, the EVM token factory and SVM
    /// Token-2022 TransferChecked). Issuer operations go through
    /// the EVM factory's own freeze and forced-transfer selectors on the EVM
    /// state and through the native Token transaction elsewhere. After every
    /// operation each state agrees on the outcome and on every ledger slot,
    /// and the SVM Pausable extension reports the halt.
    #[tokio::test]
    async fn every_vm_view_of_a_token_agrees_over_ten_thousand_operations() {
        use crate::evm::token_factory::{selector, selectors};
        use crate::native::SELECTOR_TOKEN;
        use crate::precompiles::PRECOMPILE_TOKEN_FACTORY;
        use crate::svm::spl_adapter::{
            GET_MINT_EXTENSIONS, MintExtension, TOKEN_2022_PROGRAM_ID, decode_tlv,
        };
        use tenzro_types::token_op::TokenOp;
        use tenzro_types::token_policy::{Authority, IssuerAction, PowerManifest, TokenPolicy};

        const OPS: usize = 10_000;
        const NATIVE: usize = 0;
        const EVM: usize = 1;
        const SVM: usize = 2;
        let rt = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let addrs: [[u8; 20]; 4] = [[0x1E; 20], [0x41; 20], [0x42; 20], [0x43; 20]];
        let keys = addrs.map(slot);
        let issuer = 0;
        let spec = crate::token_ledger::TokenRecord {
            name: "T".into(),
            symbol: "T".into(),
            decimals: 0,
            total_supply: 1_000_000,
            creator: keys[issuer].to_vec(),
            max_supply: None,
            powers: PowerManifest {
                mint: Authority::Issuer,
                freeze: Authority::Issuer,
                halt: Authority::Issuer,
                force: Authority::Issuer,
                policy_change: Authority::Disabled,
            },
            policy: TokenPolicy {
                eligibility: Vec::new(),
                policy_timelock_ms: 0,
            },
            council: None,
            reserve_backing: None,
            pending: None,
        };
        let mut states: Vec<StateAdapter> = Vec::new();
        let mut token = [0u8; 32];
        for _ in 0..3 {
            let mut state = StateAdapter::new();
            for k in &keys {
                state.set_balance(k, 1_000_000 * ONE);
            }
            token = crate::token_ledger::create(&mut state, &keys[issuer], &spec, &mut Vec::new())
                .unwrap();
            states.push(state);
        }

        let word = |v: u128| {
            let mut w = [0u8; 32];
            w[16..].copy_from_slice(&v.to_be_bytes());
            w.to_vec()
        };
        let addr_word = |a: &[u8; 20]| {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(a);
            w.to_vec()
        };
        let evm = |from: [u8; 20], sel: [u8; 4], args: Vec<Vec<u8>>, nonce: u64| {
            let mut data = sel.to_vec();
            data.extend_from_slice(&token);
            args.iter().for_each(|a| data.extend_from_slice(a));
            VmTransaction::new(
                from.to_vec(),
                Some(PRECOMPILE_TOKEN_FACTORY.to_vec()),
                0,
                data,
                3_000_000,
                GAS_PRICE,
                nonce,
                VmType::Evm,
                rt.config().chain_id,
            )
            .with_block_height(100)
            .with_block_timestamp_ms(BLOCK_MS)
        };
        let typed = |from: &[u8], to: &[u8], data: Vec<u8>, vm: VmType, nonce: u64| {
            VmTransaction::new(
                from.to_vec(),
                Some(to.to_vec()),
                0,
                data,
                3_000_000,
                GAS_PRICE,
                nonce,
                vm,
                rt.config().chain_id,
            )
            .with_block_height(100)
            .with_block_timestamp_ms(BLOCK_MS)
        };
        let native = |from: &[u8], op: &TokenOp, nonce: u64| {
            let mut data = SELECTOR_TOKEN.to_vec();
            data.extend(serde_json::to_vec(op).unwrap());
            tenzro_tx(&rt, from, data, nonce)
        };
        let token_2022 = |from: [u8; 32], accounts: &[[u8; 32]], ix: &[u8], nonce: u64| {
            let mut data = vec![accounts.len() as u8];
            accounts.iter().for_each(|a| data.extend_from_slice(a));
            data.extend_from_slice(ix);
            typed(&from, &TOKEN_2022_PROGRAM_ID, data, VmType::Svm, nonce)
        };
        let applied =
            |o: &TxOutcome| matches!(o, TxOutcome::Applied { result, .. } if result.success);
        let snapshot = |state: &StateAdapter| {
            let mut v: Vec<u128> = Vec::new();
            for k in &keys {
                v.push(crate::token_ledger::balance(state, &token, k));
                v.push(crate::token_ledger::frozen(state, &token, k));
            }
            v.push(u128::from(crate::token_ledger::halted(state, &token)));
            v.push(
                crate::token_ledger::read_token(state, &token)
                    .unwrap()
                    .total_supply,
            );
            let holders = state
                .get_storage(
                    &PRECOMPILE_TOKEN_FACTORY,
                    &crate::evm::token_factory::holders_slot(&token),
                )
                .map_or(0, |w| u128::from_be_bytes(w[16..32].try_into().unwrap()));
            v.push(holders);
            v
        };
        let action = IssuerAction {
            reason_code: 1,
            evidence_hash: [0xEE; 32],
        };

        let mut seed = 0x7e57_5eed_u64;
        let mut next = move || {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let mut counts = [0usize; 6];
        // Every outcome and post-state in order, hashed: the sequence is
        // seeded, so this root is a fixed vector and a change in any view's
        // semantics changes it.
        let mut trace = <sha2::Sha256 as sha2::Digest>::new();
        for n in 0..OPS {
            let (a, b) = ((next() % 4) as usize, (next() % 4) as usize);
            let held = crate::token_ledger::balance(&states[NATIVE], &token, &keys[a]);
            let amount = u128::from(next()) % (held + 50).min(5_000_000);
            let pick = next() % 100;
            let mut outcomes = [false; 3];
            let mut txs: Vec<VmTransaction> = Vec::new();
            for (v, state) in states.iter().enumerate() {
                let nonce_of = |k: &[u8]| state.get_nonce(k);
                let issuer_op = |op: TokenOp| native(&keys[issuer], &op, nonce_of(&keys[issuer]));
                let tx = match pick {
                    0..55 => {
                        let (from, to) = (keys[a], keys[b]);
                        match v {
                            NATIVE => native(
                                &from,
                                &TokenOp::Transfer {
                                    token_id: token,
                                    to: to.to_vec(),
                                    amount,
                                },
                                nonce_of(&from),
                            ),
                            EVM => evm(
                                addrs[a],
                                selectors::TRANSFER,
                                vec![addr_word(&addrs[b]), word(amount)],
                                nonce_of(&addrs[a]),
                            ),
                            _ => {
                                let mut ix = vec![12u8];
                                ix.extend_from_slice(&u64::try_from(amount).unwrap().to_le_bytes());
                                ix.push(0);
                                token_2022(from, &[from, token, to, from], &ix, nonce_of(&from))
                            }
                        }
                    }
                    55..65 => native(
                        &keys[a],
                        &TokenOp::Burn {
                            token_id: token,
                            amount,
                        },
                        nonce_of(&keys[a]),
                    ),
                    65..78 if v == EVM => evm(
                        addrs[issuer],
                        selector("setFrozenTokens(bytes32,address,uint256)"),
                        vec![addr_word(&addrs[a]), word(amount)],
                        nonce_of(&addrs[issuer]),
                    ),
                    65..78 => issuer_op(TokenOp::SetFrozen {
                        token_id: token,
                        account: keys[a].to_vec(),
                        amount,
                        action,
                    }),
                    78..88 if v == EVM => evm(
                        addrs[issuer],
                        selector("forcedTransfer(bytes32,address,address,uint256)"),
                        vec![addr_word(&addrs[a]), addr_word(&addrs[b]), word(amount)],
                        nonce_of(&addrs[issuer]),
                    ),
                    78..88 => issuer_op(TokenOp::ForcedTransfer {
                        token_id: token,
                        from: keys[a].to_vec(),
                        to: keys[b].to_vec(),
                        amount,
                        action,
                    }),
                    88..93 => issuer_op(TokenOp::SetHalted {
                        token_id: token,
                        halted: !crate::token_ledger::halted(state, &token),
                        action,
                    }),
                    _ => issuer_op(TokenOp::Mint {
                        token_id: token,
                        to: keys[a].to_vec(),
                        amount,
                        reserves: Vec::new(),
                    }),
                };
                txs.push(tx);
            }
            let mut reasons: Vec<String> = Vec::new();
            for (v, tx) in txs.iter().enumerate() {
                let outcome = run(&rt, &mut states[v], tx).await;
                outcomes[v] = applied(&outcome);
                reasons.push(match &outcome {
                    TxOutcome::Applied { result, .. } => format!("{:?}", result.revert_reason),
                    TxOutcome::Reverted { reason, .. } => reason.clone(),
                    TxOutcome::Rejected(e) => e.to_string(),
                });
            }
            counts[match pick {
                0..55 => 0,
                55..65 => 1,
                65..78 => 2,
                78..88 => 3,
                88..93 => 4,
                _ => 5,
            }] += usize::from(outcomes[0]);
            assert!(
                outcomes.iter().all(|o| *o == outcomes[0]),
                "op {n} (kind {pick}, amount {amount}, {a}->{b}): outcomes differ {outcomes:?} {reasons:?}"
            );
            let want = snapshot(&states[NATIVE]);
            sha2::Digest::update(&mut trace, [u8::from(outcomes[0]), pick as u8]);
            want.iter()
                .for_each(|w| sha2::Digest::update(&mut trace, w.to_be_bytes()));
            for v in [EVM, SVM] {
                assert_eq!(
                    snapshot(&states[v]),
                    want,
                    "op {n} (kind {pick}): view {v} diverged"
                );
            }
            for (k, key) in keys.iter().enumerate() {
                let state = &states[NATIVE];
                assert!(
                    crate::token_ledger::frozen(state, &token, key)
                        <= crate::token_ledger::balance(state, &token, key),
                    "op {n}: holder {k} frozen past its balance"
                );
            }
            if (55..65).contains(&pick) {
                // The SVM view has no burn: Token-2022 Burn is refused and moves nothing.
                let from = keys[a];
                let mut ix = vec![8u8];
                ix.extend_from_slice(&1u64.to_le_bytes());
                let tx = token_2022(
                    from,
                    &[from, token, from],
                    &ix,
                    states[SVM].get_nonce(&from),
                );
                let before = snapshot(&states[SVM]);
                assert!(
                    !applied(&run(&rt, &mut states[SVM], &tx).await),
                    "op {n}: SVM Burn applied"
                );
                assert_eq!(snapshot(&states[SVM]), before);
            }
            if (88..93).contains(&pick) || n % 500 == 0 {
                let from = keys[1];
                let tx = token_2022(
                    from,
                    &[token],
                    &[GET_MINT_EXTENSIONS],
                    states[SVM].get_nonce(&from),
                );
                let TxOutcome::Applied { result, .. } = run(&rt, &mut states[SVM], &tx).await
                else {
                    panic!("op {n}: the extension read failed");
                };
                let paused =
                    decode_tlv(&result.output)
                        .unwrap()
                        .into_iter()
                        .find_map(|e| match e {
                            MintExtension::Pausable { paused, .. } => Some(paused),
                            _ => None,
                        });
                assert_eq!(
                    paused,
                    Some(crate::token_ledger::halted(&states[SVM], &token)),
                    "op {n}: paused != halted"
                );
            }
        }
        // Every kind of operation succeeded at some point.
        assert!(counts.iter().all(|c| *c > 0), "{counts:?}");
        let root = hex::encode(sha2::Digest::finalize(trace));
        assert_eq!(
            root, CROSS_VM_TRACE_ROOT,
            "the seeded 10 000-operation trace changed"
        );
    }

    /// SHA-256 over the outcome, operation kind and post-state of every step
    /// of the seeded sequence in
    /// [`every_vm_view_of_a_token_agrees_over_ten_thousand_operations`].
    const CROSS_VM_TRACE_ROOT: &str =
        "81124efccd81a091a0487d20fae64305f4d4b5fbd8609333034e4b83f994f0f8";
}
