//! Training rounds on chain and the provenance of what they produced.
//!
//! `tenzro_commitTrainingRound` commits a round this machine trained against
//! the milestone escrow that pays for it: the round's receipt, signed through
//! a session key this machine's hardware identity certified, sent as a
//! training proof transaction. `tenzro_settleTrainingRound` settles a round
//! once its challenge window has closed, releasing the milestone.
//! `tenzro_trainedModelProvenance` signs the receipt for the weights a job
//! produced and hands it out with its provenance pack, which anyone checks
//! offline from the genesis anchor ([`tenzro_types::training_provenance`]).

use std::sync::Arc;

use serde_json::Value;
use tenzro_types::training_provenance::{
    ROUND_KIND, SignedTrainedModelReceipt, TRAINER_KIND, TrainedModelReceipt,
    TrainingProvenancePack,
};
use tenzro_types::training_verification::training_receipt_slot;

use crate::evidence_pack::{Certified, certified, prove};
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Most rounds one receipt names.
pub const MAX_ROUNDS: usize = 1024;

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

/// `tenzro_trainedModelProvenance { model_id, base_sha256, output_sha256, rounds }`:
/// sign, as this trainer machine, the receipt for the weights a training job
/// produced and return its provenance pack. `rounds` are the
/// receipt ids of the job's committed rounds, first to last, each trained by
/// this machine and released. The receipt names the state the last round
/// ended at, read from chain state.
pub(crate) async fn handle_trained_model(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let request = TrainedModelRequest::from_params(params)?;
    let signer = node
        .records()
        .cloned()
        .ok_or_else(|| err(-32000, "this machine has no hardware identity to sign with"))?;
    let pack = provenance_pack(&signer, certified(node)?, request)?;
    serde_json::to_value(pack).map_err(|e| err(-32603, e.to_string()))
}

/// What `tenzro_trainedModelProvenance` asks for.
pub(crate) struct TrainedModelRequest {
    model_id: String,
    base_sha256: String,
    output_sha256: String,
    rounds: Vec<String>,
}

impl TrainedModelRequest {
    fn from_params(params: Option<Value>) -> Result<Self, JsonRpcError> {
        let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
        let text = |k: &str| {
            params
                .get(k)
                .and_then(Value::as_str)
                .map(|s| s.trim_start_matches("0x").to_ascii_lowercase())
                .ok_or_else(|| err(-32602, format!("'{k}' is required")))
        };
        let model_id = params
            .get("model_id")
            .and_then(Value::as_str)
            .ok_or_else(|| err(-32602, "'model_id' is required"))?
            .to_string();
        let base_sha256 = text("base_sha256")?;
        let output_sha256 = text("output_sha256")?;
        let rounds: Vec<String> = params
            .get("rounds")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.trim_start_matches("0x").to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        if rounds.is_empty() || rounds.len() > MAX_ROUNDS {
            return Err(err(
                -32602,
                format!("'rounds' names 1 to {MAX_ROUNDS} committed rounds"),
            ));
        }
        Ok(Self {
            model_id,
            base_sha256,
            output_sha256,
            rounds,
        })
    }
}

/// The provenance pack for `request`, its receipt signed by `signer`, under
/// the certified state `at`. Only a pack that verifies is returned.
pub(crate) fn provenance_pack(
    signer: &dyn tenzro_crypto::batch::RecordSigner,
    at: Certified,
    request: TrainedModelRequest,
) -> Result<TrainingProvenancePack, JsonRpcError> {
    let TrainedModelRequest {
        model_id,
        base_sha256,
        output_sha256,
        rounds,
    } = request;
    let trainer_did = crate::tool_call_record::signer_did(signer);

    let Certified {
        storage,
        trie,
        height,
        state_root,
        state_trie_hash,
        checkpoint,
    } = at;
    let chain = tenzro_vm::StateAdapter::with_storage(storage);
    let last = rounds.last().map(String::as_str).unwrap_or_default();
    let end_checkpoint = tenzro_vm::native::training_proof::read_training_record(&chain, last)
        .ok_or_else(|| {
            err(
                -32004,
                format!("no round {last} is committed at height {height}"),
            )
        })?
        .receipt
        .end_checkpoint;

    let receipt = TrainedModelReceipt {
        model_id,
        base_sha256,
        output_sha256,
        trainer_did: trainer_did.clone(),
        rounds: rounds.clone(),
        end_checkpoint,
        signed_at_ms: tenzro_crypto::session::now_ms(),
    };
    receipt.validate().map_err(|e| err(-32602, e))?;
    let signature = signer
        .sign_record(&receipt.digest())
        .map_err(|e| err(-32603, e.to_string()))?;

    let mut records = vec![prove(
        &trie,
        height,
        TRAINER_KIND,
        &trainer_did,
        tenzro_types::identity::identity_slot(&trainer_did),
    )?];
    for id in &rounds {
        records.push(prove(
            &trie,
            height,
            ROUND_KIND,
            id,
            training_receipt_slot(id),
        )?);
    }
    let pack = TrainingProvenancePack {
        receipt: SignedTrainedModelReceipt {
            receipt,
            signature: serde_json::to_vec(&signature).map_err(|e| err(-32603, e.to_string()))?,
        },
        state_height: height,
        state_root: state_root.clone(),
        state_trie_hash,
        checkpoint,
        records,
    };
    // Hand out only what verifies: a round another machine trained, one not
    // yet released, or a gap in the rounds is refused here, not downstream.
    let root: [u8; 32] = hex::decode(&state_root)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err(-32603, "the certified state root is not 32 bytes"))?;
    tenzro_consensus::training_provenance::verify_provenance_under_root(&pack, &root)
        .map_err(|e| err(-32003, e))?;
    Ok(pack)
}

/// A round's receipt signed by `signer` and wrapped in the commit operation
/// that carries it: [`TrainingProofOp::Commit`], the receipt digest
/// signed in a hardware batch.
pub fn sign_round_op(
    signer: &dyn tenzro_crypto::batch::RecordSigner,
    receipt: tenzro_types::training_verification::TrainingReceipt,
) -> Result<tenzro_types::training_verification::TrainingProofOp, String> {
    use tenzro_types::training_verification::{SignedTrainingReceipt, TrainingProofOp};
    let signature = signer
        .sign_record(&receipt.digest())
        .map_err(|e| e.to_string())?;
    Ok(TrainingProofOp::Commit {
        receipt: SignedTrainingReceipt {
            receipt,
            batched: hex::encode(serde_json::to_vec(&signature.batched).map_err(|e| e.to_string())?),
            tee: None,
        },
    })
}

async fn submit_op(
    node: &Arc<TenzroNode>,
    op: tenzro_types::training_verification::TrainingProofOp,
) -> Result<String, JsonRpcError> {
    let submitter = node
        .ledger_submitter()
        .cloned()
        .ok_or_else(|| err(-32000, "this node has no ledger account to send from"))?;
    let bytes = serde_json::to_vec(&op)
        .map_err(|e| err(-32603, e.to_string()))?
        .len() as u64;
    let gas = tenzro_vm::native::GAS_TRAINING_PROOF
        + tenzro_vm::native::GAS_TRAINING_PROOF_BYTE * (bytes + 64);
    submitter
        .submit_with_gas(
            submitter.address(),
            tenzro_types::TransactionType::TrainingProof { op },
            gas * 2,
        )
        .await
        .map_err(|e| err(-32000, e))
}

/// `tenzro_commitTrainingRound { escrow_id, round, start_checkpoint,
/// shard_commitment, hyperparameters, steps, end_checkpoint, step_root,
/// kernel_class }`: commit a round this machine trained against the escrow
/// that pays for it. The fields are those `tenzro_trainRound` answers with
/// (`start_root`, `data_root`, `recipe_hash`, `steps`, `end_root`,
/// `log_head`, `kernel_class`). Returns the receipt id and the transaction.
pub(crate) async fn handle_commit_round(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| err(-32602, "Missing params"))?;
    let signer = node
        .records()
        .cloned()
        .ok_or_else(|| err(-32000, "this machine has no hardware identity to sign with"))?;
    let (receipt_id, op) = commit_op(&signer, &params)?;
    let tx_hash = submit_op(node, op).await?;
    Ok(serde_json::json!({ "receipt_id": receipt_id, "tx_hash": tx_hash }))
}

/// The operation `tenzro_commitTrainingRound` sends for `params`, the
/// round's receipt signed by `signer`, with the receipt id.
pub(crate) fn commit_op(
    signer: &dyn tenzro_crypto::batch::RecordSigner,
    params: &Value,
) -> Result<(String, tenzro_types::training_verification::TrainingProofOp), JsonRpcError> {
    let text = |k: &str| {
        params
            .get(k)
            .and_then(Value::as_str)
            .map(|s| s.trim_start_matches("0x").to_ascii_lowercase())
            .ok_or_else(|| err(-32602, format!("'{k}' is required")))
    };
    let number = |k: &str| {
        params
            .get(k)
            .and_then(Value::as_u64)
            .ok_or_else(|| err(-32602, format!("'{k}' is required")))
    };
    let receipt = tenzro_types::training_verification::TrainingReceipt {
        escrow_id: text("escrow_id")?,
        trainer_did: crate::tool_call_record::signer_did(signer),
        round: number("round")?,
        start_checkpoint: text("start_checkpoint")?,
        shard_commitment: text("shard_commitment")?,
        hyperparameters: text("hyperparameters")?,
        steps: number("steps")?,
        end_checkpoint: text("end_checkpoint")?,
        step_root: text("step_root")?,
        kernel_class: params
            .get("kernel_class")
            .and_then(Value::as_str)
            .ok_or_else(|| err(-32602, "'kernel_class' is required"))?
            .to_string(),
        signed_at_ms: tenzro_crypto::session::now_ms(),
    };
    receipt.digests().map_err(|e| err(-32602, e))?;
    let receipt_id = receipt.receipt_id();
    let op = sign_round_op(signer, receipt).map_err(|e| err(-32603, e))?;
    Ok((receipt_id, op))
}

/// `tenzro_settleTrainingRound { receipt_id }`: settle a committed round
/// whose challenge window has closed. The module releases the milestone to
/// the trainer, or returns it to the payer after an upheld challenge.
pub(crate) async fn handle_settle_round(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let (receipt_id, op) = settle_op(params.as_ref())?;
    // A settle the chain would revert is refused here, so the operator learns
    // it now instead of from a transaction that fails after this call said ok.
    let storage = node
        .storage()
        .ok_or_else(|| err(-32603, "storage not initialised"))?
        .clone();
    let record = tenzro_vm::native::training_proof::read_training_record(
        &tenzro_vm::StateAdapter::with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>),
        &receipt_id,
    );
    if let Some(why) = settle_refusal(
        &receipt_id,
        record.as_ref(),
        chain_time_ms(node, storage).await?,
    ) {
        return Err(err(-32004, why));
    }
    let tx_hash = submit_op(node, op).await?;
    Ok(serde_json::json!({ "receipt_id": receipt_id, "tx_hash": tx_hash }))
}

/// Why the chain would revert a settle of `record` at chain time `now_ms`:
/// no round committed under `receipt_id`, a round already settled, or one
/// whose challenge window has not closed. The chain decides again when the
/// settle executes (a challenge still being decided is left to it).
pub(crate) fn settle_refusal(
    receipt_id: &str,
    record: Option<&tenzro_vm::native::training_proof::TrainingRecord>,
    now_ms: i64,
) -> Option<String> {
    let Some(record) = record else {
        return Some(format!("no training receipt {receipt_id} is committed"));
    };
    if record.settled.is_some() {
        return Some("this round is already settled".into());
    }
    let closes = record.window_end_ms();
    (now_ms <= closes).then(|| {
        format!("this round's challenge window is still open until {closes} (chain time {now_ms})")
    })
}

/// The time of the latest block, ms: the clock the chain settles by.
async fn chain_time_ms(
    node: &Arc<TenzroNode>,
    storage: Arc<tenzro_storage::RocksDbStore>,
) -> Result<i64, JsonRpcError> {
    use tenzro_storage::BlockStore;
    let blocks = tenzro_storage::block_store::BlockStoreImpl::new(storage)
        .map_err(|e| err(-32603, format!("block store: {e}")))?;
    let block = blocks
        .get_block_by_height(tenzro_types::BlockHeight::new(node.chain_tip_height()))
        .await
        .map_err(|e| err(-32603, format!("latest block: {e}")))?
        .ok_or_else(|| err(-32004, "no block at the chain tip yet"))?;
    Ok(block.header.timestamp.as_millis())
}

/// The operation `tenzro_settleTrainingRound` sends for `params`, with the
/// receipt id.
pub(crate) fn settle_op(
    params: Option<&Value>,
) -> Result<(String, tenzro_types::training_verification::TrainingProofOp), JsonRpcError> {
    let receipt_id = params
        .and_then(|p| p.get("receipt_id"))
        .and_then(Value::as_str)
        .map(|s| s.trim_start_matches("0x").to_ascii_lowercase())
        .ok_or_else(|| err(-32602, "'receipt_id' is required"))?;
    Ok((
        receipt_id.clone(),
        tenzro_types::training_verification::TrainingProofOp::Settle { receipt_id },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signed receipt carries what the training proof module checks:
    /// the hardware identity signed the batch holding the receipt digest.
    #[test]
    fn a_round_receipt_is_signed_as_the_training_proof_module_checks_it() {
        let id: Arc<dyn tenzro_crypto::composite::HybridSigner> =
            Arc::new(tenzro_crypto::testing::TestHybridSigner::p256_only(50));
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(id);
        let receipt = tenzro_types::training_verification::TrainingReceipt {
            escrow_id: hex::encode([1; 32]),
            trainer_did: crate::tool_call_record::signer_did(&signer),
            round: 0,
            start_checkpoint: hex::encode([2; 32]),
            shard_commitment: hex::encode([3; 32]),
            hyperparameters: hex::encode([4; 32]),
            steps: 10,
            end_checkpoint: hex::encode([5; 32]),
            step_root: hex::encode([6; 32]),
            kernel_class: "sm_121".into(),
            signed_at_ms: tenzro_crypto::session::now_ms(),
        };
        let tenzro_types::training_verification::TrainingProofOp::Commit { receipt: signed } =
            sign_round_op(&signer, receipt.clone()).unwrap()
        else {
            panic!("a batched commit");
        };
        let sig: tenzro_crypto::batch::BatchedSignature =
            serde_json::from_slice(&hex::decode(&signed.batched).unwrap()).unwrap();
        let check = |r: &tenzro_types::training_verification::TrainingReceipt| {
            tenzro_crypto::batch::RecordSignature::batched(sig.clone()).verify_record_at(
                signer.identity(),
                &r.digest(),
                r.signed_at_ms,
            )
        };
        assert!(check(&receipt).is_ok());
        let mut other = receipt;
        other.end_checkpoint = hex::encode([9; 32]);
        assert!(check(&other).is_err());
    }

    const TNZO: u128 = 1_000_000_000_000_000_000;

    /// A ledger account that signs its transactions with a test key.
    struct Account {
        key: tenzro_crypto::composite::testing::TestHybridSigner,
        nonce: u64,
    }

    impl Account {
        fn new(seed: u8) -> Self {
            Self {
                key: tenzro_crypto::composite::testing::TestHybridSigner::hybrid(seed),
                nonce: 0,
            }
        }

        /// `tx_type` signed by this account, as block execution runs it at
        /// `at_ms`.
        fn send(
            &mut self,
            tx_type: tenzro_types::TransactionType,
            at_ms: i64,
        ) -> tenzro_vm::VmTransaction {
            use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
            let mut tx = tenzro_types::transaction::Transaction::new(
                tenzro_types::primitives::ChainId::from(1),
                self.key.address(),
                tenzro_types::primitives::Address::default(),
                tenzro_types::primitives::Nonce::from(self.nonce),
                tx_type,
                10_000_000,
                1,
            );
            tx.valid_until = tenzro_types::primitives::Timestamp::new(at_ms + 3_600_000);
            self.nonce += 1;
            let sig = self
                .key
                .sign(SignatureContext::Transaction, tx.hash().as_bytes())
                .unwrap();
            let signed = tenzro_types::transaction::SignedTransaction::new(
                tx,
                self.key.public_key().p256.clone(),
                sig,
            );
            let mut vm = crate::event_loop::convert_transaction(&signed);
            vm.block_timestamp_ms = Some(at_ms);
            vm
        }
    }

    /// The chain at one state version: `txs` execute in order, each must
    /// succeed, and every write is committed to the state trie at `version`.
    /// Returns each transaction's output and the root.
    async fn block(
        store: &Arc<dyn tenzro_storage::KvStore>,
        version: u64,
        setup: impl FnOnce(&mut tenzro_vm::StateAdapter),
        txs: Vec<tenzro_vm::VmTransaction>,
    ) -> (Vec<Vec<u8>>, [u8; 32]) {
        use tenzro_storage::state_trie::capture;
        let runtime =
            tenzro_vm::MultiVmRuntime::new(tenzro_vm::VmConfig::default().with_chain_id(1))
                .await
                .unwrap();
        let writes = capture::WriteSet::new();
        let mut state = tenzro_vm::StateAdapter::with_storage(store.clone());
        capture::in_thread(writes.clone(), || setup(&mut state));
        let mut outputs = Vec::new();
        for tx in &txs {
            let r = capture::in_task(writes.clone(), runtime.execute_transaction(tx, &mut state))
                .await
                .unwrap();
            assert!(r.success, "{r:?}");
            outputs.push(r.output);
        }
        capture::in_thread(writes.clone(), || state.commit()).unwrap();
        let root = tenzro_storage::StateTrie::new(store.clone())
            .commit(version, &writes.take())
            .unwrap();
        (outputs, root.as_bytes().try_into().unwrap())
    }

    fn at(store: &Arc<dyn tenzro_storage::KvStore>, version: u64, root: [u8; 32]) -> Certified {
        let trie = tenzro_storage::StateTrie::new(store.clone());
        Certified {
            storage: store.clone(),
            state_trie_hash: trie.scheme_at(version).unwrap(),
            trie,
            height: version,
            state_root: hex::encode(root),
            checkpoint: Value::Null,
        }
    }

    /// A round committed with `tenzro_commitTrainingRound` and settled with
    /// `tenzro_settleTrainingRound` runs as a training proof transaction
    /// through the VM: the commit records the round against its milestone
    /// escrow, the settle after the challenge window pays the trainer, and
    /// the trained model's provenance pack proves the released round under
    /// the committed state root. Before the settle, no pack is handed out.
    #[tokio::test]
    async fn a_committed_and_settled_round_is_on_chain_and_in_the_provenance_pack() {
        use tenzro_vm::native::training_proof::{
            RoundSettlement, read_training_record, training_executor,
        };
        use tenzro_vm::traits::VmState as _;

        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn tenzro_storage::KvStore> =
            Arc::new(tenzro_storage::RocksDbStore::open_default(dir.path()).unwrap());

        // The trainer machine's hardware identity, registered on chain.
        let identity: Arc<dyn tenzro_crypto::composite::HybridSigner> =
            Arc::new(tenzro_crypto::testing::TestHybridSigner::p256_only(60));
        let machine = tenzro_crypto::batch::ImmediateRecordSigner::new(identity);
        let did = crate::tool_call_record::signer_did(&machine);
        let mut trainer = Account::new(61);
        let mut payer = Account::new(62);
        let trainer_account = trainer.key.address();
        let payer_account = payer.key.address();

        let t0 = tenzro_crypto::session::now_ms() as i64 + 60_000;
        let escrowed = 50 * TNZO;
        let bond_tx = trainer.send(
            tenzro_types::TransactionType::PostComputeBond {
                provider_did: did.clone(),
                amount: 100 * TNZO,
            },
            t0,
        );
        let escrow_tx = payer.send(
            tenzro_types::TransactionType::CreateEscrow {
                payee: trainer_account,
                amount: escrowed,
                asset_id: tenzro_types::asset::AssetId::tnzo(),
                usd_e6: 0,
                expires_at: (t0 + 30 * 24 * 3_600_000) as u64,
                release_conditions: tenzro_types::settlement::ReleaseConditions::Executor {
                    executor: training_executor(),
                },
                reference: None,
            },
            t0,
        );
        let registered = tenzro_types::identity::RegisterIdentityPayload {
            did: did.clone(),
            identity_type: "machine".into(),
            display_name: String::new(),
            controller_pubkey: machine.identity().p256.clone(),
            key_type: "p256".into(),
            wallet_id: String::new(),
            wallet_address: trainer_account,
            pq_verifying_key: Vec::new(),
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        let enrolments = {
            use tenzro_crypto::composite::HybridSigner as _;
            [
                trainer.key.public_key().clone(),
                payer.key.public_key().clone(),
            ]
        };
        let (out, _) = block(
            &store,
            1,
            |s| {
                s.set_storage(
                    &tenzro_vm::native::SYSTEM_ADDRESS,
                    tenzro_types::identity::identity_slot(&did).as_bytes(),
                    serde_json::to_vec(&registered).unwrap(),
                );
                s.set_balance(trainer_account.as_bytes(), 1_000 * TNZO);
                s.set_balance(payer_account.as_bytes(), 1_000 * TNZO);
                for key in &enrolments {
                    tenzro_vm::account_keys::set_enrolled_pq_key(
                        s,
                        &key.p256,
                        key.pq.clone().expect("a hybrid signer"),
                        &mut Vec::new(),
                    );
                }
            },
            vec![bond_tx, escrow_tx],
        )
        .await;
        let escrow_id = hex::encode(&out[1]);

        // tenzro_commitTrainingRound, as the trainer machine answers it.
        let (receipt_id, commit) = commit_op(
            &machine,
            &serde_json::json!({
                "escrow_id": format!("0x{escrow_id}"),
                "round": 0,
                "start_checkpoint": hex::encode([2; 32]),
                "shard_commitment": hex::encode([3; 32]),
                "hyperparameters": hex::encode([4; 32]),
                "steps": 10,
                "end_checkpoint": hex::encode([5; 32]),
                "step_root": hex::encode([6; 32]),
                "kernel_class": "sm_121",
            }),
        )
        .unwrap();
        let commit_tx = trainer.send(
            tenzro_types::TransactionType::TrainingProof { op: commit },
            t0,
        );
        let (_, root) = block(&store, 2, |_| {}, vec![commit_tx]).await;
        let chain = tenzro_vm::StateAdapter::with_storage(store.clone());
        let committed = read_training_record(&chain, &receipt_id).expect("the round is on chain");
        assert_eq!(committed.receipt.trainer_did, did);
        assert_eq!(committed.receipt.escrow_id, escrow_id);
        assert_eq!(committed.receipt.end_checkpoint, hex::encode([5; 32]));
        assert!(committed.settled.is_none());

        // The node refuses a settle the chain would revert, before sending it.
        let early = settle_refusal(&receipt_id, Some(&committed), committed.window_end_ms());
        assert!(early.is_some_and(|w| w.contains("challenge window is still open")));
        assert!(
            settle_refusal(&receipt_id, Some(&committed), committed.window_end_ms() + 1).is_none()
        );
        let unknown = settle_refusal("00", None, committed.window_end_ms() + 1);
        assert!(unknown.is_some_and(|w| w.contains("no training receipt 00 is committed")));

        let request = || {
            TrainedModelRequest::from_params(Some(serde_json::json!({
                "model_id": "qwen3-0.6b",
                "base_sha256": hex::encode([9; 32]),
                "output_sha256": hex::encode([10; 32]),
                "rounds": [receipt_id.clone()],
            })))
            .unwrap()
        };
        // A round not yet released is not provenance.
        assert!(provenance_pack(&machine, at(&store, 2, root), request()).is_err());

        // tenzro_settleTrainingRound once the challenge window has closed.
        let (settled_id, settle) =
            settle_op(Some(&serde_json::json!({ "receipt_id": receipt_id }))).unwrap();
        assert_eq!(settled_id, receipt_id);
        let paid_before = chain.get_balance(trainer_account.as_bytes());
        let settle_tx = trainer.send(
            tenzro_types::TransactionType::TrainingProof { op: settle },
            committed.window_end_ms() + 1,
        );
        let (_, root) = block(&store, 3, |_| {}, vec![settle_tx]).await;
        let chain = tenzro_vm::StateAdapter::with_storage(store.clone());
        let record = read_training_record(&chain, &receipt_id).unwrap();
        assert!(matches!(record.settled, Some(RoundSettlement::Released)));
        let again = settle_refusal(&receipt_id, Some(&record), record.window_end_ms() + 1);
        assert!(again.is_some_and(|w| w.contains("already settled")));
        assert!(
            chain.get_balance(trainer_account.as_bytes()) > paid_before,
            "the milestone is paid to the trainer"
        );

        let pack = provenance_pack(&machine, at(&store, 3, root), request()).unwrap();
        assert_eq!(pack.receipt.receipt.trainer_did, did);
        assert_eq!(pack.receipt.receipt.end_checkpoint, hex::encode([5; 32]));
        let report =
            tenzro_consensus::training_provenance::verify_provenance_under_root(&pack, &root)
                .unwrap();
        assert_eq!(report.rounds.len(), 1);
        assert_eq!(report.rounds[0].shard_commitment, hex::encode([3; 32]));
    }
}
