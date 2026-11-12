//! Settlement rails backed by the Tenzro Ledger.
//!
//! [`LedgerRail`] settles a payer-authorized HTTP-402 payment with an
//! `PayerSettle` transaction and reports success only after that transaction
//! executed successfully in a finalized block. The payer's signed
//! authorization travels on the transaction and every validator re-verifies
//! it, so this node's key pays gas and has no other authority over the funds.
//!
//! [`LedgerSubmitter`] is the shared piece: it signs a transaction with the
//! node key, admits it to the mempool, gossips it, and waits for its receipt.

use std::sync::Arc;
use std::time::Duration;

use crate::consensus_driver::ConsensusHandle;
use async_trait::async_trait;
use dashmap::DashMap;
use tenzro_payments::gateway::{RailOutcome, SettlementInstruction, SettlementRail};
use tenzro_payments::{PaymentError, Result as PaymentResult};
use tenzro_storage::CF_TRANSACTIONS;
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::event_loop::{NodeEvent, TxReceiptRecord};

/// Gas limit stamped on node-submitted settlement transactions. Covers the
/// largest settlement handler (a full voucher batch) with headroom.
const SETTLEMENT_TX_GAS_LIMIT: u64 = 2_000_000;

/// How long a settlement waits for its transaction to execute before
/// reporting it pending.
const SETTLEMENT_WAIT: Duration = Duration::from_secs(20);

/// How often the receipt store is polled while waiting.
const RECEIPT_POLL: Duration = Duration::from_millis(100);

/// Where a submitted transaction stands.
#[derive(Debug, Clone)]
pub(crate) enum Inclusion {
    /// Executed in a finalized block.
    Executed(TxReceiptRecord),
    /// Admitted but not yet executed within the wait.
    Waiting,
}

/// The one nonce allocator of the validator's ledger account on this node.
/// Every transaction the node signs from that account is numbered and
/// admitted to the mempool under one lock, at the first nonce the chain and
/// the mempool leave free for the account (an operator's CLI sends from the
/// same account, and a transaction that was dropped leaves its nonce free
/// again), so no two share a nonce and no admission failure leaves a gap.
#[derive(Debug, Default)]
pub struct NonceReservation {
    lock: parking_lot::Mutex<()>,
    /// When this account last submitted the enrolment of its ML-DSA-65 key,
    /// while it was not yet enrolled on chain.
    enrolment_submitted: parking_lot::Mutex<Option<std::time::Instant>>,
}

/// The error a submission returns while the node account's ML-DSA-65 key is
/// not yet enrolled on chain: its enrolment is submitted and nothing else is
/// admitted from the account before it has executed. Retryable; the
/// submission itself is not dropped, the caller still holds it.
pub const PQ_ENROLMENT_PENDING: &str =
    "the node account's ML-DSA-65 key enrolment is pending on chain; retry shortly";

/// How long a submitted enrolment is awaited before one is submitted again.
const ENROLMENT_RETRY: Duration = Duration::from_secs(30);

impl NonceReservation {
    /// Runs `admit` with the next free nonce of `address`, holding the
    /// allocator until it returns: `admit` signs at that nonce and submits to
    /// the mempool.
    pub fn admit_next<T, E>(
        &self,
        consensus: &ConsensusHandle,
        storage: Arc<dyn tenzro_storage::KvStore>,
        address: &Address,
        admit: impl FnOnce(u64) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let _held = self.lock.lock();
        let chain_nonce = || {
            use tenzro_vm::traits::VmState as _;
            tenzro_vm::StateAdapter::with_storage(storage).get_nonce(address.as_bytes())
        };
        admit(consensus.mempool().next_nonce(address, chain_nonce))
    }

    /// Whether the account is due to submit the enrolment of its ML-DSA-65
    /// key: true at most once per retry interval.
    pub(crate) fn enrolment_due(&self) -> bool {
        let mut last = self.enrolment_submitted.lock();
        if last.is_some_and(|at| at.elapsed() < ENROLMENT_RETRY) {
            return false;
        }
        *last = Some(std::time::Instant::now());
        true
    }
}

/// The event-loop sender a locally admitted transaction is gossiped through;
/// empty until the event loop starts.
pub type GossipSlot = Arc<parking_lot::Mutex<Option<mpsc::Sender<NodeEvent>>>>;

/// Gossip a transaction already admitted to the local mempool, from a
/// context that cannot wait: when the event loop's queue is full the next
/// proposer still has it locally, and gossip of later ones carries on.
pub fn gossip_admitted(slot: &GossipSlot, signed: SignedTransaction) {
    let sender = slot.lock().clone();
    if let Some(sender) = sender
        && let Err(e) = sender.try_send(NodeEvent::LocallyAdmittedTransaction(signed))
    {
        warn!("validator transaction admitted but not gossiped: {e}");
    }
}

/// Signs, admits, gossips and awaits node-submitted transactions.
pub struct LedgerSubmitter {
    consensus: Arc<ConsensusHandle>,
    hybrid_signer: Arc<dyn tenzro_crypto::composite::HybridSigner>,
    node_addr: Address,
    storage: Arc<dyn tenzro_storage::KvStore>,
    chain_id: u64,
    nonces: Arc<NonceReservation>,
    event_sender: GossipSlot,
}

impl LedgerSubmitter {
    /// Build a submitter paying gas from `node_addr`.
    pub fn new(
        consensus: Arc<ConsensusHandle>,
        hybrid_signer: Arc<dyn tenzro_crypto::composite::HybridSigner>,
        node_addr: Address,
        storage: Arc<dyn tenzro_storage::KvStore>,
        chain_id: u64,
        nonces: Arc<NonceReservation>,
        event_sender: GossipSlot,
    ) -> Self {
        Self {
            consensus,
            hybrid_signer,
            node_addr,
            storage,
            chain_id,
            nonces,
            event_sender,
        }
    }

    /// The account this submitter sends from: the validator's ledger account.
    pub fn address(&self) -> Address {
        self.node_addr
    }

    /// The most a transaction of `gas` can cost this account at the gas price
    /// it sends with, in the smallest unit.
    pub fn fee_for(&self, gas: u64) -> u128 {
        u128::from(self.consensus.node_tx_gas_price()).saturating_mul(u128::from(gas))
    }

    /// The chain this submitter signs for.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Self-signs a `PaymentAuthorization` paying `payee` under `binding`,
    /// from this submitter's own ledger account rather than an external
    /// caller's: for a leg this node owes out of its own funds, such as the
    /// provider leg of a call it forwarded and already collected payment for
    /// from its own caller. Mirrors the CLI's `keystore::sign_payment`, using
    /// this submitter's own hardware-backed signer in place of a namespaced
    /// client key.
    pub(crate) fn sign_own_payment(
        &self,
        payee: Address,
        payment_id: &str,
        max_amount: u128,
        binding: tenzro_types::payment_authorization::PaymentBinding,
    ) -> std::result::Result<crate::ledger_payment::PayerPayment, String> {
        use tenzro_crypto::composite::SignatureContext;
        use tenzro_types::payment_authorization::{
            PaymentAuthorization, payment_authorization_preimage,
        };
        let public = self.hybrid_signer.public_key();
        let payer = self.node_addr;
        let signature = self
            .hybrid_signer
            .sign(
                SignatureContext::PaymentAuthorization,
                &payment_authorization_preimage(
                    self.chain_id,
                    payment_id,
                    &payer,
                    &payee,
                    max_amount,
                    "TNZO",
                    &binding,
                ),
            )
            .map_err(|e| e.to_string())?;
        Ok(crate::ledger_payment::PayerPayment {
            payer,
            payment_id: payment_id.to_string(),
            authorization: PaymentAuthorization {
                resellers: Vec::new(),
                binding,
                public_key: public.p256.clone(),
                signature,
                max_amount,
                asset: "TNZO".to_string(),
            },
        })
    }

    /// Submit `tx_type` and wait for it to execute, as a settlement outcome:
    /// settled once it executed successfully, failed with its revert reason,
    /// or pending under its hash when it has not executed within the wait.
    pub async fn settle(
        &self,
        to: Address,
        tx_type: TransactionType,
    ) -> Result<RailOutcome, String> {
        let tx_hash = self.submit(to, tx_type).await?;
        Ok(outcome_of(
            &tx_hash,
            self.await_inclusion(&tx_hash, SETTLEMENT_WAIT).await,
        ))
    }

    /// Sign and admit `tx_type`, returning the hash the receipt is keyed by.
    pub async fn submit(&self, to: Address, tx_type: TransactionType) -> Result<String, String> {
        self.submit_with_gas(to, tx_type, SETTLEMENT_TX_GAS_LIMIT)
            .await
    }

    /// [`submit`](Self::submit) with an explicit gas limit, for transactions
    /// whose cost grows with their payload.
    pub async fn submit_with_gas(
        &self,
        to: Address,
        tx_type: TransactionType,
        gas_limit: u64,
    ) -> Result<String, String> {
        // Every account transaction carries the ML-DSA-65 leg, checked against
        // the key the account enrolled, and this account is the node's
        // whether or not it is a validator. Nothing is admitted from it before
        // its key has executed on chain; the caller is told so, and retries.
        if !crate::node::ensure_pq_key_enrolled(
            &self.consensus,
            &self.hybrid_signer,
            &self.storage,
            self.chain_id,
            &self.nonces,
            &self.event_sender,
        )
        .map_err(|e| format!("enrolling the node account's ML-DSA-65 key: {e}"))?
        {
            return Err(PQ_ENROLMENT_PENDING.to_string());
        }
        let gas_price = self.consensus.node_tx_gas_price();
        let signed = self.nonces.admit_next(
            &self.consensus,
            self.storage.clone(),
            &self.node_addr,
            |nonce| {
                let tx = Transaction::new(
                    ChainId::from(self.chain_id),
                    self.node_addr,
                    to,
                    Nonce::from(nonce),
                    tx_type,
                    gas_limit,
                    gas_price,
                );
                let composite = self
                    .hybrid_signer
                    .sign(
                        tenzro_crypto::composite::SignatureContext::Transaction,
                        tx.hash().as_bytes(),
                    )
                    .map_err(|e| format!("signing failed: {e}"))?;
                let signed = SignedTransaction::new(
                    tx,
                    self.hybrid_signer.public_key().p256.clone(),
                    composite,
                );
                self.consensus
                    .submit_transaction(signed.clone())
                    .map_err(|e| format!("rejected by the mempool: {e}"))?;
                Ok::<_, String>(signed)
            },
        )?;
        self.gossip(signed).await
    }

    /// Admit a transaction someone else signed (the mempool checks its
    /// signature) and gossip it, returning the hash its receipt is keyed by.
    pub async fn submit_signed(&self, signed: SignedTransaction) -> Result<String, String> {
        self.admit(signed).await
    }

    async fn admit(&self, signed: SignedTransaction) -> Result<String, String> {
        self.consensus
            .submit_transaction(signed.clone())
            .map_err(|e| format!("rejected by the mempool: {e}"))?;
        self.gossip(signed).await
    }

    /// Gossip a transaction already in the local mempool, returning the hash
    /// its receipt is keyed by.
    async fn gossip(&self, signed: SignedTransaction) -> Result<String, String> {
        let tx_hash = signed.transaction.hash();
        let sender = self.event_sender.lock().clone();
        if let Some(sender) = sender
            && let Err(e) = sender
                .send(NodeEvent::LocallyAdmittedTransaction(signed))
                .await
        {
            warn!("settlement tx {tx_hash} admitted but not gossiped: {e}");
        }
        Ok(tx_hash.to_string())
    }

    /// The execution receipt for `tx_hash`, if its block has finalized.
    pub(crate) fn receipt(&self, tx_hash: &str) -> Option<TxReceiptRecord> {
        let key = format!("receipt:{tx_hash}");
        let bytes = self.storage.get(CF_TRANSACTIONS, key.as_bytes()).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    /// Wait up to `wait` for `tx_hash` to execute.
    pub(crate) async fn await_inclusion(&self, tx_hash: &str, wait: Duration) -> Inclusion {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(r) = self.receipt(tx_hash) {
                return Inclusion::Executed(r);
            }
            if tokio::time::Instant::now() >= deadline {
                return Inclusion::Waiting;
            }
            tokio::time::sleep(RECEIPT_POLL).await;
        }
    }
}

fn outcome_of(tx_hash: &str, inclusion: Inclusion) -> RailOutcome {
    match inclusion {
        Inclusion::Executed(r) if r.success => RailOutcome::Settled {
            reference: tx_hash.to_string(),
        },
        Inclusion::Executed(r) => RailOutcome::Failed {
            reason: r
                .revert_reason
                .unwrap_or_else(|| "settlement transaction reverted".to_string()),
        },
        Inclusion::Waiting => RailOutcome::Pending {
            reference: tx_hash.to_string(),
        },
    }
}

/// The Tenzro Ledger as a settlement rail for TNZO and the tokens its
/// operator opted into.
pub struct LedgerRail {
    submitter: Arc<LedgerSubmitter>,
    /// Token ids accepted besides TNZO, lowercase `0x` hex.
    assets: Vec<String>,
    /// Transactions submitted per payment id, for status polling.
    submitted: DashMap<String, String>,
}

impl LedgerRail {
    /// A ledger rail submitting through `submitter`, carrying TNZO and the
    /// token ids in `assets`.
    pub fn new(submitter: Arc<LedgerSubmitter>, assets: &[String]) -> Self {
        Self {
            submitter,
            assets: assets.iter().map(|a| a.to_ascii_lowercase()).collect(),
            submitted: DashMap::new(),
        }
    }
}

#[async_trait]
impl SettlementRail for LedgerRail {
    fn name(&self) -> &'static str {
        "tenzro-ledger"
    }

    fn carries(&self, asset: &str) -> bool {
        asset.eq_ignore_ascii_case("TNZO") || self.assets.contains(&asset.to_ascii_lowercase())
    }

    async fn settle(&self, i: &SettlementInstruction) -> PaymentResult<RailOutcome> {
        let tx_type = TransactionType::PayerSettle {
            payer: i.payer.address,
            payee: i.payee,
            amount: i.amount,
            payment_id: i.payment_id.clone(),
            authorization: i.payer.authorization.clone(),
        };
        let tx_hash = self
            .submitter
            .submit(i.payee, tx_type)
            .await
            .map_err(PaymentError::SettlementError)?;
        self.submitted.insert(i.payment_id.clone(), tx_hash.clone());
        let outcome = outcome_of(
            &tx_hash,
            self.submitter
                .await_inclusion(&tx_hash, SETTLEMENT_WAIT)
                .await,
        );
        if let RailOutcome::Settled { .. } = outcome {
            info!(
                "payment {} settled on the ledger in {}",
                i.payment_id, tx_hash
            );
        }
        Ok(outcome)
    }

    async fn status(&self, payment_id: &str) -> PaymentResult<RailOutcome> {
        let tx_hash = self
            .submitted
            .get(payment_id)
            .map(|h| h.clone())
            .ok_or_else(|| {
                PaymentError::SettlementError(format!(
                    "no ledger settlement was submitted for {payment_id}"
                ))
            })?;
        Ok(outcome_of(
            &tx_hash,
            self.submitter
                .await_inclusion(&tx_hash, Duration::from_millis(0))
                .await,
        ))
    }
}

/// Opens payer-signed settlement plans for the x402 facilitator: admits the
/// payer's plan transaction and reads the plan and its leg receipts from VM
/// state.
pub struct LedgerPlanRail {
    submitter: Arc<LedgerSubmitter>,
    storage: Arc<dyn tenzro_storage::KvStore>,
}

impl LedgerPlanRail {
    /// A plan rail admitting through `submitter`, reading `storage`.
    pub fn new(submitter: Arc<LedgerSubmitter>, storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        Self { submitter, storage }
    }
}

#[async_trait]
impl tenzro_payments::gateway::PlanRail for LedgerPlanRail {
    async fn open(&self, signed: &SignedTransaction) -> PaymentResult<RailOutcome> {
        let tx_hash = self
            .submitter
            .submit_signed(signed.clone())
            .await
            .map_err(PaymentError::SettlementError)?;
        Ok(outcome_of(
            &tx_hash,
            self.submitter
                .await_inclusion(&tx_hash, SETTLEMENT_WAIT)
                .await,
        ))
    }

    fn plan(
        &self,
        plan_id: &[u8; 32],
    ) -> Option<(
        tenzro_types::settlement::SettlementPlan,
        Vec<tenzro_types::settlement::LegReceipt>,
    )> {
        use tenzro_vm::native::{read_leg_receipt, read_plan};
        let state = tenzro_vm::StateAdapter::with_storage(self.storage.clone());
        let plan = read_plan(&state, plan_id)?;
        let receipts = (0..plan.legs.len() as u8)
            .filter_map(|i| read_leg_receipt(&state, &tenzro_types::settlement::leg_id(plan_id, i)))
            .collect();
        Some((plan, receipts))
    }
}

/// Reads the ML-DSA-65 keys accounts enrolled from the node's VM state, the
/// only source payers' and meters' post-quantum keys are verified against.
/// A node holding no chain state refuses every payment rather than verify
/// one against keys it cannot read.
pub struct LedgerEnrolledKeys {
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl LedgerEnrolledKeys {
    /// A reader over the node's VM state, if it holds one.
    pub fn new(storage: Option<Arc<dyn tenzro_storage::KvStore>>) -> Self {
        Self { storage }
    }
}

impl tenzro_payments::EnrolledKeys for LedgerEnrolledKeys {
    fn enrolled_pq_key(&self, p256_xy: &[u8]) -> PaymentResult<Option<Vec<u8>>> {
        let storage = self.storage.as_ref().ok_or_else(|| {
            tenzro_payments::PaymentError::VerificationFailed(
                "this node holds no chain state to read the payer's enrolled keys from".to_string(),
            )
        })?;
        let state = tenzro_vm::StateAdapter::with_storage(storage.clone());
        Ok(tenzro_vm::account_keys::enrolled_pq_key(&state, p256_xy))
    }

    fn keystore_rp_id(
        &self,
        p256_xy: &[u8],
        account: &tenzro_types::Address,
    ) -> PaymentResult<Option<String>> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(None);
        };
        let state = tenzro_vm::StateAdapter::with_storage(storage.clone());
        Ok(tenzro_vm::keystore::account_signing_key(
            &state,
            p256_xy,
            account.as_bytes(),
            crate::calendar::now_ms(),
        )
        .ok()
        .and_then(|(_, rp_id)| rp_id))
    }
}

/// Reads escrows from VM state for the session manager.
pub struct LedgerEscrowReader {
    storage: Arc<dyn tenzro_storage::KvStore>,
    chain_id: u64,
}

impl LedgerEscrowReader {
    /// A reader over the node's VM state on `chain_id`.
    pub fn new(storage: Arc<dyn tenzro_storage::KvStore>, chain_id: u64) -> Self {
        Self { storage, chain_id }
    }
}

impl tenzro_payments::mpp::EscrowReader for LedgerEscrowReader {
    fn escrow(
        &self,
        escrow_id: &[u8; 32],
    ) -> PaymentResult<Option<tenzro_payments::mpp::EscrowView>> {
        let state = tenzro_vm::StateAdapter::with_storage(self.storage.clone());
        Ok(tenzro_vm::native::read_escrow(&state, escrow_id)
            .map(|e| tenzro_payments::mpp::EscrowView::from_account(&e)))
    }

    // Escrow expiries are calendar time, as the chain checks them.
    fn now_ms(&self) -> i64 {
        crate::calendar::now_ms() as i64
    }

    // The ledger's own voucher check: the payer's keys, or the agent's
    // terms for an agent's escrow.
    fn check_signer(
        &self,
        voucher: &tenzro_types::payment_authorization::EscrowVoucher,
        _escrow: &tenzro_payments::mpp::EscrowView,
    ) -> PaymentResult<()> {
        let state = tenzro_vm::StateAdapter::with_storage(self.storage.clone());
        tenzro_vm::native::check_escrow_voucher(&state, self.chain_id, self.now_ms(), voucher)
            .map(|_| ())
            .map_err(|e| tenzro_payments::PaymentError::VerificationFailed(e.to_string()))
    }
}

/// Payment records and the agent account chains whose payments a route
/// proves, read from the node's VM state.
pub struct LedgerPaymentRecords {
    storage: Arc<dyn tenzro_storage::KvStore>,
}

impl LedgerPaymentRecords {
    /// A reader over the node's VM state.
    pub fn new(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        Self { storage }
    }
}

impl tenzro_payments::x402::LedgerRecords for LedgerPaymentRecords {
    fn payment(&self, pay_ref: &[u8; 32]) -> Option<tenzro_types::settlement::PaymentRecord> {
        let state = tenzro_vm::StateAdapter::with_storage(self.storage.clone());
        tenzro_vm::native::read_payment(&state, pay_ref)
    }

    fn agent_account_networks(&self) -> Vec<tenzro_payments::x402::AgentAccountNetwork> {
        crate::agent_accounts::chains_in(self.storage.as_ref())
            .into_iter()
            .filter(|c| c.open)
            .filter_map(|c| {
                c.report_route
                    .map(|r| tenzro_payments::x402::AgentAccountNetwork {
                        caip2: c.caip2,
                        route_chain: r.source_chain.to_ascii_lowercase(),
                    })
            })
            .collect()
    }
}

/// How often due voucher claims are submitted.
const CLAIM_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Claim every due session voucher in one `ClaimEscrow` transaction and
/// record the claims that executed. Returns how many vouchers were claimed.
pub async fn claim_due_vouchers(
    submitter: &LedgerSubmitter,
    sessions: &tenzro_payments::mpp::MppSessionManager,
) -> usize {
    let due = sessions.due_claims();
    if due.is_empty() {
        return 0;
    }
    let mut claimed = 0;
    for batch in due.chunks(tenzro_types::payment_authorization::MAX_VOUCHERS_PER_CLAIM) {
        let tx_type = TransactionType::ClaimEscrow {
            claims: batch.to_vec(),
        };
        let tx_hash = match submitter.submit(Address::zero(), tx_type).await {
            Ok(h) => h,
            Err(e) => {
                warn!("voucher claim not admitted: {e}");
                continue;
            }
        };
        match submitter.await_inclusion(&tx_hash, SETTLEMENT_WAIT).await {
            Inclusion::Executed(r) if r.success => {
                for c in batch {
                    if let Err(e) = sessions.mark_claimed(&c.voucher.escrow_id, c.amount) {
                        warn!("claimed voucher not recorded: {e}");
                    }
                }
                claimed += batch.len();
                info!("claimed {} session vouchers in {}", batch.len(), tx_hash);
            }
            Inclusion::Executed(r) => warn!(
                "voucher claim {} reverted: {}",
                tx_hash,
                r.revert_reason.unwrap_or_default()
            ),
            Inclusion::Waiting => warn!("voucher claim {tx_hash} not yet executed"),
        }
    }
    claimed
}

/// Keep claiming due session vouchers for as long as the node runs.
pub fn spawn_voucher_claimer(
    submitter: Arc<LedgerSubmitter>,
    sessions: Arc<tenzro_payments::mpp::MppSessionManager>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CLAIM_SWEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            claim_due_vouchers(&submitter, &sessions).await;
        }
    });
}
