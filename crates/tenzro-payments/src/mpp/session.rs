//! Capped streaming sessions over on-chain escrows.
//!
//! A session's cap is the payer's escrow on the Tenzro Ledger: a
//! `CreateEscrow` transaction the payer signs, naming the payee. Each request
//! in the session is paid with a cumulative voucher against that escrow
//! ([`EscrowVoucher`]); the payee claims what the session spent, under the
//! highest voucher, and after expiry the payer refunds whatever was not
//! claimed, the vouchers' headroom above the metered spend included. Value never sits in this node's memory: the manager only tracks
//! which voucher it has accepted and how much of it has been spent, so it can
//! refuse a request that is not paid for and claim before the escrow expires.
//!
//! The same mechanism backs the x402 `batch-settlement` scheme and payment
//! channels: all three are "an escrow plus cumulative vouchers".
//!
//! Accounting per session (keyed by escrow id):
//!
//! - `accepted_cumulative` — the highest voucher accepted;
//! - `spent` — what served requests have cost;
//! - `claimed_on_chain` — what the payee has claimed from the escrow.
//!
//! A request costing `c` is accepted when the voucher it carries is at least
//! the accepted one (vouchers never go backwards) and leaves
//! `voucher - spent >= c`. The voucher is persisted before the request is
//! answered, so a restart cannot forget a voucher the node already honoured.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_storage::kv::{CF_CHANNELS, KvStore};
use tenzro_types::Address;
use tenzro_types::payment_authorization::{EscrowClaim, EscrowVoucher};
use tracing::{info, warn};

use crate::error::{PaymentError, Result};
use crate::gateway::{RailOutcome, VoucherRail};

/// Key prefix for sessions in `CF_CHANNELS`.
const SESSION_KEY_PREFIX: &str = "mpp-session:";

/// What the ledger says about an escrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowView {
    /// The account that funded it.
    pub payer: Address,
    /// The account it pays.
    pub payee: Address,
    /// Total locked.
    pub amount: u128,
    /// Already claimed by the payee.
    pub claimed: u128,
    /// Expiry, Unix milliseconds.
    pub expires_at_ms: i64,
    /// Whether it is still funded (not released or refunded).
    pub funded: bool,
    /// The asset it holds.
    pub asset: String,
    /// What releases it: a refund-window escrow is a hold the payee
    /// captures, a hash-locked one pays whoever reveals its key.
    pub conditions: tenzro_types::settlement::ReleaseConditions,
}

impl EscrowView {
    /// The view of a ledger escrow account.
    pub fn from_account(e: &tenzro_settlement::escrow::EscrowAccount) -> Self {
        Self {
            payer: e.payer,
            payee: e.payee,
            amount: e.amount,
            claimed: e.claimed,
            expires_at_ms: e.expires_at.0,
            funded: e.status == tenzro_settlement::escrow::EscrowStatus::Funded,
            asset: e.asset_id.as_str().to_string(),
            conditions: e.release_conditions.clone(),
        }
    }

    /// What is still locked and unclaimed.
    pub fn unclaimed(&self) -> u128 {
        self.amount.saturating_sub(self.claimed)
    }

    /// The lock of a hash-locked escrow.
    pub fn hash_lock(&self) -> Option<[u8; 32]> {
        match self.conditions {
            tenzro_types::settlement::ReleaseConditions::HashLock { hash } => Some(hash),
            _ => None,
        }
    }

    /// Whether it is funded, pays `payee`, holds `amount` unclaimed and
    /// outlives `now_ms` by `margin_ms`, so the payee can still claim it.
    pub fn pays(
        &self,
        payee: &Address,
        amount: u128,
        now_ms: i64,
        margin_ms: i64,
    ) -> std::result::Result<(), String> {
        if !self.funded {
            return Err("is not funded".to_string());
        }
        if &self.payee != payee {
            return Err("pays someone else".to_string());
        }
        if self.unclaimed() < amount {
            return Err(format!(
                "holds {} unclaimed; {amount} is needed",
                self.unclaimed()
            ));
        }
        if self.expires_at_ms < now_ms.saturating_add(margin_ms) {
            return Err("expires too soon to claim".to_string());
        }
        Ok(())
    }
}

/// Reads escrow state from the ledger. The node implements it over VM state.
pub trait EscrowReader: Send + Sync {
    /// The escrow `escrow_id`, if it exists.
    fn escrow(&self, escrow_id: &[u8; 32]) -> Result<Option<EscrowView>>;
    /// Current time, Unix milliseconds.
    fn now_ms(&self) -> i64;
    /// Whether the ledger would honour `voucher`'s signer for the escrow it
    /// draws on: the payer's own keys, or for an agent's escrow a serving
    /// node its terms assign, before revocation.
    fn check_signer(&self, voucher: &EscrowVoucher, escrow: &EscrowView) -> Result<()>;
}

/// State of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MppSessionState {
    /// Accepting vouchers.
    Open,
    /// The payee asked to close; the highest voucher is awaiting its claim.
    Closing,
    /// The highest voucher has been claimed on-chain.
    Closed,
}

/// One session: an escrow and the vouchers accepted against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppSession {
    /// Hex of the escrow id; the session id.
    pub session_id: String,
    /// The escrow's payer.
    pub payer: Address,
    /// The escrow's payee.
    pub payee: Address,
    /// The cap: the escrow amount.
    pub deposit: u128,
    /// Escrow expiry, Unix milliseconds.
    pub expires_at_ms: i64,
    /// Highest voucher accepted.
    pub accepted_cumulative: u128,
    /// What served requests have cost.
    pub spent: u128,
    /// What has been claimed from the escrow.
    pub claimed_on_chain: u128,
    /// The voucher to claim with.
    pub highest_voucher: Option<EscrowVoucher>,
    /// Session state.
    pub state: MppSessionState,
    /// First voucher accepted.
    pub created_at: DateTime<Utc>,
    /// Last voucher accepted.
    pub last_activity: DateTime<Utc>,
}

/// Tracks sessions and accepts vouchers against them.
pub struct MppSessionManager {
    sessions: DashMap<String, MppSession>,
    storage: Option<Arc<dyn KvStore>>,
    reader: Arc<dyn EscrowReader>,
    /// A voucher is refused when its escrow expires sooner than this, so the
    /// payee always has time to claim before the payer can refund.
    claim_margin_ms: i64,
}

/// Default time a session's escrow must outlive an accepted voucher.
pub const DEFAULT_CLAIM_MARGIN_MS: i64 = 10 * 60 * 1000;

impl MppSessionManager {
    /// A manager reading escrows through `reader`, in memory only.
    pub fn new(reader: Arc<dyn EscrowReader>) -> Self {
        Self {
            sessions: DashMap::new(),
            storage: None,
            reader,
            claim_margin_ms: DEFAULT_CLAIM_MARGIN_MS,
        }
    }

    /// A manager persisting sessions to `CF_CHANNELS`, hydrated on start.
    pub fn with_storage(reader: Arc<dyn EscrowReader>, storage: Arc<dyn KvStore>) -> Self {
        let sessions = DashMap::new();
        match storage.get_keys_with_prefix(CF_CHANNELS, SESSION_KEY_PREFIX.as_bytes()) {
            Ok(keys) => {
                for key in keys {
                    if let Ok(Some(bytes)) = storage.get(CF_CHANNELS, &key) {
                        match serde_json::from_slice::<MppSession>(&bytes) {
                            Ok(s) => {
                                sessions.insert(s.session_id.clone(), s);
                            }
                            Err(e) => warn!("unreadable session record: {e}"),
                        }
                    }
                }
                if !sessions.is_empty() {
                    info!("Loaded {} payment sessions from storage", sessions.len());
                }
            }
            Err(e) => warn!("Failed to load payment sessions: {e}"),
        }
        Self {
            sessions,
            storage: Some(storage),
            reader,
            claim_margin_ms: DEFAULT_CLAIM_MARGIN_MS,
        }
    }

    /// Change how long an escrow must outlive an accepted voucher.
    pub fn with_claim_margin_ms(mut self, margin_ms: i64) -> Self {
        self.claim_margin_ms = margin_ms;
        self
    }

    fn persist(&self, session: &MppSession) -> Result<()> {
        if let Some(store) = &self.storage {
            let key = format!("{SESSION_KEY_PREFIX}{}", session.session_id);
            let bytes = serde_json::to_vec(session)?;
            store
                .put(CF_CHANNELS, key.as_bytes(), &bytes)
                .map_err(|e| {
                    PaymentError::SessionError(format!(
                        "could not persist session {}: {e}",
                        session.session_id
                    ))
                })?;
        }
        Ok(())
    }

    /// A session by escrow id (hex).
    pub fn get_session(&self, session_id: &str) -> Option<MppSession> {
        self.sessions.get(session_id).map(|s| s.clone())
    }

    /// Open a session over an escrow already funded on the ledger, before any
    /// voucher arrives. The escrow must be funded, pay `payee`, and outlive
    /// the claim margin.
    pub fn open_session(&self, escrow_id: &[u8; 32], payee: &Address) -> Result<MppSession> {
        let id = hex::encode(escrow_id);
        let view = self.reader.escrow(escrow_id)?.ok_or_else(|| {
            PaymentError::SessionError(format!("escrow {id} does not exist on the ledger"))
        })?;
        if !view.funded || view.payee != *payee {
            return Err(PaymentError::SessionError(format!(
                "escrow {id} is not a funded escrow paying this payee"
            )));
        }
        if view.expires_at_ms - self.reader.now_ms() < self.claim_margin_ms {
            return Err(PaymentError::SessionError(format!(
                "escrow {id} expires too soon to open a session on"
            )));
        }
        let session = self
            .sessions
            .entry(id.clone())
            .or_insert_with(|| Self::fresh(&id, &view))
            .clone();
        self.persist(&session)?;
        Ok(session)
    }

    fn fresh(id: &str, view: &EscrowView) -> MppSession {
        MppSession {
            session_id: id.to_string(),
            payer: view.payer,
            payee: view.payee,
            deposit: view.amount,
            expires_at_ms: view.expires_at_ms,
            accepted_cumulative: view.claimed,
            spent: view.claimed,
            claimed_on_chain: view.claimed,
            highest_voucher: None,
            state: MppSessionState::Open,
            created_at: Utc::now(),
            last_activity: Utc::now(),
        }
    }

    /// Every session.
    pub fn sessions(&self) -> Vec<MppSession> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    /// Ask to close a session: it stops accepting vouchers and what it spent
    /// becomes due for claiming under its highest voucher. Returns the claim,
    /// if any is outstanding.
    pub fn close_session(&self, session_id: &str) -> Result<Option<EscrowClaim>> {
        let mut s = self.sessions.get_mut(session_id).ok_or_else(|| {
            PaymentError::SessionError(format!("session not found: {session_id}"))
        })?;
        if s.state == MppSessionState::Open {
            s.state = MppSessionState::Closing;
        }
        let due = Self::claim_of(&s);
        if due.is_none() {
            s.state = MppSessionState::Closed;
        }
        self.persist(&s)?;
        Ok(due)
    }

    /// Claims due now: sessions closing, or open ones whose escrow expires
    /// within the claim margin. Each claims what the session spent, under its
    /// highest voucher; the voucher's headroom above that stays the payer's.
    pub fn due_claims(&self) -> Vec<EscrowClaim> {
        let now = self.reader.now_ms();
        self.sessions
            .iter()
            .filter(|s| {
                s.state == MppSessionState::Closing
                    || (s.state == MppSessionState::Open
                        && s.expires_at_ms - now <= self.claim_margin_ms)
            })
            .filter_map(|s| Self::claim_of(&s))
            .collect()
    }

    /// The claim a session has outstanding: what it spent, above what was
    /// claimed, under the highest voucher it accepted.
    fn claim_of(s: &MppSession) -> Option<EscrowClaim> {
        let voucher = s.highest_voucher.clone()?;
        (s.spent > s.claimed_on_chain && s.spent <= voucher.cumulative_amount).then_some({
            EscrowClaim {
                voucher,
                amount: s.spent,
            }
        })
    }

    /// Record that a claim of `cumulative` in total executed on-chain.
    pub fn mark_claimed(&self, escrow_id: &[u8; 32], cumulative: u128) -> Result<()> {
        let id = hex::encode(escrow_id);
        let mut s = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| PaymentError::SessionError(format!("session not found: {id}")))?;
        s.claimed_on_chain = s.claimed_on_chain.max(cumulative);
        if s.state == MppSessionState::Closing && s.claimed_on_chain >= s.spent {
            s.state = MppSessionState::Closed;
        }
        self.persist(&s)
    }

    fn refuse(reason: String) -> Result<RailOutcome> {
        Ok(RailOutcome::Failed { reason })
    }
}

#[async_trait]
impl VoucherRail for MppSessionManager {
    async fn accept(
        &self,
        voucher: &EscrowVoucher,
        payee: &Address,
        charge: u128,
    ) -> Result<RailOutcome> {
        self.accept_voucher(voucher, payee, charge)
    }

    async fn check(
        &self,
        voucher: &EscrowVoucher,
        payee: &Address,
        charge: u128,
    ) -> Result<RailOutcome> {
        self.check_voucher(voucher, payee, charge)
    }
}

impl MppSessionManager {
    /// Accept `voucher` as payment of `charge` to `payee`. The escrow must
    /// exist and be funded on the ledger, pay `payee`, be owned by the
    /// voucher's key, hold at least the cumulative amount and outlive the
    /// claim margin; the voucher must not go backwards and must cover what
    /// the session has spent plus `charge`. The voucher's signature is the
    /// caller's check.
    pub fn accept_voucher(
        &self,
        voucher: &EscrowVoucher,
        payee: &Address,
        charge: u128,
    ) -> Result<RailOutcome> {
        self.voucher_outcome(voucher, payee, charge, true)
    }

    /// Every check [`Self::accept_voucher`] makes, without accepting.
    pub fn check_voucher(
        &self,
        voucher: &EscrowVoucher,
        payee: &Address,
        charge: u128,
    ) -> Result<RailOutcome> {
        self.voucher_outcome(voucher, payee, charge, false)
    }

    fn voucher_outcome(
        &self,
        voucher: &EscrowVoucher,
        payee: &Address,
        charge: u128,
        commit: bool,
    ) -> Result<RailOutcome> {
        let id = hex::encode(voucher.escrow_id);
        let Some(view) = self.reader.escrow(&voucher.escrow_id)? else {
            return Self::refuse(format!("escrow {id} does not exist on the ledger"));
        };
        if !view.funded {
            return Self::refuse(format!("escrow {id} is no longer funded"));
        }
        if view.payee != *payee {
            return Self::refuse(format!("escrow {id} pays another account"));
        }
        if let Err(e) = self.reader.check_signer(voucher, &view) {
            return Self::refuse(format!("voucher on escrow {id} refused: {e}"));
        }
        if voucher.cumulative_amount > view.amount {
            return Self::refuse(format!(
                "voucher for {} exceeds escrow {id} holding {}",
                voucher.cumulative_amount, view.amount
            ));
        }
        let now = self.reader.now_ms();
        if view.expires_at_ms - now < self.claim_margin_ms {
            return Self::refuse(format!("escrow {id} expires too soon to claim against"));
        }

        if !commit {
            let (accepted, spent) = self
                .sessions
                .get(&id)
                .map(|s| (s.accepted_cumulative, s.spent))
                .unwrap_or((view.claimed, view.claimed));
            if voucher.cumulative_amount < accepted {
                return Self::refuse(format!(
                    "voucher for {} is behind the accepted {accepted}",
                    voucher.cumulative_amount
                ));
            }
            if spent.saturating_add(charge) > voucher.cumulative_amount {
                return Self::refuse(format!(
                    "session {id} has {} available, the request costs {charge}",
                    voucher.cumulative_amount.saturating_sub(spent)
                ));
            }
            return Ok(RailOutcome::Settled {
                reference: format!("escrow:{id}:{}", voucher.cumulative_amount),
            });
        }

        // The entry guard serialises concurrent requests on one session.
        let mut entry = self
            .sessions
            .entry(id.clone())
            .or_insert_with(|| Self::fresh(&id, &view));
        let s = entry.value_mut();
        if s.state != MppSessionState::Open {
            return Self::refuse(format!("session {id} is closing"));
        }
        if voucher.cumulative_amount < s.accepted_cumulative {
            return Self::refuse(format!(
                "voucher for {} is behind the accepted {}",
                voucher.cumulative_amount, s.accepted_cumulative
            ));
        }
        let new_spent = s
            .spent
            .checked_add(charge)
            .ok_or_else(|| PaymentError::SessionError("spend overflow".to_string()))?;
        if new_spent > voucher.cumulative_amount {
            return Self::refuse(format!(
                "session {id} has {} available, the request costs {charge}",
                voucher.cumulative_amount.saturating_sub(s.spent)
            ));
        }
        let before = s.clone();
        s.accepted_cumulative = voucher.cumulative_amount;
        s.spent = new_spent;
        s.highest_voucher = Some(voucher.clone());
        s.last_activity = Utc::now();
        if let Err(e) = self.persist(s) {
            *s = before;
            return Err(e);
        }
        Ok(RailOutcome::Settled {
            reference: format!("escrow:{id}:{}", voucher.cumulative_amount),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    struct FakeLedger {
        escrow: Mutex<Option<EscrowView>>,
        now: i64,
    }

    impl EscrowReader for FakeLedger {
        fn escrow(&self, _id: &[u8; 32]) -> Result<Option<EscrowView>> {
            Ok(self.escrow.lock().clone())
        }
        fn now_ms(&self) -> i64 {
            self.now
        }
        fn check_signer(&self, voucher: &EscrowVoucher, escrow: &EscrowView) -> Result<()> {
            if crate::payer_auth::keys_control_account(&voucher.public_key, &escrow.payer) {
                Ok(())
            } else {
                Err(PaymentError::VerificationFailed(
                    "voucher keys do not own the escrow".into(),
                ))
            }
        }
    }

    const PAYEE: Address = Address([9u8; 32]);

    fn setup(amount: u128) -> (MppSessionManager, Vec<u8>) {
        let pk = vec![5u8; 32];
        let ledger = Arc::new(FakeLedger {
            escrow: Mutex::new(Some(EscrowView {
                payer: crate::payer_auth::payer_account(&pk),
                payee: PAYEE,
                amount,
                claimed: 0,
                expires_at_ms: 10_000_000,
                funded: true,
                asset: "TNZO".into(),
                conditions: tenzro_types::settlement::ReleaseConditions::ConsumerSignature,
            })),
            now: 0,
        });
        (MppSessionManager::new(ledger), pk)
    }

    fn voucher(pk: &[u8], cumulative: u128) -> EscrowVoucher {
        EscrowVoucher {
            binding: [0u8; 32],
            agent: None,
            escrow_id: [1u8; 32],
            cumulative_amount: cumulative,
            public_key: pk.to_vec(),
            signature: tenzro_crypto::composite::CompositeSignature::classical(
                tenzro_crypto::composite::ClassicalProof::Raw {
                    signature: vec![0u8; 64],
                },
            ),
            attribution: None,
        }
    }

    #[tokio::test]
    async fn requests_are_paid_from_the_voucher_until_it_runs_out() {
        let (m, pk) = setup(1_000);
        let ok = |o: RailOutcome| matches!(o, RailOutcome::Settled { .. });
        assert!(ok(m.accept(&voucher(&pk, 100), &PAYEE, 60).await.unwrap()));
        // 40 left under the 100 voucher; a 50 request needs a bigger voucher.
        assert!(!ok(m.accept(&voucher(&pk, 100), &PAYEE, 50).await.unwrap()));
        assert!(ok(m.accept(&voucher(&pk, 150), &PAYEE, 50).await.unwrap()));
        let s = m.get_session(&hex::encode([1u8; 32])).unwrap();
        assert_eq!(s.spent, 110);
        assert_eq!(s.accepted_cumulative, 150);
    }

    #[tokio::test]
    async fn a_voucher_cannot_go_backwards_or_exceed_the_cap() {
        let (m, pk) = setup(1_000);
        m.accept(&voucher(&pk, 500), &PAYEE, 10).await.unwrap();
        assert!(matches!(
            m.accept(&voucher(&pk, 400), &PAYEE, 10).await.unwrap(),
            RailOutcome::Failed { .. }
        ));
        assert!(matches!(
            m.accept(&voucher(&pk, 1_001), &PAYEE, 10).await.unwrap(),
            RailOutcome::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn a_voucher_from_a_key_that_does_not_own_the_escrow_is_refused() {
        let (m, _pk) = setup(1_000);
        assert!(matches!(
            m.accept(&voucher(&[6u8; 32], 100), &PAYEE, 10)
                .await
                .unwrap(),
            RailOutcome::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn an_escrow_for_another_payee_is_refused() {
        let (m, pk) = setup(1_000);
        assert!(matches!(
            m.accept(&voucher(&pk, 100), &Address([8u8; 32]), 10)
                .await
                .unwrap(),
            RailOutcome::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn closing_hands_back_the_voucher_to_claim_and_marks_closed_after() {
        let (m, pk) = setup(1_000);
        m.accept(&voucher(&pk, 300), &PAYEE, 300).await.unwrap();
        let id = hex::encode([1u8; 32]);
        let due = m.close_session(&id).unwrap().unwrap();
        assert_eq!((due.voucher.cumulative_amount, due.amount), (300, 300));
        assert_eq!(m.due_claims().len(), 1);
        m.mark_claimed(&[1u8; 32], 300).unwrap();
        assert_eq!(m.get_session(&id).unwrap().state, MppSessionState::Closed);
        assert!(m.due_claims().is_empty());
        // A closed session takes no more vouchers.
        assert!(matches!(
            m.accept(&voucher(&pk, 400), &PAYEE, 10).await.unwrap(),
            RailOutcome::Failed { .. }
        ));
    }

    /// Each call's voucher covers that call's ceiling; the claim is what the
    /// calls cost, so the headroom of the last voucher stays the payer's.
    #[tokio::test]
    async fn a_claim_is_the_metered_spend_not_the_last_voucher() {
        let (m, pk) = setup(1_000);
        let ceiling = 100;
        let mut spent = 0;
        for cost in [7, 11, 13] {
            m.accept(&voucher(&pk, spent + ceiling), &PAYEE, cost)
                .await
                .unwrap();
            spent += cost;
        }
        let id = hex::encode([1u8; 32]);
        let due = m.close_session(&id).unwrap().unwrap();
        assert_eq!(due.amount, 31);
        assert_eq!(due.voucher.cumulative_amount, 18 + ceiling);
        m.mark_claimed(&[1u8; 32], due.amount).unwrap();
        assert_eq!(m.get_session(&id).unwrap().state, MppSessionState::Closed);
        assert!(m.due_claims().is_empty());
    }
}
