//! The mailbox: deposit, list, collect and acknowledge.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tenzro_crypto::{
    CompositePublicKey, CompositeSignature, HybridSigner, PqPolicy, SignatureContext,
    verify_composite, verify_composite_for,
};
use tenzro_types::did_services::MAX_DID_LEN;
use tenzro_types::payment_authorization::{
    EscrowVoucher, attributed_voucher_preimage, escrow_voucher_preimage,
};

use crate::error::MailboxError;
use crate::store::{EscrowAccount, Recent, Store};
use crate::wire::{
    Action, Auth, Deposit, DepositPolicy, Receipt, SenderProof, TAG_PREFIX, auth_preimage,
    deposit_binding, sender_preimage, tag_key,
};

/// DIDs one recipient may name as its depositors.
const MAX_POLICY_DEPOSITORS: usize = 1024;

pub(crate) const HOUR_MS: u64 = 3_600_000;

/// What the operator sets for its mailbox.
#[derive(Debug, Clone)]
pub struct MailboxConfig {
    /// The chain whose escrows pay the mailbox.
    pub chain_id: u64,
    /// Price of keeping one byte for one hour, in wei.
    pub rate_per_byte_hour: u128,
    /// The sizes a sealed message may have. A sender pads its message to
    /// one of them, so the size the operator sees says only which class a
    /// message is in. Mail carries messages; content over the largest class
    /// belongs in storage, with the message carrying its reference.
    pub size_classes: Vec<u64>,
    /// Longest lifetime taken, in seconds.
    pub max_lifetime_s: u64,
    /// Bytes the operator gives the mailbox for mail: sealed bytes and
    /// receipts together.
    pub max_total_bytes: u64,
    /// Messages kept waiting for one recipient.
    pub max_messages_per_recipient: usize,
    /// Whether a rate of zero is meant. A mailbox that charges nothing is
    /// bounded only by the limits above, so it is refused unless this is set.
    pub allow_free: bool,
    /// Deposits one payer account may make in an hour.
    pub max_deposits_per_payer_per_hour: usize,
    /// How far a recipient's signing time may be from the mailbox clock, in
    /// milliseconds. A nonce is refused a second time within it.
    pub auth_window_ms: u64,
    /// Longest a recipient's capability may still run when it is used, in
    /// milliseconds.
    pub max_capability_lifetime_ms: u64,
    /// Price of one key package, in wei.
    pub prekey_price: u128,
    /// Largest key package a recipient may upload.
    pub max_prekey_bytes: usize,
    /// Key packages kept for one recipient, the last-resort one aside.
    pub max_prekeys_per_recipient: usize,
    /// Key packages handed out for one recipient in an hour, whoever pays,
    /// so its packages cannot be drained to leave only the last-resort one.
    pub max_fetches_per_recipient_per_hour: usize,
    /// How long an escrow must still run when it pays for a deposit, in
    /// milliseconds, so the mailbox can claim before the payer can refund.
    pub claim_margin_ms: u64,
    /// Ledger reads in a minute for vouchers not yet checked, whoever sends
    /// them: a voucher names an escrow before anything says it is paid.
    pub max_voucher_lookups_per_minute: usize,
    /// Of those, the reads for vouchers naming one escrow.
    pub max_voucher_lookups_per_escrow_per_minute: usize,
    /// Bytes of key packages and depositor policies kept for all recipients
    /// together, which a recipient addressed by a tag can have as many of as
    /// it makes tags.
    pub max_key_bytes_total: u64,
}

impl MailboxConfig {
    /// A mailbox on `chain_id` charging `rate_per_byte_hour` wei: messages
    /// padded to 1, 4, 16 or 64 KiB kept up to 30 days, 1 GiB in total, 1000
    /// messages waiting per recipient, 600 deposits per payer per hour, a 60
    /// second signing window, a one hour claim margin and capabilities
    /// running at most 30 days; key packages of up to 4 KiB, 100 kept per
    /// recipient, 60 handed out per recipient per hour, each priced as a 4
    /// KiB message kept for an hour; 6000 ledger reads a minute for unchecked
    /// vouchers, 120 for one escrow; 256 MiB of key packages and policies in all.
    pub fn new(chain_id: u64, rate_per_byte_hour: u128) -> Self {
        Self {
            chain_id,
            rate_per_byte_hour,
            size_classes: vec![1024, 4 * 1024, 16 * 1024, 64 * 1024],
            max_lifetime_s: 30 * 24 * 3600,
            max_total_bytes: 1024 * 1024 * 1024,
            max_messages_per_recipient: 1000,
            allow_free: false,
            max_deposits_per_payer_per_hour: 600,
            auth_window_ms: 60_000,
            claim_margin_ms: HOUR_MS,
            max_capability_lifetime_ms: 30 * 24 * HOUR_MS,
            // A post-quantum MLS key package signed by a composite DID key
            // (ML-DSA-65 alone signs 3.3 KB) is about 10 KB as uploaded.
            prekey_price: rate_per_byte_hour.saturating_mul(16 * 1024),
            max_prekey_bytes: 16 * 1024,
            max_prekeys_per_recipient: 100,
            max_fetches_per_recipient_per_hour: 60,
            max_voucher_lookups_per_minute: 6000,
            max_voucher_lookups_per_escrow_per_minute: 120,
            max_key_bytes_total: 256 * 1024 * 1024,
        }
    }

    /// What keeping `size` bytes for `lifetime_s` seconds costs: the rate
    /// times the size times the hours, a started hour counting whole.
    pub fn charge(&self, size: u64, lifetime_s: u64) -> Option<u128> {
        self.rate_per_byte_hour
            .checked_mul(u128::from(size))?
            .checked_mul(u128::from(lifetime_s.div_ceil(3600)))
    }
}

/// The keys a P-256 key signs with for an account or a DID.
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// The P-256 key and the ML-DSA-65 key enrolled for it.
    pub key: CompositePublicKey,
    /// The relying party a passkey assertion by it must be for, when a
    /// keystore links it.
    pub rp_id: Option<String>,
}

/// An escrow as consensus state has it.
#[derive(Debug, Clone)]
pub struct EscrowView {
    /// The payer's account, in its 32-byte slot.
    pub payer: [u8; 32],
    /// The payee's account, in its 32-byte slot.
    pub payee: [u8; 32],
    /// What the payer put in, in wei.
    pub amount: u128,
    /// What the payee already claimed, in wei.
    pub claimed: u128,
    /// Unix milliseconds after which the payer may refund the rest.
    pub expires_at_ms: u64,
}

/// What the mailbox reads from the ledger. Every read is one any caller of
/// a node's public interface can make.
#[async_trait]
pub trait Ledger: Send + Sync {
    /// The keys the P-256 key `public_key` signs with for `account`, as a
    /// signature by it is judged in a block, or `None` when it does not act
    /// for the account.
    async fn account_key(
        &self,
        public_key: &[u8],
        account: &[u8; 32],
    ) -> Result<Option<SigningKey>, MailboxError>;

    /// The keys the P-256 key `public_key` signs with for `did`: the key the
    /// DID resolves to, or one its account's keystore links. `None` when it
    /// does not act for the DID, or the DID is unknown or revoked.
    async fn did_key(
        &self,
        did: &str,
        public_key: &[u8],
    ) -> Result<Option<SigningKey>, MailboxError>;

    /// The escrow `escrow_id`, if it exists and is open.
    async fn escrow(&self, escrow_id: &[u8; 32]) -> Result<Option<EscrowView>, MailboxError>;
}

/// What a sender needs to know before it deposits.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MailboxInfo {
    /// The operator's service key: it signs receipts, and a recipient pins
    /// it beside the mailbox's address in its DID document.
    pub operator_key: CompositePublicKey,
    /// The account an escrow must name as payee, hex.
    pub payee: String,
    /// The chain whose escrows pay the mailbox.
    pub chain_id: u64,
    /// Price of keeping one byte for one hour, in wei.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub rate_per_byte_hour: u128,
    /// The sizes a sealed message may have.
    pub size_classes: Vec<u64>,
    /// Longest lifetime taken, in seconds.
    pub max_lifetime_s: u64,
    /// Price of one key package, in wei.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub prekey_price: u128,
    /// Largest key package a recipient may upload.
    pub max_prekey_bytes: usize,
    /// Key packages kept for one recipient.
    pub max_prekeys_per_recipient: usize,
}

pub(crate) struct State {
    pub(crate) store: Store,
    pub(crate) recent: Recent,
}

impl State {
    /// Forgets nonces and deposit times that left their windows.
    fn prune(&mut self, window_ms: u64, now_ms: u64) {
        self.recent
            .nonces
            .retain(|_, signed_at| *signed_at + window_ms >= now_ms);
        for times in [&mut self.recent.deposits, &mut self.recent.fetches] {
            times.retain(|_, times| {
                while times.front().is_some_and(|t| t + HOUR_MS <= now_ms) {
                    times.pop_front();
                }
                !times.is_empty()
            });
        }
    }

    /// Rewrites the log of recent requests once most of it is records that
    /// left their windows.
    pub(crate) fn compact(&mut self, window_ms: u64, now_ms: u64) -> Result<(), MailboxError> {
        if self.store.recent_lines() < 1024 {
            return Ok(());
        }
        self.prune(window_ms, now_ms);
        if self.store.recent_lines() >= 2 * self.recent.len() {
            self.store.compact_recent(&self.recent)?;
        }
        Ok(())
    }
}

/// A mailbox an operator runs beside its node.
pub struct Mailbox {
    pub(crate) config: MailboxConfig,
    pub(crate) ledger: Arc<dyn Ledger>,
    pub(crate) signer: Arc<dyn HybridSigner>,
    pub(crate) state: Mutex<State>,
    lookups: Mutex<Lookups>,
}

/// How long the ledger reads for unchecked vouchers are counted, in
/// milliseconds.
const LOOKUP_WINDOW_MS: u64 = 60_000;

/// When the ledger was last read for a voucher that no signature had yet
/// vouched for. A read costs the node a request whoever sent the voucher, so
/// they are bounded as a whole and for each escrow before any is made.
#[derive(Debug, Default)]
struct Lookups {
    all: VecDeque<u64>,
    by_escrow: HashMap<[u8; 32], VecDeque<u64>>,
}

impl Lookups {
    /// Counts a read for `escrow_id`, or refuses it when a limit is reached.
    fn admit(
        &mut self,
        escrow_id: &[u8; 32],
        now_ms: u64,
        config: &MailboxConfig,
    ) -> Result<(), MailboxError> {
        let leaving = |t: &u64| t + LOOKUP_WINDOW_MS <= now_ms;
        while self.all.front().is_some_and(leaving) {
            self.all.pop_front();
        }
        if self.by_escrow.len() > self.all.len() {
            self.by_escrow.retain(|_, times| {
                while times.front().is_some_and(leaving) {
                    times.pop_front();
                }
                !times.is_empty()
            });
        }
        if self.all.len() >= config.max_voucher_lookups_per_minute {
            return Err(MailboxError::RateLimited);
        }
        let times = self.by_escrow.entry(*escrow_id).or_default();
        while times.front().is_some_and(leaving) {
            times.pop_front();
        }
        if times.len() >= config.max_voucher_lookups_per_escrow_per_minute {
            return Err(MailboxError::RateLimited);
        }
        times.push_back(now_ms);
        self.all.push_back(now_ms);
        Ok(())
    }
}

/// What an escrow will have been charged in total once `charge` is added
/// under `voucher`, if the voucher and the escrow cover it. What the ledger
/// shows as already claimed counts too.
pub(crate) fn total_after(
    account: Option<&EscrowAccount>,
    escrow: &EscrowView,
    voucher: &EscrowVoucher,
    charge: u128,
) -> Result<u128, MailboxError> {
    let charged = account
        .map_or(0, |a| a.charged)
        .max(escrow.claimed)
        .checked_add(charge)
        .ok_or_else(|| MailboxError::Unpaid("the charge overflows".to_string()))?;
    if voucher.cumulative_amount < charged {
        return Err(MailboxError::Unpaid(format!(
            "the voucher covers {} wei in total and this request brings the total to {charged}",
            voucher.cumulative_amount
        )));
    }
    if voucher.cumulative_amount > escrow.amount {
        return Err(MailboxError::Unpaid(format!(
            "the voucher promises {} wei and the escrow holds {}",
            voucher.cumulative_amount, escrow.amount
        )));
    }
    Ok(charged)
}

/// The higher of the voucher an escrow's record holds and `voucher`.
pub(crate) fn highest(account: Option<&EscrowAccount>, voucher: &EscrowVoucher) -> EscrowVoucher {
    match account {
        Some(a) if a.voucher.cumulative_amount > voucher.cumulative_amount => a.voucher.clone(),
        _ => voucher.clone(),
    }
}

/// Gas a `ClaimEscrow` transaction is given per voucher it claims. The
/// ledger charges 55,000 per voucher and nothing else for the claim; the
/// rest is margin.
pub const CLAIM_GAS_PER_VOUCHER: u64 = 60_000;

/// Gas a `ClaimEscrow` transaction of `vouchers` vouchers is given.
pub fn claim_gas(vouchers: usize) -> u64 {
    200_000 + CLAIM_GAS_PER_VOUCHER * vouchers as u64
}

pub(crate) fn entry_id(
    recipient_did: &str,
    sealed_sha256: &[u8; 32],
    voucher: &EscrowVoucher,
) -> String {
    let mut h = Sha256::new();
    h.update(b"tenzro/mailbox/v1/id");
    h.update((recipient_did.len() as u32).to_be_bytes());
    h.update(recipient_did.as_bytes());
    h.update(sealed_sha256);
    h.update(voucher.escrow_id);
    h.update(voucher.cumulative_amount.to_be_bytes());
    hex::encode(&h.finalize()[..16])
}

pub(crate) fn verify(
    key: &CompositePublicKey,
    rp_id: Option<&str>,
    context: SignatureContext,
    message: &[u8],
    signature: &CompositeSignature,
    policy: PqPolicy,
) -> bool {
    match rp_id {
        Some(rp_id) => verify_composite_for(rp_id, key, context, message, signature, policy),
        None => verify_composite(key, context, message, signature, policy),
    }
    .is_ok()
}

impl Mailbox {
    /// Opens the mailbox kept in the directory `root`. `signer` is the
    /// operator's service key: it signs receipts, and its account is the
    /// payee every paying escrow must name. The nonces and deposit times
    /// still inside their windows at `now_ms` are kept from the last run.
    pub fn open(
        config: MailboxConfig,
        root: &Path,
        ledger: Arc<dyn Ledger>,
        signer: Arc<dyn HybridSigner>,
        now_ms: u64,
    ) -> Result<Self, MailboxError> {
        if config.rate_per_byte_hour == 0 && !config.allow_free {
            return Err(MailboxError::Config(
                "the rate is zero; set allow_free if the mailbox is meant to charge nothing"
                    .to_string(),
            ));
        }
        let store = Store::open(root)?;
        let (recent, damaged) = store.recent()?;
        let mut state = State { store, recent };
        if damaged > 0 {
            // A lost line may be a nonce or a deposit time, so both kinds of
            // request wait out the window their records cover.
            // A request may be dated a whole window ahead of the clock, so a
            // lost nonce stays usable until two windows after the crash.
            state.recent.auth_closed_until_ms = now_ms + 2 * config.auth_window_ms;
            state.recent.deposits_closed_until_ms = now_ms + HOUR_MS;
            tracing::warn!(
                "{damaged} damaged line(s) in the log of recent requests: recipients' requests are refused for {} ms and deposits for an hour",
                2 * config.auth_window_ms
            );
        }
        state.prune(config.auth_window_ms, now_ms);
        state.store.compact_recent(&state.recent)?;
        Ok(Self {
            config,
            ledger,
            signer,
            state: Mutex::new(state),
            lookups: Mutex::new(Lookups::default()),
        })
    }

    /// What a sender needs to know before it deposits.
    pub fn info(&self) -> MailboxInfo {
        let operator_key = self.signer.public_key().clone();
        MailboxInfo {
            payee: hex::encode(operator_key.account_slot()),
            operator_key,
            chain_id: self.config.chain_id,
            rate_per_byte_hour: self.config.rate_per_byte_hour,
            size_classes: self.config.size_classes.clone(),
            max_lifetime_s: self.config.max_lifetime_s,
            prekey_price: self.config.prekey_price,
            max_prekey_bytes: self.config.max_prekey_bytes,
            max_prekeys_per_recipient: self.config.max_prekeys_per_recipient,
        }
    }

    /// Takes a sealed message for an offline recipient and returns the
    /// operator's receipt. The deposit is refused unless its voucher pays
    /// for it. Offering the same message under the same voucher again
    /// returns the first receipt and charges nothing.
    pub async fn deposit(&self, deposit: &Deposit, now_ms: u64) -> Result<Receipt, MailboxError> {
        let size = deposit.sealed.len() as u64;
        if deposit.recipient_did.is_empty() || deposit.recipient_did.len() > MAX_DID_LEN {
            return Err(MailboxError::Recipient { max: MAX_DID_LEN });
        }
        if !self.config.size_classes.contains(&size) {
            return Err(MailboxError::SizeClass {
                size,
                classes: self.config.size_classes.clone(),
            });
        }
        if deposit.lifetime_s == 0 || deposit.lifetime_s > self.config.max_lifetime_s {
            return Err(MailboxError::Lifetime {
                lifetime_s: deposit.lifetime_s,
                max_s: self.config.max_lifetime_s,
            });
        }
        let charge = self
            .config
            .charge(size, deposit.lifetime_s)
            .ok_or_else(|| MailboxError::Unpaid("the charge overflows".to_string()))?;
        let sealed_sha256: [u8; 32] = Sha256::digest(&deposit.sealed).into();
        let voucher = &deposit.voucher;
        let binding = deposit_binding(&deposit.recipient_did, &sealed_sha256, deposit.lifetime_s);
        let escrow = self.check_voucher(voucher, &binding, now_ms).await?;
        // The payer's hourly count is checked, and a refused attempt counted,
        // before anything else is asked of the ledger: a voucher sent again
        // and again costs its payer its allowance.
        let (policy, epoch) = {
            let state = self.state.lock();
            if now_ms < state.recent.deposits_closed_until_ms {
                return Err(MailboxError::Recovering);
            }
            if state.recent.count(&escrow.payer, now_ms)
                >= self.config.max_deposits_per_payer_per_hour
            {
                return Err(MailboxError::RateLimited);
            }
            state.store.policy(&deposit.recipient_did)?
        };
        if let Err(e) = self.check_depositor(deposit, &policy, epoch, now_ms).await {
            let mut state = self.state.lock();
            state
                .recent
                .deposits
                .entry(escrow.payer)
                .or_default()
                .push_back(now_ms);
            state.store.record_deposit(&escrow.payer, now_ms)?;
            return Err(e);
        }

        let mut state = self.state.lock();
        let id = entry_id(&deposit.recipient_did, &sealed_sha256, voucher);
        if let Some(receipt) = state.store.entry(&deposit.recipient_did, &id)? {
            return Ok(receipt);
        }
        let escrow_id = hex::encode(voucher.escrow_id);
        let account = state.store.account(&escrow_id)?;
        if account.as_ref().is_some_and(|a| a.took(&id)) {
            return Err(MailboxError::Spent);
        }
        if state.recent.count(&escrow.payer, now_ms) >= self.config.max_deposits_per_payer_per_hour
        {
            return Err(MailboxError::RateLimited);
        }
        if state.store.count(&deposit.recipient_did)? >= self.config.max_messages_per_recipient {
            return Err(MailboxError::RecipientFull);
        }
        let charged = total_after(account.as_ref(), &escrow, voucher, charge)?;
        let mut receipt = Receipt {
            id,
            recipient_did: deposit.recipient_did.clone(),
            sealed_sha256: hex::encode(sealed_sha256),
            size,
            deposited_at_ms: now_ms,
            expires_at_ms: now_ms + deposit.lifetime_s * 1000,
            escrow_id,
            charge,
            signature: CompositeSignature::default(),
        };
        receipt.signature = self
            .signer
            .sign(SignatureContext::Mailbox, &receipt.preimage())
            .map_err(|e| MailboxError::Signing(e.to_string()))?;
        state.store.insert(
            &receipt,
            &deposit.sealed,
            account.as_ref(),
            highest(account.as_ref(), voucher),
            charged,
            escrow.expires_at_ms,
            self.config.max_total_bytes,
        )?;
        state
            .recent
            .deposits
            .entry(escrow.payer)
            .or_default()
            .push_back(now_ms);
        state.store.record_deposit(&escrow.payer, now_ms)?;
        state.compact(self.config.auth_window_ms, now_ms)?;
        Ok(receipt)
    }

    /// The escrow behind `voucher`, once the voucher is the payer's own
    /// promise to this mailbox for the request whose binding is `binding`.
    pub(crate) async fn check_voucher(
        &self,
        voucher: &EscrowVoucher,
        binding: &[u8; 32],
        now_ms: u64,
    ) -> Result<EscrowView, MailboxError> {
        let unpaid = |why: &str| MailboxError::Unpaid(why.to_string());
        if voucher.agent.is_some() {
            return Err(unpaid("a voucher signed for an agent is not accepted"));
        }
        if voucher.binding != *binding {
            return Err(unpaid("the voucher is not bound to this request"));
        }
        self.lookups
            .lock()
            .admit(&voucher.escrow_id, now_ms, &self.config)?;
        let escrow = self
            .ledger
            .escrow(&voucher.escrow_id)
            .await?
            .ok_or_else(|| unpaid("no open escrow has the voucher's id"))?;
        if escrow.payee != self.signer.public_key().account_slot() {
            return Err(unpaid("the escrow does not pay this mailbox"));
        }
        if escrow.expires_at_ms < now_ms.saturating_add(self.config.claim_margin_ms) {
            return Err(unpaid("the escrow ends too soon to be claimed"));
        }
        let key = self
            .ledger
            .account_key(&voucher.public_key, &escrow.payer)
            .await?
            .ok_or_else(|| unpaid("the voucher key does not act for the escrow's payer"))?;
        let message = attributed_voucher_preimage(
            escrow_voucher_preimage(
                self.config.chain_id,
                &voucher.escrow_id,
                voucher.cumulative_amount,
                &voucher.binding,
            ),
            voucher.attribution.as_ref(),
        );
        if !verify(
            &key.key,
            key.rp_id.as_deref(),
            SignatureContext::EscrowVoucher,
            &message,
            &voucher.signature,
            PqPolicy::Required,
        ) {
            return Err(unpaid("the voucher signature does not verify"));
        }
        Ok(escrow)
    }

    /// The key `public_key` names for `recipient`, and how much of a
    /// signature by it must verify: a tag's own composite key, both halves;
    /// a DID's key as its document or keystore has it, its ML-DSA half when
    /// it has one.
    async fn recipient_key(
        &self,
        recipient: &str,
        public_key: &[u8],
    ) -> Result<Option<(SigningKey, PqPolicy)>, MailboxError> {
        if recipient.starts_with(TAG_PREFIX) {
            return Ok(tag_key(recipient, public_key)
                .map(|key| (SigningKey { key, rp_id: None }, PqPolicy::Required)));
        }
        Ok(self
            .ledger
            .did_key(recipient, public_key)
            .await?
            .map(|k| (k, PqPolicy::WhenPresent)))
    }

    /// Checks that `auth` is the recipient's own request for `action` on
    /// `entry_id`, signed within the window and not seen before.
    pub(crate) async fn authorize(
        &self,
        action: Action,
        auth: &Auth,
        entry_id: &str,
        now_ms: u64,
    ) -> Result<(), MailboxError> {
        let window = self.config.auth_window_ms;
        if now_ms.abs_diff(auth.timestamp_ms) > window {
            return Err(MailboxError::Unauthorized(
                "the signing time is outside the accepted window".to_string(),
            ));
        }
        let message = auth_preimage(
            &self.signer.public_key().p256,
            action,
            &auth.did,
            entry_id,
            auth.timestamp_ms,
            &auth.nonce,
        );
        let signed = self
            .recipient_key(&auth.did, &auth.public_key)
            .await?
            .is_some_and(|(k, policy)| {
                verify(
                    &k.key,
                    k.rp_id.as_deref(),
                    SignatureContext::Mailbox,
                    &message,
                    &auth.signature,
                    policy,
                )
            });
        if !signed {
            return Err(MailboxError::Unauthorized(
                "the signature is not by a key of the recipient".to_string(),
            ));
        }
        let mut state = self.state.lock();
        if now_ms < state.recent.auth_closed_until_ms {
            return Err(MailboxError::Recovering);
        }
        if state.recent.nonces.contains_key(&auth.nonce) {
            return Err(MailboxError::Unauthorized(
                "the nonce was already used".to_string(),
            ));
        }
        state.store.record_nonce(&auth.nonce, auth.timestamp_ms)?;
        state.recent.nonces.insert(auth.nonce, auth.timestamp_ms);
        state.compact(window, now_ms)
    }

    /// Whether `proof` is `did`'s signature over this deposit at this
    /// mailbox.
    async fn sender_signed(
        &self,
        proof: &SenderProof,
        escrow_id: &[u8; 32],
        binding: &[u8; 32],
    ) -> Result<bool, MailboxError> {
        let message = sender_preimage(
            &self.signer.public_key().p256,
            &proof.did,
            escrow_id,
            binding,
        );
        Ok(self
            .ledger
            .did_key(&proof.did, &proof.public_key)
            .await?
            .is_some_and(|k| {
                verify(
                    &k.key,
                    k.rp_id.as_deref(),
                    SignatureContext::Mailbox,
                    &message,
                    &proof.signature,
                    PqPolicy::WhenPresent,
                )
            }))
    }

    /// Whether `deposit` may be made under the recipient's `policy`, set at
    /// `epoch`.
    async fn check_depositor(
        &self,
        deposit: &Deposit,
        policy: &DepositPolicy,
        epoch: u64,
        now_ms: u64,
    ) -> Result<(), MailboxError> {
        let DepositPolicy::Only(depositors) = policy else {
            return Ok(());
        };
        let refused = |why: &str| MailboxError::NotAllowed(why.to_string());
        // The DID the deposit proves it comes from, if it proves one.
        let sender = match &deposit.sender {
            Some(proof) if proof.did.is_empty() || proof.did.len() > MAX_DID_LEN => {
                return Err(refused("the sender proof names no DID"));
            }
            Some(proof) => {
                if !self
                    .sender_signed(proof, &deposit.voucher.escrow_id, &deposit.voucher.binding)
                    .await?
                {
                    return Err(refused("the sender proof is not by a key of its DID"));
                }
                Some(proof.did.as_str())
            }
            None => None,
        };
        let Some(capability) = &deposit.capability else {
            return match sender {
                Some(did) if depositors.contains(did) => Ok(()),
                _ => Err(refused("the depositor is not one the recipient named")),
            };
        };
        if capability.operator_key != self.signer.public_key().p256 {
            return Err(refused("the capability is for another mailbox"));
        }
        if capability.recipient_did != deposit.recipient_did {
            return Err(refused("the capability is for another recipient"));
        }
        if capability.policy_epoch != epoch {
            return Err(refused(
                "the recipient set its policy again since the capability",
            ));
        }
        if capability.expires_at_ms <= now_ms {
            return Err(refused("the capability expired"));
        }
        if capability.expires_at_ms > now_ms.saturating_add(self.config.max_capability_lifetime_ms)
        {
            return Err(refused(
                "the capability lasts longer than this mailbox takes",
            ));
        }
        match &capability.depositor_did {
            Some(named) if named.is_empty() => {
                return Err(refused("the capability names an empty depositor"));
            }
            Some(named) if sender != Some(named.as_str()) => {
                return Err(refused("the capability is for another depositor"));
            }
            _ => {}
        }
        let signed = self
            .recipient_key(&deposit.recipient_did, &capability.public_key)
            .await?
            .is_some_and(|(k, policy)| {
                verify(
                    &k.key,
                    k.rp_id.as_deref(),
                    SignatureContext::Mailbox,
                    &capability.preimage(),
                    &capability.signature,
                    policy,
                )
            });
        if !signed {
            return Err(refused("the capability is not signed by the recipient"));
        }
        Ok(())
    }

    /// Sets who may deposit for the recipient that signed `auth`, and
    /// returns the policy epoch it starts: capabilities given under an
    /// earlier epoch no longer count.
    pub async fn set_policy(
        &self,
        auth: &Auth,
        policy: &DepositPolicy,
        now_ms: u64,
    ) -> Result<u64, MailboxError> {
        if let DepositPolicy::Only(dids) = policy
            && (dids.len() > MAX_POLICY_DEPOSITORS
                || dids.iter().any(|d| d.is_empty() || d.len() > MAX_DID_LEN))
        {
            return Err(MailboxError::Policy(format!(
                "at most {MAX_POLICY_DEPOSITORS} DIDs of 1..={MAX_DID_LEN} bytes"
            )));
        }
        self.authorize(Action::Policy, auth, &policy.digest(), now_ms)
            .await?;
        self.state
            .lock()
            .store
            .set_policy(&auth.did, policy, self.config.max_key_bytes_total)
    }

    /// The receipts of the messages held for the recipient, oldest first.
    pub async fn list(&self, auth: &Auth, now_ms: u64) -> Result<Vec<Receipt>, MailboxError> {
        self.authorize(Action::List, auth, "", now_ms).await?;
        let mut entries = self.state.lock().store.entries(&auth.did)?;
        entries.retain(|r| r.expires_at_ms > now_ms);
        Ok(entries)
    }

    /// One message held for the recipient: its receipt and sealed bytes. The
    /// message stays until the recipient acknowledges it or it expires.
    pub async fn collect(
        &self,
        auth: &Auth,
        id: &str,
        now_ms: u64,
    ) -> Result<(Receipt, Vec<u8>), MailboxError> {
        self.authorize(Action::Collect, auth, id, now_ms).await?;
        let state = self.state.lock();
        let receipt = state
            .store
            .entry(&auth.did, id)?
            .filter(|r| r.expires_at_ms > now_ms)
            .ok_or(MailboxError::NotFound)?;
        let sealed = state.store.sealed(&receipt)?;
        if hex::encode(Sha256::digest(&sealed)) != receipt.sealed_sha256 {
            return Err(MailboxError::Store(format!(
                "message {id} does not match its receipt"
            )));
        }
        Ok((receipt, sealed))
    }

    /// Drops a message the recipient confirms it read.
    pub async fn ack(&self, auth: &Auth, id: &str, now_ms: u64) -> Result<(), MailboxError> {
        self.authorize(Action::Ack, auth, id, now_ms).await?;
        let mut state = self.state.lock();
        let receipt = state
            .store
            .entry(&auth.did, id)?
            .ok_or(MailboxError::NotFound)?;
        state.store.remove(&receipt)
    }

    /// Drops every message whose lifetime ended by `now_ms` and returns how
    /// many were dropped.
    pub fn sweep(&self, now_ms: u64) -> Result<usize, MailboxError> {
        self.state.lock().store.sweep(now_ms)
    }

    /// What each paying escrow owes: its highest voucher and the cumulative
    /// amount to claim under it.
    pub fn due(&self) -> Result<Vec<EscrowAccount>, MailboxError> {
        self.state.lock().store.accounts()
    }
}
