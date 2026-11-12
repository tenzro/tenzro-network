//! Message signing where every private-key operation is in hardware.
//!
//! The identity key (P-256 with ML-DSA-65, held in a TPM or secure element
//! behind a [`HybridSigner`]) signs one statement per batch: the Merkle root
//! of the batch's messages. No session key exists in memory. Each message
//! travels with a [`BatchProof`] (32 bytes per tree level) and the one
//! [`RootSignature`] the batch shares. A verifier checks the root signature
//! once ([`CertificateCache`]) and then pays only hashing per message.
//!
//! Both legs of the identity key must be present and verify, so the batch
//! holds if either Ed25519-class or ML-DSA assumption breaks, not only when
//! both do. Batch size and flush interval are parameters ([`BatchParams`]),
//! never constants. A message waits at most the flush interval plus one
//! hardware signing time.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::composite::{
    CompositePublicKey, CompositeSignature, HybridSigner, PqPolicy, SignatureContext,
    verify_composite,
};
use crate::error::{CryptoError, Result};
use crate::session::CertificateCache;

const LEAF: u8 = 0;
const NODE: u8 = 1;
const MAX_PATH: usize = 40;

fn bad(what: &str) -> CryptoError {
    CryptoError::InvalidSignature(what.to_string())
}

fn leaf_hash(message: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update([LEAF])
        .chain_update(b"tenzro/batch/leaf/v1")
        .chain_update((message.len() as u64).to_be_bytes())
        .chain_update(message)
        .finalize()
        .into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update([NODE])
        .chain_update(l)
        .chain_update(r)
        .finalize()
        .into()
}

fn split(n: u64) -> u64 {
    1u64 << (63 - (n - 1).leading_zeros())
}

fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = split(leaves.len() as u64) as usize;
    node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
}

fn path_of(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
    if leaves.len() == 1 {
        return;
    }
    let k = split(leaves.len() as u64) as usize;
    if index < k {
        path_of(&leaves[..k], index, out);
        out.push(root_of(&leaves[k..]));
    } else {
        path_of(&leaves[k..], index - k, out);
        out.push(root_of(&leaves[..k]));
    }
}

fn fold(index: u64, count: u64, leaf: [u8; 32], path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if count == 1 {
        return path.is_empty().then_some(leaf);
    }
    let k = split(count);
    let (top, rest) = path.split_last()?;
    if index < k {
        Some(node_hash(&fold(index, k, leaf, rest)?, top))
    } else {
        Some(node_hash(top, &fold(index - k, count - k, leaf, rest)?))
    }
}

/// Where a message sits in a signed batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchProof {
    pub index: u32,
    pub count: u32,
    pub path: Vec<[u8; 32]>,
}

impl BatchProof {
    /// The root this proof leads to for `message`.
    pub fn root_for(&self, message: &[u8]) -> Option<[u8; 32]> {
        if self.count == 0 || self.index >= self.count || self.path.len() > MAX_PATH {
            return None;
        }
        fold(
            u64::from(self.index),
            u64::from(self.count),
            leaf_hash(message),
            &self.path,
        )
    }
}

/// The identity key's signature over a batch root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSignature {
    pub signed_at_ms: u64,
    pub count: u32,
    pub root: [u8; 32],
    pub signature: CompositeSignature,
}

impl RootSignature {
    /// The bytes the identity key signs. They name the identity, so a root
    /// signature cannot be moved to another identity.
    pub fn message(
        identity: &CompositePublicKey,
        signed_at_ms: u64,
        count: u32,
        root: &[u8; 32],
    ) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&(identity.p256.len() as u32).to_le_bytes());
        m.extend_from_slice(&identity.p256);
        match &identity.pq {
            Some(pq) => {
                m.push(1);
                m.extend_from_slice(&(pq.len() as u32).to_le_bytes());
                m.extend_from_slice(pq);
            }
            None => m.push(0),
        }
        m.extend_from_slice(&signed_at_ms.to_le_bytes());
        m.extend_from_slice(&count.to_le_bytes());
        m.extend_from_slice(root);
        m
    }

    /// Verifies under `identity` with the governed requirement the node last
    /// read from chain state ([`set_pq_leg_required_from_ms`]).
    pub fn verify(&self, identity: &CompositePublicKey) -> Result<()> {
        self.verify_under(identity, pq_leg_required_from_ms())
    }

    /// Both legs verify under `identity` when the root was signed at or after
    /// `pq_required_from_ms`: an identity without an ML-DSA key, or a root
    /// without the leg, is then refused, so the hybrid guarantee cannot be
    /// stripped. Before that moment a root signed with the classical leg alone
    /// by an identity that has no ML-DSA key verifies; an identity that has
    /// one still needs both legs (see [`verify_composite`]).
    pub fn verify_under(
        &self,
        identity: &CompositePublicKey,
        pq_required_from_ms: u64,
    ) -> Result<()> {
        let required = self.signed_at_ms >= pq_required_from_ms;
        if required && (identity.pq.is_none() || self.signature.pq.is_none()) {
            return Err(bad("a batch root needs an identity with an ML-DSA key"));
        }
        let policy = if required {
            PqPolicy::Required
        } else {
            PqPolicy::WhenPresent
        };
        let message = Self::message(identity, self.signed_at_ms, self.count, &self.root);
        CertificateCache::global().check(&message, &self.signature, || {
            verify_composite(
                identity,
                SignatureContext::BatchRoot,
                &message,
                &self.signature,
                policy,
            )
            .map(|_| ())
        })
    }
}

/// A message's signature: its place in a batch and the batch's root signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchedSignature {
    pub proof: BatchProof,
    pub root: RootSignature,
}

impl BatchedSignature {
    /// For a record made at `made_at_ms`, checked at `now_ms`: the batch was
    /// signed no earlier than the record (within `skew_ms`) and no later than
    /// now (within `skew_ms`), and the signature stands. A batch is signed
    /// after the records it holds, by up to the flush interval plus the
    /// hardware's time.
    pub fn verify_for_record(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        made_at_ms: u64,
        now_ms: u64,
        skew_ms: u64,
    ) -> Result<()> {
        self.verify_for_record_under(
            identity,
            message,
            made_at_ms,
            now_ms,
            skew_ms,
            pq_leg_required_from_ms(),
        )
    }

    /// [`verify_for_record`](Self::verify_for_record) with the moment from
    /// which the ML-DSA leg is required given.
    pub fn verify_for_record_under(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        made_at_ms: u64,
        now_ms: u64,
        skew_ms: u64,
        pq_required_from_ms: u64,
    ) -> Result<()> {
        if self.root.signed_at_ms.saturating_add(skew_ms) < made_at_ms {
            return Err(bad("the batch was signed before the record was made"));
        }
        self.verify_under(identity, message, now_ms, skew_ms, pq_required_from_ms)
    }

    /// The verification a consensus verifier uses, judged by the time of the
    /// block it runs in (`block_ms`) and not by dates the signer wrote.
    ///
    /// The signing node's clock supplies `root.signed_at_ms` and the record's
    /// own date, and a hardware key signs whatever date it is given, so neither
    /// can decide whether the ML-DSA leg is required. Two rules follow.
    /// First, once `block_ms` has reached `pq_required_from_ms`, the leg is
    /// required whatever the dates say: a classical-only signer cannot backdate
    /// to before the moment. Second, both dates must lie within `max_age_ms`
    /// (plus `skew_ms`) before the block, so a date cannot be pushed back
    /// without limit; a date after the block is refused by the existing skew
    /// check. Before the moment a classical-only root still verifies, as
    /// [`verify_for_record_under`](Self::verify_for_record_under) judges it.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_record_at_block(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        made_at_ms: u64,
        block_ms: u64,
        skew_ms: u64,
        max_age_ms: u64,
        pq_required_from_ms: u64,
    ) -> Result<()> {
        let oldest = block_ms.saturating_sub(max_age_ms).saturating_sub(skew_ms);
        if self.root.signed_at_ms < oldest {
            return Err(bad("the batch was signed too long before this block"));
        }
        if made_at_ms < oldest {
            return Err(bad("the record is dated too long before this block"));
        }
        let required_from = if block_ms >= pq_required_from_ms {
            0
        } else {
            pq_required_from_ms
        };
        self.verify_for_record_under(
            identity,
            message,
            made_at_ms,
            block_ms,
            skew_ms,
            required_from,
        )
    }

    /// `message` is in the batch the identity signed, which was signed no
    /// later than `at_ms` plus `skew_ms`.
    pub fn verify(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        at_ms: u64,
        skew_ms: u64,
    ) -> Result<()> {
        self.verify_under(identity, message, at_ms, skew_ms, pq_leg_required_from_ms())
    }

    /// [`verify`](Self::verify) with the moment from which the ML-DSA leg is
    /// required given, for a verifier that reads it from chain state.
    pub fn verify_under(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        at_ms: u64,
        skew_ms: u64,
        pq_required_from_ms: u64,
    ) -> Result<()> {
        let root = self
            .proof
            .root_for(message)
            .ok_or_else(|| bad("batch proof"))?;
        if root != self.root.root || self.proof.count != self.root.count {
            return Err(bad("batch proof"));
        }
        if self.root.signed_at_ms > at_ms.saturating_add(skew_ms) {
            return Err(bad("batch signed in the future"));
        }
        self.root.verify_under(identity, pq_required_from_ms)
    }
}

/// Governed, not constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchParams {
    pub max_batch: usize,
    pub flush_interval_ms: u64,
}

const PQ_REFUSAL: &str = "this machine identity key has no ML-DSA-65 leg and the network now \
requires it: records are not signed until a key with the leg is provisioned \
(`tenzro-node tpm provision`) or governance moves records.pq_leg_required_from_ms";

/// Collects messages and has the hardware identity key sign a batch root.
pub struct HardwareBatcher {
    identity: Arc<dyn HybridSigner>,
    params: BatchParams,
    pending: Vec<Vec<u8>>,
    oldest_ms: Option<u64>,
}

impl HardwareBatcher {
    pub fn new(identity: Arc<dyn HybridSigner>, params: BatchParams) -> Result<Self> {
        if params.max_batch == 0 || params.max_batch > u32::MAX as usize {
            return Err(bad("batch size out of range"));
        }
        Ok(Self {
            identity,
            params,
            pending: Vec::new(),
            oldest_ms: None,
        })
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Why this identity may not sign a batch at `now_ms`, if it may not: from
    /// the governed moment a root needs the ML-DSA leg, and a key without one
    /// can only produce roots every verifier refuses. Signing them would cost a
    /// hardware signature each, to be thrown away.
    pub fn refusal(&self, now_ms: u64) -> Option<&'static str> {
        (self.identity.public_key().pq.is_none() && now_ms >= pq_leg_required_from_ms())
            .then_some(PQ_REFUSAL)
    }

    /// The most messages one batch holds.
    pub fn capacity(&self) -> usize {
        self.params.max_batch
    }

    /// Drops everything pending without signing it.
    pub fn discard(&mut self) {
        self.pending.clear();
        self.oldest_ms = None;
    }

    /// Adds a message; signs when the batch is full. A failed hardware
    /// signature keeps the messages pending.
    pub fn submit(
        &mut self,
        message: Vec<u8>,
        now_ms: u64,
    ) -> Result<Option<Vec<BatchedSignature>>> {
        self.oldest_ms.get_or_insert(now_ms);
        self.pending.push(message);
        if self.pending.len() >= self.params.max_batch {
            return self.flush(now_ms).map(Some);
        }
        Ok(None)
    }

    /// Signs the pending messages once the oldest has waited the interval.
    pub fn tick(&mut self, now_ms: u64) -> Result<Option<Vec<BatchedSignature>>> {
        match self.oldest_ms {
            Some(t) if now_ms.saturating_sub(t) >= self.params.flush_interval_ms => {
                self.flush(now_ms).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// One hardware signature over everything pending.
    pub fn flush(&mut self, now_ms: u64) -> Result<Vec<BatchedSignature>> {
        if self.pending.is_empty() {
            return Err(bad("nothing to sign"));
        }
        if let Some(why) = self.refusal(now_ms) {
            return Err(bad(why));
        }
        let leaves: Vec<[u8; 32]> = self.pending.iter().map(|m| leaf_hash(m)).collect();
        let root = root_of(&leaves);
        let count = leaves.len() as u32;
        let message = RootSignature::message(self.identity.public_key(), now_ms, count, &root);
        let signature = self.identity.sign(SignatureContext::BatchRoot, &message)?;
        let root_sig = RootSignature {
            signed_at_ms: now_ms,
            count,
            root,
            signature,
        };
        root_sig.verify(self.identity.public_key())?;
        let out = (0..leaves.len())
            .map(|i| {
                let mut path = Vec::new();
                path_of(&leaves, i, &mut path);
                BatchedSignature {
                    proof: BatchProof {
                        index: i as u32,
                        count,
                        path,
                    },
                    root: root_sig.clone(),
                }
            })
            .collect();
        self.pending.clear();
        self.oldest_ms = None;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Signing without waiting for the caller to block on a batch
// ---------------------------------------------------------------------------

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

type Waiter = mpsc::Sender<BatchedSignature>;

/// A pending batched signature: resolves when the batch it joined is signed.
pub struct Ticket(mpsc::Receiver<BatchedSignature>);

impl Ticket {
    /// Waits for the batch to be signed, at most `timeout`.
    pub fn wait(self, timeout: Duration) -> Result<BatchedSignature> {
        self.0.recv_timeout(timeout).map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => bad("the batch was not signed in time"),
            mpsc::RecvTimeoutError::Disconnected => {
                bad("the batch was dropped without a signature (signing refused)")
            }
        })
    }
}

/// Most extra time an adaptive wait adds to a signer's base wait.
pub const MAX_ADAPTIVE_EXTRA: Duration = Duration::from_secs(28);

struct State {
    batcher: HardwareBatcher,
    waiting: Vec<Waiter>,
    last_immediate_ms: Option<u64>,
    refused: bool,
}

/// A hardware identity's batch signing, shared by every record type of a
/// node. `submit` joins the next batch and returns a [`Ticket`]; `tick` is
/// driven by a timer and signs a batch that has waited the flush interval;
/// `sign_now` signs at once (a batch of everything pending), under a governed
/// minimum interval, for the callers that cannot wait. Every path ends in the
/// identity key's hardware; no key is held here.
pub struct BatchService {
    identity: Arc<dyn HybridSigner>,
    state: Mutex<State>,
    immediate_min_interval_ms: u64,
    /// Recent worst hardware time for one flush attempt, in ms: it follows
    /// the slowest attempt up at once and decays a quarter per attempt.
    slow_flush_ms: AtomicU64,
}

impl BatchService {
    pub fn new(
        identity: Arc<dyn HybridSigner>,
        params: BatchParams,
        immediate_min_interval_ms: u64,
    ) -> Result<Self> {
        let batcher = HardwareBatcher::new(identity.clone(), params)?;
        Ok(Self {
            identity,
            state: Mutex::new(State {
                batcher,
                waiting: Vec::new(),
                last_immediate_ms: None,
                refused: false,
            }),
            immediate_min_interval_ms,
            slow_flush_ms: AtomicU64::new(0),
        })
    }

    /// Recent worst hardware time of one flush attempt, failed attempts
    /// included. A signer waits longer while the hardware is slow.
    pub fn observed_flush_ms(&self) -> u64 {
        self.slow_flush_ms.load(Ordering::Relaxed)
    }

    fn note_flush(&self, started: std::time::Instant) {
        let took = started.elapsed().as_millis() as u64;
        let prev = self.slow_flush_ms.load(Ordering::Relaxed);
        self.slow_flush_ms
            .store(took.max(prev - prev / 4), Ordering::Relaxed);
    }

    /// The identity whose hardware key signs.
    pub fn identity(&self) -> &CompositePublicKey {
        self.identity.public_key()
    }

    /// Most messages that may wait for a signature: a hardware that keeps
    /// failing does not grow the queue without bound.
    const QUEUE_FACTOR: usize = 16;

    /// Called under the lock before any message is taken: when the identity may
    /// not sign now, everything waiting is dropped (its tickets end at once
    /// with an error) and nothing is queued. Not latched: a governed change of
    /// the moment ends the refusal.
    ///
    /// `admitting` is true for a call that would add a message: only such a
    /// call is refused when the queue is full. A tick never is, because it is
    /// what empties the queue once the hardware signs again.
    fn gate(st: &mut State, now_ms: u64, admitting: bool) -> Result<()> {
        if let Some(why) = st.batcher.refusal(now_ms) {
            st.batcher.discard();
            st.waiting.clear();
            st.refused = true;
            return Err(bad(why));
        }
        st.refused = false;
        if admitting && st.batcher.pending() >= st.batcher.capacity() * Self::QUEUE_FACTOR {
            return Err(bad(
                "the signing queue is full: the hardware is not signing",
            ));
        }
        Ok(())
    }

    /// Whether the last signing attempt was refused because this identity
    /// lacks the ML-DSA leg the network requires.
    pub fn refused(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).refused
    }

    fn resolve(waiting: &mut Vec<Waiter>, sigs: Vec<BatchedSignature>) {
        for (w, sig) in waiting.drain(..).zip(sigs) {
            let _ = w.send(sig);
        }
    }

    /// Joins the next batch. A batch that fills is signed now; if the
    /// hardware fails, the messages stay pending and `tick` retries.
    pub fn submit(&self, message: Vec<u8>, now_ms: u64) -> Result<Ticket> {
        let (tx, rx) = mpsc::channel();
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::gate(&mut st, now_ms, true)?;
        st.waiting.push(tx);
        let started = std::time::Instant::now();
        let flushed = st.batcher.submit(message, now_ms);
        if !matches!(flushed, Ok(None)) {
            self.note_flush(started);
        }
        if let Ok(Some(sigs)) = flushed {
            Self::resolve(&mut st.waiting, sigs);
        }
        Ok(Ticket(rx))
    }

    /// Signs the pending batch when its oldest message has waited the
    /// interval. Returns how many tickets resolved.
    pub fn tick(&self, now_ms: u64) -> Result<usize> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.batcher.pending() > 0 {
            Self::gate(&mut st, now_ms, false)?;
        }
        // A failed signature leaves everything pending and the next tick tries
        // the whole queue again; submissions are refused while it is full, so
        // the retry is bounded and the queue empties when the hardware recovers.
        let started = std::time::Instant::now();
        let ticked = st.batcher.tick(now_ms);
        if !matches!(ticked, Ok(None)) {
            self.note_flush(started);
        }
        match ticked? {
            Some(sigs) => {
                let n = sigs.len();
                Self::resolve(&mut st.waiting, sigs);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    /// Signs `message` now, with everything already pending in the same
    /// batch. Refused when the previous immediate signature was less than
    /// the governed interval ago, so the hardware is not driven per message.
    pub fn sign_now(&self, message: Vec<u8>, now_ms: u64) -> Result<BatchedSignature> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::gate(&mut st, now_ms, true)?;
        if let Some(last) = st.last_immediate_ms
            && now_ms.saturating_sub(last) < self.immediate_min_interval_ms
        {
            return Err(bad("immediate signing is rate limited"));
        }
        let (tx, rx) = mpsc::channel();
        st.waiting.push(tx);
        // Keep waiters and pending messages aligned: submit, then force.
        let _ = st.batcher.submit(message, now_ms);
        if st.batcher.pending() > 0 {
            let started = std::time::Instant::now();
            let flushed = st.batcher.flush(now_ms);
            self.note_flush(started);
            let sigs = flushed?;
            Self::resolve(&mut st.waiting, sigs);
        }
        st.last_immediate_ms = Some(now_ms);
        rx.try_recv().map_err(|_| bad("the batch was not signed"))
    }
}

// ---------------------------------------------------------------------------
// The signature field of a record
// ---------------------------------------------------------------------------

/// A record's signature: the identity key's hardware signature over the
/// Merkle root of a batch of records, with the record's path to that root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSignature {
    pub batched: BatchedSignature,
}

static BATCH_SKEW_MS: AtomicU64 = AtomicU64::new(60_000);

/// How far ahead of the verifier's clock a batch may have been signed. A
/// process-wide value, 60 seconds unless a caller sets it; it is not a governed
/// parameter and the node does not set it from chain state, so every node
/// judges with the same constant.
pub fn set_batch_skew_ms(ms: u64) {
    BATCH_SKEW_MS.store(ms, Ordering::Relaxed);
}

pub fn batch_skew_ms() -> u64 {
    BATCH_SKEW_MS.load(Ordering::Relaxed)
}

static PQ_LEG_REQUIRED_FROM_MS: AtomicU64 = AtomicU64::new(u64::MAX);

/// The moment from which a batch root needs the ML-DSA leg (the node sets it
/// from chain state, see `records.pq_leg_required_from_ms`). Never until set.
pub fn set_pq_leg_required_from_ms(from_ms: u64) {
    PQ_LEG_REQUIRED_FROM_MS.store(from_ms, Ordering::Relaxed);
}

pub fn pq_leg_required_from_ms() -> u64 {
    PQ_LEG_REQUIRED_FROM_MS.load(Ordering::Relaxed)
}

impl RecordSignature {
    pub fn batched(sig: BatchedSignature) -> Self {
        Self { batched: sig }
    }

    /// Verified at `at_ms` (the batch's own date), within the clock skew.
    pub fn verify(&self, identity: &CompositePublicKey, message: &[u8], at_ms: u64) -> Result<()> {
        self.batched
            .verify(identity, message, at_ms, batch_skew_ms())
    }

    /// Verified now.
    pub fn verify_now(&self, identity: &CompositePublicKey, message: &[u8]) -> Result<()> {
        self.verify_record_now(identity, message)
    }

    /// `message` was signed by `identity` for a record made now.
    pub fn verify_record_now(&self, identity: &CompositePublicKey, message: &[u8]) -> Result<()> {
        self.verify_record_at(identity, message, crate::session::now_ms())
    }

    /// `message` was signed by `identity`; a record is dated by its batch's
    /// root signature.
    pub fn verify_record_at(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        _made_at_ms: u64,
    ) -> Result<()> {
        self.batched
            .verify(identity, message, crate::session::now_ms(), batch_skew_ms())
    }
}

// ---------------------------------------------------------------------------
// One signing interface for records
// ---------------------------------------------------------------------------

/// Signs a record for the node's identity. A record type holds a
/// [`RecordSignature`] (or the batched form its wire format carries) and
/// takes this trait where it once took a session signer, so the signing
/// form is chosen by the node, not by the record.
pub trait RecordSigner: Send + Sync {
    /// The identity the signatures verify under.
    fn identity(&self) -> &CompositePublicKey;
    /// Signs `message`. The batched signer waits for its batch to be signed
    /// in hardware, at most its configured time.
    fn sign_record(&self, message: &[u8]) -> Result<RecordSignature>;
}

/// A record signer for tests: every record is signed in a batch of one at
/// once, with no ticker.
#[cfg(any(test, feature = "test-keys"))]
pub struct ImmediateRecordSigner(BatchService);

#[cfg(any(test, feature = "test-keys"))]
impl ImmediateRecordSigner {
    pub fn new(identity: Arc<dyn HybridSigner>) -> Self {
        Self(
            BatchService::new(
                identity,
                BatchParams {
                    max_batch: 8,
                    flush_interval_ms: 1_000,
                },
                0,
            )
            .expect("a batch service over a test identity"),
        )
    }

    pub fn identity(&self) -> &CompositePublicKey {
        self.0.identity()
    }
}

#[cfg(any(test, feature = "test-keys"))]
impl RecordSigner for ImmediateRecordSigner {
    fn identity(&self) -> &CompositePublicKey {
        self.0.identity()
    }
    fn sign_record(&self, message: &[u8]) -> Result<RecordSignature> {
        self.0
            .sign_now(message.to_vec(), crate::session::now_ms())
            .map(RecordSignature::batched)
    }
}

impl<T: RecordSigner + ?Sized> RecordSigner for Arc<T> {
    fn identity(&self) -> &CompositePublicKey {
        (**self).identity()
    }
    fn sign_record(&self, message: &[u8]) -> Result<RecordSignature> {
        (**self).sign_record(message)
    }
}

/// A [`RecordSigner`] over the node's hardware batch service: every
/// private-key operation of the identity happens in hardware.
pub struct BatchRecordSigner {
    service: Arc<BatchService>,
    wait: Duration,
}

impl BatchRecordSigner {
    /// `wait` bounds how long one signature waits for its batch while the
    /// hardware is quick; while it is slow the wait grows by three times the
    /// slowest recent flush, at most [`MAX_ADAPTIVE_EXTRA`].
    pub fn new(service: Arc<BatchService>, wait: Duration) -> Self {
        Self { service, wait }
    }

    /// The batch service behind this signer.
    pub fn service(&self) -> &Arc<BatchService> {
        &self.service
    }

    /// How long a signature requested now waits for its batch.
    pub fn current_wait(&self) -> Duration {
        let extra = Duration::from_millis(self.service.observed_flush_ms().saturating_mul(3));
        self.wait + extra.min(MAX_ADAPTIVE_EXTRA)
    }
}

impl RecordSigner for BatchRecordSigner {
    fn identity(&self) -> &CompositePublicKey {
        self.service.identity()
    }
    fn sign_record(&self, message: &[u8]) -> Result<RecordSignature> {
        let ticket = self
            .service
            .submit(message.to_vec(), crate::session::now_ms())?;
        ticket
            .wait(self.current_wait())
            .map(RecordSignature::batched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composite::testing::TestHybridSigner;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counted(TestHybridSigner, AtomicUsize);
    impl HybridSigner for Counted {
        fn sign(&self, c: SignatureContext, m: &[u8]) -> Result<CompositeSignature> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.sign(c, m)
        }
        fn public_key(&self) -> &CompositePublicKey {
            self.0.public_key()
        }
        fn sign_external(&self, d: &[u8]) -> Result<Vec<u8>> {
            self.0.sign_external(d)
        }
    }

    const P: BatchParams = BatchParams {
        max_batch: 4,
        flush_interval_ms: 1_000,
    };

    /// A hardware that takes `delay` per signature.
    struct Slow(TestHybridSigner, Duration);
    impl HybridSigner for Slow {
        fn sign(&self, c: SignatureContext, m: &[u8]) -> Result<CompositeSignature> {
            std::thread::sleep(self.1);
            self.0.sign(c, m)
        }
        fn public_key(&self) -> &CompositePublicKey {
            self.0.public_key()
        }
        fn sign_external(&self, d: &[u8]) -> Result<Vec<u8>> {
            self.0.sign_external(d)
        }
    }

    #[test]
    fn a_slow_hardware_lengthens_the_signer_wait_within_the_cap() {
        let slow = Arc::new(Slow(
            TestHybridSigner::hybrid(44),
            Duration::from_millis(80),
        ));
        let svc = Arc::new(BatchService::new(slow, P, 0).unwrap());
        let signer = BatchRecordSigner::new(svc.clone(), Duration::from_millis(500));
        assert_eq!(signer.current_wait(), Duration::from_millis(500));
        svc.sign_now(b"a".to_vec(), 10).unwrap();
        assert!(svc.observed_flush_ms() >= 80);
        let w = signer.current_wait();
        assert!(w >= Duration::from_millis(500 + 3 * 80), "{w:?}");
        assert!(w <= Duration::from_millis(500) + MAX_ADAPTIVE_EXTRA);
        // A hardware stall far past the cap does not grow the wait without bound.
        svc.slow_flush_ms.store(600_000, Ordering::Relaxed);
        assert_eq!(
            signer.current_wait(),
            Duration::from_millis(500) + MAX_ADAPTIVE_EXTRA
        );
    }

    #[test]
    fn the_observed_flush_time_decays_as_the_hardware_recovers() {
        let id = Arc::new(Counted(TestHybridSigner::hybrid(45), AtomicUsize::new(0)));
        let svc = BatchService::new(id, P, 0).unwrap();
        svc.slow_flush_ms.store(4_000, Ordering::Relaxed);
        svc.sign_now(b"a".to_vec(), 10).unwrap();
        assert_eq!(svc.observed_flush_ms(), 3_000);
    }

    fn rig(seed: u8) -> (Arc<Counted>, HardwareBatcher) {
        let id = Arc::new(Counted(TestHybridSigner::hybrid(seed), AtomicUsize::new(0)));
        (id.clone(), HardwareBatcher::new(id, P).unwrap())
    }

    #[test]
    fn a_full_batch_costs_one_hardware_signature_and_every_member_verifies() {
        let (id, mut b) = rig(31);
        for i in 0..3u8 {
            assert!(b.submit(vec![i], 100).unwrap().is_none());
        }
        let sigs = b.submit(vec![3], 100).unwrap().unwrap();
        assert_eq!(id.1.load(Ordering::SeqCst), 1);
        for (i, s) in sigs.iter().enumerate() {
            let again: BatchedSignature =
                serde_json::from_slice(&serde_json::to_vec(s).unwrap()).unwrap();
            again.verify(id.public_key(), &[i as u8], 200, 0).unwrap();
            assert!(again.verify(id.public_key(), b"x", 200, 0).is_err());
        }
    }

    #[test]
    fn a_partial_batch_flushes_at_the_interval_only() {
        let (id, mut b) = rig(32);
        b.submit(b"a".to_vec(), 1_000).unwrap();
        assert!(b.tick(1_999).unwrap().is_none());
        let s = b.tick(2_000).unwrap().unwrap();
        s[0].verify(id.public_key(), b"a", 2_000, 0).unwrap();
        assert!(b.tick(9_999).unwrap().is_none());
    }

    #[test]
    fn tampering_another_identity_and_a_missing_ml_dsa_leg_are_refused() {
        let (id, mut b) = rig(33);
        b.submit(b"a".to_vec(), 10).unwrap();
        let s = b.flush(10).unwrap().remove(0);
        let mut t = s.clone();
        t.root.count += 1;
        assert!(t.verify(id.public_key(), b"a", 20, 0).is_err());
        let mut t = s.clone();
        t.root.signed_at_ms += 1;
        assert!(t.verify(id.public_key(), b"a", 20, 0).is_err());
        let other = TestHybridSigner::hybrid(34);
        assert!(s.verify(other.public_key(), b"a", 20, 0).is_err());
        let mut stripped = s.clone();
        stripped.root.signature.pq = None;
        assert!(stripped.verify(id.public_key(), b"a", 20, 0).is_err());
        // The future: signed later than the verifier's time plus skew.
        assert!(s.verify(id.public_key(), b"a", 5, 0).is_err());
        s.verify(id.public_key(), b"a", 5, 5).unwrap();
        // An identity with no ML-DSA key batches with the classical leg alone, and its
        // root is refused from the governed moment on.
        let classical = Arc::new(Counted(
            TestHybridSigner::p256_only(35),
            AtomicUsize::new(0),
        ));
        let mut batcher = HardwareBatcher::new(classical.clone(), P).unwrap();
        batcher.submit(b"a".to_vec(), 10).unwrap();
        let sigs = batcher.flush(10).unwrap();
        let (m, sig) = (b"a".as_slice(), &sigs[0]);
        sig.verify_under(classical.public_key(), m, 20, 0, u64::MAX)
            .unwrap();
        assert!(
            sig.verify_under(classical.public_key(), m, 20, 0, 0)
                .is_err()
        );
    }

    #[test]
    fn every_batch_size_proves_every_member_and_nothing_else() {
        let id = Arc::new(Counted(TestHybridSigner::hybrid(36), AtomicUsize::new(0)));
        for n in 1..=9usize {
            let mut b = HardwareBatcher::new(
                id.clone(),
                BatchParams {
                    max_batch: 64,
                    flush_interval_ms: 1,
                },
            )
            .unwrap();
            for i in 0..n {
                b.submit(vec![i as u8; 3], 0).unwrap();
            }
            let sigs = b.flush(0).unwrap();
            for (i, s) in sigs.iter().enumerate() {
                s.verify(id.public_key(), &vec![i as u8; 3], 0, 0).unwrap();
                let mut moved = s.clone();
                moved.proof.index = (s.proof.index + 1) % s.proof.count;
                if n > 1 {
                    assert!(
                        moved
                            .verify(id.public_key(), &vec![i as u8; 3], 0, 0)
                            .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn a_batched_record_round_trips_and_verifies() {
        let id = Arc::new(Counted(TestHybridSigner::hybrid(41), AtomicUsize::new(0)));
        let mut b = HardwareBatcher::new(id.clone(), P).unwrap();
        b.submit(b"m".to_vec(), crate::session::now_ms()).unwrap();
        let sig = b.flush(crate::session::now_ms()).unwrap().remove(0);
        let rec = RecordSignature::batched(sig);
        let bytes = serde_json::to_vec(&rec).unwrap();
        let again: RecordSignature = serde_json::from_slice(&bytes).unwrap();
        again.verify_record_now(id.public_key(), b"m").unwrap();
        assert!(again.verify_record_now(id.public_key(), b"x").is_err());
    }

    #[test]
    fn the_service_resolves_tickets_on_a_full_batch_and_on_the_timer() {
        let id = Arc::new(Counted(TestHybridSigner::hybrid(42), AtomicUsize::new(0)));
        let svc = BatchService::new(id.clone(), P, 0).unwrap();
        let t: Vec<_> = (0..4u8).map(|i| svc.submit(vec![i], 10).unwrap()).collect();
        assert_eq!(id.1.load(Ordering::SeqCst), 1);
        for (i, t) in t.into_iter().enumerate() {
            let s = t.wait(Duration::from_millis(10)).unwrap();
            s.verify(id.public_key(), &[i as u8], 10, 0).unwrap();
        }
        let t = svc.submit(b"late".to_vec(), 100).unwrap();
        assert_eq!(svc.tick(500).unwrap(), 0);
        assert_eq!(svc.tick(1_100).unwrap(), 1);
        t.wait(Duration::from_millis(10)).unwrap();
        assert_eq!(id.1.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_immediate_path_is_hardware_signed_and_rate_limited() {
        let id = Arc::new(Counted(TestHybridSigner::hybrid(43), AtomicUsize::new(0)));
        let svc = BatchService::new(id.clone(), P, 1_000).unwrap();
        let waiting = svc.submit(b"queued".to_vec(), 0).unwrap();
        let s = svc.sign_now(b"now".to_vec(), 10).unwrap();
        s.verify(id.public_key(), b"now", 10, 0).unwrap();
        // The queued message rode the same hardware signature.
        waiting.wait(Duration::from_millis(10)).unwrap();
        assert_eq!(id.1.load(Ordering::SeqCst), 1);
        assert!(svc.sign_now(b"again".to_vec(), 500).is_err());
        svc.sign_now(b"later".to_vec(), 1_010).unwrap();
        assert_eq!(id.1.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_record_signer_signs_records_that_verify() {
        let id = Arc::new(Counted(TestHybridSigner::hybrid(91), AtomicUsize::new(0)));
        let svc = Arc::new(
            BatchService::new(
                id.clone(),
                BatchParams {
                    max_batch: 1,
                    flush_interval_ms: 1_000,
                },
                0,
            )
            .unwrap(),
        );
        let signer: Box<dyn RecordSigner> =
            Box::new(BatchRecordSigner::new(svc, Duration::from_millis(100)));
        assert_eq!(signer.identity(), id.public_key());
        let sig = signer.sign_record(b"rec").unwrap();
        sig.verify_record_now(signer.identity(), b"rec").unwrap();
        assert!(sig.verify_record_now(signer.identity(), b"other").is_err());
    }

    // -- the requirement is judged at block time --------------------------------

    fn classical_batch(
        seed: u8,
        message: &[u8],
        at: u64,
    ) -> (CompositePublicKey, BatchedSignature) {
        let id = Arc::new(TestHybridSigner::p256_only(seed));
        let pk = id.public_key().clone();
        let mut b = HardwareBatcher::new(id, P).unwrap();
        b.submit(message.to_vec(), at).unwrap();
        (pk, b.flush(at).unwrap().remove(0))
    }

    #[test]
    fn a_classical_root_dated_before_the_moment_is_refused_once_the_block_is_past_it() {
        let from = 1_000_000;
        let skew = 60_000;
        let age = 3_600_000;
        let (pk, sig) = classical_batch(11, b"receipt", from - 1_000);
        // A block before the moment accepts the classical-only root.
        sig.verify_for_record_at_block(&pk, b"receipt", from - 1_000, from - 500, skew, age, from)
            .unwrap();
        // A block at or after the moment refuses it, though the root is dated
        // before the moment and well within the age window: the date is the
        // signer's own claim and decides nothing.
        for block in [from, from + 1, from + 60_000, from + age] {
            assert!(
                sig.verify_for_record_at_block(
                    &pk,
                    b"receipt",
                    from - 1_000,
                    block,
                    skew,
                    age,
                    from
                )
                .is_err(),
                "block {block}"
            );
        }
        // Far enough past the window it is refused for its age as well.
        let err = sig
            .verify_for_record_at_block(
                &pk,
                b"receipt",
                from - 1_000,
                from + 10 * age,
                skew,
                age,
                from,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("too long before"), "{err}");
    }

    #[test]
    fn a_hybrid_root_is_accepted_within_the_window_and_refused_beyond_it() {
        let from = 100_000_000;
        let id = Arc::new(TestHybridSigner::hybrid(12));
        let pk = id.public_key().clone();
        let mut b = HardwareBatcher::new(id, P).unwrap();
        b.submit(b"r".to_vec(), from + 10_000).unwrap();
        let sig = b.flush(from + 10_000).unwrap().remove(0);
        sig.verify_for_record_at_block(
            &pk,
            b"r",
            from + 10_000,
            from + 20_000,
            60_000,
            3_600_000,
            from,
        )
        .unwrap();
        assert!(
            sig.verify_for_record_at_block(
                &pk,
                b"r",
                from + 10_000,
                from + 10_000_000,
                60_000,
                3_600_000,
                from
            )
            .is_err()
        );
        // A record dated long before its root is refused for its own date.
        assert!(
            sig.verify_for_record_at_block(&pk, b"r", 1, from + 20_000, 60_000, 3_600_000, from)
                .is_err()
        );
    }

    // -- a classical-only node after the moment ----------------------------------

    static GLOBAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Failing(TestHybridSigner, AtomicUsize);
    impl HybridSigner for Failing {
        fn sign(&self, _: SignatureContext, _: &[u8]) -> Result<CompositeSignature> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Err(bad("the hardware is busy"))
        }
        fn public_key(&self) -> &CompositePublicKey {
            self.0.public_key()
        }
        fn sign_external(&self, d: &[u8]) -> Result<Vec<u8>> {
            self.0.sign_external(d)
        }
    }

    #[test]
    fn a_classical_only_service_refuses_once_and_does_not_sign_after_the_moment() {
        let _guard = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
        let before = pq_leg_required_from_ms();
        let t = 2_000_000_000_000_000u64;
        set_pq_leg_required_from_ms(t);
        let id = Arc::new(Counted(
            TestHybridSigner::p256_only(13),
            AtomicUsize::new(0),
        ));
        let svc = BatchService::new(id.clone(), P, 0).unwrap();
        let ticket = svc.submit(b"a".to_vec(), t - 1).unwrap();
        assert!(svc.tick(t).is_err());
        assert!(svc.refused());
        assert!(
            ticket
                .wait(Duration::from_millis(50))
                .unwrap_err()
                .to_string()
                .contains("refused")
        );
        assert!(svc.submit(b"b".to_vec(), t).is_err());
        assert!(svc.sign_now(b"c".to_vec(), t).is_err());
        assert_eq!(
            id.1.load(Ordering::SeqCst),
            0,
            "no hardware signature is spent"
        );
        // Governance moving the moment back ends the refusal.
        set_pq_leg_required_from_ms(u64::MAX);
        svc.submit(b"d".to_vec(), t).unwrap();
        assert!(!svc.refused());
        set_pq_leg_required_from_ms(before);
    }

    #[test]
    fn a_hardware_that_keeps_failing_does_not_grow_the_queue_without_bound() {
        let id = Arc::new(Failing(TestHybridSigner::hybrid(14), AtomicUsize::new(0)));
        let svc = BatchService::new(id, P, 0).unwrap();
        let accepted = (0..1_000)
            .filter(|i| svc.submit(vec![*i as u8, (*i >> 8) as u8], 1).is_ok())
            .count();
        assert_eq!(accepted, P.max_batch * 16);
    }

    struct Flaky(TestHybridSigner, AtomicUsize, usize);
    impl HybridSigner for Flaky {
        fn sign(&self, c: SignatureContext, m: &[u8]) -> Result<CompositeSignature> {
            if self.1.fetch_add(1, Ordering::SeqCst) < self.2 {
                return Err(bad("the hardware is busy"));
            }
            self.0.sign(c, m)
        }
        fn public_key(&self) -> &CompositePublicKey {
            self.0.public_key()
        }
        fn sign_external(&self, d: &[u8]) -> Result<Vec<u8>> {
            self.0.sign_external(d)
        }
    }

    #[test]
    fn a_full_queue_empties_and_signing_resumes_once_the_hardware_recovers() {
        let id = Arc::new(Flaky(
            TestHybridSigner::hybrid(15),
            AtomicUsize::new(0),
            100,
        ));
        let svc = BatchService::new(id.clone(), P, 0).unwrap();
        let cap = P.max_batch * 16;
        // Every full-batch flush fails while the hardware is busy; the queue
        // fills to its bound and no further.
        let mut tickets = Vec::new();
        for i in 0..cap + 20 {
            if let Ok(t) = svc.submit(vec![i as u8, (i >> 8) as u8], 1) {
                tickets.push(t);
            }
        }
        assert_eq!(tickets.len(), cap);
        assert!(
            svc.submit(b"more".to_vec(), 1).is_err(),
            "full queue refuses new messages"
        );
        // Ticks keep trying, each failing while the hardware is busy, and the
        // queue does not grow.
        let mut failures = 0;
        let mut signed = 0;
        for k in 0..200u64 {
            match svc.tick(5_000 + k) {
                Ok(n) => {
                    signed += n;
                    break;
                }
                Err(_) => failures += 1,
            }
        }
        assert!(failures > 0, "the busy hardware was retried");
        assert_eq!(
            signed, cap,
            "the whole queue is signed in one batch once the hardware works"
        );
        for t in tickets {
            t.wait(Duration::from_millis(100)).unwrap();
        }
        // And new messages are accepted and signed again.
        let t = svc.submit(b"after".to_vec(), 10_000).unwrap();
        svc.tick(20_000).unwrap();
        t.wait(Duration::from_millis(100)).unwrap();
    }
}
