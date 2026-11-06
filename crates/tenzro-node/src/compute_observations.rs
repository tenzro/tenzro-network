//! What this validator's router observed providers charge and deliver: the
//! readings a validator submits to the chain's compute index, and the public
//! feed agents discover providers through.
//!
//! This is not a market. The compute index that compute claims settle against
//! lives in chain state (`tenzro_vm::native::compute_claim`), frozen per epoch
//! once two thirds of bonded stake submitted readings; this window only holds
//! the evidence one validator reads its submission from.
//!
//! # Why observations and not announcements
//!
//! A provider announcement says what the provider *claims*: its price list,
//! its hardware, its region. None of that is evidence. A feed built from
//! announcements would let a provider advertise a low price and charge a high
//! one, or advertise low latency and serve slowly, and an index built on it
//! would settle a compute claim on numbers the counterparty wrote.
//!
//! So every number here comes from a [`SignedObservation`]: the routing node,
//! not the provider, records what a call actually cost, how long it actually
//! took, and whether it succeeded. The router already meters these at its
//! own HTTP boundary (latency is its own clock; token counts are capped at the
//! wire byte count), so the observation adds only a signature and a gossip hop.
//!
//! # Who counts
//!
//! Anyone can sign an observation, so signatures alone prove nothing about
//! the market. Two rules bound what an observation can move:
//!
//! - [`ObservationWindow::ingest`] admits only observations signed by an active
//!   validator identity (the node installs that check with
//!   [`ObservationWindow::set_observer_filter`]; with none installed, nothing is
//!   admitted). Validators are staked and slashable, so a fabricated
//!   observation has a named, bonded author.
//! - A (provider, model) entry is `attested` — and only attested entries enter
//!   the index — once at least [`MIN_DISTINCT_OBSERVERS`] different validators
//!   have observed it. One colluding validator routing to its own provider
//!   cannot move the index alone.
//!
//! Hardware class and region are recorded as the observer saw them in the
//! provider's announcement. They remain the provider's claim; the feed labels
//! them as such and prices them with the observed numbers beside them.
//!
//! # Window and persistence
//!
//! The window keeps a rolling [`OBSERVATION_WINDOW_MS`] of observations in
//! memory, refilled from gossip. Nothing settles against it directly.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::{Signature, Signer, verify};
pub use tenzro_model::routing::{ObservationDraft, ObservationSink};
use tenzro_types::hardware::HardwareClass;
use tenzro_types::primitives::Address;

/// How long an observation stays in the window.
pub const OBSERVATION_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
/// How far in the future an observation's timestamp may be.
pub const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
/// Distinct validator observers an entry needs before it is attested.
pub const MIN_DISTINCT_OBSERVERS: usize = 2;
/// Observations kept per (provider, model); the oldest is dropped first.
pub const MAX_OBSERVATIONS_PER_ENTRY: usize = 512;
/// Distinct (provider, model) entries kept; beyond it new entries are refused.
pub const MAX_ENTRIES: usize = 20_000;

const DOMAIN: &[u8] = b"tenzro/compute-observation/v1";

/// Errors from signing, verifying or ingesting an observation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ObservationError {
    /// The observation's signature does not verify.
    #[error("observation signature does not verify")]
    BadSignature,
    /// Signing failed.
    #[error("signing failed: {0}")]
    Signing(String),
    /// The signer is not an active validator identity (or no filter is set).
    #[error("observer is not an active validator")]
    NotValidator,
    /// The observer signed an observation of itself.
    #[error("observer and provider are the same party")]
    SelfObservation,
    /// Outside the window, or too far in the future.
    #[error("observation timestamp {0} is outside the accepted window")]
    Stale(i64),
    /// Already ingested.
    #[error("duplicate observation")]
    Duplicate,
    /// The window is at [`MAX_ENTRIES`].
    #[error("observation window is full")]
    Full,
}

/// An observation signed by the node that routed the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedObservation {
    /// Model the call was routed for.
    pub model_id: String,
    /// Provider that served the call.
    pub provider: Address,
    /// Hardware class the provider announced.
    pub hardware_class: HardwareClass,
    /// Region the provider declared; empty when undeclared.
    pub region: String,
    /// Whether the call succeeded.
    pub success: bool,
    /// Router-measured latency in milliseconds.
    pub latency_ms: u64,
    /// Price charged, in wei.
    pub price_wei: u128,
    /// Billed input tokens.
    pub input_tokens: u32,
    /// Billed output tokens.
    pub output_tokens: u32,
    /// When the call completed (unix ms).
    pub observed_at_ms: i64,
    /// Observer's Ed25519 public key.
    pub observer_pubkey: Vec<u8>,
    /// Ed25519 signature over [`Self::preimage`].
    pub signature: Vec<u8>,
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

impl SignedObservation {
    /// Domain-separated, length-prefixed bytes the signature covers. Every
    /// variable-length field carries its length, so no two distinct
    /// observations share a preimage.
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        put_bytes(&mut out, DOMAIN);
        put_bytes(&mut out, self.model_id.as_bytes());
        put_bytes(&mut out, self.provider.as_bytes());
        out.push(self.hardware_class as u8);
        put_bytes(&mut out, self.region.as_bytes());
        out.push(self.success as u8);
        out.extend_from_slice(&self.latency_ms.to_le_bytes());
        out.extend_from_slice(&self.price_wei.to_le_bytes());
        out.extend_from_slice(&self.input_tokens.to_le_bytes());
        out.extend_from_slice(&self.output_tokens.to_le_bytes());
        out.extend_from_slice(&self.observed_at_ms.to_le_bytes());
        put_bytes(&mut out, &self.observer_pubkey);
        out
    }

    /// Sign a draft as observed at `observed_at_ms` with the observer's
    /// Ed25519 node key.
    pub fn sign<S: Signer + ?Sized>(
        draft: ObservationDraft,
        observed_at_ms: i64,
        signer: &S,
    ) -> Result<Self, ObservationError> {
        let mut obs = SignedObservation {
            model_id: draft.model_id,
            provider: draft.provider,
            hardware_class: draft.hardware_class,
            region: draft.region,
            success: draft.success,
            latency_ms: draft.latency_ms,
            price_wei: draft.price_wei,
            input_tokens: draft.input_tokens,
            output_tokens: draft.output_tokens,
            observed_at_ms,
            observer_pubkey: signer.public_key().as_bytes().to_vec(),
            signature: Vec::new(),
        };
        let sig = signer
            .sign(&obs.preimage())
            .map_err(|e| ObservationError::Signing(e.to_string()))?;
        obs.signature = sig.as_bytes().to_vec();
        Ok(obs)
    }

    /// Verify the signature against the embedded observer key.
    pub fn verify(&self) -> Result<(), ObservationError> {
        let pk = PublicKey::new(KeyType::Ed25519, self.observer_pubkey.clone());
        let sig = Signature::new(KeyType::Ed25519, self.signature.clone());
        verify(&pk, &self.preimage(), &sig).map_err(|_| ObservationError::BadSignature)
    }

    /// Content address used for de-duplication.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.preimage()).into()
    }

    /// Price of one second of served compute, in wei. `None` for a failed or
    /// unpriced call, or one with no measurable latency.
    pub fn price_per_compute_second_wei(&self) -> Option<u128> {
        if !self.success || self.price_wei == 0 || self.latency_ms == 0 {
            return None;
        }
        Some(self.price_wei.saturating_mul(1000) / self.latency_ms as u128)
    }

    /// Price of one thousand output tokens, in wei. `None` when there is no
    /// priced output to divide by.
    pub fn price_per_1k_output_tokens_wei(&self) -> Option<u128> {
        if !self.success || self.price_wei == 0 || self.output_tokens == 0 {
            return None;
        }
        Some(self.price_wei.saturating_mul(1000) / self.output_tokens as u128)
    }
}

/// The 32-byte ledger address of an Ed25519 key: its 20-byte key address,
/// zero-padded, which is how the ledger widens a key-derived address.
fn observer_ledger_address(pubkey: &[u8]) -> Address {
    let key_addr = PublicKey::new(KeyType::Ed25519, pubkey.to_vec()).to_address();
    let mut bytes = [0u8; 32];
    bytes[..20].copy_from_slice(key_addr.as_bytes());
    Address::new(bytes)
}

/// Filter on the observer's Ed25519 public key.
pub type ObserverFilter = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Selects feed entries. Unset fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedQuery {
    /// Only this model.
    #[serde(default)]
    pub model_id: Option<String>,
    /// Only this hardware class.
    #[serde(default)]
    pub hardware_class: Option<HardwareClass>,
    /// Only this region (case-insensitive).
    #[serde(default)]
    pub region: Option<String>,
    /// Only entries observed by enough distinct validators.
    #[serde(default)]
    pub attested_only: bool,
}

/// One (provider, model) row of the feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEntry {
    /// Provider address.
    pub provider: Address,
    /// Model id.
    pub model_id: String,
    /// Hardware class the provider announced (claim).
    pub hardware_class: HardwareClass,
    /// Region the provider declared (claim); empty when undeclared.
    pub region: String,
    /// Observations in the window.
    pub observations: usize,
    /// Distinct validator observers.
    pub distinct_observers: usize,
    /// Whether `distinct_observers >= MIN_DISTINCT_OBSERVERS`.
    pub attested: bool,
    /// Observed success rate in basis points.
    pub success_rate_bps: u32,
    /// Median router-measured latency of successful calls.
    pub latency_p50_ms: Option<u64>,
    /// 90th-percentile router-measured latency of successful calls.
    pub latency_p90_ms: Option<u64>,
    /// Median price per 1k output tokens, in wei.
    pub price_per_1k_output_tokens_wei: Option<u128>,
    /// Median price per second of served compute, in wei.
    pub price_per_compute_second_wei: Option<u128>,
    /// Most recent observation time (unix ms).
    pub last_observed_ms: i64,
}

/// One constituent of an index snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexConstituent {
    /// Provider address.
    pub provider: Address,
    /// Model id.
    pub model_id: String,
    /// The entry's median price per compute-second, in wei.
    pub price_per_compute_second_wei: u128,
}

/// The compute price index for one (hardware class, region) bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexSnapshot {
    /// Bucket hardware class.
    pub hardware_class: HardwareClass,
    /// Bucket region; `None` means every region.
    pub region: Option<String>,
    /// Window the index covers.
    pub window_ms: i64,
    /// Median across constituents of their median price per compute-second.
    /// `None` when the bucket has no attested, priced entry.
    pub price_per_compute_second_wei: Option<u128>,
    /// Attested entries that contributed.
    pub constituents: Vec<IndexConstituent>,
    /// Observations behind those constituents.
    pub observations: usize,
    /// When the snapshot was computed (unix ms).
    pub computed_at_ms: i64,
}

/// Outcome of [`ObservationWindow::ingest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Admitted.
    Accepted,
}

/// Rolling window of validator-signed observations.
#[derive(Default)]
pub struct ObservationWindow {
    entries: DashMap<(Address, String), VecDeque<SignedObservation>>,
    seen: DashMap<[u8; 32], i64>,
    observer_filter: RwLock<Option<ObserverFilter>>,
}

fn median(mut v: Vec<u128>) -> Option<u128> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}

fn percentile(mut v: Vec<u64>, pct: usize) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    let idx = ((v.len() - 1) * pct) / 100;
    Some(v[idx])
}

impl ObservationWindow {
    /// An empty market that admits nothing until a filter is installed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the check deciding whose observations count. The node passes
    /// its active-validator identity check.
    pub fn set_observer_filter(&self, filter: ObserverFilter) {
        *self.observer_filter.write() = Some(filter);
    }

    /// Verify and admit one observation.
    pub fn ingest(
        &self,
        obs: SignedObservation,
        now_ms: i64,
    ) -> Result<IngestOutcome, ObservationError> {
        if obs.observed_at_ms > now_ms + MAX_CLOCK_SKEW_MS
            || obs.observed_at_ms < now_ms - OBSERVATION_WINDOW_MS
        {
            return Err(ObservationError::Stale(obs.observed_at_ms));
        }
        obs.verify()?;
        if observer_ledger_address(&obs.observer_pubkey) == obs.provider {
            return Err(ObservationError::SelfObservation);
        }
        let admitted = self
            .observer_filter
            .read()
            .as_ref()
            .is_some_and(|f| f(&obs.observer_pubkey));
        if !admitted {
            return Err(ObservationError::NotValidator);
        }
        let digest = obs.digest();
        if self.seen.insert(digest, obs.observed_at_ms).is_some() {
            return Err(ObservationError::Duplicate);
        }
        let key = (obs.provider, obs.model_id.clone());
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_ENTRIES {
            self.seen.remove(&digest);
            return Err(ObservationError::Full);
        }
        let mut ring = self.entries.entry(key).or_default();
        ring.push_back(obs);
        while ring.len() > MAX_OBSERVATIONS_PER_ENTRY {
            if let Some(old) = ring.pop_front() {
                self.seen.remove(&old.digest());
            }
        }
        Ok(IngestOutcome::Accepted)
    }

    /// Drop everything older than the window.
    pub fn prune(&self, now_ms: i64) {
        let cutoff = now_ms - OBSERVATION_WINDOW_MS;
        self.entries.retain(|_, ring| {
            while ring.front().is_some_and(|o| o.observed_at_ms < cutoff) {
                ring.pop_front();
            }
            !ring.is_empty()
        });
        self.seen.retain(|_, at| *at >= cutoff);
    }

    fn summarize(ring: &VecDeque<SignedObservation>, cutoff: i64) -> Option<FeedEntry> {
        let live: Vec<&SignedObservation> =
            ring.iter().filter(|o| o.observed_at_ms >= cutoff).collect();
        let latest = live.iter().max_by_key(|o| o.observed_at_ms)?;
        let observers: BTreeSet<&[u8]> =
            live.iter().map(|o| o.observer_pubkey.as_slice()).collect();
        let successes = live.iter().filter(|o| o.success).count();
        let ok_latencies: Vec<u64> = live
            .iter()
            .filter(|o| o.success)
            .map(|o| o.latency_ms)
            .collect();
        Some(FeedEntry {
            provider: latest.provider,
            model_id: latest.model_id.clone(),
            hardware_class: latest.hardware_class,
            region: latest.region.clone(),
            observations: live.len(),
            distinct_observers: observers.len(),
            attested: observers.len() >= MIN_DISTINCT_OBSERVERS,
            success_rate_bps: (successes * 10_000 / live.len()) as u32,
            latency_p50_ms: percentile(ok_latencies.clone(), 50),
            latency_p90_ms: percentile(ok_latencies, 90),
            price_per_1k_output_tokens_wei: median(
                live.iter()
                    .filter_map(|o| o.price_per_1k_output_tokens_wei())
                    .collect(),
            ),
            price_per_compute_second_wei: median(
                live.iter()
                    .filter_map(|o| o.price_per_compute_second_wei())
                    .collect(),
            ),
            last_observed_ms: latest.observed_at_ms,
        })
    }

    /// Feed rows matching `query`, cheapest compute-second first (unpriced
    /// rows last).
    pub fn feed(&self, query: &FeedQuery, now_ms: i64) -> Vec<FeedEntry> {
        let cutoff = now_ms - OBSERVATION_WINDOW_MS;
        let region = query.region.as_ref().map(|r| r.to_ascii_lowercase());
        let mut rows: Vec<FeedEntry> = self
            .entries
            .iter()
            .filter(|e| query.model_id.as_ref().is_none_or(|m| &e.key().1 == m))
            .filter_map(|e| Self::summarize(e.value(), cutoff))
            .filter(|r| query.hardware_class.is_none_or(|h| r.hardware_class == h))
            .filter(|r| {
                region
                    .as_ref()
                    .is_none_or(|want| r.region.to_ascii_lowercase() == *want)
            })
            .filter(|r| !query.attested_only || r.attested)
            .collect();
        rows.sort_by(|a, b| {
            match (
                a.price_per_compute_second_wei,
                b.price_per_compute_second_wei,
            ) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => b.last_observed_ms.cmp(&a.last_observed_ms),
            }
            .then_with(|| a.provider.as_bytes().cmp(b.provider.as_bytes()))
            .then_with(|| a.model_id.cmp(&b.model_id))
        });
        rows
    }

    /// The index for one bucket: the median, across attested priced entries,
    /// of each entry's median price per compute-second. A median of medians
    /// so one provider with many observations cannot outweigh the others.
    pub fn index(
        &self,
        hardware_class: HardwareClass,
        region: Option<&str>,
        now_ms: i64,
    ) -> IndexSnapshot {
        let rows = self.feed(
            &FeedQuery {
                model_id: None,
                hardware_class: Some(hardware_class),
                region: region.map(str::to_string),
                attested_only: true,
            },
            now_ms,
        );
        let mut constituents = Vec::new();
        let mut observations = 0;
        for row in rows {
            if let Some(p) = row.price_per_compute_second_wei {
                observations += row.observations;
                constituents.push(IndexConstituent {
                    provider: row.provider,
                    model_id: row.model_id,
                    price_per_compute_second_wei: p,
                });
            }
        }
        IndexSnapshot {
            hardware_class,
            region: region.map(str::to_string),
            window_ms: OBSERVATION_WINDOW_MS,
            price_per_compute_second_wei: median(
                constituents
                    .iter()
                    .map(|c| c.price_per_compute_second_wei)
                    .collect(),
            ),
            constituents,
            observations,
            computed_at_ms: now_ms,
        }
    }

    /// Indexes for every (hardware class, region) bucket that has data.
    pub fn all_indexes(&self, now_ms: i64) -> Vec<IndexSnapshot> {
        let cutoff = now_ms - OBSERVATION_WINDOW_MS;
        let mut buckets: BTreeSet<(HardwareClass, String)> = BTreeSet::new();
        for e in self.entries.iter() {
            if let Some(row) = Self::summarize(e.value(), cutoff) {
                buckets.insert((row.hardware_class, row.region));
            }
        }
        buckets
            .into_iter()
            .map(|(h, r)| self.index(h, Some(&r), now_ms))
            .filter(|s| s.price_per_compute_second_wei.is_some())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::signatures::Ed25519SignerImpl;

    fn draft(provider: Address, price: u128, latency: u64) -> ObservationDraft {
        ObservationDraft {
            model_id: "qwen3-8b".into(),
            provider,
            hardware_class: HardwareClass::DatacenterGpu,
            region: "SG".into(),
            success: true,
            latency_ms: latency,
            price_wei: price,
            input_tokens: 100,
            output_tokens: 200,
        }
    }

    fn window_admitting_all() -> ObservationWindow {
        let m = ObservationWindow::new();
        m.set_observer_filter(Arc::new(|_| true));
        m
    }

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn sign_verify_round_trip_and_tamper_detection() {
        let s = Ed25519SignerImpl::generate().unwrap();
        let obs =
            SignedObservation::sign(draft(Address::new([1; 32]), 1000, 500), NOW, &s).unwrap();
        obs.verify().unwrap();
        let mut bad = obs.clone();
        bad.price_wei = 1;
        assert_eq!(bad.verify(), Err(ObservationError::BadSignature));
    }

    #[test]
    fn nothing_is_admitted_without_a_filter() {
        let m = ObservationWindow::new();
        let s = Ed25519SignerImpl::generate().unwrap();
        let obs =
            SignedObservation::sign(draft(Address::new([1; 32]), 1000, 500), NOW, &s).unwrap();
        assert_eq!(m.ingest(obs, NOW), Err(ObservationError::NotValidator));
    }

    #[test]
    fn non_validators_are_refused() {
        let m = ObservationWindow::new();
        m.set_observer_filter(Arc::new(|_| false));
        let s = Ed25519SignerImpl::generate().unwrap();
        let obs =
            SignedObservation::sign(draft(Address::new([1; 32]), 1000, 500), NOW, &s).unwrap();
        assert_eq!(m.ingest(obs, NOW), Err(ObservationError::NotValidator));
    }

    #[test]
    fn self_observation_duplicates_and_stale_are_refused() {
        let m = window_admitting_all();
        let s = Ed25519SignerImpl::generate().unwrap();
        let own = observer_ledger_address(s.public_key().as_bytes());
        let obs = SignedObservation::sign(draft(own, 1000, 500), NOW, &s).unwrap();
        assert_eq!(m.ingest(obs, NOW), Err(ObservationError::SelfObservation));

        let obs =
            SignedObservation::sign(draft(Address::new([1; 32]), 1000, 500), NOW, &s).unwrap();
        m.ingest(obs.clone(), NOW).unwrap();
        assert_eq!(m.ingest(obs, NOW), Err(ObservationError::Duplicate));

        let old = SignedObservation::sign(
            draft(Address::new([1; 32]), 1000, 500),
            NOW - OBSERVATION_WINDOW_MS - 1,
            &s,
        )
        .unwrap();
        assert!(matches!(
            m.ingest(old, NOW),
            Err(ObservationError::Stale(_))
        ));
    }

    #[test]
    fn one_observer_does_not_attest_and_does_not_move_the_index() {
        let m = window_admitting_all();
        let s = Ed25519SignerImpl::generate().unwrap();
        for i in 0..5 {
            let obs = SignedObservation::sign(draft(Address::new([1; 32]), 1000, 500), NOW - i, &s)
                .unwrap();
            m.ingest(obs, NOW).unwrap();
        }
        let feed = m.feed(&FeedQuery::default(), NOW);
        assert_eq!(feed.len(), 1);
        assert!(!feed[0].attested);
        assert_eq!(feed[0].distinct_observers, 1);
        let idx = m.index(HardwareClass::DatacenterGpu, Some("SG"), NOW);
        assert_eq!(idx.price_per_compute_second_wei, None);
    }

    #[test]
    fn index_is_a_median_of_attested_entry_medians() {
        let m = window_admitting_all();
        let a = Ed25519SignerImpl::generate().unwrap();
        let b = Ed25519SignerImpl::generate().unwrap();
        // Three providers at 2000, 4000, 100_000 wei per compute-second.
        for (p, price) in [(1u8, 1000u128), (2, 2000), (3, 50_000)] {
            for (i, s) in [&a, &b].into_iter().enumerate() {
                let obs = SignedObservation::sign(
                    draft(Address::new([p; 32]), price, 500),
                    NOW - i as i64,
                    s,
                )
                .unwrap();
                m.ingest(obs, NOW).unwrap();
            }
        }
        let idx = m.index(HardwareClass::DatacenterGpu, Some("sg"), NOW);
        assert_eq!(idx.constituents.len(), 3);
        assert_eq!(idx.price_per_compute_second_wei, Some(4000));
        let feed = m.feed(&FeedQuery::default(), NOW);
        assert_eq!(feed[0].price_per_compute_second_wei, Some(2000));
        assert_eq!(feed[0].price_per_1k_output_tokens_wei, Some(5000));
        assert_eq!(m.all_indexes(NOW).len(), 1);
    }

    #[test]
    fn failures_count_against_success_rate_but_not_price() {
        let m = window_admitting_all();
        let s = Ed25519SignerImpl::generate().unwrap();
        let mut d = draft(Address::new([1; 32]), 0, 30_000);
        d.success = false;
        m.ingest(SignedObservation::sign(d, NOW, &s).unwrap(), NOW)
            .unwrap();
        m.ingest(
            SignedObservation::sign(draft(Address::new([1; 32]), 1000, 500), NOW - 1, &s).unwrap(),
            NOW,
        )
        .unwrap();
        let row = &m.feed(&FeedQuery::default(), NOW)[0];
        assert_eq!(row.success_rate_bps, 5000);
        assert_eq!(row.latency_p50_ms, Some(500));
        assert_eq!(row.price_per_compute_second_wei, Some(2000));
    }

    #[test]
    fn prune_drops_expired_observations() {
        let m = window_admitting_all();
        let s = Ed25519SignerImpl::generate().unwrap();
        m.ingest(
            SignedObservation::sign(draft(Address::new([1; 32]), 1000, 500), NOW, &s).unwrap(),
            NOW,
        )
        .unwrap();
        m.prune(NOW + OBSERVATION_WINDOW_MS + 1);
        assert!(
            m.feed(&FeedQuery::default(), NOW + OBSERVATION_WINDOW_MS + 1)
                .is_empty()
        );
    }
}
