//! Keyed prefix affinity.
//!
//! A provider that served a prompt holds its prefix warm, and routing the next
//! request that shares that prefix to the same provider saves a prefill. What
//! must not happen is that anyone else can learn which prefixes are warm, or
//! benefit from another caller's warm prefix: either one reveals the other
//! caller's prompt, through a public fingerprint or through time to first
//! token.
//!
//! So every warm prefix is recorded under a **cache salt**, a secret 32-byte
//! value scoped to one principal:
//!
//! * a request names its salt through [`scoped`]. A transport derives it with
//!   [`principal_salt`] from the caller it authenticated, or takes the salt a
//!   forwarding node attached for its own caller. An anonymous caller has no
//!   salt and nothing it sends is recorded;
//! * the runtime records each served prompt as [`salted_prefix_digests`] under
//!   the current salt into a bounded [`WarmPrefixIndex`];
//! * a router asks a provider how much of a prompt it holds warm by sending it
//!   the same digests. Only a party holding both the salt and the prompt can
//!   produce them, and a provider only finds a match among prefixes recorded
//!   under that salt.
//!
//! The only thing published is the number of warm runs a provider holds
//! ([`tenzro_types::PrefixCacheSummary`]).

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
pub use tenzro_types::model::{PREFIX_RUN_BYTES, PrefixDigest, salted_prefix_digests};
use tenzro_types::primitives::Address;

/// A principal's cache salt.
pub type Salt = [u8; 32];

/// Most digests one model's index holds before the oldest are forgotten.
pub const MAX_WARM_DIGESTS: usize = 4096;

/// Most digests a probe may carry. A prompt longer than this many runs is
/// probed on its leading runs, which is where a shared prefix lives.
pub const MAX_PROBE_DIGESTS: usize = 256;

tokio::task_local! {
    static SALT: Salt;
}

/// Run `f` with `salt` as the current cache salt. `None` runs it without one,
/// so nothing it serves is recorded as warm.
pub async fn scoped<F: Future>(salt: Option<Salt>, f: F) -> F::Output {
    match salt {
        Some(s) => SALT.scope(s, f).await,
        None => f.await,
    }
}

/// The cache salt the current task is running under, if any.
pub fn current() -> Option<Salt> {
    SALT.try_with(|s| *s).ok()
}

/// Carry the current salt into work handed to another task. A task-local does
/// not cross `tokio::spawn`.
pub fn inherit<F: Future>(f: F) -> impl Future<Output = F::Output> {
    scoped(current(), f)
}

/// Per-process secret mixed into every salt this process derives. Random,
/// held only in memory, never sent anywhere: a restart simply starts every
/// principal on a fresh salt.
fn process_secret() -> &'static [u8; 32] {
    static SECRET: OnceLock<[u8; 32]> = OnceLock::new();
    SECRET.get_or_init(rand::random)
}

/// The cache salt for an authenticated principal, stable for the life of the
/// process.
pub fn principal_salt(principal: &str) -> Salt {
    let mut h = Sha256::new();
    h.update(b"tenzro/cache-salt");
    h.update(process_secret());
    h.update(principal.as_bytes());
    h.finalize().into()
}

/// Parse a salt carried as 64 hex characters.
pub fn parse_salt(hex_salt: &str) -> Option<Salt> {
    let bytes = hex::decode(hex_salt.trim()).ok()?;
    bytes.try_into().ok()
}

/// The warm digests one model holds, oldest forgotten first.
#[derive(Debug, Default)]
pub struct WarmPrefixIndex {
    present: HashSet<PrefixDigest>,
    order: VecDeque<PrefixDigest>,
}

impl WarmPrefixIndex {
    /// Record a served prompt's digests.
    pub fn record(&mut self, digests: &[PrefixDigest]) {
        for d in digests {
            if self.present.insert(*d) {
                self.order.push_back(*d);
            }
        }
        while self.order.len() > MAX_WARM_DIGESTS {
            if let Some(old) = self.order.pop_front() {
                self.present.remove(&old);
            }
        }
    }

    /// Leading runs of `digests` this index holds. Digests are chained, so a
    /// present digest at depth `i` means the whole prefix up to `i` was
    /// served under the same salt.
    pub fn longest_match(&self, digests: &[PrefixDigest]) -> u32 {
        digests
            .iter()
            .take(MAX_PROBE_DIGESTS)
            .take_while(|d| self.present.contains(*d))
            .count() as u32
    }

    /// Runs held.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Probe results a router gathered for one request: warm runs held by each
/// `(provider, model)` for the caller's prompt under the caller's salt.
pub type PrefixMatches = HashMap<(Address, String), u32>;

/// Warm bytes `provider` holds of this prompt for `model_id`, per `matches`.
pub fn matched_bytes(matches: &PrefixMatches, provider: &Address, model_id: &str) -> u32 {
    matches
        .get(&(*provider, model_id.to_string()))
        .map_or(0, |runs| runs.saturating_mul(PREFIX_RUN_BYTES as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(tag: &str, runs: usize) -> Vec<u8> {
        tag.repeat(PREFIX_RUN_BYTES * runs / tag.len() + 1)
            .into_bytes()
    }

    #[test]
    fn a_prefix_matches_only_under_the_salt_it_was_recorded_with() {
        let alice = principal_salt("key:alice");
        let bob = principal_salt("key:bob");
        let p = prompt("system prompt ", 4);
        let mut idx = WarmPrefixIndex::default();
        idx.record(&salted_prefix_digests(&alice, &p));
        assert_eq!(idx.longest_match(&salted_prefix_digests(&alice, &p)), 4);
        // The same prompt under another principal's salt finds nothing, so
        // neither a probe nor a slot choice can reveal Alice's prefix to Bob.
        assert_eq!(idx.longest_match(&salted_prefix_digests(&bob, &p)), 0);
    }

    #[test]
    fn digests_do_not_reveal_the_prompt_without_the_salt() {
        let p = prompt("guessable ", 2);
        let a = salted_prefix_digests(&principal_salt("x"), &p);
        let b = salted_prefix_digests(&[0u8; 32], &p);
        assert_ne!(a, b);
    }

    #[test]
    fn a_shared_prefix_matches_up_to_the_divergence() {
        let salt = principal_salt("key:alice");
        let mut a = prompt("shared ", 3);
        a.truncate(PREFIX_RUN_BYTES * 3);
        let mut b = a.clone();
        a.extend(prompt("left ", 2));
        b.extend(prompt("right ", 2));
        let mut idx = WarmPrefixIndex::default();
        idx.record(&salted_prefix_digests(&salt, &a));
        assert_eq!(idx.longest_match(&salted_prefix_digests(&salt, &b)), 3);
    }

    #[test]
    fn the_index_is_bounded() {
        let salt = principal_salt("k");
        let mut idx = WarmPrefixIndex::default();
        for i in 0..(MAX_WARM_DIGESTS / 2 + 10) {
            idx.record(&salted_prefix_digests(&salt, &prompt(&format!("p{i} "), 2)));
        }
        assert!(idx.len() <= MAX_WARM_DIGESTS);
    }

    #[tokio::test]
    async fn the_salt_is_scoped_to_the_task_and_inherited_explicitly() {
        assert!(current().is_none());
        let s = principal_salt("k");
        let seen = scoped(Some(s), async {
            let inherited = tokio::spawn(inherit(async { current() })).await.unwrap();
            let lost = tokio::spawn(async { current() }).await.unwrap();
            (current(), inherited, lost)
        })
        .await;
        assert_eq!(seen, (Some(s), Some(s), None));
        assert_eq!(scoped(None, async { current() }).await, None);
    }
}
