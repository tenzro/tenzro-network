//! An [`IssuerResolver`] fed by the chain's record of an identity's keys.
//!
//! The chain records, for each identity, the sequence of identity keys it has
//! had: a version, the Ed25519 and ML-DSA-65 public keys, the time the key
//! took effect, and whether the identity later declared it compromised. It
//! also records revoked delegation identifiers with the time of revocation.
//! Anyone who follows the chain can build the same view, so nothing here is
//! granted by a party: a [`LedgerView`] is a read of public state.
//!
//! Three rules decide what a verifier accepts:
//!
//! * **Live check** ([`IssuerResolver`]): the identity's current key, or the
//!   key just before it for a delegation that was issued before the
//!   rotation, for at most `overlap_ms` after the rotation. Keys are replaced
//!   when Tenzro upgrades; the overlap lets messages already in flight
//!   finish and no longer. A key declared compromised has no overlap.
//! * **Stored check** ([`ChainIssuerResolver::verify_stored`]): a record
//!   made at time T is judged by the key in force at T, so a rotation does
//!   not invalidate old receipts. A key declared compromised from time C
//!   vouches for nothing made at or after C. A delegation revoked at time R
//!   vouches for nothing made at or after R.
//! * **Fail closed**: a view that is older than `max_staleness_ms` refuses
//!   to answer. There is no fallback to an earlier answer.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::batch_signer::RootSignature;
use crate::delegation::{Clock, DelegationError, DelegationResult, IssuerRecord, IssuerResolver};

/// One identity key and when it was in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEpoch {
    pub version: u64,
    pub ed25519: [u8; 32],
    pub ml_dsa: Vec<u8>,
    /// When the chain recorded this key as the identity's key.
    pub effective_from_ms: u64,
    /// When the identity declared this key compromised, if it did.
    pub compromised_from_ms: Option<u64>,
    /// Digest of the key this one commits to be replaced by
    /// ([`commitment_of`]). A later epoch whose keys do not match is not a
    /// rotation the identity made; the resolver refuses the history. Set
    /// when a standby provider's key is registered in advance.
    pub next_commitment: Option<[u8; 32]>,
}

/// The digest an epoch commits to for its successor.
pub fn commitment_of(ed25519: &[u8; 32], ml_dsa: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/identity/next-key/v1");
    h.update(ed25519);
    h.update((ml_dsa.len() as u32).to_be_bytes());
    h.update(ml_dsa);
    h.finalize().into()
}

/// The keys an identity has had, oldest first, versions rising by one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityHistory {
    pub epochs: Vec<KeyEpoch>,
}

impl IdentityHistory {
    fn epoch(&self, version: u64) -> Option<(usize, &KeyEpoch)> {
        self.epochs
            .iter()
            .enumerate()
            .find(|(_, e)| e.version == version)
    }

    /// Every rotation matches the key the previous epoch committed to.
    fn check_commitments(&self) -> DelegationResult<()> {
        for w in self.epochs.windows(2) {
            if let Some(c) = w[0].next_commitment
                && c != commitment_of(&w[1].ed25519, &w[1].ml_dsa)
            {
                return Err(DelegationError::WrongIssuer(
                    "a rotation does not match the key the identity committed to".into(),
                ));
            }
        }
        Ok(())
    }

    fn latest(&self) -> Option<&KeyEpoch> {
        self.epochs.last()
    }
}

/// What the chain exposes. Implemented over the node's chain state.
pub trait LedgerView: Send + Sync {
    fn history(&self, identity: &str) -> DelegationResult<IdentityHistory>;
    /// When the delegation was revoked, if it was.
    fn revoked_at_ms(&self, delegation_id: &[u8; 32]) -> Option<u64>;
    /// The timestamp of the newest block this view has applied.
    fn head_time_ms(&self) -> u64;
}

/// Governed, not constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverParams {
    /// How long after a rotation a delegation issued before it is still
    /// accepted live.
    pub overlap_ms: u64,
    /// The oldest the ledger view may be before the resolver refuses.
    pub max_staleness_ms: u64,
    /// How long an identity's history is reused before it is read again.
    /// A rotation or a compromise declaration reaches a verifier within
    /// this time.
    pub history_ttl_ms: u64,
}

pub struct ChainIssuerResolver {
    ledger: Arc<dyn LedgerView>,
    clock: Arc<dyn Clock>,
    params: ResolverParams,
    cache: RwLock<HashMap<String, (u64, Arc<IdentityHistory>)>>,
}

impl ChainIssuerResolver {
    pub fn new(ledger: Arc<dyn LedgerView>, clock: Arc<dyn Clock>, params: ResolverParams) -> Self {
        Self {
            ledger,
            clock,
            params,
            cache: RwLock::new(HashMap::new()),
        }
    }

    fn fresh(&self, now_ms: u64) -> DelegationResult<()> {
        let head = self.ledger.head_time_ms();
        if now_ms.saturating_sub(head) > self.params.max_staleness_ms {
            return Err(DelegationError::Provider(format!(
                "the chain view is {} ms old; the limit is {} ms",
                now_ms.saturating_sub(head),
                self.params.max_staleness_ms
            )));
        }
        Ok(())
    }

    fn history(&self, identity: &str, now_ms: u64) -> DelegationResult<Arc<IdentityHistory>> {
        self.fresh(now_ms)?;
        if let Some((at, h)) = self.cache.read().expect("cache").get(identity)
            && now_ms.saturating_sub(*at) < self.params.history_ttl_ms
        {
            return Ok(h.clone());
        }
        let h = self.ledger.history(identity)?;
        if h.epochs.is_empty() {
            return Err(DelegationError::UnknownIdentity(identity.to_string()));
        }
        h.check_commitments()?;
        let h = Arc::new(h);
        self.cache
            .write()
            .expect("cache")
            .insert(identity.to_string(), (now_ms, h.clone()));
        Ok(h)
    }

    fn record(epoch: &KeyEpoch) -> IssuerRecord {
        IssuerRecord {
            version: epoch.version,
            ed25519: epoch.ed25519,
            ml_dsa: epoch.ml_dsa.clone(),
        }
    }

    /// Checks a batch root signature for a record made at `made_at_ms`, by the
    /// key in force when the root was signed (not the key in force now): the
    /// signature names a key the chain recorded, was made while that key was
    /// in force, was not made after a compromise or revocation, and both legs
    /// verify.
    pub fn verify_stored(&self, sig: &RootSignature, made_at_ms: u64) -> DelegationResult<()> {
        let now = self.clock.now_ms();
        let history = self.history(&sig.identity, now)?;
        let (i, epoch) = history.epoch(sig.issuer_version).ok_or_else(|| {
            DelegationError::WrongIssuer("the chain has no such key version".into())
        })?;
        if epoch.ed25519 != sig.issuer_ed25519 || epoch.ml_dsa != sig.issuer_ml_dsa {
            return Err(DelegationError::WrongIssuer(
                "its keys are not the keys the chain records for that version".into(),
            ));
        }
        if sig.signed_at_ms < epoch.effective_from_ms {
            return Err(DelegationError::WrongIssuer(
                "signed before its key took effect".into(),
            ));
        }
        if let Some(next) = history.epochs.get(i + 1)
            && sig.signed_at_ms >= next.effective_from_ms
        {
            return Err(DelegationError::WrongIssuer(
                "signed after its key was replaced".into(),
            ));
        }
        if let Some(c) = epoch.compromised_from_ms
            && (sig.signed_at_ms >= c || made_at_ms >= c)
        {
            return Err(DelegationError::WrongIssuer(
                "its key was declared compromised before this was made".into(),
            ));
        }
        if let Some(r) = self.ledger.revoked_at_ms(&sig.id())
            && made_at_ms >= r
        {
            return Err(DelegationError::Revoked);
        }
        sig.verify_signatures()
    }
}

impl IssuerResolver for ChainIssuerResolver {
    fn resolve(&self, identity: &str) -> DelegationResult<IssuerRecord> {
        let now = self.clock.now_ms();
        let history = self.history(identity, now)?;
        let latest = history.latest().expect("non-empty");
        if latest.compromised_from_ms.is_some() {
            return Err(DelegationError::WrongIssuer(
                "the identity's current key was declared compromised".into(),
            ));
        }
        Ok(Self::record(latest))
    }

    fn is_revoked(&self, delegation_id: &[u8; 32]) -> bool {
        self.ledger.revoked_at_ms(delegation_id).is_some()
    }

    fn resolve_issuing(
        &self,
        identity: &str,
        issuer_version: u64,
        issued_at_ms: u64,
        now_ms: u64,
    ) -> DelegationResult<IssuerRecord> {
        let history = self.history(identity, now_ms)?;
        let latest = history.latest().expect("non-empty");
        let (i, epoch) = history
            .epoch(issuer_version)
            .ok_or(DelegationError::IssuerRotated {
                delegation: issuer_version,
                current: latest.version,
            })?;
        if epoch.compromised_from_ms.is_some() {
            return Err(DelegationError::WrongIssuer(
                "its key was declared compromised".into(),
            ));
        }
        if issued_at_ms < epoch.effective_from_ms {
            return Err(DelegationError::WrongIssuer(
                "issued before its key took effect".into(),
            ));
        }
        match history.epochs.get(i + 1) {
            None => Ok(Self::record(epoch)),
            Some(next) => {
                let in_overlap = issued_at_ms < next.effective_from_ms
                    && now_ms
                        < next
                            .effective_from_ms
                            .saturating_add(self.params.overlap_ms);
                if in_overlap {
                    Ok(Self::record(epoch))
                } else {
                    Err(DelegationError::IssuerRotated {
                        delegation: issuer_version,
                        current: latest.version,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::tests::{Chain, IDENTITY, ManualClock, VERIFY};
    use crate::derive::RemoteDerive;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tenzro_crypto::pq::context;

    /// The test chain's keys, with the times they took effect.
    struct Ledger {
        chain: Arc<Chain>,
        effective: Mutex<Vec<u64>>,
        compromised: Mutex<HashMap<u64, u64>>,
        revoked: Mutex<HashMap<[u8; 32], u64>>,
        commit: Mutex<HashMap<u64, [u8; 32]>>,
        head: AtomicU64,
    }

    impl Ledger {
        fn rotate(&self, at: u64) {
            self.chain.rotate();
            self.effective.lock().unwrap().push(at);
        }
    }

    impl LedgerView for Ledger {
        fn history(&self, _identity: &str) -> DelegationResult<IdentityHistory> {
            let keys = self.chain.keys.lock().unwrap();
            let eff = self.effective.lock().unwrap();
            let comp = self.compromised.lock().unwrap();
            Ok(IdentityHistory {
                epochs: keys
                    .iter()
                    .enumerate()
                    .map(|(i, (ml, ed))| KeyEpoch {
                        version: i as u64 + 1,
                        ed25519: ed.verifying_key().to_bytes(),
                        ml_dsa: ml.verifying_key_bytes().to_vec(),
                        effective_from_ms: eff[i],
                        compromised_from_ms: comp.get(&(i as u64 + 1)).copied(),
                        next_commitment: self.commit.lock().unwrap().get(&(i as u64 + 1)).copied(),
                    })
                    .collect(),
            })
        }
        fn revoked_at_ms(&self, id: &[u8; 32]) -> Option<u64> {
            self.revoked.lock().unwrap().get(id).copied()
        }
        fn head_time_ms(&self) -> u64 {
            self.head.load(Ordering::SeqCst)
        }
    }

    const PARAMS: ResolverParams = ResolverParams {
        overlap_ms: 60_000,
        max_staleness_ms: 30_000,
        history_ttl_ms: 0,
    };

    struct Rig {
        chain: Arc<Chain>,
        clock: Arc<ManualClock>,
        ledger: Arc<Ledger>,
        resolver: Arc<ChainIssuerResolver>,
    }

    impl Rig {
        fn new() -> Self {
            let chain = Chain::new();
            let clock = Arc::new(ManualClock(AtomicU64::new(1_000_000)));
            let ledger = Arc::new(Ledger {
                chain: chain.clone(),
                effective: Mutex::new(vec![0]),
                compromised: Mutex::new(HashMap::new()),
                revoked: Mutex::new(HashMap::new()),
                commit: Mutex::new(HashMap::new()),
                head: AtomicU64::new(1_000_000),
            });
            let resolver = Arc::new(ChainIssuerResolver::new(
                ledger.clone(),
                clock.clone(),
                PARAMS,
            ));
            Self {
                chain,
                clock,
                ledger,
                resolver,
            }
        }

        fn now(&self) -> u64 {
            self.clock.0.load(Ordering::SeqCst)
        }

        fn advance(&self, ms: u64) {
            self.clock.0.fetch_add(ms, Ordering::SeqCst);
            self.ledger.head.fetch_add(ms, Ordering::SeqCst);
        }

        /// A batch root signed under key `version` at `signed_at_ms`, as the
        /// hardware of that version would.
        fn root_at(&self, version: u64, signed_at_ms: u64) -> RootSignature {
            let hw = crate::delegation::tests::ChainRoot(self.chain.clone());
            let label = format!("tenzro/test/identity/v{version}");
            let mut sig = RootSignature {
                identity: IDENTITY.to_string(),
                issuer_version: version,
                issuer_ed25519: hw.ed25519_public(&label).unwrap(),
                issuer_ml_dsa: hw.ml_dsa65_public(&label).unwrap(),
                signed_at_ms,
                count: 1,
                root: [version as u8; 32],
                ed_signature: [0; 64],
                ml_dsa_signature: Vec::new(),
            };
            let st = sig.statement();
            sig.ed_signature = hw.ed25519_sign(&label, &st).unwrap();
            sig.ml_dsa_signature = hw.ml_dsa65_sign(&label, context::BATCH_ROOT, &st).unwrap();
            sig
        }

        fn current(&self) -> RootSignature {
            self.root_at(self.chain.version(), self.now())
        }
    }

    #[test]
    fn a_signature_under_the_current_key_verifies_through_the_chain_view() {
        let r = Rig::new();
        r.current()
            .verify(r.resolver.as_ref(), r.now(), VERIFY)
            .unwrap();
    }

    #[test]
    fn after_a_rotation_an_in_flight_signature_lives_only_for_the_overlap() {
        let r = Rig::new();
        let sig = r.current();
        r.advance(1_000);
        r.ledger.rotate(r.now());
        r.advance(10_000);
        sig.verify(r.resolver.as_ref(), r.now(), VERIFY).unwrap();
        r.advance(60_000);
        assert!(matches!(
            sig.verify(r.resolver.as_ref(), r.now(), VERIFY),
            Err(DelegationError::IssuerRotated {
                delegation: 1,
                current: 2
            })
        ));
        let fresh = r.current();
        assert_eq!(fresh.issuer_version, 2);
        fresh.verify(r.resolver.as_ref(), r.now(), VERIFY).unwrap();
    }

    #[test]
    fn a_signature_the_old_key_makes_after_the_rotation_is_refused_even_in_the_overlap() {
        let r = Rig::new();
        r.advance(1_000);
        let rotated_at = r.now();
        r.ledger.rotate(rotated_at);
        r.advance(1_000);
        // The old key (version 1) signs a root dated after the rotation, as a
        // thief holding it would.
        let sig = r.root_at(1, r.now());
        assert!(matches!(
            sig.verify(r.resolver.as_ref(), r.now(), VERIFY),
            Err(DelegationError::IssuerRotated { .. })
        ));
    }

    #[test]
    fn a_compromised_key_has_no_overlap_and_vouches_for_nothing_after() {
        let r = Rig::new();
        let sig = r.current();
        let signed_at = sig.signed_at_ms;
        r.advance(5_000);
        r.ledger.rotate(r.now());
        r.ledger.compromised.lock().unwrap().insert(1, r.now());
        r.advance(1_000);
        assert!(sig.verify(r.resolver.as_ref(), r.now(), VERIFY).is_err());
        r.resolver.verify_stored(&sig, signed_at + 1).unwrap();
        assert!(r.resolver.verify_stored(&sig, r.now()).is_err());
    }

    #[test]
    fn a_rotation_does_not_invalidate_a_stored_record() {
        let r = Rig::new();
        let sig = r.current();
        let made_at = r.now();
        r.advance(1_000);
        r.ledger.rotate(r.now());
        r.advance(10_000_000);
        assert!(sig.verify(r.resolver.as_ref(), r.now(), VERIFY).is_err());
        r.resolver.verify_stored(&sig, made_at).unwrap();
    }

    #[test]
    fn revocation_blocks_later_records_and_not_earlier_ones() {
        let r = Rig::new();
        let sig = r.current();
        let id = sig.id();
        let made_at = r.now();
        r.advance(2_000);
        r.ledger.revoked.lock().unwrap().insert(id, r.now());
        assert!(r.resolver.is_revoked(&id));
        assert_eq!(
            sig.verify(r.resolver.as_ref(), r.now(), VERIFY),
            Err(DelegationError::Revoked)
        );
        r.resolver.verify_stored(&sig, made_at).unwrap();
        assert_eq!(
            r.resolver.verify_stored(&sig, r.now()),
            Err(DelegationError::Revoked)
        );
    }

    #[test]
    fn a_stale_view_fails_closed_and_an_unknown_identity_is_refused() {
        let r = Rig::new();
        let sig = r.current();
        r.clock.0.fetch_add(31_000, Ordering::SeqCst);
        let err = sig
            .verify(r.resolver.as_ref(), r.now(), VERIFY)
            .unwrap_err();
        assert!(matches!(err, DelegationError::Provider(_)), "{err:?}");

        struct Empty;
        impl LedgerView for Empty {
            fn history(&self, _: &str) -> DelegationResult<IdentityHistory> {
                Ok(IdentityHistory::default())
            }
            fn revoked_at_ms(&self, _: &[u8; 32]) -> Option<u64> {
                None
            }
            fn head_time_ms(&self) -> u64 {
                1_000_000
            }
        }
        let none = ChainIssuerResolver::new(
            Arc::new(Empty),
            Arc::new(ManualClock(AtomicU64::new(1_000_000))),
            PARAMS,
        );
        assert!(matches!(
            none.resolve("did:tenzro:test:nobody"),
            Err(DelegationError::UnknownIdentity(_))
        ));
    }

    #[test]
    fn the_history_is_reused_for_its_ttl() {
        let r = Rig::new();
        let cached = ChainIssuerResolver::new(
            r.ledger.clone(),
            r.clock.clone(),
            ResolverParams {
                history_ttl_ms: 5_000,
                ..PARAMS
            },
        );
        assert_eq!(cached.resolve(IDENTITY).unwrap().version, 1);
        r.ledger.rotate(r.now());
        assert_eq!(cached.resolve(IDENTITY).unwrap().version, 1);
        r.advance(5_000);
        assert_eq!(cached.resolve(IDENTITY).unwrap().version, 2);
    }

    #[test]
    fn a_rotation_to_the_committed_standby_key_is_accepted_and_any_other_is_refused() {
        let r = Rig::new();
        r.chain.rotate();
        r.ledger.effective.lock().unwrap().push(500);
        let (ed, ml) = {
            let keys = r.chain.keys.lock().unwrap();
            let (m, e) = keys.last().unwrap();
            (
                e.verifying_key().to_bytes(),
                m.verifying_key_bytes().to_vec(),
            )
        };
        r.ledger
            .commit
            .lock()
            .unwrap()
            .insert(1, commitment_of(&ed, &ml));
        assert_eq!(r.resolver.resolve(IDENTITY).unwrap().version, 2);

        let r2 = Rig::new();
        r2.ledger.commit.lock().unwrap().insert(1, [9; 32]);
        r2.ledger.rotate(500);
        assert!(matches!(
            r2.resolver.resolve(IDENTITY),
            Err(DelegationError::WrongIssuer(_))
        ));
    }
}
