//! Compact checkpoint certificates.
//!
//! A checkpoint certificate carries one composite session signature per
//! signer, about 3.4 KB each (4.7 KB under ML-DSA-87). Its compact form
//! keeps the ECDSA halves and replaces the quorum's ML-DSA halves with one
//! STARK over the committee's session keys (see [`tenzro_cert_stark`]), about a
//! quarter of the size at a 100-member committee, and costs a verifier one
//! proof check instead of a quorum of ML-DSA verifications.
//!
//! The proof has one slot per committee member, in index order. A slot holds
//! the ML-DSA key of a session certificate of that member from the epoch's
//! bundle ([`SessionBook`]): the one the member signed with, or, for a member
//! that did not sign, the one it was last certified with, so the slot keys,
//! and with them the proof set-up, stay the same from one certificate to the
//! next until a validator restarts. A member with no session certificate
//! fills its slot with a key nobody holds.
//!
//! Compact certificates are made off the critical path, every
//! [`crate::TimeRules::compact_interval_ms`] of checkpoint time, by one
//! prover per epoch ([`prover_rank`]); the next members in the rotation
//! prove only if no verified compact certificate has reached them after
//! their fallback time ([`prove_after_ms`]). Every other validator only
//! verifies the one it receives, from whoever sent it.

use tenzro_finality::key::SignatureScheme;

use crate::checkpoint::{Certificate, CertificateContext};
use crate::committee::ValidatorIndex;
use crate::error::{ConsensusError, Result};
use crate::vertex::Digest;

pub use crate::compact_certificate::{
    CompactCertificate, ProofSetups, message_prime, proof_scheme, slot_keys,
};

/// Whether the certificate of checkpoint `index` gets a compact form under
/// `time`: one every [`crate::TimeRules::compact_interval_ms`] of checkpoint
/// time. Proving one takes a 16-core prover tens of seconds, so on the public
/// network a validator proves about one in every few hundred, and never more
/// than one at a time.
pub fn is_compacted(index: u64, time: &crate::TimeRules) -> bool {
    let every = (time.compact_interval_ms / time.checkpoint_interval_ms.max(1)).max(1);
    index.is_multiple_of(every)
}

/// `member`'s place in the rotation of provers for the compact certificates
/// of `epoch`, over a committee of `members`: 0 for the designated prover,
/// then each member after it in index order, wrapping around. The rotation
/// starts at a member drawn from the epoch number alone, so every validator
/// derives the same order whatever certificate it formed.
pub fn prover_rank(epoch: u64, members: usize, member: ValidatorIndex) -> usize {
    let n = members.max(1);
    let mut h = blake3::Hasher::new();
    h.update(b"tenzro/consensus/compact-prover");
    h.update(&epoch.to_be_bytes());
    let seed = u64::from_be_bytes(
        h.finalize().as_bytes()[..8]
            .try_into()
            .expect("eight bytes"),
    );
    let first = (seed % n as u64) as usize;
    (usize::from(member) % n + n - first) % n
}

/// How long after a compact certificate of `epoch` is due `member` waits
/// for a verified one to arrive before proving it itself: nothing for the
/// designated prover, one fallback time
/// ([`crate::TimeRules::compact_handoff_ms`]) more for each rank after it.
pub fn prove_after_ms(
    epoch: u64,
    members: usize,
    member: ValidatorIndex,
    time: &crate::TimeRules,
) -> u64 {
    prover_rank(epoch, members, member) as u64 * time.compact_handoff_ms
}

/// The compact form of `cert`, which must verify under `ctx`.
pub fn prove(
    cert: &Certificate,
    ctx: &CertificateContext<'_>,
    setups: &ProofSetups,
) -> Result<CompactCertificate> {
    cert.verify(ctx)?;
    let size = ctx.committee.size();
    let mut slots: Vec<Option<Digest>> = (0..size)
        .map(|i| ctx.sessions.latest(i as ValidatorIndex))
        .collect();
    let mut p256 = vec![None; size];
    let mut signatures: Vec<Option<&[u8]>> = vec![None; size];
    let mut signed_as = None;
    for ((s, session), sig) in cert
        .signers
        .iter()
        .zip(&cert.sessions)
        .zip(&cert.signatures)
    {
        let i = *s as usize;
        slots[i] = Some(*session);
        p256[i] = Some(sig.p256.clone());
        let (scheme, bare) = SignatureScheme::split_signature(&sig.ml_dsa).ok_or_else(|| {
            ConsensusError::InvalidCertificate("an ML-DSA signature names no scheme".into())
        })?;
        if *signed_as.get_or_insert(scheme) != scheme {
            return Err(ConsensusError::InvalidCertificate(
                "the signers' session keys are of more than one scheme".into(),
            ));
        }
        signatures[i] = Some(bare);
    }
    let (scheme, keys) = slot_keys(&slots, ctx.sessions)?;
    if signed_as.is_some_and(|s| s != scheme) {
        return Err(ConsensusError::InvalidCertificate(
            "the signatures are of another scheme than the slot keys".into(),
        ));
    }
    let setup = setups.get(scheme, &keys)?;
    let proof = setup
        .prove(&message_prime(&cert.checkpoint, scheme), &signatures)
        .ok_or_else(|| {
            ConsensusError::InvalidCertificate("the signatures could not be proven".into())
        })?;
    Ok(CompactCertificate {
        checkpoint: cert.checkpoint.clone(),
        slots,
        p256,
        proof: proof.encode(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::Checkpoint;
    use crate::checkpoint::test_support::{MemoryHighWater, checkpoint, sign_as};
    use crate::checkpoint::{VoteCollector, VoteOutcome};
    use crate::committee::Committee;
    use crate::committee::test_support::committee;
    use crate::light_client::LightClient;
    use crate::session::SessionBook;
    use crate::validator_key::test_signer::SoftwareTestSigner;

    fn certify(
        c: &Committee,
        s: &[SoftwareTestSigner],
        who: &[ValidatorIndex],
        cp: &Checkpoint,
        book: &mut SessionBook,
    ) -> Certificate {
        let mut col = VoteCollector::new();
        let mut out = None;
        for i in who {
            let v = sign_as(&s[*i as usize], &MemoryHighWater::default(), *i, cp).unwrap();
            book.admit(c, v.signature.session.clone()).unwrap();
            if let VoteOutcome::Certified(cert) = col.add(c, v) {
                out = Some(*cert);
            }
        }
        out.expect("quorum")
    }

    fn ctx<'a>(c: &'a Committee, sessions: &'a SessionBook) -> CertificateContext<'a> {
        CertificateContext {
            chain_id: 7,
            genesis_hash: &[1; 32],
            committee: c,
            sessions,
        }
    }

    #[test]
    fn each_epoch_designates_one_prover_and_orders_every_member_after_it() {
        let mut designated = std::collections::BTreeSet::new();
        for epoch in 0..64 {
            let mut ranks: Vec<usize> = (0..7).map(|m| prover_rank(epoch, 7, m)).collect();
            designated.insert(
                ranks
                    .iter()
                    .position(|r| *r == 0)
                    .expect("a designated prover"),
            );
            ranks.sort_unstable();
            assert_eq!(
                ranks,
                (0..7).collect::<Vec<_>>(),
                "epoch {epoch}: ranks are not a rotation"
            );
        }
        assert!(
            designated.len() >= 5,
            "the designated prover rarely rotates: {designated:?}"
        );
    }

    /// Seven validators, each holding the certificate it formed itself
    /// from a different quorum of votes, prove the compact form on the
    /// schedule a node runs: the epoch's designated prover at once, each
    /// later member of the rotation only when its fallback time passes with
    /// no verified compact certificate received. Returns who proved and
    /// asserts every validator ends up holding one that verifies.
    fn prove_on_schedule(silent: &[ValidatorIndex]) -> Vec<ValidatorIndex> {
        const N: usize = 7;
        let (c, s) = committee(N);
        let time = crate::TimeRules::default();
        let mut book = SessionBook::new(7, [1; 32], 0);
        let cp = checkpoint(4, 9);
        let certs: Vec<Certificate> = (0..N as ValidatorIndex)
            .map(|i| {
                let who: Vec<ValidatorIndex> =
                    (0..5).map(|k| (i + k) % N as ValidatorIndex).collect();
                certify(&c, &s, &who, &cp, &mut book)
            })
            .collect();
        let epoch = cp.epoch;
        let verifier = ProofSetups::new();
        let mut held: Vec<Option<CompactCertificate>> = vec![None; N];
        let mut provers = Vec::new();
        let mut now = 0u64;
        while held
            .iter()
            .enumerate()
            .any(|(i, h)| h.is_none() && !silent.contains(&(i as ValidatorIndex)))
        {
            for i in 0..N as ValidatorIndex {
                let due = prove_after_ms(epoch, N, i, &time) <= now;
                if !due || held[i as usize].is_some() || silent.contains(&i) {
                    continue;
                }
                let cc =
                    crate::compact::prove(&certs[i as usize], &ctx(&c, &book), &ProofSetups::new())
                        .unwrap();
                provers.push(i);
                // Sent to every validator, which keeps it only if it verifies.
                for (j, h) in held.iter_mut().enumerate() {
                    if h.is_none() {
                        cc.verify(&ctx(&c, &book), &verifier)
                            .unwrap_or_else(|e| panic!("validator {j} refused: {e}"));
                        *h = Some(cc.clone());
                    }
                }
            }
            now += time.compact_handoff_ms;
            assert!(
                now <= N as u64 * time.compact_handoff_ms,
                "no validator proved"
            );
        }
        for (i, h) in held.iter().enumerate() {
            let cc = h
                .as_ref()
                .unwrap_or_else(|| panic!("validator {i} holds no compact certificate"));
            assert!(cc.verify(&ctx(&c, &book), &ProofSetups::new()).is_ok());
        }
        provers
    }

    #[test]
    fn only_the_designated_prover_proves_and_a_fallback_takes_over_when_it_is_silent() {
        let epoch = checkpoint(4, 9).epoch;
        let rank_of = |r: usize| {
            (0..7)
                .find(|m| prover_rank(epoch, 7, *m) == r)
                .expect("a member of that rank")
        };
        assert_eq!(
            prove_on_schedule(&[]),
            vec![rank_of(0)],
            "someone besides the designated prover proved"
        );
        assert_eq!(
            prove_on_schedule(&[rank_of(0)]),
            vec![rank_of(1)],
            "with the designated prover silent, the first fallback alone proves after its deadline"
        );
    }

    #[test]
    fn a_compact_certificate_verifies_and_binds_checkpoint_signers_and_keys() {
        let (c, s) = committee(4);
        let mut book = SessionBook::new(7, [1; 32], 0);
        // Member 3 signs an earlier checkpoint only: its slot holds its key
        // though it does not sign this one.
        certify(&c, &s, &[1, 2, 3], &checkpoint(1, 1), &mut book);
        let cp = checkpoint(2, 3);
        let cert = certify(&c, &s, &[0, 1, 2], &cp, &mut book);
        let setups = ProofSetups::new();
        let cc = crate::compact::prove(&cert, &ctx(&c, &book), &setups).unwrap();
        assert!(cc.verify(&ctx(&c, &book), &setups).is_ok());
        assert_eq!(cc.signers(), vec![0, 1, 2]);
        assert!(
            cc.slots[3].is_some(),
            "a non-signer's slot holds its latest session key"
        );
        assert!(
            cc.verify(&ctx(&c, &book), &ProofSetups::new()).is_ok(),
            "a fresh verifier sets up the same keys"
        );

        // A non-signer's slot other than its latest session key is refused
        // before any set-up is made for it.
        let fresh = ProofSetups::new();
        assert!(cc.verify(&ctx(&c, &book), &fresh).is_ok());
        assert_eq!(fresh.built(), 1);
        let mut m = cc.clone();
        m.slots[3] = None;
        assert!(
            m.verify(&ctx(&c, &book), &fresh).is_err(),
            "a non-signer's slot emptied"
        );
        assert_eq!(fresh.built(), 1, "a set-up was made for chosen slot keys");

        let mut m = cc.clone();
        m.checkpoint.state_root[0] ^= 1;
        assert!(
            m.verify(&ctx(&c, &book), &setups).is_err(),
            "another checkpoint"
        );
        let mut m = cc.clone();
        m.p256[1] = None;
        assert!(
            m.verify(&ctx(&c, &book), &setups).is_err(),
            "a signer's P-256 half removed"
        );
        let mut m = cc.clone();
        m.p256[3] = m.p256[2].clone();
        assert!(
            m.verify(&ctx(&c, &book), &setups).is_err(),
            "a P-256 half moved to a non-signer"
        );
        let mut m = cc.clone();
        m.slots.swap(0, 1);
        assert!(
            m.verify(&ctx(&c, &book), &setups).is_err(),
            "session keys swapped between slots"
        );
        let mut m = cc.clone();
        m.slots[3] = m.slots[2];
        assert!(
            m.verify(&ctx(&c, &book), &setups).is_err(),
            "a slot holding another member's key"
        );
        let mut m = cc.clone();
        let at = m.proof.len() / 2;
        m.proof[at] ^= 1;
        assert!(
            m.verify(&ctx(&c, &book), &setups).is_err(),
            "a flipped proof byte"
        );
        let other = crate::compact::prove(
            &certify(&c, &s, &[1, 2, 3], &checkpoint(3, 3), &mut book),
            &ctx(&c, &book),
            &setups,
        )
        .unwrap();
        let mut m = cc.clone();
        m.proof = other.proof.clone();
        assert!(
            m.verify(&ctx(&c, &book), &setups).is_err(),
            "the proof of another checkpoint"
        );
        let mut m = cc.clone();
        m.p256[3] = other.p256[3].clone();
        m.slots[3] = other.slots[3];
        m.p256[0] = None;
        assert!(
            m.verify(&ctx(&c, &book), &setups).is_err(),
            "signer sets mixed"
        );
        assert!(
            cc.verify(&ctx(&c, &SessionBook::new(7, [1; 32], 0)), &setups)
                .is_err(),
            "without the bundle"
        );
        let other_chain = CertificateContext {
            chain_id: 8,
            ..ctx(&c, &book)
        };
        assert!(cc.verify(&other_chain, &setups).is_err(), "another chain");
    }

    #[test]
    fn a_light_client_follows_certificates_across_a_handover() {
        let (c0, s) = committee(4);
        let c1 = Committee::from_members(1, c0.members().to_vec()).unwrap();
        let mut lc = LightClient::new(7, [1; 32], c0.clone());

        let mut book0 = SessionBook::new(7, [1; 32], 0);
        let end = crate::checkpoint::Checkpoint {
            next_committee_root: Some(c1.root()),
            ..checkpoint(5, 1)
        };
        let handover = certify(&c0, &s, &[0, 1, 2], &end, &mut book0);
        assert!(lc.accept_certificate(&handover).is_err(), "no bundle yet");
        assert!(
            lc.hand_over(c1.members().to_vec()).is_err(),
            "no accepted checkpoint ends the epoch"
        );
        assert_eq!(lc.add_sessions(book0.bundle(&handover.sessions)), 3);
        let setups = ProofSetups::new();
        let compact = crate::compact::prove(&handover, &ctx(&c0, &book0), &setups).unwrap();
        lc.accept_compact(&compact).unwrap();
        assert_eq!(lc.latest().map(|c| c.index), Some(5));

        // A committee other than the one committed is refused.
        let mut wrong = c1.members().to_vec();
        wrong[0].stake += 1;
        assert!(lc.hand_over(wrong).is_err());
        lc.hand_over(c1.members().to_vec()).unwrap();
        assert_eq!(lc.committee().epoch, 1);

        let mut book1 = SessionBook::new(7, [1; 32], 1);
        let cp1 = crate::checkpoint::Checkpoint {
            epoch: 1,
            ..checkpoint(9, 2)
        };
        let cert1 = certify(&c1, &s, &[1, 2, 3], &cp1, &mut book1);
        // Epoch 0's certificate no longer counts, and epoch 1's needs its own bundle.
        assert!(lc.accept_certificate(&handover).is_err());
        assert!(lc.accept_certificate(&cert1).is_err());
        lc.add_sessions(book1.bundle(&cert1.sessions));
        lc.accept_certificate(&cert1).unwrap();
        assert_eq!(lc.latest().map(|c| c.index), Some(9));
    }

    /// A committee on ML-DSA-87 hardware keys votes with ML-DSA-87 session
    /// keys; their compact certificate names the scheme, and a light client
    /// holding only the committee and the session bundle verifies it. A
    /// proof that names the other scheme, or an ECDSA half that is not the
    /// signer's, is refused.
    #[test]
    fn a_committee_on_ml_dsa_87_session_keys_has_a_compact_certificate_a_light_client_verifies() {
        use crate::validator_key::{SignatureScheme, ValidatorSigner};
        let (c0, _) = committee(4);
        let s: Vec<SoftwareTestSigner> = (0..4)
            .map(|i| {
                SoftwareTestSigner::from_seed_with_scheme(7_000 + i, SignatureScheme::MlDsa87P384)
            })
            .collect();
        let mut members = c0.members().to_vec();
        for (m, k) in members.iter_mut().zip(&s) {
            m.public_key = k.public_key().clone();
        }
        let c = Committee::from_members(0, members).unwrap();
        let mut book = SessionBook::new(7, [1; 32], 0);
        let cp = checkpoint(3, 4);
        let cert = certify(&c, &s, &[0, 2, 3], &cp, &mut book);
        for d in &cert.sessions {
            let (_, session) = book.get(d).unwrap();
            assert_eq!(session.session_key.scheme(), SignatureScheme::MlDsa87P384);
        }

        let setups = ProofSetups::new();
        let start = std::time::Instant::now();
        let cc = crate::compact::prove(&cert, &ctx(&c, &book), &setups).unwrap();
        let prove_ms = start.elapsed().as_millis();
        assert_eq!(
            cc.proof[0],
            tenzro_cert_stark::Scheme::MlDsa87.id(),
            "the proof names its scheme"
        );

        let mut lc = LightClient::new(7, [1; 32], c.clone());
        assert_eq!(lc.add_sessions(book.bundle(&cert.sessions)), 3);
        let start = std::time::Instant::now();
        lc.accept_compact(&cc).unwrap();
        let verify_ms = start.elapsed().as_millis();
        assert_eq!(lc.latest().map(|c| c.index), Some(3));
        let raw: usize = cert
            .signatures
            .iter()
            .map(|s| s.ml_dsa.len() + s.p256.len())
            .sum();
        let compact: usize = cc.proof.len() + cc.p256.iter().flatten().map(Vec::len).sum::<usize>();
        eprintln!(
            "ML-DSA-87 compact certificate: committee 4, signers 3, raw signatures {raw} B, \
             compact {compact} B, prove {prove_ms} ms, light client verify {verify_ms} ms"
        );

        let fresh = || LightClient::new(7, [1; 32], c.clone());
        let mut renamed = cc.clone();
        renamed.proof[0] = tenzro_cert_stark::Scheme::MlDsa65.id();
        let mut lc2 = fresh();
        lc2.add_sessions(book.bundle(&cert.sessions));
        assert!(
            lc2.accept_compact(&renamed).is_err(),
            "a proof naming the other scheme"
        );
        let mut swapped = cc.clone();
        swapped.p256.swap(0, 2);
        assert!(
            lc2.accept_compact(&swapped).is_err(),
            "another signer's ECDSA half"
        );
        let mut changed = cc.clone();
        changed.checkpoint.state_root[0] ^= 1;
        assert!(lc2.accept_compact(&changed).is_err(), "another checkpoint");
    }

    /// A memory line of this process's status (`VmHWM`, `VmRSS`), in MB.
    fn status_mb(field: &str) -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with(field)).map(str::to_owned))
            .and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .map_or(0, |kb| kb / 1024)
    }

    fn peak_rss_mb() -> u64 {
        status_mb("VmHWM:")
    }

    /// One node under steady compact-certificate load for
    /// `TDC_SOAK_SECS` (default 300): every round it proves two
    /// certificates and checks both proofs, through [`CompactWork`] as the
    /// node does, and every fifth round a validator restarts with a new
    /// session key, so the set-ups change. Its memory must stay flat: the
    /// resident set of the second half of the run is no higher than the
    /// first half's plus 64 MB, and the peak stays under 2 GB. Prints one
    /// `GATE {json}` line. Run in release with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn soak_compact_certificates_keep_memory_flat() {
        use crate::compact_work::CompactWork;
        use crate::session::{SessionCertificate, SessionKey};
        use crate::validator_key::ValidatorSigner;
        let secs: u64 = std::env::var("TDC_SOAK_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let (c, s) = committee(7);
        let marks: Vec<MemoryHighWater> = (0..7).map(|_| MemoryHighWater::default()).collect();
        let session_of = |i: usize| {
            let key = SessionKey::generate().unwrap();
            let cert =
                crate::session::sign_certificate(&s[i], 7, [1; 32], 0, key.public_key().clone())
                    .unwrap();
            (key, cert)
        };
        let mut sessions: Vec<(SessionKey, SessionCertificate)> = (0..7).map(session_of).collect();
        let mut book = SessionBook::new(7, [1; 32], 0);
        let work = CompactWork::new();
        let setups = ProofSetups::new();
        let started = std::time::Instant::now();
        let mut samples: Vec<u64> = Vec::new();
        let mut round = 0u64;
        while started.elapsed().as_secs() < secs {
            round += 1;
            if round.is_multiple_of(5) {
                let i = (round / 5 % 7) as usize;
                sessions[i] = session_of(i);
            }
            let mut certs = Vec::new();
            for offset in 0..2 {
                let cp = checkpoint(2 * round + offset, round as u8);
                let mut col = VoteCollector::new();
                let mut out = None;
                for (i, (key, cert)) in sessions.iter().enumerate().take(5) {
                    let _ = book.admit(&c, cert.clone());
                    let v = crate::checkpoint::sign_checkpoint(
                        key,
                        cert,
                        &marks[i],
                        i as ValidatorIndex,
                        &cp,
                    )
                    .unwrap();
                    if let VoteOutcome::Certified(cert) = col.add(&c, v) {
                        out = Some(*cert);
                    }
                }
                certs.push(out.expect("quorum"));
            }
            let own = work
                .run(|| crate::compact::prove(&certs[0], &ctx(&c, &book), &setups))
                .unwrap();
            let theirs = work
                .run(|| crate::compact::prove(&certs[1], &ctx(&c, &book), &setups))
                .unwrap();
            work.run(|| theirs.verify(&ctx(&c, &book), &setups))
                .unwrap();
            assert!(
                work.try_run(|| own.verify(&ctx(&c, &book), &setups))
                    .expect("the pool is idle")
                    .is_ok()
            );
            samples.push(status_mb("VmRSS:"));
        }
        let half = samples.len() / 2;
        let first = samples[..half].iter().copied().max().unwrap_or(0);
        let second = samples[half..].iter().copied().max().unwrap_or(0);
        println!(
            "GATE {{\"soak_secs\":{secs},\"rounds\":{round},\"rss_first_half_max_mb\":{first},\"rss_second_half_max_mb\":{second},\"rss_last_mb\":{},\"rss_peak_mb\":{}}}",
            samples.last().copied().unwrap_or(0),
            peak_rss_mb()
        );
        assert!(
            samples.len() >= 4,
            "too short a soak to judge: {round} rounds"
        );
        assert!(
            second <= first + 64,
            "memory grew: {first} MB, then {second} MB"
        );
        assert!(peak_rss_mb() < 2_048, "peak {} MB", peak_rss_mb());
    }

    /// What one compact certificate costs: set-up and proof on the prover,
    /// then set-up and check on a fresh verifier, for a committee of
    /// `TDC_COMPACT_MEMBERS` (default 7). Prints one `GATE {json}` line.
    /// Run in release with `--ignored --nocapture --test-threads 1`.
    #[test]
    #[ignore]
    fn gate_compact_certificate_cost() {
        let n: usize = std::env::var("TDC_COMPACT_MEMBERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7);
        let (c, s) = committee(n);
        let mut book = SessionBook::new(7, [1; 32], 0);
        let who: Vec<ValidatorIndex> = (0..c.size() as ValidatorIndex).collect();
        let cert = certify(&c, &s, &who, &checkpoint(1, 1), &mut book);
        let base = peak_rss_mb();
        let t = std::time::Instant::now();
        let setups = ProofSetups::new();
        let cc = crate::compact::prove(&cert, &ctx(&c, &book), &setups).unwrap();
        let prove_ms = t.elapsed().as_millis();
        let prove_peak = peak_rss_mb();
        let held_after_prove = status_mb("VmRSS:");
        drop(setups);
        let after_drop = status_mb("VmRSS:");
        // Resets the peak so the verifier's is measured on its own.
        let _ = std::fs::write("/proc/self/clear_refs", "5");
        let t = std::time::Instant::now();
        let verifier = ProofSetups::new();
        cc.verify(&ctx(&c, &book), &verifier).unwrap();
        let verify_ms = t.elapsed().as_millis();
        let held_after_verify = status_mb("VmRSS:");
        println!(
            "GATE {{\"members\":{n},\"threads\":{},\"prove_ms\":{prove_ms},\"verify_fresh_ms\":{verify_ms},\"proof_bytes\":{},\"rss_base_mb\":{base},\"rss_peak_prove_mb\":{prove_peak},\"rss_held_with_setup_mb\":{held_after_prove},\"rss_after_setup_dropped_mb\":{after_drop},\"rss_peak_verify_mb\":{},\"rss_held_after_verify_mb\":{held_after_verify}}}",
            std::thread::available_parallelism().map_or(0, |p| p.get()),
            cc.proof.len(),
            peak_rss_mb()
        );
    }
}
