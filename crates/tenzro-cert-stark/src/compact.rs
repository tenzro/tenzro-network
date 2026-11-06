//! Compact certificates over a committee's ML-DSA keys of one parameter set.
//!
//! A compact certificate for a message is, per committee slot, either
//! nothing (the member did not sign) or a [`Claim`] `(c~, w1)`, plus one
//! STARK. The verifier checks each claim's hash half natively,
//! `c~ = H(mu || w1Encode(w1))`, and the STARK proves the lattice half: that
//! some norm-bounded `z` and some hint of at most `omega` bits map to `w1`
//! under the member's key and `c~`'s challenge. Together they are ML-DSA
//! verification of a signature `(c~, z, h)` whose `z` and `h` stay out of the
//! certificate.
//!
//! Everything that depends on the keys alone is set up once per epoch in an
//! [`Epoch`].

use std::sync::Arc;

use p3_batch_stark::{BatchProof, ProverData, StarkInstance, prove_batch, verify_batch};
use sha3::{Digest, Sha3_256};

use super::arith::{self, SlotInput};
use super::mldsa::{self, C_TILDE_BYTES, K, L, N, Poly};
use crate::config::{CertStarkConfig, config, queries_for};

/// Provable soundness a compact certificate is configured for, in bits.
pub const SOUNDNESS_BITS: f64 = 100.0;

/// What a compact certificate reveals about one signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The signature's challenge seed.
    pub c_tilde: [u8; C_TILDE_BYTES],
    /// `UseHint(h, w'_approx)`, coefficients below 16.
    pub w1: [Poly; K],
}

impl Claim {
    /// Bytes of a claim on the wire: `c~` and `w1Encode(w1)`.
    pub const ENCODED_LEN: usize = C_TILDE_BYTES + K * N / 2;

    /// `c~ || w1Encode(w1)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.c_tilde);
        out.extend_from_slice(&mldsa::w1_encode(&self.w1));
        out
    }

    /// The claim [`Claim::encode`] wrote. None if the length is wrong.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }
        let mut c_tilde = [0u8; C_TILDE_BYTES];
        c_tilde.copy_from_slice(&bytes[..C_TILDE_BYTES]);
        let mut w1 = [[0u32; N]; K];
        for (i, b) in bytes[C_TILDE_BYTES..].iter().enumerate() {
            w1[i / (N / 2)][2 * (i % (N / 2))] = (b & 0x0f) as u32;
            w1[i / (N / 2)][2 * (i % (N / 2)) + 1] = (b >> 4) as u32;
        }
        Some(Self { c_tilde, w1 })
    }
}

/// A compact certificate: one entry per committee slot and the proof.
pub struct CompactProof {
    /// Per slot, the claim of a member that signed.
    pub claims: Vec<Option<Claim>>,
    /// The STARK.
    pub proof: BatchProof<CertStarkConfig>,
}

impl CompactProof {
    /// The claims and the proof as bytes.
    pub fn encode(&self) -> Vec<u8> {
        let claims: Vec<Option<Vec<u8>>> = self
            .claims
            .iter()
            .map(|c| c.as_ref().map(Claim::encode))
            .collect();
        bincode::serialize(&(claims, &self.proof)).expect("compact proof encodes")
    }

    /// The compact proof [`CompactProof::encode`] wrote. None if it does not
    /// decode.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (claims, proof): (Vec<Option<Vec<u8>>>, BatchProof<CertStarkConfig>) =
            bincode::deserialize(bytes).ok()?;
        let claims = claims
            .into_iter()
            .map(|c| match c {
                None => Some(None),
                Some(b) => Claim::decode(&b).map(Some),
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { claims, proof })
    }
}

/// Everything about a committee's keys a compact certificate is proven and
/// checked against.
pub struct Epoch {
    keys: Vec<mldsa::PublicKey>,
    constants: Arc<Vec<[[Poly; L]; K]>>,
    data: ProverData<CertStarkConfig>,
    degree_bits: Vec<usize>,
    key_digest: [u8; 32],
    queries: usize,
}

impl Epoch {
    /// Sets up the committee whose slots hold `keys`, in slot order.
    pub fn new(keys: Vec<mldsa::PublicKey>) -> Self {
        let queries = queries_for(SOUNDNESS_BITS);
        let constants = Arc::new(arith::key_constants(&keys));
        let mut tables = arith::tables(constants.clone(), &[]);
        let degree_bits: Vec<usize> = tables
            .iter()
            .map(|t| t.height().trailing_zeros() as usize)
            .collect();
        let data = ProverData::from_airs_and_degrees(
            &config(queries, &[0; 32]),
            &mut tables,
            &degree_bits,
        );
        let mut h = Sha3_256::new();
        h.update(super::params::KEYS_DOMAIN);
        for key in &keys {
            h.update(key.tr);
        }
        Self {
            keys,
            constants,
            data,
            degree_bits,
            key_digest: h.finalize().into(),
            queries,
        }
    }

    /// Number of slots.
    pub fn slots(&self) -> usize {
        self.keys.len()
    }

    /// What the transcript is bound to: the keys, the message and every
    /// claim.
    fn statement(&self, message_prime: &[u8], claims: &[Option<Claim>]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"tenzro/compact-certificate/statement");
        h.update(self.key_digest);
        h.update((message_prime.len() as u64).to_be_bytes());
        h.update(message_prime);
        for claim in claims {
            match claim {
                None => h.update([0u8]),
                Some(c) => {
                    h.update([1u8]);
                    h.update(c.c_tilde);
                    h.update(mldsa::w1_encode(&c.w1));
                }
            }
        }
        h.finalize().into()
    }

    /// The packed public rows of `claims`.
    fn public_rows(&self, claims: &[Option<Claim>]) -> Vec<u64> {
        let mut rows = Vec::with_capacity(claims.len() * K * N);
        for (key, claim) in self.keys.iter().zip(claims) {
            match claim {
                None => rows.extend(std::iter::repeat_n(0, K * N)),
                Some(c) => {
                    let term = mldsa::challenge_term(key, &c.c_tilde);
                    for r in 0..K {
                        for i in 0..N {
                            rows.push(arith::packed_public(&term, &c.w1, r, i));
                        }
                    }
                }
            }
        }
        rows
    }

    /// Proves the compact certificate of `signatures` (one per slot, `None`
    /// where the member did not sign) over `message_prime`. None if a
    /// signature does not verify or the count is not one per slot.
    pub fn prove(
        &self,
        message_prime: &[u8],
        signatures: &[Option<mldsa::Signature>],
    ) -> Option<CompactProof> {
        if signatures.len() != self.keys.len() {
            return None;
        }
        let mut inputs = Vec::with_capacity(signatures.len());
        let mut claims = Vec::with_capacity(signatures.len());
        for (key, sig) in self.keys.iter().zip(signatures) {
            match sig {
                None => {
                    inputs.push(SlotInput::absent());
                    claims.push(None);
                }
                Some(sig) => {
                    let w = mldsa::decompose_verification(key, message_prime, sig)?;
                    inputs.push(SlotInput {
                        z: sig.z,
                        h: sig.h,
                        challenge_term: mldsa::challenge_term(key, &sig.c_tilde),
                    });
                    claims.push(Some(Claim {
                        c_tilde: sig.c_tilde,
                        w1: w.w1,
                    }));
                }
            }
        }
        let (traces, w1) = arith::traces(&self.constants, &inputs);
        debug_assert!(
            claims
                .iter()
                .zip(&w1)
                .all(|(c, w)| c.as_ref().is_none_or(|c| c.w1 == *w))
        );
        let tables = arith::tables(self.constants.clone(), &self.public_rows(&claims));
        let instances: Vec<StarkInstance<'_, CertStarkConfig, arith::Table>> = tables
            .iter()
            .zip(&traces)
            .zip(&self.data.common.lookups)
            .map(|((air, trace), lookups)| StarkInstance {
                air,
                trace,
                public_values: Vec::new(),
                lookups: lookups.clone(),
            })
            .collect();
        let cfg = config(self.queries, &self.statement(message_prime, &claims));
        let proof = prove_batch(&cfg, &instances, &self.data);
        Some(CompactProof { claims, proof })
    }

    /// Whether `cert` proves, for every slot with a claim, an ML-DSA
    /// signature by that slot's key over `message_prime`.
    pub fn verify(&self, message_prime: &[u8], cert: &CompactProof) -> bool {
        if cert.claims.len() != self.keys.len() || cert.proof.degree_bits != self.degree_bits {
            return false;
        }
        for (key, claim) in self.keys.iter().zip(&cert.claims) {
            if let Some(c) = claim
                && !mldsa::challenge_matches(key, message_prime, &c.c_tilde, &c.w1)
            {
                return false;
            }
        }
        let tables = arith::tables(self.constants.clone(), &self.public_rows(&cert.claims));
        let cfg = config(self.queries, &self.statement(message_prime, &cert.claims));
        let public_values = vec![Vec::new(); tables.len()];
        verify_batch(
            &cfg,
            &tables,
            &cert.proof,
            &public_values,
            &self.data.common,
        )
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::super::params::MlDsa;
    use super::*;
    use ml_dsa::ExpandedSigningKey;

    const CTX: &[u8] = super::super::params::LABEL;

    fn committee(n: usize) -> (Vec<ExpandedSigningKey<MlDsa>>, Vec<mldsa::PublicKey>) {
        let sks: Vec<_> = (0..n)
            .map(|i| ExpandedSigningKey::<MlDsa>::from_seed(&[i as u8; 32].into()))
            .collect();
        let pks = sks
            .iter()
            .map(|sk| mldsa::PublicKey::decode(&sk.verifying_key().encode()).unwrap())
            .collect();
        (sks, pks)
    }

    fn sign(
        sks: &[ExpandedSigningKey<MlDsa>],
        who: &[usize],
        msg: &[u8],
    ) -> Vec<Option<mldsa::Signature>> {
        (0..sks.len())
            .map(|i| {
                who.contains(&i).then(|| {
                    let sig = sks[i]
                        .sign_deterministic(msg, CTX)
                        .expect("signs")
                        .encode()
                        .to_vec();
                    mldsa::Signature::decode(&sig).unwrap()
                })
            })
            .collect()
    }

    #[test]
    fn a_compact_certificate_verifies_and_binds_its_signers_and_message() {
        let (sks, pks) = committee(4);
        let epoch = Epoch::new(pks);
        let msg = [0x5a; 150];
        let mp = mldsa::message_prime(&msg, CTX).unwrap();
        let a = epoch
            .prove(&mp, &sign(&sks, &[0, 1, 3], &msg))
            .expect("proves");
        assert!(epoch.verify(&mp, &a));
        assert_eq!(a.claims.iter().filter(|c| c.is_some()).count(), 3);
        let decoded = CompactProof::decode(&a.encode()).expect("decodes");
        assert_eq!(decoded.claims, a.claims);
        assert!(epoch.verify(&mp, &decoded), "the encoding round-trips");
        let mut bytes = a.encode();
        let at = bytes.len() / 2;
        bytes[at] ^= 1;
        assert!(
            CompactProof::decode(&bytes).is_none_or(|d| !epoch.verify(&mp, &d)),
            "a flipped byte"
        );

        let other = mldsa::message_prime(&[0xa5; 150], CTX).unwrap();
        assert!(!epoch.verify(&other, &a), "another message");

        let b = epoch
            .prove(&mp, &sign(&sks, &[0, 1, 2], &msg))
            .expect("proves");
        assert!(epoch.verify(&mp, &b));
        let swapped = CompactProof {
            claims: a.claims.clone(),
            proof: b.proof,
        };
        assert!(
            !epoch.verify(&mp, &swapped),
            "the proof of another signer set"
        );

        let mut dropped = CompactProof {
            claims: a.claims.clone(),
            proof: a.proof,
        };
        dropped.claims[3] = None;
        assert!(
            !epoch.verify(&mp, &dropped),
            "a claim removed after proving"
        );

        let mut moved = a.claims.clone();
        moved.swap(2, 3);
        let c = epoch
            .prove(&mp, &sign(&sks, &[0, 1, 3], &msg))
            .expect("proves");
        assert!(
            !epoch.verify(
                &mp,
                &CompactProof {
                    claims: moved,
                    proof: c.proof
                }
            ),
            "a claim under another key"
        );

        let mut forged = sign(&sks, &[0, 1], &msg);
        let mut bad = sign(&sks, &[2], &msg)[2].clone().unwrap();
        bad.z[0][0] += 1;
        forged[2] = Some(bad);
        assert!(
            epoch.prove(&mp, &forged).is_none(),
            "an invalid signature is not proven"
        );
    }

    /// The Merkle sponge does not separate lengths on its own (config.rs),
    /// so no committed row may be opened at a second length. A trace row
    /// lengthened by exactly the value that keeps its leaf digest, and with
    /// it the Merkle path, unchanged is rejected; so are a longer FRI row,
    /// another folding arity and a longer out-of-domain opening.
    #[test]
    fn an_opening_at_another_length_is_rejected_even_when_its_leaf_collides() {
        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        use p3_symmetric::CryptographicHasher;

        use crate::config::{Challenge, Val, colliding_extension, field_hash};

        let (sks, pks) = committee(2);
        let epoch = Epoch::new(pks);
        let msg = [0x3c; 96];
        let mp = mldsa::message_prime(&msg, CTX).unwrap();
        let cert = epoch
            .prove(&mp, &sign(&sks, &[0, 1], &msg))
            .expect("proves");
        assert!(epoch.verify(&mp, &cert));
        let fresh = || CompactProof::decode(&cert.encode()).expect("decodes");

        // The first input batch is the main trace; its tallest rows share
        // one leaf, hashed in instance order.
        let top = *epoch.degree_bits.iter().max().unwrap();
        let group: Vec<usize> = (0..epoch.degree_bits.len())
            .filter(|&i| epoch.degree_bits[i] == top)
            .collect();
        let mut lengthened = fresh();
        let rows = &mut lengthened.proof.opening_proof.query_proofs[0].input_proof[0].opened_values;
        let leaf: Vec<u64> = group
            .iter()
            .flat_map(|&i| rows[i].iter().map(|v| v.as_canonical_u64()))
            .collect();
        let e = colliding_extension(&leaf).expect("the leaf ends inside a sponge block");
        assert!(e < Val::ORDER_U64);
        let digest = |rows: &Vec<Vec<Val>>| -> [u64; 4] {
            field_hash().hash_iter_slices(group.iter().map(|&i| rows[i].as_slice()))
        };
        let before = digest(rows);
        rows[*group.last().unwrap()].push(Val::new(e));
        assert_eq!(
            before,
            digest(rows),
            "the lengthened row keeps its leaf digest"
        );
        assert!(
            !epoch.verify(&mp, &lengthened),
            "a trace row at another length"
        );

        let mut wider = fresh();
        wider.proof.opening_proof.query_proofs[0].commit_phase_openings[0]
            .sibling_values
            .push(Challenge::ZERO);
        assert!(!epoch.verify(&mp, &wider), "a FRI row at another length");

        let mut refolded = fresh();
        refolded.proof.opening_proof.query_proofs[0].commit_phase_openings[0].log_arity += 1;
        assert!(!epoch.verify(&mp, &refolded), "a FRI row at another arity");

        let mut longer = fresh();
        longer.proof.opened_values.instances[0]
            .base_opened_values
            .trace_local
            .push(Challenge::ZERO);
        assert!(
            !epoch.verify(&mp, &longer),
            "an out-of-domain opening at another length"
        );
    }

    /// What a compact certificate costs: `TENZRO_CERT_COMMITTEE` slots
    /// (default 100) with `TENZRO_CERT_SIGNERS` signers (default 67), proven
    /// `TENZRO_CERT_RUNS` times (default 5). Prints one `COST {json}` line.
    /// Run with `--release --ignored --nocapture`.
    #[test]
    #[ignore]
    fn cost_of_a_compact_certificate() {
        let env = |k: &str, d: usize| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let n = env("TENZRO_CERT_COMMITTEE", 100);
        let q = env("TENZRO_CERT_SIGNERS", 67);
        let runs = env("TENZRO_CERT_RUNS", 5);
        let (sks, pks) = committee(n);
        let start = std::time::Instant::now();
        let epoch = Epoch::new(pks);
        let setup_ms = start.elapsed().as_secs_f64() * 1e3;
        let msg = [0x5a; 150];
        let mp = mldsa::message_prime(&msg, CTX).unwrap();
        let who: Vec<usize> = (0..q).collect();
        let signatures = sign(&sks, &who, &msg);
        let mut prove_ms = Vec::with_capacity(runs);
        let mut cert = None;
        for _ in 0..runs {
            let start = std::time::Instant::now();
            cert = epoch.prove(&mp, &signatures);
            prove_ms.push(start.elapsed().as_secs_f64() * 1e3);
        }
        let cert = cert.expect("proves");
        let start = std::time::Instant::now();
        assert!(epoch.verify(&mp, &cert));
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;
        prove_ms.sort_by(f64::total_cmp);
        let proof_bytes = bincode::serialized_size(&cert.proof).expect("proof encodes");
        let encoded = cert.encode();
        let start = std::time::Instant::now();
        let decoded = CompactProof::decode(&encoded).expect("decodes");
        assert!(epoch.verify(&mp, &decoded));
        let decode_verify_ms = start.elapsed().as_secs_f64() * 1e3;
        let claim_bytes = q * Claim::ENCODED_LEN + n.div_ceil(8);
        let peak_rss_kb = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmHWM:"))
                    .map(|l| l.split_whitespace().nth(1).unwrap_or("0").to_string())
            })
            .unwrap_or_default();
        let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "all".into());
        println!(
            "COST {{\"what\":\"compact_certificate\",\"committee\":{n},\"signers\":{q},\"threads\":\"{threads}\",\
             \"queries\":{},\"setup_ms\":{setup_ms:.0},\"prove_ms_median\":{:.0},\"prove_ms_max\":{:.0},\
             \"verify_ms\":{verify_ms:.1},\"proof_bytes\":{proof_bytes},\"claim_bytes\":{claim_bytes},\
             \"total_bytes\":{},\"encoded_bytes\":{},\"decode_verify_ms\":{decode_verify_ms:.1},\
             \"peak_rss_kb\":{peak_rss_kb}}}",
            epoch.queries,
            prove_ms[prove_ms.len() / 2],
            prove_ms[prove_ms.len() - 1],
            proof_bytes as usize + claim_bytes,
            encoded.len(),
        );
    }
}
