//! A committee with software keys and a small committed state, for tests.

use ml_dsa::{ExpandedSigningKey, MlDsa65};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tenzro_finality::checkpoint::{
    CHECKPOINT_VOTE_DOMAIN, Certificate, Checkpoint, checkpoint_state_height,
};
use tenzro_finality::committee::{Committee, Member};
use tenzro_finality::key::{
    CompositeSignature, ValidatorPublicKey, message_representative, ml_dsa_context,
};
use tenzro_finality::session::{
    SESSION_CERTIFICATE_DOMAIN, SessionCertificate, certificate_message,
};
use tenzro_state_proof::hashing::{
    EMPTY, Stem, build_subtree, leaf_hash, slots_root_from_path, split_tree_key, stem_bit, tree_key,
};
use tenzro_state_proof::{ProofTerminal, StateProof};
use tenzro_types::hash_scheme::HashScheme;
use tenzro_types::primitives::Address;

use crate::client::{Clock, LightClient, TrustAnchor};

pub const CHAIN_ID: u64 = 13380;
pub const GENESIS: [u8; 32] = [3; 32];
const SCHEME: HashScheme = HashScheme::Sha256;

struct Key {
    ml_dsa: Box<ExpandedSigningKey<MlDsa65>>,
    p256: p256::ecdsa::SigningKey,
    public: ValidatorPublicKey,
}

impl Key {
    fn from_seed(seed: u64) -> Self {
        let mut xi = [0u8; 32];
        xi[..8].copy_from_slice(&seed.to_le_bytes());
        xi[8] = 0xA5;
        let ml_dsa = Box::new(ExpandedSigningKey::<MlDsa65>::from_seed(&xi.into()));
        let mut scalar = [0u8; 32];
        scalar[..8].copy_from_slice(&seed.to_le_bytes());
        scalar[31] = 1;
        let p256 = p256::ecdsa::SigningKey::from_slice(&scalar).expect("valid P-256 scalar");
        let public = ValidatorPublicKey::new(
            ml_dsa.verifying_key().encode().to_vec(),
            p256.verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        )
        .expect("well-formed test key");
        Self {
            ml_dsa,
            p256,
            public,
        }
    }

    fn sign(&self, domain: &[u8], message: &[u8]) -> CompositeSignature {
        let rep = message_representative(domain, message).expect("short domain");
        let ml_dsa = self
            .ml_dsa
            .sign_deterministic(&rep, ml_dsa_context())
            .expect("ML-DSA signs")
            .encode()
            .to_vec();
        let digest: [u8; 32] = Sha256::digest(&rep).into();
        let ec: p256::ecdsa::Signature = self.p256.sign_prehash(&digest).expect("P-256 signs");
        CompositeSignature {
            ml_dsa,
            p256: ec.to_bytes().to_vec(),
        }
    }
}

/// One epoch's committee: every member's hardware key and session key.
pub struct Net {
    pub epoch: u64,
    pub members: Vec<Member>,
    hardware: Vec<Key>,
    session: Vec<Key>,
}

impl Net {
    /// Epoch 0 with `n` one-seat members.
    pub fn new(n: u64) -> Self {
        Self::of(0, n)
    }

    fn of(epoch: u64, n: u64) -> Self {
        let base = (epoch + 1) * 1_000 + n * 100;
        let hardware: Vec<Key> = (0..n).map(|i| Key::from_seed(base + i)).collect();
        let session = (0..n).map(|i| Key::from_seed(base + 50 + i)).collect();
        let members = hardware
            .iter()
            .enumerate()
            .map(|(i, k)| Member {
                address: Address::new([i as u8 + 1; 32]),
                public_key: k.public.clone(),
                stake: 1,
                seats: 1,
            })
            .collect();
        Self {
            epoch,
            members,
            hardware,
            session,
        }
    }

    /// The same committee after `validator` restarted: its session key lived
    /// in memory only, so it signs under a new one its hardware key certifies.
    pub fn restarted(&self, validator: usize) -> Self {
        let n = self.members.len() as u64;
        let mut net = Self::of(self.epoch, n);
        net.session[validator] =
            Key::from_seed((self.epoch + 1) * 1_000 + n * 100 + 90 + validator as u64);
        net
    }

    /// The following epoch with `n` fresh members.
    pub fn next_epoch(&self, n: u64) -> Self {
        Self::of(self.epoch + 1, n)
    }

    pub fn committee(&self) -> Committee {
        Committee::from_members(self.epoch, self.members.clone()).expect("committee")
    }

    pub fn anchor(&self) -> TrustAnchor {
        TrustAnchor {
            chain_id: CHAIN_ID,
            genesis_hash: GENESIS,
            epoch: self.epoch,
            committee_root: self.committee().root(),
        }
    }

    pub fn client(&self) -> LightClient {
        LightClient::new(&self.anchor(), self.members.clone()).expect("anchored client")
    }

    /// The checkpoint that follows `held` in this epoch.
    pub fn after(&self, held: &Checkpoint) -> Checkpoint {
        let mut cp = self.checkpoint(held.index + 1);
        cp.prev = held.digest();
        cp
    }

    /// A clock under which every checkpoint [`Self::checkpoint`] makes is
    /// current.
    pub fn clock() -> Clock {
        Clock {
            now_ms: 1_800_000_000_000,
            max_age_ms: 3_600_000,
            max_ahead_ms: 3_600_000,
        }
    }

    /// A clock shortly after `checkpoint`, with a one minute age bound.
    pub fn clock_after(checkpoint: &Checkpoint) -> Clock {
        Clock {
            now_ms: checkpoint.timestamp_ms + 1_000,
            max_age_ms: 60_000,
            max_ahead_ms: 5_000,
        }
    }

    /// A well-formed checkpoint of this epoch with `index`, building on the
    /// one with the index below.
    pub fn checkpoint(&self, index: u64) -> Checkpoint {
        let prev = match index {
            0 => [0; 32],
            _ => self.checkpoint(index - 1).digest(),
        };
        let (first, last) = (index * 4 + 1, index * 4 + 4);
        Checkpoint {
            chain_id: CHAIN_ID,
            genesis_hash: GENESIS,
            epoch: self.epoch,
            index,
            prev,
            first_height: first,
            last_height: last,
            blocks_root: [4; 32],
            state_height: checkpoint_state_height(first, last),
            state_root: [5; 32],
            statement_root: [6; 32],
            next_committee_root: None,
            anchor_round: index,
            timestamp_ms: 1_800_000_000_000 + index * 500,
            ordering_root: [7; 32],
        }
    }

    /// Member `validator`'s hardware signature over `cert`.
    pub fn hardware_signature(
        &self,
        validator: usize,
        cert: &SessionCertificate,
    ) -> CompositeSignature {
        self.hardware[validator].sign(SESSION_CERTIFICATE_DOMAIN, &certificate_message(cert))
    }

    fn session_certificate(&self, validator: usize) -> SessionCertificate {
        let mut cert = SessionCertificate {
            chain_id: CHAIN_ID,
            genesis_hash: GENESIS,
            epoch: self.epoch,
            validator: self.hardware[validator].public.fingerprint(),
            session_key: self.session[validator].public.clone(),
            signature: CompositeSignature {
                ml_dsa: Vec::new(),
                p256: Vec::new(),
            },
        };
        cert.signature = self.hardware_signature(validator, &cert);
        cert
    }

    /// A certificate of `checkpoint` signed by `signers` (ascending), and the
    /// session certificates it names.
    pub fn certify(
        &self,
        checkpoint: &Checkpoint,
        signers: &[usize],
    ) -> (Certificate, Vec<SessionCertificate>) {
        let digest = checkpoint.digest();
        let sessions: Vec<SessionCertificate> = signers
            .iter()
            .map(|v| self.session_certificate(*v))
            .collect();
        let certificate = Certificate {
            checkpoint: checkpoint.clone(),
            signers: signers.iter().map(|v| *v as u16).collect(),
            sessions: sessions.iter().map(SessionCertificate::digest).collect(),
            signatures: signers
                .iter()
                .map(|v| self.session[*v].sign(CHECKPOINT_VOTE_DOMAIN, &digest))
                .collect(),
        };
        (certificate, sessions)
    }
}

/// A node's committed state at one height: a few entries, each alone in its
/// stem, with proofs of presence and absence under one root.
pub struct State {
    height: u64,
    entries: Vec<(Stem, u8, Vec<u8>)>,
}

impl State {
    pub fn new(height: u64, entries: &[(&str, &[u8], &[u8])]) -> Self {
        let mut entries: Vec<(Stem, u8, Vec<u8>)> = entries
            .iter()
            .map(|(namespace, key, value)| {
                let (stem, slot) = split_tree_key(&tree_key(namespace, key));
                (stem, slot, value.to_vec())
            })
            .collect();
        entries.sort();
        Self { height, entries }
    }

    fn stems(&self) -> Vec<(Stem, [u8; 32])> {
        self.entries
            .iter()
            .map(|(stem, slot, value)| {
                let leaf = leaf_hash(SCHEME, value);
                (
                    *stem,
                    slots_root_from_path(SCHEME, *slot, leaf, &[EMPTY; 8]),
                )
            })
            .collect()
    }

    pub fn root(&self) -> [u8; 32] {
        build_subtree(SCHEME, 0, &self.stems()).hash()
    }

    /// The value of (`namespace`, `key`), if set, and its proof.
    fn prove(&self, namespace: &str, key: &[u8]) -> (Option<Vec<u8>>, StateProof) {
        let (target, slot) = split_tree_key(&tree_key(namespace, key));
        let all = self.stems();
        let mut stems = &all[..];
        let mut siblings = Vec::new();
        while stems.len() > 1 {
            let depth = siblings.len();
            let split = stems.partition_point(|(s, _)| stem_bit(s, depth) == 0);
            let (zeros, ones) = stems.split_at(split);
            let (mine, other) = if stem_bit(&target, depth) == 0 {
                (zeros, ones)
            } else {
                (ones, zeros)
            };
            siblings.push(build_subtree(SCHEME, depth + 1, other).hash());
            stems = mine;
        }
        let held = self
            .entries
            .iter()
            .find(|(stem, s, _)| *stem == target && *s == slot)
            .map(|(_, _, value)| value.clone());
        let terminal = match stems {
            [] => ProofTerminal::Empty,
            [(stem, _)] if *stem == target => ProofTerminal::Stem {
                slot_siblings: [EMPTY; 8],
            },
            [(stem, slots_root)] => ProofTerminal::OtherStem {
                stem: *stem,
                slots_root: *slots_root,
            },
            _ => unreachable!("the walk ends at one stem or none"),
        };
        (held, StateProof { siblings, terminal })
    }

    /// The reply to `tenzro_getStateProof` with `params`.
    pub fn reply(&self, params: &Value) -> std::result::Result<Value, String> {
        if params["height"] != self.height {
            return Err(format!("no committed state at height {}", params["height"]));
        }
        let namespace = params["namespace"].as_str().ok_or("no namespace")?;
        let key =
            hex::decode(params["key"].as_str().ok_or("no key")?).map_err(|e| e.to_string())?;
        let (value, proof) = self.prove(namespace, &key);
        Ok(json!({
            "height": self.height,
            "state_trie_hash": SCHEME,
            "value": value.map(hex::encode),
            "proof": proof,
        }))
    }
}
