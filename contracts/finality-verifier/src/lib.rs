// SPDX-License-Identifier: Apache-2.0
//! Tenzro finality as other chains check it.
//!
//! A finality proof is a Groth16 proof (BN254) that RISC Zero's recursion
//! circuit accepted a receipt of the finality program: its claim commits the
//! program's image id and the SHA-256 of its journal, which states one Tenzro
//! checkpoint the program verified under the committee of its epoch. This
//! crate holds everything such a check needs apart from the curve
//! arithmetic, which each chain supplies ([`Bn254`]): the verifying key, the
//! receipt claim and its public inputs, the journal, and the client state
//! that follows the committee from epoch to epoch, as Tenzro's EVM client
//! does. [`state_proof`] checks entries under a final checkpoint's state
//! root and [`agent`] the agent grants accounts on other chains act within.
#![no_std]

use sha2::{Digest, Sha256};

pub mod agent;
#[cfg(feature = "arkworks")]
pub mod arkworks;
pub mod governance;
pub mod settlement;
pub mod state_proof;

/// The control root of the recursion circuit, split as public inputs.
pub const CONTROL_ROOT: [u8; 32] = hex32("a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56");
/// The BN254 control id, the last public input.
pub const BN254_CONTROL_ID: [u8; 32] = hex32("04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0");

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not hex"),
    }
}

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// A decimal field element as 32 big-endian bytes.
const fn dec32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < b.len() {
        // out = out * 10 + digit
        let mut carry = (b[i] - b'0') as u32;
        let mut j = 32;
        while j > 0 {
            j -= 1;
            let v = out[j] as u32 * 10 + carry;
            out[j] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        i += 1;
    }
    out
}

/// The recursion circuit's Groth16 verifying key: alpha (G1), beta, gamma and
/// delta (G2, in the precompile order x_im, x_re, y_im, y_re) and the input
/// commitments IC0..IC5 (G1), each coordinate 32 bytes big-endian.
pub mod vk {
    use super::dec32;

    pub const ALPHA: [[u8; 32]; 2] = [
        dec32("20491192805390485299153009773594534940189261866228447918068658471970481763042"),
        dec32("9383485363053290200918347156157836566562967994039712273449902621266178545958"),
    ];
    pub const BETA: [[u8; 32]; 4] = [
        dec32("4252822878758300859123897981450591353533073413197771768651442665752259397132"),
        dec32("6375614351688725206403948262868962793625744043794305715222011528459656738731"),
        dec32("21847035105528745403288232691147584728191162732299865338377159692350059136679"),
        dec32("10505242626370262277552901082094356697409835680220590971873171140371331206856"),
    ];
    pub const GAMMA: [[u8; 32]; 4] = [
        dec32("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
        dec32("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
        dec32("4082367875863433681332203403145435568316851327593401208105741076214120093531"),
        dec32("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
    ];
    pub const DELTA: [[u8; 32]; 4] = [
        dec32("1668323501672964604911431804142266013250380587483576094566949227275849579036"),
        dec32("12043754404802191763554326994664886008979042643626290185762540825416902247219"),
        dec32("7710631539206257456743780535472368339139328733484942210876916214502466455394"),
        dec32("13740680757317479711909903993315946540841369848973133181051452051592786724563"),
    ];
    pub const IC: [[[u8; 32]; 2]; 6] = [
        [
            dec32("8446592859352799428420270221449902464741693648963397251242447530457567083492"),
            dec32("1064796367193003797175961162477173481551615790032213185848276823815288302804"),
        ],
        [
            dec32("3179835575189816632597428042194253779818690147323192973511715175294048485951"),
            dec32("20895841676865356752879376687052266198216014795822152491318012491767775979074"),
        ],
        [
            dec32("5332723250224941161709478398807683311971555792614491788690328996478511465287"),
            dec32("21199491073419440416471372042641226693637837098357067793586556692319371762571"),
        ],
        [
            dec32("12457994489566736295787256452575216703923664299075106359829199968023158780583"),
            dec32("19706766271952591897761291684837117091856807401404423804318744964752784280790"),
        ],
        [
            dec32("19617808913178163826953378459323299110911217259216006187355745713323154132237"),
            dec32("21663537384585072695701846972542344484111393047775983928357046779215877070466"),
        ],
        [
            dec32("6834578911681792552110317589222010969491336870276623105249474534788043166867"),
            dec32("15060583660288623605191393599883223885678013570733629274538391874953353488393"),
        ],
    ];
    /// The base field modulus.
    pub const Q: [u8; 32] = dec32("21888242871839275222246405745257275088696311157297823662689037894645226208583");
}

/// The curve operations a chain provides, with the encodings of the
/// Ethereum BN254 precompiles: G1 points 64 bytes, G2 points 128 bytes,
/// scalars 32 bytes, all big-endian.
pub trait Bn254 {
    /// `a + b` in G1.
    fn g1_add(&self, a: &[u8; 64], b: &[u8; 64]) -> Option<[u8; 64]>;
    /// `s * p` in G1.
    fn g1_mul(&self, p: &[u8; 64], s: &[u8; 32]) -> Option<[u8; 64]>;
    /// Whether the product of the pairings of the four (G1, G2) pairs is one.
    fn pairing4(&self, pairs: &[([u8; 64], [u8; 128]); 4]) -> Option<bool>;
}

/// Why a proof or a journal was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The seal is not 4 selector bytes and eight words.
    MalformedSeal,
    /// The seal names another verifier than this one.
    WrongSelector,
    /// The curve operations refused an input.
    BadPoint,
    /// The pairing check failed.
    InvalidProof,
    /// The journal is not thirteen words.
    MalformedJournal,
    /// The journal is of another chain.
    WrongChain,
    /// The journal's epoch has no known committee, or another one.
    UnknownCommittee,
    /// That checkpoint is already final.
    AlreadyFinal,
}

/// SHA-256 of a tag, as RISC Zero's tagged structures use.
fn tag(name: &[u8]) -> [u8; 32] {
    Sha256::digest(name).into()
}

/// The digest of a successful receipt claim of program `image_id` with
/// journal digest `journal_digest` (RISC Zero's `ReceiptClaim::ok`).
pub fn claim_digest(image_id: &[u8; 32], journal_digest: &[u8; 32]) -> [u8; 32] {
    // Output { journal_digest, assumptions: empty }
    let mut h = Sha256::new();
    h.update(tag(b"risc0.Output"));
    h.update(journal_digest);
    h.update([0u8; 32]);
    h.update(2u16.to_le_bytes());
    let output: [u8; 32] = h.finalize().into();
    // The terminal state of a halted program.
    let post_state: [u8; 32] = hex32("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2");
    let mut h = Sha256::new();
    h.update(tag(b"risc0.ReceiptClaim"));
    h.update([0u8; 32]); // input
    h.update(image_id); // pre-state
    h.update(post_state);
    h.update(output);
    h.update(0u32.to_le_bytes()); // exit code: halted
    h.update(0u32.to_le_bytes()); // user exit code 0
    h.update(4u16.to_le_bytes());
    h.finalize().into()
}

/// A digest split as two public inputs: its bytes reversed, then the low
/// and the high 128 bits, each as a 32-byte big-endian scalar.
fn split(d: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut r = *d;
    r.reverse();
    let (mut lo, mut hi) = ([0u8; 32], [0u8; 32]);
    lo[16..].copy_from_slice(&r[16..]);
    hi[16..].copy_from_slice(&r[..16]);
    (lo, hi)
}

/// The five public inputs of a receipt with `claim`.
pub fn public_inputs(claim: &[u8; 32]) -> [[u8; 32]; 5] {
    let (c0, c1) = split(&CONTROL_ROOT);
    let (d0, d1) = split(claim);
    [c0, c1, d0, d1, BN254_CONTROL_ID]
}

/// The selector of the seals this verifier accepts: the leading bytes of the
/// digest of RISC Zero's Groth16 verifier parameters, as the EVM verifier
/// checks it.
pub const SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];

fn sub_mod(q: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    // q - y for 0 <= y < q; zero stays zero.
    if y.iter().all(|b| *b == 0) {
        return *y;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut v = q[i] as i16 - y[i] as i16 - borrow;
        borrow = if v < 0 {
            v += 256;
            1
        } else {
            0
        };
        out[i] = v as u8;
    }
    out
}

/// Verify `seal` (selector and the ABI words of A, B and C) as a proof of a
/// receipt with claim `claim`.
pub fn verify_seal(curve: &impl Bn254, seal: &[u8], claim: &[u8; 32]) -> Result<(), Error> {
    if seal.len() != 4 + 8 * 32 {
        return Err(Error::MalformedSeal);
    }
    if seal[..4] != SELECTOR {
        return Err(Error::WrongSelector);
    }
    let w = |i: usize| -> [u8; 32] { seal[4 + 32 * i..4 + 32 * (i + 1)].try_into().expect("32 bytes") };
    let inputs = public_inputs(claim);
    let mut vk_x = [0u8; 64];
    vk_x[..32].copy_from_slice(&vk::IC[0][0]);
    vk_x[32..].copy_from_slice(&vk::IC[0][1]);
    for (i, input) in inputs.iter().enumerate() {
        let mut p = [0u8; 64];
        p[..32].copy_from_slice(&vk::IC[i + 1][0]);
        p[32..].copy_from_slice(&vk::IC[i + 1][1]);
        let term = curve.g1_mul(&p, input).ok_or(Error::BadPoint)?;
        vk_x = curve.g1_add(&vk_x, &term).ok_or(Error::BadPoint)?;
    }
    let g1 = |x: &[u8; 32], y: &[u8; 32]| {
        let mut p = [0u8; 64];
        p[..32].copy_from_slice(x);
        p[32..].copy_from_slice(y);
        p
    };
    let g2 = |c: &[[u8; 32]; 4]| {
        let mut p = [0u8; 128];
        for (i, x) in c.iter().enumerate() {
            p[32 * i..32 * (i + 1)].copy_from_slice(x);
        }
        p
    };
    let neg_a = g1(&w(0), &sub_mod(&vk::Q, &w(1)));
    let b = g2(&[w(2), w(3), w(4), w(5)]);
    let c = g1(&w(6), &w(7));
    let pairs = [
        (neg_a, b),
        (g1(&vk::ALPHA[0], &vk::ALPHA[1]), g2(&vk::BETA)),
        (vk_x, g2(&vk::GAMMA)),
        (c, g2(&vk::DELTA)),
    ];
    match curve.pairing4(&pairs) {
        Some(true) => Ok(()),
        Some(false) => Err(Error::InvalidProof),
        None => Err(Error::BadPoint),
    }
}

/// What the finality program commits: one checkpoint and the committee it
/// was verified under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Journal {
    pub chain_id: u64,
    pub genesis_hash: [u8; 32],
    pub epoch: u64,
    pub committee_root: [u8; 32],
    pub index: u64,
    pub checkpoint_digest: [u8; 32],
    pub last_height: u64,
    pub state_height: u64,
    pub state_root: [u8; 32],
    pub blocks_root: [u8; 32],
    pub statement_root: [u8; 32],
    pub next_committee_root: [u8; 32],
    pub timestamp_ms: u64,
}

/// Bytes of an encoded journal: thirteen words.
pub const JOURNAL_LEN: usize = 13 * 32;

impl Journal {
    /// Decode the journal's thirteen words (integers right-aligned).
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != JOURNAL_LEN {
            return Err(Error::MalformedJournal);
        }
        let word = |i: usize| -> [u8; 32] { b[32 * i..32 * (i + 1)].try_into().expect("32 bytes") };
        let int = |i: usize| -> Result<u64, Error> {
            let w = word(i);
            if w[..24].iter().any(|x| *x != 0) {
                return Err(Error::MalformedJournal);
            }
            Ok(u64::from_be_bytes(w[24..].try_into().expect("8 bytes")))
        };
        Ok(Self {
            chain_id: int(0)?,
            genesis_hash: word(1),
            epoch: int(2)?,
            committee_root: word(3),
            index: int(4)?,
            checkpoint_digest: word(5),
            last_height: int(6)?,
            state_height: int(7)?,
            state_root: word(8),
            blocks_root: word(9),
            statement_root: word(10),
            next_committee_root: word(11),
            timestamp_ms: int(12)?,
        })
    }
}

/// Where a chain keeps a finality client's state.
pub trait Store {
    fn committee_root(&self, epoch: u64) -> Option<[u8; 32]>;
    fn set_committee_root(&mut self, epoch: u64, root: [u8; 32]);
    fn is_final(&self, index: u64) -> bool;
    fn set_final(&mut self, journal: &Journal);
}

/// The client's fixed parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub image_id: [u8; 32],
    pub chain_id: u64,
    pub genesis_hash: [u8; 32],
}

/// The checkpoint `journal` states, if `seal` proves it for the finality
/// program and the journal is of this chain under the committee the store
/// holds for its epoch; nothing is stored.
pub fn check(curve: &impl Bn254, params: &Params, store: &impl Store, journal: &[u8], seal: &[u8]) -> Result<Journal, Error> {
    let digest: [u8; 32] = Sha256::digest(journal).into();
    verify_seal(curve, seal, &claim_digest(&params.image_id, &digest))?;
    let j = Journal::decode(journal)?;
    if j.chain_id != params.chain_id || j.genesis_hash != params.genesis_hash {
        return Err(Error::WrongChain);
    }
    match store.committee_root(j.epoch) {
        Some(root) if root == j.committee_root && root != [0u8; 32] => Ok(j),
        _ => Err(Error::UnknownCommittee),
    }
}

/// Accept the checkpoint `journal` states, proven by `seal`: the proof must
/// verify for the finality program and this journal, the journal must be of
/// this chain and name the committee the store holds for its epoch, and the
/// checkpoint must not be final already. A checkpoint that ends an epoch
/// hands over to the next committee. Returns the accepted journal.
pub fn submit(curve: &impl Bn254, params: &Params, store: &mut impl Store, journal: &[u8], seal: &[u8]) -> Result<Journal, Error> {
    let j = check(curve, params, store, journal, seal)?;
    if store.is_final(j.index) {
        return Err(Error::AlreadyFinal);
    }
    store.set_final(&j);
    if j.next_committee_root != [0u8; 32] && store.committee_root(j.epoch + 1).is_none() {
        store.set_committee_root(j.epoch + 1, j.next_committee_root);
    }
    Ok(j)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// A real finality proof of a test build of the finality program.
    const PROOF: &str = include_str!("../../../crates/tenzro-vm/tests/fixtures/finality_proof.json");

    #[test]
    fn the_journal_of_a_real_proof_decodes() {
        let v: serde_json::Value = serde_json::from_str(PROOF).unwrap();
        let journal = hex::decode(v["journal"].as_str().unwrap()).unwrap();
        let j = Journal::decode(&journal).unwrap();
        assert_eq!(j.chain_id, 1337);
        let seal = hex::decode(v["evm_seal"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(seal[..4], SELECTOR);
        let mut bad = journal.clone();
        bad[0] = 1;
        assert_eq!(Journal::decode(&bad), Err(Error::MalformedJournal));
    }

    const GRANTS: &str = include_str!("../../../sdk/fixtures/remote_grant/vectors.json");
    const STATE: &str = include_str!("../../../sdk/fixtures/state_proof/vectors.json");

    fn h(v: &serde_json::Value) -> std::vec::Vec<u8> {
        hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    fn h32(v: &serde_json::Value) -> [u8; 32] {
        h(v).try_into().unwrap()
    }

    #[test]
    fn the_shared_state_proofs_verify_and_nothing_else_does() {
        let s: serde_json::Value = serde_json::from_str(STATE).unwrap();
        let (r1, r2) = (h32(&s["root_v1"]), h32(&s["root_v2"]));
        for e in s["entries"].as_array().unwrap() {
            let tk = h32(&e["tree_key"]);
            let (g1, g2) = (h(&e["value_v1"]), h(&e["value_v2"]));
            let (p1, p2) = (h(&e["proof_v1"]), h(&e["proof_v2"]));
            assert!(state_proof::verify_at(&r1, &tk, Some(&g1), &p1));
            assert!(state_proof::verify_at(&r2, &tk, Some(&g2), &p2));
            assert!(!state_proof::verify_at(&r1, &tk, Some(&g2), &p1), "another value");
            assert!(!state_proof::verify_at(&r2, &tk, Some(&g2), &p1), "another root");
            assert!(!state_proof::verify_at(&r1, &tk, None, &p1), "absence of a present entry");
            let atk = h32(&e["absent_tree_key"]);
            let pa = h(&e["proof_absent_v1"]);
            assert!(state_proof::verify_at(&r1, &atk, None, &pa));
            assert!(!state_proof::verify_at(&r1, &atk, Some(&g1), &pa));
            let mut cut = p1.clone();
            cut.pop();
            assert!(!state_proof::verify_at(&r1, &tk, Some(&g1), &cut), "a truncated proof");
        }
    }

    #[test]
    fn the_shared_grants_decode_and_their_digests_and_proofs_match() {
        let v: serde_json::Value = serde_json::from_str(GRANTS).unwrap();
        let did = v["did"].as_str().unwrap().as_bytes();
        let keys_root = h32(&v["keys_root"]);
        for k in v["keys"].as_array().unwrap() {
            let pk: [u8; 65] = h(&k["public_key"]).try_into().unwrap();
            let leaf = agent::key_leaf(&pk, k["operator_did"].as_str().unwrap().as_bytes());
            assert_eq!(leaf, h32(&k["leaf"]));
            let proof: std::vec::Vec<[u8; 32]> = k["proof"].as_array().unwrap().iter().map(h32).collect();
            assert!(agent::merkle_verify(&keys_root, &leaf, &proof));
        }
        for c in v["chains"].as_array().unwrap() {
            let g = agent::Grant::decode(&h(&c["grant"]["bytes"])).unwrap();
            assert_eq!(g.seq, 1);
            assert_eq!(g.keys_root, keys_root);
            assert_eq!(g.account, h32(&c["account_word"]));
            assert!(agent::Grant::decode(&h(&c["void_grant"]["bytes"])).unwrap().void);
            let caip2 = c["chain"].as_str().unwrap().as_bytes();
            assert_eq!(agent::grant_tree_key(did, caip2), h32(&c["tree_key"]));
            assert_eq!(agent::salt(did), h32(&c["salt"]));
            let action = h(&c["action"]["encoded"]);
            assert_eq!(agent::act_digest(&g.chain, &g.account, 1, 0, &action), h32(&c["action_digest"]));
            assert_eq!(agent::payload_hash(&action), h32(&c["payload_hash"]));
            if !g.is_exact() {
                for t in c["targets"].as_array().unwrap() {
                    let leaf = agent::target_leaf(&h(&t["target"]), &h(&t["selector"]));
                    let proof: std::vec::Vec<[u8; 32]> = t["proof"].as_array().unwrap().iter().map(h32).collect();
                    assert!(agent::merkle_verify(&g.targets_root, &leaf, &proof));
                }
            }
        }
    }

    #[test]
    fn decimal_constants_are_read_exactly() {
        // q - 1 is even, and the alpha point's y is below q.
        assert_eq!(vk::Q[31] & 1, 1);
        assert!(vk::ALPHA[1] < vk::Q);
    }
}
