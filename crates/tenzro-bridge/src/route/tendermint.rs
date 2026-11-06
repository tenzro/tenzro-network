//! The CometBFT (Tendermint) light client, with ICS-23 membership proofs of
//! IBC packet commitments.
//!
//! **Headers.** The client starts from the route's anchor: the header at
//! the trusted height, whose hash must equal the anchor's. It then stores a
//! consensus state (time, app hash, next validator set hash) for every
//! header it accepts. A header is accepted on the rules CometBFT's light
//! client applies:
//!
//! - it names the anchor's chain id, is newer than the trusted header, and
//!   is not more than a minute ahead of Tenzro's clock;
//! - the trusted consensus state is younger than the trusting period;
//! - its commit is for this header, and validators holding more than two
//!   thirds of the header's validator set's power signed it;
//! - for the next height, its validator set is the one the trusted header
//!   named; further ahead, validators holding more than a third of the
//!   power of the trusted next validator set also signed it.
//!
//! Hashes follow CometBFT exactly: the header hash is the RFC 6962 Merkle
//! root of its protobuf-encoded fields, the validator set hash that of each
//! validator's protobuf encoding, and each vote is signed over its
//! length-delimited canonical protobuf encoding.
//!
//! **Packets.** A delivery's proof names a height whose consensus state the
//! client holds, repeats the packet, and carries two ICS-23 existence
//! proofs: the packet commitment under its path in the IAVL store the
//! route's `ramp` names, and that store's root in the multistore, whose root
//! is the header's app hash. A packet whose timeout has passed is refused.
//!
//! **Store entries.** [`verify_store_entry`] proves any other entry of that
//! store the same way ([`EntryProof`]): that it holds a value (a connection
//! or channel end, an acknowledgement), or that it is absent (a receipt),
//! by its two neighbouring leaves, which must be adjacent in the tree.
//!
//! **Encodings.** All fixed-layout, big-endian:
//!
//! ```text
//! update     = 0x00 header                                  (bootstrap)
//!            | 0x01 trusted_height:u64 header commit validators trusted_validators
//! header     = version_block:u64 version_app:u64 chain_id:str height:u64
//!              time_seconds:u64 time_nanos:u32
//!              last_block_hash:bytes last_parts_total:u32 last_parts_hash:bytes
//!              last_commit_hash:bytes data_hash:bytes validators_hash:bytes
//!              next_validators_hash:bytes consensus_hash:bytes app_hash:bytes
//!              last_results_hash:bytes evidence_hash:bytes proposer:bytes
//! commit     = height:u64 round:u32 block_hash:bytes parts_total:u32 parts_hash:bytes
//!              count:u16 { flag:u8 [address:20 seconds:u64 nanos:u32 signature:64] }
//! validators = count:u16 { ed25519_key:32 power:u64 }
//! proof      = height:u64 packet:bytes iavl:existence store:existence
//! existence  = key:bytes value:bytes leaf_prefix:bytes count:u8 { prefix:bytes suffix:bytes }
//! ```
//!
//! `str` is a u16 length and UTF-8, `bytes` a u32 length; a commit
//! signature carries address, time and signature unless its flag is 1
//! (absent).

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::attestation::body_hash;
use super::canonical::{Reader, Writer};
use super::ibc::Packet;
use super::light_client::{LightClientHead, LightClientVerifier};
use super::state::RouteState;
use super::{BridgeRoute, LightClientAnchor, LightClientKind};
use crate::error::{BridgeError, Result};

/// Largest validator set accepted.
pub const MAX_VALIDATORS: usize = 300;

/// How far a header's time may run ahead of Tenzro's clock.
pub const MAX_CLOCK_DRIFT_MS: i64 = 60_000;

/// Longest ICS-23 path accepted.
const MAX_PATH: usize = 64;

/// Longest hash-like header field.
const MAX_HASH_FIELD: usize = 64;

const FLAG_ABSENT: u8 = 1;
const FLAG_COMMIT: u8 = 2;
const FLAG_NIL: u8 = 3;
const PRECOMMIT: u64 = 2;

fn refuse(what: impl Into<String>) -> BridgeError {
    BridgeError::TransferFailed(format!("tendermint light client: {}", what.into()))
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ---- protobuf, as CometBFT encodes it ----

fn uvarint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn key(out: &mut Vec<u8>, field: u64, wire: u64) {
    uvarint(out, (field << 3) | wire);
}

/// A varint field, omitted when zero.
fn pb_uint(out: &mut Vec<u8>, field: u64, v: u64) {
    if v != 0 {
        key(out, field, 0);
        uvarint(out, v);
    }
}

/// A bytes or string field, omitted when empty.
fn pb_bytes(out: &mut Vec<u8>, field: u64, b: &[u8]) {
    if !b.is_empty() {
        pb_msg(out, field, b);
    }
}

/// An embedded message, always written.
fn pb_msg(out: &mut Vec<u8>, field: u64, b: &[u8]) {
    key(out, field, 2);
    uvarint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// An sfixed64 field, omitted when zero.
fn pb_sfixed64(out: &mut Vec<u8>, field: u64, v: i64) {
    if v != 0 {
        key(out, field, 1);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn timestamp(seconds: u64, nanos: u32) -> Vec<u8> {
    let mut t = Vec::new();
    pb_uint(&mut t, 1, seconds);
    pb_uint(&mut t, 2, u64::from(nanos));
    t
}

/// `BytesValue` / `StringValue` wrapping, as `cdcEncode` writes it.
fn wrapped(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    pb_bytes(&mut out, 1, b);
    out
}

/// RFC 6962 Merkle root, as CometBFT's `merkle.HashFromByteSlices`.
pub fn merkle_root(items: &[Vec<u8>]) -> [u8; 32] {
    match items.len() {
        0 => sha256(&[]),
        1 => sha256(&[&[0], &items[0]]),
        n => {
            let k = n.next_power_of_two() / 2;
            let left = merkle_root(&items[..k]);
            let right = merkle_root(&items[k..]);
            sha256(&[&[1], &left, &right])
        }
    }
}

// ---- headers, validator sets, commits ----

/// A CometBFT block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version_block: u64,
    pub version_app: u64,
    pub chain_id: String,
    pub height: u64,
    pub time_seconds: u64,
    pub time_nanos: u32,
    pub last_block_hash: Vec<u8>,
    pub last_parts_total: u32,
    pub last_parts_hash: Vec<u8>,
    pub last_commit_hash: Vec<u8>,
    pub data_hash: Vec<u8>,
    pub validators_hash: Vec<u8>,
    pub next_validators_hash: Vec<u8>,
    pub consensus_hash: Vec<u8>,
    pub app_hash: Vec<u8>,
    pub last_results_hash: Vec<u8>,
    pub evidence_hash: Vec<u8>,
    pub proposer: Vec<u8>,
}

impl Header {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let h = Self {
            version_block: r.u64_be()?,
            version_app: r.u64_be()?,
            chain_id: r.be_str(tenzro_types::bridge_route::MAX_TENDERMINT_CHAIN_ID_LEN)?,
            height: r.u64_be()?,
            time_seconds: r.u64_be()?,
            time_nanos: r.u32_be()?,
            last_block_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            last_parts_total: r.u32_be()?,
            last_parts_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            last_commit_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            data_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            validators_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            next_validators_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            consensus_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            app_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            last_results_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            evidence_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            proposer: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
        };
        if h.time_nanos >= 1_000_000_000 || h.time_seconds > i64::MAX as u64 {
            return Err(refuse("header time out of range"));
        }
        if h.height == 0 || h.validators_hash.len() != 32 || h.next_validators_hash.len() != 32 {
            return Err(refuse(
                "a header needs a height and both validator set hashes",
            ));
        }
        Ok(h)
    }

    /// The fixed-layout encoding.
    pub fn write(&self, w: &mut Writer) {
        w.u64_be(self.version_block)
            .u64_be(self.version_app)
            .be_str(&self.chain_id)
            .u64_be(self.height)
            .u64_be(self.time_seconds)
            .u32_be(self.time_nanos)
            .be_bytes(&self.last_block_hash)
            .u32_be(self.last_parts_total)
            .be_bytes(&self.last_parts_hash)
            .be_bytes(&self.last_commit_hash)
            .be_bytes(&self.data_hash)
            .be_bytes(&self.validators_hash)
            .be_bytes(&self.next_validators_hash)
            .be_bytes(&self.consensus_hash)
            .be_bytes(&self.app_hash)
            .be_bytes(&self.last_results_hash)
            .be_bytes(&self.evidence_hash)
            .be_bytes(&self.proposer);
    }

    /// The header hash, as CometBFT computes it.
    pub fn hash(&self) -> [u8; 32] {
        let mut version = Vec::new();
        pb_uint(&mut version, 1, self.version_block);
        pb_uint(&mut version, 2, self.version_app);
        let mut parts = Vec::new();
        pb_uint(&mut parts, 1, u64::from(self.last_parts_total));
        pb_bytes(&mut parts, 2, &self.last_parts_hash);
        let mut block_id = Vec::new();
        pb_bytes(&mut block_id, 1, &self.last_block_hash);
        pb_msg(&mut block_id, 2, &parts);
        let mut height = Vec::new();
        pb_uint(&mut height, 1, self.height);
        merkle_root(&[
            version,
            wrapped(self.chain_id.as_bytes()),
            height,
            timestamp(self.time_seconds, self.time_nanos),
            block_id,
            wrapped(&self.last_commit_hash),
            wrapped(&self.data_hash),
            wrapped(&self.validators_hash),
            wrapped(&self.next_validators_hash),
            wrapped(&self.consensus_hash),
            wrapped(&self.app_hash),
            wrapped(&self.last_results_hash),
            wrapped(&self.evidence_hash),
            wrapped(&self.proposer),
        ])
    }

    fn time_ns(&self) -> i128 {
        i128::from(self.time_seconds) * 1_000_000_000 + i128::from(self.time_nanos)
    }
}

/// One validator: its Ed25519 key and voting power.
pub type Validator = ([u8; 32], u64);

fn read_validators(r: &mut Reader<'_>) -> Result<Vec<Validator>> {
    let n = r.u16_be()? as usize;
    if n == 0 || n > MAX_VALIDATORS {
        return Err(refuse(format!("a validator set of {n}")));
    }
    let mut set = Vec::with_capacity(n);
    for _ in 0..n {
        let key = r.array::<32>()?;
        let power = r.u64_be()?;
        if power == 0 || power > i64::MAX as u64 {
            return Err(refuse("validator power out of range"));
        }
        set.push((key, power));
    }
    Ok(set)
}

/// The fixed-layout encoding of a validator set.
pub fn write_validators(w: &mut Writer, set: &[Validator]) {
    w.u16_be(set.len() as u16);
    for (k, p) in set {
        w.raw(k).u64_be(*p);
    }
}

/// The validator set hash, as CometBFT computes it.
pub fn validators_hash(set: &[Validator]) -> [u8; 32] {
    let items: Vec<Vec<u8>> = set
        .iter()
        .map(|(k, p)| {
            let mut pk = Vec::new();
            pb_bytes(&mut pk, 1, k);
            let mut v = Vec::new();
            pb_msg(&mut v, 1, &pk);
            pb_uint(&mut v, 2, *p);
            v
        })
        .collect();
    merkle_root(&items)
}

/// A validator's address: the first 20 bytes of the SHA-256 of its key.
pub fn address(key: &[u8; 32]) -> [u8; 20] {
    let h = sha256(&[key]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[..20]);
    a
}

fn total_power(set: &[Validator]) -> Result<u128> {
    Ok(set.iter().map(|(_, p)| u128::from(*p)).sum())
}

/// One signature in a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSig {
    pub flag: u8,
    pub address: [u8; 20],
    pub seconds: u64,
    pub nanos: u32,
    pub signature: [u8; 64],
}

/// A commit: the precommits that finalized one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub height: u64,
    pub round: u32,
    pub block_hash: [u8; 32],
    pub parts_total: u32,
    pub parts_hash: Vec<u8>,
    pub signatures: Vec<CommitSig>,
}

impl Commit {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let height = r.u64_be()?;
        let round = r.u32_be()?;
        let block_hash: [u8; 32] = r
            .be_bytes(32)?
            .try_into()
            .map_err(|_| refuse("a commit's block hash is 32 bytes"))?;
        let parts_total = r.u32_be()?;
        let parts_hash = r.be_bytes(MAX_HASH_FIELD)?.to_vec();
        let n = r.u16_be()? as usize;
        if n == 0 || n > MAX_VALIDATORS {
            return Err(refuse(format!("a commit with {n} signatures")));
        }
        let mut signatures = Vec::with_capacity(n);
        for _ in 0..n {
            let flag = r.u8()?;
            let sig = match flag {
                FLAG_ABSENT => CommitSig {
                    flag,
                    address: [0; 20],
                    seconds: 0,
                    nanos: 0,
                    signature: [0; 64],
                },
                FLAG_COMMIT | FLAG_NIL => CommitSig {
                    flag,
                    address: r.array()?,
                    seconds: r.u64_be()?,
                    nanos: r.u32_be()?,
                    signature: r.array()?,
                },
                _ => return Err(refuse(format!("unknown commit flag {flag}"))),
            };
            signatures.push(sig);
        }
        Ok(Self {
            height,
            round,
            block_hash,
            parts_total,
            parts_hash,
            signatures,
        })
    }

    /// The fixed-layout encoding.
    pub fn write(&self, w: &mut Writer) {
        w.u64_be(self.height)
            .u32_be(self.round)
            .be_bytes(&self.block_hash)
            .u32_be(self.parts_total)
            .be_bytes(&self.parts_hash)
            .u16_be(self.signatures.len() as u16);
        for s in &self.signatures {
            w.u8(s.flag);
            if s.flag != FLAG_ABSENT {
                w.raw(&s.address)
                    .u64_be(s.seconds)
                    .u32_be(s.nanos)
                    .raw(&s.signature);
            }
        }
    }

    /// The bytes validator `sig` signed: the length-delimited canonical
    /// precommit for this block.
    pub fn sign_bytes(&self, chain_id: &str, sig: &CommitSig) -> Vec<u8> {
        let mut parts = Vec::new();
        pb_uint(&mut parts, 1, u64::from(self.parts_total));
        pb_bytes(&mut parts, 2, &self.parts_hash);
        let mut block_id = Vec::new();
        pb_bytes(&mut block_id, 1, &self.block_hash);
        pb_msg(&mut block_id, 2, &parts);
        let mut vote = Vec::new();
        pb_uint(&mut vote, 1, PRECOMMIT);
        pb_sfixed64(&mut vote, 2, self.height as i64);
        pb_sfixed64(&mut vote, 3, i64::from(self.round));
        pb_msg(&mut vote, 4, &block_id);
        pb_msg(&mut vote, 5, &timestamp(sig.seconds, sig.nanos));
        pb_bytes(&mut vote, 6, chain_id.as_bytes());
        let mut out = Vec::new();
        uvarint(&mut out, vote.len() as u64);
        out.extend_from_slice(&vote);
        out
    }

    fn check_signature(&self, chain_id: &str, key: &[u8; 32], sig: &CommitSig) -> Result<()> {
        let vk = VerifyingKey::from_bytes(key)
            .map_err(|_| refuse("a validator key is not a curve point"))?;
        vk.verify_strict(
            &self.sign_bytes(chain_id, sig),
            &Signature::from_bytes(&sig.signature),
        )
        .map_err(|_| {
            refuse(format!(
                "bad precommit signature from {}",
                hex::encode(sig.address)
            ))
        })
    }

    /// Power of `set` that signed this block, matching signatures to the
    /// set by position. Every signature for the block must verify.
    fn power_by_index(&self, chain_id: &str, set: &[Validator]) -> Result<u128> {
        if self.signatures.len() != set.len() {
            return Err(refuse("the commit does not match the validator set's size"));
        }
        let mut power = 0u128;
        for (sig, (key, p)) in self.signatures.iter().zip(set) {
            if sig.flag == FLAG_ABSENT {
                continue;
            }
            if sig.address != address(key) {
                return Err(refuse("a commit signature is out of validator order"));
            }
            if sig.flag == FLAG_COMMIT {
                self.check_signature(chain_id, key, sig)?;
                power += u128::from(*p);
            }
        }
        Ok(power)
    }

    /// Power of `trusted` that signed this block, matching signatures to
    /// the set by address, each validator once.
    fn power_by_address(&self, chain_id: &str, trusted: &[Validator]) -> Result<u128> {
        let mut seen = std::collections::HashSet::new();
        let mut power = 0u128;
        for sig in self.signatures.iter().filter(|s| s.flag == FLAG_COMMIT) {
            let Some((key, p)) = trusted.iter().find(|(k, _)| address(k) == sig.address) else {
                continue;
            };
            if !seen.insert(sig.address) {
                return Err(refuse("a validator signed the commit twice"));
            }
            self.check_signature(chain_id, key, sig)?;
            power += u128::from(*p);
        }
        Ok(power)
    }
}

// ---- ICS-23 ----

/// The two proof specs a packet proof uses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Spec {
    /// An IAVL store.
    Iavl,
    /// The multistore's simple Merkle tree.
    Tendermint,
}

/// An ICS-23 existence proof with the hash and length operations fixed by
/// its spec (SHA-256; the key as is, the value pre-hashed with SHA-256,
/// both length-prefixed with a protobuf varint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistenceProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub leaf_prefix: Vec<u8>,
    pub path: Vec<(Vec<u8>, Vec<u8>)>,
}

impl ExistenceProof {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let key = r.be_bytes(1024)?.to_vec();
        let value = r.be_bytes(1024)?.to_vec();
        let leaf_prefix = r.be_bytes(64)?.to_vec();
        let n = r.u8()? as usize;
        if n > MAX_PATH {
            return Err(refuse("ICS-23 path too long"));
        }
        let mut path = Vec::with_capacity(n);
        for _ in 0..n {
            path.push((r.be_bytes(128)?.to_vec(), r.be_bytes(128)?.to_vec()));
        }
        Ok(Self {
            key,
            value,
            leaf_prefix,
            path,
        })
    }

    /// The fixed-layout encoding.
    pub fn write(&self, w: &mut Writer) {
        w.be_bytes(&self.key)
            .be_bytes(&self.value)
            .be_bytes(&self.leaf_prefix)
            .u8(self.path.len() as u8);
        for (p, s) in &self.path {
            w.be_bytes(p).be_bytes(s);
        }
    }

    /// The root this proof computes, after checking every operation
    /// against `spec`.
    fn root(&self, spec: Spec) -> Result<[u8; 32]> {
        match spec {
            Spec::Iavl => {
                let mut r = Reader::new(&self.leaf_prefix);
                let (height, size, version) = (zigzag(&mut r)?, zigzag(&mut r)?, zigzag(&mut r)?);
                if height != 0 || size != 1 || version < 1 {
                    return Err(refuse("IAVL leaf prefix"));
                }
                r.finish().map_err(|_| refuse("IAVL leaf prefix"))?;
            }
            Spec::Tendermint => {
                if self.leaf_prefix != [0] {
                    return Err(refuse("multistore leaf prefix"));
                }
            }
        }
        let mut leaf = self.leaf_prefix.clone();
        uvarint(&mut leaf, self.key.len() as u64);
        leaf.extend_from_slice(&self.key);
        uvarint(&mut leaf, 32);
        leaf.extend_from_slice(&sha256(&[&self.value]));
        let mut node = sha256(&[&leaf]);
        for (layer, (prefix, suffix)) in self.path.iter().enumerate() {
            check_inner(spec, layer as i64 + 1, prefix, suffix)?;
            node = sha256(&[prefix, &node, suffix]);
        }
        Ok(node)
    }
}

fn zigzag(r: &mut Reader<'_>) -> Result<i64> {
    let mut v = 0u64;
    for i in 0..10 {
        let b = r.u8()?;
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            if b == 0 && i > 0 {
                return Err(refuse("non-minimal varint"));
            }
            return Ok(((v >> 1) as i64) ^ -((v & 1) as i64));
        }
    }
    Err(refuse("varint too long"))
}

fn check_inner(spec: Spec, layer: i64, prefix: &[u8], suffix: &[u8]) -> Result<()> {
    match spec {
        Spec::Iavl => {
            let mut r = Reader::new(prefix);
            let height = zigzag(&mut r)?;
            let size = zigzag(&mut r)?;
            let version = zigzag(&mut r)?;
            if height < layer || size < 2 || version < 1 {
                return Err(refuse("IAVL inner node"));
            }
            let rest = &prefix[r.position()..];
            let ok = match (rest.len(), suffix.len()) {
                // The proven child is the left one.
                (1, 33) => rest[0] == 32 && suffix[0] == 32,
                // The proven child is the right one.
                (34, 0) => rest[0] == 32 && rest[33] == 32,
                _ => false,
            };
            if !ok {
                return Err(refuse("IAVL inner node children"));
            }
        }
        Spec::Tendermint => {
            let ok = prefix.first() == Some(&1)
                && matches!((prefix.len(), suffix.len()), (1, 32) | (33, 0));
            if !ok {
                return Err(refuse("multistore inner node"));
            }
        }
    }
    Ok(())
}

// ---- the client ----

/// What the client keeps for each accepted height.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConsensusState {
    time_seconds: u64,
    time_nanos: u32,
    app_hash: Vec<u8>,
    next_validators_hash: [u8; 32],
}

impl ConsensusState {
    fn of(h: &Header) -> Result<Self> {
        Ok(Self {
            time_seconds: h.time_seconds,
            time_nanos: h.time_nanos,
            app_hash: h.app_hash.clone(),
            next_validators_hash: h
                .next_validators_hash
                .as_slice()
                .try_into()
                .map_err(|_| refuse("next validators hash"))?,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_be(self.time_seconds)
            .u32_be(self.time_nanos)
            .be_bytes(&self.app_hash)
            .raw(&self.next_validators_hash);
        w.into_bytes()
    }

    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let s = Self {
            time_seconds: r.u64_be()?,
            time_nanos: r.u32_be()?,
            app_hash: r.be_bytes(MAX_HASH_FIELD)?.to_vec(),
            next_validators_hash: r.array()?,
        };
        r.finish()?;
        Ok(s)
    }

    fn time_ns(&self) -> i128 {
        i128::from(self.time_seconds) * 1_000_000_000 + i128::from(self.time_nanos)
    }
}

struct Anchor<'a> {
    chain_id: &'a str,
    trusted_height: u64,
    trusted_header_hash: [u8; 32],
    trusting_period_ns: i128,
}

fn anchor_parts(anchor: &LightClientAnchor) -> Result<Anchor<'_>> {
    match anchor {
        LightClientAnchor::Tendermint {
            chain_id,
            trusted_height,
            trusted_header_hash,
            trusting_period_secs,
        } => Ok(Anchor {
            chain_id,
            trusted_height: *trusted_height,
            trusted_header_hash: *trusted_header_hash,
            trusting_period_ns: i128::from(*trusting_period_secs) * 1_000_000_000,
        }),
        _ => Err(refuse("the route's anchor is not a Tendermint anchor")),
    }
}

fn key_prefix(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    anchor.store_key(route)
}

fn consensus_key(route: &BridgeRoute, anchor: &LightClientAnchor, height: u64) -> String {
    format!("{}:cs:{height:020}", key_prefix(route, anchor))
}

fn latest_key(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    key_prefix(route, anchor)
}

fn consensus(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    height: u64,
) -> Result<Option<ConsensusState>> {
    state
        .get(&consensus_key(route, anchor, height))
        .map(|b| ConsensusState::decode(&b))
        .transpose()
}

fn latest(state: &dyn RouteState, route: &BridgeRoute, anchor: &LightClientAnchor) -> Option<u64> {
    state
        .get(&latest_key(route, anchor))
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
}

fn now_ns(state: &dyn RouteState) -> i128 {
    i128::from(state.now_ms()) * 1_000_000
}

fn ibc_version(route: &BridgeRoute) -> Result<super::IbcVersion> {
    route
        .ibc
        .as_ref()
        .map(|i| i.version)
        .ok_or_else(|| refuse("the route has no IBC settings"))
}

/// `store` proves `store_root` as the root of the route's store (named by
/// its `ramp`) in the multistore whose root is the header's app hash.
fn check_store_root(
    route: &BridgeRoute,
    cs: &ConsensusState,
    store_root: [u8; 32],
    store: &ExistenceProof,
) -> Result<()> {
    let store_name = route
        .ramp
        .iter()
        .take_while(|b| **b != 0)
        .copied()
        .collect::<Vec<u8>>();
    if store.key != store_name || store.value != store_root {
        return Err(refuse(
            "the multistore proof is not of the route's store root",
        ));
    }
    if store.root(Spec::Tendermint)?.as_slice() != cs.app_hash.as_slice() {
        return Err(refuse("the proof does not reach the header's app hash"));
    }
    Ok(())
}

/// Which child of an IAVL inner node a proof step passes through: 0 for the
/// left one (the sibling follows it), 1 for the right one.
fn iavl_side(step: &(Vec<u8>, Vec<u8>)) -> u8 {
    if step.1.is_empty() { 1 } else { 0 }
}

/// Every step of `path` passes through the right child: the leaf is the
/// last one under the node the path ends at.
fn rightmost(path: &[(Vec<u8>, Vec<u8>)]) -> bool {
    path.iter().all(|s| iavl_side(s) == 1)
}

fn leftmost(path: &[(Vec<u8>, Vec<u8>)]) -> bool {
    path.iter().all(|s| iavl_side(s) == 0)
}

/// Whether `left` and `right` (paths from leaf to root, both proven to the
/// same root) end at adjacent leaves: above the node where they part they
/// are the same steps, there `left` goes left and `right` goes right, and
/// below it `left` keeps right and `right` keeps left.
fn left_neighbour(left: &[(Vec<u8>, Vec<u8>)], right: &[(Vec<u8>, Vec<u8>)]) -> bool {
    let mut l = left.len();
    let mut r = right.len();
    while l > 0 && r > 0 && left[l - 1] == right[r - 1] {
        l -= 1;
        r -= 1;
    }
    if l == 0 || r == 0 {
        return false;
    }
    iavl_side(&left[l - 1]) == 0
        && iavl_side(&right[r - 1]) == 1
        && rightmost(&left[..l - 1])
        && leftmost(&right[..r - 1])
}

/// A proof of one entry of the route's IBC store: that it holds a value, or
/// that it is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreEntryProof {
    /// The entry exists.
    Exists(ExistenceProof),
    /// The entry is absent: its neighbours on either side (at most one may
    /// be missing, at the edge of the tree) are adjacent leaves.
    Absent {
        /// The absent key.
        key: Vec<u8>,
        /// The greatest key below it.
        left: Option<ExistenceProof>,
        /// The least key above it.
        right: Option<ExistenceProof>,
    },
}

/// A proof of one IBC store entry at a height of the route's chain:
///
/// ```text
/// entry_proof = height:u64 kind:u8 { 0: existence
///                                  | 1: key:bytes has_left:u8 [existence] has_right:u8 [existence] }
///               store:existence
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryProof {
    /// Height of the header whose app hash the proof reaches.
    pub height: u64,
    /// The entry in the IAVL store.
    pub entry: StoreEntryProof,
    /// The store's root in the multistore.
    pub store: ExistenceProof,
}

impl EntryProof {
    /// The fixed-layout encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_be(self.height);
        match &self.entry {
            StoreEntryProof::Exists(p) => {
                w.u8(0);
                p.write(&mut w);
            }
            StoreEntryProof::Absent { key, left, right } => {
                w.u8(1).be_bytes(key);
                for side in [left, right] {
                    match side {
                        Some(p) => {
                            w.u8(1);
                            p.write(&mut w);
                        }
                        None => {
                            w.u8(0);
                        }
                    }
                }
            }
        }
        self.store.write(&mut w);
        w.into_bytes()
    }

    /// Read a complete proof.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let height = r.u64_be()?;
        let entry = match r.u8()? {
            0 => StoreEntryProof::Exists(ExistenceProof::read(&mut r)?),
            1 => {
                let key = r.be_bytes(1024)?.to_vec();
                let mut side = || -> Result<Option<ExistenceProof>> {
                    match r.u8()? {
                        0 => Ok(None),
                        1 => Ok(Some(ExistenceProof::read(&mut r)?)),
                        _ => Err(refuse("a neighbour flag is 0 or 1")),
                    }
                };
                let left = side()?;
                let right = side()?;
                StoreEntryProof::Absent { key, left, right }
            }
            _ => return Err(refuse("unknown entry proof kind")),
        };
        let store = ExistenceProof::read(&mut r)?;
        r.finish()?;
        Ok(Self {
            height,
            entry,
            store,
        })
    }
}

/// Prove, against the route's light client, that the route's chain held
/// `value` under `key` in its IBC store (or, for `None`, held nothing
/// there) at the proof's height. Returns that height's block time in Unix
/// nanoseconds.
pub fn verify_store_entry(
    state: &dyn RouteState,
    route: &BridgeRoute,
    key: &[u8],
    value: Option<&[u8]>,
    proof: &[u8],
) -> Result<i128> {
    let anchor = route
        .light_client
        .as_ref()
        .ok_or_else(|| refuse("the route has no light client"))?;
    let a = anchor_parts(anchor)?;
    check_not_expired(state, route, anchor, &a)?;
    let p = EntryProof::decode(proof)?;
    let root = match (&p.entry, value) {
        (StoreEntryProof::Exists(e), Some(v)) => {
            if e.key != key || e.value != v {
                return Err(refuse("the IAVL proof is not of the expected entry"));
            }
            e.root(Spec::Iavl)?
        }
        (
            StoreEntryProof::Absent {
                key: absent,
                left,
                right,
            },
            None,
        ) => {
            if absent.as_slice() != key {
                return Err(refuse("the absence proof is for another key"));
            }
            let roots = [left, right]
                .into_iter()
                .flatten()
                .map(|n| n.root(Spec::Iavl))
                .collect::<Result<Vec<_>>>()?;
            let root = *roots
                .first()
                .ok_or_else(|| refuse("an absence proof needs a neighbour"))?;
            if roots.iter().any(|r| *r != root) {
                return Err(refuse("the neighbours prove different roots"));
            }
            let adjacent = match (left, right) {
                (Some(l), Some(r)) => {
                    l.key.as_slice() < key
                        && key < r.key.as_slice()
                        && left_neighbour(&l.path, &r.path)
                }
                (Some(l), None) => l.key.as_slice() < key && rightmost(&l.path),
                (None, Some(r)) => key < r.key.as_slice() && leftmost(&r.path),
                (None, None) => false,
            };
            if !adjacent {
                return Err(refuse("the neighbours do not enclose the key"));
            }
            root
        }
        _ => return Err(refuse("the proof does not show what is claimed")),
    };
    let cs = consensus(state, route, anchor, p.height)?
        .ok_or_else(|| refuse(format!("no verified header at height {}", p.height)))?;
    check_store_root(route, &cs, root, &p.store)?;
    Ok(cs.time_ns())
}

/// The multistore name of the CosmWasm module's store.
pub const WASM_STORE: &[u8] = b"wasm";

/// Where a CosmWasm settlement lock keeps leg `leg_id`: the wasm module's
/// contract-store prefix (0x03), the contract's address, then the lock's
/// own key `leg:<leg_id>`.
pub fn wasm_leg_key(lock: &[u8; 32], leg_id: &[u8; 32]) -> Vec<u8> {
    [&[0x03u8][..], lock, b"leg:", leg_id].concat()
}

/// Where a CosmWasm settlement lock keeps its reconciliation checkpoint:
/// the contract-store prefix, the contract's address, then `recon`.
pub fn wasm_recon_key(lock: &[u8; 32]) -> Vec<u8> {
    [&[0x03u8][..], lock, b"recon"].concat()
}

/// A CosmWasm lock's stored checkpoint (JSON `{"count", "acc": hex}`).
fn read_wasm_recon(value: &[u8]) -> Result<super::receipt_proof::LockCheckpoint> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Recon {
        count: u64,
        acc: String,
    }
    let r: Recon = serde_json::from_slice(value)
        .map_err(|e| refuse(format!("the stored checkpoint does not decode: {e}")))?;
    let mut acc = [0u8; 32];
    hex::decode_to_slice(&r.acc, &mut acc)
        .map_err(|_| refuse("the stored checkpoint hash is not 32 bytes of hex"))?;
    Ok(super::receipt_proof::LockCheckpoint {
        count: r.count,
        acc,
    })
}

/// A CosmWasm lock's stored leg (JSON), as the family-neutral event without
/// its plan, leg id and index: bech32 addresses as their bytes left-padded
/// to 32, the asset as SHA-256 of the denom. Only a leg still locked counts.
fn read_wasm_leg(value: &[u8]) -> Result<super::receipt_proof::LockEvent> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Coin {
        denom: String,
        amount: String,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Leg {
        payer: String,
        recipient: String,
        coin: Coin,
        escape_at: u64,
        stage: String,
    }
    let leg: Leg = serde_json::from_slice(value)
        .map_err(|e| refuse(format!("the stored leg does not decode: {e}")))?;
    if leg.stage != "locked" {
        return Err(refuse("the leg is no longer locked"));
    }
    let addr = |s: &str| -> Result<[u8; 32]> {
        let (_, data) = bech32::decode(s).map_err(|_| refuse("a leg address is not bech32"))?;
        if data.is_empty() || data.len() > 32 {
            return Err(refuse("a leg address is 1 to 32 bytes"));
        }
        let mut w = [0u8; 32];
        w[32 - data.len()..].copy_from_slice(&data);
        Ok(w)
    };
    let amount: u128 = leg
        .coin
        .amount
        .parse()
        .map_err(|_| refuse("the leg amount is not a number"))?;
    Ok(super::receipt_proof::LockEvent {
        plan_id: [0; 32],
        leg_id: [0; 32],
        index: 0,
        payer: addr(&leg.payer)?,
        recipient: addr(&leg.recipient)?,
        asset: sha256(&[leg.coin.denom.as_bytes()]),
        amount,
        escape_at_ms: leg.escape_at.saturating_mul(1000),
    })
}

/// The client must have a consensus state within the trusting period.
fn check_not_expired(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    a: &Anchor<'_>,
) -> Result<u64> {
    let height =
        latest(state, route, anchor).ok_or_else(|| refuse("not bootstrapped from the anchor"))?;
    let cs =
        consensus(state, route, anchor, height)?.ok_or_else(|| refuse("latest state missing"))?;
    if cs.time_ns() + a.trusting_period_ns <= now_ns(state) {
        return Err(refuse(
            "the client has expired: no header within the trusting period",
        ));
    }
    Ok(height)
}

/// The CometBFT light client. Its state lives in route state.
#[derive(Debug, Default)]
pub struct TendermintLightClient;

impl LightClientVerifier for TendermintLightClient {
    fn kind(&self) -> LightClientKind {
        LightClientKind::Tendermint
    }

    fn proven_lock_record(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        lock: &[u8; 32],
        proof: &[u8],
    ) -> Result<super::receipt_proof::LockRecord> {
        let a = anchor_parts(anchor)?;
        check_not_expired(state, route, anchor, &a)?;
        // 0 || plan_id (32) || index (1) || the entry proof of the leg, or
        // 1 || the entry proof of the lock's stored checkpoint.
        let (leg, p) = match proof.split_first() {
            Some((0, rest)) if rest.len() > 33 => {
                let plan_id: [u8; 32] = rest[..32].try_into().expect("32 bytes");
                (Some((plan_id, rest[32])), EntryProof::decode(&rest[33..])?)
            }
            Some((1, rest)) => (None, EntryProof::decode(rest)?),
            _ => return Err(refuse("a lock proof names a leg or the lock's checkpoint")),
        };
        let StoreEntryProof::Exists(entry) = &p.entry else {
            return Err(refuse("a lock is proven by its stored entry"));
        };
        let key = match leg {
            Some((plan_id, index)) => {
                wasm_leg_key(lock, &tenzro_types::settlement::leg_id(&plan_id, index))
            }
            None => wasm_recon_key(lock),
        };
        if entry.key != key {
            return Err(refuse(
                "the proof is not of the entry in the route's settlement lock",
            ));
        }
        let cs = consensus(state, route, anchor, p.height)?
            .ok_or_else(|| refuse(format!("no verified header at height {}", p.height)))?;
        if p.store.key != WASM_STORE || p.store.value != entry.root(Spec::Iavl)? {
            return Err(refuse("the multistore proof is not of the wasm store root"));
        }
        if p.store.root(Spec::Tendermint)?.as_slice() != cs.app_hash.as_slice() {
            return Err(refuse("the proof does not reach the header's app hash"));
        }
        let Some((plan_id, index)) = leg else {
            return read_wasm_recon(&entry.value).map(super::receipt_proof::LockRecord::Checkpoint);
        };
        let leg_id = tenzro_types::settlement::leg_id(&plan_id, index);
        let leg = read_wasm_leg(&entry.value)?;
        Ok(super::receipt_proof::LockRecord::Locked(
            super::receipt_proof::LockEvent {
                plan_id,
                leg_id,
                index,
                ..leg
            },
        ))
    }

    fn verify(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        body: &[u8; 32],
        proof: &[u8],
    ) -> Result<()> {
        let a = anchor_parts(anchor)?;
        check_not_expired(state, route, anchor, &a)?;
        let mut r = Reader::new(proof);
        let height = r.u64_be()?;
        let packet_bytes = r.be_bytes(super::attestation::MAX_BODY_LEN)?;
        let iavl = ExistenceProof::read(&mut r)?;
        let store = ExistenceProof::read(&mut r)?;
        r.finish()?;

        if body_hash(packet_bytes) != *body {
            return Err(refuse("the proof is for another packet"));
        }
        let packet = Packet::decode(packet_bytes, ibc_version(route)?)?;
        if packet.timeout_ns() <= now_ns(state) {
            return Err(refuse("the packet has timed out"));
        }
        if iavl.key != packet.commitment_key() || iavl.value != packet.commitment() {
            return Err(refuse("the IAVL proof is not of this packet's commitment"));
        }
        let cs = consensus(state, route, anchor, height)?
            .ok_or_else(|| refuse(format!("no verified header at height {height}")))?;
        check_store_root(route, &cs, iavl.root(Spec::Iavl)?, &store)
    }

    fn advance(
        &self,
        state: &mut dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        update: &[u8],
    ) -> Result<LightClientHead> {
        let a = anchor_parts(anchor)?;
        let mut r = Reader::new(update);
        let mut writes = Vec::new();
        let header = match r.u8()? {
            0 => {
                let header = Header::read(&mut r)?;
                r.finish()?;
                if header.height != a.trusted_height || header.hash() != a.trusted_header_hash {
                    return Err(refuse("the bootstrap header is not the anchor's"));
                }
                if header.chain_id != a.chain_id {
                    return Err(refuse("the bootstrap header names another chain"));
                }
                header
            }
            1 => {
                let trusted_height = r.u64_be()?;
                let header = Header::read(&mut r)?;
                let commit = Commit::read(&mut r)?;
                let validators = read_validators(&mut r)?;
                let trusted_validators = read_validators(&mut r)?;
                r.finish()?;
                let trusted =
                    consensus(state, route, anchor, trusted_height)?.ok_or_else(|| {
                        refuse(format!("no verified header at height {trusted_height}"))
                    })?;
                verify_header(
                    state,
                    &a,
                    &HeaderUpdate {
                        trusted_height,
                        trusted: &trusted,
                        header: &header,
                        commit: &commit,
                        validators: &validators,
                        trusted_validators: &trusted_validators,
                    },
                )?;
                header
            }
            t => return Err(refuse(format!("unknown update tag {t}"))),
        };

        let cs = ConsensusState::of(&header)?;
        match consensus(state, route, anchor, header.height)? {
            Some(existing) if existing != cs => {
                return Err(refuse(format!(
                    "a conflicting header at height {}: the chain's validators signed two blocks",
                    header.height
                )));
            }
            _ => {}
        }
        let height = latest(state, route, anchor).map_or(header.height, |l| l.max(header.height));
        writes.push((consensus_key(route, anchor, header.height), cs.encode()));
        writes.push((latest_key(route, anchor), height.to_be_bytes().to_vec()));
        state.apply(writes)?;
        Ok(LightClientHead {
            kind: "tendermint",
            finalized: height,
            period: 0,
            next_known: true,
        })
    }

    fn head(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
    ) -> Option<LightClientHead> {
        latest(state, route, anchor).map(|h| LightClientHead {
            kind: "tendermint",
            finalized: h,
            period: 0,
            next_known: true,
        })
    }
}

/// A header update against one trusted consensus state.
struct HeaderUpdate<'a> {
    trusted_height: u64,
    trusted: &'a ConsensusState,
    header: &'a Header,
    commit: &'a Commit,
    validators: &'a [Validator],
    trusted_validators: &'a [Validator],
}

fn verify_header(state: &dyn RouteState, a: &Anchor<'_>, u: &HeaderUpdate<'_>) -> Result<()> {
    let HeaderUpdate {
        trusted_height,
        trusted,
        header,
        commit,
        validators,
        trusted_validators,
    } = *u;
    let now = now_ns(state);
    if header.chain_id != a.chain_id {
        return Err(refuse("the header names another chain"));
    }
    if header.height <= trusted_height || header.time_ns() <= trusted.time_ns() {
        return Err(refuse("the header is not newer than the trusted header"));
    }
    if trusted.time_ns() + a.trusting_period_ns <= now {
        return Err(refuse("the trusted header is outside the trusting period"));
    }
    if header.time_ns() > now + i128::from(MAX_CLOCK_DRIFT_MS) * 1_000_000 {
        return Err(refuse("the header is from the future"));
    }
    if commit.height != header.height || commit.block_hash != header.hash() {
        return Err(refuse("the commit is for another block"));
    }
    if header.validators_hash != validators_hash(validators) {
        return Err(refuse("the validator set is not the header's"));
    }
    if validators_hash(trusted_validators) != trusted.next_validators_hash {
        return Err(refuse(
            "the trusted validators are not the trusted header's next set",
        ));
    }
    if header.height == trusted_height + 1 {
        if header.validators_hash != trusted.next_validators_hash {
            return Err(refuse(
                "the next header's validators are not the ones the trusted header named",
            ));
        }
    } else {
        let signed = commit.power_by_address(a.chain_id, trusted_validators)?;
        if signed * 3 <= total_power(trusted_validators)? {
            return Err(refuse(
                "a third of the trusted validators' power did not sign",
            ));
        }
    }
    let signed = commit.power_by_index(a.chain_id, validators)?;
    if signed * 3 <= total_power(validators)? * 2 {
        return Err(refuse("two thirds of the validators' power did not sign"));
    }
    Ok(())
}

/// A CometBFT node's RPC responses (`/commit`, `/validators`, `/abci_query`
/// with `prove=true`) turned into the encodings this light client takes. A
/// relayer needs nothing else: every value is checked when applied.
pub mod cometbft_rpc {
    use serde_json::Value;

    use super::super::canonical::Writer;
    use super::{
        Commit, CommitSig, EntryProof, ExistenceProof, Header, StoreEntryProof, Validator,
        write_validators,
    };
    use crate::error::{BridgeError, Result};

    fn bad(what: impl Into<String>) -> BridgeError {
        BridgeError::InvalidParameter(format!("cometbft rpc: {}", what.into()))
    }

    fn field<'a>(v: &'a Value, path: &[&str]) -> Result<&'a Value> {
        path.iter()
            .try_fold(v, |v, k| v.get(*k))
            .ok_or_else(|| bad(format!("missing {}", path.join("."))))
    }

    fn text<'a>(v: &'a Value, path: &[&str]) -> Result<&'a str> {
        field(v, path)?
            .as_str()
            .ok_or_else(|| bad(format!("{} is not text", path.join("."))))
    }

    fn number(v: &Value, path: &[&str]) -> Result<u64> {
        let f = field(v, path)?;
        f.as_u64()
            .or_else(|| f.as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| bad(format!("{} is not a number", path.join("."))))
    }

    fn hexb(v: &Value, path: &[&str]) -> Result<Vec<u8>> {
        hex::decode(text(v, path)?).map_err(|_| bad(format!("{} is not hex", path.join("."))))
    }

    fn b64(s: &str) -> Result<Vec<u8>> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|_| bad("not base64"))
    }

    fn time(s: &str) -> Result<(u64, u32)> {
        let t = chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|_| bad(format!("'{s}' is not a time")))?;
        Ok((
            u64::try_from(t.timestamp()).map_err(|_| bad("a time before 1970"))?,
            t.timestamp_subsec_nanos(),
        ))
    }

    fn result(v: &Value) -> &Value {
        v.get("result").unwrap_or(v)
    }

    /// The header of a `/commit` response.
    pub fn header(commit: &Value) -> Result<Header> {
        let h = field(result(commit), &["signed_header", "header"])?;
        let (time_seconds, time_nanos) = time(text(h, &["time"])?)?;
        Ok(Header {
            version_block: number(h, &["version", "block"])?,
            version_app: number(h, &["version", "app"]).unwrap_or(0),
            chain_id: text(h, &["chain_id"])?.to_string(),
            height: number(h, &["height"])?,
            time_seconds,
            time_nanos,
            last_block_hash: hexb(h, &["last_block_id", "hash"])?,
            last_parts_total: number(h, &["last_block_id", "parts", "total"])? as u32,
            last_parts_hash: hexb(h, &["last_block_id", "parts", "hash"])?,
            last_commit_hash: hexb(h, &["last_commit_hash"])?,
            data_hash: hexb(h, &["data_hash"])?,
            validators_hash: hexb(h, &["validators_hash"])?,
            next_validators_hash: hexb(h, &["next_validators_hash"])?,
            consensus_hash: hexb(h, &["consensus_hash"])?,
            app_hash: hexb(h, &["app_hash"])?,
            last_results_hash: hexb(h, &["last_results_hash"])?,
            evidence_hash: hexb(h, &["evidence_hash"])?,
            proposer: hexb(h, &["proposer_address"])?,
        })
    }

    /// The commit of a `/commit` response.
    pub fn commit(commit: &Value) -> Result<Commit> {
        let c = field(result(commit), &["signed_header", "commit"])?;
        let mut signatures = Vec::new();
        for s in field(c, &["signatures"])?
            .as_array()
            .ok_or_else(|| bad("signatures is not a list"))?
        {
            let flag = number(s, &["block_id_flag"])? as u8;
            if flag == 1 {
                signatures.push(CommitSig {
                    flag,
                    address: [0; 20],
                    seconds: 0,
                    nanos: 0,
                    signature: [0; 64],
                });
                continue;
            }
            let (seconds, nanos) = time(text(s, &["timestamp"])?)?;
            signatures.push(CommitSig {
                flag,
                address: hexb(s, &["validator_address"])?
                    .try_into()
                    .map_err(|_| bad("an address is 20 bytes"))?,
                seconds,
                nanos,
                signature: b64(text(s, &["signature"])?)?
                    .try_into()
                    .map_err(|_| bad("a signature is 64 bytes"))?,
            });
        }
        Ok(Commit {
            height: number(c, &["height"])?,
            round: number(c, &["round"])? as u32,
            block_hash: hexb(c, &["block_id", "hash"])?
                .try_into()
                .map_err(|_| bad("a block hash is 32 bytes"))?,
            parts_total: number(c, &["block_id", "parts", "total"])? as u32,
            parts_hash: hexb(c, &["block_id", "parts", "hash"])?,
            signatures,
        })
    }

    /// The validators of `/validators` responses (all pages), in order.
    pub fn validators(list: &[Value]) -> Result<Vec<Validator>> {
        list.iter()
            .map(|v| {
                if text(v, &["pub_key", "type"])? != "tendermint/PubKeyEd25519" {
                    return Err(bad("a validator key that is not Ed25519"));
                }
                Ok((
                    b64(text(v, &["pub_key", "value"])?)?
                        .try_into()
                        .map_err(|_| bad("a key is 32 bytes"))?,
                    number(v, &["voting_power"])?,
                ))
            })
            .collect()
    }

    /// The bootstrap update from the anchor's `/commit` response.
    pub fn bootstrap(commit_response: &Value) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(0);
        header(commit_response)?.write(&mut w);
        Ok(w.into_bytes())
    }

    /// The update to the header of `target` (a `/commit` response), whose
    /// validator set is `validators`, from the header at `trusted_height`
    /// whose next validator set is `trusted_next`.
    pub fn update(
        trusted_height: u64,
        target: &Value,
        validators: &[Validator],
        trusted_next: &[Validator],
    ) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(1).u64_be(trusted_height);
        header(target)?.write(&mut w);
        commit(target)?.write(&mut w);
        write_validators(&mut w, validators);
        write_validators(&mut w, trusted_next);
        Ok(w.into_bytes())
    }

    fn varint(b: &[u8], at: &mut usize) -> Result<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *b.get(*at).ok_or_else(|| bad("truncated protobuf"))?;
            *at += 1;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(bad("a varint too long"))
    }

    /// The fields of a protobuf message: number, and bytes for
    /// length-delimited fields (varints are skipped).
    fn fields(b: &[u8]) -> Result<Vec<(u64, &[u8])>> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < b.len() {
            let key = varint(b, &mut at)?;
            match key & 7 {
                0 => {
                    varint(b, &mut at)?;
                }
                2 => {
                    let n = varint(b, &mut at)? as usize;
                    let v = b.get(at..at + n).ok_or_else(|| bad("truncated protobuf"))?;
                    at += n;
                    out.push((key >> 3, v));
                }
                _ => return Err(bad("an unexpected protobuf wire type")),
            }
        }
        Ok(out)
    }

    fn existence(commitment_proof: &[u8]) -> Result<ExistenceProof> {
        let exist = fields(commitment_proof)?
            .into_iter()
            .find(|(n, _)| *n == 1)
            .map(|(_, v)| v)
            .ok_or_else(|| bad("not an existence proof"))?;
        existence_message(exist)
    }

    /// The proof of the IBC store entry an `/abci_query` (with
    /// `prove=true`) of `key` returned, existing or absent, for the header at
    /// `height` (the query's height plus one).
    pub fn entry_proof(abci_query: &Value, key: &[u8], height: u64) -> Result<EntryProof> {
        let ops = field(result(abci_query), &["response", "proofOps", "ops"])?
            .as_array()
            .ok_or_else(|| bad("ops is not a list"))?;
        let [iavl, store] = ops.as_slice() else {
            return Err(bad("an IAVL proof and a multistore proof"));
        };
        let commitment = b64(text(iavl, &["data"])?)?;
        let (kind, body) = fields(&commitment)?
            .into_iter()
            .next()
            .ok_or_else(|| bad("an empty commitment proof"))?;
        let entry = match kind {
            1 => StoreEntryProof::Exists(existence_message(body)?),
            2 => {
                let mut left = None;
                let mut right = None;
                for (n, v) in fields(body)? {
                    match n {
                        2 => left = Some(existence_message(v)?),
                        3 => right = Some(existence_message(v)?),
                        _ => {}
                    }
                }
                StoreEntryProof::Absent {
                    key: key.to_vec(),
                    left,
                    right,
                }
            }
            _ => return Err(bad("neither an existence nor a non-existence proof")),
        };
        Ok(EntryProof {
            height,
            entry,
            store: existence(&b64(text(store, &["data"])?)?)?,
        })
    }

    fn existence_message(exist: &[u8]) -> Result<ExistenceProof> {
        let mut p = ExistenceProof {
            key: vec![],
            value: vec![],
            leaf_prefix: vec![],
            path: vec![],
        };
        for (n, v) in fields(exist)? {
            match n {
                1 => p.key = v.to_vec(),
                2 => p.value = v.to_vec(),
                3 => {
                    p.leaf_prefix = fields(v)?
                        .into_iter()
                        .find(|(n, _)| *n == 5)
                        .map(|(_, v)| v.to_vec())
                        .unwrap_or_default();
                }
                4 => {
                    let f = fields(v)?;
                    let get = |k: u64| {
                        f.iter()
                            .find(|(n, _)| *n == k)
                            .map(|(_, v)| v.to_vec())
                            .unwrap_or_default()
                    };
                    p.path.push((get(2), get(3)));
                }
                _ => {}
            }
        }
        Ok(p)
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod fixtures {
    //! Validators that sign real CometBFT precommits, and ICS-23 proofs of
    //! a packet commitment, for route tests.

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    pub struct Validators {
        pub keys: Vec<SigningKey>,
    }

    impl Validators {
        pub fn new(seed: u8, n: usize) -> Self {
            Self {
                keys: (0..n)
                    .map(|i| SigningKey::from_bytes(&[seed.wrapping_add(i as u8).max(1); 32]))
                    .collect(),
            }
        }

        pub fn set(&self) -> Vec<Validator> {
            self.keys
                .iter()
                .map(|k| (k.verifying_key().to_bytes(), 10))
                .collect()
        }

        pub fn hash(&self) -> [u8; 32] {
            validators_hash(&self.set())
        }

        /// A commit for `header` signed by the first `signers` validators.
        pub fn commit(&self, header: &Header, signers: usize) -> Commit {
            let mut c = Commit {
                height: header.height,
                round: 0,
                block_hash: header.hash(),
                parts_total: 1,
                parts_hash: vec![0x77; 32],
                signatures: vec![],
            };
            c.signatures = self
                .keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    if i >= signers {
                        return CommitSig {
                            flag: FLAG_ABSENT,
                            address: [0; 20],
                            seconds: 0,
                            nanos: 0,
                            signature: [0; 64],
                        };
                    }
                    let mut s = CommitSig {
                        flag: FLAG_COMMIT,
                        address: address(&k.verifying_key().to_bytes()),
                        seconds: header.time_seconds,
                        nanos: 5,
                        signature: [0; 64],
                    };
                    s.signature = k.sign(&c.sign_bytes(&header.chain_id, &s)).to_bytes();
                    s
                })
                .collect();
            c
        }
    }

    pub fn header(
        chain_id: &str,
        height: u64,
        seconds: u64,
        vals: [u8; 32],
        next: [u8; 32],
        app_hash: [u8; 32],
    ) -> Header {
        Header {
            version_block: 11,
            version_app: 0,
            chain_id: chain_id.into(),
            height,
            time_seconds: seconds,
            time_nanos: 1,
            last_block_hash: vec![0x11; 32],
            last_parts_total: 1,
            last_parts_hash: vec![0x12; 32],
            last_commit_hash: vec![0x13; 32],
            data_hash: vec![0x14; 32],
            validators_hash: vals.to_vec(),
            next_validators_hash: next.to_vec(),
            consensus_hash: vec![0x15; 32],
            app_hash: app_hash.to_vec(),
            last_results_hash: vec![],
            evidence_hash: vec![0x16; 32],
            proposer: vec![0x17; 20],
        }
    }

    pub fn bootstrap(h: &Header) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(0);
        h.write(&mut w);
        w.into_bytes()
    }

    pub fn update(
        trusted_height: u64,
        h: &Header,
        c: &Commit,
        vals: &[Validator],
        trusted: &[Validator],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).u64_be(trusted_height);
        h.write(&mut w);
        c.write(&mut w);
        write_validators(&mut w, vals);
        write_validators(&mut w, trusted);
        w.into_bytes()
    }

    fn zz(out: &mut Vec<u8>, v: i64) {
        uvarint(out, ((v << 1) ^ (v >> 63)) as u64);
    }

    /// An IAVL store holding `entries` (balanced, keys in order) under a
    /// multistore, with the ICS-23 proofs a Cosmos chain serves for it.
    pub struct StoreFixture {
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        /// The app hash the multistore commits to.
        pub app_hash: [u8; 32],
        /// The store's root in the multistore.
        pub store: ExistenceProof,
    }

    fn leaf_prefix() -> Vec<u8> {
        let mut p = Vec::new();
        zz(&mut p, 0);
        zz(&mut p, 1);
        zz(&mut p, 9);
        p
    }

    /// The hash and height of the subtree over `entries`, and the proof
    /// path from entry `target` (if it is in the subtree) up to its root.
    fn subtree(
        entries: &[(Vec<u8>, Vec<u8>)],
        target: usize,
    ) -> ([u8; 32], i64, Vec<(Vec<u8>, Vec<u8>)>) {
        if entries.len() == 1 {
            let leaf = ExistenceProof {
                key: entries[0].0.clone(),
                value: entries[0].1.clone(),
                leaf_prefix: leaf_prefix(),
                path: vec![],
            };
            return (leaf.root(Spec::Iavl).unwrap(), 0, vec![]);
        }
        let mid = entries.len() / 2;
        let (lh, lheight, lpath) = subtree(&entries[..mid], target);
        let (rh, rheight, rpath) = subtree(&entries[mid..], target.wrapping_sub(mid));
        let height = lheight.max(rheight) + 1;
        let mut meta = Vec::new();
        zz(&mut meta, height);
        zz(&mut meta, entries.len() as i64);
        zz(&mut meta, 9);
        let mut prefix = meta.clone();
        prefix.push(32);
        prefix.extend_from_slice(&lh);
        prefix.push(32);
        let hash = sha256(&[&prefix, &rh]);
        let path = if target < mid {
            let mut step_prefix = meta;
            step_prefix.push(32);
            let mut suffix = vec![32u8];
            suffix.extend_from_slice(&rh);
            let mut p = lpath;
            p.push((step_prefix, suffix));
            p
        } else if target - mid < entries.len() - mid {
            let mut p = rpath;
            p.push((prefix, vec![]));
            p
        } else {
            vec![]
        };
        (hash, height, path)
    }

    impl StoreFixture {
        /// The store `store` holding `entries`.
        pub fn new(store: &str, mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
            entries.sort();
            let (root, ..) = subtree(&entries, usize::MAX);
            let multistore = ExistenceProof {
                key: store.as_bytes().to_vec(),
                value: root.to_vec(),
                leaf_prefix: vec![0],
                path: vec![(vec![1], vec![0x6b; 32])],
            };
            let app_hash = multistore.root(Spec::Tendermint).unwrap();
            Self {
                entries,
                app_hash,
                store: multistore,
            }
        }

        fn exist(&self, i: usize) -> ExistenceProof {
            ExistenceProof {
                key: self.entries[i].0.clone(),
                value: self.entries[i].1.clone(),
                leaf_prefix: leaf_prefix(),
                path: subtree(&self.entries, i).2,
            }
        }

        /// The existence proof of `key`.
        pub fn existence(&self, key: &[u8]) -> ExistenceProof {
            self.exist(
                self.entries
                    .iter()
                    .position(|(k, _)| k == key)
                    .expect("an entry"),
            )
        }

        /// The proof of `key` at `height`: existence if the store holds it,
        /// else absence between its neighbours.
        pub fn proof(&self, key: &[u8], height: u64) -> EntryProof {
            let entry = match self.entries.iter().position(|(k, _)| k == key) {
                Some(i) => StoreEntryProof::Exists(self.exist(i)),
                None => {
                    let right = self.entries.iter().position(|(k, _)| k.as_slice() > key);
                    let left = match right {
                        Some(0) => None,
                        Some(r) => Some(r - 1),
                        None => Some(self.entries.len() - 1),
                    };
                    StoreEntryProof::Absent {
                        key: key.to_vec(),
                        left: left.map(|i| self.exist(i)),
                        right: right.map(|i| self.exist(i)),
                    }
                }
            };
            EntryProof {
                height,
                entry,
                store: self.store.clone(),
            }
        }
    }

    /// ICS-23 proofs of `packet`'s commitment in store `store`: returns the
    /// app hash they reach and the two existence proofs.
    pub fn packet_proofs(
        packet: &Packet,
        store: &str,
    ) -> ([u8; 32], ExistenceProof, ExistenceProof) {
        let key = packet.commitment_key();
        let s = StoreFixture::new(
            store,
            vec![
                (key.clone(), packet.commitment().to_vec()),
                (b"zz-other".to_vec(), vec![0x5a; 32]),
            ],
        );
        (s.app_hash, s.existence(&key), s.store.clone())
    }

    pub fn message_proof(
        height: u64,
        packet: &Packet,
        iavl: &ExistenceProof,
        store: &ExistenceProof,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_be(height).be_bytes(&packet.encode());
        iavl.write(&mut w);
        store.write(&mut w);
        w.into_bytes()
    }
}

#[cfg(test)]
mod cometbft_tests {
    use serde_json::Value;

    use super::super::test_support::{MemState, NOW_MS};
    use super::super::{BridgeRouteAdapter, ChainFamily, MintRateLimit, VerifierQuorum};
    use super::*;

    /// Recorded from Cosmos Hub through a public CometBFT RPC node: a header
    /// and, forty blocks later, a header with its commit and validator set,
    /// the validators the first header named next, and an ICS-23 proof of an
    /// IBC packet commitment as of the block before the second header.
    const HUB: &str = include_str!("../../tests/fixtures/cosmoshub.json");

    fn route(anchor: LightClientAnchor) -> BridgeRoute {
        let mut ramp = [0u8; 32];
        ramp[..3].copy_from_slice(b"ibc");
        BridgeRoute {
            adapter: BridgeRouteAdapter::Ibc,
            family: ChainFamily::Cosmos,
            source_chain: "cosmoshub".into(),
            source_chain_id: 1,
            local_selector: 2,
            peer: [1; 32],
            ramp,
            local_endpoint: [2; 32],
            remote_token: [3; 32],
            verifiers: VerifierQuorum {
                set_index: 0,
                size: 0,
                members: vec![],
                threshold: 0,
            },
            blessing: None,
            light_client: Some(anchor),
            mint_limit: MintRateLimit {
                per_mint: 1,
                per_epoch: 1,
            },
            outflow: tenzro_types::bridge_route::LaneRateLimit {
                capacity: u128::MAX,
                rate: u128::MAX / 2,
            },
            lane_limits: None,
            ibc: None,
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
        }
    }

    #[test]
    fn cosmos_hub_headers_are_followed_and_a_packet_commitment_is_proven_to_their_app_hash() {
        let f: Value = serde_json::from_str(HUB).unwrap();
        let trusted = cometbft_rpc::header(&f["trusted"]).unwrap();
        let target = cometbft_rpc::header(&f["target"]).unwrap();
        // The headers hash to the block ids the chain names them by.
        let id = |v: &Value| {
            hex::decode(
                v["signed_header"]["commit"]["block_id"]["hash"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(trusted.hash().to_vec(), id(&f["trusted"]));
        assert_eq!(target.hash().to_vec(), id(&f["target"]));

        let anchor = LightClientAnchor::Tendermint {
            chain_id: "cosmoshub-4".into(),
            trusted_height: trusted.height,
            trusted_header_hash: trusted.hash(),
            trusting_period_secs: 14 * 24 * 3600,
        };
        let route = route(anchor.clone());
        let mut s = MemState {
            elapsed_ms: (target.time_seconds as i64) * 1000 + 30_000 - NOW_MS,
            ..Default::default()
        };
        let lc = TendermintLightClient;
        lc.advance(
            &mut s,
            &route,
            &anchor,
            &cometbft_rpc::bootstrap(&f["trusted"]).unwrap(),
        )
        .unwrap();

        let validators =
            cometbft_rpc::validators(f["target_validators"].as_array().unwrap()).unwrap();
        let trusted_next =
            cometbft_rpc::validators(f["trusted_next_validators"].as_array().unwrap()).unwrap();
        assert_eq!(
            validators_hash(&validators).to_vec(),
            target.validators_hash
        );
        let update =
            cometbft_rpc::update(trusted.height, &f["target"], &validators, &trusted_next).unwrap();

        // A forged signature, or the trusted set swapped for the target's
        // with half its power removed, is refused.
        let mut forged_commit = f["target"].clone();
        let sigs = forged_commit["signed_header"]["commit"]["signatures"]
            .as_array_mut()
            .unwrap();
        for sig in sigs.iter_mut().filter(|s| s["block_id_flag"] == 2) {
            sig["signature"] = Value::String({
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([7u8; 64])
            });
        }
        let forged =
            cometbft_rpc::update(trusted.height, &forged_commit, &validators, &trusted_next)
                .unwrap();
        assert!(
            lc.advance(&mut s.clone(), &route, &anchor, &forged)
                .is_err()
        );

        let head = lc.advance(&mut s, &route, &anchor, &update).unwrap();
        assert_eq!(head.finalized, target.height);

        // The packet commitment, under its path in the IBC store, under the
        // store's root in the multistore, up to the new header's app hash.
        let key = f["key"].as_str().unwrap().as_bytes();
        let proof = cometbft_rpc::entry_proof(&f["abci_query"], key, target.height).unwrap();
        let StoreEntryProof::Exists(iavl) = &proof.entry else {
            panic!("an existence proof")
        };
        let store = &proof.store;
        assert_eq!(iavl.key, key);
        let value = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(f["abci_query"]["response"]["value"].as_str().unwrap())
                .unwrap()
        };
        assert_eq!(iavl.value, value);
        let store_root = iavl.root(Spec::Iavl).unwrap();
        assert_eq!(
            (store.key.as_slice(), store.value.as_slice()),
            (&b"ibc"[..], &store_root[..])
        );
        assert_eq!(
            store.root(Spec::Tendermint).unwrap().to_vec(),
            target.app_hash
        );
        let mut tampered = iavl.clone();
        tampered.value[0] ^= 1;
        assert_ne!(tampered.root(Spec::Iavl).unwrap(), store_root);

        // The same proof, checked end to end against the light client: the
        // entry holds exactly this value, so another value or a claim that
        // it is absent is refused.
        let encoded = proof.encode();
        assert_eq!(EntryProof::decode(&encoded).unwrap(), proof);
        verify_store_entry(&s, &route, key, Some(&value), &encoded).unwrap();
        let mut other = value.clone();
        other[0] ^= 1;
        assert!(verify_store_entry(&s, &route, key, Some(&other), &encoded).is_err());
        assert!(verify_store_entry(&s, &route, key, None, &encoded).is_err());
        assert!(
            verify_store_entry(
                &s,
                &route,
                b"commitments/ports/transfer/channels/channel-0/sequences/1",
                Some(&value),
                &encoded
            )
            .is_err()
        );
    }
}
