//! Ethereum light client: the beacon chain's sync committee.
//!
//! Every 8192 slots (a sync-committee period) 512 validators form the sync
//! committee, and each block carries their BLS aggregate signature over the
//! previous block's header. A header signed by a supermajority of the
//! committee carries, in its state, the finalized checkpoint and the next
//! period's committee, each provable with a Merkle branch. This light client
//! therefore needs nothing but signatures and hashes:
//!
//! - **Bootstrap.** The route's anchor names a finalized beacon block root.
//!   The bootstrap update carries that block's header and the current sync
//!   committee with its branch into the header's state root.
//! - **Handover.** An update signed by a supermajority of the committee it
//!   knows proves the next committee (branch into the signed header's state)
//!   and a finalized header (finality branch). Once a finalized header of the
//!   next period is proven, the next committee becomes the current one.
//! - **Message.** A delivery's proof carries a header signed by a
//!   supermajority of a known committee, the finalized header it commits to,
//!   optionally an older block linked to the finalized block by the chain of
//!   headers between them (each names its parent's root), that block's
//!   `receipts_root` (branch into its body), and
//!   a Merkle-Patricia proof of a successful receipt whose log is the ramp's
//!   message event, in the version the route's lane declares, with exactly
//!   the delivered body as its data.
//!
//! The Merkle layouts are those of the current beacon fork (Electra and
//! Fulu). A fork that moves these fields needs this module updated before
//! governance moves the route's anchor to it.
//!
//! Encodings are fixed-layout (all integers little-endian, as SSZ):
//!
//! ```text
//! header           slot u64 | proposer u64 | parent 32 | state 32 | body 32   (112 bytes)
//! committee        512 pubkeys * 48 | aggregate pubkey 48
//! sync_aggregate   participation bits 64 | signature 96
//!
//! bootstrap        0x00 | header | committee | branch 6*32
//! handover         0x01 | attested header | next committee | branch 6*32
//!                       | finalized header | finality branch 7*32
//!                       | sync_aggregate | signature_slot u64
//! message proof    attested header | finalized header | finality branch 7*32
//!                       | sync_aggregate | signature_slot u64
//!                       | 0x00 (the message's block is the finalized block)
//!                         or 0x01 | count u32 | headers 112*count (the
//!                         message's block first, each next one its child,
//!                         the last the finalized block's parent)
//!                       | receipts_root 32 | receipts branch 9*32
//!                       | tx_index u32 | log_index u32
//!                       | node count u8 | (length u32 | node) * count
//! ```

use blst::BLST_ERROR;
use blst::min_pk::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use super::canonical::{Reader, Writer};
use super::evm::{evm_address, lane_version, onramp_log_matches};
use super::light_client::{LightClientHead, LightClientVerifier};
use super::receipt_proof::verify_log;
use super::state::RouteState;
use super::{BridgeRoute, LightClientAnchor, LightClientKind};
use crate::error::{BridgeError, Result};

/// Validators in a sync committee.
pub const SYNC_COMMITTEE_SIZE: usize = 512;
/// Slots in a sync-committee period.
pub const SLOTS_PER_PERIOD: u64 = 8192;
/// Most headers an ancestor chain from a message's block to the finalized
/// block may hold.
pub const MAX_ANCESTORS: u64 = 8192;

const PUBKEY_LEN: usize = 48;
const COMMITTEE_LEN: usize = (SYNC_COMMITTEE_SIZE + 1) * PUBKEY_LEN;
const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Generalized index of `current_sync_committee` in the beacon state.
pub const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 86;
/// Generalized index of `next_sync_committee` in the beacon state.
pub const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 87;
/// Generalized index of `finalized_checkpoint.root` in the beacon state.
pub const FINALIZED_ROOT_GINDEX: u64 = 169;
/// Generalized index of `execution_payload.receipts_root` in the block body.
pub const RECEIPTS_ROOT_GINDEX: u64 = 803;

fn refuse(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("ethereum light client: {}", what.into()))
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn depth(gindex: u64) -> usize {
    (63 - gindex.leading_zeros()) as usize
}

/// Whether `branch` proves `leaf` at generalized index `gindex` under `root`.
pub fn is_valid_branch(leaf: &[u8; 32], branch: &[[u8; 32]], gindex: u64, root: &[u8; 32]) -> bool {
    if branch.len() != depth(gindex) {
        return false;
    }
    let mut node = *leaf;
    let mut index = gindex;
    for sibling in branch {
        node = if index & 1 == 1 {
            sha256(&[sibling, &node])
        } else {
            sha256(&[&node, sibling])
        };
        index >>= 1;
    }
    node == *root
}

/// A beacon block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconHeader {
    /// Slot.
    pub slot: u64,
    /// Proposer index.
    pub proposer_index: u64,
    /// Parent block root.
    pub parent_root: [u8; 32],
    /// Post-state root.
    pub state_root: [u8; 32],
    /// Body root.
    pub body_root: [u8; 32],
}

fn uint_leaf(v: u64) -> [u8; 32] {
    let mut leaf = [0u8; 32];
    leaf[..8].copy_from_slice(&v.to_le_bytes());
    leaf
}

fn merkleize(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
    debug_assert!(layer.len().is_power_of_two());
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|p| sha256(&[&p[0], &p[1]])).collect();
    }
    layer[0]
}

impl BeaconHeader {
    /// SSZ `hash_tree_root`.
    pub fn root(&self) -> [u8; 32] {
        merkleize(vec![
            uint_leaf(self.slot),
            uint_leaf(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
        ])
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            slot: r.u64_le()?,
            proposer_index: r.u64_le()?,
            parent_root: r.array()?,
            state_root: r.array()?,
            body_root: r.array()?,
        })
    }

    /// Fixed-layout encoding.
    pub fn write(&self, w: &mut Writer) {
        w.u64_le(self.slot)
            .u64_le(self.proposer_index)
            .raw(&self.parent_root)
            .raw(&self.state_root)
            .raw(&self.body_root);
    }

    fn period(&self) -> u64 {
        self.slot / SLOTS_PER_PERIOD
    }
}

fn pubkey_root(pk: &[u8]) -> [u8; 32] {
    let mut second = [0u8; 32];
    second[..PUBKEY_LEN - 32].copy_from_slice(&pk[32..PUBKEY_LEN]);
    sha256(&[&pk[..32], &second])
}

/// SSZ `hash_tree_root` of a sync committee in its fixed-layout encoding.
pub fn committee_root(committee: &[u8]) -> [u8; 32] {
    debug_assert_eq!(committee.len(), COMMITTEE_LEN);
    let keys = merkleize(
        committee[..SYNC_COMMITTEE_SIZE * PUBKEY_LEN]
            .chunks(PUBKEY_LEN)
            .map(pubkey_root)
            .collect(),
    );
    sha256(&[
        &keys,
        &pubkey_root(&committee[SYNC_COMMITTEE_SIZE * PUBKEY_LEN..]),
    ])
}

/// Read a committee, checking every member key is a valid BLS public key.
/// Returns the member keys (without the aggregate) and the full encoding's
/// root.
fn read_committee(r: &mut Reader<'_>) -> Result<(Vec<u8>, [u8; 32])> {
    let raw = r.take(COMMITTEE_LEN)?;
    let keys = &raw[..SYNC_COMMITTEE_SIZE * PUBKEY_LEN];
    for pk in keys.chunks(PUBKEY_LEN) {
        PublicKey::key_validate(pk)
            .map_err(|_| refuse("a committee key is not a valid BLS key"))?;
    }
    Ok((keys.to_vec(), committee_root(raw)))
}

fn read_branch<const N: usize>(r: &mut Reader<'_>) -> Result<[[u8; 32]; N]> {
    let mut out = [[0u8; 32]; N];
    for node in out.iter_mut() {
        *node = r.array()?;
    }
    Ok(out)
}

/// The signing domain for sync-committee signatures under `anchor`.
fn domain(fork_version: &[u8; 4], genesis_validators_root: &[u8; 32]) -> [u8; 32] {
    let mut version = [0u8; 32];
    version[..4].copy_from_slice(fork_version);
    let fork_data_root = sha256(&[&version, genesis_validators_root]);
    let mut d = [0u8; 32];
    d[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    d[4..].copy_from_slice(&fork_data_root[..28]);
    d
}

/// A sync aggregate: which members signed, and their aggregate signature.
struct SyncAggregate {
    bits: [u8; SYNC_COMMITTEE_SIZE / 8],
    signature: [u8; 96],
}

impl SyncAggregate {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            bits: r.array()?,
            signature: r.array()?,
        })
    }

    /// Require a supermajority of `committee` to have signed `header` under
    /// `domain`.
    fn verify(&self, committee: &[u8], header: &BeaconHeader, domain: &[u8; 32]) -> Result<()> {
        let mut keys = Vec::new();
        for (i, pk) in committee.chunks(PUBKEY_LEN).enumerate() {
            if self.bits[i / 8] >> (i % 8) & 1 == 1 {
                keys.push(
                    PublicKey::from_bytes(pk)
                        .map_err(|_| refuse("a stored committee key does not decode"))?,
                );
            }
        }
        if keys.len() * 3 < SYNC_COMMITTEE_SIZE * 2 {
            return Err(refuse(format!(
                "{} of {SYNC_COMMITTEE_SIZE} committee members signed; a two-thirds supermajority is required",
                keys.len()
            )));
        }
        let signing_root = sha256(&[&header.root(), domain]);
        let signature = Signature::from_bytes(&self.signature)
            .map_err(|_| refuse("the aggregate signature does not decode"))?;
        let refs: Vec<&PublicKey> = keys.iter().collect();
        match signature.fast_aggregate_verify(true, &signing_root, BLS_DST, &refs) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(refuse("the sync committee's signature does not verify")),
        }
    }
}

/// The light client's state for one route and anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Store {
    period: u64,
    finalized_slot: u64,
    current: Vec<u8>,
    next: Option<Vec<u8>>,
}

impl Store {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_le(self.period)
            .u64_le(self.finalized_slot)
            .raw(&self.current);
        match &self.next {
            Some(next) => w.u8(1).raw(next),
            None => w.u8(0),
        };
        w.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let period = r.u64_le()?;
        let finalized_slot = r.u64_le()?;
        let current = r.take(SYNC_COMMITTEE_SIZE * PUBKEY_LEN)?.to_vec();
        let next = match r.u8()? {
            0 => None,
            1 => Some(r.take(SYNC_COMMITTEE_SIZE * PUBKEY_LEN)?.to_vec()),
            _ => return Err(refuse("stored state is malformed")),
        };
        r.finish()?;
        Ok(Self {
            period,
            finalized_slot,
            current,
            next,
        })
    }

    /// The committee that signs in `period`.
    fn committee(&self, period: u64) -> Result<&[u8]> {
        if period == self.period {
            Ok(&self.current)
        } else if period == self.period + 1 {
            self.next
                .as_deref()
                .ok_or_else(|| refuse(format!("the committee of period {period} is not known yet")))
        } else {
            Err(refuse(format!(
                "a signature from period {period}; the light client follows period {}",
                self.period
            )))
        }
    }

    fn head(&self) -> LightClientHead {
        LightClientHead {
            kind: "ethereum_sync_committee",
            finalized: self.finalized_slot,
            period: self.period,
            next_known: self.next.is_some(),
        }
    }
}

/// A finalized header proven by a supermajority of a known committee.
struct Finalized {
    attested: BeaconHeader,
    finalized: BeaconHeader,
}

/// Read and check the attested header, the finalized header with its
/// finality branch, and the committee's signature over the attested header.
fn read_finalized(
    r: &mut Reader<'_>,
    attested: BeaconHeader,
    store: &Store,
    domain: &[u8; 32],
) -> Result<Finalized> {
    let finalized = BeaconHeader::read(r)?;
    let finality_branch: [[u8; 32]; 7] = read_branch(r)?;
    let aggregate = SyncAggregate::read(r)?;
    let signature_slot = r.u64_le()?;
    if !(signature_slot > attested.slot && attested.slot >= finalized.slot) {
        return Err(refuse(
            "slots must satisfy signature > attested >= finalized",
        ));
    }
    if !is_valid_branch(
        &finalized.root(),
        &finality_branch,
        FINALIZED_ROOT_GINDEX,
        &attested.state_root,
    ) {
        return Err(refuse(
            "the finalized header is not the attested state's finalized checkpoint",
        ));
    }
    let committee = store.committee(signature_slot / SLOTS_PER_PERIOD)?;
    aggregate.verify(committee, &attested, domain)?;
    Ok(Finalized {
        attested,
        finalized,
    })
}

/// The Ethereum sync-committee light client.
#[derive(Debug, Default)]
pub struct EthereumLightClient;

impl EthereumLightClient {
    /// A light client with no state of its own: everything it follows lives
    /// in route state.
    pub fn new() -> Self {
        Self
    }
}

fn store_key(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    anchor.store_key(route)
}

fn anchor_parts(anchor: &LightClientAnchor) -> Result<([u8; 32], [u8; 4], [u8; 32])> {
    match anchor {
        LightClientAnchor::EthereumSyncCommittee {
            genesis_validators_root,
            fork_version,
            trusted_block_root,
        } => Ok((*genesis_validators_root, *fork_version, *trusted_block_root)),
        _ => Err(refuse("the route's anchor is not a sync-committee anchor")),
    }
}

fn load(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
) -> Result<Option<Store>> {
    state
        .get(&store_key(route, anchor))
        .map(|b| Store::decode(&b))
        .transpose()
}

/// The log a message proof proves final: every signature, branch and trie
/// node checked against the light-client state `anchor` started, and the
/// transaction it belongs to successful. What the log must say is the
/// caller's to check.
pub fn proven_log(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    proof: &[u8],
) -> Result<super::receipt_proof::ReceiptLog> {
    let store = load(state, route, anchor)?
        .ok_or_else(|| refuse("not bootstrapped from the route's anchor"))?;
    let (gvr, fork_version, _) = anchor_parts(anchor)?;
    let domain = domain(&fork_version, &gvr);

    let mut r = Reader::new(proof);
    let attested = BeaconHeader::read(&mut r)?;
    let f = read_finalized(&mut r, attested, &store, &domain)?;

    let block = match r.u8()? {
        0 => f.finalized,
        1 => {
            let count = r.u32_le()? as usize;
            if count == 0 || count as u64 > MAX_ANCESTORS {
                return Err(refuse("an ancestor chain holds 1 to 8192 headers"));
            }
            let chain = (0..count)
                .map(|_| BeaconHeader::read(&mut r))
                .collect::<Result<Vec<_>>>()?;
            for pair in chain.windows(2) {
                if pair[1].parent_root != pair[0].root() || pair[1].slot <= pair[0].slot {
                    return Err(refuse("the ancestor chain is not linked parent to child"));
                }
            }
            let last = chain.last().expect("non-empty");
            if f.finalized.parent_root != last.root() || last.slot >= f.finalized.slot {
                return Err(refuse(
                    "the block is not an ancestor of the finalized block",
                ));
            }
            chain[0]
        }
        _ => return Err(refuse("unknown block reference")),
    };

    let receipts_root: [u8; 32] = r.array()?;
    let receipts_branch: [[u8; 32]; 9] = read_branch(&mut r)?;
    if !is_valid_branch(
        &receipts_root,
        &receipts_branch,
        RECEIPTS_ROOT_GINDEX,
        &block.body_root,
    ) {
        return Err(refuse("the receipts root is not the block's"));
    }
    let tx_index = r.u32_le()?;
    let log_index = r.u32_le()?;
    let count = r.u8()? as usize;
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.u32_le()? as usize;
        nodes.push(r.take(len)?.to_vec());
    }
    r.finish()?;

    verify_log(&receipts_root, tx_index, log_index, &nodes)
}

impl LightClientVerifier for EthereumLightClient {
    fn kind(&self) -> LightClientKind {
        LightClientKind::EthereumSyncCommittee
    }

    fn verify(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        body_hash: &[u8; 32],
        proof: &[u8],
    ) -> Result<()> {
        let log = proven_log(state, route, anchor, proof)?;
        if log.address != evm_address(&route.ramp)? {
            return Err(refuse("the log was not emitted by the route's ramp"));
        }
        if !onramp_log_matches(lane_version(route)?, &log.topics, &log.data, route) {
            return Err(refuse("the log is not the ramp's message to this chain"));
        }
        let data_hash: [u8; 32] = Keccak256::digest(&log.data).into();
        if data_hash != *body_hash {
            return Err(refuse("the log's message is not the delivered body"));
        }
        Ok(())
    }

    fn proven_lock_record(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        lock: &[u8; 32],
        proof: &[u8],
    ) -> Result<super::receipt_proof::LockRecord> {
        let log = proven_log(state, route, anchor, proof)?;
        if log.address != evm_address(lock)? {
            return Err(refuse(
                "the log was not emitted by the route's settlement lock",
            ));
        }
        super::receipt_proof::evm_lock_record(&log)
    }

    fn advance(
        &self,
        state: &mut dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        update: &[u8],
    ) -> Result<LightClientHead> {
        let (gvr, fork_version, trusted_root) = anchor_parts(anchor)?;
        let existing = load(state, route, anchor)?;
        let mut r = Reader::new(update);
        let store = match r.u8()? {
            0 => {
                if existing.is_some() {
                    return Err(refuse("already bootstrapped from this anchor"));
                }
                let header = BeaconHeader::read(&mut r)?;
                let (current, root) = read_committee(&mut r)?;
                let branch: [[u8; 32]; 6] = read_branch(&mut r)?;
                r.finish()?;
                if header.root() != trusted_root {
                    return Err(refuse("the bootstrap header is not the anchor's block"));
                }
                if !is_valid_branch(
                    &root,
                    &branch,
                    CURRENT_SYNC_COMMITTEE_GINDEX,
                    &header.state_root,
                ) {
                    return Err(refuse(
                        "the committee is not the anchor block's current committee",
                    ));
                }
                Store {
                    period: header.period(),
                    finalized_slot: header.slot,
                    current,
                    next: None,
                }
            }
            1 => {
                let mut store =
                    existing.ok_or_else(|| refuse("not bootstrapped from the route's anchor"))?;
                let attested = BeaconHeader::read(&mut r)?;
                let (next, next_root) = read_committee(&mut r)?;
                let next_branch: [[u8; 32]; 6] = read_branch(&mut r)?;
                let f = read_finalized(&mut r, attested, &store, &domain(&fork_version, &gvr))?;
                r.finish()?;
                if !is_valid_branch(
                    &next_root,
                    &next_branch,
                    NEXT_SYNC_COMMITTEE_GINDEX,
                    &f.attested.state_root,
                ) {
                    return Err(refuse("the next committee is not the attested state's"));
                }
                let finalized_period = f.finalized.period();
                let attested_period = f.attested.period();
                if finalized_period == store.period + 1 {
                    // The next committee takes over once a header of its
                    // period is final; the update's own next committee is the
                    // one after it.
                    let Some(known) = store.next.take() else {
                        return Err(refuse(
                            "the next committee must be learned before its period",
                        ));
                    };
                    store.current = known;
                    store.period += 1;
                    store.next = (attested_period == store.period).then_some(next);
                } else if finalized_period == store.period && attested_period == store.period {
                    match &store.next {
                        Some(known) if *known != next => {
                            return Err(refuse("a different next committee is already known"));
                        }
                        Some(_) if f.finalized.slot <= store.finalized_slot => {
                            return Err(refuse("the update moves the light client nowhere"));
                        }
                        _ => store.next = Some(next),
                    }
                } else {
                    return Err(refuse(format!(
                        "an update finalizing period {finalized_period}; the light client follows period {}",
                        store.period
                    )));
                }
                store.finalized_slot = store.finalized_slot.max(f.finalized.slot);
                store
            }
            _ => return Err(refuse("unknown update kind")),
        };
        state.apply(vec![(store_key(route, anchor), store.encode())])?;
        Ok(store.head())
    }

    fn head(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
    ) -> Option<LightClientHead> {
        load(state, route, anchor).ok().flatten().map(|s| s.head())
    }
}

/// Light-client updates as a beacon node serves them (the standard Beacon
/// API: `/eth/v1/beacon/light_client/bootstrap/{block_root}` and
/// `/eth/v1/beacon/light_client/updates`), turned into the encodings this
/// light client takes. A relayer needs nothing else: every value is checked
/// on its signatures and branches when the update is applied.
pub mod beacon_api {
    use serde_json::Value;

    use super::super::canonical::Writer;
    use super::{BeaconHeader, COMMITTEE_LEN, PUBKEY_LEN, SYNC_COMMITTEE_SIZE};
    use crate::error::{BridgeError, Result};

    fn bad(what: impl Into<String>) -> BridgeError {
        BridgeError::InvalidParameter(format!("beacon light-client data: {}", what.into()))
    }

    fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
        v.get(key).ok_or_else(|| bad(format!("missing '{key}'")))
    }

    fn hex_bytes(v: &Value, len: usize, what: &str) -> Result<Vec<u8>> {
        let s = v
            .as_str()
            .ok_or_else(|| bad(format!("{what} is not a string")))?;
        let b = hex::decode(s.trim_start_matches("0x"))
            .map_err(|_| bad(format!("{what} is not hex")))?;
        if b.len() != len {
            return Err(bad(format!("{what} is {} bytes, expected {len}", b.len())));
        }
        Ok(b)
    }

    fn hex32(v: &Value, what: &str) -> Result<[u8; 32]> {
        Ok(hex_bytes(v, 32, what)?.try_into().expect("32 bytes"))
    }

    fn number(v: &Value, what: &str) -> Result<u64> {
        v.as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| v.as_u64())
            .ok_or_else(|| bad(format!("{what} is not a number")))
    }

    /// A light-client header's beacon header (`{"beacon": {...}}`).
    fn header(v: &Value) -> Result<BeaconHeader> {
        let b = field(v, "beacon")?;
        Ok(BeaconHeader {
            slot: number(field(b, "slot")?, "slot")?,
            proposer_index: number(field(b, "proposer_index")?, "proposer_index")?,
            parent_root: hex32(field(b, "parent_root")?, "parent_root")?,
            state_root: hex32(field(b, "state_root")?, "state_root")?,
            body_root: hex32(field(b, "body_root")?, "body_root")?,
        })
    }

    fn committee(w: &mut Writer, v: &Value) -> Result<()> {
        let keys = field(v, "pubkeys")?
            .as_array()
            .ok_or_else(|| bad("pubkeys is not a list"))?;
        if keys.len() != SYNC_COMMITTEE_SIZE {
            return Err(bad(format!(
                "{} committee keys, expected {SYNC_COMMITTEE_SIZE}",
                keys.len()
            )));
        }
        let mut out = Vec::with_capacity(COMMITTEE_LEN);
        for k in keys {
            out.extend(hex_bytes(k, PUBKEY_LEN, "a committee key")?);
        }
        out.extend(hex_bytes(
            field(v, "aggregate_pubkey")?,
            PUBKEY_LEN,
            "aggregate_pubkey",
        )?);
        w.raw(&out);
        Ok(())
    }

    fn branch(w: &mut Writer, v: &Value, len: usize, what: &str) -> Result<()> {
        let nodes = v
            .as_array()
            .ok_or_else(|| bad(format!("{what} is not a list")))?;
        if nodes.len() != len {
            return Err(bad(format!(
                "{what} has {} nodes, expected {len}",
                nodes.len()
            )));
        }
        for n in nodes {
            w.raw(&hex32(n, what)?);
        }
        Ok(())
    }

    /// The `data` of a response, or the value itself.
    fn data(v: &Value) -> &Value {
        v.get("data").unwrap_or(v)
    }

    /// The bootstrap update from a `LightClientBootstrap`.
    pub fn bootstrap(response: &Value) -> Result<Vec<u8>> {
        let d = data(response);
        let mut w = Writer::new();
        w.u8(0);
        header(field(d, "header")?)?.write(&mut w);
        committee(&mut w, field(d, "current_sync_committee")?)?;
        branch(
            &mut w,
            field(d, "current_sync_committee_branch")?,
            6,
            "current_sync_committee_branch",
        )?;
        Ok(w.into_bytes())
    }

    /// The handover update from a `LightClientUpdate`.
    pub fn handover(response: &Value) -> Result<Vec<u8>> {
        let d = data(response);
        let mut w = Writer::new();
        w.u8(1);
        header(field(d, "attested_header")?)?.write(&mut w);
        committee(&mut w, field(d, "next_sync_committee")?)?;
        branch(
            &mut w,
            field(d, "next_sync_committee_branch")?,
            6,
            "next_sync_committee_branch",
        )?;
        header(field(d, "finalized_header")?)?.write(&mut w);
        branch(&mut w, field(d, "finality_branch")?, 7, "finality_branch")?;
        let agg = field(d, "sync_aggregate")?;
        w.raw(&hex_bytes(
            field(agg, "sync_committee_bits")?,
            SYNC_COMMITTEE_SIZE / 8,
            "sync_committee_bits",
        )?);
        w.raw(&hex_bytes(
            field(agg, "sync_committee_signature")?,
            96,
            "sync_committee_signature",
        )?);
        w.u64_le(number(field(d, "signature_slot")?, "signature_slot")?);
        Ok(w.into_bytes())
    }

    /// A beacon header as `/eth/v1/beacon/headers/{block_id}` serves it.
    pub fn block_header(response: &Value) -> Result<BeaconHeader> {
        let m = field(field(data(response), "header")?, "message")?;
        header(&serde_json::json!({ "beacon": m }))
    }

    /// The proof that the `log_index`-th log of the receipt of transaction
    /// `tx_index` in `block` is final, in the encoding
    /// [`super::EthereumLightClient`] verifies.
    ///
    /// - `finality`: a `LightClientFinalityUpdate`
    ///   (`/eth/v1/beacon/light_client/finality_update`) whose finalized
    ///   block is `block` or a descendant of it.
    /// - `block`: the message's block (`/eth/v2/beacon/blocks/{block_id}`).
    /// - `descendants`: the headers (`/eth/v1/beacon/headers/{block_id}`) of
    ///   every block after `block` up to the finalized block's parent, in
    ///   slot order; empty when `block` is the finalized block or its parent.
    /// - `receipts`: every receipt of the block's execution payload
    ///   (`eth_getBlockReceipts`), in order.
    ///
    /// Every link is checked here before the proof is returned, so a relayer
    /// learns of a wrong input at once rather than from a refused delivery.
    pub fn message_proof(
        finality: &Value,
        block: &Value,
        descendants: &[Value],
        receipts: &[Value],
        tx_index: u32,
        log_index: u32,
    ) -> Result<Vec<u8>> {
        use super::super::beacon_body::receipts_branch;
        use super::super::receipt_proof::{receipt_from_json, receipt_key, trie, verify_log};

        let d = data(finality);
        let attested = header(field(d, "attested_header")?)?;
        let finalized = header(field(d, "finalized_header")?)?;

        let message = field(data(block), "message")?;
        let rb = receipts_branch(field(message, "body")?)?;
        let own = BeaconHeader {
            slot: number(field(message, "slot")?, "slot")?,
            proposer_index: number(field(message, "proposer_index")?, "proposer_index")?,
            parent_root: hex32(field(message, "parent_root")?, "parent_root")?,
            state_root: hex32(field(message, "state_root")?, "state_root")?,
            body_root: rb.body_root,
        };
        let mut chain = Vec::new();
        if own.root() != finalized.root() {
            chain.push(own);
            for h in descendants {
                chain.push(block_header(h)?);
            }
            for pair in chain.windows(2) {
                if pair[1].parent_root != pair[0].root() {
                    return Err(bad(format!(
                        "block {} is not the parent of block {}",
                        pair[0].slot, pair[1].slot
                    )));
                }
            }
            if chain.last().map(|h| h.root()) != Some(finalized.parent_root) {
                return Err(bad(
                    "the chain does not end at the finalized block's parent",
                ));
            }
            if chain.len() as u64 > super::MAX_ANCESTORS {
                return Err(bad("the block is too far behind the finalized block"));
            }
        }

        let encoded = receipts
            .iter()
            .map(receipt_from_json)
            .collect::<Result<Vec<_>>>()?;
        let entries: Vec<(Vec<u8>, Vec<u8>)> = encoded
            .into_iter()
            .enumerate()
            .map(|(i, r)| (receipt_key(i as u32), r))
            .collect();
        if tx_index as usize >= entries.len() {
            return Err(bad("the block has no receipt at that index"));
        }
        let (root, nodes) = trie::build(&entries, &receipt_key(tx_index));
        if root != rb.receipts_root {
            return Err(bad("the receipts do not hash to the block's receipts_root"));
        }
        verify_log(&root, tx_index, log_index, &nodes)?;
        if nodes.len() > u8::MAX as usize {
            return Err(bad("the receipt proof is too deep"));
        }

        let mut w = Writer::new();
        attested.write(&mut w);
        finalized.write(&mut w);
        branch(&mut w, field(d, "finality_branch")?, 7, "finality_branch")?;
        let agg = field(d, "sync_aggregate")?;
        w.raw(&hex_bytes(
            field(agg, "sync_committee_bits")?,
            SYNC_COMMITTEE_SIZE / 8,
            "sync_committee_bits",
        )?);
        w.raw(&hex_bytes(
            field(agg, "sync_committee_signature")?,
            96,
            "sync_committee_signature",
        )?);
        w.u64_le(number(field(d, "signature_slot")?, "signature_slot")?);
        if chain.is_empty() {
            w.u8(0);
        } else {
            w.u8(1).u32_le(chain.len() as u32);
            for h in &chain {
                h.write(&mut w);
            }
        }
        w.raw(&rb.receipts_root);
        for n in &rb.branch {
            w.raw(n);
        }
        w.u32_le(tx_index).u32_le(log_index).u8(nodes.len() as u8);
        for n in &nodes {
            w.u32_le(n.len() as u32).raw(n);
        }
        Ok(w.into_bytes())
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! A synthetic beacon chain signed by a real BLS sync committee.
    use std::collections::BTreeMap;

    use blst::min_pk::{AggregateSignature, SecretKey};

    use super::*;

    /// A sparse SSZ tree: the leaves set, every other node zero.
    pub struct Tree(pub BTreeMap<u64, [u8; 32]>);

    impl Tree {
        pub fn new(leaves: &[(u64, [u8; 32])]) -> Self {
            Self(leaves.iter().copied().collect())
        }

        fn has_under(&self, g: u64) -> bool {
            // A leaf at generalized index l lies under g when shifting l right
            // by the depth difference gives g.
            self.0.keys().any(|&l| {
                let (dl, dg) = (depth(l), depth(g));
                dl >= dg && l >> (dl - dg) == g
            })
        }

        pub fn node(&self, g: u64) -> [u8; 32] {
            if let Some(leaf) = self.0.get(&g) {
                return *leaf;
            }
            if !self.has_under(g) {
                return [0u8; 32];
            }
            sha256(&[&self.node(2 * g), &self.node(2 * g + 1)])
        }

        pub fn root(&self) -> [u8; 32] {
            self.node(1)
        }

        pub fn branch(&self, mut g: u64) -> Vec<[u8; 32]> {
            let mut out = Vec::new();
            while g > 1 {
                out.push(self.node(g ^ 1));
                g >>= 1;
            }
            out
        }
    }

    pub struct Committee {
        pub keys: Vec<SecretKey>,
        pub encoded: Vec<u8>,
    }

    impl Committee {
        pub fn new(seed: u8) -> Self {
            let keys: Vec<SecretKey> = (0..SYNC_COMMITTEE_SIZE)
                .map(|i| {
                    let mut ikm = [seed; 32];
                    ikm[..2].copy_from_slice(&(i as u16).to_le_bytes());
                    SecretKey::key_gen(&ikm, &[]).unwrap()
                })
                .collect();
            let mut encoded = Vec::new();
            for k in &keys {
                encoded.extend_from_slice(&k.sk_to_pk().compress());
            }
            // The aggregate key only enters the committee's root here.
            encoded.extend_from_slice(&keys[0].sk_to_pk().compress());
            Self { keys, encoded }
        }

        pub fn root(&self) -> [u8; 32] {
            committee_root(&self.encoded)
        }

        /// The sync aggregate of the first `signers` members over `header`.
        pub fn sign(&self, header: &BeaconHeader, domain: &[u8; 32], signers: usize) -> Vec<u8> {
            let msg = sha256(&[&header.root(), domain]);
            let sigs: Vec<_> = self.keys[..signers]
                .iter()
                .map(|k| k.sign(&msg, BLS_DST, &[]))
                .collect();
            let refs: Vec<_> = sigs.iter().collect();
            let agg = AggregateSignature::aggregate(&refs, true)
                .unwrap()
                .to_signature();
            let mut bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
            for i in 0..signers {
                bits[i / 8] |= 1 << (i % 8);
            }
            let mut out = bits.to_vec();
            out.extend_from_slice(&agg.compress());
            out
        }
    }

    pub const GVR: [u8; 32] = [0x4b; 32];
    pub const FORK: [u8; 4] = [6, 0, 0, 0];

    pub fn domain() -> [u8; 32] {
        super::domain(&FORK, &GVR)
    }

    pub fn header(slot: u64, state_root: [u8; 32], body_root: [u8; 32]) -> BeaconHeader {
        BeaconHeader {
            slot,
            proposer_index: 7,
            parent_root: [slot as u8; 32],
            state_root,
            body_root,
        }
    }

    pub fn write_branch(w: &mut Writer, branch: &[[u8; 32]]) {
        for n in branch {
            w.raw(n);
        }
    }

    /// The anchor block at `slot`, whose state holds `committee` as current,
    /// and its bootstrap update.
    pub fn bootstrap(slot: u64, committee: &Committee) -> (BeaconHeader, Vec<u8>) {
        let state = Tree::new(&[(CURRENT_SYNC_COMMITTEE_GINDEX, committee.root())]);
        let h = header(slot, state.root(), [1u8; 32]);
        let mut w = Writer::new();
        w.u8(0);
        h.write(&mut w);
        w.raw(&committee.encoded);
        write_branch(&mut w, &state.branch(CURRENT_SYNC_COMMITTEE_GINDEX));
        (h, w.into_bytes())
    }

    /// A handover update: `signer` signs an attested header at `slot` whose
    /// state names `next` and finalizes a header at `slot - 64`.
    pub fn handover(slot: u64, signer: &Committee, next: &Committee, signers: usize) -> Vec<u8> {
        let finalized = header(slot - 64, [2u8; 32], [3u8; 32]);
        let state = Tree::new(&[
            (NEXT_SYNC_COMMITTEE_GINDEX, next.root()),
            (FINALIZED_ROOT_GINDEX, finalized.root()),
        ]);
        let attested = header(slot, state.root(), [4u8; 32]);
        let mut w = Writer::new();
        w.u8(1);
        attested.write(&mut w);
        w.raw(&next.encoded);
        write_branch(&mut w, &state.branch(NEXT_SYNC_COMMITTEE_GINDEX));
        finalized.write(&mut w);
        write_branch(&mut w, &state.branch(FINALIZED_ROOT_GINDEX));
        w.raw(&signer.sign(&attested, &domain(), signers));
        w.u64_le(slot + 1);
        w.into_bytes()
    }

    /// A message proof for a log in `receipts_root`'s trie, in a block that is
    /// either the finalized block (`ancestor` false) or an older block linked
    /// to it by three headers.
    #[allow(clippy::too_many_arguments)]
    pub fn message_proof(
        slot: u64,
        signer: &Committee,
        signers: usize,
        ancestor: bool,
        receipts_root: [u8; 32],
        tx_index: u32,
        log_index: u32,
        nodes: &[Vec<u8>],
    ) -> Vec<u8> {
        let body = Tree::new(&[(RECEIPTS_ROOT_GINDEX, receipts_root)]);
        let fin_slot = slot - 64;
        let (finalized, chain) = if ancestor {
            let mut chain = vec![header(fin_slot - 100, [5u8; 32], body.root())];
            for slot in [fin_slot - 60, fin_slot - 3] {
                let mut next = header(slot, [7u8; 32], [8u8; 32]);
                next.parent_root = chain.last().unwrap().root();
                chain.push(next);
            }
            let mut finalized = header(fin_slot, [6u8; 32], [6u8; 32]);
            finalized.parent_root = chain.last().unwrap().root();
            (finalized, chain)
        } else {
            (header(fin_slot, [5u8; 32], body.root()), Vec::new())
        };
        let state = Tree::new(&[(FINALIZED_ROOT_GINDEX, finalized.root())]);
        let attested = header(slot, state.root(), [4u8; 32]);
        let mut w = Writer::new();
        attested.write(&mut w);
        finalized.write(&mut w);
        write_branch(&mut w, &state.branch(FINALIZED_ROOT_GINDEX));
        w.raw(&signer.sign(&attested, &domain(), signers));
        w.u64_le(slot + 1);
        if chain.is_empty() {
            w.u8(0);
        } else {
            w.u8(1).u32_le(chain.len() as u32);
            for h in &chain {
                h.write(&mut w);
            }
        }
        w.raw(&receipts_root);
        write_branch(&mut w, &body.branch(RECEIPTS_ROOT_GINDEX));
        w.u32_le(tx_index).u32_le(log_index).u8(nodes.len() as u8);
        for n in nodes {
            w.u32_le(n.len() as u32).raw(n);
        }
        w.into_bytes()
    }
}

#[cfg(test)]
mod beacon_api_tests {
    use serde_json::{Value, json};

    use super::super::CcipLaneVersion;
    use super::fixture::{Committee, Tree, bootstrap, domain, handover, header};
    use super::*;

    fn hx(b: &[u8]) -> String {
        format!("0x{}", hex::encode(b))
    }

    fn header_json(h: &BeaconHeader) -> Value {
        json!({ "beacon": {
            "slot": h.slot.to_string(),
            "proposer_index": h.proposer_index.to_string(),
            "parent_root": hx(&h.parent_root),
            "state_root": hx(&h.state_root),
            "body_root": hx(&h.body_root),
        }})
    }

    fn committee_json(c: &Committee) -> Value {
        let keys: Vec<String> = c.encoded[..SYNC_COMMITTEE_SIZE * PUBKEY_LEN]
            .chunks(PUBKEY_LEN)
            .map(hx)
            .collect();
        json!({ "pubkeys": keys, "aggregate_pubkey": hx(&c.encoded[SYNC_COMMITTEE_SIZE * PUBKEY_LEN..]) })
    }

    fn branch_json(b: &[[u8; 32]]) -> Value {
        Value::Array(b.iter().map(|n| Value::String(hx(n))).collect())
    }

    #[test]
    fn beacon_api_updates_encode_exactly_as_the_light_client_reads_them() {
        let c = Committee::new(1);
        let (h, expected) = bootstrap(8192 * 4, &c);
        let state = Tree::new(&[(CURRENT_SYNC_COMMITTEE_GINDEX, c.root())]);
        let response = json!({ "version": "electra", "data": {
            "header": header_json(&h),
            "current_sync_committee": committee_json(&c),
            "current_sync_committee_branch": branch_json(&state.branch(CURRENT_SYNC_COMMITTEE_GINDEX)),
        }});
        assert_eq!(beacon_api::bootstrap(&response).unwrap(), expected);

        let next = Committee::new(2);
        let slot = 8192 * 4 + 100;
        let expected = handover(slot, &c, &next, 400);
        let finalized = header(slot - 64, [2u8; 32], [3u8; 32]);
        let state = Tree::new(&[
            (NEXT_SYNC_COMMITTEE_GINDEX, next.root()),
            (FINALIZED_ROOT_GINDEX, finalized.root()),
        ]);
        let attested = header(slot, state.root(), [4u8; 32]);
        let agg = c.sign(&attested, &domain(), 400);
        let update = json!({ "data": {
            "attested_header": header_json(&attested),
            "next_sync_committee": committee_json(&next),
            "next_sync_committee_branch": branch_json(&state.branch(NEXT_SYNC_COMMITTEE_GINDEX)),
            "finalized_header": header_json(&finalized),
            "finality_branch": branch_json(&state.branch(FINALIZED_ROOT_GINDEX)),
            "sync_aggregate": { "sync_committee_bits": hx(&agg[..64]), "sync_committee_signature": hx(&agg[64..]) },
            "signature_slot": (slot + 1).to_string(),
        }});
        assert_eq!(beacon_api::handover(&update).unwrap(), expected);

        // A branch one node short is refused, not padded.
        let mut short = update.clone();
        short["data"]["finality_branch"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(beacon_api::handover(&short).is_err());
    }

    /// Recorded from Ethereum mainnet through the standard Beacon API and an
    /// execution node: a finality update, the bootstrap of its finalized
    /// block, a block carrying a transaction of the CCIP on-ramp, the headers
    /// from that block to the finalized one, and the block's receipts.
    const MAINNET: &str = include_str!("../../tests/fixtures/ethereum/mainnet_message.json");

    /// The beacon chain's genesis validators root.
    const MAINNET_GVR: &str = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";

    #[test]
    fn a_recorded_mainnet_log_is_proven_final_from_the_beacon_chain() {
        use super::super::test_support::MemState;
        let f: Value = serde_json::from_str(MAINNET).unwrap();
        let root: [u8; 32] = hex::decode(
            f["finalized_root"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let anchor = LightClientAnchor::EthereumSyncCommittee {
            genesis_validators_root: hex::decode(MAINNET_GVR).unwrap().try_into().unwrap(),
            fork_version: [6, 0, 0, 0],
            trusted_block_root: root,
        };
        let mut ramp = [0u8; 32];
        ramp[12..].copy_from_slice(
            &hex::decode(f["onramp"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
        );
        let route = BridgeRoute {
            adapter: super::super::BridgeRouteAdapter::Ccip,
            family: super::super::ChainFamily::Evm,
            source_chain: "ethereum".into(),
            source_chain_id: 5_009_297_550_715_157_269,
            // The destination the recorded message travels to.
            local_selector: 8_481_857_512_324_358_265,
            peer: [1; 32],
            ramp,
            local_endpoint: [2; 32],
            remote_token: [3; 32],
            verifiers: super::super::VerifierQuorum {
                set_index: 0,
                size: 0,
                members: vec![],
                threshold: 0,
            },
            blessing: None,
            light_client: Some(anchor.clone()),
            mint_limit: super::super::MintRateLimit {
                per_mint: 1,
                per_epoch: 1,
            },
            ibc: None,
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
            outflow: super::super::LaneRateLimit {
                capacity: 2,
                rate: 1,
            },
            lane_limits: Some(super::super::CcipLane {
                version: CcipLaneVersion::V2_0,
                off_ramp: [0u8; 20],
                ccv_and_executor_hash: [0u8; 32],
                inbound: super::super::LaneRateLimit {
                    capacity: 1,
                    rate: 1,
                },
            }),
        };
        let lc = EthereumLightClient::new();
        let mut state = MemState::default();
        let head = lc
            .advance(
                &mut state,
                &route,
                &anchor,
                &beacon_api::bootstrap(&f["bootstrap"]).unwrap(),
            )
            .unwrap();
        let slot: u64 = f["finality_update"]["data"]["finalized_header"]["beacon"]["slot"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(head.finalized, slot);

        let receipts = f["receipts"].as_array().unwrap();
        let descendants = f["descendants"].as_array().unwrap();
        let tx_index = f["tx_index"].as_u64().unwrap() as u32;
        let receipt = &receipts[tx_index as usize];
        let log_index = receipt["logs"]
            .as_array()
            .unwrap()
            .iter()
            .position(|l| {
                l["address"]
                    .as_str()
                    .unwrap()
                    .eq_ignore_ascii_case(f["onramp"].as_str().unwrap())
            })
            .unwrap() as u32;
        let proof = beacon_api::message_proof(
            &f["finality_update"],
            &f["block"],
            descendants,
            receipts,
            tx_index,
            log_index,
        )
        .unwrap();

        // The light client proves the on-ramp's log final, exactly as the
        // execution node reported it.
        let log = proven_log(&state, &route, &anchor, &proof).unwrap();
        let expected = &receipt["logs"][log_index as usize];
        let h = |v: &Value| hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(log.address.to_vec(), h(&expected["address"]));
        assert_eq!(
            log.topics.iter().map(|t| t.to_vec()).collect::<Vec<_>>(),
            expected["topics"]
                .as_array()
                .unwrap()
                .iter()
                .map(h)
                .collect::<Vec<_>>()
        );
        assert_eq!(log.data, h(&expected["data"]));

        // Any altered piece of the proof is refused.
        for at in [10, 300, proof.len() / 2, proof.len() - 5] {
            let mut bad = proof.clone();
            bad[at] ^= 1;
            assert!(
                proven_log(&state, &route, &anchor, &bad).is_err(),
                "byte {at}"
            );
        }
        // A proof that skips a block of the chain to the finalized block.
        let mut short = descendants.to_vec();
        short.remove(short.len() / 2);
        assert!(
            beacon_api::message_proof(
                &f["finality_update"],
                &f["block"],
                &short,
                receipts,
                tx_index,
                log_index
            )
            .is_err()
        );
        // The receipts of another block do not hash to this block's root.
        let mut others = receipts.to_vec();
        others.swap(0, 1);
        assert!(
            beacon_api::message_proof(
                &f["finality_update"],
                &f["block"],
                descendants,
                &others,
                tx_index,
                log_index
            )
            .is_err()
        );

        // The mainnet on-ramp runs 2.0.0: its message is proven on a lane
        // that declares 2.0.0 and refused on a lane of any other version.
        let body_hash: [u8; 32] = Keccak256::digest(&log.data).into();
        lc.verify(&state, &route, &anchor, &body_hash, &proof)
            .unwrap();
        let mut r = Reader::new(&log.data);
        let message = super::super::evm::read_onramp_message(&route, &mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(message.message_id.as_slice(), &log.topics[3]);
        for version in [CcipLaneVersion::V1_6, CcipLaneVersion::V1_5] {
            let mut other = route.clone();
            other.lane_limits = Some(super::super::CcipLane {
                version,
                ..route.lane_limits.unwrap()
            });
            let err = lc
                .verify(&state, &other, &anchor, &body_hash, &proof)
                .unwrap_err();
            assert!(
                err.to_string().contains("is not the ramp's message"),
                "{err}"
            );
        }
        // Nor is it this lane's message to another chain.
        let mut elsewhere = route.clone();
        elsewhere.local_selector = 7_777;
        assert!(
            lc.verify(&state, &elsewhere, &anchor, &body_hash, &proof)
                .is_err()
        );
    }
}
