//! The node-side step of a recovery restart: applies an operator-agreed
//! recovery manifest at start-up. The procedure and its reasons are in
//! docs/RECOVERY-BELOW-QUORUM.md; the manifest and its checks are in
//! [`tenzro_consensus::recovery_manifest`].
//!
//! [`apply`] runs once per start, before consensus is seated, on every node
//! that is given `--recovery-manifest` (successor members and the nodes that
//! follow them). It refuses, leaving the node unchanged, unless:
//!
//! - the digest the operator passed (`--recovery-digest`, compared out of
//!   band with the published one) equals the digest of the manifest file;
//! - `--checkpoint-height` and `--checkpoint-hash` equal the manifest's
//!   anchor;
//! - the manifest passes [`recovery_manifest::check`] against this node's
//!   own tip, epoch and (when it holds it) anchor checkpoint;
//! - the anchor block and the state at it are present;
//! - when `--recovery-confirm` is given, the recovery root equals it.
//!
//! With `--recovery-check` it stops after these checks, prints the recovery
//! root and changes nothing, so the members can compare roots first.
//!
//! Then, in order, it installs the successor set as epoch `to_epoch` in the
//! epoch manager, replaces the validator registry with the successor set,
//! ends the halted epoch's consensus journal, keeps the successor committee,
//! and records the manifest digest and the epoch start durably. Every step
//! is idempotent, so a crash part-way is repaired by starting again. Once
//! the record exists a start with the same flags does nothing; the first
//! block after the anchor commits the epoch and registry records
//! (`state_commitment::epoch_start_records`).

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenzro_consensus::recovery_manifest::{self, LocalView, RecoveryManifest};
use tenzro_consensus::{EpochStart, STATE_ROOT_LAG};
use tenzro_storage::block_store::BlockStoreImpl;
use tenzro_storage::traits::BlockStore;
use tenzro_storage::{CF_METADATA, KvStore, RocksDbStore, StateTrie, WriteOp};
use tenzro_token::{RecoveryMember, ValidatorRegistry};
use tenzro_types::primitives::BlockHeight;

use crate::consensus_driver::ConsensusHandle;
use crate::error::{NodeError, Result};

/// Domain separation for the recovery root.
const ROOT_DOMAIN: &[u8] = b"tenzro/recovery-root/v1";
/// Metadata key prefix of the record that a manifest was applied.
const APPLIED_PREFIX: &[u8] = b"recovery/applied/";
/// Metadata key of the epoch start the recovery epoch begins from, kept
/// until consensus has launched from it.
const START_KEY: &[u8] = b"recovery/start";
/// Whole TNZO to base units: the registry holds wei, epoch sets whole TNZO.
const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

/// What the operator passed on the command line.
#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    /// The manifest file.
    pub manifest: RecoveryManifest,
    /// The digest the operator compared with the published one.
    pub digest: [u8; 32],
    /// The weak-subjectivity checkpoint of the command line, which must be
    /// the manifest's anchor.
    pub checkpoint: Option<(u64, [u8; 32])>,
    /// When given, the node starts only if the recovery root equals it.
    pub confirm_root: Option<[u8; 32]>,
    /// Run every check and print the recovery root, then exit without
    /// changing anything (`--recovery-check`).
    pub check_only: bool,
}

impl RecoveryRequest {
    /// Reads the manifest file and the hex arguments.
    pub fn load(
        manifest_path: &PathBuf,
        digest_hex: &str,
        confirm_hex: Option<&str>,
        checkpoint: Option<(u64, [u8; 32])>,
        check_only: bool,
    ) -> Result<Self> {
        let bytes = std::fs::read(manifest_path).map_err(|e| {
            NodeError::Config(format!(
                "--recovery-manifest {}: {e}",
                manifest_path.display()
            ))
        })?;
        let manifest = RecoveryManifest::from_json(&bytes).map_err(NodeError::Config)?;
        Ok(Self {
            manifest,
            digest: hash32(digest_hex, "--recovery-digest")?,
            checkpoint,
            confirm_root: confirm_hex
                .map(|h| hash32(h, "--recovery-confirm"))
                .transpose()?,
            check_only,
        })
    }
}

fn hash32(text: &str, flag: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(text.trim().trim_start_matches("0x"))
        .map_err(|e| NodeError::Config(format!("{flag}: {e}")))?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| NodeError::Config(format!("{flag}: expected 32 bytes of hex")))
}

/// The outcome of [`apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// This manifest was applied by an earlier start: nothing was done.
    Inert,
    /// The manifest was applied now.
    Applied {
        /// The epoch the successor set serves.
        epoch: u64,
        /// The recovery root every member prints.
        root: [u8; 32],
    },
}

/// The record that the recovery epoch starts from `start`, written when a
/// manifest is applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingStart {
    /// The recovery epoch.
    pub epoch: u64,
    /// Where it starts.
    pub start: EpochStart,
}

/// The epoch start a recovery put in the store, if the chain is still at its
/// anchor: the node launches consensus from it when no consensus journal
/// exists. `None` once the chain has moved past the anchor.
pub fn pending_start(storage: &RocksDbStore, tip: u64) -> Result<Option<PendingStart>> {
    let Some(bytes) = storage.get(CF_METADATA, START_KEY)? else {
        return Ok(None);
    };
    let pending: PendingStart = bincode::deserialize(&bytes)
        .map_err(|e| NodeError::Other(format!("recovery epoch start: {e}")))?;
    Ok((tip + 1 == pending.start.first_height).then_some(pending))
}

/// The root the members compare before they start: a digest of the state
/// root at the anchor, the manifest digest, and the committed record of the
/// recovery epoch. It does not depend on anything local to the node, so every
/// member with the same anchor state and the same manifest prints the same.
pub fn recovery_root(anchor_state_root: [u8; 32], manifest: &RecoveryManifest) -> Result<[u8; 32]> {
    let record = crate::state_commitment::EpochRecord {
        number: manifest.to_epoch,
        start_height: manifest.anchor_height + 1,
        validators: manifest
            .successor_validators()
            .map_err(|e| NodeError::Config(format!("recovery manifest: {e:?}")))?
            .iter()
            .map(|v| crate::state_commitment::EpochValidator {
                address: v.address,
                ml_dsa_public_key: v.public_key.ml_dsa.clone(),
                p256_public_key: v.public_key.p256.clone(),
                node_key: v.node_key,
                stake: v.stake,
            })
            .collect(),
    };
    let mut h = blake3::Hasher::new();
    h.update(ROOT_DOMAIN);
    h.update(&anchor_state_root);
    h.update(&manifest.digest());
    h.update(&bincode::serialize(&record).expect("an epoch record encodes"));
    Ok(h.finalize().into())
}

fn refuse(why: impl std::fmt::Display) -> NodeError {
    NodeError::Config(format!("recovery manifest refused: {why}"))
}

/// Applies the manifest. See the module documentation.
pub async fn apply(
    req: &RecoveryRequest,
    storage: &Arc<RocksDbStore>,
    consensus: &Arc<ConsensusHandle>,
    registry: Option<&ValidatorRegistry>,
    chain_id: u64,
) -> Result<Outcome> {
    let m = &req.manifest;
    let digest = m.digest();
    if digest != req.digest {
        return Err(refuse(format!(
            "the file's digest is 0x{} but --recovery-digest is 0x{}",
            hex::encode(digest),
            hex::encode(req.digest)
        )));
    }
    if req.checkpoint != Some((m.anchor_height, m.anchor_hash)) {
        return Err(refuse(
            "--checkpoint-height and --checkpoint-hash must be the manifest's anchor",
        ));
    }
    let mut applied_key = APPLIED_PREFIX.to_vec();
    applied_key.extend_from_slice(&digest);
    if storage.get(CF_METADATA, &applied_key)?.is_some() {
        tracing::info!(
            digest = %format!("0x{}", hex::encode(digest)),
            "Recovery manifest already applied; the flag does nothing"
        );
        return Ok(Outcome::Inert);
    }

    let blocks = BlockStoreImpl::new(storage.clone()).map_err(NodeError::Storage)?;
    let tip = blocks
        .latest_height()
        .await
        .map_err(NodeError::Storage)?
        .map_or(0, |h| h.0);
    let tip_block = blocks
        .get_block_by_height(BlockHeight::from(tip))
        .await
        .map_err(NodeError::Storage)?
        .ok_or_else(|| refuse("this node holds no block at its tip"))?;
    let epochs = consensus.epoch_manager();
    let tip_epoch = epochs
        .get_epoch_for_height(BlockHeight::from(tip))
        .map(|e| e.number)
        .unwrap_or_else(|| epochs.current_epoch().number);
    let tip_checkpoint = consensus
        .checkpoint(m.anchor_checkpoint_index)
        .filter(|c| c.last_height == tip)
        .map(|c| (c.index, c.digest()));
    let local = LocalView {
        chain_id,
        tip_height: tip,
        tip_hash: tip_block.hash().0,
        tip_epoch,
        tip_checkpoint,
    };
    recovery_manifest::check(m, &local).map_err(|e| refuse(format!("{e:?}")))?;

    let trie = StateTrie::new(storage.clone() as Arc<dyn KvStore>);
    let anchor_state_root = trie
        .root_at(m.anchor_height)
        .map_err(NodeError::Storage)?
        .ok_or_else(|| refuse("the state at the anchor is not committed on this node"))?
        .0;
    let root = recovery_root(anchor_state_root, m)?;
    if let Some(confirm) = req.confirm_root
        && confirm != root
    {
        return Err(refuse(format!(
            "the recovery root is 0x{} but --recovery-confirm is 0x{}",
            hex::encode(root),
            hex::encode(confirm)
        )));
    }

    let mut base_blocks = Vec::new();
    for h in m.anchor_height.saturating_sub(STATE_ROOT_LAG)..=m.anchor_height {
        let block = blocks
            .get_block_by_height(BlockHeight::from(h))
            .await
            .map_err(NodeError::Storage)?;
        let state_root = trie.root_at(h).map_err(NodeError::Storage)?;
        if let (Some(block), Some(state_root)) = (block, state_root) {
            base_blocks.push((h, block.hash().0, state_root.0));
        }
    }
    if base_blocks.last().map(|b| b.0) != Some(m.anchor_height) {
        return Err(refuse("the anchor block is not executed on this node"));
    }
    let kv: Arc<dyn KvStore> = storage.clone();
    let start = EpochStart {
        first_height: m.anchor_height + 1,
        first_checkpoint: m.anchor_checkpoint_index + 1,
        prev_checkpoint: m.anchor_checkpoint_digest,
        timestamp_ms: tip_block.header.timestamp.as_millis().max(0) as u64,
        base_blocks,
        leader_lookahead_rounds: crate::consensus_driver::governed_lookahead(Some(&kv)),
    };

    if req.check_only {
        println!("recovery root 0x{}", hex::encode(root));
        return Err(NodeError::RecoveryChecked(root));
    }

    // Everything above only read. From here each step is idempotent.
    let successors = m
        .successor_validators()
        .map_err(|e| refuse(format!("{e:?}")))?;
    epochs
        .install_recovery_epoch(
            m.from_epoch,
            BlockHeight::from(m.anchor_height + 1),
            successors,
        )
        .map_err(|e| NodeError::Other(format!("recovery epoch: {e}")))?;
    if let Some(registry) = registry {
        let members: Vec<RecoveryMember> = m
            .successor
            .iter()
            .map(|s| RecoveryMember {
                address: s.address,
                ml_dsa_pubkey: s.ml_dsa_public_key.clone(),
                p256_pubkey: s.p256_public_key.clone(),
                node_key: s.node_key,
                self_stake: s.stake.saturating_mul(ONE_TNZO),
            })
            .collect();
        registry
            .replace_active_set(&members, m.to_epoch)
            .map_err(|e| NodeError::Other(format!("recovery registry: {e}")))?;
    }
    consensus.begin_recovery_epoch(m.to_epoch)?;
    storage.write_batch(vec![
        WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: START_KEY.to_vec(),
            value: bincode::serialize(&PendingStart {
                epoch: m.to_epoch,
                start,
            })
            .expect("an epoch start encodes"),
        },
        WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: applied_key,
            value: root.to_vec(),
        },
    ])?;
    tracing::info!(
        epoch = m.to_epoch,
        anchor_height = m.anchor_height,
        digest = %format!("0x{}", hex::encode(digest)),
        root = %format!("0x{}", hex::encode(root)),
        "Recovery manifest applied"
    );
    println!("recovery root 0x{}", hex::encode(root));
    Ok(Outcome::Applied {
        epoch: m.to_epoch,
        root,
    })
}
