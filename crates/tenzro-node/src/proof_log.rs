//! The epoch handovers a proof of a checkpoint carries, kept on disk as each
//! epoch closes. A snapshot's proof is written from them as it is taken, so
//! the node never rebuilds the whole proof in memory.
//!
//! Once a proof of the handover chain is installed, the handovers it covers
//! are dropped: the log keeps that one proof, the members of the committee
//! it reaches and the handovers of the epochs since, so it stops growing
//! with the chain's age.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tenzro_consensus::committee::Committee;
use tenzro_consensus::light_client::{
    Certification, EpochHandover, GenesisAnchor, HandoverChainJournal,
};
use tenzro_consensus::{Certificate, Checkpoint, Member, SessionCertificate};

use crate::consensus_driver::ConsensusHandle;
use crate::error::{NodeError, Result};

const DATA: &str = "handovers.bin";
const INDEX: &str = "handovers.len";
const CHAIN: &str = "chain.bin";

/// The bytes a proof written from an installed chain proof starts with: a
/// [`tenzro_consensus::light_client::ChainedCheckpointProof`] follows. A
/// proof from genesis never starts with them (its first eight bytes count
/// the genesis members).
pub const CHAINED_PROOF_TAG: [u8; 8] = *b"TZCHAIN1";

fn io(what: &str, path: &Path, e: io::Error) -> NodeError {
    NodeError::Other(format!("{what} {}: {e}", path.display()))
}

/// The handovers of epochs `base..` are in this file; those before `base`
/// are covered by the chain proof.
fn data_name(base: u64) -> String {
    if base == 0 {
        DATA.to_string()
    } else {
        format!("handovers-{base:020}.bin")
    }
}

/// An installed, verified proof of the handover chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainProof {
    /// What the receipt proves.
    pub journal: HandoverChainJournal,
    /// Members of the committee of `journal.epoch`.
    pub members: Vec<Member>,
    /// The receipt.
    pub receipt: Vec<u8>,
}

/// The handovers of epochs `base..count`, encoded back to back exactly as a
/// proof carries them, and the chain proof that covers epochs `0..base`.
#[derive(Debug)]
pub struct ProofLog {
    dir: PathBuf,
    count: u64,
    bytes: u64,
    base: u64,
    chain: Option<ChainProof>,
}

/// Counts the bytes read through it.
struct Counting<R> {
    inner: R,
    read: u64,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        Ok(n)
    }
}

impl ProofLog {
    /// The log under `dir`. A tail written after the index was last updated
    /// (the process stopped mid-append) is dropped.
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| io("create", dir, e))?;
        let (count, bytes, base) = match fs::read(dir.join(INDEX)) {
            Ok(b) if b.len() == 16 || b.len() == 24 => {
                let word =
                    |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
                (word(0), word(1), if b.len() == 24 { word(2) } else { 0 })
            }
            _ => (0, 0, 0),
        };
        let chain_path = dir.join(CHAIN);
        let chain: Option<ChainProof> = match fs::read(&chain_path) {
            Ok(b) => Some(bincode::deserialize(&b).map_err(|e| {
                NodeError::Other(format!("{} does not decode: {e}", chain_path.display()))
            })?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(io("read", &chain_path, e)),
        };
        if base > 0 && chain.as_ref().is_none_or(|c| c.journal.epoch < base) {
            return Err(NodeError::Other(format!(
                "{} drops the handovers before epoch {base} but holds no chain proof covering them",
                dir.display()
            )));
        }
        let data = dir.join(data_name(base));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&data)
            .map_err(|e| io("open", &data, e))?;
        let len = file.metadata().map_err(|e| io("stat", &data, e))?.len();
        let (count, bytes) = if len < bytes {
            (base, 0)
        } else {
            (count, bytes)
        };
        if len != bytes {
            file.set_len(bytes).map_err(|e| io("truncate", &data, e))?;
        }
        // Files of an earlier base, left by a stop mid-install.
        let current = data_name(base);
        for entry in fs::read_dir(dir).map_err(|e| io("list", dir, e))?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("handovers") && name.ends_with(".bin") && name != current {
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            count,
            bytes,
            base,
            chain,
        })
    }

    /// Epochs whose handover the log holds or its chain proof covers: those
    /// before this one.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The installed chain proof, if any.
    pub fn chain(&self) -> Option<&ChainProof> {
        self.chain.as_ref()
    }

    /// The epoch the installed chain proof reaches, 0 without one.
    pub fn chain_epoch(&self) -> u64 {
        self.chain.as_ref().map_or(0, |c| c.journal.epoch)
    }

    /// Bytes the log keeps on disk.
    pub fn disk_bytes(&self) -> u64 {
        fs::read_dir(&self.dir)
            .map(|d| {
                d.flatten()
                    .filter_map(|e| e.metadata().ok())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0)
    }

    fn write_index(&self) -> Result<()> {
        let mut index = Vec::with_capacity(24);
        index.extend_from_slice(&self.count.to_le_bytes());
        index.extend_from_slice(&self.bytes.to_le_bytes());
        index.extend_from_slice(&self.base.to_le_bytes());
        let tmp = self.dir.join(format!("{INDEX}.tmp"));
        fs::write(&tmp, &index)
            .and_then(|()| fs::rename(&tmp, self.dir.join(INDEX)))
            .map_err(|e| io("write", &tmp, e))
    }

    /// Appends the handover of epoch `count()`.
    pub fn append(&mut self, handover: &EpochHandover) -> Result<()> {
        let encoded = bincode::serialize(handover)
            .map_err(|e| NodeError::Other(format!("encode handover: {e}")))?;
        let data = self.dir.join(data_name(self.base));
        let mut file = OpenOptions::new()
            .append(true)
            .open(&data)
            .map_err(|e| io("open", &data, e))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_data())
            .map_err(|e| io("append", &data, e))?;
        self.count += 1;
        self.bytes += encoded.len() as u64;
        self.write_index()
    }

    /// The byte offset of the handover of epoch `epoch` in the data file.
    fn offset_of(&self, epoch: u64) -> io::Result<u64> {
        let skip = epoch.saturating_sub(self.base).min(self.count - self.base);
        let file = File::open(self.dir.join(data_name(self.base)))?;
        let mut reader = Counting {
            inner: BufReader::new(file.take(self.bytes)),
            read: 0,
        };
        for _ in 0..skip {
            let _: EpochHandover = bincode::deserialize_from(&mut reader)
                .map_err(|e| io::Error::other(format!("decode handover: {e}")))?;
        }
        Ok(reader.read)
    }

    /// Installs `proof`, already verified, and drops the handovers it
    /// covers. A proof that reaches no further than the installed one is
    /// refused. The proof is written first, then the remaining handovers to
    /// a file of their own, then the index that names that file: a stop at
    /// any point leaves a log that opens and writes a valid proof.
    pub fn install(&mut self, proof: ChainProof) -> Result<()> {
        let epoch = proof.journal.epoch;
        if epoch <= self.chain_epoch() {
            return Err(NodeError::Other(format!(
                "a chain proof to epoch {epoch} does not reach past the installed one (epoch {})",
                self.chain_epoch()
            )));
        }
        let encoded = bincode::serialize(&proof)
            .map_err(|e| NodeError::Other(format!("encode chain proof: {e}")))?;
        let tmp = self.dir.join(format!("{CHAIN}.tmp"));
        File::create(&tmp)
            .and_then(|mut f| f.write_all(&encoded).and_then(|()| f.sync_all()))
            .and_then(|()| fs::rename(&tmp, self.dir.join(CHAIN)))
            .map_err(|e| io("write", &tmp, e))?;

        let kept_from = epoch.min(self.count);
        let offset = self
            .offset_of(kept_from)
            .map_err(|e| io("read", &self.dir.join(data_name(self.base)), e))?;
        let old = self.dir.join(data_name(self.base));
        let new = self.dir.join(data_name(epoch));
        {
            let mut src = File::open(&old).map_err(|e| io("open", &old, e))?;
            io::copy(&mut (&mut src).take(offset), &mut io::sink())
                .map_err(|e| io("read", &old, e))?;
            let mut dst = File::create(&new).map_err(|e| io("create", &new, e))?;
            io::copy(&mut src.take(self.bytes - offset), &mut dst)
                .and_then(|_| dst.sync_all())
                .map_err(|e| io("write", &new, e))?;
        }
        self.chain = Some(proof);
        self.bytes -= offset;
        self.count = self.count.max(epoch);
        self.base = epoch;
        self.write_index()?;
        if old != new {
            let _ = fs::remove_file(&old);
        }
        Ok(())
    }

    /// Writes the proof that `certificate` is certified, with the handovers
    /// copied from the log rather than held in memory. Without a chain
    /// proof it is exactly the bytes `bincode::serialize` gives a
    /// `CheckpointProof` from genesis; with one, [`CHAINED_PROOF_TAG`] then a
    /// `ChainedCheckpointProof`. The log must reach the certificate's epoch.
    pub fn write_proof(
        &self,
        genesis_members: &[Member],
        certificate: &Certificate,
        sessions: &[SessionCertificate],
        out: &mut dyn Write,
    ) -> io::Result<()> {
        if self.count != certificate.checkpoint.epoch {
            return Err(io::Error::other(format!(
                "the proof log holds {} handovers, a checkpoint of epoch {} needs {}",
                self.count, certificate.checkpoint.epoch, certificate.checkpoint.epoch
            )));
        }
        let encode = |e: bincode::Error| io::Error::other(e.to_string());
        let from = match &self.chain {
            None => {
                bincode::serialize_into(&mut *out, genesis_members).map_err(encode)?;
                0
            }
            Some(chain) => {
                out.write_all(&CHAINED_PROOF_TAG)?;
                bincode::serialize_into(&mut *out, &chain.receipt).map_err(encode)?;
                bincode::serialize_into(&mut *out, &chain.members).map_err(encode)?;
                chain.journal.epoch
            }
        };
        out.write_all(&(self.count - from).to_le_bytes())?;
        let offset = self.offset_of(from)?;
        let mut data = File::open(self.dir.join(data_name(self.base)))?;
        io::copy(&mut (&mut data).take(offset), &mut io::sink())?;
        io::copy(&mut data.take(self.bytes - offset), out)?;
        bincode::serialize_into(&mut *out, certificate).map_err(encode)?;
        bincode::serialize_into(&mut *out, sessions).map_err(encode)?;
        Ok(())
    }

    /// The handovers of epochs `from..to`, read from the log.
    pub fn handovers(&self, from: u64, to: u64) -> io::Result<Vec<EpochHandover>> {
        if from < self.base || to > self.count || from > to {
            return Err(io::Error::other(format!(
                "the log holds the handovers of epochs {}..{}, not {from}..{to}",
                self.base, self.count
            )));
        }
        let offset = self.offset_of(from)?;
        let file = File::open(self.dir.join(data_name(self.base)))?;
        let mut data = BufReader::new(file.take(self.bytes));
        io::copy(&mut (&mut data).take(offset), &mut io::sink())?;
        (from..to)
            .map(|_| {
                bincode::deserialize_from(&mut data)
                    .map_err(|e| io::Error::other(format!("decode handover: {e}")))
            })
            .collect()
    }

    /// What a checkpoint of epoch `to_epoch` is certified from: the
    /// installed chain proof, the members of the committee it reaches
    /// (`genesis_members` before any proof is installed) and the handovers
    /// from there to `to_epoch`.
    pub fn segment(
        &self,
        genesis_members: Option<&[Member]>,
        to_epoch: u64,
    ) -> io::Result<ChainSegment> {
        let (journal, receipt, members) = match &self.chain {
            Some(c) => (Some(c.journal), c.receipt.clone(), c.members.clone()),
            None => (
                None,
                Vec::new(),
                genesis_members
                    .ok_or_else(|| io::Error::other("the genesis committee is not known here"))?
                    .to_vec(),
            ),
        };
        let from = journal.map_or(0, |j| j.epoch);
        if to_epoch < from {
            return Err(io::Error::other(format!(
                "the chain proof here reaches epoch {from}, past epoch {to_epoch}: certify a later checkpoint"
            )));
        }
        Ok(ChainSegment {
            journal,
            receipt,
            members,
            handovers: self.handovers(from, to_epoch)?,
        })
    }
}

pub use tenzro_consensus::light_client::ChainSegment;

/// Writes what a prover needs to extend the chain proof by `segment`'s
/// handovers, as `tenzro-finality-prover handover` reads it: `genesis-root`
/// (hex), `prev.bin` (the chain proof's receipt, when there is one) and, per
/// epoch, `<epoch>/handover.bin` and `<epoch>/members.bin`, the members of
/// that epoch's committee. Returns the epochs written.
pub fn write_prover_inputs(segment: &ChainSegment, out: &Path) -> Result<Vec<u64>> {
    let genesis_root = match &segment.journal {
        Some(j) => j.genesis_root,
        None => Committee::from_members(0, segment.members.clone())
            .map_err(|e| NodeError::Other(format!("the genesis committee: {e}")))?
            .root(),
    };
    let write =
        |path: PathBuf, bytes: &[u8]| fs::write(&path, bytes).map_err(|e| io("write", &path, e));
    let encode = |what: &str, e: bincode::Error| NodeError::Other(format!("encode {what}: {e}"));
    fs::create_dir_all(out).map_err(|e| io("create", out, e))?;
    write(
        out.join("genesis-root"),
        hex::encode(genesis_root).as_bytes(),
    )?;
    if !segment.receipt.is_empty() {
        write(out.join("prev.bin"), &segment.receipt)?;
    }
    let mut members = &segment.members;
    let mut epochs = Vec::with_capacity(segment.handovers.len());
    for (i, h) in segment.handovers.iter().enumerate() {
        let epoch = segment.first_epoch() + i as u64;
        let dir = out.join(epoch.to_string());
        fs::create_dir_all(&dir).map_err(|e| io("create", &dir, e))?;
        write(
            dir.join("handover.bin"),
            &bincode::serialize(h).map_err(|e| encode("handover", e))?,
        )?;
        write(
            dir.join("members.bin"),
            &bincode::serialize(members).map_err(|e| encode("members", e))?,
        )?;
        members = &h.next_members;
        epochs.push(epoch);
    }
    Ok(epochs)
}

/// The certification of checkpoint `index`: from genesis while consensus
/// still holds every handover before it, otherwise from the proof log's
/// chain proof and the handovers since. `None` when neither holds it.
pub fn certification(
    consensus: &ConsensusHandle,
    log: Option<&parking_lot::Mutex<ProofLog>>,
    index: u64,
) -> Option<Certification> {
    if let Some(p) = consensus.checkpoint_proof(index) {
        return Some(Certification::FromGenesis(p));
    }
    let certificate = consensus.certificate(index)?;
    let sessions = consensus.session_bundle(&certificate);
    let genesis = consensus.committee_of(0).map(|c| c.members().to_vec());
    let segment = log?
        .lock()
        .segment(genesis.as_deref(), certificate.checkpoint.epoch)
        .ok()?;
    Some(segment.certify(certificate, sessions))
}

/// The checkpoint `certification` certifies from the genesis `anchor`; a
/// chained one against the handover program `program`, its receipt checked
/// by the zkVM receipt verifier.
pub fn verify_certification(
    certification: &Certification,
    anchor: &GenesisAnchor,
    program: Option<[u8; 32]>,
) -> std::result::Result<Checkpoint, String> {
    certification
        .verify(anchor, program, tenzro_zk::handover_chain::verify_receipt)
        .cloned()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_consensus::light_client::{ChainedCheckpointProof, CheckpointProof};

    fn certificate(epoch: u64, index: u64) -> Certificate {
        Certificate {
            checkpoint: Checkpoint {
                chain_id: 7,
                genesis_hash: [1; 32],
                epoch,
                index,
                prev: [index as u8; 32],
                first_height: index,
                last_height: index,
                blocks_root: [2; 32],
                state_height: index,
                state_root: [3; 32],
                statement_root: [4; 32],
                next_committee_root: Some([5; 32]),
                anchor_round: index,
                timestamp_ms: index * 500,
                ordering_root: [6; 32],
            },
            signers: vec![epoch as u16],
            sessions: vec![[epoch as u8; 32]],
            signatures: Vec::new(),
        }
    }

    fn handover(epoch: u64) -> EpochHandover {
        EpochHandover {
            certificate: certificate(epoch, epoch * 3 + 2),
            sessions: Vec::new(),
            next_members: Vec::new(),
        }
    }

    fn chain_proof(epoch: u64) -> ChainProof {
        ChainProof {
            journal: HandoverChainJournal {
                program: [9; 32],
                chain_id: 7,
                genesis_hash: [1; 32],
                genesis_root: [2; 32],
                epoch,
                committee_root: [3; 32],
            },
            members: Vec::new(),
            receipt: vec![epoch as u8; 300],
        }
    }

    fn members(n: u64) -> Vec<Member> {
        vec![Member {
            address: tenzro_types::primitives::Address([n as u8; 32]),
            public_key: tenzro_consensus::ValidatorPublicKey {
                ml_dsa: Vec::new(),
                p256: Vec::new(),
            },
            stake: 1,
            seats: 1,
        }]
    }

    /// A node that dropped the handovers its chain proof covers still serves
    /// what a restoring node certifies a checkpoint from: the chain proof and
    /// the handovers since, read back from the RPC answer. Before any chain
    /// proof it serves the handovers from genesis.
    #[test]
    fn a_served_segment_certifies_a_checkpoint_past_the_dropped_handovers() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = ProofLog::open(dir.path()).unwrap();
        for e in 0..10 {
            log.append(&handover(e)).unwrap();
        }
        let genesis = members(0);
        let reply = log.segment(Some(&genesis), 4).unwrap().to_reply();
        match ChainSegment::from_reply(&reply)
            .unwrap()
            .certify(certificate(4, 14), Vec::new())
        {
            Certification::FromGenesis(p) => {
                assert_eq!(p.genesis_members, genesis);
                assert_eq!(p.handovers.len(), 4);
            }
            other => panic!("expected a proof from genesis, got {other:?}"),
        }

        log.install(chain_proof(7)).unwrap();
        let reply = log.segment(None, 9).unwrap().to_reply();
        assert_eq!(
            (reply["first_epoch"].as_u64(), reply["to_epoch"].as_u64()),
            (Some(7), Some(9))
        );
        match ChainSegment::from_reply(&reply)
            .unwrap()
            .certify(certificate(9, 30), Vec::new())
        {
            Certification::Chained(p) => {
                assert_eq!(p.chain, vec![7u8; 300]);
                let epochs: Vec<u64> = p
                    .handovers
                    .iter()
                    .map(|h| h.certificate.checkpoint.epoch)
                    .collect();
                assert_eq!(epochs, vec![7, 8]);
                assert_eq!(p.certificate.checkpoint.index, 30);
            }
            other => panic!("expected a chained proof, got {other:?}"),
        }
        assert!(
            log.segment(None, 5).is_err(),
            "a checkpoint before the chain proof's epoch"
        );
        assert!(log.segment(None, 11).is_err(), "an epoch past the log");
        assert!(
            ChainSegment::from_reply(&serde_json::json!({ "segment": "0x00" })).is_err(),
            "bytes that are no segment"
        );
    }

    /// A prover is handed the chain proof's receipt to build on, the genesis
    /// committee root and, per epoch since, its handover and the members of
    /// its committee: those the handover before it handed over to.
    #[test]
    fn prover_inputs_chain_each_epoch_to_the_handover_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = ProofLog::open(dir.path()).unwrap();
        for e in 0..10 {
            let mut h = handover(e);
            h.next_members = members(e + 1);
            log.append(&h).unwrap();
        }
        log.install(ChainProof {
            members: members(7),
            ..chain_proof(7)
        })
        .unwrap();
        let out = tempfile::tempdir().unwrap();
        let segment = log.segment(None, 10).unwrap();
        let epochs = write_prover_inputs(&segment, out.path()).unwrap();
        assert_eq!(epochs, vec![7, 8, 9]);
        assert_eq!(
            fs::read_to_string(out.path().join("genesis-root")).unwrap(),
            hex::encode([2u8; 32])
        );
        assert_eq!(
            fs::read(out.path().join("prev.bin")).unwrap(),
            vec![7u8; 300]
        );
        for e in 7..10u64 {
            let d = out.path().join(e.to_string());
            let h: EpochHandover =
                bincode::deserialize(&fs::read(d.join("handover.bin")).unwrap()).unwrap();
            assert_eq!(h.certificate.checkpoint.epoch, e);
            let m: Vec<Member> =
                bincode::deserialize(&fs::read(d.join("members.bin")).unwrap()).unwrap();
            assert_eq!(m, members(e), "epoch {e}'s committee");
        }
    }

    fn chained(out: &[u8]) -> ChainedCheckpointProof {
        assert_eq!(out[..8], CHAINED_PROOF_TAG);
        bincode::deserialize(&out[8..]).unwrap()
    }

    /// The streamed proof is byte for byte the proof built in memory, so
    /// restore and every verifier read it unchanged.
    #[test]
    fn the_streamed_proof_is_the_proof_built_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = ProofLog::open(dir.path()).unwrap();
        let handovers: Vec<EpochHandover> = (0..25).map(handover).collect();
        for h in &handovers {
            log.append(h).unwrap();
        }
        let cert = certificate(25, 80);
        let mut streamed = Vec::new();
        log.write_proof(&[], &cert, &[], &mut streamed).unwrap();
        let built = CheckpointProof {
            genesis_members: Vec::new(),
            handovers,
            certificate: cert,
            sessions: Vec::new(),
        };
        assert_eq!(streamed, bincode::serialize(&built).unwrap());
        let back: CheckpointProof = bincode::deserialize(&streamed).unwrap();
        assert_eq!(back.handovers.len(), 25);
    }

    /// Reopened, the log resumes where it was; a tail written after its
    /// index (a stop mid-append) is dropped, and a proof for an epoch the
    /// log does not cover exactly is refused.
    #[test]
    fn the_log_survives_a_restart_and_drops_a_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = ProofLog::open(dir.path()).unwrap();
            for e in 0..3 {
                log.append(&handover(e)).unwrap();
            }
        }
        let mut torn = OpenOptions::new()
            .append(true)
            .open(dir.path().join(DATA))
            .unwrap();
        torn.write_all(&[0xab; 40]).unwrap();
        drop(torn);

        let mut log = ProofLog::open(dir.path()).unwrap();
        assert_eq!(log.count(), 3);
        log.append(&handover(3)).unwrap();
        let mut out = Vec::new();
        log.write_proof(&[], &certificate(4, 14), &[], &mut out)
            .unwrap();
        let back: CheckpointProof = bincode::deserialize(&out).unwrap();
        assert_eq!(back.handovers.len(), 4);
        assert_eq!(back.handovers[3].certificate.checkpoint.epoch, 3);

        let err = log.write_proof(&[], &certificate(6, 20), &[], &mut Vec::new());
        assert!(err.is_err(), "a log short of the epoch is refused");
    }

    /// Once a chain proof is installed the log holds it and only the
    /// handovers after it; the proof it writes carries no handover the chain
    /// proof covers, and the log reopens to the same state.
    #[test]
    fn an_installed_chain_proof_replaces_the_handovers_it_covers() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = ProofLog::open(dir.path()).unwrap();
        for e in 0..10 {
            log.append(&handover(e)).unwrap();
        }
        let before = log.disk_bytes();
        log.install(chain_proof(7)).unwrap();
        assert_eq!((log.count(), log.chain_epoch()), (10, 7));
        assert!(log.disk_bytes() < before, "the covered handovers are gone");
        assert!(
            log.install(chain_proof(7)).is_err(),
            "no further than the installed proof"
        );

        let mut out = Vec::new();
        log.write_proof(&[], &certificate(10, 40), &[], &mut out)
            .unwrap();
        let proof = chained(&out);
        assert_eq!(proof.chain, vec![7u8; 300]);
        let epochs: Vec<u64> = proof
            .handovers
            .iter()
            .map(|h| h.certificate.checkpoint.epoch)
            .collect();
        assert_eq!(epochs, vec![7, 8, 9]);

        drop(log);
        let mut log = ProofLog::open(dir.path()).unwrap();
        assert_eq!((log.count(), log.chain_epoch()), (10, 7));
        log.append(&handover(10)).unwrap();
        // A proof that reaches past what the log holds leaves it no handover.
        log.install(chain_proof(12)).unwrap();
        assert_eq!((log.count(), log.chain_epoch()), (12, 12));
        let mut out = Vec::new();
        log.write_proof(&[], &certificate(12, 50), &[], &mut out)
            .unwrap();
        assert!(chained(&out).handovers.is_empty());
        let files: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("handovers") && n.ends_with(".bin"))
            .collect();
        assert_eq!(files, vec![data_name(12)], "one handover file");
    }

    /// A stop after the chain proof is written but before the index names
    /// the new handover file: the log reopens on the old file, and the proof
    /// it writes skips the handovers the chain proof covers.
    #[test]
    fn a_stop_mid_install_leaves_a_log_that_writes_a_valid_proof() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = ProofLog::open(dir.path()).unwrap();
        for e in 0..6 {
            log.append(&handover(e)).unwrap();
        }
        drop(log);
        fs::write(
            dir.path().join(CHAIN),
            bincode::serialize(&chain_proof(4)).unwrap(),
        )
        .unwrap();
        fs::write(dir.path().join(data_name(4)), b"partial").unwrap();
        let log = ProofLog::open(dir.path()).unwrap();
        assert_eq!((log.count(), log.chain_epoch()), (6, 4));
        assert!(
            !dir.path().join(data_name(4)).exists(),
            "the partial file is gone"
        );
        let mut out = Vec::new();
        log.write_proof(&[], &certificate(6, 30), &[], &mut out)
            .unwrap();
        let epochs: Vec<u64> = chained(&out)
            .handovers
            .iter()
            .map(|h| h.certificate.checkpoint.epoch)
            .collect();
        assert_eq!(epochs, vec![4, 5]);
    }
}
