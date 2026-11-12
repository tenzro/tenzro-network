//! Continuity primitives for inference sessions: the failure domain a node
//! sits in, the rule that picks a session's successor, and the sealing of
//! checkpoint streams to that successor.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::encryption::{
    EncryptedEnvelope, SymmetricKey, envelope_decrypt, envelope_encrypt,
};
use thiserror::Error;

use crate::node::TenzroNode;

/// How much continuity a session buys.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityLevel {
    /// No checkpoints and no successor: a node failure loses the session.
    #[default]
    None,
    /// Periodic checkpoints held by a successor, which restores from the
    /// latest one when the primary fails.
    Standby,
    /// Checkpoints streamed to a successor after every turn, so a takeover
    /// starts from local state at once.
    HotSuccessor,
}

impl ContinuityLevel {
    /// Whether this level assigns a successor and takes checkpoints.
    pub fn needs_successor(self) -> bool {
        self != Self::None
    }

    /// The checkpoint interval used when the request names none.
    pub fn default_interval_secs(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Standby => 300,
            Self::HotSuccessor => 30,
        }
    }
}

/// Errors on the continuity path.
#[derive(Debug, Error)]
pub enum ContinuityError {
    #[error("outside jurisdiction {0}")]
    OutsideJurisdiction(String),
    #[error("no successor in jurisdiction {0} in a different failure domain")]
    NoSuccessor(String),
    #[error("not the designated successor")]
    NotDesignated,
    #[error("checkpoint from a node that is not the workload's primary")]
    WrongPrimary,
    #[error("checkpoint out of order: {0}")]
    OutOfOrder(String),
    #[error("no checkpoints held for {0}")]
    NotHeld(String),
    #[error("sealing: {0}")]
    Seal(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("refused by peer: {0}")]
    Refused(String),
    #[error("storage: {0}")]
    Storage(String),
}

/// A live node that may hold a session as its successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCandidate {
    /// The iroh `EndpointId` the session's checkpoints are sent to.
    pub endpoint_id: String,
    pub region: Option<String>,
    /// The operator the node pays out to. Two nodes with the same operator
    /// share a failure domain.
    pub operator: Option<String>,
    /// The node's declared serving jurisdiction.
    pub jurisdiction: Option<tenzro_types::JurisdictionClaim>,
}

impl NodeCandidate {
    /// The candidate a provider announcement describes.
    pub fn of(ann: &tenzro_network::ProviderAnnouncementMessage) -> Self {
        Self {
            endpoint_id: ann.iroh_endpoint_id.clone(),
            region: ann.region.clone(),
            operator: Some(ann.provider_address.clone()).filter(|a| !a.is_empty()),
            jurisdiction: ann.capacity.jurisdiction.clone(),
        }
    }
}

/// Where a node sits for failure purposes: who operates it and at which site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureDomain {
    pub endpoint_id: String,
    pub operator: Option<String>,
    pub site: Option<String>,
}

impl FailureDomain {
    pub fn of(candidate: &NodeCandidate) -> Self {
        Self {
            endpoint_id: candidate.endpoint_id.clone(),
            operator: candidate.operator.clone(),
            site: candidate.region.clone(),
        }
    }

    /// Whether `other` fails independently of this domain: another operator
    /// or another site. An undeclared operator or site proves nothing, so it
    /// never counts as a difference.
    pub fn is_distinct_from(&self, other: &FailureDomain) -> bool {
        if self.endpoint_id == other.endpoint_id {
            return false;
        }
        let differs = |a: &Option<String>, b: &Option<String>| matches!((a, b), (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b));
        differs(&self.operator, &other.operator) || differs(&self.site, &other.site)
    }
}

/// The successor rule every continuity path shares, over nodes already able
/// to serve the session: the node's declared jurisdiction satisfies the pin,
/// it sits in a different failure domain from `primary`, and it is not in
/// `exclude`. Order is kept, so the caller's ranking decides the best first.
pub fn pick_successors<'a>(
    jurisdiction: &str,
    primary: &FailureDomain,
    capable: impl IntoIterator<Item = &'a NodeCandidate>,
    exclude: &[&str],
) -> Result<Vec<NodeCandidate>, ContinuityError> {
    let eligible: Vec<NodeCandidate> = capable
        .into_iter()
        .filter(|c| !exclude.contains(&c.endpoint_id.as_str()))
        .filter(|c| {
            c.jurisdiction
                .as_ref()
                .is_some_and(|j| j.matches(jurisdiction))
        })
        .filter(|c| primary.is_distinct_from(&FailureDomain::of(c)))
        .cloned()
        .collect();
    if eligible.is_empty() {
        return Err(ContinuityError::NoSuccessor(jurisdiction.to_string()));
    }
    Ok(eligible)
}

/// This node as a failure domain.
pub fn local_domain(node: &TenzroNode) -> Option<FailureDomain> {
    Some(FailureDomain {
        endpoint_id: node.iroh_resolver()?.endpoint_id().to_string(),
        operator: node
            .operator_payee()
            .map(|a| format!("0x{}", hex::encode(a.as_bytes()))),
        site: node.config().region.clone(),
    })
}

const SEAL_MAGIC: &[u8; 8] = b"TZMCKPT\0";
const SEAL_CHUNK: usize = 4 * 1024 * 1024;
/// Frame header inside each sealed chunk: index (u64) and last flag (u8).
const FRAME_HEADER: usize = 9;

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Seal a stream under `key` in bounded memory. The plaintext is cut into
/// chunks; each is sealed with its index and a last-chunk flag inside the
/// authenticated plaintext, so chunks cannot be reordered, dropped or
/// truncated without the open failing. Returns the plaintext SHA-256 (hex).
pub fn seal_stream(
    mut src: impl Read,
    mut dst: impl Write,
    key: &SymmetricKey,
) -> Result<String, ContinuityError> {
    let io = |e: std::io::Error| ContinuityError::Seal(e.to_string());
    dst.write_all(SEAL_MAGIC).map_err(io)?;
    let mut hasher = Sha256::new();
    let mut cur = vec![0u8; SEAL_CHUNK];
    let mut next = vec![0u8; SEAL_CHUNK];
    let mut cur_len = read_full(&mut src, &mut cur).map_err(io)?;
    let mut index = 0u64;
    loop {
        let next_len = read_full(&mut src, &mut next).map_err(io)?;
        let last = next_len == 0;
        let mut frame = Vec::with_capacity(FRAME_HEADER + cur_len);
        frame.extend_from_slice(&index.to_le_bytes());
        frame.push(u8::from(last));
        frame.extend_from_slice(&cur[..cur_len]);
        hasher.update(&cur[..cur_len]);
        let sealed = key
            .encrypt(&frame)
            .map_err(|e| ContinuityError::Seal(e.to_string()))?;
        dst.write_all(&(sealed.len() as u32).to_le_bytes())
            .map_err(io)?;
        dst.write_all(&sealed).map_err(io)?;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        index += 1;
    }
    dst.flush().map_err(io)?;
    Ok(hex::encode(hasher.finalize()))
}

/// Open a stream sealed by [`seal_stream`], checking chunk order, the final
/// chunk and the plaintext digest `expected_sha256`.
pub fn open_stream(
    mut src: impl Read,
    mut dst: impl Write,
    key: &SymmetricKey,
    expected_sha256: &str,
) -> Result<(), ContinuityError> {
    let io = |e: std::io::Error| ContinuityError::Seal(e.to_string());
    let mut magic = [0u8; 8];
    src.read_exact(&mut magic).map_err(io)?;
    if &magic != SEAL_MAGIC {
        return Err(ContinuityError::Seal("not a sealed checkpoint".into()));
    }
    let mut hasher = Sha256::new();
    let mut expected_index = 0u64;
    loop {
        let mut len = [0u8; 4];
        if read_full(&mut src, &mut len).map_err(io)? != 4 {
            return Err(ContinuityError::Seal(
                "sealed checkpoint is truncated".into(),
            ));
        }
        let len = u32::from_le_bytes(len) as usize;
        if len > SEAL_CHUNK + 1024 {
            return Err(ContinuityError::Seal("oversized sealed chunk".into()));
        }
        let mut sealed = vec![0u8; len];
        src.read_exact(&mut sealed).map_err(io)?;
        let frame = key
            .decrypt(&sealed)
            .map_err(|e| ContinuityError::Seal(e.to_string()))?;
        if frame.len() < FRAME_HEADER {
            return Err(ContinuityError::Seal("short sealed chunk".into()));
        }
        let index = u64::from_le_bytes(frame[..8].try_into().expect("8 bytes"));
        if index != expected_index {
            return Err(ContinuityError::Seal("sealed chunks out of order".into()));
        }
        let data = &frame[FRAME_HEADER..];
        hasher.update(data);
        dst.write_all(data).map_err(io)?;
        if frame[8] == 1 {
            break;
        }
        expected_index += 1;
    }
    let mut trailing = [0u8; 1];
    if src.read(&mut trailing).map_err(io)? != 0 {
        return Err(ContinuityError::Seal("data after the final chunk".into()));
    }
    dst.flush().map_err(io)?;
    if hex::encode(hasher.finalize()) != expected_sha256 {
        return Err(ContinuityError::Seal("plaintext digest mismatch".into()));
    }
    Ok(())
}

/// Wrap a checkpoint's data key to a hybrid X25519 + ML-KEM-768 recipient.
pub fn wrap_data_key(
    key: &SymmetricKey,
    recipient: &tenzro_crypto::hybrid_seal::HybridPublicKey,
) -> Result<EncryptedEnvelope, ContinuityError> {
    envelope_encrypt(recipient, key.as_bytes()).map_err(|e| ContinuityError::Seal(e.to_string()))
}

/// Unwrap a checkpoint's data key with the recipient's key.
pub fn unwrap_data_key(
    recipient: &dyn tenzro_crypto::hybrid_seal::HybridRecipient,
    wrapped: &EncryptedEnvelope,
) -> Result<SymmetricKey, ContinuityError> {
    let mut bytes =
        envelope_decrypt(recipient, wrapped).map_err(|e| ContinuityError::Seal(e.to_string()))?;
    let key = SymmetricKey::from_bytes(&bytes).map_err(|e| ContinuityError::Seal(e.to_string()));
    zeroize::Zeroize::zeroize(&mut bytes);
    key
}
