//! Portable identity export bundles in CARv1 + DAG-CBOR (C.6).
//!
//! A CAR (Content Addressable aRchive) bundle is the on-the-wire format used
//! to move a Tenzro identity — DID, credentials, and the encrypted wallet
//! keystore files that back it — between machines. The bundle is
//! self-contained: drop it on a different node, run `tenzro identity
//! import-car`, and the wallet/agent/credential operations resume exactly
//! where they left off on the source.
//!
//! # What's inside
//!
//! [`IdentityCarBundle`] is the DAG-CBOR-serialized payload that becomes the
//! single root block of a CARv1 file. It carries:
//!
//! * [`TenzroIdentity`] — the public identity record (`did`, public keys,
//!   verifying keys, embedded `credentials`, services, metadata). Credentials
//!   already live on the identity, so they ride along without a separate
//!   field.
//! * `wallet_files` — a map from on-disk filename (`<wallet_id>.json`,
//!   `<wallet_id>.pq.json`, `<wallet_id>.bls.json`) to the **already
//!   encrypted** keystore bytes. The user's wallet password never leaves the
//!   source machine; the recipient supplies it locally at import time. That
//!   keeps the bundle safe over insecure transport — losing it leaks nothing
//!   beyond the public identity record.
//!
//! # Wire format
//!
//! Plain CARv1, hand-rolled in ~40 LOC ([`encode_car`] / [`decode_car`])
//! because we only need a single-root, single-block file — no streaming, no
//! CARv2 index, no async. Format:
//!
//! ```text
//! varint(len) || header_dag_cbor_bytes
//! varint(len) || cid_bytes || payload_dag_cbor_bytes
//! ```
//!
//! `cid` is `cidv1 dag-cbor sha2-256(payload)`, computed deterministically
//! from the DAG-CBOR-encoded [`IdentityCarBundle`]. The header carries
//! `{ roots: [cid], version: 1 }`, also DAG-CBOR-encoded.
//!
//! # Why not iroh-car
//!
//! `iroh-car` is the obvious crate but hasn't shipped since 2024-10 and pulls
//! in async traits we don't need here. A direct CARv1 writer over `cid` +
//! `multihash` + `serde_ipld_dagcbor` is smaller, has no stale deps, and is
//! easy to audit.

use std::collections::{BTreeMap, HashMap};

use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};
use crate::identity::TenzroIdentity;

/// IPLD codec code for DAG-CBOR (multicodec table).
const DAG_CBOR_CODEC: u64 = 0x71;

/// Maximum size we'll accept for a single varint length on decode.
///
/// CARv1 has no formal cap; this is a defense-in-depth limit to prevent a
/// malicious bundle from convincing the decoder to allocate gigabytes.
/// 16 MiB is comfortably larger than any plausible identity + 3 keystore
/// files (typically under 5 KiB total).
const MAX_BLOCK_SIZE: usize = 16 * 1024 * 1024;

/// One identity, its credentials (embedded on the identity), and the
/// encrypted keystore files that let the recipient sign on its behalf.
///
/// `wallet_files` is keyed by on-disk filename so the importer can drop the
/// bytes back into its keystore directory without inventing a name mapping.
/// `BTreeMap` (rather than `HashMap`) is used for the on-the-wire payload so
/// the DAG-CBOR encoding is deterministic — the same logical bundle always
/// produces the same CAR CID, which makes the format auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCarBundle {
    /// The identity record (DID, public keys, credentials, services, …).
    pub identity: TenzroIdentity,
    /// Encrypted keystore files, keyed by filename. Values are the verbatim
    /// AES-256-GCM ciphertext as written by `tenzro_wallet::Keystore`.
    pub wallet_files: BTreeMap<String, Vec<u8>>,
    /// Bundle format version for forward-compat reads.
    pub version: u32,
}

impl IdentityCarBundle {
    /// Current bundle format version. Bump on any breaking change to the
    /// serialized shape of [`IdentityCarBundle`] itself.
    pub const CURRENT_VERSION: u32 = 1;

    /// Build a bundle from an identity and a map of encrypted wallet files
    /// (as returned by `tenzro_wallet::Keystore::export_encrypted_wallet_files`).
    pub fn new(identity: TenzroIdentity, wallet_files: HashMap<String, Vec<u8>>) -> Self {
        Self {
            identity,
            wallet_files: wallet_files.into_iter().collect(),
            version: Self::CURRENT_VERSION,
        }
    }

    /// Encode this bundle as a CARv1 byte stream. The output starts with a
    /// varint-length-prefixed DAG-CBOR header carrying the single root CID,
    /// followed by the payload block.
    pub fn to_car_bytes(&self) -> Result<Vec<u8>> {
        encode_car(self)
    }

    /// Decode a CARv1 byte stream produced by [`Self::to_car_bytes`].
    ///
    /// Verifies that the bundle's content CID matches the root advertised in
    /// the CAR header — a torn or tampered bundle will fail here rather than
    /// silently importing.
    pub fn from_car_bytes(bytes: &[u8]) -> Result<Self> {
        decode_car(bytes)
    }
}

/// Encode an [`IdentityCarBundle`] as a CARv1 file with one block.
fn encode_car(bundle: &IdentityCarBundle) -> Result<Vec<u8>> {
    // 1. Serialize the bundle as DAG-CBOR; this is the single block's payload.
    let payload = serde_ipld_dagcbor::to_vec(bundle)
        .map_err(|e| IdentityError::SerializationError(format!("CAR payload encode: {e}")))?;

    // 2. CID = cidv1 + dag-cbor codec + sha2-256(payload).
    let hash = Code::Sha2_256.digest(&payload);
    let root_cid = Cid::new_v1(DAG_CBOR_CODEC, hash);

    // 3. CAR header: { roots: [cid], version: 1 }. Field order matters for
    //    deterministic encoding — DAG-CBOR sorts map keys by length-then-bytes
    //    automatically via `serde_ipld_dagcbor`.
    let header = CarHeader {
        roots: vec![root_cid],
        version: 1,
    };
    let header_bytes = serde_ipld_dagcbor::to_vec(&header)
        .map_err(|e| IdentityError::SerializationError(format!("CAR header encode: {e}")))?;

    // 4. Block on the wire = cid_bytes || payload.
    let cid_bytes = root_cid.to_bytes();
    let mut block = Vec::with_capacity(cid_bytes.len() + payload.len());
    block.extend_from_slice(&cid_bytes);
    block.extend_from_slice(&payload);

    // 5. Stitch with varint length prefixes.
    let mut out = Vec::with_capacity(16 + header_bytes.len() + block.len());
    write_varint(&mut out, header_bytes.len() as u64);
    out.extend_from_slice(&header_bytes);
    write_varint(&mut out, block.len() as u64);
    out.extend_from_slice(&block);
    Ok(out)
}

/// Decode a CARv1 file produced by [`encode_car`] and verify its integrity.
fn decode_car(bytes: &[u8]) -> Result<IdentityCarBundle> {
    let mut cursor = bytes;

    // 1. Header.
    let header_len = read_varint(&mut cursor)? as usize;
    if header_len > MAX_BLOCK_SIZE || header_len > cursor.len() {
        return Err(IdentityError::SerializationError(format!(
            "CAR header length {} out of range",
            header_len
        )));
    }
    let (header_bytes, rest) = cursor.split_at(header_len);
    let header: CarHeader = serde_ipld_dagcbor::from_slice(header_bytes)
        .map_err(|e| IdentityError::SerializationError(format!("CAR header decode: {e}")))?;
    if header.version != 1 {
        return Err(IdentityError::SerializationError(format!(
            "Unsupported CAR version {}",
            header.version
        )));
    }
    if header.roots.len() != 1 {
        return Err(IdentityError::SerializationError(format!(
            "Expected exactly one root in CAR header, got {}",
            header.roots.len()
        )));
    }
    let expected_root = header.roots[0];
    cursor = rest;

    // 2. Block.
    let block_len = read_varint(&mut cursor)? as usize;
    if block_len > MAX_BLOCK_SIZE || block_len > cursor.len() {
        return Err(IdentityError::SerializationError(format!(
            "CAR block length {} out of range",
            block_len
        )));
    }
    let (block_bytes, rest) = cursor.split_at(block_len);
    let (cid, payload) = split_cid_and_payload(block_bytes)?;

    if cid != expected_root {
        return Err(IdentityError::SerializationError(
            "CAR block CID does not match the root advertised in the header".into(),
        ));
    }

    // 3. Re-derive the CID from the payload to detect tampering.
    let derived = Cid::new_v1(DAG_CBOR_CODEC, Code::Sha2_256.digest(payload));
    if derived != cid {
        return Err(IdentityError::SerializationError(
            "CAR block content does not hash to its advertised CID".into(),
        ));
    }

    if !rest.is_empty() {
        return Err(IdentityError::SerializationError(format!(
            "CAR file has {} trailing bytes after the only expected block",
            rest.len()
        )));
    }

    let bundle: IdentityCarBundle = serde_ipld_dagcbor::from_slice(payload)
        .map_err(|e| IdentityError::SerializationError(format!("CAR payload decode: {e}")))?;
    Ok(bundle)
}

/// CARv1 header shape: `{ roots: [Cid, ...], version: u64 }`. Field names
/// match the spec and are alphabetically ordered by `serde_ipld_dagcbor`.
#[derive(Serialize, Deserialize)]
struct CarHeader {
    roots: Vec<Cid>,
    version: u64,
}

/// Pull a CID off the front of a block and return the remainder as the
/// payload. CIDv1 doesn't carry its own length prefix inside a block, so we
/// rely on `cid::Cid::read_bytes` to consume exactly the right number of
/// bytes.
fn split_cid_and_payload(block: &[u8]) -> Result<(Cid, &[u8])> {
    let mut cursor = block;
    let cid = Cid::read_bytes(&mut cursor)
        .map_err(|e| IdentityError::SerializationError(format!("CAR block CID: {e}")))?;
    let consumed = block.len() - cursor.len();
    Ok((cid, &block[consumed..]))
}

/// Write an unsigned LEB128 varint (CARv1's length prefix encoding).
fn write_varint(out: &mut Vec<u8>, value: u64) {
    let mut buf = unsigned_varint::encode::u64_buffer();
    let encoded = unsigned_varint::encode::u64(value, &mut buf);
    out.extend_from_slice(encoded);
}

/// Read an unsigned LEB128 varint and advance the cursor past it.
fn read_varint(cursor: &mut &[u8]) -> Result<u64> {
    let (value, rest) = unsigned_varint::decode::u64(cursor)
        .map_err(|e| IdentityError::SerializationError(format!("CAR varint: {e}")))?;
    *cursor = rest;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::IdentityRegistry;
    use tenzro_types::identity::KycTier;

    fn sample_identity() -> TenzroIdentity {
        // The registry guarantees a serializable identity with the right key
        // lengths, so we don't have to hand-craft one and risk drifting from
        // the validated shape.
        let registry = IdentityRegistry::new();
        let result = tokio_test_block_on(async {
            registry
                .register_human_with_fee(
                    vec![7u8; 32],
                    "Carol".to_string(),
                    KycTier::Basic,
                )
                .await
                .unwrap()
        });
        result.identity
    }

    /// Minimal block_on so this module doesn't pull a heavier dev-dep just
    /// for one round-trip test. We're inside a single-threaded test; spawning
    /// a current-thread runtime is fine.
    fn tokio_test_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn bundle_round_trip_via_car() {
        let identity = sample_identity();
        let mut wallet_files = HashMap::new();
        wallet_files.insert("walletA.json".to_string(), b"sealed-shares-blob".to_vec());
        wallet_files.insert("walletA.pq.json".to_string(), b"sealed-mldsa-seed".to_vec());
        wallet_files.insert("walletA.bls.json".to_string(), b"sealed-bls-seed".to_vec());

        let bundle = IdentityCarBundle::new(identity.clone(), wallet_files.clone());
        let car = bundle.to_car_bytes().unwrap();

        let decoded = IdentityCarBundle::from_car_bytes(&car).unwrap();
        assert_eq!(decoded.version, IdentityCarBundle::CURRENT_VERSION);
        assert_eq!(decoded.identity.did_string(), identity.did_string());
        assert_eq!(decoded.identity.pq_verifying_key.len(), 1952);
        assert_eq!(decoded.identity.bls_verifying_key.len(), 48);
        assert_eq!(decoded.wallet_files.len(), 3);
        for (k, v) in &wallet_files {
            assert_eq!(decoded.wallet_files.get(k), Some(v));
        }
    }

    #[test]
    fn corrupted_payload_fails_hash_check() {
        let identity = sample_identity();
        let bundle = IdentityCarBundle::new(identity, HashMap::new());
        let mut car = bundle.to_car_bytes().unwrap();

        // Flip a byte well inside the payload block (past the headers + cid).
        let len = car.len();
        car[len - 1] ^= 0xff;

        let err = IdentityCarBundle::from_car_bytes(&car).expect_err("must reject torn bundle");
        let msg = format!("{err}");
        assert!(
            msg.contains("hash") || msg.contains("CID") || msg.contains("decode"),
            "expected integrity error, got: {msg}"
        );
    }

    #[test]
    fn determinism_same_bundle_same_bytes() {
        let identity = sample_identity();
        let mut files = HashMap::new();
        files.insert("w.json".to_string(), vec![1, 2, 3]);
        files.insert("w.pq.json".to_string(), vec![4, 5, 6]);
        files.insert("w.bls.json".to_string(), vec![7, 8, 9]);

        let a = IdentityCarBundle::new(identity.clone(), files.clone())
            .to_car_bytes()
            .unwrap();
        let b = IdentityCarBundle::new(identity, files)
            .to_car_bytes()
            .unwrap();
        // Sorted BTreeMap + deterministic DAG-CBOR ⇒ byte-identical output.
        assert_eq!(a, b);
    }

}
