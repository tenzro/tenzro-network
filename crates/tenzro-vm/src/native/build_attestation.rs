//! Release binaries vouched for by reproducible builders.
//!
//! A protocol upgrade names the binaries every node is to run, by SHA-256. A
//! hash says which bytes; it does not say those bytes come from the
//! published source. A builder (an account bonded in the attestor role)
//! rebuilds the release from its source and records, with a build
//! attestation, the hash it got. Once [`GATE`] is in force, a
//! protocol upgrade enacts only when every binary it names has
//! [`MIN_BUILDERS_PARAM`] attestations from builders whose bonds stand at
//! enactment, each counted once.
//!
//! The trust root of a release is then a quorum of bonded builders who each
//! got the same bytes, not the key of whoever published it.

use serde::{Deserialize, Serialize};
use tenzro_types::network::NetworkRole;

use super::funding::{read_json, refuse, write_json};
use super::*;

/// The gate of builder attestations.
pub const GATE: &str = "feature.builder_attestations.activation_epoch";

/// How many distinct bonded builders must have attested each binary an
/// upgrade names before it enacts.
pub const MIN_BUILDERS_PARAM: &str = "feature.builder_attestations.min_builders";

pub use tenzro_native_ops::SELECTOR_BUILD_ATTESTATION;

/// Gas for one attestation.
pub const GAS_BUILD_ATTESTATION: u64 = 40_000;

/// Topic of the log an attestation emits.
pub const BUILD_ATTESTED_TOPIC: &[u8] = b"BuildAttested";

/// Most attestations kept for one binary.
const MAX_ATTESTATIONS: usize = 256;

/// One builder's attestation of a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildAttestationRecord {
    /// The builder's account, hex.
    pub builder: String,
    /// The release it built.
    pub version: String,
    /// The target triple it built for.
    pub platform: String,
    /// The block it was recorded in.
    pub height: u64,
}

fn key(code_hash: &[u8]) -> String {
    format!("build_attestations:{}", hex::encode(code_hash))
}

/// Every attestation recorded for the binary `code_hash`.
pub fn build_attestations(state: &dyn VmState, code_hash: &[u8]) -> Vec<BuildAttestationRecord> {
    read_json(state, &key(code_hash)).unwrap_or_default()
}

/// The distinct builders whose bonds stand now and who attested `code_hash`.
pub fn standing_builders(state: &dyn VmState, code_hash: &[u8]) -> usize {
    build_attestations(state, code_hash)
        .iter()
        .filter(|a| {
            hex::decode(&a.builder)
                .is_ok_and(|acct| role_bonded(state, &acct, NetworkRole::Attestor))
        })
        .count()
}

/// Record the attestation `payload` from the builder `from` at `height`.
pub(super) fn apply(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &[u8],
    height: u64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Err(refuse(
            "build attestations are not in force on this chain yet",
        ));
    }
    let p: tenzro_native_ops::build_attestation::BuildAttestationOp =
        serde_json::from_slice(payload)
            .map_err(|e| refuse(format!("Invalid build attestation payload: {e}")))?;
    p.validate().map_err(refuse)?;
    if !role_bonded(state, from, NetworkRole::Attestor) {
        return Err(refuse(format!(
            "{} holds no attestor bond; a build is attested by a bonded builder",
            hex::encode(from)
        )));
    }
    let builder = hex::encode(from);
    let mut records = build_attestations(state, &p.code_hash);
    if records.iter().any(|a| a.builder == builder) {
        return Err(refuse(format!(
            "{builder} has already attested this binary"
        )));
    }
    if records.len() >= MAX_ATTESTATIONS {
        return Err(refuse("this binary holds the most attestations kept"));
    }
    let record = BuildAttestationRecord {
        builder,
        version: p.version,
        platform: p.platform,
        height,
    };
    records.push(record.clone());
    let mut changes = Vec::new();
    write_json(state, &key(&p.code_hash), &records, &mut changes)?;
    let data = serde_json::to_vec(&serde_json::json!({
        "code_hash": hex::encode(&p.code_hash),
        "builder": record.builder,
        "version": record.version,
        "platform": record.platform,
    }))
    .map_err(|e| VmError::Internal(format!("encode build attestation log: {e}")))?;
    Ok((
        changes,
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![BUILD_ATTESTED_TOPIC.to_vec()],
            data,
        )],
    ))
}

/// Refuse to enact an upgrade one of whose binaries `binaries` lacks the
/// governed number of standing builder attestations, once [`GATE`] is in
/// force.
pub(super) fn require_builders(state: &dyn VmState, binaries: &[&[u8]]) -> Result<()> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Ok(());
    }
    let need = network_param(state, MIN_BUILDERS_PARAM) as usize;
    for code_hash in binaries {
        let have = standing_builders(state, code_hash);
        if have < need {
            return Err(refuse(format!(
                "binary {} is attested by {have} bonded builders; {need} must rebuild it before \
                 the upgrade enacts",
                hex::encode(code_hash)
            )));
        }
    }
    Ok(())
}
