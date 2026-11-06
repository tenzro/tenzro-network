//! A TPM attestation attached to a machine root registered without one.
//!
//! A machine root records its TPM's attestation when it registers (credential
//! activation and a quote over the admission challenge for its DID and
//! identity key). A root registered before it did so has no attestation and,
//! without this operation, no way to add one short of a new identity. The
//! attach carries the same evidence, signed by the root's identity key and
//! sent by its wallet, with the quote answering a chain challenge bound to
//! the sending account's nonce. It is refused when the root already carries
//! an attestation, when the quote does not verify, and when the TPM is
//! already admitted under another identity: a machine holds one identity.
//!
//! Admission is recorded per TPM (keyed by its endorsement key) so the next
//! identity presenting the same chip is refused by a point lookup.

use super::funding::{identity_record, read_json, refuse, write_json};
use super::*;
use tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY;
use tenzro_tee::tpm_attest::{MachineAttestation, admission_challenge, attestation_key_sec1};
use tenzro_types::identity::{AttachMachineAttestationOp, attach_attestation_nonce};

/// Gas for one attach: a composite signature, a quote verification and
/// three records.
pub const GAS_ATTACH_MACHINE_ATTESTATION: u64 = 200_000;
/// Topic of the log an attach emits; nodes mirror it into their registry.
pub const MACHINE_ATTESTATION_ATTACHED_TOPIC: &[u8] = b"MachineAttestationAttached";
/// Metadata a machine root anchored in its TPM carries.
const MACHINE_ANCHOR_KEY: &str = "machine_anchor";
const MACHINE_ANCHOR_TPM: &str = "tpm_attested";

fn admitted_tpm_key(device: &str) -> String {
    format!("machine_tpm:{device}")
}

/// The identity TPM `device` (the hex SHA-256 of its endorsement key) was
/// admitted under, by a registration or an attach.
pub fn admitted_tpm_holder(state: &dyn VmState, device: &str) -> Option<String> {
    read_json(state, &admitted_tpm_key(device))
}

/// The identity, other than `did`, that already answers for the TPM whose
/// attestation is `att`: one it was admitted under, the autonomous machine
/// its attestation key roots, or one that claimed it at a reward epoch
/// close. A revoked identity answers for nothing.
fn other_holder(state: &dyn VmState, did: &str, att: &MachineAttestation) -> Option<String> {
    let device = tenzro_types::hardware_level::device_id(&att.evidence.ek_public);
    let autonomous = attestation_key_sec1(&att.evidence)
        .ok()
        .map(|ak| tenzro_tee::tpm_attest::machine_did_for_attestation_key(&ak))
        .filter(|d| identity_record(state, d).is_some());
    [
        admitted_tpm_holder(state, &device),
        autonomous,
        super::hardware_level::device_holder(state, &device),
    ]
    .into_iter()
    .flatten()
    .find(|holder| holder != did && !is_identity_revoked(state, holder))
}

/// Attach the TPM attestation `data` (an [`AttachMachineAttestationOp`])
/// carries to its machine root, sent by `from`.
pub fn attach(
    state: &mut dyn VmState,
    from: &[u8],
    data: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let op: AttachMachineAttestationOp = serde_json::from_slice(data)
        .map_err(|e| refuse(format!("invalid AttachMachineAttestation payload: {e}")))?;
    op.validate().map_err(refuse)?;
    let did = op.did.clone();
    let mut record =
        identity_record(state, &did).ok_or_else(|| refuse(format!("{did} is not registered")))?;
    if record.identity_type != "machine"
        || !tenzro_types::did_derivation::did_derives_from_key(&did, &record.controller_pubkey)
    {
        return Err(refuse(format!(
            "{did} is not a machine root: an attestation attaches only to a machine whose DID its \
             identity key derives"
        )));
    }
    if is_identity_revoked(state, &did) {
        return Err(refuse(format!("{did} is revoked")));
    }
    if record.metadata.contains_key(TPM_ATTESTATION_KEY) {
        return Err(refuse(format!(
            "{did} already carries a TPM attestation; it attaches once"
        )));
    }
    if record.wallet_address.as_bytes() != from {
        return Err(refuse(format!("an attach for {did} is sent by its wallet")));
    }
    let controller_xy = match record.controller_pubkey.as_slice() {
        [0x04, xy @ ..] if xy.len() == 64 => xy,
        other => other,
    };
    let enrolled_pq = crate::account_keys::enrolled_pq_key(&*state, controller_xy);
    if !tenzro_tee::identity_evidence::controller_signature_holds(
        &record.controller_pubkey,
        &op.statement(),
        &op.signature,
        enrolled_pq.as_deref(),
    ) {
        return Err(refuse(format!(
            "the attach is not signed by {did}'s identity key"
        )));
    }

    let att: MachineAttestation = serde_json::from_str(&op.attestation)
        .map_err(|e| refuse(format!("the attestation does not parse: {e}")))?;
    if !att.activated {
        return Err(refuse(
            "the attestation records no credential activation of its attestation key",
        ));
    }
    let nonce = attach_attestation_nonce(&did, from, state.get_nonce(from));
    if att.nonce.as_slice() != nonce.as_slice() {
        return Err(refuse(
            "the quote does not answer this attach's chain challenge (the sending account's \
             current nonce)",
        ));
    }
    let challenge = admission_challenge(&did, &record.controller_pubkey, &nonce);
    tenzro_tee::tpm_attest::verify_quote(&att.evidence, &challenge)
        .map_err(|e| refuse(format!("the TPM quote does not verify: {e}")))?;
    if let Some(holder) = other_holder(state, &did, &att) {
        return Err(refuse(format!(
            "this TPM is already admitted under {holder}; a machine holds one identity"
        )));
    }

    let mut changes = Vec::new();
    record
        .metadata
        .insert(TPM_ATTESTATION_KEY.to_string(), op.attestation.clone());
    record.metadata.insert(
        MACHINE_ANCHOR_KEY.to_string(),
        MACHINE_ANCHOR_TPM.to_string(),
    );
    let key = identity_storage_key(&did);
    let prior = state.get_storage(&SYSTEM_ADDRESS, &key);
    let blob = serde_json::to_vec(&record)
        .map_err(|e| VmError::Internal(format!("encode identity record: {e}")))?;
    state.set_storage(&SYSTEM_ADDRESS, &key, blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key,
        prior,
        Some(blob),
    ));
    let device = tenzro_types::hardware_level::device_id(&att.evidence.ek_public);
    write_json(state, &admitted_tpm_key(&device), &did, &mut changes)?;

    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![MACHINE_ATTESTATION_ATTACHED_TOPIC.to_vec()],
        serde_json::to_vec(&serde_json::json!({
            "did": did,
            "device": device,
            "metadata": {
                TPM_ATTESTATION_KEY: op.attestation,
                MACHINE_ANCHOR_KEY: MACHINE_ANCHOR_TPM,
            },
        }))
        .map_err(|e| VmError::Internal(format!("encode attach log: {e}")))?,
    );
    Ok((changes, vec![log]))
}

/// Record the TPM a registration admits, when its attestation binds the
/// registered identity and no identity holds that TPM yet, so a later attach
/// of the same chip under another identity is refused.
pub(super) fn note_registered_tpm(
    state: &mut dyn VmState,
    payload: &tenzro_types::identity::RegisterIdentityPayload,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let Some(att) = payload
        .metadata
        .get(TPM_ATTESTATION_KEY)
        .and_then(|json| serde_json::from_str::<MachineAttestation>(json).ok())
    else {
        return Ok(());
    };
    if !tenzro_tee::identity_evidence::tpm_evidence_binds(
        &payload.did,
        &payload.controller_pubkey,
        &att,
    ) {
        return Ok(());
    }
    let device = tenzro_types::hardware_level::device_id(&att.evidence.ek_public);
    if admitted_tpm_holder(state, &device).is_none() {
        write_json(state, &admitted_tpm_key(&device), &payload.did, changes)?;
    }
    Ok(())
}
