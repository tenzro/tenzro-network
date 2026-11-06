//! Device-side passkey and FIDO caBLE commands.
//!
//! These have to run in the Tauri process rather than the WebView. The
//! private key lives in the platform secure enclave and never leaves
//! it, and the cross-device ceremony needs Bluetooth plus the CTAP2
//! stack — none of which a WebView can reach.
//!
//! A passkey is a pair of hardware keys under one label: a P-256 key the
//! platform will not export, and an ML-DSA-65 key for the post-quantum leg.
//! Both are held by this machine's hardware. On hardware that cannot hold an
//! ML-DSA-65 key the passkey is refused; there is no software or sealed
//! stand-in for the post-quantum leg.

use serde::{Deserialize, Serialize};

/// Public halves of a newly created device key pair.
///
/// `public_key_hex` is the raw P-256 point (`x ‖ y`, 64 bytes, no SEC1
/// prefix) that `tenzro_enrollPasskey` takes as the classical leg.
/// `ml_dsa_public_key_hex` is the 1952-byte FIPS-204 verifying key of the
/// hardware ML-DSA-65 key. `credential_id_hex` is derived from the label
/// and is what later signing calls echo back.
#[derive(Debug, Serialize)]
pub struct DeviceKeyInfo {
    pub label: String,
    pub public_key_hex: String,
    pub ml_dsa_public_key_hex: String,
    pub credential_id_hex: String,
}

/// Label of the hardware ML-DSA-65 key paired with passkey `label`.
fn ml_dsa_label(label: &str) -> String {
    format!("tenzro/passkey-pq/{label}")
}

#[tauri::command]
pub async fn device_create_passkey(label: String) -> Result<DeviceKeyInfo, String> {
    // The post-quantum key is opened first, so hardware that cannot hold one
    // refuses before a P-256 key is created for a passkey that cannot enrol.
    let pq = tenzro_device_key::signer::open_or_create_ml_dsa(&ml_dsa_label(&label))
        .map_err(|e| e.to_string())?;
    let pq_vk = pq.verifying_key().map_err(|e| e.to_string())?;
    let key = tenzro_device_key::create(&label).map_err(|e| e.to_string())?;
    let pk = key.public_key().map_err(|e| e.to_string())?;

    Ok(DeviceKeyInfo {
        label: key.label().to_string(),
        public_key_hex: hex::encode(pk),
        ml_dsa_public_key_hex: hex::encode(pq_vk),
        credential_id_hex: hex::encode(credential_id(&label)),
    })
}

fn parse_prehash(prehash_hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(prehash_hex.trim_start_matches("0x"))
        .map_err(|e| format!("prehash not hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("prehash must be 32 bytes, got {}", bytes.len()));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

#[tauri::command]
pub async fn device_sign_with_passkey(
    label: String,
    prehash_hex: String,
) -> Result<String, String> {
    let digest = parse_prehash(&prehash_hex)?;
    let key = tenzro_device_key::open(&label).map_err(|e| e.to_string())?;
    let sig = key.sign_prehash(&digest).map_err(|e| e.to_string())?;
    Ok(hex::encode(sig))
}

/// Both signature legs over one prehash: classical P-256 `r ‖ s`, and
/// the hardware ML-DSA-65 key. Hybrid custody verification needs both.
#[derive(Debug, Serialize)]
pub struct HybridSignature {
    pub p256_signature_hex: String,
    pub ml_dsa_signature_hex: String,
}

#[tauri::command]
pub async fn device_sign_hybrid_with_passkey(
    label: String,
    prehash_hex: String,
) -> Result<HybridSignature, String> {
    let digest = parse_prehash(&prehash_hex)?;
    let key = tenzro_device_key::open(&label).map_err(|e| e.to_string())?;
    let p256_sig = key.sign_prehash(&digest).map_err(|e| e.to_string())?;
    let ml_dsa_sig = sign_pq(&label, &digest)?;

    Ok(HybridSignature {
        p256_signature_hex: hex::encode(p256_sig),
        ml_dsa_signature_hex: hex::encode(ml_dsa_sig),
    })
}

/// The post-quantum leg, signed by the hardware ML-DSA-65 key paired with
/// passkey `label`, under the composite scheme's ML-DSA context.
fn sign_pq(label: &str, message: &[u8]) -> Result<Vec<u8>, String> {
    tenzro_device_key::signer::open_or_create_ml_dsa(&ml_dsa_label(label))
        .and_then(|pq| pq.sign(tenzro_crypto::composite::LABEL_MLDSA65_P256, message))
        .map_err(|e| e.to_string())
}

/// The credential id the enclave key for `label` was enrolled under.
/// Recomputed from the label rather than stored, matching what
/// [`device_create_passkey`] reported at enrollment.
pub(crate) fn credential_id(label: &str) -> [u8; 32] {
    tenzro_device_key::credential_id_for_label(label)
}

/// A started cross-device ceremony. The frontend renders `qr_url`, then
/// calls the completion command with the same `session_id` once it has a
/// challenge.
#[derive(Debug, Serialize)]
pub struct CableSessionStart {
    pub session_id: String,
    pub qr_url: String,
}

#[tauri::command]
pub async fn device_start_cross_device_link(
    cable: tauri::State<'_, std::sync::Arc<crate::cable::CableSessionManager>>,
) -> Result<CableSessionStart, String> {
    let (session_id, qr_url) = cable.start().await.map_err(|e| e.to_string())?;
    Ok(CableSessionStart { session_id, qr_url })
}

#[derive(Debug, Deserialize)]
pub struct CableCompleteRequest {
    pub session_id: String,
    pub challenge_hex: String,
    pub rp_id: String,
    #[serde(default)]
    pub allow_credential_ids_hex: Vec<String>,
}

#[tauri::command]
pub async fn device_complete_cross_device_link(
    cable: tauri::State<'_, std::sync::Arc<crate::cable::CableSessionManager>>,
    request: CableCompleteRequest,
) -> Result<crate::cable::CableAssertion, String> {
    let challenge =
        hex::decode(&request.challenge_hex).map_err(|e| format!("challenge_hex: {}", e))?;

    let mut allow_credential_ids = Vec::with_capacity(request.allow_credential_ids_hex.len());
    for h in &request.allow_credential_ids_hex {
        let bytes = hex::decode(h).map_err(|e| format!("credential id: {}", e))?;
        allow_credential_ids.push(bytes);
    }

    cable
        .complete(
            &request.session_id,
            challenge,
            request.rp_id,
            allow_credential_ids,
        )
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn device_cancel_cross_device_link(
    cable: tauri::State<'_, std::sync::Arc<crate::cable::CableSessionManager>>,
    session_id: String,
) -> Result<(), String> {
    cable.cancel(&session_id).map_err(|e| e.to_string())
}
