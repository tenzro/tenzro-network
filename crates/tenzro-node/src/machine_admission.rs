//! Admission of an autonomous machine: a machine that answers for itself,
//! with no human or institution controller.
//!
//! Such a machine must prove, not claim, that its identity belongs to a key
//! it holds. Admission therefore requires TPM attestation
//! ([`tenzro_tee::tpm_attest::attest_local_machine`]): credential activation
//! proves the attestation key lives in the same TPM as the endorsement key,
//! the machine DID is derived from that attestation key, and a quote by it
//! answers a fresh challenge committing to the DID and the wallet key.
//!
//! Whether a TPM manufacturer certified the endorsement key is not an
//! admission condition: a vendor root in the admission rule would make chip
//! vendors gatekeepers of who may hold an identity. It is recorded as the
//! identity's `tpm_endorsement` grade, a reputation signal relying parties
//! weigh for themselves.
//!
//! The evidence is recorded with the identity, so any node can re-check the
//! quote and the DID derivation without trusting the node that admitted it.

use std::sync::Arc;

use serde_json::Value;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

pub use tenzro_types::did_derivation::MACHINE_WALLET_KEY_LABEL;

fn refused(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: message.into(),
        data: None,
    }
}

/// Register this node's own machine as an autonomous identity. Returns the
/// identity and its registration proof: the machine's hardware key signs the
/// record's registration statement, since the TPM quote names only the DID
/// and that key.
pub(crate) async fn register_autonomous(
    node: &Arc<TenzroNode>,
    params: &Value,
    public_key_bytes: &[u8],
    identity_type: &str,
    capabilities: Vec<String>,
) -> Result<
    (
        tenzro_identity::PendingRegistration,
        tenzro_types::identity::RegistrationProof,
    ),
    JsonRpcError,
> {
    let registry = node
        .identity_registry()
        .ok_or_else(|| refused("Identity registry not initialized"))?;

    let signer = Arc::new(
        tenzro_device_key::HardwareHybridSigner::open_or_create(MACHINE_WALLET_KEY_LABEL).map_err(
            |e| {
                refused(format!(
                    "This machine cannot bind a wallet to its own hardware key: {e}"
                ))
            },
        )?,
    );
    let machine_p256 = {
        use tenzro_crypto::HybridSigner as _;
        signer.public_key().p256.clone()
    };
    if params.get("public_key").is_some() && public_key_bytes != machine_p256 {
        return Err(JsonRpcError {
            code: -32602,
            message: "An autonomous machine identity binds to this machine's own hardware \
                      P-256 key (TPM or Secure Enclave). Remove `public_key`, or supply \
                      that key's public half (x || y)."
                .to_string(),
            data: None,
        });
    }

    let wallet_service = node
        .wallet_service()
        .ok_or_else(|| refused("No wallet service is running"))?;
    let wallet = wallet_service
        .provision_watch_only_wallet(signer.clone())
        .await
        .map_err(|e| refused(format!("Watch-only wallet provisioning failed: {e}")))?;
    let mut addr_bytes = [0u8; 32];
    let src = wallet.address.as_bytes();
    let len = src.len().min(32);
    addr_bytes[..len].copy_from_slice(&src[..len]);
    let binding = tenzro_identity::WalletBinding {
        wallet_id: wallet.wallet_id.to_string(),
        address: tenzro_types::primitives::Address::new(addr_bytes),
        public_key: wallet.public_key.p256.clone(),
        pq_verifying_key: wallet.public_key.pq.clone().unwrap_or_default(),
    };

    if let Some(bound) = crate::rpc::chain_state_of(node)
        .and_then(|chain| tenzro_vm::native::identity_did_of(&chain, binding.address.as_bytes()))
    {
        return Err(refused(already_bound(&bound)));
    }
    let (did_string, mut attestation) = attest(&binding.public_key).await?;
    let roots_pem = crate::rpc::chain_state_of(node)
        .map(|chain| tenzro_vm::native::read_endorsement_roots(&chain))
        .unwrap_or_default();
    complete_endorsement_chain(&mut attestation, &roots_pem).await;
    let did = tenzro_identity::TenzroDid::parse(&did_string)
        .map_err(|e| refused(format!("attested machine DID: {e}")))?;

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("machine_anchor".to_string(), "tpm_attested".to_string());
    metadata.insert(
        "wallet_custody".to_string(),
        "hardware_device_key".to_string(),
    );
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
        serde_json::to_string(&attestation).map_err(|e| refused(e.to_string()))?,
    );
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ENDORSEMENT_KEY.to_string(),
        tenzro_tee::identity_evidence::endorsement_label(&attestation, &roots_pem).to_string(),
    );

    let pending = registry
        .prepare_autonomous_machine_with_binding(did, binding, capabilities, metadata)
        .await
        .map_err(|e| refused(format!("Autonomous machine registration failed: {e}")))?;
    let unsigned = crate::node::identity_register_payload(
        &pending.identity,
        identity_type,
        tenzro_types::identity::RegistrationProof::TpmQuote {
            signature: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        },
    );
    let statement = tenzro_types::identity::registration_statement(&unsigned);
    let signature = {
        use tenzro_crypto::HybridSigner as _;
        signer
            .sign(
                tenzro_crypto::composite::SignatureContext::IdentityRegistration,
                &statement,
            )
            .map_err(|e| refused(format!("signing the machine registration: {e}")))?
    };
    Ok((
        pending,
        tenzro_types::identity::RegistrationProof::TpmQuote { signature },
    ))
}

/// Why an autonomous admission is refused on a machine whose node account
/// already answers for `did`: a machine holds one identity, and a machine
/// root admits its TPM with its own registration.
fn already_bound(did: &str) -> String {
    format!(
        "this machine's node account is already bound to {did}; a machine holds one identity, so its TPM is \
         admitted with that identity, not as a second one (`tenzro validator register-machine` records the \
         TPM attestation on the machine root)"
    )
}

/// Most certificates fetched to complete one EK chain.
const MAX_FETCHED_ISSUERS: usize = 4;
/// Largest issuer certificate accepted from a manufacturer's site.
const MAX_ISSUER_CERT_BYTES: usize = 64 * 1024;

/// Complete the EK certificate chain from the manufacturer's published
/// issuer certificates, when the TPM carries the EK certificate but not the
/// intermediates that lead to a root the network recognises (as Nuvoton
/// parts do). Each step follows the `caIssuers` URL of the topmost
/// certificate; a fetched certificate becomes evidence only through
/// [`tenzro_tee::tpm_attest::verify_endorsement`], which checks every
/// signature up to the governed roots, so a wrong or hostile download can
/// only leave the machine graded uncertified. A self-issued certificate is
/// never added: roots come from governance, not from a vendor's website.
async fn complete_endorsement_chain(
    attestation: &mut tenzro_tee::tpm_attest::MachineAttestation,
    roots_pem: &[String],
) {
    use tenzro_tee::tpm_attest::missing_issuer_url;
    if attestation.evidence.ek_certificate.is_empty() {
        return;
    }
    let Ok(roots) = tenzro_tee::tpm_attest::parse_roots(roots_pem) else {
        return;
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    else {
        return;
    };
    for _ in 0..MAX_FETCHED_ISSUERS {
        let Some(url) = missing_issuer_url(&attestation.evidence, &roots) else {
            return;
        };
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            tracing::warn!(%url, "EK issuer URL is not HTTP(S); chain left as the TPM holds it");
            return;
        }
        let der = match fetch_issuer(&client, &url).await {
            Ok(der) => der,
            Err(e) => {
                tracing::warn!(%url, "fetching the EK issuer certificate: {e}");
                return;
            }
        };
        match tenzro_tee::x509::parse(&der) {
            Ok(cert) if cert.subject_der != cert.issuer_der => {
                attestation.evidence.ek_intermediates.push(der);
            }
            Ok(_) => return,
            Err(e) => {
                tracing::warn!(%url, "EK issuer certificate does not parse: {e}");
                return;
            }
        }
    }
}

/// One issuer certificate, DER or PEM, size-capped.
async fn fetch_issuer(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_ISSUER_CERT_BYTES {
            return Err("certificate larger than any issuer certificate".into());
        }
    }
    if body.starts_with(b"-----BEGIN") {
        let pem = String::from_utf8(body).map_err(|e| e.to_string())?;
        let certs = tenzro_tee::x509::parse_pem_chain(&pem).map_err(|e| e.to_string())?;
        return certs
            .into_iter()
            .next()
            .map(|c| c.der)
            .ok_or_else(|| "no certificate in the PEM".into());
    }
    Ok(body)
}

#[cfg(any(target_os = "linux", windows))]
async fn attest(
    wallet_public_key: &[u8],
) -> Result<(String, tenzro_tee::tpm_attest::MachineAttestation), JsonRpcError> {
    let key = wallet_public_key.to_vec();
    tokio::task::spawn_blocking(move || tenzro_tee::tpm_attest::attest_local_machine(&key))
        .await
        .map_err(|e| refused(format!("TPM attestation task failed: {e}")))?
        .map_err(|e| {
            refused(format!(
                "TPM attestation failed, so this machine is not admitted: {e}"
            ))
        })
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn attest(
    _wallet_public_key: &[u8],
) -> Result<(String, tenzro_tee::tpm_attest::MachineAttestation), JsonRpcError> {
    Err(refused(
        "autonomous admission needs a Linux TPM 2.0 resource manager (/dev/tpmrm0)",
    ))
}

/// The registry's check for a TPM-attested machine identity it did not
/// admit itself: the recorded quote must be by the attestation key the DID
/// derives from, vouching for the identity's registered key.
pub(crate) fn evidence_holds(identity: &tenzro_identity::TenzroIdentity) -> bool {
    let metadata: std::collections::BTreeMap<String, String> = identity
        .metadata
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let did = identity.did.to_string();
    identity.public_keys.first().is_some_and(|k| {
        tenzro_tee::identity_evidence::registration_binding_holds(&did, &k.public_key, &metadata)
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_second_identity_for_one_machine_is_refused_by_name() {
        let msg = super::already_bound("did:tenzro:machine:root");
        assert!(
            msg.contains("already bound to did:tenzro:machine:root"),
            "{msg}"
        );
        assert!(msg.contains("register-machine"), "{msg}");
    }
}
