//! The CLI's own client account, keyed by this machine's hardware.
//!
//! A self-custody runner signs its own transactions and never hands a key to a
//! node. The account key is the machine's own non-exportable P-256 key in its
//! TPM or Secure Enclave, under the client's key namespace, with the hardware
//! ML-DSA-65 key beside it where the hardware implements ML-DSA. No key is
//! ever generated in software, stored or sealed, so there is nothing on disk
//! to steal and nothing to unlock. A machine with neither a TPM nor a Secure
//! Enclave is refused rather than given a software key.

use anyhow::{Result, anyhow};

/// The identity this CLI invocation acts as, from the persisted config.
pub fn active_did() -> String {
    crate::config::load_config()
        .did
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "anonymous".to_string())
}

/// Where a delegated validator's keys are: the key holder beside its node.
///
/// A validator whose machine has no TPM of its own keeps its keys in another
/// machine's TPM, reached through `tenzro-node tpm key-holder` on a local
/// socket under a grant the operator's passkey made. The node starts with
/// `--tpm-key-holder` and `--tpm-label`; a command that signs as that node
/// takes the same two (and the same environment variables), and from then on
/// every key it opens, the identity key and the node account alike, signs
/// through the holder exactly as the node's own transactions do.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct DelegatedKey {
    /// The node's key holder socket (`tenzro-node tpm key-holder`), when the
    /// node's keys are in another machine's TPM
    #[arg(long, value_name = "SOCKET", env = "TENZRO_TPM_KEY_HOLDER")]
    pub tpm_key_holder: Option<std::path::PathBuf>,

    /// The key label the provider enrolled for this machine
    #[arg(long, value_name = "LABEL", env = "TENZRO_TPM_LABEL")]
    pub tpm_label: Option<String>,
}

static DELEGATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this process signs through a key holder instead of a local TPM.
pub fn key_is_delegated() -> bool {
    DELEGATED.load(std::sync::atomic::Ordering::Acquire)
}

impl DelegatedKey {
    /// Routes every hardware key this process opens to the key holder.
    /// Returns whether the keys are delegated. Call before any key is opened.
    pub fn install(&self) -> Result<bool> {
        match (&self.tpm_key_holder, &self.tpm_label) {
            (None, None) => Ok(false),
            (Some(socket), Some(label)) => {
                tenzro_device_key::remote::use_key_holder(label, socket)
                    .map_err(|e| anyhow!("the key holder at {}: {e}", socket.display()))?;
                DELEGATED.store(true, std::sync::atomic::Ordering::Release);
                Ok(true)
            }
            _ => Err(anyhow!(
                "--tpm-key-holder and --tpm-label go together: the socket of the key holder and \
                 the key label the provider enrolled for this machine"
            )),
        }
    }
}

/// The client account under `namespace`, as `0x` hex, and its composite public
/// key.
/// A 32-byte account address from its `0x`-prefixed or bare hex form.
pub fn address32(addr: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(addr.trim().trim_start_matches("0x"))
        .map_err(|e| anyhow!("address {addr}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("address {addr} is not 32 bytes"))
}

/// Pauses between attempts to open a hardware key the TPM was too busy to open. The node on the
/// same machine uses the same chip, so a command usually only has to wait for its turn.
const TPM_PAUSES: &[std::time::Duration] = &[
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(4),
];

/// Whether a hardware-key error says the TPM was busy or slow to answer, not that it is broken.
fn tpm_contended(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    ["tpm busy", "timed out", "timeout", "0x17d", "retry"]
        .iter()
        .any(|t| m.contains(t))
}

/// Runs `open`, trying again after each of `pauses` while the failure is TPM contention. The
/// last error is returned in plain words, naming the node that shares the chip.
fn retry_while_contended<T, E: std::fmt::Display>(
    mut open: impl FnMut() -> std::result::Result<T, E>,
    pauses: &[std::time::Duration],
) -> std::result::Result<T, String> {
    let mut tries = 0;
    loop {
        match open() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let msg = e.to_string();
                if !tpm_contended(&msg) {
                    return Err(msg);
                }
                match pauses.get(tries) {
                    Some(pause) => {
                        if tries == 0 {
                            eprintln!(
                                "The TPM is busy (a node on this machine may be using it); trying again for a few seconds."
                            );
                        }
                        std::thread::sleep(*pause);
                        tries += 1;
                    }
                    None => {
                        return Err(format!(
                            "the TPM stayed busy after {} tries ({msg}). A node running on this machine uses the same chip; wait a minute and run the command again",
                            tries + 1
                        ));
                    }
                }
            }
        }
    }
}

/// Opens the hardware key `label`, waiting out TPM contention.
fn open_hybrid(
    label: &str,
) -> std::result::Result<tenzro_device_key::HardwareHybridSigner, String> {
    retry_while_contended(
        || tenzro_device_key::HardwareHybridSigner::open_or_create(label),
        TPM_PAUSES,
    )
}

/// The hardware signer for the client account under `namespace`.
pub(crate) fn client_signer(namespace: &str) -> Result<tenzro_device_key::HardwareHybridSigner> {
    open_hybrid(&format!("client/{namespace}"))
        .map_err(|e| anyhow!("the client account's hardware key: {e}"))
}

/// Selects node `ns`'s hardware key namespace for this process. The client's
/// DPoP key is the machine's, not a node's: when this process holds an access
/// session, that key is opened first, as `access sign-in` does, so the
/// session's requests keep proving with the key its token binds.
fn select_node_namespace(ns: &str) -> Result<()> {
    if crate::rpc::session_token().is_some() && crate::dpop::DpopKey::exists() {
        crate::dpop::DpopKey::load_or_create()?;
    }
    tenzro_device_key::set_label_namespace(ns).map_err(|e| anyhow!("node key namespace: {e}"))
}

/// The hardware signer for this machine's node account: the wallet key a
/// node earns into and a genesis validator entry bonds from. `namespace` is
/// the node's `hardware_key_namespace`; `None` is the machine's default node.
/// Selecting a namespace applies to every hardware key this process opens
/// afterwards, as it does in the node.
fn node_signer(namespace: Option<&str>) -> Result<tenzro_device_key::HardwareHybridSigner> {
    if let Some(ns) = namespace {
        select_node_namespace(ns)?;
    }
    open_hybrid(tenzro_types::did_derivation::MACHINE_WALLET_KEY_LABEL)
        .map_err(|e| anyhow!("the node account's hardware key: {e}"))
}

/// This machine's identity key, the one its machine DID derives from (the
/// node's consensus key). `namespace` is the node's `hardware_key_namespace`;
/// `None` is the machine's default node.
pub fn machine_identity_signer(
    namespace: Option<&str>,
) -> Result<tenzro_device_key::HardwareHybridSigner> {
    if let Some(ns) = namespace {
        select_node_namespace(ns)?;
    }
    open_hybrid(tenzro_types::did_derivation::MACHINE_KEY_LABEL)
        .map_err(|e| anyhow!("the machine's identity key: {e}"))
}

/// The node account of this machine (see [`node_signer`]).
pub fn node_account(namespace: Option<&str>) -> Result<[u8; 32]> {
    use tenzro_crypto::composite::HybridSigner;
    Ok(node_signer(namespace)?.public_key().account_slot())
}

/// The `RegisterIdentity` transaction of the autonomous machine whose identity
/// key `signer` holds, paying to `wallet`: the machine DID that key derives,
/// with the registration statement signed by that key. Returns the DID and
/// the transaction payload; anyone may submit it.
pub fn machine_identity_registration(
    signer: &tenzro_device_key::HardwareHybridSigner,
    wallet: [u8; 32],
) -> Result<(String, serde_json::Value)> {
    hardware_identity_registration(signer, wallet, "machine root", true)
}

/// The `RegisterIdentity` transaction of the client account under
/// `namespace`: the machine DID that the account's hardware key derives, with
/// the account as its wallet and the registration statement signed by that
/// key. No TPM attestation is recorded, so the machine's TPM stays free for
/// the machine root of a node on it. Returns the DID, the account and the
/// transaction payload; the account submits it and pays the gas.
pub fn client_identity_registration(
    namespace: &str,
    display_name: &str,
) -> Result<(String, [u8; 32], serde_json::Value)> {
    use tenzro_crypto::composite::HybridSigner;
    let signer = client_signer(namespace)?;
    let account = signer.public_key().account_slot();
    let (did, register) = hardware_identity_registration(&signer, account, display_name, false)?;
    Ok((did, account, register))
}

/// The `RegisterIdentity` transaction of the machine DID that the key of
/// `signer` derives, paying to `wallet` and signed by that key. With `attest`
/// it records the machine's TPM attestation, which admits the TPM under this
/// identity and no other.
fn hardware_identity_registration(
    signer: &tenzro_device_key::HardwareHybridSigner,
    wallet: [u8; 32],
    display_name: &str,
    attest: bool,
) -> Result<(String, serde_json::Value)> {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    let public = signer.public_key().clone();
    let sec1 = [&[0x04u8][..], &public.p256].concat();
    let did = tenzro_types::did_derivation::machine_did(&sec1);
    let metadata = if attest {
        machine_attestation_metadata(&did, &sec1)?
    } else {
        std::collections::BTreeMap::new()
    };
    let mut payload = tenzro_types::identity::RegisterIdentityPayload {
        did: did.clone(),
        identity_type: "machine".into(),
        display_name: display_name.into(),
        controller_pubkey: sec1,
        key_type: "P-256".into(),
        wallet_id: format!("0x{}", hex::encode(wallet)),
        wallet_address: tenzro_types::primitives::Address::new(wallet),
        pq_verifying_key: public.pq.clone().unwrap_or_default(),
        metadata,
        proof: tenzro_types::identity::RegistrationProof::Hardware {
            signature: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        },
    };
    let statement = tenzro_types::identity::registration_statement(&payload);
    let signature = signer
        .sign(SignatureContext::IdentityRegistration, &statement)
        .map_err(|e| anyhow!("signing the identity registration: {e}"))?;
    payload.proof = tenzro_types::identity::RegistrationProof::Hardware {
        signature: serde_json::from_value(serde_json::to_value(&signature)?)?,
    };
    let tx = tenzro_types::transaction::TransactionType::RegisterIdentity {
        did: payload.did,
        identity_type: payload.identity_type,
        display_name: payload.display_name,
        controller_pubkey: payload.controller_pubkey,
        key_type: payload.key_type,
        wallet_id: payload.wallet_id,
        wallet_address: payload.wallet_address,
        pq_verifying_key: payload.pq_verifying_key,
        metadata: payload.metadata,
        proof: payload.proof,
    };
    Ok((did, serde_json::to_value(&tx)?))
}

/// The TPM attestation a machine root records with its registration:
/// credential activation and a quote over the admission challenge for `did`
/// and its identity key, so the chain admits the TPM under the machine's one
/// identity (a serving node's key certifications count only from an admitted
/// TPM).
#[cfg(any(target_os = "linux", windows))]
fn machine_attestation_metadata(
    did: &str,
    identity_key: &[u8],
) -> Result<std::collections::BTreeMap<String, String>> {
    // A delegated validator's identity key is in the provider's TPM, not in
    // this machine's: this machine's TPM (if it has one) is not the key's
    // hardware, so it cannot attest for it, and attesting a different TPM
    // would admit the wrong one under this identity. Register without a TPM
    // attestation, as a Secure Enclave machine does.
    if key_is_delegated() {
        return Ok(std::collections::BTreeMap::new());
    }
    let (_, att) = tenzro_tee::tpm_attest::attest_local_machine_as(Some(did), identity_key)
        .map_err(|e| anyhow!("attesting this machine's TPM for {did}: {e}"))?;
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("machine_anchor".to_string(), "tpm_attested".to_string());
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
        serde_json::to_string(&att)?,
    );
    Ok(metadata)
}

/// A Secure Enclave has no attestation for the machine root to record.
#[cfg(not(any(target_os = "linux", windows)))]
fn machine_attestation_metadata(
    _did: &str,
    _identity_key: &[u8],
) -> Result<std::collections::BTreeMap<String, String>> {
    Ok(std::collections::BTreeMap::new())
}

/// The machine root DID the identity key `signer` holds derives.
pub fn machine_root_did(signer: &tenzro_device_key::HardwareHybridSigner) -> String {
    use tenzro_crypto::composite::HybridSigner;
    let sec1 = [&[0x04u8][..], &signer.public_key().p256].concat();
    tenzro_types::did_derivation::machine_did(&sec1)
}

/// Whether a resolved identity record carries a TPM attestation.
pub fn carries_tpm_attestation(record: &serde_json::Value) -> bool {
    record
        .get("metadata")
        .and_then(|m| m.get(tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY))
        .is_some()
}

/// The `AttachMachineAttestation` transaction for the machine root whose
/// identity key `signer` holds, sent by its wallet `wallet` at account nonce
/// `account_nonce`: this machine's TPM runs credential activation and quotes
/// the admission challenge for the DID and identity key whose nonce is the
/// chain challenge of that account nonce, and the identity key signs the
/// attach.
#[cfg(any(target_os = "linux", windows))]
pub fn machine_attestation_attachment(
    signer: &tenzro_device_key::HardwareHybridSigner,
    wallet: [u8; 32],
    account_nonce: u64,
) -> Result<serde_json::Value> {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    if key_is_delegated() {
        return Err(anyhow!(
            "this validator's keys are in another machine's TPM, so this machine cannot attest \
             for them; the TPM attestation is attached from the machine that owns the TPM"
        ));
    }
    let sec1 = [&[0x04u8][..], &signer.public_key().p256].concat();
    let did = tenzro_types::did_derivation::machine_did(&sec1);
    let nonce = tenzro_types::identity::attach_attestation_nonce(&did, &wallet, account_nonce);
    let (_, att) =
        tenzro_tee::tpm_attest::attest_local_machine_over(Some(&did), &sec1, Some(nonce))
            .map_err(|e| anyhow!("attesting this machine's TPM for {did}: {e}"))?;
    let attestation = serde_json::to_string(&att)?;
    let statement = tenzro_types::identity::attach_attestation_statement(&did, &attestation);
    let signature = signer
        .sign(SignatureContext::IdentityRegistration, &statement)
        .map_err(|e| anyhow!("signing the attestation attach: {e}"))?;
    let op = tenzro_types::identity::AttachMachineAttestationOp {
        did,
        attestation,
        signature: serde_json::from_value(serde_json::to_value(&signature)?)?,
    };
    Ok(serde_json::to_value(
        tenzro_types::transaction::TransactionType::AttachMachineAttestation { op },
    )?)
}

/// A Secure Enclave has no TPM attestation to attach.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn machine_attestation_attachment(
    _signer: &tenzro_device_key::HardwareHybridSigner,
    _wallet: [u8; 32],
    _account_nonce: u64,
) -> Result<serde_json::Value> {
    Err(anyhow!(
        "a TPM attestation is attached from a machine with a TPM (Linux or Windows)"
    ))
}

/// Whether `did` resolves on the node at `rpc`.
pub async fn identity_registered(rpc: &crate::rpc::RpcClient, did: &str) -> bool {
    rpc.call::<serde_json::Value>("tenzro_resolveIdentity", serde_json::json!({ "did": did }))
        .await
        .is_ok()
}

/// Waits up to two minutes for `did` to resolve.
pub async fn await_identity(rpc: &crate::rpc::RpcClient, did: &str) -> Result<()> {
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if identity_registered(rpc, did).await {
            return Ok(());
        }
    }
    Err(anyhow!("{did} was not registered within two minutes"))
}

/// A machine root's approval of its validator's governance ballot: this
/// machine's identity key, the one its machine DID derives from, signs the
/// custody challenge for the ballot on the network `chain_id`. `namespace`
/// is the node's `hardware_key_namespace`; `None` is the machine's default
/// node.
pub fn machine_root_ballot(
    namespace: Option<&str>,
    chain_id: u64,
    proposal_id: &[u8; 32],
    vote: bool,
    validator: &[u8],
) -> Result<tenzro_types::agent_terms::AgentTermsApproval> {
    use tenzro_types::agent_terms::{OP_ROOT_BALLOT, governance_vote_target};
    let target = governance_vote_target(proposal_id, vote, validator);
    machine_root_approval(namespace, chain_id, OP_ROOT_BALLOT, &target, validator)
}

/// A machine root's approval of the custody operation `op` over `target`:
/// this machine's identity key, the one its machine DID derives from, signs
/// the custody challenge naming `account` on the network `chain_id`.
pub fn machine_root_approval(
    namespace: Option<&str>,
    chain_id: u64,
    op: &[u8],
    target: &[u8],
    account: &[u8],
) -> Result<tenzro_types::agent_terms::AgentTermsApproval> {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_types::agent_terms::custody_challenge_digest;
    let signer = machine_identity_signer(namespace)?;
    let nonce: [u8; 16] = rand::random();
    let digest = custody_challenge_digest(chain_id, account, op, target, &nonce);
    let signature = signer
        .sign(SignatureContext::AccountOwner, &digest)
        .map_err(|e| anyhow!("signing the approval: {e}"))?;
    Ok(tenzro_types::agent_terms::AgentTermsApproval {
        account: account.to_vec(),
        nonce,
        root_public_key: signer.public_key().p256.clone(),
        signature,
    })
}

pub fn client_account(
    namespace: &str,
) -> Result<(String, tenzro_crypto::composite::CompositePublicKey)> {
    use tenzro_crypto::composite::HybridSigner;
    let public = client_signer(namespace)?.public_key().clone();
    Ok((format!("0x{}", hex::encode(public.account_slot())), public))
}

/// The fields a request signed by its owner carries (`timestamp_ms`, the
/// P-256 `public_key` and the composite `signature`), signed as the client account under
/// `namespace`. The node checks them against the domain-separated message
/// naming `method` over `canonical` and the timestamp.
pub fn sign_owner_request(
    namespace: &str,
    method: &str,
    canonical: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>> {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};

    let signer = client_signer(namespace)?;
    let timestamp_ms = chrono::Utc::now().timestamp_millis();
    let mut message = b"tenzro/rpc-owner/v1\0".to_vec();
    message.extend_from_slice(method.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical);
    message.extend_from_slice(&timestamp_ms.to_le_bytes());
    let sig = signer
        .sign(SignatureContext::AccountOwner, &message)
        .map_err(|e| anyhow!("signing the request: {e}"))?;
    let public = signer.public_key();
    let mut fields = serde_json::Map::new();
    fields.insert("timestamp_ms".into(), timestamp_ms.into());
    fields.insert("public_key".into(), hex::encode(&public.p256).into());
    fields.insert("signature".into(), serde_json::to_value(&sig)?);
    Ok(fields)
}

/// A composite signature by the client account under `namespace` over
/// `message` in `context`, with the P-256 public key (`x || y`, hex) that
/// verifies it.
pub fn sign_composite(
    namespace: &str,
    context: tenzro_crypto::composite::SignatureContext,
    message: &[u8],
) -> Result<(String, serde_json::Value)> {
    use tenzro_crypto::composite::HybridSigner;
    let signer = client_signer(namespace)?;
    let sig = signer
        .sign(context, message)
        .map_err(|e| anyhow!("signing: {e}"))?;
    Ok((
        hex::encode(&signer.public_key().p256),
        serde_json::to_value(&sig)?,
    ))
}

/// A plain ECDSA P-256 signature (`r || s` over SHA-256 of `message`) by the
/// client account's hardware key under `namespace`, with its uncompressed
/// SEC1 public key and the hardware it lives in.
pub fn sign_p256(
    namespace: &str,
    message: &[u8],
) -> Result<([u8; 65], [u8; 64], tenzro_device_key::HardwareBackend)> {
    let key = tenzro_device_key::signer::open_or_create(&format!("client/{namespace}"))
        .map_err(|e| anyhow!("the client account's hardware key: {e}"))?;
    let public = key
        .public_key_sec1()
        .map_err(|e| anyhow!("reading the hardware key: {e}"))?;
    let sig = key.sign(message).map_err(|e| anyhow!("signing: {e}"))?;
    Ok((public, sig, key.backend()))
}

/// A DID envelope, as its hex header value, signed by the client account
/// under `namespace` for `did`, authorizing `method` over `canonical`.
pub fn did_envelope(namespace: &str, did: &str, method: &str, canonical: &[u8]) -> Result<String> {
    did_envelope_by(&client_signer(namespace)?, did, method, canonical)
}

/// A DID envelope, as its hex header value, signed by `signer` (the key `did`
/// resolves to) authorizing `method` over `canonical`.
pub fn did_envelope_by(
    signer: &impl tenzro_crypto::composite::HybridSigner,
    did: &str,
    method: &str,
    canonical: &[u8],
) -> Result<String> {
    use tenzro_crypto::composite::SignatureContext;
    use tenzro_identity::envelope::{TenzroDidEnvelope, canonical_preimage, params_hash};
    let mut env = TenzroDidEnvelope {
        did: did.to_string(),
        method: method.to_string(),
        params_hash: params_hash(canonical),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
        nonce: rand::random(),
        signature: Vec::new(),
    };
    let sig = signer
        .sign(SignatureContext::DidEnvelope, &canonical_preimage(&env))
        .map_err(|e| anyhow!("signing the envelope: {e}"))?;
    env.signature = serde_json::to_vec(&sig)?;
    Ok(env.to_header_value())
}

/// A cumulative voucher on the channel over `escrow_id`, signed as the client
/// account under `namespace` (the escrow's payer), bound to `binding`: the
/// head of the receipt chain it pays for, all zero for a voucher signed
/// ahead of delivery.
pub fn sign_voucher(
    namespace: &str,
    chain_id: u64,
    escrow_id: [u8; 32],
    cumulative_amount: u128,
    binding: [u8; 32],
) -> Result<tenzro_types::payment_authorization::EscrowVoucher> {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_types::payment_authorization::{EscrowVoucher, escrow_voucher_preimage};

    let signer = client_signer(namespace)?;
    let sig = signer
        .sign(
            SignatureContext::EscrowVoucher,
            &escrow_voucher_preimage(chain_id, &escrow_id, cumulative_amount, &binding),
        )
        .map_err(|e| anyhow!("signing the voucher: {e}"))?;
    let public = signer.public_key();
    Ok(EscrowVoucher {
        binding,
        agent: None,
        escrow_id,
        cumulative_amount,
        public_key: public.p256.clone(),
        signature: sig,
        attribution: None,
    })
}

/// A `payment` object authorizing up to `max_amount` TNZO from the client
/// account under `namespace` to `payee`, under `payment_id`, as the node's
/// payment-taking RPCs read it (`{payer, payment_id, authorization}`).
pub fn sign_payment(
    namespace: &str,
    chain_id: u64,
    payment_id: &str,
    payee: &tenzro_types::primitives::Address,
    max_amount: u128,
    binding: &tenzro_types::payment_authorization::PaymentBinding,
) -> Result<serde_json::Value> {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_types::payment_authorization::{
        PaymentAuthorization, payment_authorization_preimage,
    };

    let signer = client_signer(namespace)?;
    let public = signer.public_key();
    let payer = tenzro_types::primitives::Address::new(public.account_slot());
    let sig = signer
        .sign(
            SignatureContext::PaymentAuthorization,
            &payment_authorization_preimage(
                chain_id, payment_id, &payer, payee, max_amount, "TNZO", binding,
            ),
        )
        .map_err(|e| anyhow!("signing the payment: {e}"))?;
    let authorization = PaymentAuthorization {
        resellers: Vec::new(),
        binding: *binding,
        public_key: public.p256.clone(),
        signature: sig,
        max_amount,
        asset: "TNZO".to_string(),
    };
    Ok(serde_json::json!({
        "payer": format!("0x{}", hex::encode(payer.as_bytes())),
        "payment_id": payment_id,
        "authorization": authorization,
    }))
}

/// Signs a transaction as the client account under `namespace` and submits
/// it pre-signed with `tenzro_sendRawTransaction`; the node never signs for it.
/// `tx_type` is the transaction's typed payload as the node's JSON encodes
/// it. Returns the node's answer.
pub async fn send_as_client(
    rpc: &crate::rpc::RpcClient,
    namespace: &str,
    to: [u8; 32],
    tx_type: serde_json::Value,
    gas_limit: u64,
) -> Result<serde_json::Value> {
    Ok(send_signed(
        rpc,
        &client_signer(namespace)?,
        SEND_RAW,
        to,
        tx_type,
        gas_limit,
    )
    .await?
    .0)
}

/// [`send_as_client`] that also returns the nonce the transaction took.
pub async fn send_as_client_with_nonce(
    rpc: &crate::rpc::RpcClient,
    namespace: &str,
    to: [u8; 32],
    tx_type: serde_json::Value,
    gas_limit: u64,
) -> Result<(serde_json::Value, u64)> {
    send_signed(
        rpc,
        &client_signer(namespace)?,
        SEND_RAW,
        to,
        tx_type,
        gas_limit,
    )
    .await
}

/// Signs a transaction as this machine's node account (see [`node_signer`])
/// and submits it pre-signed. Returns the node's answer and the sender.
pub async fn send_as_node(
    rpc: &crate::rpc::RpcClient,
    namespace: Option<&str>,
    to: [u8; 32],
    tx_type: serde_json::Value,
    gas_limit: u64,
) -> Result<(serde_json::Value, String)> {
    use tenzro_crypto::composite::HybridSigner;
    let signer = node_signer(namespace)?;
    let from = format!("0x{}", hex::encode(signer.public_key().account_slot()));
    Ok((
        send_signed(rpc, &signer, SEND_RAW, to, tx_type, gas_limit)
            .await?
            .0,
        from,
    ))
}

/// [`send_as_node`] for a transaction built from the account nonce (the
/// caller reads it, builds, and retries the whole thing with
/// [`retry_stale_nonce`]): sent once, with the nonce read afresh, and never
/// resent here with a payload that answers an older nonce.
pub async fn send_as_node_once(
    rpc: &crate::rpc::RpcClient,
    namespace: Option<&str>,
    to: [u8; 32],
    tx_type: serde_json::Value,
    gas_limit: u64,
) -> Result<(serde_json::Value, String)> {
    use tenzro_crypto::composite::HybridSigner;
    let signer = node_signer(namespace)?;
    let from = format!("0x{}", hex::encode(signer.public_key().account_slot()));
    let (answer, _) = submit_signed(rpc, &signer, SEND_RAW, to, tx_type, gas_limit).await?;
    Ok((answer, from))
}

/// The method every pre-signed transaction is submitted through, but a
/// revocation (see [`send_revocation`]).
const SEND_RAW: &str = "tenzro_sendRawTransaction";

/// Signs a `RevokeIdentity` transaction carrying `op` as the client account
/// under `namespace` and submits it with `tenzro_revokeIdentity`, which
/// checks the root's approval inside `op` before admitting it. Any account
/// may send a revocation; the approval is what authorises it.
pub async fn send_revocation(
    rpc: &crate::rpc::RpcClient,
    namespace: &str,
    op: &tenzro_types::identity::IdentityRevocationOp,
    gas_limit: u64,
) -> Result<serde_json::Value> {
    let tx_type =
        serde_json::to_value(tenzro_types::transaction::TransactionType::RevokeIdentity {
            op: op.clone(),
        })?;
    Ok(send_signed(
        rpc,
        &client_signer(namespace)?,
        "tenzro_revokeIdentity",
        [0u8; 32],
        tx_type,
        gas_limit,
    )
    .await?
    .0)
}

/// Gas a revocation is sent with unless the caller names more: the root's
/// approval check and room for the agents a root revocation reaches.
pub const DEFAULT_REVOCATION_GAS: u64 = 1_000_000;

/// Signs a `ContractDeploy` transaction carrying `tx_type` as the client
/// account under `namespace` and submits it with `tenzro_deployContract`,
/// which admits only a contract deployment.
pub async fn send_deployment(
    rpc: &crate::rpc::RpcClient,
    namespace: &str,
    to: [u8; 32],
    tx_type: serde_json::Value,
    gas_limit: u64,
) -> Result<serde_json::Value> {
    Ok(send_signed(
        rpc,
        &client_signer(namespace)?,
        "tenzro_deployContract",
        to,
        tx_type,
        gas_limit,
    )
    .await?
    .0)
}

/// What a node answers when an account that has not enrolled an ML-DSA-65
/// key sends a transaction carrying that leg.
const NOT_ENROLLED: &str = "no ML-DSA-65 key enrolled";

/// Enroll the hardware's ML-DSA-65 key as the post-quantum key of the account
/// `signer` names, with one `AccountKeys` transaction signed with both legs.
/// Returns the node's answer.
pub async fn enroll_pq_key(
    rpc: &crate::rpc::RpcClient,
    signer: &tenzro_device_key::HardwareHybridSigner,
) -> Result<serde_json::Value> {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_types::account_signature::{AccountKeysOp, pq_enrollment_message};

    let public = signer.public_key().clone();
    let key = public.pq.clone().ok_or_else(|| {
        anyhow!("this machine's hardware holds no ML-DSA-65 key to enroll for the account")
    })?;
    let possession = signer
        .sign(
            SignatureContext::PqKeyEnrollment,
            &pq_enrollment_message(&public.account_slot(), &key),
        )
        .map_err(|e| anyhow!("signing the proof of possession: {e}"))?
        .pq
        .ok_or_else(|| anyhow!("the hardware did not sign with its ML-DSA-65 key"))?;
    let op = serde_json::to_value(tenzro_types::transaction::TransactionType::AccountKeys {
        op: AccountKeysOp::EnrollPqKey {
            ml_dsa_public_key: key,
            possession,
        },
    })?;
    submit_signed(
        rpc,
        signer,
        SEND_RAW,
        public.account_slot(),
        op,
        crate::commands::signer::DEFAULT_TX_GAS,
    )
    .await
    .map(|(answer, _)| answer)
}

/// Enroll the client account under `namespace` (see [`enroll_pq_key`]).
pub async fn enroll_client_pq_key(
    rpc: &crate::rpc::RpcClient,
    namespace: &str,
) -> Result<serde_json::Value> {
    enroll_pq_key(rpc, &client_signer(namespace)?).await
}

/// How long the CLI waits for a transaction it submitted to be executed.
pub const RECEIPT_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The hash a node answered a submitted transaction with.
pub fn submitted_hash(answer: &serde_json::Value) -> Option<String> {
    answer
        .as_str()
        .or_else(|| answer.get("tx_hash").and_then(|v| v.as_str()))
        .filter(|hash| !hash.is_empty())
        .map(str::to_string)
}

/// What a receipt says of its transaction: `Ok` when it took effect, the
/// reason it reverted otherwise.
pub fn receipt_outcome(receipt: &serde_json::Value) -> std::result::Result<(), String> {
    if receipt.get("status").and_then(|v| v.as_str()) == Some("0x1") {
        return Ok(());
    }
    Err(receipt
        .get("revertReason")
        .and_then(|v| v.as_str())
        .filter(|reason| !reason.is_empty())
        .unwrap_or("the node recorded no reason")
        .to_string())
}

/// The error text for the transaction `tx_hash` that was executed and
/// reverted for `reason`. An account with no identity on chain is told how
/// to register one.
pub fn revert_message(tx_hash: &str, reason: &str) -> String {
    let mut text = format!("transaction {tx_hash} was executed and reverted: {reason}");
    if reason.contains("has no registered identity") {
        text.push_str(
            "\nThe sending account has no identity on chain. Register it once with \
             `tenzro identity register-account` (the same --key-namespace and --rpc), then \
             send again. A person's passkey account registers with `tenzro identity register`.",
        );
    }
    text
}

/// Waits up to `wait` for the transaction `tx_hash` to be executed. Returns
/// its receipt, `None` when it was in no block by then, and an error naming
/// the reason when it was executed and reverted.
pub async fn await_receipt(
    rpc: &crate::rpc::RpcClient,
    tx_hash: &str,
    wait: std::time::Duration,
) -> Result<Option<serde_json::Value>> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let receipt: serde_json::Value = rpc
            .call("eth_getTransactionReceipt", serde_json::json!([tx_hash]))
            .await?;
        if !receipt.is_null() {
            return match receipt_outcome(&receipt) {
                Ok(()) => Ok(Some(receipt)),
                Err(reason) => Err(anyhow!(revert_message(tx_hash, &reason))),
            };
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Waits for the key enrolment a node answered with `answer` to be executed,
/// so the transaction that follows it is checked against the enrolled key.
async fn await_enrollment(rpc: &crate::rpc::RpcClient, answer: &serde_json::Value) -> Result<()> {
    let hash = submitted_hash(answer).ok_or_else(|| {
        anyhow!("the node answered the key enrolment without a transaction hash: {answer}")
    })?;
    match await_receipt(rpc, &hash, RECEIPT_WAIT).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(anyhow!(
            "the key enrolment {hash} was in no block after {} seconds; send again once it is",
            RECEIPT_WAIT.as_secs()
        )),
        Err(e) => Err(anyhow!("enrolling the account's ML-DSA-65 key: {e}")),
    }
}

/// Sign and submit; an account that has not enrolled its ML-DSA-65 key is
/// enrolled first and the transaction sent again once the enrolment has been
/// executed, so a new account is never left unable to send.
async fn send_signed(
    rpc: &crate::rpc::RpcClient,
    signer: &tenzro_device_key::HardwareHybridSigner,
    method: &str,
    to: [u8; 32],
    tx_type: serde_json::Value,
    gas_limit: u64,
) -> Result<(serde_json::Value, u64)> {
    let first = submit_fresh(rpc, signer, method, to, &tx_type, gas_limit).await;
    match first {
        Err(e) if e.to_string().contains(NOT_ENROLLED) && tx_type.get("AccountKeys").is_none() => {
            eprintln!("  enrolling the account's ML-DSA-65 key first");
            let enrolled = enroll_pq_key(rpc, signer).await?;
            await_enrollment(rpc, &enrolled).await?;
            submit_fresh(rpc, signer, method, to, &tx_type, gas_limit).await
        }
        other => other,
    }
}

/// [`submit_signed`], sent again with a freshly read nonce when the node
/// refuses the nonce it was signed with.
async fn submit_fresh(
    rpc: &crate::rpc::RpcClient,
    signer: &tenzro_device_key::HardwareHybridSigner,
    method: &str,
    to: [u8; 32],
    tx_type: &serde_json::Value,
    gas_limit: u64,
) -> Result<(serde_json::Value, u64)> {
    retry_stale_nonce(|| submit_signed(rpc, signer, method, to, tx_type.clone(), gas_limit)).await
}

/// How many times an operation that takes the account nonce is tried.
const NONCE_ATTEMPTS: usize = 4;

/// Whether `e` is the node refusing a transaction for its nonce.
fn is_stale_nonce(e: &anyhow::Error) -> bool {
    let m = e.to_string().to_ascii_lowercase();
    m.contains("invalid nonce") || m.contains("nonce too low") || m.contains("stale nonce")
}

/// Runs `attempt`, which reads the account nonce itself, again while the node
/// refuses its nonce. A node account is also the account the node sends from
/// (its own transactions take the same nonce), so the nonce read a moment ago
/// can be taken by the time the transaction arrives; the next attempt reads
/// the nonce afresh. Any other error is returned at once.
pub async fn retry_stale_nonce<T, F, Fut>(mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut tries = 1;
    loop {
        match attempt().await {
            Err(e) if is_stale_nonce(&e) && tries < NONCE_ATTEMPTS => {
                eprintln!(
                    "  the account nonce moved before the transaction arrived; sending again with a fresh one"
                );
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            other => return other,
        }
    }
}

async fn submit_signed(
    rpc: &crate::rpc::RpcClient,
    signer: &tenzro_device_key::HardwareHybridSigner,
    method: &str,
    to: [u8; 32],
    tx_type: serde_json::Value,
    gas_limit: u64,
) -> Result<(serde_json::Value, u64)> {
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};

    let public = signer.public_key().clone();
    let from = Address::new(public.account_slot());
    let from_hex = format!("0x{}", hex::encode(from.as_bytes()));
    let (nonce, chain_id) =
        crate::rpc::fetch_nonce_and_chain_id(rpc, &from_hex, None, None).await?;
    let typed: TransactionType =
        serde_json::from_value(tx_type.clone()).map_err(|e| anyhow!("transaction payload: {e}"))?;
    let gas_price = crate::rpc::fetch_gas_price(rpc).await?;
    let tx = Transaction::new(
        ChainId::from(chain_id),
        from,
        Address::new(to),
        Nonce::from(nonce),
        typed,
        gas_limit,
        gas_price,
    );
    // A privileged power is signed over its typed preimage: show what it
    // does, decoded here from that preimage, before the key signs.
    if let Some(preimage) = tenzro_types::typed_action::action_preimage(&tx) {
        for line in tenzro_types::typed_action::describe(&preimage) {
            eprintln!("  {line}");
        }
        eprintln!("  signing digest {}", hex::encode(tx.hash().as_bytes()));
    }
    let sig = signer
        .sign(SignatureContext::Transaction, tx.hash().as_bytes())
        .map_err(|e| anyhow!("signing the transaction: {e}"))?;
    rpc.call(
        method,
        serde_json::json!({
            "from": from_hex,
            "to": format!("0x{}", hex::encode(to)),
            "gas_limit": gas_limit,
            "gas_price": gas_price,
            "nonce": nonce,
            "chain_id": chain_id,
            "timestamp": tx.timestamp.as_millis(),
            "valid_until": tx.valid_until.as_millis(),
            "tx_type": tx_type,
            "public_key": hex::encode(&public.p256),
            "signature": sig,
        }),
    )
    .await
    .map(|result| (result, nonce))
}

#[cfg(test)]
mod tpm_contention_tests {
    use super::*;
    use std::time::Duration;

    const NO_WAIT: &[Duration] = &[Duration::ZERO, Duration::ZERO, Duration::ZERO];

    #[test]
    fn a_busy_tpm_is_waited_out() {
        let mut calls = 0;
        let got = retry_while_contended(
            || {
                calls += 1;
                if calls < 3 {
                    Err("TPM command 0x17d timed out")
                } else {
                    Ok(7)
                }
            },
            NO_WAIT,
        );
        assert_eq!(got, Ok(7));
        assert_eq!(calls, 3);
    }

    #[test]
    fn a_real_failure_is_not_retried() {
        let mut calls = 0;
        let got: std::result::Result<(), String> = retry_while_contended(
            || {
                calls += 1;
                Err("this machine has no TPM 2.0")
            },
            NO_WAIT,
        );
        assert_eq!(calls, 1);
        assert_eq!(got, Err("this machine has no TPM 2.0".to_string()));
    }

    #[test]
    fn a_tpm_that_stays_busy_ends_in_plain_words() {
        let mut calls = 0;
        let got: std::result::Result<(), String> = retry_while_contended(
            || {
                calls += 1;
                Err("tpm busy: no turn within the wait limit")
            },
            NO_WAIT,
        );
        assert_eq!(calls, 4);
        let msg = got.unwrap_err();
        assert!(msg.contains("stayed busy") && msg.contains("node running on this machine"));
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    #[test]
    fn a_hash_is_read_from_either_answer_form() {
        assert_eq!(
            submitted_hash(&serde_json::json!("0xab")),
            Some("0xab".to_string())
        );
        assert_eq!(
            submitted_hash(&serde_json::json!({ "tx_hash": "cd" })),
            Some("cd".to_string())
        );
        assert_eq!(submitted_hash(&serde_json::json!({ "status": "ok" })), None);
        assert_eq!(submitted_hash(&serde_json::json!("")), None);
    }

    #[test]
    fn an_executed_transaction_took_effect() {
        let receipt = serde_json::json!({ "status": "0x1", "revertReason": null });
        assert_eq!(receipt_outcome(&receipt), Ok(()));
    }

    #[test]
    fn a_reverted_transaction_names_its_reason() {
        let receipt = serde_json::json!({ "status": "0x0", "revertReason": "out of gas" });
        assert_eq!(receipt_outcome(&receipt), Err("out of gas".to_string()));
    }

    #[test]
    fn a_revert_without_a_reason_is_still_a_failure() {
        let receipt = serde_json::json!({ "status": "0x0", "revertReason": null });
        assert!(receipt_outcome(&receipt).is_err());
        assert!(receipt_outcome(&serde_json::json!({})).is_err());
    }

    #[test]
    fn an_account_without_an_identity_is_told_how_to_register() {
        let reason = "Invalid transaction: 0xab has no registered identity; register one first";
        let text = revert_message("0x01", reason);
        assert!(text.contains(reason));
        assert!(text.contains("tenzro identity register-account"));
        assert!(!revert_message("0x01", "out of gas").contains("register-account"));
    }
}
