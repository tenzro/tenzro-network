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

/// The hardware signer for the client account under `namespace`.
pub(crate) fn client_signer(namespace: &str) -> Result<tenzro_device_key::HardwareHybridSigner> {
    tenzro_device_key::HardwareHybridSigner::open_or_create(&format!("client/{namespace}"))
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
    tenzro_device_key::HardwareHybridSigner::open_or_create(
        tenzro_types::did_derivation::MACHINE_WALLET_KEY_LABEL,
    )
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
    tenzro_device_key::HardwareHybridSigner::open_or_create(
        tenzro_types::did_derivation::MACHINE_KEY_LABEL,
    )
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
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    let public = signer.public_key().clone();
    let sec1 = [&[0x04u8][..], &public.p256].concat();
    let did = tenzro_types::did_derivation::machine_did(&sec1);
    let metadata = machine_attestation_metadata(&did, &sec1)?;
    let mut payload = tenzro_types::identity::RegisterIdentityPayload {
        did: did.clone(),
        identity_type: "machine".into(),
        display_name: "machine root".into(),
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

/// Sign and submit; an account that has not enrolled its ML-DSA-65 key is
/// enrolled first and the transaction sent again, so a new account is never
/// left unable to send.
async fn send_signed(
    rpc: &crate::rpc::RpcClient,
    signer: &tenzro_device_key::HardwareHybridSigner,
    method: &str,
    to: [u8; 32],
    tx_type: serde_json::Value,
    gas_limit: u64,
) -> Result<(serde_json::Value, u64)> {
    let first = submit_signed(rpc, signer, method, to, tx_type.clone(), gas_limit).await;
    match first {
        Err(e) if e.to_string().contains(NOT_ENROLLED) && tx_type.get("AccountKeys").is_none() => {
            eprintln!("  enrolling the account's ML-DSA-65 key first");
            enroll_pq_key(rpc, signer).await?;
            submit_signed(rpc, signer, method, to, tx_type, gas_limit).await
        }
        other => other,
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
