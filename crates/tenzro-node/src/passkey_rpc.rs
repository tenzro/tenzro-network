//! Passkey-first wallet onboarding + custody RPC handlers.
//!
//! - **Enrollment** — `tenzro_enrollPasskey` checks a passkey's registration
//!   and possession and returns the identity and account it derives. Nothing
//!   about the account is stored by the node: until its first change the
//!   account's keystore is the passkey alone, and every change after that is
//!   a `KeystoreUpdate` transaction held in consensus state (see
//!   [`crate::keystore_rpc`]), so any linked device works through any node.
//!

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tenzro_crypto::composite::{
    ClassicalProof, CompositePublicKey, CompositeSignature, SignatureContext,
};
use tenzro_crypto::webauthn::WebAuthnAssertion;
use tenzro_storage::{CF_VALIDATOR_MODULES, KvStore};
use tenzro_types::admission::ExpiringMap;
use tenzro_types::device_binding::CredentialProvenance;
use tenzro_vm::PasskeySignature;

/// The hardware key that integrity-tags rows persisted under
/// `CF_VALIDATOR_MODULES` (auth sessions), so a row edited on disk or copied
/// from another machine is refused on read.
///
/// The tag is an ECDSA P-256 signature by a key created in and held by this
/// machine's TPM or Secure Enclave, so no tag can be made without the chip.
/// A host with neither cannot persist these rows at all.
fn local_state_signer() -> Result<&'static dyn tenzro_device_key::HardwareSigner, &'static str> {
    use std::sync::OnceLock;
    static SIGNER: OnceLock<Option<Box<dyn tenzro_device_key::HardwareSigner>>> = OnceLock::new();
    SIGNER
        .get_or_init(open_local_state_signer)
        .as_deref()
        .ok_or("no TPM or Secure Enclave to hold the local-state signing key")
}

#[cfg(not(test))]
fn open_local_state_signer() -> Option<Box<dyn tenzro_device_key::HardwareSigner>> {
    tenzro_device_key::signer::open_or_create("tenzro/node/local-state").ok()
}

/// Tests only: a stand-in for the TPM key.
#[cfg(test)]
fn open_local_state_signer() -> Option<Box<dyn tenzro_device_key::HardwareSigner>> {
    Some(Box::new(crate::data_integrity::tests::test_signer(0x5c)))
}

/// Length of the tag `mac_wrap` prefixes.
const TAG_LEN: usize = 64;

/// Prefix `payload` with the hardware key's signature: `[sig(64) || payload]`.
fn mac_wrap(payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    let tag = local_state_signer()?
        .sign(payload)
        .map_err(|_| "the hardware key did not sign the row")?;
    let mut out = Vec::with_capacity(TAG_LEN + payload.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Verify and strip the tag from a row written by `mac_wrap`. A row too
/// short, tampered, or signed by another machine's key is refused.
fn mac_verify(blob: &[u8]) -> Result<&[u8], &'static str> {
    if blob.len() < TAG_LEN {
        return Err("mac_verify: row too short");
    }
    let (tag, payload) = blob.split_at(TAG_LEN);
    let signer = local_state_signer()?;
    let key = signer
        .public_key_sec1()
        .map_err(|_| "the hardware key is unreadable")?;
    if !tenzro_device_key::signer::verify_p256(&key, payload, tag) {
        return Err("mac_verify: tag mismatch (row tampered or foreign)");
    }
    Ok(payload)
}

// =============================================================================
// Request / response DTOs
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct EnrollPasskeyRequest {
    /// Proof that the caller holds the keys being enrolled.
    ///
    /// Required. Both the DID and the smart-account address are pure functions
    /// of the public key, so without this anyone who has seen a passkey's
    /// public half could claim the identity it derives — see
    /// [`require_key_possession`].
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
    /// Optional display name (e.g. "Alice's iPhone"). Stored on the TDIP
    /// identity metadata so the user can identify this account in their
    /// device list.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Raw 64-byte uncompressed P-256 public key (X || Y) or SEC1 65-byte
    /// (0x04 || X || Y) or COSE_Key CBOR. All three forms accepted; the
    /// node normalizes to raw `x || y` for the on-chain validator.
    pub passkey_public_key_hex: String,
    /// Opaque WebAuthn credential ID, which the platform authenticator
    /// locates the credential by.
    pub credential_id_hex: String,
    /// The registration's `authenticatorData`, hex: the `authData` of the
    /// attestation object `navigator.credentials.create()` returned, or
    /// `response.getAuthenticatorData()`. The node reads the credential's
    /// AAGUID and backup flags from it, after checking it names this node's
    /// relying party and the credential and key being enrolled. Required,
    /// except for a further wallet (salt > 0) under an existing identity, whose
    /// passkey is already enrolled on the identity's own account and keeps the
    /// provenance recorded there.
    #[serde(default)]
    pub registration_authenticator_data_hex: Option<String>,
    /// The relying party the passkey is registered on: the wallet provider's
    /// domain, recorded in the account's keystore. This node's relying party
    /// when absent.
    #[serde(default)]
    pub rp_id: Option<String>,
    /// CREATE2 salt for the account address, defaults to 0. Salt 0 is the
    /// identity's own account, and enrolling it again returns it. A higher salt
    /// is a further wallet under the same identity (the identity is never
    /// duplicated); enrolling that salt again returns that wallet.
    #[serde(default)]
    pub salt: u64,
    /// The hardware ML-DSA-65 verifying key enrolled with the passkey, hex.
    /// Required: `authorization` carries its signature over the same
    /// challenge as the proof that the caller holds it, and passkey sign-in
    /// checks the ML-DSA-65 leg against it.
    #[serde(default)]
    pub ml_dsa_public_key_hex: Option<String>,
    /// Registers the identity on chain, bound to its own account (salt 0):
    /// the passkey's composite signature over the identity's registration
    /// statement, context `IdentityRegistration`. The P-256 leg is a WebAuthn
    /// assertion with user verification and the ML-DSA-65 leg is by the key
    /// enrolled with the passkey. An enrolment without it returns the
    /// statement as `registration_statement_hex` and the challenge the passkey
    /// signs as `registration_webauthn_challenge`; an identity enrolled before
    /// it registers on chain by enrolling again with it.
    #[serde(default)]
    pub registration_proof: Option<tenzro_crypto::composite::CompositeSignature>,
}

#[derive(Debug, Serialize)]
pub struct EnrollPasskeyResponse {
    /// The human DID the passkey derives.
    pub did: String,
    /// The account address it derives under the requested salt.
    pub smart_account_address: String,
    pub credential_id_hex: String,
    /// The account's keystore: the one on chain, or before its first change
    /// the genesis record of this passkey.
    pub keystore: tenzro_types::keystore::KeystoreRecord,
    /// Commitment of `keystore`, hex: the `previous_commitment` the account's
    /// next `KeystoreUpdate` names.
    pub keystore_commitment: String,
    /// The anchor the account's first `KeystoreUpdate` carries; absent once
    /// the account has a keystore on chain.
    pub anchor: Option<tenzro_types::keystore::KeystoreAnchor>,
    /// For the identity's own account (salt 0): whether the identity is
    /// registered on chain with this account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_on_chain: Option<bool>,
    /// The `RegisterIdentity` transaction this enrolment submitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_tx: Option<String>,
    /// While the identity is not on chain: the registration statement the
    /// passkey signs to register it, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_statement_hex: Option<String>,
    /// The WebAuthn challenge for `registration_statement_hex`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_webauthn_challenge: Option<String>,
}

// =============================================================================
// Helpers
// =============================================================================

pub(crate) fn parse_params<T: for<'de> Deserialize<'de>>(
    params: Option<Value>,
) -> Result<T, JsonRpcError> {
    let p = params.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Missing params".to_string(),
        data: None,
    })?;
    serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("Invalid params: {}", e),
        data: None,
    })
}

pub(crate) fn decode_hex(s: &str) -> Result<Vec<u8>, JsonRpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("Invalid hex: {}", e),
        data: None,
    })
}

/// The optional `authorization` field of a params object, as a
/// [`CustodyAuthorization`]. Absence is left to [`require_key_possession`],
/// which refuses it with instructions for obtaining one.
pub(crate) fn custody_authorization_param(
    params: &Value,
) -> Result<Option<CustodyAuthorization>, JsonRpcError> {
    params
        .get("authorization")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("Invalid 'authorization': {e}"),
            data: None,
        })
}

pub(crate) fn normalize_p256_pubkey_to_raw_xy(bytes: &[u8]) -> Result<[u8; 64], JsonRpcError> {
    let xy = if bytes.len() == 64 {
        let mut a = [0u8; 64];
        a.copy_from_slice(bytes);
        a
    } else if bytes.len() == 65 && bytes[0] == 0x04 {
        let mut a = [0u8; 64];
        a.copy_from_slice(&bytes[1..]);
        a
    } else {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "Unsupported P-256 public key form: expected raw 64 or SEC1 65-byte, got {}",
                bytes.len()
            ),
            data: None,
        });
    };
    Ok(xy)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// =============================================================================
// Handler: tenzro_enrollPasskey
// =============================================================================

/// Enroll a passkey: check its registration and that the caller holds it,
/// register the human identity it derives on first enrolment, and return the
/// account it derives with that account's keystore.
///
/// Nothing about the account is stored here. Before its first change the
/// account's keystore is this passkey alone; its first `KeystoreUpdate`
/// carries the returned anchor and puts the keystore in consensus state.
/// Enrolling a passkey an account's keystore no longer links is refused.
pub(crate) async fn handle_enroll_passkey(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_types::keystore::{KeystoreAnchor, KeystoreRecord, smart_account_address};
    let req: EnrollPasskeyRequest = parse_params(params)?;
    let internal = |message: &str| JsonRpcError {
        code: -32603,
        message: message.to_string(),
        data: None,
    };
    let validator = node
        .webauthn_validator()
        .ok_or_else(|| internal("WebAuthnValidator not initialized on this node"))?;
    let identity_registry = node
        .identity_registry()
        .ok_or_else(|| internal("IdentityRegistry not initialized"))?;

    let p256_xy = normalize_p256_pubkey_to_raw_xy(&decode_hex(&req.passkey_public_key_hex)?)?;
    let credential_id = decode_hex(&req.credential_id_hex)?;
    let rp_id = req
        .rp_id
        .clone()
        .unwrap_or_else(|| node.http_surface().webauthn_rp_id().to_string());
    if !tenzro_types::keystore::valid_rp_id(&rp_id) {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("{rp_id} is not a relying party id (a lowercase DNS name)"),
            data: None,
        });
    }
    let ml_dsa_key = required_ml_dsa_key(req.ml_dsa_public_key_hex.as_deref())?;
    let did = tenzro_identity::TenzroDid::from_passkey(&p256_xy);
    let did_string = did.to_string();
    let state = validator.state();
    // A key already enrolled for this passkey on chain moves only by a signed
    // rotation, never by a re-enrolment.
    if validator
        .enrolled_pq_key(&p256_xy)
        .is_some_and(|enrolled| enrolled != ml_dsa_key)
    {
        return Err(JsonRpcError {
            code: -32001,
            message: "this passkey already has a different ML-DSA-65 key enrolled".to_string(),
            data: None,
        });
    }

    // Where the key lives: from the registration, checked against the
    // credential and key being enrolled; or, without one, as a keystore of
    // the identity on chain recorded it.
    let provenance = match req.registration_authenticator_data_hex.as_deref() {
        Some(registration) => registration_provenance(
            &decode_hex(registration)?,
            &{
                use sha2::{Digest, Sha256};
                Sha256::digest(rp_id.as_bytes()).into()
            },
            &credential_id,
            &p256_xy,
        )?,
        None => tenzro_vm::keystore::accounts_of_did(&state, &did_string)
            .iter()
            .filter_map(|a| hex::decode(a).ok())
            .filter_map(|a| tenzro_vm::keystore::read_record(&state, &a))
            .find_map(|r| r.credential_by_key(&p256_xy).filter(|c| c.rp_id == rp_id).map(|c| c.provenance_at()))
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "registration_authenticator_data_hex is required: send the authenticatorData from \
                          navigator.credentials.create()"
                    .to_string(),
                data: None,
            })?,
    };
    if let Some(auth) = req.authorization.as_ref() {
        require_matching_backup_eligibility(&provenance, &auth.assertion.authenticator_data)?;
    }
    // The identity and the account are both functions of the public key, so
    // nothing is returned for a key nobody proved they hold.
    require_key_possession(
        node,
        &rp_id,
        &p256_xy,
        &credential_id,
        &ml_dsa_key,
        req.authorization,
    )
    .await?;

    let anchor = KeystoreAnchor {
        rp_id: rp_id.clone(),
        credential_id: credential_id.clone(),
        public_key: p256_xy.to_vec(),
        aaguid: provenance.aaguid.0.to_vec(),
        backup_eligible: provenance.backup_eligible,
        backup_state: provenance.backup_state,
        salt: req.salt,
    };
    let address = smart_account_address(&p256_xy, &credential_id, req.salt);
    let (keystore, anchor) = match tenzro_vm::keystore::read_record(&state, &address) {
        Some(record) => {
            if record.credential_by_key(&p256_xy).is_none() {
                return Err(JsonRpcError {
                    code: -32001,
                    message: format!(
                        "account 0x{} no longer links this passkey; link it again from a passkey the account \
                         still has, or recover the account through its recovery signers",
                        hex::encode(address)
                    ),
                    data: None,
                });
            }
            (record, None)
        }
        None => (KeystoreRecord::genesis(&anchor), Some(anchor)),
    };

    // The identity's own wallet (salt 0) registers the identity once.
    if req.salt == 0 && identity_registry.resolve(&did_string).is_err() {
        let mut wallet = [0u8; 32];
        wallet[..20].copy_from_slice(&address);
        let binding = tenzro_identity::WalletBinding {
            wallet_id: format!("0x{}", hex::encode(address)),
            address: tenzro_types::primitives::Address::new(wallet),
            public_key: p256_xy.to_vec(),
            pq_verifying_key: ml_dsa_key.clone(),
        };
        let display_name = req
            .display_name
            .unwrap_or_else(|| "Passkey User".to_string());
        identity_registry
            .register_human_with_binding(did, display_name, binding)
            .await
            .map_err(|e| internal(&format!("identity registration: {e}")))?;
        if let Err(e) = identity_registry.set_identity_metadata(
            &did_string,
            [(
                "smart_account_address".to_string(),
                format!("0x{}", hex::encode(address)),
            )],
        ) {
            tracing::warn!(did = %did_string, error = %e, "passkey enroll: identity metadata write skipped");
        }
    }

    let on_chain = if req.salt == 0 {
        Some(
            register_identity_on_chain(node, &rp_id, &p256_xy, &did_string, req.registration_proof)
                .await?,
        )
    } else {
        None
    };

    let resp = EnrollPasskeyResponse {
        did: did_string,
        smart_account_address: format!("0x{}", hex::encode(address)),
        credential_id_hex: format!("0x{}", hex::encode(&credential_id)),
        keystore_commitment: hex::encode(keystore.commitment()),
        keystore,
        anchor,
        identity_on_chain: on_chain.as_ref().map(|o| o.registered),
        identity_tx: on_chain.as_ref().and_then(|o| o.tx.clone()),
        registration_statement_hex: on_chain.as_ref().and_then(|o| o.statement).map(hex::encode),
        registration_webauthn_challenge: on_chain.as_ref().and_then(|o| o.statement).map(|s| {
            tenzro_crypto::composite::webauthn_challenge(
                tenzro_crypto::composite::SignatureContext::IdentityRegistration,
                &s,
            )
        }),
    };
    serde_json::to_value(resp).map_err(|e| internal(&format!("serialize response: {e}")))
}

/// Where an enrolled identity stands on chain.
struct OnChainIdentity {
    /// Registered on chain with the identity's own account.
    registered: bool,
    /// The registration transaction submitted now.
    tx: Option<String>,
    /// The statement a registration signs, while none was submitted.
    statement: Option<[u8; 32]>,
}

/// Registers the passkey identity `did` on chain with the wallet its record
/// binds, when `proof` is the passkey's signature over the registration
/// statement. Without a proof, returns the statement to sign.
async fn register_identity_on_chain(
    node: &Arc<TenzroNode>,
    rp_id: &str,
    p256_xy: &[u8; 64],
    did: &str,
    proof: Option<tenzro_crypto::composite::CompositeSignature>,
) -> Result<OnChainIdentity, JsonRpcError> {
    use tenzro_crypto::composite::SignatureContext;
    use tenzro_types::identity::RegistrationProof;
    let refused = |message: String| JsonRpcError {
        code: -32001,
        message,
        data: None,
    };
    let internal = |message: String| JsonRpcError {
        code: -32603,
        message,
        data: None,
    };
    let registry = node
        .identity_registry()
        .ok_or_else(|| internal("IdentityRegistry not initialized".to_string()))?;
    let validator = node
        .webauthn_validator()
        .ok_or_else(|| internal("WebAuthnValidator not initialized on this node".to_string()))?;
    let identity = registry
        .resolve(did)
        .map_err(|e| internal(format!("identity {did}: {e}")))?;
    let state = validator.state();
    if tenzro_vm::native::identity_of_wallet(&state, identity.wallet_address.as_bytes()).as_deref()
        == Some(did)
    {
        return Ok(OnChainIdentity {
            registered: true,
            tx: None,
            statement: None,
        });
    }
    let unsigned = RegistrationProof::Hardware {
        signature: tenzro_crypto::composite::CompositeSignature::classical(
            tenzro_crypto::composite::ClassicalProof::Raw {
                signature: Vec::new(),
            },
        ),
    };
    let mut payload = crate::node::identity_register_payload(&identity, "human", unsigned);
    let statement = tenzro_types::identity::registration_statement(&payload);
    let Some(signature) = proof else {
        return Ok(OnChainIdentity {
            registered: false,
            tx: None,
            statement: Some(statement),
        });
    };
    if signature.pq.is_none() {
        return Err(refused(
            "registration_proof needs the ML-DSA-65 leg, by the key enrolled with the passkey, over \
             registration_statement_hex"
                .to_string(),
        ));
    }
    tenzro_crypto::composite::verify_classical_component_for(
        rp_id,
        p256_xy,
        SignatureContext::IdentityRegistration,
        &statement,
        &signature.classical,
    )
    .map_err(|e| {
        refused(format!(
            "registration_proof: the assertion is not by this passkey, with user verification, over \
             registration_statement_hex: {e}"
        ))
    })?;
    payload.proof = RegistrationProof::Hardware { signature };
    let enrolled_pq = validator.enrolled_pq_key(p256_xy);
    if !tenzro_tee::identity_evidence::registration_is_authorized(&payload, enrolled_pq.as_deref())
    {
        return Err(refused(
            "registration_proof does not register this identity: the ML-DSA-65 leg must be by the key \
             enrolled with the passkey, over registration_statement_hex"
                .to_string(),
        ));
    }
    let tx = node
        .submit_identity_register(&identity, "human", payload.proof)
        .await
        .map_err(|e| internal(format!("the identity registration was not submitted: {e}")))?;
    Ok(OnChainIdentity {
        registered: false,
        tx: Some(tx),
        statement: None,
    })
}

// =============================================================================
// Custody signing context
// =============================================================================

/// The context custody approvals are signed under: both legs sign the
/// composite representative of the custody challenge digest, and the WebAuthn
/// challenge is [`custody_webauthn_challenge`] of it.
pub(crate) const CUSTODY_CONTEXT: SignatureContext = SignatureContext::AccountOwner;

/// The WebAuthn challenge a passkey signs to approve the custody challenge
/// `digest`.
pub(crate) fn custody_webauthn_challenge(digest: &[u8; 32]) -> String {
    tenzro_vm::WebAuthnValidator::expected_challenge_for(CUSTODY_CONTEXT, digest)
}

/// One passkey's entry in a signature bundle: its assertion as the P-256
/// leg, with the hardware ML-DSA-65 leg when the caller supplied one.
fn passkey_leg(
    assertion: WebAuthnAssertion,
    credential_id: Vec<u8>,
    ml_dsa_signature_hex: Option<&str>,
) -> Result<PasskeySignature, JsonRpcError> {
    let classical = ClassicalProof::WebAuthn {
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
    };
    let signature = match ml_dsa_signature_hex {
        Some(hex) => CompositeSignature::hybrid(classical, decode_hex(hex)?),
        None => CompositeSignature::classical(classical),
    };
    Ok(PasskeySignature {
        credential_id,
        signature,
    })
}

// =============================================================================
// Custody authorization — proving control of an account before mutating it
// =============================================================================
//
// Every handler below this point changes who can act for a wallet. The
// account address is public (returned by `tenzro_enrollPasskey`, visible
// on-chain), so knowing it is not a credential. Every custody mutation runs
// through one gate rather than a check per handler.
//
// # What counts as proof
//
// A WebAuthn assertion from a credential **already enrolled on that account**,
// over a challenge the *node* issued, which binds:
//
//   domain-separator ‖ account ‖ operation ‖ operation-specific target ‖ nonce
//
// Binding the operation and its target is what stops an assertion collected for
// "add my new phone" being replayed as "remove the owner's laptop". Issuing the
// challenge server-side and consuming it single-use is what stops a captured
// assertion being replayed at all.
//
// Verification reuses the validator's own bundle check through
// `WebAuthnValidator::verify_approval` — the check consensus runs on a
// keystore approval, including the post-quantum ML-DSA leg, without the
// spending floor. A
// second verification routine written specially for custody would be a second
// thing to get wrong.
//
// # Risk classes
//
// Every operation here needs one user-verified passkey. Spending is judged in
// consensus: the account must hold two independent roots of control, so one
// compromised sync account or one lost device is never enough to move funds.
// A device added while the account holds fewer
// than two roots becomes a root only after a waiting period any existing
// passkey can cancel. Recovery is for an account that lost its roots: it is
// judged by the guardians' threshold and its own waiting period.

/// How long an issued custody challenge stays valid.
///
/// Long enough to walk to a phone and complete a ceremony; short enough that a
/// challenge left in a terminal's scrollback is not a standing authorization.
pub const CUSTODY_CHALLENGE_TTL_SECS: u64 = 300;

/// Upper bound on live custody challenges. Issuing is unauthenticated, so
/// without a bound the store is a memory sink for anyone who can reach the
/// RPC. Each entry expires after [`CUSTODY_CHALLENGE_TTL_SECS`]; past the
/// bound the oldest is dropped, so a flood of challenges for other accounts
/// never stops a new one being issued.
pub const MAX_OUTSTANDING_CHALLENGES: usize = 10_000;

/// The custody operations that require proof of account control.
///
/// An enum rather than a free string: the operation is bound into the signed
/// challenge, so a typo would not be a rejected call but a *differently scoped*
/// authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyOperation {
    /// Create a passkey-bound account, proving possession of the keys being
    /// enrolled.
    ///
    /// The one operation whose challenge is *not* answered by an
    /// already-enrolled credential, because at first enrolment there is none.
    /// It is answered by the keys being enrolled instead — see
    /// [`require_key_possession`].
    EnrollPasskey,
    /// Bind a device to an identity. `account` is the identity DID and
    /// `target` the device label.
    BindDevice,
    /// Unbind a device. `account` is the identity DID and `target` the
    /// credential id.
    RevokeDevice,
    /// Move a machine to another owner. `account` is the machine DID and
    /// `target` the new owner's DID.
    TransferMachineOwnership,
    /// Add, list or revoke a machine-access grant on this node. `account` is
    /// the machine owner's smart account and `target` names the change:
    /// `add:` and the grant digest, `revoke:` and the grant id, or `list`.
    MachineAccess,
    /// Approve a cluster membership list. `account` is the operator's DID and
    /// `target` the list's membership digest.
    SetClusterMembership,
    /// Delegate an agent. `account` is the controller's smart account and
    /// `target` the hash of the agent's completed terms, which the node
    /// computes from the terms itself.
    DelegateAgent,
    /// Replace a delegated agent's terms. `account` is the controller's smart
    /// account and `target` the hash of the new completed terms.
    UpdateAgentTerms,
    /// Revoke an identity on its root's authority: a root itself, or a
    /// delegated agent by its controller. `account` is the approving root's
    /// account and `target` is
    /// `tenzro_types::identity::revocation_target(did, reason)`.
    RevokeIdentity,
}

impl CustodyOperation {
    /// Stable byte tag bound into the challenge preimage.
    pub(crate) fn tag(self) -> &'static [u8] {
        match self {
            Self::EnrollPasskey => b"enroll_passkey",
            Self::BindDevice => b"bind_device",
            Self::RevokeDevice => b"revoke_device",
            Self::TransferMachineOwnership => b"transfer_machine_ownership",
            Self::MachineAccess => b"machine_access",
            Self::SetClusterMembership => b"set_cluster_membership",
            Self::DelegateAgent => b"delegate_agent",
            Self::UpdateAgentTerms => b"update_agent_terms",
            Self::RevokeIdentity => tenzro_types::identity::OP_REVOKE_IDENTITY,
        }
    }
}

/// The digest a passkey must sign to authorize one custody mutation.
///
/// `target` is the operation's own subject — the credential being added, the
/// session key being granted — so an assertion is scoped to exactly the change
/// it was collected for.
pub fn custody_challenge_digest(
    chain_id: u64,
    account: &[u8],
    operation: CustodyOperation,
    target: &[u8],
    nonce: &[u8; 16],
) -> [u8; 32] {
    // Length-prefixed, so ("ab","c") and ("a","bc") cannot hash alike — an
    // ambiguity here would let one operation's challenge satisfy another's.
    // Shared with the VM, which re-derives it for approvals it re-verifies.
    // The chain id binds it to one network.
    tenzro_types::agent_terms::custody_challenge_digest(
        chain_id,
        account,
        operation.tag(),
        target,
        nonce,
    )
}

/// An issued, not-yet-consumed custody challenge.
#[derive(Debug, Clone)]
struct IssuedChallenge {
    account: Vec<u8>,
    operation: CustodyOperation,
    target: Vec<u8>,
    nonce: [u8; 16],
}

/// Single-use, TTL-bounded custody challenges.
///
/// In memory rather than persisted, deliberately: a challenge outliving a node
/// restart buys nothing — the client simply asks for another — while a
/// persisted one is a replay window that survives the process that issued it.
#[derive(Debug)]
pub struct CustodyChallengeStore {
    issued: parking_lot::Mutex<ExpiringMap<String, IssuedChallenge>>,
    chain_id: u64,
}

impl CustodyChallengeStore {
    /// A store with nothing issued, for challenges on the network `chain_id`.
    pub fn new(chain_id: u64) -> Self {
        Self {
            issued: parking_lot::Mutex::new(ExpiringMap::new(
                std::time::Duration::from_secs(CUSTODY_CHALLENGE_TTL_SECS),
                MAX_OUTSTANDING_CHALLENGES,
            )),
            chain_id,
        }
    }

    /// The chain id this store's challenges are bound to.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Issue a challenge for one specific mutation.
    ///
    /// Returns `(challenge_id, digest, nonce)`. The client recomputes
    /// `digest` from the account, operation, target and `nonce`, signs it with
    /// an enrolled passkey and presents the id and signature back.
    ///
    /// Fails when the system RNG fails: a predictable nonce would make the
    /// challenge replayable.
    pub fn issue(
        &self,
        account: &[u8],
        operation: CustodyOperation,
        target: &[u8],
    ) -> Result<(String, [u8; 32], [u8; 16]), String> {
        let mut nonce = [0u8; 16];
        getrandom_0_4::fill(&mut nonce)
            .map_err(|e| format!("system RNG unavailable, no challenge issued: {e}"))?;
        let digest = custody_challenge_digest(self.chain_id, account, operation, target, &nonce);
        let id = hex::encode(digest);
        self.issued.lock().insert(
            id.clone(),
            IssuedChallenge {
                account: account.to_vec(),
                operation,
                target: target.to_vec(),
                nonce,
            },
        );
        Ok((id, digest, nonce))
    }

    /// Consume a challenge, checking it authorizes exactly this mutation.
    ///
    /// Removal happens on every outcome, success or failure: a challenge that
    /// was presented against the wrong target has been observed by whoever
    /// presented it, and letting them retry with a corrected target would make
    /// the binding advisory.
    pub fn consume(
        &self,
        challenge_id: &str,
        account: &[u8],
        operation: CustodyOperation,
        target: &[u8],
    ) -> Result<[u8; 32], String> {
        self.consume_with_nonce(challenge_id, account, operation, target)
            .map(|(digest, _)| digest)
    }

    /// [`Self::consume`], also returning the challenge nonce, for an
    /// approval the chain re-verifies.
    pub fn consume_with_nonce(
        &self,
        challenge_id: &str,
        account: &[u8],
        operation: CustodyOperation,
        target: &[u8],
    ) -> Result<([u8; 32], [u8; 16]), String> {
        let entry = self
            .issued
            .lock()
            .take(&challenge_id.to_string())
            .ok_or_else(|| "custody challenge is unknown, expired, or already used".to_string())?;
        if entry.account != account {
            return Err("custody challenge was issued for a different account".to_string());
        }
        if entry.operation != operation {
            return Err(format!(
                "custody challenge authorizes {:?}, not {:?}",
                entry.operation, operation
            ));
        }
        if entry.target != target {
            return Err(
                "custody challenge was issued for a different target; a challenge authorizes one \
                 specific change"
                    .to_string(),
            );
        }
        Ok((
            custody_challenge_digest(self.chain_id, account, operation, target, &entry.nonce),
            entry.nonce,
        ))
    }

    /// How many challenges are outstanding. For tests and operator diagnostics.
    pub fn outstanding(&self) -> usize {
        let mut issued = self.issued.lock();
        issued.sweep();
        issued.len()
    }
}

/// The proof a caller presents to mutate an account's custody.
#[derive(Debug, Deserialize)]
pub struct CustodyAuthorization {
    /// The challenge id returned by `tenzro_createCustodyChallenge`.
    pub challenge_id: String,
    /// Credential id of a passkey **already enrolled on this account**.
    pub credential_id_hex: String,
    /// WebAuthn assertion from that credential over the challenge digest.
    pub assertion: WebAuthnAssertion,
    /// ML-DSA-65 signature over the same digest — the post-quantum leg.
    #[serde(default)]
    pub ml_dsa_signature_hex: Option<String>,
    /// For an account with no keystore on chain yet: its first passkey,
    /// which must derive the account. Its genesis record is then the
    /// keystore the credential is checked against.
    #[serde(default)]
    pub anchor: Option<tenzro_types::keystore::KeystoreAnchor>,
}

/// Refuse unless the caller proves they hold the keys they are enrolling.
///
/// # Why this exists separately from [`require_account_control`]
///
/// That gate asks an *already-enrolled* credential to authorise a change. At
/// first enrolment there is none, so it cannot be the gate here — and without
/// one, enrolment was open: anyone could present a P-256 public key they did
/// not hold and have the node build an identity and a smart account around it.
///
/// That is not a theoretical hole. The DID is derived from the passkey
/// (`TenzroDid::from_passkey`) and the account address from
/// `SHA-256(passkey || credential || did)`, so both are a pure function of the
/// public key. An attacker who has seen someone's passkey public key — it is
/// public, that is what a public key is — could claim their DID and their
/// account address before they did, and the real holder would arrive to find
/// their identity already taken by a record they cannot control.
///
/// So enrolment proves possession of what is being enrolled: the WebAuthn
/// assertion must verify against the **P-256 key in this request**, not one
/// looked up from anywhere.
///
/// The ML-DSA-65 key enrolled with the passkey is proved the same way: the
/// authorization's ML-DSA-65 leg must verify over the same challenge digest
/// against `ml_dsa_public_key`, so nobody enrols a post-quantum key they do
/// not hold, and the passkey is never enrolled without one.
///
/// The challenge is issued against the P-256 key rather than an account,
/// because the account does not exist yet. `target` binds the credential id,
/// so an assertion collected to enrol one credential cannot be replayed to
/// enrol a different one.
///
/// Verification runs through the same primitives and the same relying party the
/// [`tenzro_vm::aa_webauthn_validator::WebAuthnValidator`] uses, including its
/// challenge derivation, so the enrolment gate and the signing gate cannot
/// disagree about what a valid assertion is.
pub(crate) async fn require_key_possession(
    node: &Arc<TenzroNode>,
    rp_id: &str,
    p256_xy: &[u8; 64],
    credential_id: &[u8],
    ml_dsa_public_key: &[u8],
    auth: Option<CustodyAuthorization>,
) -> Result<(), JsonRpcError> {
    let auth = auth.ok_or_else(|| JsonRpcError {
        code: -32001,
        message: "enrolling a passkey requires proof you hold it: call \
                  tenzro_createCustodyChallenge with operation `enroll_passkey`, \
                  account_address set to the 64-byte P-256 public key (x || y) you are \
                  enrolling and target_hex set to its credential_id, then sign the returned \
                  webauthn_challenge with that passkey and present it as `authorization`"
            .to_string(),
        data: None,
    })?;

    // The credential the assertion claims to come from must be the one being
    // enrolled. Without this the gate would verify a signature by some other
    // credential of the caller's and then enrol a different one.
    let claimed = decode_hex(&auth.credential_id_hex)?;
    if claimed != credential_id {
        return Err(JsonRpcError {
            code: -32001,
            message: format!(
                "the authorization is from credential 0x{}, but the enrolment is for 0x{}",
                hex::encode(&claimed),
                hex::encode(credential_id)
            ),
            data: None,
        });
    }

    // Binds the credential into the challenge, so one enrolment's assertion
    // cannot be lifted onto another credential.
    let target = credential_id.to_vec();

    let digest = node
        .custody_challenges()
        .consume(
            &auth.challenge_id,
            p256_xy.as_slice(),
            CustodyOperation::EnrollPasskey,
            &target,
        )
        .map_err(|message| JsonRpcError {
            code: -32001,
            message,
            data: None,
        })?;

    let expected_challenge = custody_webauthn_challenge(&digest);
    require_user_verified(&auth.assertion.authenticator_data)?;
    tenzro_crypto::webauthn::verify_webauthn_assertion_require_uv(
        &auth.assertion,
        p256_xy,
        &expected_challenge,
        &tenzro_crypto::webauthn::WebAuthnRelyingParty::RegistrableDomain {
            rp_id: rp_id.to_string(),
            related_origins: Vec::new(),
        },
        tenzro_crypto::webauthn::WebAuthnCeremonyType::Get,
    )
    .map_err(|e| JsonRpcError {
        code: -32001,
        message: format!(
            "enrolment authorization failed: the assertion did not verify against the \
             passkey being enrolled: {e}"
        ),
        data: None,
    })?;

    let pq_sig = auth
        .ml_dsa_signature_hex
        .as_deref()
        .map(decode_hex)
        .transpose()?;
    tenzro_crypto::composite::verify_pq_component(
        Some(ml_dsa_public_key),
        CUSTODY_CONTEXT,
        &digest,
        pq_sig.as_deref(),
        tenzro_crypto::composite::PqPolicy::Required,
    )
    .map_err(|e| JsonRpcError {
        code: -32001,
        message: format!(
            "enrolment authorization failed: the ML-DSA-65 leg did not verify against the \
             ML-DSA-65 key being enrolled: {e}"
        ),
        data: None,
    })?;

    Ok(())
}

/// The hardware ML-DSA-65 verifying key a passkey enrolment carries, hex.
/// A passkey is never enrolled without one.
pub(crate) fn required_ml_dsa_key(hex_key: Option<&str>) -> Result<Vec<u8>, JsonRpcError> {
    let key = hex_key
        .map(decode_hex)
        .transpose()?
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "ml_dsa_public_key_hex is required: a passkey is enrolled together with the \
                  ML-DSA-65 key of the hardware that holds it, and its signature over the \
                  enrolment challenge goes in authorization.ml_dsa_signature_hex"
                .to_string(),
            data: None,
        })?;
    if key.len() != tenzro_crypto::ML_DSA_65_VK_LEN {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "ml_dsa_public_key_hex must be a {}-byte ML-DSA-65 verifying key, got {} bytes",
                tenzro_crypto::ML_DSA_65_VK_LEN,
                key.len()
            ),
            data: None,
        });
    }
    Ok(key)
}

/// Authenticator-data flags.
const AD_FLAG_UV: u8 = 0x04;
const AD_FLAG_BE: u8 = 0x08;

/// Refuse an assertion made without user verification: a touch is not the
/// account holder.
///
/// Synced passkeys may approve. What a synced passkey shares with the others
/// its provider syncs is counted where it matters, in the account's
/// independent roots, which consensus checks before the account spends.
///
/// The flags are read from the signed authenticator data, so the check holds
/// once the signature over it verifies.
pub(crate) fn require_user_verified(authenticator_data: &[u8]) -> Result<(), JsonRpcError> {
    let flags = *authenticator_data.get(32).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "authenticatorData is too short to carry flags".to_string(),
        data: None,
    })?;
    if flags & AD_FLAG_UV == 0 {
        return Err(JsonRpcError {
            code: -32001,
            message: "custody changes require user verification (biometric or PIN), not just \
                      a touch"
                .to_string(),
            data: None,
        });
    }
    Ok(())
}

// =============================================================================
// Registration provenance
// =============================================================================

/// Where a passkey being enrolled keeps its key, read from its registration.
///
/// `authenticator_data` is the registration's `authenticatorData` (the
/// `authData` of the attestation object). It must be for this node's relying
/// party and must carry, as its attested credential, exactly the credential id
/// and P-256 key being enrolled; otherwise the AAGUID and flags it reports
/// would describe some other credential.
pub(crate) fn registration_provenance(
    authenticator_data: &[u8],
    rp_id_hash: &[u8; 32],
    credential_id: &[u8],
    p256_xy: &[u8; 64],
) -> Result<CredentialProvenance, JsonRpcError> {
    let parsed =
        tenzro_auth::read_authenticator_data(authenticator_data).map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("registration authenticator_data: {e}"),
            data: None,
        })?;
    if &parsed.rp_id_hash != rp_id_hash {
        return Err(JsonRpcError {
            code: -32001,
            message: "the registration authenticator_data is for a different relying party"
                .to_string(),
            data: None,
        });
    }
    let attested = parsed.attested_credential.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "the registration authenticator_data carries no attested credential (AT flag \
                  unset); send the authData from navigator.credentials.create()"
            .to_string(),
        data: None,
    })?;
    if attested.credential_id != credential_id {
        return Err(JsonRpcError {
            code: -32001,
            message: format!(
                "the registration authenticator_data is for credential 0x{}, not 0x{}",
                hex::encode(&attested.credential_id),
                hex::encode(credential_id)
            ),
            data: None,
        });
    }
    let tenzro_auth::CredentialKey::P256(sec1) = attested.credential_key else {
        return Err(JsonRpcError {
            code: -32602,
            message: "the registered credential is not a P-256 key".to_string(),
            data: None,
        });
    };
    if sec1[1..] != p256_xy[..] {
        return Err(JsonRpcError {
            code: -32001,
            message: "the registration authenticator_data carries a different public key from \
                      the one being enrolled"
                .to_string(),
            data: None,
        });
    }
    Ok(CredentialProvenance {
        aaguid: attested.aaguid,
        backup_eligible: parsed.backup_eligible,
        backup_state: parsed.backed_up,
    })
}

/// Refuse when a signed assertion from the credential disagrees with its
/// registration about backup eligibility.
///
/// Backup eligibility is fixed for a credential's lifetime, and the
/// assertion's flags are covered by the credential's own signature, so a
/// registration that reports otherwise was not produced by this credential.
pub(crate) fn require_matching_backup_eligibility(
    registration: &CredentialProvenance,
    assertion_authenticator_data: &[u8],
) -> Result<(), JsonRpcError> {
    let flags = *assertion_authenticator_data
        .get(32)
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "authenticatorData is too short to carry flags".to_string(),
            data: None,
        })?;
    let asserted = flags & AD_FLAG_BE != 0;
    if asserted != registration.backup_eligible {
        return Err(JsonRpcError {
            code: -32001,
            message: format!(
                "the registration says backup_eligible={}, but the passkey's signed assertion \
                 says backup_eligible={asserted}",
                registration.backup_eligible
            ),
            data: None,
        });
    }
    Ok(())
}

/// Refuse unless the caller proves they already control `account`.
///
/// The single gate every custody mutation runs through. Returns `Ok(())` only
/// when an already-enrolled credential has signed a node-issued challenge bound
/// to this exact operation and target.
pub(crate) async fn require_account_control(
    node: &Arc<TenzroNode>,
    account: &[u8],
    operation: CustodyOperation,
    target: &[u8],
    auth: Option<CustodyAuthorization>,
) -> Result<String, JsonRpcError> {
    require_account_control_over(node, account, operation, target, auth)
        .await
        .map(|(credential, _)| credential)
}

/// [`require_account_control`], also returning the challenge digest the
/// authorizing passkey signed, for an operation that needs a second signature
/// over the same challenge.
pub(crate) async fn require_account_control_over(
    node: &Arc<TenzroNode>,
    account: &[u8],
    operation: CustodyOperation,
    target: &[u8],
    auth: Option<CustodyAuthorization>,
) -> Result<(String, [u8; 32]), JsonRpcError> {
    require_account_control_detailed(node, account, operation, target, auth)
        .await
        .map(|a| (a.credential_hex, a.digest))
}

/// A verified custody approval, with what the chain needs to re-verify it.
pub(crate) struct VerifiedApproval {
    /// The authorizing credential, hex.
    pub credential_hex: String,
    /// The challenge digest the passkey signed.
    pub digest: [u8; 32],
    /// The challenge nonce.
    pub nonce: [u8; 16],
    /// The authorizing passkey, P-256 `x || y`.
    pub passkey_xy: [u8; 64],
    /// The WebAuthn assertion.
    pub assertion: WebAuthnAssertion,
    /// The hardware ML-DSA-65 leg over the same challenge, when supplied.
    pub ml_dsa_signature: Option<Vec<u8>>,
}

/// [`require_account_control_over`], returning the full approval.
pub(crate) async fn require_account_control_detailed(
    node: &Arc<TenzroNode>,
    account: &[u8],
    operation: CustodyOperation,
    target: &[u8],
    auth: Option<CustodyAuthorization>,
) -> Result<VerifiedApproval, JsonRpcError> {
    let auth = auth.ok_or_else(|| JsonRpcError {
        code: -32001,
        message: format!(
            "changing an account's custody requires proof you already control it: call \
             tenzro_createCustodyChallenge for {:?}, sign the returned digest with a passkey \
             already enrolled on this account, and present it as `authorization`",
            operation
        ),
        data: None,
    })?;

    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized on this node".to_string(),
        data: None,
    })?;

    // The authorizing credential must already be enrolled here. Without this,
    // a caller could sign the challenge with any key of their own choosing.
    let credential_id = decode_hex(&auth.credential_id_hex)?;
    // Kept before `credential_id` is moved into the signature bundle below.
    let authorizing_credential_hex = hex::encode(&credential_id);
    let keystore = webauthn_validator.keystore_or_genesis(account, auth.anchor.as_ref());
    let Some(enrolled) = keystore
        .as_ref()
        .and_then(|k| k.credential_by_id(&credential_id))
        .cloned()
    else {
        return Err(JsonRpcError {
            code: -32001,
            message: format!(
                "credential 0x{} is not enrolled on account 0x{}, so it cannot authorize a \
                 change to that account",
                hex::encode(&credential_id),
                hex::encode(account)
            ),
            data: None,
        });
    };
    let mut passkey_xy = [0u8; 64];
    passkey_xy.copy_from_slice(&enrolled.public_key);
    let assertion = auth.assertion.clone();
    let ml_dsa_signature = auth
        .ml_dsa_signature_hex
        .as_deref()
        .map(decode_hex)
        .transpose()?;

    // Consume the challenge, which checks it was issued for this account, this
    // operation, and this target — then yields the digest that must have been
    // signed.
    let (digest, nonce) = node
        .custody_challenges()
        .consume_with_nonce(&auth.challenge_id, account, operation, target)
        .map_err(|message| JsonRpcError {
            code: -32001,
            message,
            data: None,
        })?;

    // Verify through the validator's bundle check, so the custody gate and
    // consensus cannot disagree about what a valid assertion is.
    // The ML-DSA-65 leg is required only when the signing key has an
    // ML-DSA-65 key enrolled; the node never holds or derives one, so the
    // caller's hardware supplies it over the same digest the WebAuthn leg
    // covers. A key with none enrolled signs with the WebAuthn leg alone.
    require_user_verified(&auth.assertion.authenticator_data)?;
    let legs = vec![passkey_leg(
        auth.assertion,
        credential_id,
        auth.ml_dsa_signature_hex.as_deref(),
    )?];
    let sig_bytes = PasskeySignature::encode_bundle(&legs).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("encode passkey signature: {}", e),
        data: None,
    })?;

    // An approval, not a spend: the spending floor on independent roots does
    // not apply here; consensus applies it to the account's transactions.
    let verified = keystore.as_ref().is_some_and(|k| {
        webauthn_validator.verify_approval_by(k, &sig_bytes, CUSTODY_CONTEXT, &digest)
    });
    if !verified {
        return Err(JsonRpcError {
            code: -32001,
            message: "custody authorization failed: the assertion did not verify against an \
                      enrolled credential"
                .to_string(),
            data: None,
        });
    }
    // Hand back who authorized. The published account record chains each
    // version to the credential that permitted it, so "someone was allowed"
    // is not enough — the caller needs the identity.
    Ok(VerifiedApproval {
        credential_hex: authorizing_credential_hex,
        digest,
        nonce,
        passkey_xy,
        assertion,
        ml_dsa_signature,
    })
}

/// `tenzro_createCustodyChallenge` — issue the digest a passkey must sign to
/// authorize one custody mutation.
///
/// Params: `account_address`, `operation`, `target_hex`; or, for operation
/// `machine_access`, `machine_access` naming the change (`action` `add` with the
/// grant terms, `list`, or `revoke` with `grant_id`), from which the node
/// derives the machine owner's account and the target itself. Open by design:
/// a challenge is worthless without an enrolled credential to sign it, and
/// gating issuance would only mean a legitimate owner cannot start.
#[derive(Debug, Deserialize)]
pub struct CreateCustodyChallengeRequest {
    pub account_address: Option<String>,
    pub operation: CustodyOperation,
    /// The operation's subject, hex-encoded — the credential being added, the
    /// session key being granted. Empty for operations with no distinct target.
    #[serde(default)]
    pub target_hex: Option<String>,
    pub machine_access: Option<crate::machine_access::MachineAccessChange>,
    /// For `delegate_agent` and `update_agent_terms`: the agent's terms. The
    /// node completes the serving-node entries and computes the target, so
    /// `target_hex` must be absent.
    #[serde(default)]
    pub delegation: Option<crate::agent_delegation::AgentTerms>,
    /// For `update_agent_terms`: the agent whose terms change.
    #[serde(default)]
    pub agent_did: Option<String>,
    /// For `update_agent_terms`: also withdraw the agent's live access tokens.
    #[serde(default)]
    pub rotate_tokens: bool,
    /// For `delegate_agent` of a machine: its hardware key, hex. The machine
    /// is then the agent's single serving node.
    #[serde(default)]
    pub device_public_key: Option<String>,
    /// For `delegate_agent` of a machine: its machine id.
    #[serde(default)]
    pub machine_id: Option<String>,
}

pub(crate) async fn handle_create_custody_challenge(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: CreateCustodyChallengeRequest = parse_params(params)?;
    if matches!(
        req.operation,
        CustodyOperation::DelegateAgent | CustodyOperation::UpdateAgentTerms
    ) {
        return crate::agent_delegation::create_challenge(node, req).await;
    }
    if req.delegation.is_some()
        || req.agent_did.is_some()
        || req.device_public_key.is_some()
        || req.machine_id.is_some()
    {
        return Err(JsonRpcError {
            code: -32602,
            message: "delegation, agent_did, device_public_key and machine_id apply only to \
                      operations delegate_agent and update_agent_terms"
                .to_string(),
            data: None,
        });
    }
    let (account, target) = match (&req.machine_access, req.operation) {
        (Some(change), CustodyOperation::MachineAccess) => {
            crate::machine_access::challenge_subject(node, change)?
        }
        (Some(_), _) => {
            return Err(JsonRpcError {
                code: -32602,
                message: "machine_access names a change only for operation machine_access"
                    .to_string(),
                data: None,
            });
        }
        (None, _) => {
            let account = req.account_address.as_deref().ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "account_address is required".to_string(),
                data: None,
            })?;
            let target = match req.target_hex.as_deref() {
                Some(t) if !t.is_empty() => decode_hex(t)?,
                _ => Vec::new(),
            };
            (decode_hex(account)?, target)
        }
    };
    let (challenge_id, digest, nonce) = node
        .custody_challenges()
        .issue(&account, req.operation, &target)
        .map_err(|message| JsonRpcError {
            code: -32000,
            message,
            data: None,
        })?;
    Ok(serde_json::json!({
        "challenge_id": challenge_id,
        "challenge_hex": format!("0x{}", hex::encode(digest)),
        "webauthn_challenge": custody_webauthn_challenge(&digest),
        "account_address": format!("0x{}", hex::encode(&account)),
        "operation": req.operation,
        "target_hex": format!("0x{}", hex::encode(&target)),
        "nonce_hex": format!("0x{}", hex::encode(nonce)),
        "chain_id": node.custody_challenges().chain_id(),
        "expires_in_secs": CUSTODY_CHALLENGE_TTL_SECS,
    }))
}

/// A key's part of a custody-challenge target: its P-256 key and the SHA-256
/// of its ML-DSA-65 key (32 zero bytes without one).
pub fn key_target(key: &CompositePublicKey) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut target = key.p256.clone();
    target.extend_from_slice(
        &key.pq
            .as_deref()
            .map(|pq| <[u8; 32]>::from(Sha256::digest(pq)))
            .unwrap_or([0; 32]),
    );
    target
}

// =============================================================================
// PasskeySessionStore — browser-launch WebAuthn ceremony sessions
//
// Backs the `tenzro passkey login`-style flow: the CLI creates a pending
// session over JSON-RPC, opens the node-served page at
// `/auth/passkey?session=<id>` in the user's browser, the page runs the
// WebAuthn ceremony (`navigator.credentials.create()` / `get()`) and posts
// the outcome back against the session, and the CLI polls
// `tenzro_getPasskeySession` until the session reaches a terminal state.
//
// Sessions persist to `CF_VALIDATOR_MODULES / erc7579/auth_session/<id>`
// with the same MAC-tagged row layout as pending recoveries, so an
// in-flight login survives a node restart and a tampered row is refused
// at read time. Creating a session deletes the rows of sessions past their
// linger, oldest first, and holds the store to a fixed number of sessions.
// =============================================================================

/// What the browser ceremony is expected to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionKind {
    /// `navigator.credentials.create()` → new smart account via
    /// `tenzro_enrollPasskey`.
    Enroll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionStatus {
    /// Waiting for the browser ceremony.
    Pending,
    /// A completion request claimed the session and is executing. A session
    /// stuck here (crash mid-execution) expires like any other — it can
    /// never be claimed twice.
    InFlight,
    /// Ceremony executed successfully; `result` carries the handler response.
    Completed,
    /// Ceremony executed and the underlying handler rejected it; `error`
    /// carries the reason. Terminal — start a fresh session to retry.
    Failed,
    /// TTL elapsed before completion.
    Expired,
}

/// One browser-launch ceremony session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthSession {
    /// 32 random bytes, hex. Capability token: knowing the id is the
    /// authorization to complete the ceremony, exactly like the device-code
    /// string in an OAuth device flow.
    pub session_id: String,
    pub kind: AuthSessionKind,
    pub status: AuthSessionStatus,
    /// WebAuthn challenge, base64url no-pad. Random 32 bytes for
    /// `Enroll`/`Add`; the raw op-hash bytes for `Sign` (the assertion's
    /// clientDataJSON challenge must equal the op hash for the validator
    /// to accept it).
    pub challenge_b64: String,
    /// Kind-specific parameters supplied by the CLI at creation time
    /// (display name, account address, ML-DSA verifying key / signature,
    /// salt, label, op hash). Merged with the browser payload when the
    /// ceremony completes.
    pub params: Value,
    /// Handler response once `Completed`.
    pub result: Option<Value>,
    /// Failure reason once `Failed`.
    pub error: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Session TTL — 10 minutes, generous enough for a user to find their
/// phone / security key, short enough that an abandoned link dies.
const AUTH_SESSION_TTL_MS: u64 = 10 * 60 * 1000;

/// How long a terminal (Completed / Failed) session row survives so the
/// CLI poll loop can read the outcome before the sweep removes it.
const AUTH_SESSION_LINGER_MS: u64 = 10 * 60 * 1000;

/// Most browser-launch sessions held. Creating one is unauthenticated, so
/// past this the oldest session's row is deleted to make room.
const MAX_AUTH_SESSIONS: usize = 10_000;

/// Persistent store for browser-launch ceremony sessions.
///
/// The sessions alive are also indexed in memory in creation order, so each
/// create drops the expired rows at the front of the index (and, at
/// [`MAX_AUTH_SESSIONS`], the oldest) without reading the others.
pub struct PasskeySessionStore {
    storage: Arc<dyn KvStore>,
    live: parking_lot::Mutex<ExpiringMap<String, ()>>,
}

impl PasskeySessionStore {
    const PREFIX: &'static [u8] = b"erc7579/auth_session/";

    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        Self::with_capacity(storage, MAX_AUTH_SESSIONS)
    }

    /// A store holding at most `capacity` sessions. The rows already stored
    /// are indexed once, oldest first; rows past their linger, or unreadable,
    /// are deleted.
    pub(crate) fn with_capacity(storage: Arc<dyn KvStore>, capacity: usize) -> Self {
        let store = Self {
            storage,
            live: parking_lot::Mutex::new(ExpiringMap::new(
                std::time::Duration::from_millis(AUTH_SESSION_TTL_MS + AUTH_SESSION_LINGER_MS),
                capacity,
            )),
        };
        store.index_stored_rows();
        store
    }

    fn index_stored_rows(&self) {
        let Ok(rows) = self.storage.scan_prefix(CF_VALIDATOR_MODULES, Self::PREFIX) else {
            return;
        };
        let now = now_ms();
        let mut alive: Vec<(u64, String)> = Vec::new();
        for (key, value) in rows {
            let Some(sid) = key.strip_prefix(Self::PREFIX) else {
                continue;
            };
            let sid = String::from_utf8_lossy(sid).to_string();
            // Only the expiry is read here; the tag is checked whenever the
            // row is read for use.
            let session = value
                .get(TAG_LEN..)
                .and_then(|payload| serde_json::from_slice::<PendingAuthSession>(payload).ok());
            match session {
                Some(s) if now <= s.expires_at_ms + AUTH_SESSION_LINGER_MS => {
                    alive.push((s.created_at_ms, sid))
                }
                _ => self.delete(&sid),
            }
        }
        alive.sort();
        let mut live = self.live.lock();
        for (_, sid) in alive {
            for (dropped, ()) in live.insert(sid, ()) {
                self.delete(&dropped);
            }
        }
    }

    /// Store a new session, first deleting the rows of sessions past their
    /// linger and, at capacity, the oldest.
    pub(crate) fn create(&self, session: &PendingAuthSession) -> Result<(), JsonRpcError> {
        let dropped = self.live.lock().insert(session.session_id.clone(), ());
        for (sid, ()) in dropped {
            self.delete(&sid);
        }
        self.put(session)
    }

    fn key(session_id: &str) -> Vec<u8> {
        let mut k = Self::PREFIX.to_vec();
        k.extend_from_slice(session_id.as_bytes());
        k
    }

    pub(crate) fn put(&self, session: &PendingAuthSession) -> Result<(), JsonRpcError> {
        let bytes = serde_json::to_vec(session).map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("serialize auth session: {}", e),
            data: None,
        })?;
        let tagged = mac_wrap(&bytes).map_err(|e| JsonRpcError {
            code: -32603,
            message: e.to_string(),
            data: None,
        })?;
        self.storage
            .put(
                CF_VALIDATOR_MODULES,
                &Self::key(&session.session_id),
                &tagged,
            )
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("persist auth session: {}", e),
                data: None,
            })
    }

    /// Read a session, transparently flipping `Pending`/`InFlight` rows
    /// past their expiry to `Expired` (persisted).
    pub(crate) fn get(&self, session_id: &str) -> Result<Option<PendingAuthSession>, JsonRpcError> {
        let bytes = self
            .storage
            .get(CF_VALIDATOR_MODULES, &Self::key(session_id))
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("read auth session: {}", e),
                data: None,
            })?;
        let Some(b) = bytes else { return Ok(None) };
        let payload = mac_verify(&b).map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("tampered auth session row: {}", e),
            data: None,
        })?;
        let mut session: PendingAuthSession =
            serde_json::from_slice(payload).map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("deserialize auth session: {}", e),
                data: None,
            })?;
        if matches!(
            session.status,
            AuthSessionStatus::Pending | AuthSessionStatus::InFlight
        ) && now_ms() > session.expires_at_ms
        {
            session.status = AuthSessionStatus::Expired;
            self.put(&session)?;
        }
        Ok(Some(session))
    }

    pub(crate) fn delete(&self, session_id: &str) {
        let _ = self
            .storage
            .delete(CF_VALIDATOR_MODULES, &Self::key(session_id));
    }
}

// =============================================================================
// Handler: tenzro_createPasskeySession
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CreatePasskeySessionRequest {
    /// "enroll".
    pub kind: AuthSessionKind,
    /// Enroll: optional display name for the new identity.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Enroll: CREATE2 salt (defaults to 0).
    #[serde(default)]
    pub salt: u64,
    /// Display label shown in the browser ceremony.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreatePasskeySessionResponse {
    pub session_id: String,
    /// Path on the node's web server the CLI should open in a browser.
    pub verification_path: String,
    pub status: AuthSessionStatus,
    pub challenge_b64: String,
    pub expires_at_ms: u64,
}

pub(crate) async fn handle_create_passkey_session(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: CreatePasskeySessionRequest = parse_params(params)?;
    let store = node.passkey_sessions().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "PasskeySessionStore not initialized on this node".to_string(),
        data: None,
    })?;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let AuthSessionKind::Enroll = req.kind;
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
    let params_value = serde_json::json!({
        "display_name": req.display_name,
        "salt": req.salt,
    });

    let mut sid_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sid_bytes);
    let session_id = hex::encode(sid_bytes);
    let now = now_ms();
    let session = PendingAuthSession {
        session_id: session_id.clone(),
        kind: req.kind,
        status: AuthSessionStatus::Pending,
        challenge_b64: challenge_b64.clone(),
        params: params_value,
        result: None,
        error: None,
        created_at_ms: now,
        expires_at_ms: now + AUTH_SESSION_TTL_MS,
    };
    store.create(&session)?;

    serde_json::to_value(CreatePasskeySessionResponse {
        verification_path: format!("/auth/passkey?session={}", session_id),
        session_id,
        status: AuthSessionStatus::Pending,
        challenge_b64,
        expires_at_ms: session.expires_at_ms,
    })
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_getPasskeySession
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct GetPasskeySessionRequest {
    pub session_id: String,
}

pub(crate) async fn handle_get_passkey_session(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: GetPasskeySessionRequest = parse_params(params)?;
    let store = node.passkey_sessions().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "PasskeySessionStore not initialized on this node".to_string(),
        data: None,
    })?;
    let session = store.get(&req.session_id)?.ok_or_else(|| JsonRpcError {
        code: -32404,
        message: "Unknown or swept auth session".to_string(),
        data: None,
    })?;
    // The CLI poll surface deliberately excludes `params` (which can carry
    // an ML-DSA signature) and `challenge_b64` — the poller only needs the
    // outcome.
    Ok(serde_json::json!({
        "session_id": session.session_id,
        "kind": session.kind,
        "status": session.status,
        "result": session.result,
        "error": session.error,
        "expires_at_ms": session.expires_at_ms,
    }))
}

/// Claim a pending session for execution and run the underlying handler.
/// Called by the web completion endpoint, never dispatched over JSON-RPC.
///
/// Single-use discipline: the session row is flipped to `InFlight` and
/// persisted **before** the handler runs, so a second completion attempt
/// (double-submit, replayed request, concurrent tab) is refused even if
/// the first one is still executing — and a crash mid-execution leaves an
/// unclaimable row that simply expires.
pub(crate) async fn complete_passkey_session(
    node: &Arc<TenzroNode>,
    session_id: &str,
    browser_payload: Value,
) -> Result<Value, JsonRpcError> {
    let store = node.passkey_sessions().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "PasskeySessionStore not initialized on this node".to_string(),
        data: None,
    })?;
    let mut session = store.get(session_id)?.ok_or_else(|| JsonRpcError {
        code: -32404,
        message: "Unknown or swept auth session".to_string(),
        data: None,
    })?;
    if session.status != AuthSessionStatus::Pending {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "auth session is not pending (status: {})",
                serde_json::to_string(&session.status).unwrap_or_default()
            ),
            data: None,
        });
    }
    session.status = AuthSessionStatus::InFlight;
    store.put(&session)?;

    let handler_params = match build_completion_params(&session, browser_payload) {
        Ok(p) => p,
        Err(e) => {
            session.status = AuthSessionStatus::Failed;
            session.error = Some(e.message.clone());
            let _ = store.put(&session);
            return Err(e);
        }
    };

    let outcome = match session.kind {
        AuthSessionKind::Enroll => handle_enroll_passkey(node, Some(handler_params)).await,
    };

    match outcome {
        Ok(result) => {
            session.status = AuthSessionStatus::Completed;
            session.result = Some(result.clone());
            store.put(&session)?;
            Ok(result)
        }
        Err(e) => {
            session.status = AuthSessionStatus::Failed;
            session.error = Some(e.message.clone());
            let _ = store.put(&session);
            Err(e)
        }
    }
}

/// Merge the CLI-supplied session params with the browser ceremony payload
/// into the exact request shape the underlying handler expects.
fn build_completion_params(
    session: &PendingAuthSession,
    browser_payload: Value,
) -> Result<Value, JsonRpcError> {
    let str_field = |v: &Value, key: &str| -> Result<String, JsonRpcError> {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: format!("completion payload missing `{}`", key),
                data: None,
            })
    };
    match session.kind {
        AuthSessionKind::Enroll => Ok(serde_json::json!({
            "display_name": session.params.get("display_name"),
            "passkey_public_key_hex": str_field(&browser_payload, "passkey_public_key_hex")?,
            "credential_id_hex": str_field(&browser_payload, "credential_id_hex")?,
            "registration_authenticator_data_hex":
                str_field(&browser_payload, "registration_authenticator_data_hex")?,
            "salt": session.params.get("salt"),
        })),
    }
}

#[cfg(test)]
mod custody_challenge_tests {
    use super::require_user_verified;

    fn ad(flags: u8) -> Vec<u8> {
        let mut a = vec![0u8; 37];
        a[32] = flags;
        a
    }

    /// Presence alone cannot change custody; a synced passkey that verified
    /// its user can.
    #[test]
    fn custody_needs_user_verification_and_accepts_synced_passkeys() {
        assert!(require_user_verified(&ad(0x01 | 0x04)).is_ok());
        assert!(
            require_user_verified(&ad(0x01 | 0x04 | 0x08)).is_ok(),
            "BE with UV"
        );
        assert!(
            require_user_verified(&ad(0x01 | 0x04 | 0x08 | 0x10)).is_ok(),
            "BE+BS with UV"
        );
        assert!(require_user_verified(&ad(0x01)).is_err(), "UP without UV");
        assert!(
            require_user_verified(&ad(0x01 | 0x08 | 0x10)).is_err(),
            "synced without UV"
        );
        assert!(require_user_verified(&[0u8; 10]).is_err());
    }

    use super::*;

    const RP_ID: &str = "tenzro.com";

    fn rp_hash(rp_id: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(rp_id.as_bytes()).into()
    }

    /// A registration `authenticatorData` for `rp_id` carrying `credential_id`
    /// and the P-256 key `xy`, with `flags` plus AT.
    fn registration(
        rp_id: &str,
        flags: u8,
        aaguid: [u8; 16],
        credential_id: &[u8],
        xy: &[u8; 64],
    ) -> Vec<u8> {
        let mut a = rp_hash(rp_id).to_vec();
        a.push(flags | 0x40);
        a.extend_from_slice(&0u32.to_be_bytes());
        a.extend_from_slice(&aaguid);
        a.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        a.extend_from_slice(credential_id);
        // COSE_Key {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        a.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        a.extend_from_slice(&xy[..32]);
        a.extend_from_slice(&[0x22, 0x58, 0x20]);
        a.extend_from_slice(&xy[32..]);
        a
    }

    const XY: [u8; 64] = [0x31; 64];
    const CRED: &[u8] = b"credential-1";

    #[test]
    fn provenance_is_read_from_the_registration() {
        let synced = registration(RP_ID, 0x01 | 0x04 | 0x08 | 0x10, [0xea; 16], CRED, &XY);
        let p = registration_provenance(&synced, &rp_hash(RP_ID), CRED, &XY).unwrap();
        assert_eq!(p.aaguid.0, [0xea; 16]);
        assert!(p.backup_eligible && p.backup_state);

        let bound = registration(RP_ID, 0x01 | 0x04, [0xcb; 16], CRED, &XY);
        let p = registration_provenance(&bound, &rp_hash(RP_ID), CRED, &XY).unwrap();
        assert_eq!(p.aaguid.0, [0xcb; 16]);
        assert!(!p.backup_eligible && !p.backup_state);
    }

    #[test]
    fn a_registration_for_another_relying_party_is_refused() {
        let reg = registration("evil.example", 0x05, [0xea; 16], CRED, &XY);
        let err = registration_provenance(&reg, &rp_hash(RP_ID), CRED, &XY).unwrap_err();
        assert!(
            err.message.contains("different relying party"),
            "{}",
            err.message
        );
    }

    /// The AAGUID and flags describe whichever credential the data carries, so
    /// data carrying a different credential or key is refused rather than
    /// recorded against this one.
    #[test]
    fn a_registration_that_disagrees_with_the_enrolment_is_refused() {
        let reg = registration(RP_ID, 0x05, [0xea; 16], CRED, &XY);
        let err = registration_provenance(&reg, &rp_hash(RP_ID), b"credential-2", &XY).unwrap_err();
        assert!(err.message.contains("is for credential"), "{}", err.message);
        let err = registration_provenance(&reg, &rp_hash(RP_ID), CRED, &[0x32; 64]).unwrap_err();
        assert!(
            err.message.contains("different public key"),
            "{}",
            err.message
        );
    }

    #[test]
    fn a_registration_without_an_attested_credential_or_too_short_is_refused() {
        // An assertion's authenticator data: no AT flag.
        let mut assertion = rp_hash(RP_ID).to_vec();
        assertion.push(0x05);
        assertion.extend_from_slice(&0u32.to_be_bytes());
        let err = registration_provenance(&assertion, &rp_hash(RP_ID), CRED, &XY).unwrap_err();
        assert!(err.message.contains("AT flag"), "{}", err.message);
        assert!(registration_provenance(&[0u8; 20], &rp_hash(RP_ID), CRED, &XY).is_err());
    }

    /// Backup eligibility is fixed for a credential's life, and the assertion
    /// is signed by the credential, so a registration claiming otherwise did
    /// not come from it.
    #[test]
    fn backup_eligibility_must_match_the_signed_assertion() {
        let synced = CredentialProvenance {
            aaguid: tenzro_types::device_binding::Aaguid([0xea; 16]),
            backup_eligible: true,
            backup_state: true,
        };
        assert!(require_matching_backup_eligibility(&synced, &ad(0x05 | 0x08)).is_ok());
        let err = require_matching_backup_eligibility(&synced, &ad(0x05)).unwrap_err();
        assert!(err.message.contains("backup_eligible"), "{}", err.message);
        let bound = CredentialProvenance {
            backup_eligible: false,
            backup_state: false,
            ..synced
        };
        assert!(require_matching_backup_eligibility(&bound, &ad(0x05)).is_ok());
        assert!(require_matching_backup_eligibility(&bound, &ad(0x05 | 0x08)).is_err());
    }

    /// Every operation this enum can name, so a new one cannot be added
    /// without appearing here.
    const ALL: [CustodyOperation; 9] = [
        CustodyOperation::EnrollPasskey,
        CustodyOperation::MachineAccess,
        CustodyOperation::BindDevice,
        CustodyOperation::RevokeDevice,
        CustodyOperation::TransferMachineOwnership,
        CustodyOperation::SetClusterMembership,
        CustodyOperation::DelegateAgent,
        CustodyOperation::UpdateAgentTerms,
        CustodyOperation::RevokeIdentity,
    ];

    /// **Two operations sharing a tag would be interchangeable.** A challenge
    /// collected to bind a device would satisfy a request to move a
    /// machine, and nothing would report an error — the signature would verify
    /// and the wrong change would be authorised. A duplicate is not a compile
    /// error, so it is a test.
    #[test]
    fn every_custody_operation_has_its_own_tag() {
        let mut seen = std::collections::HashSet::new();
        for op in ALL {
            assert!(
                seen.insert(op.tag()),
                "{op:?} shares a challenge tag with an earlier operation"
            );
        }
        assert_eq!(seen.len(), ALL.len());
    }

    /// And the tag has to reach the digest, or having distinct tags would
    /// prove nothing.
    #[test]
    fn the_operation_is_bound_into_the_digest() {
        let account = [7u8; 64];
        let target = b"credential";
        let nonce = [0u8; 16];

        let mut seen = std::collections::HashSet::new();
        for op in ALL {
            assert!(
                seen.insert(custody_challenge_digest(1337, &account, op, target, &nonce)),
                "{op:?} produces a digest another operation already produces"
            );
        }
    }

    /// **The property enrolment leans on.** The challenge for enrolling a
    /// passkey is issued against the key itself rather than an account, and it
    /// binds the credential and the post-quantum key. An assertion collected to
    /// enrol one pairing must not enrol a different one — otherwise a caller
    /// could prove they hold a passkey and then attach someone else's ML-DSA
    /// key to the account it creates.
    #[test]
    fn an_enrolment_challenge_is_bound_to_one_key_pairing() {
        let store = CustodyChallengeStore::new(1337);
        let passkey = [1u8; 64];
        let credential = b"cred-1";
        let pq_a = vec![0xAAu8; 8];
        let pq_b = vec![0xBBu8; 8];

        let mut target_a = credential.to_vec();
        target_a.extend_from_slice(&pq_a);
        let mut target_b = credential.to_vec();
        target_b.extend_from_slice(&pq_b);

        let (id, _, _) = store
            .issue(&passkey, CustodyOperation::EnrollPasskey, &target_a)
            .unwrap();
        let err = store
            .consume(&id, &passkey, CustodyOperation::EnrollPasskey, &target_b)
            .unwrap_err();
        assert!(err.contains("different target"), "{err}");

        // A different passkey cannot use it either.
        let (id, _, _) = store
            .issue(&passkey, CustodyOperation::EnrollPasskey, &target_a)
            .unwrap();
        let err = store
            .consume(&id, &[2u8; 64], CustodyOperation::EnrollPasskey, &target_a)
            .unwrap_err();
        assert!(err.contains("different account"), "{err}");
    }

    /// An enrolment challenge must not satisfy a mutation on an existing
    /// account, and vice versa. The two gates ask different questions — "do you
    /// hold this key?" and "do you already control this account?" — and a
    /// challenge that answered both would let the weaker one stand in for the
    /// stronger.
    #[test]
    fn an_enrolment_challenge_does_not_authorise_a_custody_change() {
        let store = CustodyChallengeStore::new(1337);
        let subject = [3u8; 64];

        let (id, _, _) = store
            .issue(&subject, CustodyOperation::EnrollPasskey, b"t")
            .unwrap();
        let err = store
            .consume(&id, &subject, CustodyOperation::BindDevice, b"t")
            .unwrap_err();
        assert!(err.contains("authorizes EnrollPasskey"), "{err}");

        let (id, _, _) = store
            .issue(&subject, CustodyOperation::BindDevice, b"t")
            .unwrap();
        let err = store
            .consume(&id, &subject, CustodyOperation::EnrollPasskey, b"t")
            .unwrap_err();
        assert!(err.contains("authorizes BindDevice"), "{err}");
    }

    /// The issued nonce lets the client recompute the digest it signs
    /// instead of trusting the node's word for it.
    #[test]
    fn the_issued_nonce_recomputes_the_digest() {
        let store = CustodyChallengeStore::new(1337);
        let account = [7u8; 20];
        let target = b"guardian-target";
        let (id, digest, nonce) = store
            .issue(&account, CustodyOperation::BindDevice, target)
            .unwrap();
        assert_eq!(
            custody_challenge_digest(
                store.chain_id(),
                &account,
                CustodyOperation::BindDevice,
                target,
                &nonce
            ),
            digest
        );
        assert_eq!(id, hex::encode(digest));
    }

    /// Issuing is unauthenticated, so the store stops growing at its bound:
    /// past it the oldest challenge is dropped and the new one issued.
    #[test]
    fn the_challenge_store_stops_growing_at_its_bound() {
        let store = CustodyChallengeStore::new(1337);
        let (first, _, _) = store
            .issue(b"first", CustodyOperation::BindDevice, b"t")
            .unwrap();
        for i in 0..MAX_OUTSTANDING_CHALLENGES {
            store
                .issue(
                    &(i as u64).to_be_bytes(),
                    CustodyOperation::BindDevice,
                    b"t",
                )
                .unwrap();
        }
        assert_eq!(store.outstanding(), MAX_OUTSTANDING_CHALLENGES);
        assert!(
            store
                .consume(&first, b"first", CustodyOperation::BindDevice, b"t")
                .is_err(),
            "the oldest challenge was dropped"
        );
    }

    /// Single use, including after a failed attempt. A challenge presented
    /// against the wrong target has been seen by whoever presented it, and
    /// letting them retry with a corrected one would make the binding
    /// advisory.
    #[test]
    fn a_challenge_is_spent_whether_or_not_it_succeeded() {
        let store = CustodyChallengeStore::new(1337);
        let subject = [4u8; 64];

        let (id, _, _) = store
            .issue(&subject, CustodyOperation::EnrollPasskey, b"t")
            .unwrap();
        store
            .consume(&id, &subject, CustodyOperation::EnrollPasskey, b"t")
            .expect("the first use is the real one");
        let err = store
            .consume(&id, &subject, CustodyOperation::EnrollPasskey, b"t")
            .unwrap_err();
        assert!(err.contains("already used"), "{err}");

        let (id, _, _) = store
            .issue(&subject, CustodyOperation::EnrollPasskey, b"t")
            .unwrap();
        let _ = store.consume(&id, &subject, CustodyOperation::EnrollPasskey, b"wrong");
        let err = store
            .consume(&id, &subject, CustodyOperation::EnrollPasskey, b"t")
            .unwrap_err();
        assert!(
            err.contains("already used"),
            "a failed attempt must still spend the challenge: {err}"
        );
    }

    /// Length-prefixing: without it a (credential, pq_key) pair could be
    /// re-split so one enrolment's challenge covers another's bytes.
    #[test]
    fn the_digest_preimage_is_unambiguous() {
        let nonce = [0u8; 16];
        assert_ne!(
            custody_challenge_digest(1337, b"AB", CustodyOperation::EnrollPasskey, b"C", &nonce),
            custody_challenge_digest(1337, b"A", CustodyOperation::EnrollPasskey, b"BC", &nonce),
        );
    }

    /// The same approval on two networks is two different digests, so one
    /// signed on a test network cannot be replayed on another.
    #[test]
    fn the_chain_id_is_bound_into_the_digest() {
        let nonce = [0u8; 16];
        assert_ne!(
            custody_challenge_digest(1337, b"A", CustodyOperation::RevokeDevice, b"C", &nonce),
            custody_challenge_digest(13380, b"A", CustodyOperation::RevokeDevice, b"C", &nonce),
        );
        let (_, digest, nonce) = CustodyChallengeStore::new(13380)
            .issue(b"A", CustodyOperation::RevokeDevice, b"C")
            .unwrap();
        assert_eq!(
            custody_challenge_digest(13380, b"A", CustodyOperation::RevokeDevice, b"C", &nonce),
            digest
        );
    }
}

#[cfg(test)]
mod unauthenticated_growth_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A flood of challenges for other accounts does not stop a new account
    /// from getting one.
    #[test]
    fn a_flood_of_challenges_does_not_block_another_account() {
        let store = CustodyChallengeStore::new(1337);
        for i in 0..MAX_OUTSTANDING_CHALLENGES {
            store
                .issue(
                    &(i as u64).to_be_bytes(),
                    CustodyOperation::BindDevice,
                    b"t",
                )
                .unwrap();
        }
        store
            .issue(b"fresh-account", CustodyOperation::RevokeDevice, b"cred")
            .unwrap();
    }

    /// Counts reads, so a test can bound the work one call does.
    #[derive(Default)]
    struct CountingStore {
        inner: tenzro_storage::MemoryStore,
        gets: AtomicUsize,
    }

    impl KvStore for CountingStore {
        fn get(&self, cf: &str, key: &[u8]) -> tenzro_storage::Result<Option<Vec<u8>>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(cf, key)
        }
        fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> tenzro_storage::Result<()> {
            self.inner.put(cf, key, value)
        }
        fn delete(&self, cf: &str, key: &[u8]) -> tenzro_storage::Result<()> {
            self.inner.delete(cf, key)
        }
        fn write_batch(&self, ops: Vec<tenzro_storage::WriteOp>) -> tenzro_storage::Result<()> {
            self.inner.write_batch(ops)
        }
        fn write_batch_sync(
            &self,
            ops: Vec<tenzro_storage::WriteOp>,
        ) -> tenzro_storage::Result<()> {
            self.inner.write_batch_sync(ops)
        }
        fn get_keys_with_prefix(
            &self,
            cf: &str,
            prefix: &[u8],
        ) -> tenzro_storage::Result<Vec<Vec<u8>>> {
            self.inner.get_keys_with_prefix(cf, prefix)
        }
    }

    fn pending(id: &str, now: u64) -> PendingAuthSession {
        PendingAuthSession {
            session_id: id.to_string(),
            kind: AuthSessionKind::Enroll,
            status: AuthSessionStatus::Pending,
            challenge_b64: "c".to_string(),
            params: serde_json::json!({}),
            result: None,
            error: None,
            created_at_ms: now,
            expires_at_ms: now + AUTH_SESSION_TTL_MS,
        }
    }

    /// Creating a session does not read every session already stored.
    #[test]
    fn creating_a_session_does_not_walk_every_stored_session() {
        let counting = Arc::new(CountingStore::default());
        let store = PasskeySessionStore::with_storage(counting.clone());
        let now = now_ms();
        for i in 0..2_000 {
            store.put(&pending(&format!("s{i}"), now)).unwrap();
        }
        counting.gets.store(0, Ordering::SeqCst);
        store.create(&pending("new", now)).unwrap();
        let gets = counting.gets.load(Ordering::SeqCst);
        assert!(gets < 64, "one create read {gets} rows");
    }

    /// Past its capacity the store deletes the oldest session's row, and a
    /// restarted store indexes the rows it finds.
    #[test]
    fn the_session_store_holds_at_most_its_capacity() {
        let storage: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let store = PasskeySessionStore::with_capacity(storage.clone(), 3);
        let now = now_ms();
        for i in 0..5 {
            store.create(&pending(&format!("s{i}"), now + i)).unwrap();
        }
        let rows = || {
            storage
                .get_keys_with_prefix(CF_VALIDATOR_MODULES, PasskeySessionStore::PREFIX)
                .unwrap()
                .len()
        };
        assert_eq!(rows(), 3);
        assert!(store.get("s0").unwrap().is_none());
        assert!(store.get("s4").unwrap().is_some());

        let restarted = PasskeySessionStore::with_capacity(storage.clone(), 2);
        assert_eq!(rows(), 2);
        assert!(restarted.get("s2").unwrap().is_none());
        assert!(restarted.get("s4").unwrap().is_some());
    }
}
