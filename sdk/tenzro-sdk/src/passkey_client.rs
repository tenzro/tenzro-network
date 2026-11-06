//! Passkey-first wallet RPC client.
//!
//! Mirrors the `tenzro_*Passkey*` RPC surface defined in
//! `crates/tenzro-node/src/passkey_rpc.rs`. Every method maps 1:1 to a
//! single JSON-RPC call. Linked passkeys, policy and recovery live in the
//! account's keystore in consensus state: see [`crate::keystore`]. An
//! account acts through transactions its keystore authorizes
//! ([`crate::typed_tx`]).

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct PasskeyClient {
    rpc: Arc<RpcClient>,
}

impl PasskeyClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Enroll a passkey: the node checks its registration and possession,
    /// registers the human identity it derives, and returns the account it
    /// derives with that account's keystore (the passkey alone until the
    /// account's first keystore change, which carries the returned anchor).
    pub async fn enroll(&self, params: EnrollPasskeyParams) -> SdkResult<EnrollPasskeyResponse> {
        self.rpc
            .call("tenzro_enrollPasskey", serde_json::to_value(params)?)
            .await
    }

    // ── Device linking ──────────────────────────────────────────────
    //
    // Adding a device is a *custody change*: afterwards, a new key can spend
    // from the wallet. So it takes two ceremonies — proof of control from a
    // device already on the account, then registration of the new one.
    //
    // The account address alone is not proof. It is returned by `enroll`
    // and visible on-chain, so treating it as a credential would let anyone
    // who knows it enroll themselves.

    /// Ask the node for the challenge an already-enrolled passkey must sign
    /// to authorize one custody change.
    ///
    /// Single-use and time-bounded, bound to this account and this operation.
    /// Issuing is unauthenticated by design: a challenge is worthless without
    /// an enrolled credential to sign it, and gating issuance would only stop
    /// a legitimate owner from starting.
    pub async fn create_custody_challenge(
        &self,
        params: CustodyChallengeParams,
    ) -> SdkResult<CustodyChallengeResponse> {
        self.rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::to_value(params)?,
            )
            .await
    }

    // ---- Browser-launch WebAuthn session flow -------------------------

    /// Open a pending WebAuthn ceremony that a browser tab completes.
    ///
    /// The node returns a `verification_path` (`/auth/passkey?session=<id>`)
    /// that the caller opens; the page runs `navigator.credentials.create()`
    /// and posts the outcome back. Poll [`Self::get_passkey_session`] until
    /// the status is terminal. `kind` is `"enroll"`.
    pub async fn create_passkey_session(
        &self,
        params: CreatePasskeySessionParams,
    ) -> SdkResult<CreatePasskeySessionResponse> {
        self.rpc
            .call("tenzro_createPasskeySession", serde_json::to_value(params)?)
            .await
    }

    /// Poll a pending WebAuthn session by id. Status transitions
    /// pending → in_flight → completed | failed | expired.
    pub async fn get_passkey_session(
        &self,
        session_id: &str,
    ) -> SdkResult<GetPasskeySessionResponse> {
        self.rpc
            .call(
                "tenzro_getPasskeySession",
                serde_json::json!({ "session_id": session_id }),
            )
            .await
    }

    // ---- Passkey credential management --------------------------------

    // ---- Identity / credential lifecycle ------------------------------

    /// Revoke a single JWT by its `jti`, cascading to the act-chain
    /// transitive closure. Admin-token-gated.
    pub async fn revoke_jwt(&self, params: RevokeJwtParams) -> SdkResult<RevokeJwtResponse> {
        self.rpc
            .call("tenzro_revokeJwt", serde_json::to_value(params)?)
            .await
    }
}

// =============================================================================
// DTOs
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollPasskeyParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub passkey_public_key_hex: String,
    pub credential_id_hex: String,
    /// The ML-DSA-65 verifying key of the hardware that holds the passkey,
    /// hex. Required: the authorization's `ml_dsa_signature_hex` signs the
    /// same challenge with it, and passkey sign-in checks it.
    pub ml_dsa_public_key_hex: String,
    /// For a further wallet (salt above 0) under an existing identity:
    /// proof the caller holds this passkey, its assertion over the
    /// `webauthn_challenge` of an `enroll_passkey` custody challenge issued
    /// for the passkey's P-256 key with the credential id as target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<CustodyAuthorization>,
    /// The registration's `authenticatorData`, hex, as
    /// `navigator.credentials.create()` returned it. The node reads the
    /// passkey's backup flags from it. Required for a first wallet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_authenticator_data_hex: Option<String>,
    /// The relying party the passkey is registered on: the wallet
    /// provider's domain. The node's own when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub salt: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollPasskeyResponse {
    pub did: String,
    pub smart_account_address: String,
    pub credential_id_hex: String,
    /// The account's keystore: on chain, or its genesis record before its
    /// first change.
    pub keystore: serde_json::Value,
    /// The `previous_commitment` the account's next keystore change names.
    pub keystore_commitment: String,
    /// What the account's first keystore change carries; absent once it has
    /// a keystore on chain.
    #[serde(default)]
    pub anchor: Option<serde_json::Value>,
}

// ---- Session flow ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePasskeySessionParams {
    /// `"enroll"`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub salt: u64,
    /// Display label shown in the browser ceremony.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePasskeySessionResponse {
    pub session_id: String,
    /// Path on the node's web server to open in a browser
    /// (`/auth/passkey?session=<id>`).
    pub verification_path: String,
    /// `"pending" | "in_flight" | "completed" | "failed" | "expired"`.
    pub status: String,
    pub challenge_b64: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPasskeySessionResponse {
    pub session_id: String,
    /// `"enroll"`.
    pub kind: String,
    /// `"pending" | "in_flight" | "completed" | "failed" | "expired"`.
    pub status: String,
    /// Present once the ceremony completes; the shape mirrors the underlying
    /// enroll handler response.
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
    pub expires_at_ms: u64,
}

// ---- Passkey credential management ----------------------------------------

// ---- Identity / credential lifecycle --------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeJwtParams {
    pub jti: String,
    /// The hex DID envelope proving control of the token's bearer DID or of
    /// the controller DID that authorized it, bound to method
    /// `tenzro_revokeJwt` with the `jti` bytes as the params hash.
    pub did_envelope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeJwtResponse {
    pub jti: String,
    pub status: String,
    pub cascade: String,
}

// ---- Custody authorization -------------------------------------------------
//
// Changing who can sign for a wallet takes two ceremonies: proof of control
// from a device already on the account, then the change itself. The account
// address alone is not proof — it is returned by `enroll` and visible
// on-chain.

/// Which custody change a challenge authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyOperation {
    /// Approve a cluster membership list. The account is the operator's DID
    /// and the target the list's membership digest.
    SetClusterMembership,
    /// Prove possession of a passkey and its ML-DSA-65 key before they are
    /// enrolled. The account is the passkey's 64-byte P-256 public key
    /// (`x || y`) and the target `credential_id || ml_dsa_public_key`.
    EnrollPasskey,
    /// Delegate an agent. The account is the controller's smart account; the
    /// node computes the target from the terms sent as `delegation`.
    DelegateAgent,
    /// Replace a delegated agent's terms. The node computes the target from
    /// the new terms.
    UpdateAgentTerms,
    /// Revoke an identity on its root's authority: a root itself, or a
    /// delegated agent by its controller. The account is the approving root's
    /// and the target `revocation_target(did, reason)`.
    RevokeIdentity,
    /// Bind a device to an identity. The account is the identity DID's bytes
    /// and the target the device label's bytes.
    BindDevice,
    /// Unbind a device. The account is the identity DID's bytes and the
    /// target the credential id's bytes.
    RevokeDevice,
    /// Move a machine to a new owner. The account is the machine DID's bytes
    /// and the target the new owner DID's bytes.
    TransferMachineOwnership,
    /// Add, list or revoke a machine-access grant. The node derives the
    /// account and target from the change sent as `machine_access`.
    MachineAccess,
}

/// Request a custody challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyChallengeParams {
    /// The smart account being changed.
    pub account_address: String,
    /// Which change the challenge should authorize.
    pub operation: CustodyOperation,
    /// The operation's subject, hex-encoded — the session key being
    /// withdrawn, the signer being added.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_hex: Option<String>,
}

/// The challenge to sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyChallengeResponse {
    /// Present this back with the signed assertion.
    pub challenge_id: String,
    /// The 32-byte challenge digest, `0x`-prefixed.
    pub challenge_hex: String,
    /// The WebAuthn challenge the passkey signs: the composite digest of
    /// `challenge_hex` under the account-owner context, base64url.
    pub webauthn_challenge: String,
    /// The account it was issued for.
    pub account_address: String,
    /// The target the challenge is bound to, `0x`-prefixed.
    pub target_hex: String,
    /// The 16-byte challenge nonce, `0x`-prefixed. With the chain id,
    /// account, operation and target it lets the caller recompute
    /// `challenge_hex` before signing rather than trusting the node's word for
    /// it.
    pub nonce_hex: String,
    /// The chain id the challenge is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// How long it stays valid.
    pub expires_in_secs: u64,
    /// For agent delegation: the agent's DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    /// For agent delegation: the completed terms. Send them back unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<serde_json::Value>,
    /// For a terms update: whether the approval also withdraws the agent's
    /// live access tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_tokens: Option<bool>,
}

/// Proof of control accompanying a custody change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyAuthorization {
    /// From [`CustodyChallengeResponse::challenge_id`].
    pub challenge_id: String,
    /// A credential **already enrolled** on this account.
    pub credential_id_hex: String,
    /// That credential's assertion over
    /// [`CustodyChallengeResponse::webauthn_challenge`].
    pub assertion: serde_json::Value,
    /// The hardware ML-DSA-65 leg, required when the account has one
    /// enrolled: a signature over the composite representative of the
    /// challenge digest under the account-owner context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ml_dsa_signature_hex: Option<String>,
    /// For an account with no keystore on chain yet: its first passkey
    /// (`KeystoreAnchor`), which must derive the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<serde_json::Value>,
}
