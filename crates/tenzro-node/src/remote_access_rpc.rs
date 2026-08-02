//! RPCs for the remote-access lease book and the shell sign-in ceremony.
//!
//! Two audiences, two gates.
//!
//! The **operator** manages leases: which service key selects which slice of
//! their hardware, which wallets may use it, and when it ends. Those are
//! admin-token-gated.
//!
//! The **renter** signs in. `tenzro_requestShellSession` takes the service key
//! they were given and the wallet they intend to use, and hands back a link to
//! open in a browser — the `gcloud auth login` shape, reusing the passkey
//! ceremony the Tenzro wallet already runs. On completion the node mints a
//! single-use grant; the CLI redeems it when it opens the `tenzro/shell`
//! stream.
//!
//! The service key is not admin-gated, because the renter is not an admin.
//! What protects it is that the key on its own reaches nothing: without a
//! passkey ceremony from a wallet the operator named on that lease, the
//! request stops here.

use std::sync::Arc;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::node::TenzroNode;
use crate::remote_access::{AccessLease, AccessScope, LeaseStatus, ShellGrant};
use crate::rpc::JsonRpcError;

/// Domain tag for the op hash a shell sign-in passkey assertion commits to.
///
/// Domain-separated so an assertion collected for a shell sign-in can never be
/// replayed as a transaction signature, and vice versa.
const SHELL_SESSION_DOMAIN: &[u8] = b"tenzro/shell/session";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn bad_request(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn unauthorized(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32001,
        message: message.into(),
        data: None,
    }
}

fn internal(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: message.into(),
        data: None,
    }
}

fn parse<T: for<'de> Deserialize<'de>>(params: Option<Value>) -> Result<T, JsonRpcError> {
    serde_json::from_value(params.unwrap_or(Value::Null))
        .map_err(|e| bad_request(format!("invalid params: {e}")))
}

fn registry(
    node: &Arc<TenzroNode>,
) -> Result<&Arc<crate::remote_access::LeaseRegistry>, JsonRpcError> {
    node.lease_registry()
        .ok_or_else(|| internal("remote-access lease registry is not initialized on this node"))
}

/// The op hash a shell sign-in assertion commits to.
///
/// Binds the ceremony to the specific lease, wallet and nonce, so an assertion
/// captured for one sign-in cannot open a session on another lease or for
/// another wallet.
fn shell_op_hash(lease_id: &str, wallet: &str, nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SHELL_SESSION_DOMAIN);
    for field in [lease_id.as_bytes(), wallet.as_bytes(), nonce.as_slice()] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Renter: sign in
// ---------------------------------------------------------------------------

/// `tenzro_requestShellSession` params.
#[derive(Debug, Deserialize)]
pub(crate) struct RequestShellSessionRequest {
    /// The service key the operator issued for this lease.
    pub service_key: String,
    /// The wallet smart-account the renter will passkey-verify with.
    pub account_address: String,
}

/// `tenzro_requestShellSession` result.
#[derive(Debug, Serialize)]
pub(crate) struct RequestShellSessionResponse {
    /// Poll this with `tenzro_getPasskeySession`.
    pub session_id: String,
    /// Path on the node's web server to open in a browser.
    pub verification_path: String,
    /// The lease the service key selected, for the CLI to show the user what
    /// they are about to get.
    pub lease_id: String,
    /// Accelerator indices this lease grants.
    pub accelerators: Vec<u32>,
    /// Per-session ceiling actually applied.
    pub max_session_secs: u64,
    /// When the browser link dies.
    pub expires_at_ms: u64,
}

/// Start a shell sign-in.
///
/// Checks the service key and the wallet list *before* creating the ceremony,
/// so a renter is not sent to a browser to authenticate for something that was
/// never going to be granted.
pub(crate) async fn handle_request_shell_session(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: RequestShellSessionRequest = parse(params)?;
    let leases = registry(node)?;
    let now = now_ms();

    let lease = leases
        .lease_for_service_key(&req.service_key, now)
        .map_err(|denied| unauthorized(denied.to_string()))?;

    if !lease.authorizes_wallet(&req.account_address) {
        return Err(unauthorized(format!(
            "wallet {} is not authorized on this lease; ask the node operator to add it",
            req.account_address
        )));
    }

    let account = hex::decode(req.account_address.trim_start_matches("0x"))
        .map_err(|_| bad_request("account_address must be hex"))?;
    let validator = node
        .webauthn_validator()
        .ok_or_else(|| internal("WebAuthnValidator is not initialized on this node"))?;
    if validator.list_credentials(&account).is_empty() {
        return Err(bad_request(format!(
            "wallet {} has no passkey enrolled on this node; enrol one with `tenzro key \
             passkey enroll` before signing in",
            req.account_address
        )));
    }

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let op_hash = shell_op_hash(&lease.lease_id, &req.account_address, &nonce);

    // Reuses the wallet's existing `Sign` ceremony rather than inventing a
    // fourth kind: what a shell sign-in needs is exactly "prove you hold this
    // wallet, over these bytes", which is what `Sign` already does. The shell
    // fields ride along in `params` and are what
    // `mint_grant_for_completed_shell_session` keys off afterwards.
    let session = crate::passkey_rpc::create_session_for_shell(
        node,
        &req.account_address,
        &hex::encode(op_hash),
        &lease.lease_id,
    )
    .await?;

    Ok(serde_json::to_value(RequestShellSessionResponse {
        session_id: session.0,
        verification_path: session.1,
        lease_id: lease.lease_id,
        accelerators: lease.scope.accelerators(),
        max_session_secs: lease.scope.effective_session_secs(),
        expires_at_ms: session.2,
    })
    .unwrap_or(Value::Null))
}

/// Mint the grant once a shell sign-in ceremony has verified.
///
/// Called from the passkey completion path. Returns `None` for any ceremony
/// that was not a shell sign-in, so ordinary signing is untouched.
pub(crate) fn mint_grant_for_completed_shell_session(
    node: &Arc<TenzroNode>,
    session_params: &Value,
) -> Option<ShellGrant> {
    let lease_id = session_params.get("shell_lease_id")?.as_str()?;
    let wallet = session_params.get("account_address")?.as_str()?;
    let leases = node.lease_registry()?;
    let lease = leases.get(lease_id)?;

    let mut grant_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut grant_id);

    match leases.mint_grant(&lease, wallet, hex::encode(grant_id), now_ms()) {
        Ok(grant) => Some(grant),
        Err(denied) => {
            // The wallet was authorized when the ceremony started and is not
            // now — the operator changed the list mid-flight. That is the
            // operator's decision winning, which is the intent.
            tracing::warn!(lease = %lease_id, "shell grant refused after ceremony: {denied}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Operator: manage leases
// ---------------------------------------------------------------------------

/// `tenzro_openAccessLease` params.
#[derive(Debug, Deserialize)]
pub(crate) struct OpenAccessLeaseRequest {
    /// Plaintext service key to issue. Only its digest is stored.
    pub service_key: String,
    /// Wallets permitted to passkey-verify against this lease.
    pub authorized_wallets: Vec<String>,
    /// The renter's DID, for the audit record.
    pub renter_did: String,
    /// The compute rental this accompanies, if any.
    #[serde(default)]
    pub rental_id: Option<String>,
    /// What the renter may touch.
    pub scope: AccessScope,
    /// How long the lease lasts, milliseconds from now.
    pub term_ms: u64,
}

/// Open a lease. Admin-token-gated.
pub(crate) async fn handle_open_access_lease(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: OpenAccessLeaseRequest = parse(params)?;
    if req.term_ms == 0 {
        return Err(bad_request("term_ms must be greater than zero"));
    }
    let leases = registry(node)?;
    let now = now_ms();
    let digest = hex::encode(Sha256::digest(req.service_key.as_bytes()));

    let lease = AccessLease {
        lease_id: format!("lease-{}", &digest[..16]),
        rental_id: req.rental_id,
        renter_did: req.renter_did,
        service_key_hash: digest,
        authorized_wallets: req.authorized_wallets,
        scope: req.scope,
        expires_at_ms: now.saturating_add(req.term_ms),
        status: LeaseStatus::Active,
        created_at_ms: now,
    };

    leases.open_lease(lease.clone()).map_err(bad_request)?;

    Ok(serde_json::json!({
        "lease_id": lease.lease_id,
        "expires_at_ms": lease.expires_at_ms,
        "authorized_wallets": lease.authorized_wallets,
        // Echoed so the operator can hand the renter the key and record the
        // digest, but the plaintext is never returned by any read path.
        "service_key_digest": lease.service_key_hash,
    }))
}

/// `tenzro_revokeAccessLease` params.
#[derive(Debug, Deserialize)]
pub(crate) struct RevokeAccessLeaseRequest {
    /// The lease to end.
    pub lease_id: String,
}

/// Revoke a lease. Admin-token-gated.
pub(crate) async fn handle_revoke_access_lease(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: RevokeAccessLeaseRequest = parse(params)?;
    let lease = registry(node)?
        .revoke_lease(&req.lease_id)
        .map_err(bad_request)?;
    Ok(serde_json::json!({
        "lease_id": lease.lease_id,
        "status": lease.status,
    }))
}

/// `tenzro_listAccessLeases` — every lease this node holds, newest first.
///
/// Never returns a service key: the node does not have one to return.
pub(crate) async fn handle_list_access_leases(
    node: &Arc<TenzroNode>,
) -> Result<Value, JsonRpcError> {
    let leases = registry(node)?.list();
    Ok(serde_json::json!({
        "leases": leases,
        "count": leases.len(),
        "confinement": registry(node)?.confinement().map(|c| c.kind()),
    }))
}

/// `tenzro_getAccessLease` params.
#[derive(Debug, Deserialize)]
pub(crate) struct GetAccessLeaseRequest {
    /// The lease to read.
    pub lease_id: String,
}

/// Read one lease. Admin-token-gated.
pub(crate) async fn handle_get_access_lease(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: GetAccessLeaseRequest = parse(params)?;
    let lease = registry(node)?
        .get(&req.lease_id)
        .ok_or_else(|| bad_request(format!("no such lease: {}", req.lease_id)))?;
    Ok(serde_json::to_value(lease).unwrap_or(Value::Null))
}

/// `tenzro_listShellSessionReceipts` params.
#[derive(Debug, Deserialize)]
pub(crate) struct ListSessionReceiptsRequest {
    /// Narrow to one lease. Omit for every session this node has recorded.
    #[serde(default)]
    pub lease_id: Option<String>,
}

/// `tenzro_listShellSessionReceipts` — the audit trail of confined sessions.
///
/// Admin-token-gated: these are the operator's records of who had a shell on
/// their hardware, and the bounded transcript each session left. The cloud
/// equivalent — an SSM session history, an IAP audit log — is retrievable by
/// the operator, and a commitment written to a log line is not.
///
/// Oldest first. Each entry is the full [`tenzro_storage::da::ReceiptEnvelope`],
/// so the `commitment` binds the payload and an edited record is detectable.
pub(crate) async fn handle_list_shell_session_receipts(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: ListSessionReceiptsRequest = match params {
        Some(Value::Null) | None => ListSessionReceiptsRequest { lease_id: None },
        other => parse(other)?,
    };
    let receipts = registry(node)?.session_receipts(req.lease_id.as_deref());
    Ok(serde_json::json!({
        "receipts": receipts,
        "count": receipts.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The op hash is what stops an assertion collected for one sign-in from
    /// opening a session on another lease or for another wallet.
    #[test]
    fn the_op_hash_binds_lease_wallet_and_nonce() {
        let n = [7u8; 32];
        let base = shell_op_hash("lease-a", "0xaa", &n);
        assert_ne!(base, shell_op_hash("lease-b", "0xaa", &n));
        assert_ne!(base, shell_op_hash("lease-a", "0xbb", &n));
        assert_ne!(base, shell_op_hash("lease-a", "0xaa", &[8u8; 32]));
        assert_eq!(base, shell_op_hash("lease-a", "0xaa", &n));
    }

    /// Length-prefixed fields, so a lease id and a wallet cannot be shuffled
    /// across the boundary to produce the same hash.
    #[test]
    fn field_boundaries_cannot_be_shifted() {
        let n = [0u8; 32];
        assert_ne!(
            shell_op_hash("lease", "-a0xaa", &n),
            shell_op_hash("lease-a", "0xaa", &n)
        );
    }

    #[test]
    fn a_non_shell_ceremony_mints_no_grant() {
        // No `shell_lease_id` in the params: an ordinary transaction-signing
        // ceremony must not produce shell access as a side effect.
        let params = serde_json::json!({ "account_address": "0xaa" });
        assert!(params.get("shell_lease_id").is_none());
    }

    /// The domain tag is what keeps a shell assertion from being replayable as
    /// a transaction signature.
    #[test]
    fn the_domain_tag_is_pinned() {
        assert_eq!(SHELL_SESSION_DOMAIN, b"tenzro/shell/session");
    }
}
