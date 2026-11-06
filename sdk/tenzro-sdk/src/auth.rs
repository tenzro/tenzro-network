//! OAuth 2.1 + DPoP onboarding helpers for Tenzro Network.
//!
//! Onboarding uses OAuth 2.1 (RFC 6749 successor) + DPoP-bound JWTs
//! (RFC 9449) + Rich Authorization Requests (RFC 9396). Participants —
//! humans, delegated agents under a human controller, and fully
//! autonomous agents — onboard via the three RPCs exposed here. Each
//! call provisions a TDIP identity (+ permissionless wallet) and returns a JWT
//! bound to a holder-supplied DPoP `jkt` (RFC 7638 thumbprint of the
//! holder's Ed25519 public key).
//!
//! Subsequent privileged calls (sign + send transaction, escrow create,
//! release/refund, etc.) authenticate by sending the JWT in the
//! `Authorization: Bearer <jwt>` header alongside a per-request DPoP proof
//! in the `DPoP` header (when the token is DPoP-bound). The SDK forwards
//! both headers automatically when the `TENZRO_BEARER_JWT` and
//! `TENZRO_DPOP_PROOF` environment variables are set — see
//! [`crate::rpc::RpcClient`] for the transport-level wiring.
//!
//! # Example
//!
//! ```no_run
//! # use tenzro_sdk::{TenzroClient, config::SdkConfig};
//! # use tenzro_sdk::passkey_client::{CustodyAuthorization, CustodyChallengeResponse};
//! # async fn sign_on_my_authenticator(
//! #     _: CustodyChallengeResponse,
//! # ) -> tenzro_sdk::error::SdkResult<CustodyAuthorization> { unimplemented!() }
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
//! # let (credential_id_hex, public_key_hex) = ("", "");
//! let auth = client.auth();
//! // The passkey stays on the caller's authenticator, which signs the
//! // node's `enroll_passkey` challenge.
//! let session = auth
//!     .onboard_human(
//!         "Alice",
//!         credential_id_hex,
//!         public_key_hex,
//!         None,
//!         sign_on_my_authenticator,
//!     )
//!     .await?;
//! println!("DID:    {}", session.identity["did"]);
//! println!("Wallet: {}", session.wallet["address"]);
//! println!("Token:  {}…", &session.access_token[..32]);
//! # Ok(()) }
//! ```

use crate::error::{SdkError, SdkResult};
use crate::passkey_client::{
    CustodyAuthorization, CustodyChallengeParams, CustodyChallengeResponse, CustodyOperation,
};
use crate::rpc::RpcClient;
use crate::wallet::{
    ACCOUNT_OWNER_SIGNATURE_CONTEXT, HybridSigner, composite_message_representative,
    composite_signature_json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A machine root's approval of a custody challenge, for the `authorize`
/// callback of [`AuthClient::delegate_agent`], [`AuthClient::update_agent_terms`]
/// and [`AuthClient::revoke_identity`] when the agent's root is an
/// autonomous machine: its TPM or Secure Enclave signature over the
/// challenge digest. A human root returns a passkey [`CustodyAuthorization`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineRootAuthorization {
    /// From [`CustodyChallengeResponse::challenge_id`].
    pub challenge_id: String,
    /// The composite signature, JSON.
    pub signature: serde_json::Value,
}

/// The composite signature of the machine root `signer` over a challenge
/// digest under the account-owner context, as validators verify it.
async fn sign_root_digest(
    signer: &dyn HybridSigner,
    digest_hex: &str,
) -> SdkResult<serde_json::Value> {
    let digest = decode_hex_field("challenge_hex", digest_hex)?;
    let m_prime = composite_message_representative(ACCOUNT_OWNER_SIGNATURE_CONTEXT, &digest);
    let (p256, pq) = signer.sign_composite(&m_prime).await?;
    Ok(composite_signature_json(&p256, pq.as_deref()))
}

/// Approve `challenge` as a machine root with its hardware `signer`.
pub async fn machine_root_authorization(
    challenge: &CustodyChallengeResponse,
    signer: &dyn HybridSigner,
) -> SdkResult<MachineRootAuthorization> {
    Ok(MachineRootAuthorization {
        challenge_id: challenge.challenge_id.clone(),
        signature: sign_root_digest(signer, &challenge.challenge_hex).await?,
    })
}

/// The `step_up` a machine root gives a held action: `step_up` is the error
/// data `tenzro_agentAct` returned (its `step_up` object). Send the same
/// action again with the result as its `step_up`.
pub async fn machine_root_step_up(
    step_up: &serde_json::Value,
    signer: &dyn HybridSigner,
) -> SdkResult<AgentStepUp> {
    let step_up = step_up.get("step_up").unwrap_or(step_up);
    let field = |name: &str| {
        step_up
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| SdkError::InvalidParameter(format!("step_up.{name} is missing")))
    };
    Ok(AgentStepUp {
        account: field("account")?,
        nonce: field("nonce")?,
        root_public_key: hex::encode(signer.p256_public_key()),
        signature: sign_root_digest(signer, &field("challenge_hex")?).await?,
    })
}

/// The custody digest a machine root signs to cast its validator's
/// governance ballot on the network `chain_id`: `account` (the validator
/// account), the operation `governance_ballot` and the target
/// `proposal_id || vote || len || validator`, under `nonce`.
pub fn governance_ballot_digest(
    chain_id: u64,
    account: &[u8],
    proposal_id: &[u8; 32],
    vote: bool,
    validator: &[u8],
    nonce: &[u8; 16],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut target = proposal_id.to_vec();
    target.push(u8::from(vote));
    target.push(validator.len() as u8);
    target.extend_from_slice(validator);
    let mut h = Sha256::new();
    h.update(b"tenzro/custody-challenge/v2");
    h.update(chain_id.to_be_bytes());
    for part in [account, b"governance_ballot".as_slice(), target.as_slice()] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.update(nonce);
    h.finalize().into()
}

/// The `root_approval` of a `GovernanceVote` for a validator whose identity
/// is the autonomous machine holding `signer`: the hardware key its machine
/// DID derives from approves exactly this ballot on the network `chain_id`.
/// Put it in the transaction's `GovernanceVote.root_approval`; any account
/// may submit it.
pub async fn machine_root_ballot(
    signer: &dyn HybridSigner,
    chain_id: u64,
    proposal_id_hex: &str,
    vote: bool,
    validator_hex: &str,
) -> SdkResult<serde_json::Value> {
    {
        let proposal_id: [u8; 32] = decode_hex_field("proposal_id", proposal_id_hex)?
            .try_into()
            .map_err(|_| SdkError::InvalidParameter("proposal_id is 32 bytes".to_string()))?;
        let validator = decode_hex_field("validator", validator_hex)?;
        if validator.len() != 32 {
            return Err(SdkError::InvalidParameter(
                "validator is a 32-byte account".to_string(),
            ));
        }
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| SdkError::InvalidParameter(format!("nonce: {e}")))?;
        let digest =
            governance_ballot_digest(chain_id, &validator, &proposal_id, vote, &validator, &nonce);
        let m_prime = composite_message_representative(ACCOUNT_OWNER_SIGNATURE_CONTEXT, &digest);
        let (p256, pq) = signer.sign_composite(&m_prime).await?;
        Ok(serde_json::json!({
            "account": validator,
            "nonce": nonce,
            "root_public_key": signer.p256_public_key().to_vec(),
            "signature": composite_signature_json(&p256, pq.as_deref()),
        }))
    }
}

fn decode_hex_field(field: &str, value: &str) -> SdkResult<Vec<u8>> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| SdkError::InvalidParameter(format!("{field} is not hex: {e}")))
}

/// The completed terms a delegation challenge carries, to send back unchanged.
fn completed_terms(challenge: &CustodyChallengeResponse) -> SdkResult<serde_json::Value> {
    challenge.delegation.clone().ok_or_else(|| {
        SdkError::InvalidParameter("the node returned no completed delegation terms".to_string())
    })
}

/// Client for OAuth 2.1 onboarding RPCs.
///
/// Construct via [`crate::TenzroClient::auth`].
#[derive(Clone)]
pub struct AuthClient {
    rpc: Arc<RpcClient>,
}

impl AuthClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Onboard a new **human** participant — provisions a TDIP `did:tenzro:human:*`
    /// identity rooted in the caller's passkey, a permissionless wallet, and
    /// returns an OAuth 2.1 access token.
    ///
    /// The node only onboards a caller that proves it holds the passkey. This
    /// method requests the `enroll_passkey` custody challenge for exactly that
    /// passkey and hands it to `authorize`, which has the authenticator sign
    /// its `webauthn_challenge` and returns the [`CustodyAuthorization`]. The
    /// SDK never sees the private key.
    ///
    /// # Arguments
    ///
    /// * `display_name` — human-readable label surfaced in approver UIs.
    /// * `credential_id_hex` — the passkey's credential id.
    /// * `public_key_hex` — the passkey's P-256 public key, raw `x || y` or
    ///   SEC1 uncompressed (`04 || x || y`).
    /// * `dpop_jkt` — optional RFC 7638 JWK thumbprint of the holder's Ed25519
    ///   public key. If supplied, the issued JWT is DPoP-bound to that key
    ///   and every subsequent privileged call must accompany the bearer with
    ///   a fresh DPoP proof signed by the same key. Strongly recommended.
    /// * `authorize` — signs the issued challenge on the caller's
    ///   authenticator; its `credential_id_hex` must be `credential_id_hex`.
    pub async fn onboard_human<F, Fut>(
        &self,
        display_name: &str,
        credential_id_hex: &str,
        public_key_hex: &str,
        dpop_jkt: Option<&str>,
        authorize: F,
    ) -> SdkResult<OnboardSession>
    where
        F: FnOnce(CustodyChallengeResponse) -> Fut,
        Fut: std::future::Future<Output = SdkResult<CustodyAuthorization>>,
    {
        let credential_id = decode_hex_field("credential_id_hex", credential_id_hex)?;
        let public_key = decode_hex_field("public_key_hex", public_key_hex)?;
        let passkey_xy = match public_key.len() {
            64 => public_key.as_slice(),
            65 if public_key[0] == 0x04 => &public_key[1..],
            n => {
                return Err(SdkError::InvalidParameter(format!(
                    "public_key_hex must be a raw 64-byte or SEC1 65-byte P-256 key, got {n} bytes"
                )));
            }
        };

        // The challenge names the passkey being enrolled and binds its
        // credential id, so it cannot enrol another credential.
        let challenge: CustodyChallengeResponse = self
            .rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::to_value(CustodyChallengeParams {
                    account_address: hex::encode(passkey_xy),
                    operation: CustodyOperation::EnrollPasskey,
                    target_hex: Some(hex::encode(&credential_id)),
                })?,
            )
            .await?;
        let authorization = authorize(challenge).await?;

        let mut params = serde_json::json!({
            "display_name": display_name,
            "credential_id": hex::encode(&credential_id),
            "public_key": hex::encode(passkey_xy),
            "authorization": authorization,
        });
        if let Some(jkt) = dpop_jkt {
            params["dpop_jkt"] = serde_json::Value::String(jkt.to_string());
        }
        self.rpc.call("tenzro_onboardHuman", params).await
    }

    /// Onboard a **machine** as a delegated agent of an existing
    /// `controller_did` (a human). The machine's key lives in its TPM or
    /// Secure Enclave; `device_public_key_hex` is its public half. The
    /// controller approves the machine's terms, with its hardware key as the
    /// single serving node, through a `delegate_agent` custody challenge on
    /// their smart account (`account_address`); `authorize` signs it with a
    /// passkey enrolled there.
    #[allow(clippy::too_many_arguments)]
    pub async fn onboard_delegated_agent<F, Fut, A>(
        &self,
        account_address: &str,
        controller_did: &str,
        device_public_key_hex: &str,
        machine_id: &str,
        capabilities: Vec<String>,
        delegation_scope: serde_json::Value,
        dpop_jkt: Option<&str>,
        authorize: F,
    ) -> SdkResult<OnboardSession>
    where
        F: FnOnce(CustodyChallengeResponse) -> Fut,
        Fut: std::future::Future<Output = SdkResult<A>>,
        A: Serialize,
    {
        let challenge: CustodyChallengeResponse = self
            .rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::json!({
                    "account_address": account_address,
                    "operation": CustodyOperation::DelegateAgent,
                    "device_public_key": device_public_key_hex,
                    "machine_id": machine_id,
                    "delegation": {
                        "controller_did": controller_did,
                        "agent_name": machine_id,
                        "delegation_scope": delegation_scope,
                        "capabilities": capabilities,
                    },
                }),
            )
            .await?;
        let authorization = authorize(challenge).await?;
        let mut params = serde_json::json!({
            "controller_did": controller_did,
            "device_public_key": device_public_key_hex,
            "machine_id": machine_id,
            "capabilities": capabilities,
            "delegation_scope": delegation_scope,
            "authorization": authorization,
        });
        if let Some(jkt) = dpop_jkt {
            params["dpop_jkt"] = serde_json::Value::String(jkt.to_string());
        }
        self.rpc.call("tenzro_onboardDelegatedAgent", params).await
    }

    /// Take one action as a delegated agent, with the agent's access token
    /// on the transport. The serving node checks it against the agent's
    /// approved terms, signs it with its hardware key only when it is within
    /// them, and submits it; the chain checks it again at execution.
    pub async fn agent_act(&self, action: AgentActRequest) -> SdkResult<AgentActResult> {
        self.rpc
            .call("tenzro_agentAct", serde_json::to_value(action)?)
            .await
    }

    /// The agent's next cumulative voucher on a channel its wallet funded,
    /// signed by the serving node with its hardware key for the agent. The
    /// node signs only a voucher the ledger would honour now.
    pub async fn agent_voucher(
        &self,
        channel_id: &str,
        cumulative_amount: u128,
    ) -> SdkResult<AgentVoucherResult> {
        self.rpc
            .call(
                "tenzro_agentVoucher",
                serde_json::json!({
                    "channel_id": channel_id,
                    "cumulative_amount": cumulative_amount.to_string(),
                }),
            )
            .await
    }

    /// One payment's consensus record by its reference (hex) or the payment
    /// id it settled under; `Null` when none.
    pub async fn get_payment(
        &self,
        pay_ref: Option<&str>,
        payment_id: Option<&str>,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getPayment",
                serde_json::json!({ "pay_ref": pay_ref, "payment_id": payment_id }),
            )
            .await
    }

    /// Consensus payment records in chain order, read from the event index.
    /// `query` takes `payee`, `payer`, `agent_did`, `class` (`native`,
    /// `proven`, `attested`), `asset`, `from_cursor`, `from_height`,
    /// `to_cursor`, `limit` and `proofs`. The answer is `{ payments, cursor }`,
    /// each entry `{ cursor, tx_hash, record, proof? }`; pass `cursor` back
    /// as `from_cursor` to continue with no gap.
    pub async fn list_payments(&self, query: serde_json::Value) -> SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_listPayments", query).await
    }

    /// The standing split rule every payment `payee` (32-byte hex) receives
    /// is divided by after the fee, from consensus state: `{ rule }` in the
    /// split engine's form, `rule: null` when it set none.
    pub async fn get_payee_split(&self, payee: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_getPayeeSplit",
                serde_json::json!({ "payee": payee }),
            )
            .await
    }

    /// As the payee, return `amount` (smallest unit, in the asset it was paid
    /// in) of the native payment `pay_ref` (32-byte hex) to its payer, as a
    /// `Payment` transaction `signer` signs locally. Refunds on one record
    /// never exceed what it paid.
    pub async fn refund_payment(
        &self,
        signer: &dyn crate::wallet::HybridSigner,
        pay_ref: &str,
        amount: u128,
    ) -> SdkResult<serde_json::Value> {
        self.send_payment_op(signer, refund_op(pay_ref, amount)?)
            .await
    }

    /// As the payee, set the standing split rule (the split engine's form,
    /// as `get_payee_split` returns it) every payment it receives is divided
    /// by after the fee; `None` clears it. A `Payment` transaction `signer`
    /// signs locally.
    pub async fn set_payee_split(
        &self,
        signer: &dyn crate::wallet::HybridSigner,
        rule: Option<serde_json::Value>,
    ) -> SdkResult<serde_json::Value> {
        self.send_payment_op(signer, serde_json::json!({ "set_split": { "rule": rule } }))
            .await
    }

    async fn send_payment_op(
        &self,
        signer: &dyn crate::wallet::HybridSigner,
        op: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        use crate::typed_tx::{TxKind, TypedTransaction, TypedTxClient};
        let tx = TypedTransaction::new(TxKind::Payment, serde_json::json!({ "op": op }))?;
        TypedTxClient::new(self.rpc.clone()).send(signer, &tx).await
    }

    /// Delegate an agent with its root's approval: a human's passkey, or a machine's hardware key (machine_root_authorization).
    ///
    /// `terms` names the controller, the agent, its scope and limits, its
    /// capabilities, its serving nodes as `[{machine_did, operator_did}]`,
    /// `min_distinct_operators` and `expires_at_ms`. The node completes each
    /// serving node's key and returns a challenge over the completed terms;
    /// `authorize` signs it with a passkey enrolled on the controller's
    /// smart account (`account_address`). The serving nodes deliver the
    /// agent's access tokens; the result says how each delivery went.
    pub async fn delegate_agent<F, Fut, A>(
        &self,
        account_address: &str,
        terms: serde_json::Value,
        authorize: F,
    ) -> SdkResult<DelegatedAgent>
    where
        F: FnOnce(CustodyChallengeResponse) -> Fut,
        Fut: std::future::Future<Output = SdkResult<A>>,
        A: Serialize,
    {
        let challenge: CustodyChallengeResponse = self
            .rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::json!({
                    "account_address": account_address,
                    "operation": CustodyOperation::DelegateAgent,
                    "delegation": terms,
                }),
            )
            .await?;
        let delegation = completed_terms(&challenge)?;
        let authorization = authorize(challenge).await?;
        self.rpc
            .call(
                "tenzro_onboardDelegatedAgent",
                serde_json::json!({
                    "delegation": delegation,
                    "authorization": authorization,
                }),
            )
            .await
    }

    /// Replace a delegated agent's terms with the controller's passkey. The
    /// agent's DID stays the same; with `rotate_tokens` set, its live access
    /// tokens are withdrawn and the result counts them.
    pub async fn update_agent_terms<F, Fut, A>(
        &self,
        account_address: &str,
        agent_did: &str,
        terms: serde_json::Value,
        rotate_tokens: bool,
        authorize: F,
    ) -> SdkResult<AgentTermsUpdate>
    where
        F: FnOnce(CustodyChallengeResponse) -> Fut,
        Fut: std::future::Future<Output = SdkResult<A>>,
        A: Serialize,
    {
        let challenge: CustodyChallengeResponse = self
            .rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::json!({
                    "account_address": account_address,
                    "operation": CustodyOperation::UpdateAgentTerms,
                    "agent_did": agent_did,
                    "delegation": terms,
                    "rotate_tokens": rotate_tokens,
                }),
            )
            .await?;
        let delegation = completed_terms(&challenge)?;
        let authorization = authorize(challenge).await?;
        self.rpc
            .call(
                "tenzro_updateAgentTerms",
                serde_json::json!({
                    "agent_did": agent_did,
                    "delegation": delegation,
                    "rotate_tokens": rotate_tokens,
                    "authorization": authorization,
                }),
            )
            .await
    }

    /// Revoke an identity with its root's approval (a passkey, or a machine's
    /// hardware key): a root revokes itself, a delegated agent is revoked by
    /// the controller its terms name, and a machine a root registered by
    /// that root. `account_address` is the approving root's account and
    /// `approver_did` the root (`did` itself when `None`).
    ///
    /// `approve` signs the `revoke_identity` challenge, which covers `did`
    /// and `reason`, and returns the root's key and signature. The SDK puts
    /// the approval into a `RevokeIdentity` transaction, signs it with
    /// `signer` (any account may send it; the approval authorises it) and
    /// submits it with `tenzro_revokeIdentity`. Every validator re-verifies
    /// the approval; once the transaction is in a block every node treats
    /// the identity as revoked and revokes its tokens, and revoking a root
    /// also revokes every agent it delegated.
    #[allow(clippy::too_many_arguments)]
    pub async fn revoke_identity<F, Fut>(
        &self,
        signer: &dyn crate::wallet::HybridSigner,
        account_address: &str,
        did: &str,
        approver_did: Option<&str>,
        reason: Option<&str>,
        approve: F,
    ) -> SdkResult<RevokeResponse>
    where
        F: FnOnce(CustodyChallengeResponse) -> Fut,
        Fut: std::future::Future<Output = SdkResult<RootApproval>>,
    {
        let reason = reason.unwrap_or(DEFAULT_REVOCATION_REASON);
        let challenge: CustodyChallengeResponse = self
            .rpc
            .call(
                "tenzro_createCustodyChallenge",
                serde_json::to_value(CustodyChallengeParams {
                    account_address: account_address.to_string(),
                    operation: CustodyOperation::RevokeIdentity,
                    target_hex: Some(hex::encode(revocation_target(did, reason))),
                })?,
            )
            .await?;
        let account = unhex(&challenge.account_address)?;
        let nonce = unhex(&challenge.nonce_hex)?;
        let root = approve(challenge).await?;
        let op = serde_json::json!({
            "did": did,
            "reason": reason,
            "approver_did": approver_did.unwrap_or(did),
            "approval": {
                "account": account,
                "nonce": nonce,
                "root_public_key": root.root_public_key,
                "signature": root.signature,
            },
        });
        let tx = crate::typed_tx::TypedTransaction::new(
            crate::typed_tx::TxKind::RevokeIdentity,
            serde_json::json!({ "op": op }),
        )?
        .gas_limit(REVOCATION_GAS_LIMIT);
        let answer = crate::typed_tx::TypedTxClient::new(self.rpc.clone())
            .send_via("tenzro_revokeIdentity", signer, &tx)
            .await?;
        serde_json::from_value(answer)
            .map_err(|e| SdkError::RpcError(format!("tenzro_revokeIdentity: {e}")))
    }

    /// Onboard a **fully autonomous agent**, rooted in its own secure
    /// element: `device_public_key` (hex) and the `machine_id` of the element
    /// holding it. It has no human controller; instead its bond must already
    /// be locked on chain: an active `PostAgentBond` of at least 1 TNZO for
    /// the DID the device key derives.
    pub async fn onboard_autonomous_agent(
        &self,
        device_public_key: &str,
        machine_id: &str,
        dpop_jkt: Option<&str>,
    ) -> SdkResult<OnboardSession> {
        let mut params = serde_json::json!({
            "device_public_key": device_public_key,
            "machine_id": machine_id,
        });
        if let Some(jkt) = dpop_jkt {
            params["dpop_jkt"] = serde_json::Value::String(jkt.to_string());
        }
        self.rpc.call("tenzro_onboardAutonomousAgent", params).await
    }

    /// Exchange a long-lived refresh token for a fresh access token. Mirrors
    /// OAuth 2.1 `grant_type=refresh_token`. Refresh tokens are opaque UUIDs
    /// with a 30-day TTL; access tokens are ES256 JWTs with a 1-hour TTL.
    ///
    /// `prover` holds the key the refresh token is bound to and proves it
    /// for this request; a refresh token issued without a key is bound to it
    /// from now on. Each refresh token is good for one exchange: keep the
    /// `refresh_token` the answer carries for the next one.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        prover: &dyn crate::access::DpopProver,
    ) -> SdkResult<RefreshedToken> {
        self.rpc
            .call_with_proof(
                "tenzro_refreshToken",
                serde_json::json!({ "refresh_token": refresh_token }),
                prover,
            )
            .await
    }

    /// Revoke a single JWT by its `jti` claim. The token is added to the
    /// engine's revocation set and any subsequent validation fails.
    ///
    /// `did_envelope` is the hex envelope proving control of the token's
    /// bearer DID **or** of the controller DID that authorized it, bound to
    /// method `tenzro_revokeJwt` with the `jti` bytes as the params hash. A
    /// `jti` travels in every audit row, so it is an identifier, not a
    /// credential.
    pub async fn revoke_jwt(
        &self,
        jti: &str,
        did_envelope: &str,
        reason: Option<&str>,
    ) -> SdkResult<RevokeResponse> {
        let params = serde_json::json!({
            "jti": jti,
            "did_envelope": did_envelope,
            "reason": reason.unwrap_or("revoked via SDK"),
        });
        self.rpc.call("tenzro_revokeJwt", params).await
    }

    /// TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously
    /// revoked identity from the registry and persistent storage.
    ///
    /// The identity MUST already be `Revoked` — call [`Self::revoke_identity`] first,
    /// allow the cascading revocation broadcaster to propagate, and then
    /// call this. Distinct from [`Self::revoke_identity`] which is a logical delete.
    ///
    /// Returns the erased DID and confirmation status.
    pub async fn forget_identity(&self, did: &str) -> SdkResult<serde_json::Value> {
        let params = serde_json::json!({ "did": did });
        self.rpc.call("tenzro_forgetIdentity", params).await
    }

    /// **RFC 8693 OAuth 2.0 Token Exchange.** Exchange a parent JWT for a
    /// narrower child JWT bound to a different DPoP key, with a strictly
    /// subset of the parent's RAR grants and AAP capabilities. The child
    /// token's `controller_did` is set to the parent's `sub`, extending
    /// the act-chain by one hop.
    ///
    /// Subset enforcement is performed by the AS — `requested_rar` and
    /// `requested_aap_capabilities` must be a strict subset of what the
    /// parent already holds. Anything outside the parent's authority is
    /// rejected with JSON-RPC error code `-32002`.
    ///
    /// # Arguments
    ///
    /// * `subject_token` — the parent JWT (validated for signature, exp,
    ///   and revocation by the AS).
    /// * `child_bearer_did` — DID that will be the `sub` of the child JWT.
    /// * `child_dpop_jkt` — RFC 7638 JWK thumbprint of the child holder's
    ///   Ed25519 public key. The child token will be DPoP-bound to it.
    /// * `requested_rar` — typed scope envelope (RFC 9396) the child should
    ///   carry. Must be a subset of the parent's `authorization_details`.
    /// * `requested_aap_capabilities` — AAP `aap_capabilities` claim list.
    ///   Must be a subset of the parent's capabilities.
    /// * `requested_ttl_secs` — optional override; clamped to the engine's
    ///   `max_ttl_secs` and parent's remaining lifetime.
    pub async fn exchange_token(
        &self,
        subject_token: &str,
        child_bearer_did: &str,
        child_dpop_jkt: &str,
        requested_rar: serde_json::Value,
        requested_aap_capabilities: Vec<serde_json::Value>,
        requested_ttl_secs: Option<u64>,
    ) -> SdkResult<TokenExchangeResult> {
        let mut params = serde_json::json!({
            "subject_token": subject_token,
            "child_bearer_did": child_bearer_did,
            "child_dpop_jkt": child_dpop_jkt,
            "requested_rar": requested_rar,
            "requested_aap_capabilities": requested_aap_capabilities,
        });
        if let Some(ttl) = requested_ttl_secs {
            params["requested_ttl_secs"] = serde_json::Value::Number(ttl.into());
        }
        self.rpc.call("tenzro_exchangeToken", params).await
    }

    /// **RFC 7662 OAuth 2.0 Token Introspection.** Ask the AS whether a
    /// token is currently active and, if so, return its full claim set
    /// (RAR, AAP, cnf, controller_did, etc.). Per RFC 7662 §2.2 a failed
    /// validation returns `{"active": false}` with no other fields — the
    /// AS deliberately does not leak why the token is inactive.
    ///
    /// Use this from a downstream resource server that wants to validate
    /// a bearer token without re-implementing JWT signature checking.
    pub async fn introspect_token(&self, token: &str) -> SdkResult<IntrospectionResult> {
        let params = serde_json::json!({ "token": token });
        self.rpc.call("tenzro_introspectToken", params).await
    }

    /// **RFC 8414 / RFC 9728 OAuth Authorization Server / Protected
    /// Resource Metadata.** Returns the same metadata document the AS
    /// publishes at `GET /.well-known/openid-configuration`. Useful for
    /// JSON-RPC-only clients (CLI, agents) that don't want to also speak
    /// HTTP discovery.
    pub async fn oauth_discovery(&self) -> SdkResult<OAuthDiscovery> {
        self.rpc
            .call("tenzro_oauthDiscovery", serde_json::Value::Null)
            .await
    }
}

/// One of the three onboarding RPCs (or `link_wallet_for_auth`) returns
/// this session bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardSession {
    /// Provisioned TDIP identity record.
    pub identity: serde_json::Value,
    /// Provisioned permissionless wallet record (id + address).
    pub wallet: serde_json::Value,
    /// OAuth 2.1 access token (ES256 JWT, optionally DPoP-bound). Send as
    /// `Authorization: Bearer <token>` on subsequent privileged calls.
    /// When DPoP-bound, also send a fresh `DPoP: <proof>` header.
    pub access_token: String,
    /// Always `"Bearer"` (RFC 6750 token type, even though DPoP-bound).
    #[serde(default)]
    pub token_type: String,
    /// Access-token lifetime in seconds (default 3600).
    #[serde(default)]
    pub expires_in: u64,
    /// Long-lived refresh token (opaque UUID, 30-day TTL). Exchange via
    /// [`AuthClient::refresh_token`] when the access token expires. Treat
    /// as a secret — leakage allows minting access tokens until revocation.
    #[serde(default)]
    pub refresh_token: String,
    /// Refresh-token lifetime in seconds (default 30 days).
    #[serde(default)]
    pub refresh_token_expires_in: u64,
    /// `true` iff the access token requires a DPoP proof on every call.
    #[serde(default)]
    pub dpop_bound: bool,
    /// RFC 9396 Rich Authorization Request payload echoed back, describing
    /// the act-chain and capabilities the token is authorized for.
    #[serde(default)]
    pub authorization_details: serde_json::Value,
}

/// Result of [`AuthClient::refresh_token`]. The refresh token is **not**
/// rotated in V1 — only the access token changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshedToken {
    /// New access-token JWT.
    pub access_token: String,
    /// `"DPoP"` for a key-bound token, else `"Bearer"`.
    #[serde(default)]
    pub token_type: String,
    /// Access-token lifetime in seconds.
    #[serde(default)]
    pub expires_in: u64,
    /// `true` iff the new access token carries a `cnf.jkt` claim.
    #[serde(default)]
    pub dpop_bound: bool,
    /// The refresh token for the next exchange; the one presented is spent.
    pub refresh_token: String,
    /// Seconds until `refresh_token` expires.
    pub refresh_token_expires_in: u64,
}

/// A serving node assigned to a delegated agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServingNodeRef {
    /// The node's machine identity.
    pub machine_did: String,
    /// The identity operating the node.
    pub operator_did: String,
    /// Thumbprint of the node's key for this agent.
    #[serde(default)]
    pub dpop_jkt: String,
}

/// The agent's wallet: watch-only, its address derived from the agent's DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWallet {
    /// Wallet handle.
    #[serde(default)]
    pub wallet_id: String,
    /// Address, `0x` hex.
    pub address: String,
}

/// Result of [`AuthClient::delegate_agent`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedAgent {
    /// The agent's identity: `did`, `identity_type`, `controller_did`,
    /// `capabilities`, `status`.
    pub identity: serde_json::Value,
    /// The agent's wallet.
    pub wallet: AgentWallet,
    /// Nodes serving the agent.
    pub serving_nodes: Vec<ServingNodeRef>,
    /// Distinct operators the serving nodes span, at least.
    pub min_distinct_operators: u32,
    /// When the terms expire, unix ms.
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    /// How delivering the agent's access tokens to its serving nodes went.
    #[serde(default)]
    pub token_delivery: serde_json::Value,
}

/// One action a delegated agent asks its serving node to take.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentActRequest {
    /// The operation, as the agent's terms name it.
    pub operation: String,
    /// Recipient address, hex, when the action moves value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<String>,
    /// Value moved, wei, decimal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Chain; `tenzro` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// Payment protocol, when it pays through one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_protocol: Option<String>,
    /// Model, when it runs one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Asset moved other than TNZO: a token id, `0x` hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    /// USD price of the value moved, micro-units; required with `asset`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usd_e6: Option<u64>,
    /// For `pay`: what the payment pays for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<AgentPayment>,
    /// The controller's step-up of this exact action, when its terms hold
    /// it: the root signs the challenge a refused attempt returns in the
    /// error's `data.step_up`, and the same action is sent again with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up: Option<AgentStepUp>,
}

/// The root's approval of one held action (`agent_step_up`), as
/// [`machine_root_step_up`] builds it for a machine root.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentStepUp {
    /// The agent's wallet account the challenge names, hex.
    pub account: String,
    /// The challenge nonce, 16 bytes, hex.
    pub nonce: String,
    /// The root's P-256 key, `x || y`, hex.
    pub root_public_key: String,
    /// The root's composite signature over the challenge digest under the
    /// account-owner context: `{"classical": {"form": "web_authn", ...}}`
    /// from a passkey, `{"classical": {"form": "raw", ...}, "pq": ...}` from
    /// a TPM or Secure Enclave.
    pub signature: serde_json::Value,
}

/// The payment an agent's `pay` action makes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentPayment {
    /// The payment id the record is keyed by.
    pub payment_id: String,
    /// SHA-256 of the request paid for, hex.
    pub request_digest: String,
    /// The payee's quote digest, hex, or 64 zeros for none.
    pub quote_digest: String,
}

/// Result of [`AuthClient::agent_act`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActResult {
    /// The agent.
    pub agent_did: String,
    /// The serving node that signed.
    pub machine_did: String,
    /// The action's nonce.
    pub nonce: u64,
    /// The escrow a `create_escrow` opened, hex.
    #[serde(default)]
    pub escrow_id: Option<String>,
    /// The payment record's reference, for `pay`, hex.
    #[serde(default)]
    pub pay_ref: Option<String>,
    /// The submitted transaction.
    pub tx_hash: serde_json::Value,
}

/// Result of [`AuthClient::agent_voucher`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVoucherResult {
    /// The voucher, signed by the serving node for the agent.
    pub voucher: serde_json::Value,
    /// What the ledger would pay on it now, decimal.
    pub payout: String,
}

/// Result of [`AuthClient::update_agent_terms`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTermsUpdate {
    /// The agent, unchanged.
    pub agent_did: String,
    /// The full updated terms, serving nodes included.
    pub delegation: serde_json::Value,
    /// How delivering the agent's access tokens went.
    #[serde(default)]
    pub token_delivery: serde_json::Value,
    /// Access tokens withdrawn, when the update rotated them.
    #[serde(default)]
    pub tokens_revoked: Option<u64>,
}

/// Result of `revoke_jwt` / `revoke_identity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResponse {
    /// `"revoked"` for a token; `"admitted"` for an identity, whose
    /// revocation lands with its transaction.
    #[serde(default)]
    pub status: String,
    /// For a token: the JTIs invalidated by this call (>1 indicates
    /// cascade). An identity's tokens are revoked by every node once its
    /// revocation is in a block.
    #[serde(default)]
    pub affected_jti_count: u64,
    /// For an identity: the root whose approval the chain verifies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_did: Option<String>,
    /// For an identity: the `RevokeIdentity` transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

/// A root's signature over a `revoke_identity` challenge, as the approval
/// in a `RevokeIdentity` transaction carries it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootApproval {
    /// The root's P-256 key, `x || y` (64 bytes).
    pub root_public_key: Vec<u8>,
    /// The composite signature: a passkey's WebAuthn assertion
    /// (`{"classical": {"form": "web_authn", "authenticator_data", "client_data_json",
    /// "signature"}}`, hex fields) or a machine's raw hardware signature
    /// (`{"classical": {"form": "raw", "signature"}, "pq"}`), over the
    /// challenge under the account-owner context.
    pub signature: serde_json::Value,
}

/// Gas a `RevokeIdentity` transaction is sent with: the root's approval
/// check and room for the agents a root revocation reaches.
pub const REVOCATION_GAS_LIMIT: u64 = 1_000_000;

fn unhex(s: &str) -> SdkResult<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| SdkError::RpcError(format!("bad hex {s}: {e}")))
}

/// The reason a revocation records when none is given.
pub const DEFAULT_REVOCATION_REASON: &str = "revoked by its root";

/// What a root signs to revoke `did` for `reason`: the `target` of a
/// `revoke_identity` custody challenge,
/// `SHA-256("tenzro/identity-revocation/v1" ‖ len ‖ did ‖ len ‖ reason)` with
/// 4-byte big-endian lengths.
pub fn revocation_target(did: &str, reason: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/identity-revocation/v1");
    for f in [did.as_bytes(), reason.as_bytes()] {
        h.update((f.len() as u32).to_be_bytes());
        h.update(f);
    }
    h.finalize().into()
}

#[cfg(test)]
mod revocation_target_tests {
    #[test]
    fn matches_the_node_vector() {
        assert_eq!(
            hex::encode(super::revocation_target(
                "did:tenzro:human:aa",
                "passkey lost"
            )),
            "9fae58244604f04767ff22e0809efecc7f459c45eccc23b9e61499488acb170a"
        );
    }
}

/// Result of [`AuthClient::exchange_token`] — the issued child JWT and
/// its delegation envelope per RFC 8693 §2.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeResult {
    /// The newly-issued child JWT (ES256, DPoP-bound to `child_dpop_jkt`).
    pub access_token: String,
    /// Lifetime of the child token in seconds.
    pub expires_in: u64,
    /// Always `"DPoP"` — child tokens are always DPoP-bound (RFC 9449).
    pub token_type: String,
    /// Always `"urn:ietf:params:oauth:token-type:jwt"` — the format of
    /// the issued token (RFC 8693 §2.2).
    pub issued_token_type: String,
    /// Echo of the delegation envelope: `{ controller_did, depth, … }`.
    /// The exact shape is defined by `tenzro_auth::TokenExchangeOutcome`
    /// — kept as opaque JSON in the SDK to avoid recapitulating every
    /// AAP claim type.
    pub delegation: serde_json::Value,
}

/// Result of [`AuthClient::introspect_token`] — the RFC 7662 §2.2
/// introspection response. When `active` is `false`, all other fields
/// are absent (the AS does not leak why the token is inactive).
///
/// The full claim set (RAR `authorization_details`, AAP `aap_*` claims,
/// `cnf`, `controller_did`, etc.) is returned as opaque JSON to keep
/// the SDK decoupled from `tenzro-auth` internals — callers that need
/// typed access can deserialize the `claims` map themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResult {
    /// `true` iff the token validates and its controller chain is not
    /// revoked.
    pub active: bool,
    /// Full claim set when active; empty when inactive. Includes
    /// `sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, `cnf`,
    /// `controller_did`, `authorization_details`, and any present
    /// `aap_*` claims.
    #[serde(flatten)]
    pub claims: serde_json::Map<String, serde_json::Value>,
}

/// Result of [`AuthClient::oauth_discovery`] — the OAuth 2.0
/// authorization-server metadata document (RFC 8414) augmented with
/// the AAP-specific extensions.
///
/// Mirrors the document published at
/// `GET /.well-known/openid-configuration` on the AS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthDiscovery {
    /// Issuer DID — typically `did:tenzro:node:<node_id>`.
    pub issuer: String,
    /// `POST` endpoint for authorization-code, refresh-token, and
    /// token-exchange grants.
    pub token_endpoint: String,
    /// `POST` endpoint for RFC 7662 token introspection.
    pub introspection_endpoint: String,
    /// `POST` endpoint for RFC 7009 token revocation.
    pub revocation_endpoint: String,
    /// All grant types the AS accepts. Includes
    /// `urn:ietf:params:oauth:grant-type:token-exchange`,
    /// `authorization_code`, and `refresh_token`.
    pub grant_types_supported: Vec<String>,
    /// Authentication methods at the token endpoint
    /// (`"none"` for public clients, `"private_key_jwt"`).
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Authorization-code response types — currently `["code"]`.
    pub response_types_supported: Vec<String>,
    /// DPoP signing algorithms accepted on proofs — currently
    /// `["EdDSA"]` (Ed25519 per RFC 8037).
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// RFC 9396 RAR `type` values the AS recognises:
    /// `transfer`, `create_escrow`, `discharge_escrow`, `inference`,
    /// `stake`, `vote`, `contract`, `register_identity`,
    /// `resource_invocation`.
    pub authorization_details_types_supported: Vec<String>,
    /// AAP claim names the AS issues — `aap_agent`, `aap_task`,
    /// `aap_capabilities`, `aap_delegation`,
    /// `aap_context`, `aap_audit`.
    pub aap_claims_supported: Vec<String>,
}

/// The `Payment` operation by which a payee refunds `amount` of the record
/// `pay_ref` (32-byte hex).
pub fn refund_op(pay_ref: &str, amount: u128) -> SdkResult<serde_json::Value> {
    let pay_ref = pay_ref.trim_start_matches("0x");
    if hex::decode(pay_ref).map(|b| b.len()) != Ok(32) {
        return Err(crate::error::SdkError::InvalidParameter(
            "pay_ref must be 32 bytes of hex".into(),
        ));
    }
    if amount == 0 {
        return Err(crate::error::SdkError::InvalidParameter(
            "amount must be positive".into(),
        ));
    }
    Ok(
        serde_json::json!({ "refund": { "pay_ref": pay_ref.to_ascii_lowercase(), "amount": amount.to_string() } }),
    )
}

#[cfg(test)]
mod payment_op_tests {
    use super::refund_op;

    #[test]
    fn refund_op_matches_the_shared_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/payment-ops/vectors.json");
        let vectors: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for v in vectors["payment_refund"].as_array().unwrap() {
            let a = &v["args"];
            let op = refund_op(
                a["pay_ref"].as_str().unwrap(),
                a["amount"].as_str().unwrap().parse().unwrap(),
            )
            .unwrap();
            assert_eq!(op, v["op"]);
        }
        assert!(refund_op("abcd", 1).is_err());
        assert!(refund_op(&"ab".repeat(32), 0).is_err());
    }
}

#[cfg(test)]
mod root_ballot_tests {
    use super::governance_ballot_digest;

    /// The same vector the chain's ballot digest is pinned to.
    #[test]
    fn the_ballot_digest_matches_the_chains() {
        let digest =
            governance_ballot_digest(13380, &[0x11; 32], &[0xab; 32], true, &[0x22; 32], &[5; 16]);
        assert_eq!(
            hex::encode(digest),
            "cb7ff4bed1bbc009122add80adb1a59663fa621e7234251e9017c53f8bbb0192"
        );
    }
}
