//! `NodeAuthIssuer` — the canonical [`tenzro_agent_kit::AuthIssuer`]
//! implementation that delegates to [`tenzro_auth::AuthEngine`].
//!
//! # Responsibilities
//!
//! Per the kit's [`AuthIssuer`](tenzro_agent_kit::AuthIssuer) contract,
//! this adapter is the single point in the workspace where the spawner's
//! abstract [`AgentAuthRequest`] is rendered into a concrete
//! sender-constrained credential bundle. It owns the four steps the trait
//! requires:
//!
//! 1. **Generate a fresh DPoP keypair.** A per-agent Ed25519 keypair —
//!    never reused, never persisted to disk in plaintext, and never sent
//!    over the wire. Kept in-memory inside a [`NodeDpopSigner`] for the
//!    lifetime of the agent.
//! 2. **Compute the RFC 7638 JWK thumbprint.** The `cnf.jkt` claim baked
//!    into the JWT is exactly the SHA-256 thumbprint of the public half
//!    of the keypair from step 1, so the verifier can match the proof
//!    key to the token.
//! 3. **Project the request into RFC 9396 RAR.** The kit's portable
//!    `allowed_operations: Vec<String>` shape is translated into typed
//!    [`AuthorizationDetail`] variants, each carrying the
//!    per-transaction ceiling, daily-spend ceiling, and (where present)
//!    the chain / counterparty allowlists. Unknown operation labels are
//!    rejected with [`AgentKitError::Auth`] — silent fallback would be
//!    a footgun.
//! 4. **Mint the JWT.** Delegates to
//!    [`AuthEngine::issue_jwt_with_aap`] so the resulting token carries
//!    both the RAR envelope and the AAP delegation chain rooted at the
//!    bearer DID. The TTL is clamped by the engine's own `max_ttl_secs`.
//!
//! # Lifecycle
//!
//! Constructed once at node startup in `init_auth()` and shared via
//! `Arc<NodeAuthIssuer>` with [`AgentKit::with_auth_issuer`]. Every
//! `kit.spawn(...)` call routes through `Self::issue` and the credential
//! bundle is stored on [`SpawnedAgent::credentials`] for the executor's
//! authenticated dispatch paths (EVM / SVM / DAML).
//!
//! [`AuthIssuer`]: tenzro_agent_kit::AuthIssuer
//! [`AgentAuthRequest`]: tenzro_agent_kit::AgentAuthRequest
//! [`AuthorizationDetail`]: tenzro_auth::AuthorizationDetail
//! [`AuthEngine::issue_jwt_with_aap`]: tenzro_auth::AuthEngine::issue_jwt_with_aap
//! [`AgentKit::with_auth_issuer`]: tenzro_agent_kit::AgentKit::with_auth_issuer
//! [`SpawnedAgent::credentials`]: tenzro_agent_kit::SpawnedAgent::credentials

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use tenzro_agent_kit::{
    AgentAuthRequest, AgentCredentials, AgentKitError, AuthIssuer, DpopSigner,
};
use tenzro_auth::{
    AapOverrides, AuthEngine, AuthorizationDetail, AuthorizationDetails,
};
use tenzro_types::AssetId;

/// Canonical [`AuthIssuer`] adapter. Holds an `Arc<AuthEngine>` and mints
/// per-agent DPoP-bound credentials by delegating to the engine.
pub struct NodeAuthIssuer {
    engine: Arc<AuthEngine>,
}

impl std::fmt::Debug for NodeAuthIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeAuthIssuer")
            .field("engine", &"<AuthEngine>")
            .finish()
    }
}

impl NodeAuthIssuer {
    /// Construct a new issuer that delegates to `engine`.
    pub fn new(engine: Arc<AuthEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl AuthIssuer for NodeAuthIssuer {
    async fn issue(
        &self,
        request: AgentAuthRequest,
    ) -> Result<AgentCredentials, AgentKitError> {
        // 1. Generate a fresh DPoP keypair. Ed25519 over OsRng — the
        //    same algorithm the DPoP parser accepts (`alg=EdDSA`,
        //    `kty=OKP`, `crv=Ed25519`).
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        // 2. Compute the RFC 7638 thumbprint. We build the canonical JWK
        //    here (sorted required members, no whitespace) and hand it
        //    back to `tenzro_auth::DpopProof::compute_jkt` so there is
        //    exactly one place in the workspace that knows the canonical
        //    serialization (and any change there propagates here for free).
        let pubkey_b64 = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
        let jwk_json = format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
            pubkey_b64
        );
        let jkt = tenzro_auth::DpopProof::compute_jkt(&jwk_json)
            .map_err(|e| AgentKitError::Auth(format!("compute jkt: {}", e)))?;

        // 3. Project the request into a RAR envelope. Unknown operation
        //    labels return AgentKitError::Auth — never silently dropped.
        let rar = project_to_rar(&request)?;

        // 4. Mint the JWT. The engine clamps TTL to its own
        //    `max_ttl_secs`; we pass the requested TTL through and let
        //    the engine decide. `AapOverrides::default()` makes the
        //    engine build a root AAP delegation claim `[bearer_did]` at
        //    depth 0 — exactly what a freshly-spawned agent needs.
        let jwt = self
            .engine
            .issue_jwt_with_aap(
                &request.bearer_did,
                &request.controller_did,
                &jkt,
                rar,
                Some(request.ttl_secs),
                AapOverrides::default(),
            )
            .map_err(|e| AgentKitError::Auth(format!("issue_jwt_with_aap: {}", e)))?;

        // 5. Compute the access-token expiry the same way the engine
        //    does so consumers can refresh *before* expiry. The engine
        //    clamps `ttl_secs` to `[1, max_ttl_secs]`; we honor the same
        //    bounds here so the surfaced `expires_at_unix` matches the
        //    JWT's `exp` claim.
        let now = unix_now();
        let cfg = self.engine.config();
        let effective_ttl = request.ttl_secs.clamp(1, cfg.max_ttl_secs);
        let expires_at_unix = now + effective_ttl;

        let signer: Arc<dyn DpopSigner> = Arc::new(NodeDpopSigner {
            signing_key,
            jwk_json,
        });

        Ok(AgentCredentials {
            jwt,
            jkt,
            dpop: signer,
            expires_at_unix,
        })
    }
}

/// Per-agent DPoP signer. Holds the Ed25519 private key in memory for the
/// agent's lifetime; constructs a fresh JWS for every protected request
/// the agent makes through [`RegistryClient::call_raw_with_auth`].
///
/// [`RegistryClient::call_raw_with_auth`]: tenzro_agent_kit::RegistryClient::call_raw_with_auth
struct NodeDpopSigner {
    signing_key: SigningKey,
    /// Pre-rendered JWK JSON (matches the canonical form
    /// `compute_jkt` accepts). Embedded verbatim in every proof header.
    jwk_json: String,
}

impl std::fmt::Debug for NodeDpopSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the signing key.
        f.debug_struct("NodeDpopSigner")
            .field("alg", &"EdDSA")
            .field("kty", &"OKP")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DpopSigner for NodeDpopSigner {
    async fn sign_proof(
        &self,
        http_method: &str,
        http_url: &str,
        access_token: &str,
    ) -> Result<String, AgentKitError> {
        // Strip query string per RFC 9449 §4.3 — `htu` is origin + path.
        let htu = strip_query(http_url);
        let htm = http_method.to_ascii_uppercase();

        // Payload per RFC 9449 §4.2.
        let now = unix_now() as i64;
        let jti = Uuid::new_v4().simple().to_string();
        let ath = {
            let digest = Sha256::digest(access_token.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        };

        let jwk_value: serde_json::Value = serde_json::from_str(&self.jwk_json)
            .map_err(|e| AgentKitError::Auth(format!("jwk parse: {}", e)))?;

        let header = json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": jwk_value,
        });
        let payload = json!({
            "htm": htm,
            "htu": htu,
            "iat": now,
            "jti": jti,
            "ath": ath,
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header)
                .map_err(|e| AgentKitError::Auth(format!("encode header: {}", e)))?,
        );
        let payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&payload)
                .map_err(|e| AgentKitError::Auth(format!("encode payload: {}", e)))?,
        );

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", signing_input, sig_b64))
    }
}

/// Project the kit's `AgentAuthRequest` into a typed
/// [`AuthorizationDetails`] envelope. One detail per allowed operation,
/// each carrying the per-tx and per-day ceilings (and counterparty /
/// validator / contract / model / proposal allowlists where the variant
/// has one).
///
/// Unknown operation labels return `AgentKitError::Auth` — silent
/// fallback would let a typo in a template's `allowed_operations` field
/// produce a token with empty effective scope (token validates, every
/// privileged action denies).
fn project_to_rar(req: &AgentAuthRequest) -> Result<AuthorizationDetails, AgentKitError> {
    let max_amount = req.max_transaction_value;
    let max_daily = if req.max_daily_spend > 0 {
        Some(req.max_daily_spend)
    } else {
        None
    };

    let mut details: Vec<AuthorizationDetail> = Vec::with_capacity(req.allowed_operations.len());

    for raw_op in &req.allowed_operations {
        let op = raw_op.trim().to_ascii_lowercase();
        let detail = match op.as_str() {
            // Value movement — all rendered as a Transfer in TNZO with
            // the per-tx + per-day caps. Bridges, deposits, swaps, and
            // rebalances ultimately debit the bearer's wallet, so the
            // RAR shape that gates them is the same.
            "transfer" | "send" | "pay" | "bridge" | "deposit" | "withdraw"
            | "swap" | "rebalance" | "yield" | "lend" | "borrow" | "settle" => {
                AuthorizationDetail::Transfer {
                    asset: AssetId::tnzo(),
                    max_amount,
                    max_daily_amount: max_daily,
                    allowed_counterparties: None,
                }
            }

            // Inference / model calls. `max_amount_per_call` mirrors
            // the per-transaction ceiling; per-day inherits from the
            // delegation spec.
            "inference" | "infer" | "chat" | "model" => {
                AuthorizationDetail::Inference {
                    max_amount_per_call: max_amount,
                    max_daily_amount: max_daily,
                    allowed_model_ids: None,
                }
            }

            // Staking / unstaking.
            "stake" | "unstake" | "delegate" | "undelegate" => {
                AuthorizationDetail::Stake {
                    max_amount,
                    allowed_validators: None,
                }
            }

            // Governance votes.
            "vote" | "governance" => AuthorizationDetail::Vote {
                allowed_proposals: None,
            },

            // Escrow lifecycle.
            "create_escrow" | "escrow" | "lock" => {
                AuthorizationDetail::CreateEscrow {
                    asset: AssetId::tnzo(),
                    max_amount,
                    allowed_payees: None,
                }
            }
            "discharge_escrow" | "release_escrow" | "refund_escrow"
            | "release" | "refund" => AuthorizationDetail::DischargeEscrow {
                allowed_escrow_ids: None,
            },

            // Contract calls + deploys.
            "contract" | "call" | "invoke" | "execute"
            | "evm_dispatch" | "svm_dispatch" | "daml_submit" => {
                AuthorizationDetail::Contract {
                    allowed_contracts: None,
                    allow_deploy: false,
                }
            }
            "deploy" | "deploy_contract" => AuthorizationDetail::Contract {
                allowed_contracts: None,
                allow_deploy: true,
            },

            // Spawning child identities (autonomous agent forks helpers).
            "register_identity" | "spawn" | "fork_agent" => {
                AuthorizationDetail::RegisterIdentity { max_children: None }
            }

            other => {
                return Err(AgentKitError::Auth(format!(
                    "unknown allowed_operations entry '{}' — \
                     map it to a typed RAR variant in \
                     `tenzro_node::agent_kit_auth::project_to_rar` \
                     before issuing tokens for templates that use it",
                    other
                )));
            }
        };

        details.push(detail);
    }

    Ok(AuthorizationDetails { details })
}

/// Strip the query string from a URL. Per RFC 9449 §4.3, `htu` is
/// origin + path only — query string and fragment are excluded so the
/// proof matches regardless of pagination / cache-buster params.
fn strip_query(url: &str) -> String {
    match url.find(['?', '#']) {
        Some(idx) => url[..idx].to_string(),
        None => url.to_string(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::KvStore;

    /// In-memory KvStore stub — same shape `AuthEngine::new` accepts.
    /// Mirrors the pattern from `tenzro-auth/src/engine.rs` unit tests.
    #[derive(Default)]
    struct MemStore {
        rows: parking_lot::RwLock<std::collections::BTreeMap<(String, Vec<u8>), Vec<u8>>>,
    }

    impl KvStore for MemStore {
        fn get(&self, cf: &str, key: &[u8]) -> tenzro_storage::Result<Option<Vec<u8>>> {
            Ok(self.rows.read().get(&(cf.to_string(), key.to_vec())).cloned())
        }
        fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> tenzro_storage::Result<()> {
            self.rows
                .write()
                .insert((cf.to_string(), key.to_vec()), value.to_vec());
            Ok(())
        }
        fn delete(&self, cf: &str, key: &[u8]) -> tenzro_storage::Result<()> {
            self.rows.write().remove(&(cf.to_string(), key.to_vec()));
            Ok(())
        }
        fn get_keys_with_prefix(
            &self,
            cf: &str,
            prefix: &[u8],
        ) -> tenzro_storage::Result<Vec<Vec<u8>>> {
            let rows = self.rows.read();
            Ok(rows
                .iter()
                .filter(|((c, k), _)| c == cf && k.starts_with(prefix))
                .map(|((_, k), _)| k.clone())
                .collect())
        }
        fn write_batch(
            &self,
            ops: Vec<tenzro_storage::WriteOp>,
        ) -> tenzro_storage::Result<()> {
            self.write_batch_sync(ops)
        }
        fn write_batch_sync(
            &self,
            ops: Vec<tenzro_storage::WriteOp>,
        ) -> tenzro_storage::Result<()> {
            for op in ops {
                match op {
                    tenzro_storage::WriteOp::Put { cf, key, value } => {
                        self.put(&cf, &key, &value)?;
                    }
                    tenzro_storage::WriteOp::Delete { cf, key } => {
                        self.delete(&cf, &key)?;
                    }
                }
            }
            Ok(())
        }
    }

    fn make_engine() -> Arc<AuthEngine> {
        let cfg = tenzro_auth::AuthEngineConfig::new(
            "http://test.local".to_string(),
            "http://test.local".to_string(),
            vec![0xAB; 32],
        );
        let engine = AuthEngine::new(cfg, Arc::new(MemStore::default())).unwrap();
        Arc::new(engine)
    }

    #[tokio::test]
    async fn issue_mints_dpop_bound_jwt_with_correct_jkt() {
        let issuer = NodeAuthIssuer::new(make_engine());
        let req = AgentAuthRequest {
            bearer_did: "did:tenzro:machine:acme:abc".to_string(),
            controller_did: "did:tenzro:human:acme".to_string(),
            max_transaction_value: 1_000_000_000_000_000_000,
            max_daily_spend: 10_000_000_000_000_000_000,
            allowed_operations: vec!["transfer".to_string(), "stake".to_string()],
            allowed_chains: vec!["tenzro".to_string()],
            ttl_secs: 3600,
        };
        let creds = issuer.issue(req).await.unwrap();
        assert!(!creds.jwt.is_empty());
        assert!(!creds.jkt.is_empty());
        assert!(creds.expires_at_unix > unix_now());
    }

    #[tokio::test]
    async fn issue_rejects_unknown_operation_label() {
        let issuer = NodeAuthIssuer::new(make_engine());
        let req = AgentAuthRequest {
            bearer_did: "did:tenzro:machine:acme:abc".to_string(),
            controller_did: "did:tenzro:human:acme".to_string(),
            max_transaction_value: 0,
            max_daily_spend: 0,
            allowed_operations: vec!["totally_made_up_op".to_string()],
            allowed_chains: vec![],
            ttl_secs: 60,
        };
        let err = issuer.issue(req).await.unwrap_err();
        assert!(matches!(err, AgentKitError::Auth(_)));
    }

    #[tokio::test]
    async fn dpop_signer_produces_three_part_jws_with_matching_jkt() {
        let issuer = NodeAuthIssuer::new(make_engine());
        let req = AgentAuthRequest {
            bearer_did: "did:tenzro:machine:test:1".to_string(),
            controller_did: "did:tenzro:human:test".to_string(),
            max_transaction_value: 1,
            max_daily_spend: 0,
            allowed_operations: vec!["transfer".to_string()],
            allowed_chains: vec![],
            ttl_secs: 60,
        };
        let creds = issuer.issue(req).await.unwrap();

        let proof = creds
            .dpop
            .sign_proof("POST", "https://rpc.example/?cache=1", &creds.jwt)
            .await
            .unwrap();

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS must have exactly 3 segments");

        // Parse + verify the proof binds to the same jkt as the token.
        let (parsed, signed_input, signature) =
            tenzro_auth::DpopProof::parse_with_signed_input(&proof).unwrap();
        // `htu` must have the query stripped.
        assert_eq!(parsed.htu, "https://rpc.example/");
        assert_eq!(parsed.htm, "POST");
        assert!(parsed.ath.is_some());

        let verified = parsed
            .verify(
                "POST",
                "https://rpc.example/",
                unix_now() as i64,
                &signed_input,
                &signature,
            )
            .unwrap();
        assert_eq!(verified.jkt, creds.jkt);
    }

    #[test]
    fn strip_query_removes_query_and_fragment() {
        assert_eq!(strip_query("https://x/y"), "https://x/y");
        assert_eq!(strip_query("https://x/y?a=1"), "https://x/y");
        assert_eq!(strip_query("https://x/y#frag"), "https://x/y");
        assert_eq!(strip_query("https://x/y?a=1#frag"), "https://x/y");
    }

    #[test]
    fn project_to_rar_returns_one_detail_per_op() {
        let req = AgentAuthRequest {
            bearer_did: String::new(),
            controller_did: String::new(),
            max_transaction_value: 100,
            max_daily_spend: 1000,
            allowed_operations: vec![
                "transfer".to_string(),
                "stake".to_string(),
                "vote".to_string(),
                "deploy".to_string(),
                "inference".to_string(),
            ],
            allowed_chains: vec![],
            ttl_secs: 60,
        };
        let rar = project_to_rar(&req).unwrap();
        assert_eq!(rar.details.len(), 5);
    }
}
