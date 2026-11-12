//! Credential driver: provider credentials minted under the agent's Terms.
//!
//! A Tenzro provider in OpenShell stores no secret. Its credential value is
//! the DID of the agent it acts for; the driver refuses anything else, so a
//! long-lived key never enters the gateway. Each resolve mints a fresh
//! credential ([`crate::token`]) scoped to that provider and credential key,
//! valid for minutes and never past the Terms' expiry, and only while the
//! agent and its root are unrevoked and their Terms allow the provider's
//! operation. Revocation on Tenzro therefore ends every credential: the next
//! resolve is refused and Tenzro refuses the outstanding ones on use.
//!
//! OpenShell enables one credential driver per gateway and routes every
//! gateway-managed secret through it, its own included (for example each
//! sandbox's SSH host key). Credential keys this driver does not mint for are
//! held as blobs wrapped by the serving node's hardware key ([`SecretStore`])
//! and never in the clear; without a store they are refused.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
#[cfg(test)]
use tenzro_crypto::batch::ImmediateRecordSigner;
use tenzro_crypto::batch::RecordSigner;
use tenzro_types::agent_audit::{ActionKind, ActionOutcome};
use tonic::{Request, Response, Status};

use crate::authority::Authority;
use crate::gateway_auth::{self, CallerKind};
use crate::openshell::credentials::v1::credential_driver_server::CredentialDriver;
use crate::openshell::credentials::v1::*;
use crate::openshell::datamodel::v1::CredentialHandle;
use crate::peer;
use crate::records::{Decision, RecordLog};
use crate::token::{self, Claims};

/// The driver name handles carry.
pub const DRIVER: &str = "tenzro";

/// Holds secrets the gateway owns, wrapped so only this machine's hardware
/// can recover them.
pub trait SecretStore: Send + Sync {
    /// Wrap `secret`.
    fn wrap(&self, secret: &[u8]) -> Result<Vec<u8>, String>;
    /// Recover a wrapped secret.
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, String>;
}

/// A [`SecretStore`] backed by a device key (TPM or Secure Enclave).
pub struct DeviceKeyStore(pub Box<dyn tenzro_device_key::DeviceKey>);

impl SecretStore for DeviceKeyStore {
    fn wrap(&self, secret: &[u8]) -> Result<Vec<u8>, String> {
        self.0.wrap_secret(secret).map_err(|e| e.to_string())
    }
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, String> {
        self.0
            .unwrap_secret(wrapped)
            .map(|z| z.to_vec())
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone)]
struct Grant {
    agent: String,
    provider: String,
    key: String,
}

/// The Tenzro credential driver.
pub struct TenzroCredentialDriver {
    authority: Arc<dyn Authority>,
    signer: Arc<dyn RecordSigner>,
    records: Arc<RecordLog>,
    ttl: Duration,
    scope: String,
    keys: Vec<String>,
    grants: RwLock<HashMap<String, Grant>>,
    store: Option<Arc<dyn SecretStore>>,
    held: RwLock<HashMap<String, Vec<u8>>>,
}

impl TenzroCredentialDriver {
    /// A driver minting credentials valid for `ttl` that Tenzro accepts for
    /// the operation `scope` (`inference` for the Tenzro provider).
    pub fn new(
        authority: Arc<dyn Authority>,
        signer: Arc<dyn RecordSigner>,
        records: Arc<RecordLog>,
        ttl: Duration,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            authority,
            signer,
            records,
            ttl,
            scope: scope.into(),
            keys: vec!["TENZRO_AGENT_TOKEN".to_string()],
            grants: RwLock::new(HashMap::new()),
            store: None,
            held: RwLock::new(HashMap::new()),
        }
    }

    /// Hold the gateway's other secrets wrapped by `store`.
    pub fn with_store(mut self, store: Arc<dyn SecretStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// The credential keys this driver mints for (default `TENZRO_AGENT_TOKEN`).
    pub fn with_keys(mut self, keys: Vec<String>) -> Self {
        self.keys = keys;
        self
    }

    fn record(&self, agent: &str, action: &str, outcome: ActionOutcome) {
        if let Err(e) = self.records.record(Decision {
            session: agent,
            agent,
            kind: ActionKind::GrantUse,
            action,
            outcome,
            detail: action.as_bytes(),
            linked_tx: None,
        }) {
            tracing::error!("credential record not written: {e}");
        }
    }

    /// Check the agent may use this provider now.
    fn admit(&self, agent: &str, now_ms: u64) -> Result<(), Status> {
        if let Some(why) = self.authority.revoked(agent, now_ms) {
            return Err(Status::permission_denied(why));
        }
        let terms = self
            .authority
            .terms(agent)
            .ok_or_else(|| Status::permission_denied("the agent has no Terms"))?;
        if !terms
            .delegation_scope
            .allowed_operations
            .iter()
            .any(|o| o == &self.scope)
        {
            return Err(Status::permission_denied(format!(
                "outside the agent's approved terms: operation {}",
                self.scope
            )));
        }
        Ok(())
    }

    fn mint(&self, grant: &Grant, now_ms: u64) -> Result<(String, u64), Status> {
        self.admit(&grant.agent, now_ms)?;
        let terms_end = self
            .authority
            .terms(&grant.agent)
            .and_then(|t| t.expires_at_ms)
            .unwrap_or(u64::MAX);
        let exp_ms = now_ms
            .saturating_add(self.ttl.as_millis() as u64)
            .min(terms_end);
        let claims = Claims {
            agent: grant.agent.clone(),
            provider: grant.provider.clone(),
            key: grant.key.clone(),
            scope: self.scope.clone(),
            iat_ms: now_ms,
            exp_ms,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = token::mint(&self.signer, &claims).map_err(Status::internal)?;
        Ok((token, exp_ms))
    }
}

/// Refuse a call that is not the gateway's.
fn from_gateway<T>(request: &Request<T>) -> Result<(), Status> {
    match gateway_auth::caller(request)?.kind {
        CallerKind::Gateway => Ok(()),
        CallerKind::Supervisor => Err(Status::permission_denied(
            "only the gateway calls the credential driver",
        )),
    }
}

fn timestamp(ms: u64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: (ms / 1000) as i64,
        nanos: ((ms % 1000) * 1_000_000) as i32,
    }
}

#[tonic::async_trait]
impl CredentialDriver for TenzroCredentialDriver {
    async fn get_capabilities(
        &self,
        request: Request<GetCredentialDriverCapabilitiesRequest>,
    ) -> Result<Response<GetCredentialDriverCapabilitiesResponse>, Status> {
        from_gateway(&request)?;
        peer::negotiate(request.get_ref().gateway.as_ref(), peer::CREDENTIALS)?;
        Ok(Response::new(GetCredentialDriverCapabilitiesResponse {
            driver_name: DRIVER.to_string(),
            driver_version: env!("CARGO_PKG_VERSION").to_string(),
            backend_kind: "tenzro".to_string(),
            supports_list: false,
            supports_expires_at: true,
            extension: Some(peer::metadata(peer::CREDENTIALS)),
        }))
    }

    async fn store_credential(
        &self,
        request: Request<StoreCredentialRequest>,
    ) -> Result<Response<StoreCredentialResponse>, Status> {
        from_gateway(&request)?;
        let r = request.into_inner();
        let now = crate::now_ms();
        let handle_of = |r: &StoreCredentialRequest| {
            r.existing_handle
                .as_ref()
                .filter(|h| h.driver == DRIVER && !h.handle.is_empty())
                .map(|h| h.handle.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
        };
        if !self.keys.contains(&r.credential_key) {
            let store = self.store.as_ref().ok_or_else(|| {
                Status::failed_precondition(format!(
                    "{} is not a Tenzro credential and no wrapped store is configured",
                    r.credential_key
                ))
            })?;
            let wrapped = store.wrap(r.value.as_bytes()).map_err(Status::internal)?;
            let id = handle_of(&r);
            self.held.write().insert(id.clone(), wrapped);
            return Ok(Response::new(StoreCredentialResponse {
                handle: Some(CredentialHandle {
                    driver: DRIVER.to_string(),
                    handle: id,
                    metadata: HashMap::new(),
                }),
            }));
        }
        let value = r.value.trim();
        // The gateway stores the agent's DID when the provider is created,
        // and stores again the credential it resolved when it copies the
        // provider into a sandbox: that copy names the same agent.
        let minted;
        let agent = if value.starts_with("did:tenzro:") {
            value
        } else if let Ok(claims) = token::verify(self.signer.identity(), value, now) {
            minted = claims.agent;
            minted.as_str()
        } else {
            tracing::warn!(
                provider = %r.provider, key = %r.credential_key, len = value.len(),
                prefix = %value.chars().take(5).collect::<String>(),
                "refused a credential value that names no agent"
            );
            return Err(Status::invalid_argument(
                "a Tenzro provider holds the DID of the agent it acts for, never a key",
            ));
        };
        if let Err(s) = self.admit(agent, now) {
            self.record(
                agent,
                "credential.store",
                ActionOutcome::Refused(s.message().into()),
            );
            return Err(s);
        }
        let id = handle_of(&r);
        self.grants.write().insert(
            id.clone(),
            Grant {
                agent: agent.to_string(),
                provider: r.provider.clone(),
                key: r.credential_key.clone(),
            },
        );
        self.record(agent, "credential.store", ActionOutcome::Allowed);
        Ok(Response::new(StoreCredentialResponse {
            handle: Some(CredentialHandle {
                driver: DRIVER.to_string(),
                handle: id,
                metadata: HashMap::from([("agent".to_string(), agent.to_string())]),
            }),
        }))
    }

    async fn delete_credential(
        &self,
        request: Request<DeleteCredentialRequest>,
    ) -> Result<Response<DeleteCredentialResponse>, Status> {
        from_gateway(&request)?;
        if let Some(h) = request.into_inner().handle {
            self.grants.write().remove(&h.handle);
            self.held.write().remove(&h.handle);
        }
        Ok(Response::new(DeleteCredentialResponse {}))
    }

    async fn resolve_credentials(
        &self,
        request: Request<ResolveCredentialsRequest>,
    ) -> Result<Response<ResolveCredentialsResponse>, Status> {
        from_gateway(&request)?;
        let now = crate::now_ms();
        let mut out = Vec::new();
        for r in request.into_inner().credentials {
            let handle = r
                .handle
                .as_ref()
                .filter(|h| h.driver == DRIVER)
                .ok_or_else(|| Status::invalid_argument("not a Tenzro credential handle"))?;
            if let Some(wrapped) = self.held.read().get(&handle.handle).cloned() {
                let store = self
                    .store
                    .as_ref()
                    .ok_or_else(|| Status::internal("no store"))?;
                let value = store.unwrap(&wrapped).map_err(Status::internal)?;
                out.push(ResolvedCredential {
                    request_id: r.request_id,
                    value: String::from_utf8(value).map_err(|_| Status::internal("not UTF-8"))?,
                    expiration_time: None,
                });
                continue;
            }
            let grant = self
                .grants
                .read()
                .get(&handle.handle)
                .cloned()
                .ok_or_else(|| Status::not_found("unknown Tenzro credential handle"))?;
            match self.mint(&grant, now) {
                Ok((value, exp_ms)) => {
                    self.record(&grant.agent, "credential.resolve", ActionOutcome::Allowed);
                    out.push(ResolvedCredential {
                        request_id: r.request_id,
                        value,
                        expiration_time: Some(timestamp(exp_ms)),
                    });
                }
                Err(s) => {
                    self.record(
                        &grant.agent,
                        "credential.resolve",
                        ActionOutcome::Refused(s.message().into()),
                    );
                    return Err(s);
                }
            }
        }
        Ok(Response::new(ResolveCredentialsResponse {
            credentials: out,
        }))
    }

    async fn list_credentials(
        &self,
        request: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        from_gateway(&request)?;
        Err(Status::unimplemented(
            "Tenzro credentials are not discoverable",
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::authority::StateAuthority;
    use tenzro_crypto::composite::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_types::agent_terms::{AgentTerms, ServingNode, TermsScope, agent_did};

    pub const ROOT: &str = "did:tenzro:human:0a0b0c";
    pub const MACHINE: &str = "did:tenzro:machine:serving01";

    pub fn agent() -> String {
        agent_did(ROOT, "researcher").unwrap()
    }

    pub fn terms(ops: &[&str]) -> AgentTerms {
        AgentTerms {
            controller_did: ROOT.into(),
            agent_name: "researcher".into(),
            delegation_scope: TermsScope {
                allowed_operations: ops.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            capabilities: Vec::new(),
            serving_nodes: vec![ServingNode {
                machine_did: MACHINE.into(),
                ..Default::default()
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        }
    }

    pub fn fixture(
        ops: &[&str],
    ) -> (
        Arc<StateAuthority>,
        Arc<ImmediateRecordSigner>,
        Arc<RecordLog>,
    ) {
        let id = Arc::new(TestHybridSigner::p256_only(11));
        let authority = StateAuthority::new(MACHINE, id.public_key().clone(), 1337);
        authority.install_terms(&agent(), terms(ops));
        let signer = Arc::new(tenzro_crypto::batch::ImmediateRecordSigner::new(id));
        let records = Arc::new(RecordLog::new(signer.clone(), None));
        (authority, signer, records)
    }

    fn driver(
        ops: &[&str],
    ) -> (
        TenzroCredentialDriver,
        Arc<StateAuthority>,
        Arc<ImmediateRecordSigner>,
    ) {
        let (a, s, r) = fixture(ops);
        let d = TenzroCredentialDriver::new(
            a.clone(),
            s.clone(),
            r,
            Duration::from_secs(300),
            "inference",
        );
        (d, a, s)
    }

    async fn store(d: &TenzroCredentialDriver, value: &str) -> Result<CredentialHandle, Status> {
        d.store_credential(gateway_auth::testing::from_gateway(
            StoreCredentialRequest {
                provider: "tenzro".into(),
                credential_key: "TENZRO_AGENT_TOKEN".into(),
                value: value.into(),
                ..Default::default()
            },
        ))
        .await
        .map(|r| r.into_inner().handle.unwrap())
    }

    async fn resolve(
        d: &TenzroCredentialDriver,
        h: &CredentialHandle,
    ) -> Result<ResolvedCredential, Status> {
        d.resolve_credentials(gateway_auth::testing::from_gateway(
            ResolveCredentialsRequest {
                credentials: vec![ResolveCredentialRequest {
                    request_id: "r1".into(),
                    handle: Some(h.clone()),
                    ..Default::default()
                }],
            },
        ))
        .await
        .map(|r| r.into_inner().credentials.remove(0))
    }

    #[tokio::test]
    async fn capabilities_declare_the_contract_and_expiry() {
        let (d, _, _) = driver(&["inference"]);
        let caps = d
            .get_capabilities(gateway_auth::testing::from_gateway(
                GetCredentialDriverCapabilitiesRequest {
                    gateway: Some(peer::metadata(peer::CREDENTIALS)),
                },
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(caps.supports_expires_at);
        assert_eq!(
            caps.extension.unwrap().supported_capabilities,
            vec![peer::CREDENTIALS.to_string()]
        );
    }

    #[tokio::test]
    async fn a_long_lived_key_is_refused() {
        let (d, _, _) = driver(&["inference"]);
        let err = store(&d, "sk-live-0123456789").await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn a_resolve_mints_a_short_lived_credential_for_the_agent() {
        let (d, _, signer) = driver(&["inference"]);
        let h = store(&d, &agent()).await.unwrap();
        let c = resolve(&d, &h).await.unwrap();
        assert_eq!(c.request_id, "r1");
        let claims = token::verify(signer.identity(), &c.value, crate::now_ms()).unwrap();
        assert_eq!(claims.agent, agent());
        assert_eq!(claims.key, "TENZRO_AGENT_TOKEN");
        let exp = c.expiration_time.unwrap();
        let ttl_ms = exp.seconds as u64 * 1000 - claims.iat_ms / 1000 * 1000;
        assert!(ttl_ms <= 301_000, "credential lives {ttl_ms} ms");
        // Two resolves mint two different credentials.
        assert_ne!(resolve(&d, &h).await.unwrap().value, c.value);
    }

    #[tokio::test]
    async fn a_credential_this_driver_minted_stores_as_its_agent() {
        let (d, _, _) = driver(&["inference"]);
        let h = store(&d, &agent()).await.unwrap();
        let minted = resolve(&d, &h).await.unwrap().value;
        let copy = store(&d, &minted).await.unwrap();
        assert_eq!(copy.metadata["agent"], agent());
        resolve(&d, &copy).await.unwrap();
    }

    struct Masked;
    impl SecretStore for Masked {
        fn wrap(&self, s: &[u8]) -> Result<Vec<u8>, String> {
            Ok(s.iter().map(|b| b ^ 0x5a).collect())
        }
        fn unwrap(&self, s: &[u8]) -> Result<Vec<u8>, String> {
            self.wrap(s)
        }
    }

    #[tokio::test]
    async fn the_gateways_own_secrets_are_held_wrapped_or_refused() {
        let (d, _, _) = driver(&["inference"]);
        async fn ssh(
            d: &TenzroCredentialDriver,
        ) -> Result<Response<StoreCredentialResponse>, Status> {
            d.store_credential(gateway_auth::testing::from_gateway(
                StoreCredentialRequest {
                    provider: "sandbox-ssh".into(),
                    credential_key: "SSH_HOST_PRIVATE_KEY".into(),
                    value: "-----BEGIN KEY-----".into(),
                    ..Default::default()
                },
            ))
            .await
        }
        assert_eq!(
            ssh(&d).await.unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        let d = d.with_store(Arc::new(Masked));
        let h = ssh(&d).await.unwrap().into_inner().handle.unwrap();
        assert!(!d.held.read()[&h.handle].starts_with(b"-----"));
        assert_eq!(resolve(&d, &h).await.unwrap().value, "-----BEGIN KEY-----");
    }

    #[tokio::test]
    async fn terms_without_the_operation_mint_nothing() {
        let (d, _, _) = driver(&["fetch"]);
        assert_eq!(
            store(&d, &agent()).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn revoking_the_agent_or_its_root_ends_resolution() {
        let (d, a, _) = driver(&["inference"]);
        let h = store(&d, &agent()).await.unwrap();
        resolve(&d, &h).await.unwrap();
        a.revoke(ROOT, "kill switch");
        let err = resolve(&d, &h).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(
            err.message() == crate::authority::REVOKED,
            "{}",
            err.message()
        );
    }

    #[tokio::test]
    async fn the_credential_never_outlives_the_terms() {
        let (d, a, signer) = driver(&["inference"]);
        let mut t = terms(&["inference"]);
        t.expires_at_ms = Some(crate::now_ms() + 5_000);
        a.install_terms(&agent(), t);
        let h = store(&d, &agent()).await.unwrap();
        let c = resolve(&d, &h).await.unwrap();
        let claims = token::verify(signer.identity(), &c.value, crate::now_ms()).unwrap();
        assert!(claims.exp_ms <= crate::now_ms() + 5_000);
    }

    #[tokio::test]
    async fn only_the_authenticated_gateway_reaches_the_driver() {
        let (d, _, _) = driver(&["inference"]);
        let h = store(&d, &agent()).await.unwrap();
        let ask = || ResolveCredentialsRequest {
            credentials: vec![ResolveCredentialRequest {
                request_id: "r1".into(),
                handle: Some(h.clone()),
                ..Default::default()
            }],
        };
        let unauthenticated = d
            .resolve_credentials(Request::new(ask()))
            .await
            .unwrap_err();
        assert_eq!(unauthenticated.code(), tonic::Code::Unauthenticated);
        let supervisor = d
            .resolve_credentials(gateway_auth::testing::from_supervisor(ask(), "id-1"))
            .await
            .unwrap_err();
        assert_eq!(supervisor.code(), tonic::Code::PermissionDenied);
        let stored = d
            .store_credential(Request::new(StoreCredentialRequest {
                provider: "tenzro".into(),
                credential_key: "TENZRO_AGENT_TOKEN".into(),
                value: agent(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(stored.code(), tonic::Code::Unauthenticated);
        assert!(
            d.resolve_credentials(gateway_auth::testing::from_gateway(ask()))
                .await
                .is_ok()
        );
    }
}
