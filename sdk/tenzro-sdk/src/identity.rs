//! Identity SDK for Tenzro Network
//!
//! This module provides identity management functionality for
//! TDIP (Tenzro Decentralized Identity Protocol) identities.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use crate::wallet::HybridSigner;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Identity client for TDIP identity operations
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let identity_client = client.identity();
///
/// // Resolve an identity
/// let info = identity_client.resolve("did:tenzro:human:abc123").await?;
/// println!("Status: {}", info.status);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct IdentityClient {
    rpc: Arc<RpcClient>,
}

impl IdentityClient {
    /// Creates a new identity client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Registers a human identity bound to a passkey
    /// (`tenzro_registerIdentity` with `identity_type` `human`).
    ///
    /// `public_key` is the passkey's P-256 key and `credential_id` its
    /// credential id (both hex). `proof` is the passkey's composite signature
    /// over the registration statement under the `IdentityRegistration`
    /// context; the node refuses a registration without it. Applications that
    /// enroll a passkey from a browser use
    /// [`crate::passkey_client::PasskeyClient::enroll`] instead, which takes
    /// the WebAuthn registration as it comes.
    pub async fn register_human(
        &self,
        params: &RegisterHumanParams,
    ) -> SdkResult<RegisterIdentityResponse> {
        self.rpc
            .call(
                "tenzro_registerIdentity",
                serde_json::json!({
                    "identity_type": "human",
                    "display_name": params.display_name,
                    "public_key": params.public_key,
                    "credential_id": params.credential_id,
                    "proof": params.proof,
                }),
            )
            .await
    }

    /// Resolves a DID to its identity information
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let identity_client = client.identity();
    /// let info = identity_client.resolve("did:tenzro:human:abc123").await?;
    /// println!("Status: {}", info.status);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn resolve(&self, did: &str) -> SdkResult<IdentityInfo> {
        self.rpc
            .call(
                "tenzro_resolveIdentity",
                serde_json::json!([{ "did": did }]),
            )
            .await
    }

    /// Resolves a DID to its W3C DID Document
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let identity_client = client.identity();
    /// let doc = identity_client.resolve_did_document("did:tenzro:human:abc123").await?;
    /// println!("DID Document: {}", serde_json::to_string_pretty(&doc)?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn resolve_did_document(&self, did: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_resolveDidDocument",
                serde_json::json!([{ "did": did }]),
            )
            .await
    }

    /// The service entries of a DID's document and the version of the list,
    /// from consensus state (`tenzro_getDidServices`). A change is an
    /// `IdentityServices` transaction the DID's root approves for this
    /// version.
    pub async fn did_services(&self, did: &str) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_getDidServices", serde_json::json!({ "did": did }))
            .await
    }

    /// Registers a machine identity under a controller
    /// (`tenzro_registerMachineIdentity`).
    ///
    /// The machine acts for its controller, carries its delegation scope and
    /// draws on its admission quota, so the controller signs the request:
    /// `controller` is the controller's hardware signer (passkey, TPM or
    /// Secure Enclave), and the request carries its DID envelope over every
    /// field. The node refuses a request without one, or with one from any
    /// other DID.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use tenzro_sdk::identity::RegisterMachineParams;
    /// # use tenzro_sdk::wallet::HybridSigner;
    /// # async fn example(
    /// #     client: &tenzro_sdk::TenzroClient,
    /// #     controller: Arc<dyn HybridSigner>,
    /// # ) -> Result<(), Box<dyn std::error::Error>> {
    /// let result = client
    ///     .identity()
    ///     .register_machine(
    ///         RegisterMachineParams {
    ///             controller_did: "did:tenzro:human:abc123".to_string(),
    ///             public_key: "<x || y of the machine's TPM key, hex>".to_string(),
    ///             capabilities: vec!["inference".to_string()],
    ///         },
    ///         &controller,
    ///     )
    ///     .await?;
    /// println!("Machine DID: {}", result.did);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register_machine(
        &self,
        params: RegisterMachineParams,
        controller: &Arc<dyn HybridSigner>,
    ) -> SdkResult<RegisterIdentityResponse> {
        let request = crate::did_envelope::with_request_envelope(
            controller.as_ref(),
            &params.controller_did,
            "tenzro_registerMachineIdentity",
            serde_json::json!({
                "controller_did": params.controller_did,
                "public_key": params.public_key,
                "capabilities": params.capabilities,
            }),
        )
        .await?;
        self.rpc
            .call("tenzro_registerMachineIdentity", request)
            .await
    }

    /// Lists all registered identities
    pub async fn list_identities(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listIdentities", serde_json::json!([]))
            .await
    }

    /// Verify a DID-signed envelope (for example an off-chain signed result).
    pub async fn verify_did_envelope(
        &self,
        envelope: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyDidEnvelope",
                serde_json::json!({ "envelope": envelope }),
            )
            .await
    }
}

/// A `tenzro_registerIdentity` request for a human identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterHumanParams {
    /// The name shown for the identity.
    pub display_name: String,
    /// The passkey's P-256 public key, hex.
    pub public_key: String,
    /// The passkey's credential id, hex.
    pub credential_id: String,
    /// The composite signature over the registration statement, context
    /// `IdentityRegistration`: `{"classical": {"form": ..}, "pq"?}`.
    pub proof: serde_json::Value,
}

/// Identity type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityType {
    /// Human identity
    Human,
    /// Machine identity
    Machine,
}

/// Response from identity registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterIdentityResponse {
    /// The assigned DID
    pub did: String,
    /// Registration status
    #[serde(default)]
    pub status: String,
    /// Hash of the `RegisterIdentity` transaction that replicates the
    /// identity. The node records nothing when it cannot submit one, and
    /// returns the error instead.
    #[serde(default)]
    pub tx_hash: String,
}

/// Parameters for registering a machine identity under a controller
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMachineParams {
    /// DID of the controlling identity, which signs the request
    pub controller_did: String,
    /// The machine's P-256 public key (hex, `x || y`), from its TPM or
    /// Secure Enclave
    pub public_key: String,
    /// Capabilities for the machine (e.g., "inference", "analysis")
    pub capabilities: Vec<String>,
}

/// Identity information returned by resolve
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    /// The DID string
    pub did: String,
    /// Current status (active, suspended, revoked)
    #[serde(default)]
    pub status: String,
    /// Whether this is a human identity
    #[serde(default)]
    pub is_human: bool,
    /// Whether this is a machine identity
    #[serde(default)]
    pub is_machine: bool,
    /// Display name
    #[serde(default)]
    pub display_name: String,
    /// Identity type (derived from is_human/is_machine)
    #[serde(skip)]
    pub identity_type: Option<IdentityType>,
    /// Number of public keys
    #[serde(default)]
    pub key_count: usize,
    /// Number of service endpoints
    #[serde(default)]
    pub service_count: usize,
}

impl IdentityClient {
    /// Calls `tenzro_verifyKyaCredential`: verify kya credential.
    pub async fn verify_kya_credential(
        &self,
        credential: serde_json::Value,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyKyaCredential",
                serde_json::json!({ "credential": credential }),
            )
            .await
    }

    /// Calls `tenzro_verifyNodeDidDocument`: verify node did document.
    pub async fn verify_node_did_document(
        &self,
        document: serde_json::Value,
        id: Option<&str>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyNodeDidDocument",
                serde_json::json!({ "document": document, "id": id }),
            )
            .await
    }

    /// Calls `tenzro_get7702Delegation`: get7702 delegation.
    pub async fn get_7702delegation(
        &self,
        authority: &str,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_get7702Delegation",
                serde_json::json!({ "authority": authority }),
            )
            .await
    }
}

impl IdentityClient {
    /// Calls `tenzro_issueKyaCredential`: issue kya credential.
    pub async fn issue_kya_credential(
        &self,
        did: &str,
        validity_secs: Option<u64>,
    ) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_issueKyaCredential",
                serde_json::json!({ "did": did, "validity_secs": validity_secs }),
            )
            .await
    }

    /// Update `did`. `update` carries its `kind`: `service` (`type`,
    /// `endpoint` and the hex DID `envelope` over the service) or `resource`
    /// (`resource_type`, `resource_id`).
    pub async fn update_identity(
        &self,
        did: &str,
        update: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_updateIdentity",
                serde_json::json!({ "did": did, "update": update }),
            )
            .await
    }

    /// Hand the authority of `did` to the hardware ML-DSA-65 key `new_key`.
    /// The P-256 key the DID derives from (`signer`) signs the rotation, and
    /// the new key signs it to prove possession. `sequence` is one more than
    /// the last rotation (1 for the first).
    pub async fn rotate_identity_to_pq(
        &self,
        signer: &dyn crate::wallet::HybridSigner,
        new_key: &dyn PqRotationKey,
        did: &str,
        sequence: u64,
    ) -> SdkResult<serde_json::Value> {
        let new_pq_key = new_key.verifying_key();
        let backend = new_key.backend();
        let statement = pq_rotation_statement(did, &new_pq_key, backend, sequence);
        let new_key_signature = new_key.sign_ml_dsa(PQ_ROTATION_CONTEXT, &statement).await?;
        let authority_signature = signer.sign_p256(&statement).await?;
        self.rpc
            .call(
                "tenzro_rotateIdentityToPq",
                serde_json::json!({
                    "did": did,
                    "new_pq_key": hex::encode(&new_pq_key),
                    "backend": backend,
                    "sequence": sequence,
                    "authority_signature": hex::encode(authority_signature),
                    "new_key_signature": hex::encode(new_key_signature),
                }),
            )
            .await
    }
}

/// FIPS 204 context string of the new key's signature over a post-quantum
/// rotation.
pub const PQ_ROTATION_CONTEXT: &[u8] = b"tenzro/identity/pq-rotation";

/// A hardware-held ML-DSA-65 key an identity rotates to. The SDK never holds
/// the private key; this is implemented over the TPM or Secure Enclave.
#[async_trait::async_trait]
pub trait PqRotationKey: Send + Sync {
    /// The ML-DSA-65 verifying key (1952 bytes).
    fn verifying_key(&self) -> Vec<u8>;
    /// The hardware holding it: `tpm` or `secure_enclave`.
    fn backend(&self) -> &'static str;
    /// Sign `message` under the FIPS 204 context string `context`.
    async fn sign_ml_dsa(&self, context: &[u8], message: &[u8]) -> SdkResult<Vec<u8>>;
}

/// The statement both keys sign in a post-quantum rotation, identical to
/// `tenzro_identity::pq_rotation::PqRotation::statement`.
pub fn pq_rotation_statement(
    did: &str,
    new_pq_key: &[u8],
    backend: &str,
    sequence: u64,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/identity/pq-rotation/v1\0");
    h.update((did.len() as u32).to_be_bytes());
    h.update(did.as_bytes());
    h.update((new_pq_key.len() as u32).to_be_bytes());
    h.update(new_pq_key);
    h.update(backend.as_bytes());
    h.update(sequence.to_be_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A controller signer with a fixed signature; the node checks it, this
    /// test checks what is sent.
    struct FixedSigner;

    #[async_trait]
    impl HybridSigner for FixedSigner {
        fn p256_public_key(&self) -> [u8; 64] {
            [7; 64]
        }
        fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
            None
        }
        async fn sign_composite(&self, _m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
            Ok(([9; 64], None))
        }
        async fn sign_p256(&self, _message: &[u8]) -> SdkResult<[u8; 64]> {
            unreachable!()
        }
    }

    /// One HTTP exchange: returns the JSON-RPC request the client sent.
    async fn capture_one(listener: tokio::net::TcpListener) -> serde_json::Value {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let body_start = loop {
            let n = sock.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..body_start]).to_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        while buf.len() < body_start + len {
            let n = sock.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
        }
        let request: serde_json::Value = serde_json::from_slice(&buf[body_start..]).unwrap();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": { "did": "did:tenzro:machine:x", "status": "Active" },
        })
        .to_string();
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(reply.as_bytes()).await.unwrap();
        request
    }

    #[tokio::test]
    async fn register_machine_sends_the_controllers_envelope_over_every_field() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(capture_one(listener));
        let rpc = RpcClient::new(&url, std::time::Duration::from_secs(10), None).unwrap();
        let identity = IdentityClient::new(Arc::new(rpc));
        let controller: Arc<dyn HybridSigner> = Arc::new(FixedSigner);
        let out = identity
            .register_machine(
                RegisterMachineParams {
                    controller_did: "did:tenzro:human:ab".to_string(),
                    public_key: "04".repeat(32),
                    capabilities: vec!["inference".to_string()],
                },
                &controller,
            )
            .await
            .unwrap();
        assert_eq!(out.did, "did:tenzro:machine:x");

        let request = server.await.unwrap();
        assert_eq!(request["method"], "tenzro_registerMachineIdentity");
        let params = &request["params"];
        let mut keys: Vec<&String> = params.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "capabilities",
                "controller_did",
                "did_envelope",
                "public_key"
            ]
        );
        let header = hex::decode(params["did_envelope"].as_str().unwrap()).unwrap();
        let mut o = 0usize;
        let mut take = |n: usize| {
            o += n;
            header[o - n..o].to_vec()
        };
        let did_len = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        assert_eq!(take(did_len), b"did:tenzro:human:ab");
        let method_len = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        assert_eq!(take(method_len), b"tenzro_registerMachineIdentity");
        use sha2::Digest as _;
        let bound: [u8; 32] =
            sha2::Sha256::digest(crate::did_envelope::request_binding(params)).into();
        assert_eq!(take(32), bound);
    }
}
