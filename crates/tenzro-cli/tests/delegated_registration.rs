//! A delegated validator registers its machine identity through the key
//! holder.
//!
//! The node runs on a machine with no TPM; its keys are in a provider's TPM,
//! reached through the key holder's local socket. This stands up a fake key
//! holder on a real Unix socket, in front of a real provider (the same
//! `Provider` the key holder's upstream runs, with software keys standing in
//! for the TPM), and drives the CLI's own registration path through it: the
//! identity key and the node account are the provider's, the CLI process
//! holds no key, and the registration it produces is checked by the chain's
//! own verifier.
#![cfg(unix)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use tenzro_crypto::composite::{HybridSigner, SignatureContext};
use tenzro_device_key::derive::{DerivationRoot, RemoteDerive};
use tenzro_device_key::remote::{Audit, Grant, HOLDER_OP_CALL, KeyStore, Policy, Provider};
use tenzro_device_key::{DeviceSignature, HardwareBackend, HardwareSigner};

const LABEL: &str = "tpm-host";

struct Soft(SigningKey, String);
impl HardwareSigner for Soft {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::Tpm
    }
    fn label(&self) -> &str {
        &self.1
    }
    fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
        Ok(self
            .0
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap())
    }
    fn sign_prehash(&self, digest: &[u8; 32]) -> tenzro_device_key::Result<DeviceSignature> {
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_bytes().into())
    }
}

/// The provider's TPM: one P-256 key per label, derived from the label.
struct Tpm;
fn key_for(label: &str) -> SigningKey {
    use sha2::{Digest, Sha256};
    SigningKey::from_slice(&Sha256::digest(label.as_bytes())).unwrap()
}
impl KeyStore for Tpm {
    fn open(&self, label: &str) -> tenzro_device_key::Result<Box<dyn HardwareSigner>> {
        if label.starts_with(&format!("{LABEL}/")) {
            Ok(Box::new(Soft(key_for(label), label.to_string())))
        } else {
            Err(tenzro_device_key::DeviceKeyError::NotFound(label.into()))
        }
    }
}

struct Log;
impl Audit for Log {
    fn record(&self, _client: &[u8], _kind: &str, _outcome: &str) {}
}

struct Rig {
    /// How many requests the key holder carried to the provider.
    carried: Arc<AtomicUsize>,
    root: Arc<DerivationRoot>,
    _dir: tempfile::TempDir,
}

/// Starts the fake key holder once for this process (the CLI installs its
/// signers once per process, as it does when it runs).
fn rig() -> &'static Rig {
    static RIG: OnceLock<Rig> = OnceLock::new();
    RIG.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("holder.sock");
        let root = Arc::new(DerivationRoot::for_tests([9u8; 32]));
        let policy = Policy {
            clients: HashMap::from([(
                b"holder".to_vec(),
                Grant {
                    label: LABEL.into(),
                    derived: true,
                },
            )]),
            allowed_prefixes: vec![tenzro_crypto::composite::COMPOSITE_PREFIX.to_vec()],
            allow_prehash: false,
            per_minute: 10_000,
            requests_per_minute: 100_000,
            derived_prefixes: vec!["tenzro/".into(), "machine/".into()],
        };
        let provider = Arc::new(
            Provider::new(Tpm, Log, policy)
                .with_derivation(root.clone() as Arc<dyn RemoteDerive>)
                .with_attestor(
                    LABEL,
                    Arc::new(tenzro_tee::holder_attest::HolderAttestor(
                        tenzro_tee::tpm_attest::tests::SoftTpm::new(60),
                    )),
                ),
        );
        let carried = Arc::new(AtomicUsize::new(0));
        let listener = UnixListener::bind(&socket).unwrap();
        let (p, c) = (provider.clone(), carried.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let (p, c) = (p.clone(), c.clone());
                std::thread::spawn(move || {
                    let mut s = stream.unwrap();
                    let mut head = [0u8; 5];
                    s.read_exact(&mut head).unwrap();
                    let len = u32::from_be_bytes(head[1..].try_into().unwrap()) as usize;
                    let mut body = vec![0u8; len];
                    s.read_exact(&mut body).unwrap();
                    assert_eq!(head[0], HOLDER_OP_CALL);
                    c.fetch_add(1, Ordering::SeqCst);
                    let answer = p.handle(b"holder", &body);
                    let mut out = vec![0u8];
                    out.extend_from_slice(&(answer.len() as u32).to_be_bytes());
                    out.extend_from_slice(&answer);
                    s.write_all(&out).unwrap();
                });
            }
        });
        tenzro_cli::keystore::DelegatedKey {
            tpm_key_holder: Some(socket),
            tpm_label: Some(LABEL.into()),
        }
        .install()
        .unwrap();
        Rig {
            carried,
            root,
            _dir: dir,
        }
    })
}

#[test]
fn delegated_registration_is_signed_through_the_key_holder_and_verifies() {
    let rig = rig();
    assert!(tenzro_cli::keystore::key_is_delegated());
    let signer = tenzro_cli::keystore::machine_identity_signer(None).unwrap();
    let wallet = tenzro_cli::keystore::node_account(None).unwrap();

    // The keys are the provider's: the CLI process holds none.
    let provider_key = key_for(&format!(
        "{LABEL}/{}",
        tenzro_types::did_derivation::MACHINE_KEY_LABEL
    ));
    assert_eq!(
        signer.public_key().p256,
        provider_key.verifying_key().to_sec1_point(false).as_bytes()[1..]
    );
    assert!(
        signer.has_ml_dsa(),
        "the ML-DSA-65 leg comes from the provider's root"
    );

    let before = rig.carried.load(Ordering::SeqCst);
    let (did, tx) = tenzro_cli::keystore::machine_identity_registration(&signer, wallet).unwrap();
    assert!(
        rig.carried.load(Ordering::SeqCst) > before,
        "the registration was signed by asking the key holder"
    );

    // The chain's own check of the registration: the DID derives from the
    // key, the key signed the statement, both legs verify.
    let tx: tenzro_types::transaction::TransactionType = serde_json::from_value(tx).unwrap();
    let tenzro_types::transaction::TransactionType::RegisterIdentity {
        did: tx_did,
        identity_type,
        display_name,
        controller_pubkey,
        key_type,
        wallet_id,
        wallet_address,
        pq_verifying_key,
        metadata,
        proof,
    } = tx
    else {
        panic!("not a RegisterIdentity transaction");
    };
    assert_eq!(tx_did, did);
    assert!(did.starts_with("did:tenzro:machine:"));
    assert_eq!(wallet_address.as_bytes(), &wallet);
    // The TPM that holds the key attested for it: the root carries the
    // provider's attestation, bound to this identity and its key.
    #[cfg(target_os = "linux")]
    {
        let att: tenzro_tee::tpm_attest::MachineAttestation =
            serde_json::from_str(&metadata[tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY])
                .unwrap();
        assert!(att.activated);
        assert!(tenzro_tee::identity_evidence::tpm_evidence_binds(
            &did,
            &controller_pubkey,
            &att
        ));
    }
    let payload = tenzro_types::identity::RegisterIdentityPayload {
        did,
        identity_type,
        display_name,
        controller_pubkey,
        key_type,
        wallet_id,
        wallet_address,
        pq_verifying_key,
        metadata,
        proof,
    };
    assert!(tenzro_tee::identity_evidence::registration_is_authorized(
        &payload, None
    ));

    // A registration with one field changed is refused: the signature is the
    // key's over this statement, not a blanket one.
    let mut forged = payload.clone();
    forged.wallet_address = tenzro_types::primitives::Address::new([0xEE; 32]);
    assert!(!tenzro_tee::identity_evidence::registration_is_authorized(
        &forged, None
    ));
}

/// A delegated validator's root registered without an attestation gets the
/// provider's TPM attestation attached: the quote answers the chain
/// challenge of the account nonce the attach is sent at.
#[cfg(target_os = "linux")]
#[test]
fn a_delegated_attach_carries_the_providers_attestation_for_the_chain_challenge() {
    rig();
    let signer = tenzro_cli::keystore::machine_identity_signer(None).unwrap();
    let wallet = tenzro_cli::keystore::node_account(None).unwrap();
    let did = tenzro_cli::keystore::machine_root_did(&signer);
    let key = [&[0x04u8][..], &signer.public_key().p256].concat();

    let tx = tenzro_cli::keystore::machine_attestation_attachment(&signer, wallet, 7).unwrap();
    let tenzro_types::transaction::TransactionType::AttachMachineAttestation { op } =
        serde_json::from_value(tx).unwrap()
    else {
        panic!("not an AttachMachineAttestation transaction");
    };
    assert_eq!(op.did, did);
    let att: tenzro_tee::tpm_attest::MachineAttestation =
        serde_json::from_str(&op.attestation).unwrap();
    assert!(att.activated);
    assert_eq!(
        att.nonce,
        tenzro_types::identity::attach_attestation_nonce(&did, &wallet, 7)
    );
    assert!(tenzro_tee::identity_evidence::tpm_evidence_binds(
        &did, &key, &att
    ));
    assert!(tenzro_tee::identity_evidence::controller_signature_holds(
        &key,
        &op.statement(),
        &op.signature,
        signer.public_key().pq.as_deref(),
    ));
}

/// A provider that predates attestation requests, or whose TPM answers for
/// another identity, leaves the machine root to register without a TPM
/// attestation, as before; the attach then says why there is nothing to
/// attach.
#[cfg(target_os = "linux")]
#[test]
fn a_provider_that_does_not_attest_leaves_the_root_without_an_attestation() {
    use tenzro_device_key::remote::{RemoteTpmSigner, Transport, refusal};

    /// A provider one release older: it refuses request kinds it does not
    /// know (an attestation request is kind 23).
    struct Older(Provider<Tpm, Log>);
    impl Transport for Older {
        fn call(&self, request: &[u8]) -> tenzro_device_key::Result<Vec<u8>> {
            if request[1] == 23 {
                return Ok(refusal("unknown request kind"));
            }
            Ok(self.0.handle(b"holder", request))
        }
    }
    /// A provider of this release whose operator named no client to attest for.
    struct Unnamed(Provider<Tpm, Log>);
    impl Transport for Unnamed {
        fn call(&self, request: &[u8]) -> tenzro_device_key::Result<Vec<u8>> {
            Ok(self.0.handle(b"holder", request))
        }
    }
    fn provider() -> Provider<Tpm, Log> {
        Provider::new(
            Tpm,
            Log,
            Policy {
                clients: HashMap::from([(
                    b"holder".to_vec(),
                    Grant {
                        label: LABEL.into(),
                        derived: false,
                    },
                )]),
                allowed_prefixes: vec![tenzro_crypto::composite::COMPOSITE_PREFIX.to_vec()],
                allow_prehash: false,
                per_minute: 10_000,
                requests_per_minute: 100_000,
                derived_prefixes: Vec::new(),
            },
        )
    }
    let label = format!(
        "{LABEL}/{}",
        tenzro_types::did_derivation::MACHINE_KEY_LABEL
    );
    let signers = [
        RemoteTpmSigner::open(Older(provider()), &label)
            .map(|s| Box::new(s) as Box<dyn HardwareSigner>),
        RemoteTpmSigner::open(Unnamed(provider()), &label)
            .map(|s| Box::new(s) as Box<dyn HardwareSigner>),
    ];
    for p256 in signers {
        let signer =
            tenzro_device_key::HardwareHybridSigner::from_parts(p256.unwrap(), None).unwrap();
        let (_, tx) =
            tenzro_cli::keystore::machine_identity_registration(&signer, [7u8; 32]).unwrap();
        let tenzro_types::transaction::TransactionType::RegisterIdentity { metadata, .. } =
            serde_json::from_value(tx).unwrap()
        else {
            panic!("not a RegisterIdentity transaction");
        };
        assert!(metadata.is_empty(), "{metadata:?}");
        let err = tenzro_cli::keystore::machine_attestation_attachment(&signer, [7u8; 32], 0)
            .unwrap_err();
        assert!(err.to_string().contains("does not attest"), "{err}");
    }
}

// --- A node whose account nonce moves between the read and the submit. ------

/// A JSON-RPC node that serves just what a transaction needs. Its account is
/// at nonce 6; the first `stale_reads` nonce reads report the stale 5, as if
/// the node's own transaction took 5 after the read.
struct FakeNode {
    url: String,
    sent: Arc<Mutex<Vec<serde_json::Value>>>,
    rejected: Arc<AtomicUsize>,
}

fn fake_node(stale_reads: usize) -> FakeNode {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let sent = Arc::new(Mutex::new(Vec::new()));
    let rejected = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let (s2, r2) = (sent.clone(), rejected.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let (sent, rejected, reads) = (s2.clone(), r2.clone(), reads.clone());
            std::thread::spawn(move || {
                let mut s = stream.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let body = loop {
                    let n = s.read(&mut chunk).unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..at]).to_ascii_lowercase();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .map(|v| v.trim().parse().unwrap())
                            .unwrap_or(0);
                        if buf.len() >= at + 4 + len {
                            break buf[at + 4..at + 4 + len].to_vec();
                        }
                    }
                };
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let id = req["id"].clone();
                let params = req["params"].clone();
                let mut reply = match req["method"].as_str().unwrap() {
                    "eth_getTransactionCount" => {
                        let n = if reads.fetch_add(1, Ordering::SeqCst) < stale_reads {
                            5
                        } else {
                            6
                        };
                        serde_json::json!({"result": format!("0x{n:x}")})
                    }
                    "eth_chainId" => serde_json::json!({"result": "0x539"}),
                    "eth_gasPrice" => serde_json::json!({"result": "0x3b9aca00"}),
                    "tenzro_sendRawTransaction" => {
                        if params["nonce"] != 6 {
                            rejected.fetch_add(1, Ordering::SeqCst);
                            serde_json::json!({"error": {"code": -32000,
                                "message": format!("Invalid nonce: expected 6, got {}", params["nonce"])}})
                        } else {
                            sent.lock().unwrap().push(params);
                            serde_json::json!({"result": {"tx_hash": "0xabc"}})
                        }
                    }
                    other => serde_json::json!({"error": {"code": -32601, "message": other}}),
                };
                reply["jsonrpc"] = "2.0".into();
                reply["id"] = id;
                let body = reply.to_string();
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    FakeNode {
        url,
        sent,
        rejected,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_survives_a_stale_nonce_and_the_node_account_signs_through_the_holder() {
    let rig = rig();
    let node = fake_node(1);
    let rpc = tenzro_cli::rpc::RpcClient::new(&node.url);
    let signer = tenzro_cli::keystore::machine_identity_signer(None).unwrap();
    let wallet = tenzro_cli::keystore::node_account(None).unwrap();
    let (_, register) =
        tenzro_cli::keystore::machine_identity_registration(&signer, wallet).unwrap();

    let (answer, from) =
        tenzro_cli::keystore::send_as_node(&rpc, None, [0u8; 32], register, 300_000)
            .await
            .unwrap();
    assert_eq!(answer["tx_hash"], "0xabc");
    assert_eq!(from, format!("0x{}", hex::encode(wallet)));
    // One attempt carried the stale nonce 5 and was refused; the CLI read
    // the nonce again and sent 6, with no human re-running the command.
    assert_eq!(node.rejected.load(Ordering::SeqCst), 1);
    let sent = node.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    let params = &sent[0];

    // The submitted transaction is signed by the node account, which is the
    // provider's key, and the signature verifies over the transaction hash.
    let wallet_label = format!("{LABEL}/machine/wallet");
    let xy = key_for(&wallet_label)
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()[1..]
        .to_vec();
    assert_eq!(params["public_key"], hex::encode(&xy));
    let typed: tenzro_types::transaction::TransactionType =
        serde_json::from_value(params["tx_type"].clone()).unwrap();
    let mut tx = tenzro_types::transaction::Transaction::new(
        tenzro_types::primitives::ChainId::from(0x539),
        tenzro_types::primitives::Address::new(wallet),
        tenzro_types::primitives::Address::new([0u8; 32]),
        tenzro_types::primitives::Nonce::from(6),
        typed,
        300_000,
        0x3b9aca00,
    );
    tx.timestamp = tenzro_types::primitives::Timestamp(params["timestamp"].as_i64().unwrap());
    tx.valid_until = tenzro_types::primitives::Timestamp(params["valid_until"].as_i64().unwrap());
    let sig: tenzro_crypto::composite::CompositeSignature =
        serde_json::from_value(params["signature"].clone()).unwrap();
    let pq = rig
        .root
        .ml_dsa65_public(&format!("{wallet_label}/ml-dsa-65"))
        .unwrap();
    let public = tenzro_crypto::composite::CompositePublicKey {
        p256: xy,
        pq: Some(pq),
    };
    tenzro_crypto::composite::verify_composite(
        &public,
        SignatureContext::Transaction,
        tx.hash().as_bytes(),
        &sig,
        tenzro_crypto::composite::PqPolicy::Required,
    )
    .expect("the node account's signature over the transaction verifies");
}

#[tokio::test]
async fn only_a_stale_nonce_is_retried_and_only_a_few_times() {
    use tenzro_cli::keystore::retry_stale_nonce;
    // A stale nonce twice, then success.
    let n = AtomicUsize::new(0);
    let ok = retry_stale_nonce(|| async {
        if n.fetch_add(1, Ordering::SeqCst) < 2 {
            Err(anyhow::anyhow!(
                "RPC error [-32000]: Invalid nonce: expected 7, got 6"
            ))
        } else {
            Ok(7)
        }
    })
    .await
    .unwrap();
    assert_eq!((ok, n.load(Ordering::SeqCst)), (7, 3));

    // Any other refusal comes back at once.
    let n = AtomicUsize::new(0);
    let err = retry_stale_nonce(|| async {
        n.fetch_add(1, Ordering::SeqCst);
        Err::<(), _>(anyhow::anyhow!("insufficient balance"))
    })
    .await
    .unwrap_err();
    assert_eq!(n.load(Ordering::SeqCst), 1);
    assert!(err.to_string().contains("insufficient balance"));

    // A nonce that never settles gives up with the node's own error.
    let n = AtomicUsize::new(0);
    let err = retry_stale_nonce(|| async {
        n.fetch_add(1, Ordering::SeqCst);
        Err::<(), _>(anyhow::anyhow!("Invalid nonce: expected 9, got 8"))
    })
    .await
    .unwrap_err();
    assert_eq!(n.load(Ordering::SeqCst), 4);
    assert!(err.to_string().contains("Invalid nonce"));
}

#[test]
fn the_socket_and_the_label_go_together() {
    let only_socket = tenzro_cli::keystore::DelegatedKey {
        tpm_key_holder: Some("/run/tenzro/holder.sock".into()),
        tpm_label: None,
    };
    assert!(only_socket.install().is_err());
    let only_label = tenzro_cli::keystore::DelegatedKey {
        tpm_key_holder: None,
        tpm_label: Some("tpm-host".into()),
    };
    assert!(only_label.install().is_err());
}
