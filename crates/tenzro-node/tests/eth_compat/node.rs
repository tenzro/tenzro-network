//! Ethereum wallet compatibility of the `eth_*` JSON-RPC surface, driven by
//! the libraries wallets are built on (ethers v6 and viem).
//!
//! The test starts an in-process node on chain 13380 whose genesis funds a
//! secp256k1 wallet, orders the node's mempool into a block twice a second
//! (the genesis validator is not running, so the node holds no consensus
//! key), and runs `tests/eth_compat/compat.mjs` against its RPC endpoint.
//! `scripts/eth-compat.sh` installs the script's packages and runs it.
//!
//! The file lives under `tests/` because it holds fixed test keys; `lib.rs`
//! includes it as a `#[cfg(test)]` module so it can start the node in-process.
//!
//! `TENZRO_ETH_COMPAT_SERVE=1` keeps the chain up after printing its URL,
//! for running the script by hand.

use std::sync::Arc;
use std::time::Duration;

use tenzro_types::Hash;
use tenzro_types::primitives::Address;

use crate::TenzroNode;
use crate::config::{
    GENESIS_SCHEMA_VERSION, GenesisAccount, GenesisConfig, GenesisValidator, NodeConfig,
};
use crate::consensus_driver::OrderedSegment;
use crate::rpc::RpcServer;

/// The public network's chain id, which wallets are configured with.
const CHAIN_ID: u64 = 13_380;
/// The genesis validator's account.
const VALIDATOR: [u8; 32] = [0x5a; 32];
/// Private key of the funded test wallet (a fixed vector, never a real key).
const WALLET_KEY: [u8; 32] = [0x42; 32];
/// Whole TNZO the test wallet holds at genesis.
const WALLET_TNZO: u128 = 1_000;

/// The genesis entry of a validator that never runs, so the node has a
/// committee and a mempool but orders nothing itself.
fn idle_validator() -> GenesisValidator {
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer as _};

    struct Key {
        ml_dsa: tenzro_crypto::pq::MlDsaSigningKey,
        p256: p256::ecdsa::SigningKey,
        public: tenzro_consensus::ValidatorPublicKey,
    }
    impl tenzro_consensus::ValidatorSigner for Key {
        fn public_key(&self) -> &tenzro_consensus::ValidatorPublicKey {
            &self.public
        }
        fn sign(
            &self,
            domain: &[u8],
            message: &[u8],
        ) -> tenzro_consensus::Result<tenzro_consensus::CompositeSignature> {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            use sha2::Digest;
            let rep = tenzro_consensus::validator_key::message_representative(domain, message)
                .expect("short domain");
            let ml_dsa = self
                .ml_dsa
                .sign(tenzro_consensus::validator_key::ml_dsa_context(), &rep);
            let digest: [u8; 32] = sha2::Sha256::digest(&rep).into();
            let ec: p256::ecdsa::Signature =
                self.p256.sign_prehash(&digest).expect("P-256 signature");
            Ok(tenzro_consensus::CompositeSignature {
                ml_dsa,
                p256: ec.to_bytes().to_vec(),
            })
        }
    }

    let ml_dsa = tenzro_crypto::pq::MlDsaSigningKey::generate();
    let p256 = p256::ecdsa::SigningKey::from_slice(&[7; 32]).expect("P-256 scalar");
    let public = tenzro_consensus::ValidatorPublicKey::new(
        ml_dsa.verifying_key_bytes().to_vec(),
        p256.verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
    )
    .expect("validator key");
    let key = Key {
        ml_dsa,
        p256,
        public,
    };
    let node = Ed25519SignerImpl::generate().expect("node key");
    let node_key: [u8; 32] = node
        .public_key()
        .as_bytes()
        .try_into()
        .expect("Ed25519 key");
    let proof = tenzro_consensus::validator_key::prove_registration(&key, &VALIDATOR, &node_key)
        .expect("registration proof");
    let node_key_proof = node
        .sign(
            &tenzro_consensus::validator_key::node_key_registration_message(
                &VALIDATOR,
                &key.public,
                &node_key,
            ),
        )
        .expect("node key proof");
    let vrf = tenzro_crypto::vrf::VrfSecretKey([0x6b; 32]);
    let vrf_key = tenzro_crypto::vrf::VrfProver::public_key(&vrf).0;
    let vrf_key_proof = tenzro_crypto::vrf::VrfProver::prove(
        &vrf,
        &tenzro_consensus::validator_key::vrf_key_registration_alpha(
            &VALIDATOR,
            &key.public,
            &node_key,
            &vrf_key,
        ),
    )
    .expect("VRF key proof");
    GenesisValidator {
        address: hex::encode(VALIDATOR),
        ml_dsa_public_key: hex::encode(&key.public.ml_dsa),
        p256_public_key: hex::encode(&key.public.p256),
        node_key: hex::encode(node_key),
        proof_of_possession: hex::encode(proof),
        node_key_proof: hex::encode(node_key_proof.as_bytes()),
        vrf_key: hex::encode(vrf_key),
        vrf_key_proof: hex::encode(vrf_key_proof.as_bytes()),
        stake: 1_000_000,
        relay: None,
    }
}

fn wallet_address() -> [u8; 20] {
    use sha3::{Digest, Keccak256};
    let key = k256::ecdsa::SigningKey::from_slice(&WALLET_KEY).expect("secp256k1 scalar");
    let point = key.verifying_key().to_sec1_point(false);
    Keccak256::digest(&point.as_bytes()[1..])[12..]
        .try_into()
        .expect("20 bytes")
}

/// A running test chain: the node, its RPC URL and the block-ordering task.
struct Chain {
    node: Arc<TenzroNode>,
    url: String,
    _shutdown: tokio::sync::broadcast::Sender<()>,
    _tmp: tempfile::TempDir,
}

async fn start_chain() -> Chain {
    let tmp = tempfile::tempdir().expect("temp dir");
    let wallet = tenzro_vm::external_tx::evm_account(wallet_address());
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        genesis: Some(GenesisConfig {
            version: GENESIS_SCHEMA_VERSION,
            chain_id: CHAIN_ID,
            timestamp: 0,
            validators: vec![idle_validator()],
            accounts: vec![GenesisAccount {
                address: format!("0x{}", hex::encode(wallet)),
                balance: WALLET_TNZO,
            }],
            weak_subjectivity: None,
            time: tenzro_consensus::TimeRules::default(),
            // The test asks the node for standard EIP-7702 behaviour, where an
            // authorization for another chain is skipped by the EVM; the network's
            // default refuses such an entry at admission, so this chain admits it.
            network_params: [("evm.foreign_chain_authorization_allowed".to_string(), 1)]
                .into_iter()
                .collect(),
            economy: Default::default(),
            role_stakes: Vec::new(),
        }),
        ..Default::default()
    };
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let ordered = node
        .test_ordered_segments
        .take()
        .expect("a node without a consensus key");
    let node = Arc::new(node);

    let (shutdown, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });
    let url = format!("http://{}", addr_rx.await.expect("bound address"));

    let orderer = node.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let Some(consensus) = orderer.consensus() else {
                return;
            };
            let mempool = consensus.mempool();
            let mut transactions = mempool.select_transactions(1_000, u64::MAX);
            let hashes: Vec<Hash> = transactions.iter_mut().map(|t| t.hash()).collect();
            let height = orderer.chain_tip_height() + 1;
            let segment = OrderedSegment {
                height,
                epoch: 0,
                round: height,
                anchor: Hash::new(sha2_of(height)),
                proposer: Address(VALIDATOR),
                timestamp_ms: chrono_ms(),
                transactions,
            };
            if ordered.send(segment).await.is_err() {
                return;
            }
            for _ in 0..100 {
                if orderer.chain_tip_height() >= height {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            mempool.remove_transactions(&hashes);
        }
    });

    Chain {
        node,
        url,
        _shutdown: shutdown,
        _tmp: tmp,
    }
}

fn sha2_of(height: u64) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(height.to_be_bytes()).into()
}

fn chrono_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as u64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Node.js with ethers and viem installed (scripts/eth-compat.sh)"]
async fn ethers_and_viem_drive_the_eth_rpc() {
    let chain = start_chain().await;
    for _ in 0..200 {
        if chain.node.chain_tip_height() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        chain.node.chain_tip_height() >= 1,
        "the test chain ordered no block"
    );

    if std::env::var("TENZRO_ETH_COMPAT_SERVE").is_ok_and(|v| v == "1") {
        println!("ETH_COMPAT_URL={}", chain.url);
        println!("ETH_COMPAT_KEY=0x{}", hex::encode(WALLET_KEY));
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        return;
    }

    let script = std::env::var("TENZRO_ETH_COMPAT_SCRIPT")
        .unwrap_or_else(|_| format!("{}/tests/eth_compat/compat.mjs", env!("CARGO_MANIFEST_DIR")));
    let output = tokio::process::Command::new("node")
        .arg(&script)
        .env("ETH_COMPAT_URL", &chain.url)
        .env("ETH_COMPAT_KEY", format!("0x{}", hex::encode(WALLET_KEY)))
        .env("ETH_COMPAT_CHAIN_ID", CHAIN_ID.to_string())
        .output()
        .await
        .expect("run node");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "the wallet compatibility script failed"
    );
}
