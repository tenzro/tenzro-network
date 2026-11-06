//! Payment channels driven over JSON-RPC by a client holding its own keys.
//!
//! The payer holds a P-256 key the way a wallet holds its device key (in
//! memory here, under the `test-keys` feature).
//! Every step goes over HTTP the way such a client talks to a node: the payee
//! comes from `tenzro_getNodeStatus`, the escrow is a signed `CreateEscrow` sent
//! with `tenzro_sendRawTransaction`, and the channel is opened, paid with signed
//! vouchers, and closed by the payer's signed request.
//!
//! Tests that need blocks run a solo validator on this machine's hardware
//! consensus key and are ignored elsewhere. The rest run on any machine, on a
//! node following a chain whose validator is not running: their escrow is
//! written into the ledger state directly, as the funded record a finalized
//! `CreateEscrow` leaves there, so the channel checks against it are exercised
//! without a block producer.
//!
//! One test process holds one client key namespace, and a test root derives
//! the node's keys under it too, so every test opens the payer before it
//! starts a node: the node's keys, and its payee, never change under it.

mod dpop_bearer;
mod passkey_holder;

// The media tests load models: the parser child is this binary started again.
#[cfg(feature = "inference")]
tenzro_node::enter_parse_jail_child_before_tests!();

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::broadcast;

use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner, SignatureContext};
use tenzro_crypto::signatures::Ed25519SignerImpl;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::payment_authorization::{EscrowVoucher, escrow_voucher_preimage};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{Transaction, TransactionType};

/// The payer's fixed test key seed.
const PAYER_SEED: u8 = 0x31;
/// Five TNZO (18 decimals).
const AMOUNT: u128 = 5_000_000_000_000_000_000;
/// One TNZO, for gas.
const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
const ESCROW_GAS_LIMIT: u64 = 2_000_000;

fn payer_signer() -> TestHybridSigner {
    TestHybridSigner::p256_only(PAYER_SEED)
}

/// The iroh endpoint of a test node: loopback, on a port the operating
/// system picks when the node binds, so any number of nodes run in one
/// process.
fn loopback_iroh() -> tenzro_iroh::TenzroIrohConfig {
    tenzro_iroh::TenzroIrohConfig {
        bind_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        port_mapping: false,
        ..Default::default()
    }
}

/// What the chain answers a voucher signed by a key that is not the payer's.
const NOT_THE_PAYERS_KEY: &str =
    "the key does not name the account, and no keystore on chain links it";

fn account_of(signer: &dyn HybridSigner) -> Address {
    Address::new(signer.public_key().account_slot())
}

/// A key that is not the payer's.
fn stranger() -> TestHybridSigner {
    TestHybridSigner::random()
}

struct Node {
    url: String,
    http: reqwest::Client,
    node: Arc<TenzroNode>,
    _shutdown: broadcast::Sender<()>,
    _rpc: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    /// The hardware key of the chain's one validator, for a follower whose
    /// validator is not running.
    committee_key: Option<CommitteeKey>,
    /// Held while the node lives. The model catalog is one per process and
    /// every node installs what it has learnt over it, so two nodes of this
    /// test process at once would replace each other's catalog; the media
    /// tests read the model's entry from it while a request runs.
    _one_node_at_a_time: tokio::sync::OwnedMutexGuard<()>,
}

/// The one node of this test process that is running.
static ONE_NODE: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

impl Node {
    /// A full node following a chain whose one validator is not running, so
    /// no block is produced.
    async fn follower() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let key = CommitteeKey::new(7);
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: loopback_iroh(),
            genesis: Some(genesis(key.entry())),
            ..Default::default()
        };
        let mut n = Self::start(config, tmp).await;
        n.committee_key = Some(key);
        n
    }

    /// Has the committee certify the genesis epoch's first checkpoint and
    /// imports the certificate the way a follower imports one from the
    /// network: the validator's hardware key certifies a session key for the
    /// epoch, the session key votes, the vote forms a quorum certificate, and
    /// the follower verifies it against the genesis committee before keeping
    /// it. The checkpoint covers no blocks yet: it commits the genesis state
    /// (the state trie's root at height 0, as a node seeds its executed tip),
    /// as the first one a chain with no transactions closes.
    async fn certify_first_checkpoint(&self) {
        use tenzro_consensus::checkpoint::{
            Checkpoint, VoteCollector, VoteOutcome, checkpoint_state_height, merkle_root,
        };
        use tenzro_storage::BlockStore;
        let hardware = self
            .committee_key
            .as_ref()
            .expect("a follower's committee key");
        let consensus = self
            .node
            .consensus()
            .expect("the follower tracks consensus");
        let genesis_block = tenzro_storage::block_store::BlockStoreImpl::new(
            self.node.storage().expect("storage").clone(),
        )
        .expect("block store")
        .get_block_by_height(tenzro_types::BlockHeight(0))
        .await
        .expect("block read")
        .expect("the genesis block");
        let checkpoint = Checkpoint {
            chain_id: self.chain_id().await,
            genesis_hash: genesis_block.hash().0,
            epoch: 0,
            index: 0,
            prev: [0; 32],
            first_height: 1,
            last_height: 0,
            blocks_root: merkle_root(&[]),
            state_height: checkpoint_state_height(1, 0),
            state_root: tenzro_storage::StateTrie::new(
                self.node.storage().expect("storage").clone() as Arc<dyn tenzro_storage::KvStore>,
            )
            .root_at(0)
            .expect("state trie read")
            .expect("the genesis state root")
            .0,
            statement_root: merkle_root(&[]),
            next_committee_root: None,
            anchor_round: 0,
            timestamp_ms: genesis_block.header.timestamp.as_millis().max(0) as u64,
            ordering_root: [0; 32],
        };
        let session = CommitteeKey::new(9);
        let session_cert = tenzro_consensus::session::sign_certificate(
            hardware,
            checkpoint.chain_id,
            checkpoint.genesis_hash,
            checkpoint.epoch,
            session.public.clone(),
        )
        .expect("session certificate");
        let vote =
            tenzro_consensus::sign_checkpoint(&session, &session_cert, &FirstVote, 0, &checkpoint)
                .expect("checkpoint vote");
        let committee = consensus.committee(0).expect("the genesis committee");
        let VoteOutcome::Certified(cert) = VoteCollector::new().add(&committee, vote) else {
            panic!("the one validator's vote is a quorum");
        };
        consensus.admit_sessions(0, vec![session_cert]);
        assert!(
            consensus
                .accept_certificate(&cert)
                .expect("the certificate verifies")
        );
    }

    /// A solo validator on this machine's hardware consensus key.
    async fn validator() -> Self {
        Self::validator_with(|_| {}).await
    }

    /// [`Node::validator`] on a genesis `amend` adds to.
    async fn validator_with(amend: impl FnOnce(&mut tenzro_node::config::GenesisConfig)) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let validator =
            tenzro_node::config::GenesisValidator::from_local_hardware(tmp.path(), 1_000_000)
                .expect("a hardware consensus key");
        let mut g = genesis(validator);
        amend(&mut g);
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            roles: tenzro_types::RoleSet::validator_only(),
            consensus: Some(tenzro_consensus::ConsensusConfig::default()),
            iroh: loopback_iroh(),
            genesis: Some(g),
            ..Default::default()
        };
        let n = Self::start(config, tmp).await;
        // The node claims vouchers with transactions from its own ledger account.
        let ledger = account_of(n.node.identity_signer().expect("node signer").as_ref());
        n.fund(&ledger, ONE_TNZO);
        n
    }

    async fn start(config: NodeConfig, tmp: tempfile::TempDir) -> Self {
        let one_node_at_a_time = ONE_NODE.clone().lock_owned().await;
        dpop_bearer::admit_operator(tmp.path(), &operator().did());
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);
        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");
        Self {
            url: format!("http://{addr}"),
            http: reqwest::Client::new(),
            node,
            _shutdown: shutdown,
            _rpc: handle,
            _tmp: tmp,
            committee_key: None,
            _one_node_at_a_time: one_node_at_a_time,
        }
    }

    /// The JSON-RPC response to `method(params)`: `Ok(result)` or `Err(error)`.
    async fn call(&self, method: &str, params: Value) -> Result<Value, Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .expect("HTTP request")
            .json()
            .await
            .expect("JSON response");
        match resp.get("error") {
            Some(e) if !e.is_null() => Err(e.clone()),
            _ => Ok(resp["result"].clone()),
        }
    }

    async fn ok(&self, method: &str, params: Value) -> Value {
        self.call(method, params)
            .await
            .unwrap_or_else(|e| panic!("{method} failed: {e}"))
    }

    /// The error message `method(params)` is refused with.
    async fn refused(&self, method: &str, params: Value) -> String {
        match self.call(method, params).await {
            Ok(v) => panic!("{method} was accepted: {v}"),
            Err(e) => e["message"].as_str().unwrap_or_default().to_string(),
        }
    }

    /// The payee `tenzro_getNodeStatus` reports.
    async fn payee(&self) -> Address {
        let info = self.ok("tenzro_getNodeStatus", json!({})).await;
        let hex = info["payee"]
            .as_str()
            .expect("tenzro_getNodeStatus reports a payee");
        address(hex)
    }

    async fn chain_id(&self) -> u64 {
        hex_u128(&self.ok("eth_chainId", json!([])).await) as u64
    }

    async fn balance(&self, a: &Address) -> u128 {
        hex_u128(
            &self
                .ok("eth_getBalance", json!([hex_address(a), "latest"]))
                .await,
        )
    }

    /// Credit `a` directly in the ledger state.
    fn fund(&self, a: &Address, amount: u128) {
        use tenzro_vm::traits::VmState as _;
        let mut state =
            tenzro_vm::StateAdapter::with_storage(self.node.storage().expect("storage").clone());
        let before = state.get_balance(a.as_bytes());
        state.set_balance(a.as_bytes(), before + amount);
        state.commit().expect("commit funded balance");
    }

    /// Write the funded escrow a finalized `CreateEscrow` from `payer` at
    /// `nonce` leaves in the ledger state.
    fn seed_escrow(&self, payer: &Address, nonce: u64, payee: &Address, amount: u128) -> [u8; 32] {
        use tenzro_vm::traits::VmState as _;
        let escrow_id = escrow_id_for(payer, nonce);
        let now = chrono::Utc::now().timestamp_millis();
        let record = tenzro_settlement::EscrowAccount {
            usd_e6: 0,
            escrow_id: hex::encode(escrow_id),
            payer: *payer,
            payee: *payee,
            amount,
            asset_id: tenzro_types::asset::AssetId::tnzo(),
            created_at: tenzro_types::primitives::Timestamp(now),
            expires_at: tenzro_types::primitives::Timestamp(now + 3_600_000),
            status: tenzro_settlement::EscrowStatus::Funded,
            release_conditions: tenzro_types::settlement::ReleaseConditions::Timeout,
            claimed: 0,
            approved_by: None,
            reference: None,
        };
        let mut state =
            tenzro_vm::StateAdapter::with_storage(self.node.storage().expect("storage").clone());
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            format!("escrow:{}", hex::encode(escrow_id)).as_bytes(),
            serde_json::to_vec(&record).expect("escrow json"),
        );
        state.commit().expect("commit escrow");
        escrow_id
    }

    /// Sign `tx_type` as `signer` at the pending nonce and the quoted gas
    /// price, and send it with `tenzro_sendRawTransaction`. Returns the nonce it
    /// was sent at and its hash.
    async fn send(
        &self,
        signer: &dyn HybridSigner,
        to: Address,
        tx_type: TransactionType,
    ) -> (u64, String) {
        let public = signer.public_key().clone();
        let from = account_of(signer);
        let nonce = hex_u128(
            &self
                .ok(
                    "eth_getTransactionCount",
                    json!([hex_address(&from), "pending"]),
                )
                .await,
        ) as u64;
        let chain_id = self.chain_id().await;
        let gas_price = hex_u128(&self.ok("eth_gasPrice", json!([])).await) as u64;
        let tx = Transaction::new(
            ChainId::from(chain_id),
            from,
            to,
            Nonce::from(nonce),
            tx_type.clone(),
            ESCROW_GAS_LIMIT,
            gas_price,
        );
        let sig = signer
            .sign(SignatureContext::Transaction, tx.hash().as_bytes())
            .expect("sign transaction");
        let result = self
            .ok(
                "tenzro_sendRawTransaction",
                json!({
                    "from": hex_address(&from),
                    "to": hex_address(&to),
                    "gas_limit": ESCROW_GAS_LIMIT,
                    "gas_price": gas_price,
                    "nonce": nonce,
                    "chain_id": chain_id,
                    "timestamp": tx.timestamp.as_millis(),
                    "valid_until": tx.valid_until.as_millis(),
                    "tx_type": serde_json::to_value(&tx_type).expect("tx_type json"),
                    "public_key": hex::encode(&public.p256),
                    "signature": sig,
                }),
            )
            .await;
        let hash = result
            .as_str()
            .or_else(|| result["tx_hash"].as_str())
            .unwrap_or_else(|| panic!("tenzro_sendRawTransaction returned no hash: {result}"))
            .to_string();
        (nonce, hash)
    }

    /// Wait for the transaction's receipt and return whether it succeeded.
    async fn executed(&self, tx_hash: &str) -> bool {
        for _ in 0..600 {
            let receipt = self.ok("eth_getTransactionReceipt", json!([tx_hash])).await;
            if !receipt.is_null() {
                return receipt["status"] == "0x1";
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("transaction {tx_hash} did not execute within 60s");
    }
}

/// A one-validator genesis on chain 1337.
fn genesis(validator: tenzro_node::config::GenesisValidator) -> tenzro_node::config::GenesisConfig {
    tenzro_node::config::GenesisConfig {
        version: tenzro_node::config::GENESIS_SCHEMA_VERSION,
        chain_id: 1337,
        timestamp: 0,
        validators: vec![validator],
        accounts: Vec::new(),
        weak_subjectivity: None,
        time: tenzro_consensus::TimeRules::default(),
        network_params: Default::default(),
        economy: Default::default(),
        role_stakes: Vec::new(),
    }
}

/// The consensus key of a genesis validator that never runs: it signs only
/// its own registration, so a follower has a committee to verify against.
struct CommitteeKey {
    ml_dsa: tenzro_crypto::pq::MlDsaSigningKey,
    p256: p256::ecdsa::SigningKey,
    public: tenzro_consensus::ValidatorPublicKey,
}

impl CommitteeKey {
    fn new(scalar: u8) -> Self {
        let ml_dsa = tenzro_crypto::pq::MlDsaSigningKey::generate();
        let p256 = p256::ecdsa::SigningKey::from_slice(&[scalar; 32]).expect("P-256 scalar");
        let public = tenzro_consensus::ValidatorPublicKey::new(
            ml_dsa.verifying_key_bytes().to_vec(),
            p256.verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        )
        .expect("validator key");
        Self {
            ml_dsa,
            p256,
            public,
        }
    }

    fn entry(&self) -> tenzro_node::config::GenesisValidator {
        use tenzro_crypto::signatures::Signer as _;
        let address = [0x5a; 32];
        let node = Ed25519SignerImpl::generate().expect("node key");
        let node_key: [u8; 32] = node
            .public_key()
            .as_bytes()
            .try_into()
            .expect("Ed25519 key");
        let proof = tenzro_consensus::validator_key::prove_registration(self, &address, &node_key)
            .expect("registration proof");
        let node_key_proof = node
            .sign(
                &tenzro_consensus::validator_key::node_key_registration_message(
                    &address,
                    &self.public,
                    &node_key,
                ),
            )
            .expect("node key proof");
        let vrf = tenzro_crypto::vrf::VrfSecretKey([0x6b; 32]);
        let vrf_key = tenzro_crypto::vrf::VrfProver::public_key(&vrf).0;
        let vrf_key_proof = tenzro_crypto::vrf::VrfProver::prove(
            &vrf,
            &tenzro_consensus::validator_key::vrf_key_registration_alpha(
                &address,
                &self.public,
                &node_key,
                &vrf_key,
            ),
        )
        .expect("VRF key proof");
        tenzro_node::config::GenesisValidator {
            address: hex::encode(address),
            ml_dsa_public_key: hex::encode(&self.public.ml_dsa),
            p256_public_key: hex::encode(&self.public.p256),
            node_key: hex::encode(node_key),
            proof_of_possession: hex::encode(proof),
            node_key_proof: hex::encode(node_key_proof.as_bytes()),
            vrf_key: hex::encode(vrf_key),
            vrf_key_proof: hex::encode(vrf_key_proof.as_bytes()),
            stake: 1_000_000,
            relay: None,
        }
    }
}

/// The vote high-water mark of a validator that signs one checkpoint.
struct FirstVote;

impl tenzro_consensus::VoteHighWater for FirstVote {
    fn record(
        &self,
        _epoch: u64,
        _index: u64,
        _digest: &[u8; 32],
        _prev: &[u8; 32],
    ) -> tenzro_consensus::Result<()> {
        Ok(())
    }
}

impl tenzro_consensus::ValidatorSigner for CommitteeKey {
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
        let ec: p256::ecdsa::Signature = self.p256.sign_prehash(&digest).expect("P-256 signature");
        Ok(tenzro_consensus::CompositeSignature {
            ml_dsa,
            p256: ec.to_bytes().to_vec(),
        })
    }
}

fn address(hex_str: &str) -> Address {
    let b = hex::decode(hex_str.trim_start_matches("0x")).expect("address hex");
    Address::new(<[u8; 32]>::try_from(b).expect("32-byte address"))
}

fn hex_address(a: &Address) -> String {
    format!("0x{}", hex::encode(a.as_bytes()))
}

fn hex_u128(v: &Value) -> u128 {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("expected a hex quantity, got {v}"));
    u128::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex quantity")
}

/// The VM's escrow id: `SHA-256("tenzro/escrow/id" ‖ payer ‖ nonce_le)`.
fn escrow_id_for(payer: &Address, nonce: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/escrow/id");
    h.update(payer.as_bytes());
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

/// A cumulative voucher on `escrow_id` signed by `signer`.
fn voucher(
    signer: &dyn HybridSigner,
    chain_id: u64,
    escrow_id: &[u8; 32],
    cumulative: u128,
) -> EscrowVoucher {
    let sig = signer
        .sign(
            SignatureContext::EscrowVoucher,
            &escrow_voucher_preimage(chain_id, escrow_id, cumulative, &[0u8; 32]),
        )
        .expect("sign voucher");
    let public = signer.public_key();
    EscrowVoucher {
        binding: [0u8; 32],
        agent: None,
        escrow_id: *escrow_id,
        cumulative_amount: cumulative,
        public_key: public.p256.clone(),
        signature: sig,
        attribution: None,
    }
}

fn update_params(v: &EscrowVoucher, charge: u128) -> Value {
    json!({ "voucher": v, "charge": charge.to_string() })
}

/// `tenzro_closePaymentChannel` params signed by `signer` as the account
/// owner of the channel.
fn close_params(signer: &dyn HybridSigner, escrow_id: &[u8; 32]) -> Value {
    let timestamp_ms = chrono::Utc::now().timestamp_millis();
    let mut message = b"tenzro/rpc-owner/v1\0tenzro_closePaymentChannel\0".to_vec();
    message.extend_from_slice(escrow_id);
    message.extend_from_slice(&timestamp_ms.to_le_bytes());
    let sig = signer
        .sign(SignatureContext::AccountOwner, &message)
        .expect("sign close");
    let public = signer.public_key();
    json!({
        "channel_id": hex::encode(escrow_id),
        "timestamp_ms": timestamp_ms,
        "public_key": hex::encode(&public.p256),
        "signature": sig,
    })
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn node_info_reports_the_payee_a_channel_is_opened_against() {
    let payer = payer_signer();
    let n = Node::follower().await;
    let payee = n.payee().await;
    assert_eq!(Some(payee), n.node.operator_payee());

    // An escrow naming the reported payee opens a channel ...
    let escrow_id = n.seed_escrow(&account_of(&payer), 0, &payee, AMOUNT);
    let session = n
        .ok(
            "tenzro_openPaymentChannel",
            json!({ "channel_id": hex::encode(escrow_id) }),
        )
        .await;
    assert_eq!(session["session_id"], hex::encode(escrow_id));
    assert_eq!(session["payee"], serde_json::to_value(payee).unwrap());
    assert_eq!(
        session["payer"],
        serde_json::to_value(account_of(&payer)).unwrap()
    );
    assert_eq!(session["state"], "Open");

    // ... and one naming any other account does not.
    let elsewhere = n.seed_escrow(&account_of(&payer), 1, &Address::new([0x42; 32]), AMOUNT);
    let msg = n
        .refused(
            "tenzro_openPaymentChannel",
            json!({ "channel_id": hex::encode(elsewhere) }),
        )
        .await;
    assert!(
        msg.contains("is not a funded escrow paying this payee"),
        "{msg}"
    );
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_channel_over_an_unknown_escrow_is_refused() {
    let _payer = payer_signer();
    let n = Node::follower().await;
    let msg = n
        .refused(
            "tenzro_openPaymentChannel",
            json!({ "channel_id": hex::encode([0x7a; 32]) }),
        )
        .await;
    assert!(msg.contains("does not exist on the ledger"), "{msg}");
    let msg = n
        .refused(
            "tenzro_openPaymentChannel",
            json!({ "channel_id": "0x1234" }),
        )
        .await;
    assert!(msg.contains("32-byte"), "{msg}");
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn only_the_payers_vouchers_pay_a_channel_and_only_the_payer_closes_it() {
    let payer = payer_signer();
    let n = Node::follower().await;
    let chain_id = n.chain_id().await;
    let escrow_id = n.seed_escrow(&account_of(&payer), 0, &n.payee().await, AMOUNT);
    n.ok(
        "tenzro_openPaymentChannel",
        json!({ "channel_id": hex::encode(escrow_id) }),
    )
    .await;

    // A voucher signed by another key is refused, though its signature is
    // valid for that key: the key neither names the payer's account nor is
    // linked to it by a keystore on chain.
    let forged = voucher(&stranger(), chain_id, &escrow_id, AMOUNT);
    let msg = n
        .refused(
            "tenzro_updatePaymentChannel",
            update_params(&forged, AMOUNT),
        )
        .await;
    assert!(msg.contains(NOT_THE_PAYERS_KEY), "{msg}");

    // A payer's voucher whose amount was raised after signing is refused.
    let mut raised = voucher(&payer, chain_id, &escrow_id, AMOUNT / 5);
    raised.cumulative_amount = AMOUNT;
    let msg = n
        .refused(
            "tenzro_updatePaymentChannel",
            update_params(&raised, AMOUNT),
        )
        .await;
    assert!(msg.contains("signature does not verify"), "{msg}");

    // The payer's vouchers pay, cumulatively.
    let first = voucher(&payer, chain_id, &escrow_id, AMOUNT / 5);
    let paid = n
        .ok(
            "tenzro_updatePaymentChannel",
            update_params(&first, AMOUNT / 5),
        )
        .await;
    assert_eq!(paid["session"]["spent"], json!(AMOUNT / 5));
    let second = voucher(&payer, chain_id, &escrow_id, AMOUNT * 2 / 5);
    let paid = n
        .ok(
            "tenzro_updatePaymentChannel",
            update_params(&second, AMOUNT / 5),
        )
        .await;
    assert_eq!(
        paid["session"]["accepted_cumulative"],
        json!(AMOUNT * 2 / 5)
    );
    // A charge the voucher does not cover is refused.
    let msg = n
        .refused("tenzro_updatePaymentChannel", update_params(&second, 1))
        .await;
    assert!(msg.contains("available"), "{msg}");

    // Nobody but the payer closes the channel.
    let msg = n
        .refused(
            "tenzro_closePaymentChannel",
            json!({ "channel_id": hex::encode(escrow_id) }),
        )
        .await;
    assert!(msg.contains("timestamp_ms"), "{msg}");
    let msg = n
        .refused(
            "tenzro_closePaymentChannel",
            close_params(&stranger(), &escrow_id),
        )
        .await;
    assert!(msg.contains("does not name the claimed account"), "{msg}");

    let closed = n
        .ok(
            "tenzro_closePaymentChannel",
            close_params(&payer, &escrow_id),
        )
        .await;
    assert_eq!(closed["status"], "closing");
    assert_eq!(closed["claim_due"], (AMOUNT * 2 / 5).to_string());
    let late = voucher(&payer, chain_id, &escrow_id, AMOUNT * 3 / 5);
    let msg = n
        .refused(
            "tenzro_updatePaymentChannel",
            update_params(&late, AMOUNT / 5),
        )
        .await;
    assert!(msg.contains("closing"), "{msg}");
}

#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_channel_funded_opened_paid_and_closed_over_rpc_pays_the_node_on_chain() {
    let payer = payer_signer();
    let n = Node::validator().await;
    n.fund(&account_of(&payer), AMOUNT + ONE_TNZO);
    let chain_id = n.chain_id().await;
    let payee = n.payee().await;
    let payee_before = n.balance(&payee).await;

    // The payer funds an escrow naming the node's payee.
    let expires_at = (chrono::Utc::now().timestamp_millis() + 3_600_000) as u64;
    let (nonce, tx) = n
        .send(
            &payer,
            payee,
            TransactionType::CreateEscrow {
                usd_e6: 0,
                payee,
                amount: AMOUNT,
                asset_id: tenzro_types::asset::AssetId::tnzo(),
                expires_at,
                release_conditions: tenzro_types::settlement::ReleaseConditions::Timeout,
                reference: None,
            },
        )
        .await;
    assert!(n.executed(&tx).await, "escrow funded");
    let escrow_id = escrow_id_for(&account_of(&payer), nonce);

    let session = n
        .ok(
            "tenzro_openPaymentChannel",
            json!({ "channel_id": hex::encode(escrow_id) }),
        )
        .await;
    assert_eq!(session["deposit"], json!(AMOUNT));

    let forged = voucher(&stranger(), chain_id, &escrow_id, AMOUNT);
    let msg = n
        .refused(
            "tenzro_updatePaymentChannel",
            update_params(&forged, AMOUNT),
        )
        .await;
    assert!(msg.contains(NOT_THE_PAYERS_KEY), "{msg}");

    let paid = AMOUNT * 2 / 5;
    n.ok(
        "tenzro_updatePaymentChannel",
        update_params(&voucher(&payer, chain_id, &escrow_id, paid), paid),
    )
    .await;

    let closed = n
        .ok(
            "tenzro_closePaymentChannel",
            close_params(&payer, &escrow_id),
        )
        .await;
    assert_eq!(closed["claim_due"], paid.to_string());

    // The node's claimer claims the voucher on-chain; the channel then
    // reports closed with nothing left to claim.
    let mut status = String::new();
    for _ in 0..180 {
        let again = n
            .ok(
                "tenzro_closePaymentChannel",
                close_params(&payer, &escrow_id),
            )
            .await;
        status = again["status"].as_str().unwrap_or_default().to_string();
        if status == "closed" {
            assert!(again["claim_due"].is_null());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert_eq!(status, "closed", "the voucher was claimed within 180s");
    // The claim settles like any payment, less the settlement fee. The payee
    // is the node's own ledger account, which also paid the claim's gas.
    let fee = paid * tenzro_types::fees::DEFAULT_SETTLEMENT_FEE_BPS as u128 / 10_000;
    let gained = n.balance(&payee).await - payee_before;
    assert!(
        gained <= paid - fee && gained > paid - fee - ONE_TNZO / 100,
        "the payee gained {gained}; expected {} less the claim's gas",
        paid - fee
    );
}

/// The operator every test node admits.
fn operator() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

impl Node {
    /// Call `method` as the signed-in operator and return its result.
    async fn as_operator(&self, method: &str, params: Value) -> Value {
        let op = operator().sign_in(&self.http, &self.url).await;
        let resp = op.call(&self.http, &self.url, method, params).await;
        assert!(
            resp["error"].is_null(),
            "{method} failed: {}",
            resp["error"]
        );
        resp["result"].clone()
    }
}

/// The provider's cards: a language model and an embedder in USD per million
/// tokens, an image model in TNZO per pixel-step, a speech model per thousand
/// characters and per second of audio.
fn model_cards() -> Vec<tenzro_types::price_card::PriceCard> {
    use tenzro_types::price_card::{Denom, PriceCard, Rate, RateCard};
    let card = |model: &str, denom, lines: &[(&str, u128, u8)]| PriceCard {
        model_id: model.into(),
        model_hash: "ab".repeat(32),
        rates: RateCard {
            denom,
            lines: lines
                .iter()
                .map(|(k, p, e)| (k.to_string(), Rate::per(*p, *e)))
                .collect(),
            min_charge: 0,
        },
    };
    vec![
        card(
            "qwen3-0.6b",
            Denom::NanoUsd,
            &[
                ("input_tokens", 50_000_000, 6),
                ("output_tokens", 200_000_000, 6),
            ],
        ),
        card(
            "embeddinggemma-300m",
            Denom::NanoUsd,
            &[("input_tokens", 20_000_000, 6)],
        ),
        card("flux2-klein-4b", Denom::Wei, &[("pixel_steps", 2_000, 0)]),
        card(
            "kokoro-82m",
            Denom::NanoUsd,
            &[
                ("characters", 15_000_000, 3),
                ("audio_out_ms", 1_000_000, 3),
            ],
        ),
    ]
}

/// What each model streams, one meter per chunk.
fn model_chunks() -> Vec<Vec<Value>> {
    vec![
        std::iter::once(json!({ "input_tokens": 812 }))
            .chain((0..12).map(|_| json!({ "output_tokens": 16 })))
            .collect(),
        vec![
            json!({ "input_tokens": 4096 }),
            json!({ "input_tokens": 77 }),
        ],
        vec![
            json!({ "pixel_steps": 1024 * 1024 * 28 }),
            json!({ "pixel_steps": 768 * 768 * 4 }),
        ],
        (0..4)
            .map(|i| json!({ "characters": 120 + i, "audio_out_ms": 6_400, "ttft_ms": 90 }))
            .collect(),
    ]
}

/// Add `chunk` to the running meter `total`, both units objects.
fn add_units(total: &mut Value, chunk: &Value) {
    for (k, v) in chunk.as_object().expect("units object") {
        let sum = total[k].as_u64().unwrap_or(0) + v.as_u64().expect("whole quantity");
        total[k] = json!(sum);
    }
}

/// A provider publishes a card per model as a generic registry entry; an
/// agent finds each card through the node, prices a call to a language
/// model, an embedder, an image model and a speech model on it, streams
/// each, paying every chunk with a cumulative voucher bound to the receipts
/// it received, and the provider settles all four on chain in one claim at
/// exactly what the published cards price the metered units at.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn an_agent_streams_four_model_types_and_settles_at_the_published_cards() {
    use tenzro_types::payment_authorization::{EscrowClaim, receipt_chain_next};
    use tenzro_types::price_card::{CARD_KIND, PriceCard, card_entry_name};
    use tenzro_types::registry::owned_id;
    use tenzro_types::transaction::RegistryOp;
    let payer = payer_signer();
    let provider = TestHybridSigner::p256_only(0x41);
    let provider_addr = account_of(&provider);
    let payer_addr = account_of(&payer);
    let n = Node::validator().await;
    n.fund(&provider_addr, 100 * ONE_TNZO);
    // Four 50 TNZO channels, and the gas of opening them.
    n.fund(&payer_addr, 201 * ONE_TNZO);
    let chain_id = n.chain_id().await;

    // The provider publishes one card per model under its own account.
    for card in model_cards() {
        let (_, hash) = n
            .send(
                &provider,
                provider_addr,
                TransactionType::Registry {
                    op: RegistryOp::Put {
                        id: owned_id(&provider_addr, &card_entry_name(&card.model_id)),
                        kind: CARD_KIND.into(),
                        anchor: "0".repeat(64),
                        data: hex::encode(serde_json::to_vec(&card).unwrap()),
                    },
                },
            )
            .await;
        assert!(n.executed(&hash).await, "the card is published");
    }
    let usd_rate: u128 = n.ok("tenzro_getFeeRate", json!({})).await["rate_nano_usd"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("the TNZO/USD rate");

    let mut claims = Vec::new();
    let mut expected = Vec::new();
    for (card, chunks) in model_cards().into_iter().zip(model_chunks()) {
        // Discovery: the card the provider publishes for the model.
        let found = n
            .ok(
                "tenzro_getPriceCard",
                json!({ "provider": hex_address(&provider_addr), "model_id": card.model_id }),
            )
            .await;
        assert_eq!(found["standing"], json!(true));
        let published: PriceCard = serde_json::from_value(found["card"].clone()).unwrap();
        assert_eq!(published, card);

        // A channel to the provider for this model's calls.
        let (nonce, hash) = n
            .send(
                &payer,
                provider_addr,
                TransactionType::CreateEscrow {
                    payee: provider_addr,
                    amount: 50 * ONE_TNZO,
                    asset_id: tenzro_types::asset::AssetId::tnzo(),
                    usd_e6: 0,
                    expires_at: (chrono::Utc::now().timestamp_millis() + 3_600_000) as u64,
                    release_conditions: tenzro_types::settlement::ReleaseConditions::Timeout,
                    reference: None,
                },
            )
            .await;
        assert!(n.executed(&hash).await, "the escrow is created");
        let escrow_id = escrow_id_for(&payer_addr, nonce);

        // Stream: after each chunk the agent prices the meter so far on the
        // anchored card and signs the cumulative charge, bound to the
        // receipt chain it holds.
        let mut total = json!({});
        let mut head = [0u8; 32];
        let mut last = None;
        let mut owed = 0u128;
        for (i, chunk) in chunks.iter().enumerate() {
            add_units(&mut total, chunk);
            // The agent prices the meter on the card itself, as its
            // harness does; the chain never prices.
            let meter: tenzro_types::model::BillableUnits =
                serde_json::from_value(total.clone()).unwrap();
            let now = published
                .rates
                .charge_wei(
                    &meter,
                    |u| {
                        tenzro_types::meter::genesis_units()
                            .into_iter()
                            .find(|d| d.id == u)
                            .map(|d| d.billable)
                    },
                    usd_rate,
                )
                .unwrap();
            assert!(now >= owed, "a cumulative charge never falls");
            owed = now;
            use sha2::Digest as _;
            let receipt: [u8; 32] = sha2::Sha256::digest(format!("{}:{i}", card.model_id)).into();
            head = receipt_chain_next(&head, &receipt);
            let sig = payer
                .sign(
                    SignatureContext::EscrowVoucher,
                    &escrow_voucher_preimage(chain_id, &escrow_id, owed, &head),
                )
                .unwrap();
            last = Some(EscrowVoucher {
                binding: head,
                agent: None,
                escrow_id,
                cumulative_amount: owed,
                public_key: payer.public_key().p256.clone(),
                signature: sig,
                attribution: None,
            });
        }
        expected.push((escrow_id, owed));
        claims.push(EscrowClaim {
            voucher: last.unwrap(),
            amount: owed,
        });
    }

    // One claim settles all four on chain, at the metered cost.
    let (_, hash) = n
        .send(
            &provider,
            provider_addr,
            TransactionType::ClaimEscrow { claims },
        )
        .await;
    assert!(n.executed(&hash).await, "the claim executes");
    for (escrow_id, owed) in expected {
        let escrow = n
            .ok(
                "tenzro_getEscrow",
                json!({ "escrow_id": hex::encode(escrow_id) }),
            )
            .await;
        let claimed: u128 = match &escrow["claimed"] {
            Value::String(s) => s.parse().unwrap(),
            v => v.as_u64().expect("claimed amount") as u128,
        };
        assert_eq!(claimed, owed, "{escrow}");
        assert!(owed > 0);
    }
}

/// A delegated agent this node serves, and the node's key for it.
const AGENT: &str = "did:tenzro:agent:revoked-buyer";
const AGENT_MACHINE: &str = "did:tenzro:machine:serving";

impl Node {
    /// Write the approved terms an agent's controller leaves on chain:
    /// `AGENT` served by `AGENT_MACHINE` with `key` as its key for the agent.
    fn seed_agent_terms(&self, key: &p256::ecdsa::SigningKey) {
        use tenzro_types::agent_terms::{AgentTerms, RootKind, ServingNode, TermsScope};
        use tenzro_vm::traits::VmState as _;
        let point = key.verifying_key().to_sec1_point(false);
        let stored = tenzro_vm::native::StoredAgentTerms {
            terms: AgentTerms {
                controller_did: "did:tenzro:human:controller".into(),
                agent_name: "buyer".into(),
                delegation_scope: TermsScope::default(),
                capabilities: Vec::new(),
                serving_nodes: vec![ServingNode {
                    machine_did: AGENT_MACHINE.into(),
                    operator_did: "did:tenzro:human:operator".into(),
                    dpop_public_key: hex::encode(&point.as_bytes()[1..]),
                    ..Default::default()
                }],
                min_distinct_operators: 1,
                expires_at_ms: None,
                trifecta_exception: false,
                auto_approve: None,
                credentials: Vec::new(),
            },
            root: RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: 0,
            renewed_at_ms: None,
        };
        let mut state =
            tenzro_vm::StateAdapter::with_storage(self.node.storage().expect("storage").clone());
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::agent_terms::terms_key(AGENT).as_bytes(),
            serde_json::to_vec(&stored).expect("terms json"),
        );
        state.commit().expect("commit terms");
    }

    /// Write the record a finalized revocation of `AGENT` by its controller
    /// leaves on chain, dated `at_ms`.
    fn seed_revocation(&self, at_ms: i64) {
        use tenzro_vm::traits::VmState as _;
        let record = tenzro_vm::native::AgentQuarantine {
            controller_did: "did:tenzro:human:controller".into(),
            by: "controller".into(),
            reason_code: 0,
            evidence_hash: None,
            at_ms,
            revoked: true,
        };
        let mut state =
            tenzro_vm::StateAdapter::with_storage(self.node.storage().expect("storage").clone());
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::agent_audit::quarantine_key(AGENT).as_bytes(),
            serde_json::to_vec(&record).expect("revocation json"),
        );
        state.commit().expect("commit revocation");
    }
}

/// A cumulative voucher on the agent's `escrow_id`, signed by its serving
/// node's `key` and dated `as_of_ms`.
fn agent_voucher(
    key: &p256::ecdsa::SigningKey,
    chain_id: u64,
    escrow_id: &[u8; 32],
    cumulative: u128,
    as_of_ms: u64,
) -> EscrowVoucher {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_types::payment_authorization::{AgentVoucherSigner, agent_voucher_digest};
    let signer = AgentVoucherSigner {
        agent_did: AGENT.into(),
        machine_did: AGENT_MACHINE.into(),
        as_of_ms,
    };
    let sig: p256::ecdsa::Signature = key
        .sign_prehash(&agent_voucher_digest(
            chain_id, escrow_id, cumulative, &[0u8; 32], &signer,
        ))
        .expect("P-256 signature");
    EscrowVoucher {
        binding: [0u8; 32],
        escrow_id: *escrow_id,
        cumulative_amount: cumulative,
        public_key: Vec::new(),
        signature: tenzro_crypto::composite::CompositeSignature::classical(
            tenzro_crypto::composite::ClassicalProof::Raw {
                signature: sig.to_bytes().to_vec(),
            },
        ),
        agent: Some(signer),
        attribution: None,
    }
}

/// An agent revoked in the middle of a paid session stops paying at once:
/// its serving node's voucher was accepted over RPC before the revocation,
/// and the next one, signed after it, is refused over RPC on the same open
/// channel.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_voucher_after_the_agents_revocation_is_refused_over_rpc() {
    let _payer = payer_signer();
    let n = Node::follower().await;
    let chain_id = n.chain_id().await;
    let key = p256::ecdsa::SigningKey::from_slice(&[0x47; 32]).expect("P-256 scalar");
    n.seed_agent_terms(&key);
    let wallet = Address::new(tenzro_types::agent_terms::agent_wallet(AGENT));
    let escrow_id = n.seed_escrow(&wallet, 0, &n.payee().await, AMOUNT);
    n.ok(
        "tenzro_openPaymentChannel",
        json!({ "channel_id": hex::encode(escrow_id) }),
    )
    .await;

    let now = || chrono::Utc::now().timestamp_millis();
    let first = agent_voucher(&key, chain_id, &escrow_id, AMOUNT / 5, now() as u64);
    let paid = n
        .ok(
            "tenzro_updatePaymentChannel",
            update_params(&first, AMOUNT / 5),
        )
        .await;
    assert_eq!(paid["session"]["spent"], json!(AMOUNT / 5));

    n.seed_revocation(now());
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let next = agent_voucher(&key, chain_id, &escrow_id, AMOUNT * 2 / 5, now() as u64);
    let msg = n
        .refused(
            "tenzro_updatePaymentChannel",
            update_params(&next, AMOUNT / 5),
        )
        .await;
    assert!(
        msg.contains(&format!("signed after {AGENT} was revoked")),
        "{msg}"
    );
}

/// An agent's evidence pack exported over RPC verifies offline with the same
/// check `tenzro agent audit evidence verify` runs, from the chain's genesis
/// anchor alone; a pack naming another state, or an anchor of another chain,
/// is refused.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn an_exported_evidence_pack_verifies_from_the_genesis_anchor_alone() {
    use tenzro_consensus::evidence_pack::verify_pack;
    use tenzro_consensus::light_client::GenesisAnchor;
    use tenzro_storage::BlockStore;
    let _payer = payer_signer();
    let n = Node::follower().await;
    n.certify_first_checkpoint().await;

    let exported = n
        .ok("tenzro_exportEvidencePack", json!({ "agent_did": AGENT }))
        .await;
    let pack: tenzro_types::evidence_pack::EvidencePack =
        serde_json::from_value(exported).expect("an evidence pack");
    assert_eq!(pack.subject, AGENT);
    assert_eq!(pack.agents, vec![AGENT.to_string()]);

    let genesis_block = tenzro_storage::block_store::BlockStoreImpl::new(
        n.node.storage().expect("storage").clone(),
    )
    .expect("block store")
    .get_block_by_height(tenzro_types::BlockHeight(0))
    .await
    .expect("block read")
    .expect("the genesis block");
    let anchor = GenesisAnchor {
        chain_id: n.chain_id().await,
        genesis_hash: genesis_block.hash().0,
        committee_root: n
            .node
            .consensus()
            .expect("consensus")
            .committee(0)
            .expect("the genesis committee")
            .root(),
    };

    let report = verify_pack(&pack, &anchor).expect("the pack verifies");
    assert_eq!(report.checkpoint, 0);
    assert_eq!(report.entries, 0);

    let mut other_state = pack.clone();
    other_state.state_root = hex::encode([0x5a; 32]);
    assert!(verify_pack(&other_state, &anchor).is_err());

    let mut stripped = pack.clone();
    stripped.manifest.clear();
    assert!(
        stripped.manifest != pack.manifest && verify_pack(&stripped, &anchor).is_err(),
        "a pack whose manifest does not match its sections"
    );

    let other_chain = GenesisAnchor {
        genesis_hash: [0x11; 32],
        ..anchor
    };
    assert!(verify_pack(&pack, &other_chain).is_err());
}

#[tokio::test]
#[ignore = "needs this machine\x27s hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_quote_prices_each_accepted_asset_with_its_fee_or_names_why_it_cannot() {
    let _payer = payer_signer();
    let n = Node::follower().await;
    let unknown = format!("0x{}", hex::encode([0x6b; 32]));
    let q = n
        .ok(
            "tenzro_quotePayment",
            json!({ "price": { "amount": "1", "unit": "USD" }, "accept": ["TNZO", unknown] }),
        )
        .await;
    assert_eq!(q["usd_e6"], 1_000_000);
    assert_eq!(q["unit"]["basket"], "USD");
    let tnzo = &q["assets"][0];
    assert_eq!(tnzo["asset"], "TNZO");
    let dec = |v: &Value| v.as_str().and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
    assert!(dec(&tnzo["amount"]) > 0 && dec(&tnzo["fee"]) > 0, "{q}");
    assert_eq!(tnzo["fee_asset"], "TNZO");
    assert_eq!(q["assets"][1]["error"]["code"], "asset_unpermitted", "{q}");
    // TNZO alone when no asset is named; a price is given one way.
    let plain = n
        .ok("tenzro_quotePayment", json!({ "usd_e6": 250_000 }))
        .await;
    assert_eq!(plain["assets"].as_array().unwrap().len(), 1);
    let msg = n
        .refused(
            "tenzro_quotePayment",
            json!({ "usd_e6": 1, "price": { "amount": "1", "unit": "USD" } }),
        )
        .await;
    assert!(msg.contains("not both"), "{msg}");
    let msg = n
        .refused(
            "tenzro_quotePayment",
            json!({ "price": { "amount": "0.0000001", "unit": "USD" } }),
        )
        .await;
    assert!(msg.contains("six places"), "{msg}");
    let msg = n
        .refused(
            "tenzro_quotePayment",
            json!({ "price": { "amount": "1", "unit": "EUR" } }),
        )
        .await;
    assert!(msg.contains("price.unit must be USD"), "{msg}");
    // Through a reseller, the operator price and the commission are shown
    // apart, and the whole amount carries both.
    let resold = n
        .ok(
            "tenzro_quotePayment",
            json!({
                "usd_e6": 1_000_000,
                "resellers": [{ "reseller": vec![0x33u8; 32], "commission_bps": 1_000 }],
            }),
        )
        .await;
    let r = &resold["assets"][0];
    assert_eq!(r["operator_amount"], tnzo["amount"], "{resold}");
    assert_eq!(r["legs"][0]["commission_bps"], 1_000);
    assert_eq!(r["legs"][0]["reseller"], hex::encode([0x33u8; 32]));
    assert!(dec(&r["amount"]) >= dec(&r["operator_amount"]) + dec(&r["legs"][0]["amount"]));
    // An exact lookup of a payment never made is null.
    let none = n
        .ok(
            "tenzro_getPayment",
            json!({ "payment_id": "never", "exact": true }),
        )
        .await;
    assert!(none.is_null());
}

/// The registry's smallest native text-to-image model.
const IMAGE_MODEL: &str = "janus-pro-1b";

/// A catalog publisher, bonded at genesis, that publishes registry entries.
struct Publisher(tenzro_crypto::p256::P256Signer);

impl Publisher {
    fn new() -> Self {
        Publisher(tenzro_crypto::p256::P256Signer::from_keypair(
            &tenzro_crypto::p256::P256KeyPair::from_secret_bytes(&[0x44; 32]).unwrap(),
        ))
    }
    fn did(&self) -> String {
        tenzro_trust::proof::machine_did(&self.0.public_key_sec1())
    }
    fn account(&self) -> [u8; 32] {
        tenzro_crypto::composite::account_slot(&self.0.public_key_sec1()[1..])
    }
    /// The signed catalog record publishing `entry`.
    fn publish(&self, entry: &tenzro_catalog::CatalogEntry) -> Value {
        use tenzro_trust::proof::{ProofRequest, attach_hardware, options, signing_digest};
        let doc = tenzro_trust::catalog::CatalogRecord::unsigned(
            &self.did(),
            entry.id(),
            1,
            Some(&serde_json::to_value(entry).unwrap()),
        );
        let opts = options(&ProofRequest {
            signer_did: self.did(),
            public_key_sec1: self.0.public_key_sec1(),
            purpose: "assertionMethod".into(),
            created: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            rp_id: None,
        });
        let digest = signing_digest(&doc, &opts);
        let sig: [u8; 64] = self.0.sign_prehash(&digest).as_bytes().try_into().unwrap();
        attach_hardware(doc, opts, &sig)
    }
}

impl Node {
    /// [`Node::validator`] that also serves models, keeping them in
    /// `models_dir` and accepting `licences` the operator agreed to.
    async fn validator_serving(
        models_dir: std::path::PathBuf,
        licences: &[&str],
        publisher: &Publisher,
    ) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let validator =
            tenzro_node::config::GenesisValidator::from_local_hardware(tmp.path(), 1_000_000)
                .expect("a hardware consensus key");
        let mut roles = tenzro_types::RoleSet::validator_only();
        roles.insert(tenzro_types::network::NetworkRole::ModelProvider);
        let address = validator.address.clone();
        let mut g = genesis(validator);
        // The model-serving role is bonded at genesis by the node's account.
        g.role_stakes.push(
            serde_json::from_value(json!({ "address": address, "role": "ai" }))
                .expect("a role stake"),
        );
        g.role_stakes.push(
            serde_json::from_value(
                json!({ "address": hex::encode(publisher.account()), "role": "catalog" }),
            )
            .expect("a role stake"),
        );
        let mut config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            roles,
            consensus: Some(tenzro_consensus::ConsensusConfig::default()),
            iroh: loopback_iroh(),
            genesis: Some(g),
            models_dir: Some(models_dir),
            catalog_publishers: vec![publisher.did()],
            ..Default::default()
        };
        config.model_licensing.accepted_license_ids =
            licences.iter().map(|l| l.to_string()).collect();
        let n = Self::start(config, tmp).await;
        let ledger = account_of(n.node.identity_signer().expect("node signer").as_ref());
        n.fund(&ledger, ONE_TNZO);
        n
    }
}

/// The registry's smallest native text-to-video model.
const VIDEO_MODEL: &str = "cosmos3-edge";

/// A validator serving `model` from `TENZRO_MEDIA_MODELS_DIR`, learnt from the
/// registry entry as it ships, priced at `rate` wei per pixel-step and
/// loaded, with a payer holding an open channel to it.
struct PaidMediaSession {
    n: Node,
    payer: TestHybridSigner,
    escrow_id: [u8; 32],
    chain_id: u64,
}

impl PaidMediaSession {
    async fn open(model: &str, licences: &[&str], rate: u128) -> Self {
        let models = std::path::PathBuf::from(
            std::env::var("TENZRO_MEDIA_MODELS_DIR").expect("TENZRO_MEDIA_MODELS_DIR"),
        );
        let payer = payer_signer();
        let publisher = Publisher::new();
        let n = Node::validator_serving(models, licences, &publisher).await;
        // The registry entry as it ships, published by the node's catalog
        // publisher: the path every node learns a model by.
        tenzro_catalog::install_test_seed();
        let entry = tenzro_catalog::entry(model).expect("the registry lists it");
        n.ok(
            "tenzro_submitTrustRecord",
            json!({ "record": publisher.publish(&entry) }),
        )
        .await;
        let served = n
            .ok("tenzro_getCatalogEntry", json!({ "model": model }))
            .await;
        assert_eq!(served["served"], json!(true), "{served}");
        n.fund(&account_of(&payer), AMOUNT + ONE_TNZO);
        let chain_id = n.chain_id().await;
        let payee = n.payee().await;

        // The node prices pixel-steps for the model and loads it.
        n.as_operator(
            "tenzro_setProviderPricing",
            json!({ "default": { "denom": "wei", "lines": {}, "min_charge": 0 },
                    "models": { model: { "denom": "wei",
                        "lines": { "pixel_steps": { "price": rate.to_string(), "per_exp": 0 } },
                        "min_charge": 0 } } }),
        )
        .await;
        n.as_operator("tenzro_loadMediaModel", json!({ "model_id": model }))
            .await;

        // The payer funds an escrow naming the node's payee and opens a channel.
        // A render on this machine's CPU takes most of an hour, and the node
        // refuses to claim against an escrow that is about to expire, so the
        // escrow outlives the work by hours.
        let expires_at = (chrono::Utc::now().timestamp_millis() + 8 * 3_600_000) as u64;
        let (nonce, tx) = n
            .send(
                &payer,
                payee,
                TransactionType::CreateEscrow {
                    usd_e6: 0,
                    payee,
                    amount: AMOUNT,
                    asset_id: tenzro_types::asset::AssetId::tnzo(),
                    expires_at,
                    release_conditions: tenzro_types::settlement::ReleaseConditions::Timeout,
                    reference: None,
                },
            )
            .await;
        assert!(n.executed(&tx).await, "escrow funded");
        let escrow_id = escrow_id_for(&account_of(&payer), nonce);
        n.ok(
            "tenzro_openPaymentChannel",
            json!({ "channel_id": hex::encode(escrow_id) }),
        )
        .await;
        Self {
            n,
            payer,
            escrow_id,
            chain_id,
        }
    }

    /// A voucher for `cost` on the open channel.
    fn voucher(&self, cost: u128) -> EscrowVoucher {
        voucher(&self.payer, self.chain_id, &self.escrow_id, cost)
    }

    /// The payer closes the channel; the node claims the voucher on chain.
    async fn close_and_claim(&self, cost: u128) {
        let mut status = String::new();
        for _ in 0..180 {
            let closed = self
                .n
                .ok(
                    "tenzro_closePaymentChannel",
                    close_params(&self.payer, &self.escrow_id),
                )
                .await;
            status = closed["status"].as_str().unwrap_or_default().to_string();
            if status == "closed" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        assert_eq!(status, "closed", "the voucher was claimed within 180s");
        // The payee also pays for the serving node's own transactions, so
        // the escrow's claimed amount, not its balance, is what was paid.
        let escrow = self
            .n
            .ok(
                "tenzro_getEscrow",
                json!({ "escrow_id": hex::encode(self.escrow_id) }),
            )
            .await;
        let claimed: u128 = match &escrow["claimed"] {
            Value::String(s) => s.parse().unwrap(),
            v => v.as_u64().expect("claimed amount") as u128,
        };
        assert_eq!(claimed, cost, "{escrow}");
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Digest::finalize(
        <sha2::Sha256 as sha2::Digest>::new_with_prefix(bytes),
    ))
}

/// The receipt fields every paid media answer carries.
fn assert_paid_receipt(t: &Value, output: &[u8], cost: u128) {
    assert_eq!(
        t["output_sha256"].as_str(),
        Some(sha256_hex(output).as_str()),
        "the receipt commits to these bytes"
    );
    assert!(t["receipt"].is_object(), "a signed receipt: {t}");
    assert_eq!(t["cost_wei"], cost.to_string());
    assert!(
        t["settlement"]
            .to_string()
            .to_lowercase()
            .contains("channel"),
        "{t}"
    );
}

/// An OpenAI image request renders on the node's own copy of a registry
/// model, answers with the image and the signed receipt, and is paid on the
/// caller's channel, which the node then claims on chain.
///
/// Run with `TENZRO_MEDIA_MODELS_DIR=<dir>`: the model is fetched into it
/// through `tenzro_loadMediaModel`, the registry path, on first use.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key and fetches janus-pro-1b through the registry"]
async fn an_image_request_returns_an_image_and_a_receipt_and_settles() {
    use base64::Engine as _;
    let rate: u128 = 2_000;
    let s = PaidMediaSession::open(IMAGE_MODEL, &["deepseek-model"], rate).await;
    let n = &s.n;

    // One 384x384 image is 576 image tokens, one per step.
    let cost = 384u128 * 384 * 576 * rate;
    let caller = operator().sign_in(&n.http, &n.url).await;
    let route = format!("{}/v1/images/generations", n.url);
    let resp = caller
        .authorize_route(n.http.post(&route), &route)
        .json(&json!({
            "model": IMAGE_MODEL,
            "prompt": "a red lighthouse on a cliff",
            "seed": 7,
            "channel_voucher": s.voucher(cost),
        }))
        .timeout(std::time::Duration::from_secs(1800))
        .send()
        .await
        .expect("the image request");
    let status = resp.status();
    let receipt_header = resp.headers().get("x-tenzro-receipt").cloned();
    let body: Value = resp.json().await.expect("a JSON answer");
    assert!(status.is_success(), "{status} {body}");

    let image = base64::engine::general_purpose::STANDARD
        .decode(body["data"][0]["b64_json"].as_str().expect("b64_json"))
        .expect("base64 image");
    assert!(image.len() > 1000, "an image, {} bytes", image.len());
    assert_paid_receipt(&body["tenzro"], &image, cost);
    assert!(receipt_header.is_some());
    s.close_and_claim(cost).await;
}

/// An OpenAI video request renders a clip on the node's own copy of a
/// registry model, answers with the video object and the signed receipt,
/// serves the clip by its content hash, and is paid on the caller's channel,
/// which the node then claims on chain.
///
/// Run with `TENZRO_MEDIA_MODELS_DIR=<dir>`, as the image test.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key and fetches cosmos3-edge through the registry"]
async fn a_video_request_returns_a_clip_and_a_receipt_and_settles() {
    let rate: u128 = 2_000;
    let s = PaidMediaSession::open(VIDEO_MODEL, &[], rate).await;
    let n = &s.n;

    let (width, height, frames, steps) = (832u128, 480u128, 17u128, 20u128);
    let cost = width * height * frames * steps * rate;
    let caller = operator().sign_in(&n.http, &n.url).await;
    let route = format!("{}/v1/videos", n.url);
    let resp = caller
        .authorize_route(n.http.post(&route), &route)
        .json(&json!({
            "model": VIDEO_MODEL,
            "prompt": "waves rolling onto a pebble beach at dusk",
            "size": format!("{width}x{height}"),
            "num_frames": frames,
            "steps": steps,
            "seed": 7,
            "channel_voucher": s.voucher(cost),
        }))
        .timeout(std::time::Duration::from_secs(3600))
        .send()
        .await
        .expect("the video request");
    let status = resp.status();
    let receipt_header = resp.headers().get("x-tenzro-receipt").cloned();
    let body: Value = resp.json().await.expect("a JSON answer");
    assert!(status.is_success(), "{status} {body}");
    assert_eq!(body["object"], "video", "{body}");
    assert_eq!(body["status"], "completed", "{body}");
    assert_eq!(body["size"], format!("{width}x{height}"));

    // The clip is served by the content hash the answer names.
    let id = body["id"].as_str().expect("a video id");
    let content = format!("{}/v1/videos/{id}/content", n.url);
    // The render outlasts the bearer's 15-minute life, so the caller signs
    // in again, as a client does when its token has expired.
    let caller = operator().sign_in(&n.http, &n.url).await;
    let clip = caller
        .authorize_method(n.http.get(&content), "GET", &content)
        .send()
        .await
        .expect("the content request");
    assert!(clip.status().is_success(), "{}", clip.status());
    let clip = clip.bytes().await.expect("the clip").to_vec();
    assert!(clip.len() > 1000, "a clip, {} bytes", clip.len());
    assert_paid_receipt(&body["tenzro"], &clip, cost);
    assert!(receipt_header.is_some());
    s.close_and_claim(cost).await;
}
