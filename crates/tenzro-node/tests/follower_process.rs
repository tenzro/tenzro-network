//! A follower node, one the genesis does not name, starts and stops within its
//! drain time when its process is asked to end.
//!
//! The genesis names a validator whose keys exist only in this test, so the
//! node follows and holds no validator key. A node still needs its machine's
//! identity key, so the test needs a TPM 2.0 or Secure Enclave: it runs on the
//! Windows runner and, on Linux, under a TPM emulator with `--ignored`. It
//! covers what differs between Linux and Windows: the signal that ends the
//! process and the sockets it releases. The process is ended with SIGTERM on
//! Unix and with Ctrl+Break, sent to the node's own process group, on Windows.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tenzro_crypto::signatures::Ed25519SignerImpl;

/// The consensus key of a genesis validator that never runs: it signs only
/// its own registration, so the follower has a committee to verify against.
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

/// A one-validator genesis on chain 1337.
fn genesis_file(dir: &std::path::Path) -> PathBuf {
    let genesis = tenzro_node::config::GenesisConfig {
        protocol: None,
        consensus: Default::default(),
        validator_registry: Default::default(),
        version: tenzro_node::config::GENESIS_SCHEMA_VERSION,
        chain_id: 1337,
        timestamp: 0,
        validators: vec![CommitteeKey::new(0x11).entry()],
        accounts: Vec::new(),
        weak_subjectivity: None,
        time: tenzro_consensus::TimeRules::default(),
        network_params: Default::default(),
        economy: Default::default(),
        role_stakes: Vec::new(),
    };
    let path = dir.join("genesis.toml");
    std::fs::write(&path, toml::to_string(&genesis).expect("genesis as TOML")).unwrap();
    path
}

fn node_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tenzro-node"))
}

/// A port nothing listens on now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The node's log so far, for a failure message.
fn log_tail(log: &std::path::Path) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

/// Waits until `child` has exited or `limit` has passed; its exit status if it
/// exited.
fn wait_exit(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

/// Asks the node process to end the way a service manager or a terminal does.
fn ask_to_stop(child: &Child) {
    #[cfg(unix)]
    {
        // SAFETY: `kill` takes a process id and a signal number and touches no memory.
        let rc = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        assert_eq!(rc, 0, "SIGTERM was not delivered");
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
        // SAFETY: the event and a process group id (the child leads its own group).
        let ok = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) };
        assert_ne!(
            ok, 0,
            "Ctrl+Break was not delivered to the node's process group"
        );
    }
}

#[tokio::test]
#[cfg_attr(
    not(windows),
    ignore = "starts a node: needs this machine's hardware key (TPM 2.0); run under a TPM emulator with --ignored"
)]
async fn a_follower_that_is_not_in_the_genesis_starts_and_stops_within_its_drain_time() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = genesis_file(dir.path());
    // The default iroh port is fixed; a machine that already holds it would fail the bind.
    let config = dir.path().join("node.toml");
    std::fs::write(&config, "[iroh]\nbind_addr = \"127.0.0.1:0\"\n").unwrap();
    let log = dir.path().join("node.log");
    let rpc = format!("127.0.0.1:{}", free_port());
    let mut command = Command::new(node_binary());
    command
        .arg("--config")
        .arg(&config)
        .args(["--genesis"])
        .arg(&genesis)
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .args(["--roles", "full"])
        // A validator that is not running: the follower dials it and finds nothing.
        .args([
            "--boot-nodes",
            &format!("did:tenzro:machine:{}", "ab".repeat(32)),
        ])
        .args(["--rpc-addr", &rpc])
        .args(["--web-addr", &format!("127.0.0.1:{}", free_port())])
        .args(["--mcp-addr", &format!("127.0.0.1:{}", free_port())])
        .args(["--a2a-addr", &format!("127.0.0.1:{}", free_port())])
        .env("TENZRO_HOME", dir.path())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP: Ctrl+Break reaches this node and not the test.
        command.creation_flags(0x0000_0200);
    }
    let mut node = command.spawn().unwrap();

    // The node is up once its RPC answers.
    let url = format!("http://{rpc}");
    let http = reqwest::Client::new();
    let started = Instant::now();
    loop {
        if let Some(status) = node.try_wait().unwrap() {
            panic!(
                "the node exited before serving RPC ({status}):\n{}",
                log_tail(&log)
            );
        }
        let up = http
            .post(&url)
            .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        if up {
            break;
        }
        if started.elapsed() > Duration::from_secs(180) {
            let _ = node.kill();
            panic!(
                "the node did not serve RPC within 180 s:\n{}",
                log_tail(&log)
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    ask_to_stop(&node);

    // The node drains its servers for 5 s after the signal.
    let Some(status) = wait_exit(&mut node, Duration::from_secs(30)) else {
        let _ = node.kill();
        panic!(
            "the node was still running 30 s after the stop signal:\n{}",
            log_tail(&log)
        );
    };
    assert!(
        status.success(),
        "the node exited with {status}:\n{}",
        log_tail(&log)
    );
}
