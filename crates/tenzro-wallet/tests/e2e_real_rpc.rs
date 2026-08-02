//! Full-stack test: a spawned `tenzro-node` binary plus the wallet kernel,
//! driven against the live JSON-RPC surface.
//!
//! This test is feature-gated on `e2e` because it spawns the actual
//! `tenzro-node` binary, binds ephemeral local ports, waits for the RPC
//! surface to become healthy, and exercises the wallet's
//! [`TenzroRpcChainProvider`] against it.
//!
//! Run with:
//!
//! ```bash
//! cargo build -p tenzro-node
//! cargo test -p tenzro-wallet --features e2e --test e2e_real_rpc -- --nocapture
//! ```
//!
//! # What this test verifies
//!
//! 1. `eth_blockNumber` returns a quantity hex (block height accessor works).
//! 2. `eth_getBalance` returns `0x0` for an arbitrary unfunded address.
//! 3. `eth_getTransactionCount` returns `0x0` for an unfunded address (nonce
//!    accessor works through the wallet's ChainStateProvider).
//! 4. The wallet kernel's `WalletStateSync::sync_address` round-trip succeeds
//!    against the real node.
//!
//! Funded-transfer round-trips are intentionally out of scope here — they
//! require a faucet credit + finalized block, which is a separate harness
//! (the multi-validator soak test in #173).

#![cfg(feature = "e2e")]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tenzro_types::AssetId;
use tenzro_types::primitives::{Address, Signature};
use tenzro_wallet::balance::BalanceTracker;
use tenzro_wallet::builder::TransactionBuilder;
use tenzro_wallet::history::TransactionHistory;
use tenzro_wallet::nonce::NonceManager;
use tenzro_wallet::rpc_provider::TenzroRpcChainProvider;
use tenzro_wallet::service::{TenzroWalletService, WalletServiceConfig};
use tenzro_wallet::state_sync::{ChainStateProvider, WalletStateSync};
use tenzro_wallet::traits::WalletService;
use tokio::process::{Child, Command};

/// RAII guard around a spawned `tenzro-node` process.
///
/// On drop, sends SIGTERM (via `kill_on_drop`) and waits for the process
/// to exit. The Rust standard library's `tokio::process::Command` with
/// `kill_on_drop(true)` issues SIGKILL immediately; we want to allow a
/// graceful shutdown window first, so we send SIGTERM via an explicit kill
/// in `Drop` and rely on the kernel to reap the zombie.
struct TenzroNode {
    child: Option<Child>,
    rpc_url: String,
    _data_dir: TempDir, // hold the dir alive for the duration of the node
}

impl TenzroNode {
    /// Spawn a node on ephemeral ports, wait for RPC to come up, return the
    /// guard. Returns an error string (rather than `Result<>`) so callers
    /// can `panic!` with a clear diagnostic at the test entry point.
    async fn spawn() -> Result<Self, String> {
        // `CARGO_BIN_EXE_tenzro-node` would normally be set if this test crate
        // dev-dep'd `tenzro-node`, but that would create a cycle (tenzro-node
        // already depends on tenzro-wallet). Fall back to locating the binary
        // in the workspace target directory, which the CI invocation builds
        // first via `cargo build -p tenzro-node`.
        let bin_path = std::env::var("CARGO_BIN_EXE_tenzro-node").unwrap_or_else(|_| {
            // CARGO_MANIFEST_DIR is always set during test compilation. Walk
            // up from `crates/tenzro-wallet/` to the workspace root, then
            // into `target/{debug,release}/tenzro-node`.
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let workspace = manifest
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| manifest.clone());
            let debug = workspace.join("target/debug/tenzro-node");
            let release = workspace.join("target/release/tenzro-node");
            if debug.exists() {
                debug.to_string_lossy().into_owned()
            } else if release.exists() {
                release.to_string_lossy().into_owned()
            } else {
                // Caller will get a useful error from spawn() with this path.
                debug.to_string_lossy().into_owned()
            }
        });

        let data_dir = TempDir::new().map_err(|e| format!("tempdir: {}", e))?;

        // Allocate four ephemeral ports for {rpc, web, mcp, a2a, solana, ...}
        // by binding 0 then immediately releasing — the kernel guarantees a
        // small window of port-uniqueness even after close. We open 9 ports
        // because tenzro-node spins up RPC + web + 7 MCP ports.
        let ports: Vec<u16> = (0..9)
            .map(|_| {
                TcpListener::bind("127.0.0.1:0")
                    .map(|l| l.local_addr().unwrap().port())
                    .map_err(|e| format!("bind ephemeral: {}", e))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let rpc_port = ports[0];
        let web_port = ports[1];
        let mcp_port = ports[2];
        let a2a_port = ports[3];
        let solana_mcp_port = ports[4];
        let ethereum_mcp_port = ports[5];
        let canton_mcp_port = ports[6];
        let layerzero_mcp_port = ports[7];
        let chainlink_mcp_port = ports[8];

        let rpc_url = format!("http://127.0.0.1:{}", rpc_port);

        let child = Command::new(bin_path)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--roles")
            .arg("validator")
            .arg("--listen-addr")
            .arg("/ip4/127.0.0.1/tcp/0")
            .arg("--rpc-addr")
            .arg(format!("127.0.0.1:{}", rpc_port))
            .arg("--web-addr")
            .arg(format!("127.0.0.1:{}", web_port))
            .arg("--mcp-addr")
            .arg(format!("127.0.0.1:{}", mcp_port))
            .arg("--a2a-addr")
            .arg(format!("127.0.0.1:{}", a2a_port))
            .arg("--solana-mcp-addr")
            .arg(format!("127.0.0.1:{}", solana_mcp_port))
            .arg("--ethereum-mcp-addr")
            .arg(format!("127.0.0.1:{}", ethereum_mcp_port))
            .arg("--canton-mcp-addr")
            .arg(format!("127.0.0.1:{}", canton_mcp_port))
            .arg("--layerzero-mcp-addr")
            .arg(format!("127.0.0.1:{}", layerzero_mcp_port))
            .arg("--chainlink-mcp-addr")
            .arg(format!("127.0.0.1:{}", chainlink_mcp_port))
            .arg("--log-level")
            .arg("warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("spawn tenzro-node: {}", e))?;

        let node = TenzroNode {
            child: Some(child),
            rpc_url: rpc_url.clone(),
            _data_dir: data_dir,
        };

        // Poll RPC until eth_blockNumber returns successfully (or timeout).
        // The node has heavy startup (RocksDB open, libp2p init, web/MCP/A2A
        // axum services) — give it up to 60 seconds.
        node.wait_for_rpc(Duration::from_secs(60))
            .await
            .map_err(|e| format!("RPC never became ready: {}", e))?;

        Ok(node)
    }

    async fn wait_for_rpc(&self, timeout: Duration) -> Result<(), String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| format!("HTTP client: {}", e))?;

        let deadline = Instant::now() + timeout;
        let mut last_err = String::from("never attempted");
        while Instant::now() < deadline {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1,
            });
            match client.post(&self.rpc_url).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(v) = resp.json::<serde_json::Value>().await {
                        if v.get("result").is_some() {
                            return Ok(());
                        }
                        last_err = format!("rpc replied without result: {}", v);
                    } else {
                        last_err = "rpc replied with non-JSON body".to_string();
                    }
                }
                Ok(resp) => {
                    last_err = format!("rpc HTTP {}", resp.status());
                }
                Err(e) => {
                    last_err = format!("rpc connect: {}", e);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(last_err)
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

impl Drop for TenzroNode {
    fn drop(&mut self) {
        // Best-effort SIGTERM, then rely on `kill_on_drop` for SIGKILL backup.
        // `tokio::process::Child::start_kill()` issues SIGKILL on Unix — there
        // is no built-in SIGTERM in tokio. We send SIGTERM directly via libc
        // when available, and fall back to start_kill on other platforms.
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                if let Some(pid) = child.id() {
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGTERM);
                    }
                    // Give it 2 seconds to clean up before kill_on_drop fires.
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
            // start_kill returns immediately after sending SIGKILL; we're in
            // sync drop so we cannot await — kill_on_drop handles cleanup.
            let _ = child.start_kill();
        }
    }
}

#[tokio::test]
async fn e2e_block_number_via_rpc() {
    let node = TenzroNode::spawn().await.expect("node spawn");

    let provider = TenzroRpcChainProvider::new(node.rpc_url()).expect("rpc provider");
    let height = provider.get_block_height().await.expect("block height");
    // A freshly-genesis'd node may report 0; any height in range is fine.
    assert!(height < 1_000_000, "implausible block height {}", height);
}

#[tokio::test]
async fn e2e_unfunded_address_balance_and_nonce() {
    let node = TenzroNode::spawn().await.expect("node spawn");

    let provider = TenzroRpcChainProvider::new(node.rpc_url()).expect("rpc provider");

    // An arbitrary 32-byte address that is unlikely to ever be funded.
    let addr = Address::new([0xab; 32]);
    let asset = AssetId::tnzo();

    let bal = provider
        .get_on_chain_balance(&addr, &asset)
        .await
        .expect("balance");
    assert_eq!(bal, 0, "unfunded address should have zero balance");

    let nonce = provider.get_on_chain_nonce(&addr).await.expect("nonce");
    assert_eq!(nonce, 0, "unfunded address should have zero nonce");
}

#[tokio::test]
async fn e2e_wallet_state_sync_round_trip() {
    let node = TenzroNode::spawn().await.expect("node spawn");

    let provider: Arc<dyn ChainStateProvider> =
        Arc::new(TenzroRpcChainProvider::new(node.rpc_url()).expect("rpc provider"));

    let balances = Arc::new(BalanceTracker::new());
    let nonces = Arc::new(NonceManager::new());
    let history = Arc::new(TransactionHistory::new());

    let sync = WalletStateSync::new(balances.clone(), nonces.clone(), history.clone())
        .with_chain_provider(provider);

    assert!(sync.is_connected());

    let addr = Address::new([0xcd; 32]);
    let asset = AssetId::tnzo();

    // Round-trip a sync against the real node.
    sync.sync_address(&addr, &[asset.clone()])
        .await
        .expect("sync_address");

    // After sync, the balance tracker should reflect on-chain (zero).
    let cached = balances.get_balance(&addr, &asset);
    assert_eq!(cached.available, 0);
}

/// Provision a real wallet, build a transfer transaction, sign with hybrid
/// (Ed25519 + ML-DSA-65), submit via `submit_signed_transaction` against the
/// live `tenzro-node`, and assert the wire format is accepted past parsing
/// and signature verification.
///
/// The wallet is unfunded so the node will reject the transaction at
/// admission (insufficient balance) — but that's a *post*-signature error
/// at the mempool layer. What this test actually verifies:
///
///   1. Every required field (`from`, `to`, `value`, `nonce`, `chain_id`,
///      `timestamp`, `tx_type`, `signature`, `public_key`, `pq_signature`,
///      `pq_public_key`) is present and well-formed at the wire.
///   2. The classical Ed25519 signature verifies against `Transaction::hash()`
///      server-side. Mismatch returns -32003 with "Classical Ed25519
///      signature verification failed" — this test asserts the failure
///      message does NOT contain that string.
///   3. The ML-DSA-65 signature verifies against `Transaction::hash()`
///      server-side. Mismatch returns -32003 with "ML-DSA-65 signature
///      verification failed" — this test asserts the failure message does
///      NOT contain that string.
///
/// A funded transfer round-trip (where the tx actually finalizes) requires
/// a faucet credit + block production and lives in the multi-validator soak
/// test in #173.
#[tokio::test]
async fn e2e_signed_transaction_wire_format() {
    let node = TenzroNode::spawn().await.expect("node spawn");

    // Provision a real wallet with hybrid PQ keys.
    let wallet_dir = TempDir::new().expect("wallet tempdir");
    let cfg = WalletServiceConfig::new(wallet_dir.path().to_path_buf());
    let wallet_service = TenzroWalletService::with_config(cfg).expect("wallet service");
    let wallet = wallet_service.provision_wallet().await.expect("provision");

    // Build a transfer transaction from the wallet to an arbitrary address.
    // Nonce = 0 because the wallet is fresh; chain_id falls back to 1337
    // (TransactionBuilder::default_chain).
    let nonce = wallet_service.next_nonce(&wallet.address);
    let tx = TransactionBuilder::default_chain()
        .from_wallet_pq(&wallet)
        .to(Address::new([0xbb; 32]))
        .nonce(nonce)
        .transfer(1)
        .build_validated()
        .expect("build tx");

    // Hybrid sign: Ed25519 over Transaction::hash() + ML-DSA-65 over the
    // same preimage. Both legs must verify or the node returns -32003.
    let hybrid_sig = wallet_service
        .sign_transaction(&wallet.wallet_id, &tx)
        .await
        .expect("sign tx");
    assert_eq!(hybrid_sig.classical.len(), 64, "Ed25519 sig is 64 bytes");
    assert_eq!(hybrid_sig.pq.len(), 3309, "ML-DSA-65 sig is 3309 bytes");

    // The classical leg's `public_key` must be the wallet's Ed25519 public
    // key — that's what the node will use to verify against
    // `Transaction::hash()`.
    let classical_sig = Signature::new(
        hybrid_sig.classical.clone(),
        wallet.public_key.as_bytes().to_vec(),
    );

    // Submit via the structured trait method.
    let provider = TenzroRpcChainProvider::new(node.rpc_url()).expect("rpc provider");
    let result = ChainStateProvider::submit_signed_transaction(
        &provider,
        &tx,
        &classical_sig,
        &hybrid_sig.pq,
    )
    .await;

    match result {
        Ok(tx_hash) => {
            // Best case: the node admitted the tx (some testnet configs
            // pre-fund every address or skip balance checks at admission).
            // Just sanity-check the hash is non-zero.
            assert_ne!(
                tx_hash.as_bytes(),
                &[0u8; 32],
                "admitted tx should have non-zero hash"
            );
        }
        Err(e) => {
            // Expected case: tx rejected for insufficient balance / unfunded
            // sender. The wire format and signatures must NOT be the cause.
            let msg = e.to_string();
            assert!(
                !msg.contains("Classical Ed25519 signature verification failed"),
                "wire format produced an Ed25519 verification failure: {}",
                msg
            );
            assert!(
                !msg.contains("ML-DSA-65 signature verification failed"),
                "wire format produced an ML-DSA-65 verification failure: {}",
                msg
            );
            assert!(
                !msg.contains("Missing 'signature'")
                    && !msg.contains("Missing 'public_key'")
                    && !msg.contains("Missing 'pq_signature'")
                    && !msg.contains("Missing 'pq_public_key'")
                    && !msg.contains("Missing 'from'"),
                "wire format dropped a required field: {}",
                msg
            );
            assert!(
                !msg.contains("must be 64 bytes")
                    && !msg.contains("must be 32 bytes")
                    && !msg.contains("must be 3309 bytes")
                    && !msg.contains("must be 1952 bytes"),
                "wire format produced a length error: {}",
                msg
            );
        }
    }
}
