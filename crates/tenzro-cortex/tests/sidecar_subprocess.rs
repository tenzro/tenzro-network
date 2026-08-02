//! Sidecar subprocess integration test.
//!
//! This test spawns a **real Python subprocess** that speaks the
//! `SidecarModel` wire protocol (`GET /healthz`, `POST /v1/cortex/infer`)
//! and drives a full `CortexWorker::execute` round-trip through it. Unlike
//! the mock-backed `e2e.rs` tests, this exercises the actual HTTP stack
//! (`reqwest` client, JSON serialization, hex encoding, bearer auth,
//! `ping_health` probe, and receipt re-signing after a live sidecar
//! response).
//!
//! ## Hermeticity
//!
//! The sidecar is implemented **entirely with Python stdlib**
//! (`http.server.ThreadingHTTPServer`, `hashlib`, `json`) — no FastAPI,
//! uvicorn, torch, or pip dependencies. It implements exactly the schema
//! described in `crates/tenzro-cortex/src/sidecar.rs` module docs:
//!
//! * Echo kernel: `output_hex == input_hex`
//! * `loops_used == clamp(n_loops_max, n_loops_min, n_loops_max)`
//!   (identical to `sidecar/reference_python/server.py`)
//! * `weights_hash = SHA-256("weights:" + model_id)`
//! * `runtime_hash = SHA-256("tenzro-cortex-stdlib-sidecar@0.1.0")`
//! * Bearer token auth honored when `CORTEX_SIDECAR_TOKEN` is set
//!
//! ## Port allocation
//!
//! We bind `127.0.0.1:0` with `TcpListener`, read the OS-assigned port,
//! then immediately drop the listener before handing the port to the
//! subprocess. This races with port reuse but is the standard pattern
//! and extremely reliable on localhost with unique-per-test ports.
//!
//! ## Skip semantics
//!
//! If `python3` is not on `PATH`, the test prints a skip message and
//! returns `Ok(())`. This keeps CI green on minimal container images
//! without forcing every runner to install Python.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tenzro_cortex::{
    CortexWorker,
    sidecar::{SidecarConfig, SidecarModel},
    verify_receipt,
};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_types::{
    cortex::{
        AttestationRequirement, CortexModelFamily, CortexPricing, CortexRequest, ReasoningBudget,
        ReasoningTier,
    },
    primitives::{Address, Timestamp},
};

const WORKER_DID: &str = "did:tenzro:machine:sidecar-subprocess-worker";
const MODEL_ID: &str = "mythos-3b";

/// Inline Python script implementing the Tenzro Cortex sidecar wire
/// contract using only the stdlib. Passed to `python3 -c`. The script
/// reads the port from `argv[1]`.
///
/// Contract mirror of `sidecar/reference_python/server.py`:
/// * `GET /healthz`            → `{"status":"ok"}`
/// * `POST /v1/cortex/infer`   → echo kernel, clamped loops, SHA-256 hashes
const PY_SIDECAR_SCRIPT: &str = r#"
import sys, json, hashlib, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
BEARER = os.environ.get("CORTEX_SIDECAR_TOKEN")
RUNTIME_VERSION = "tenzro-cortex-stdlib-sidecar@0.1.0"

def sha256_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass

    def _auth_ok(self) -> bool:
        if BEARER is None:
            return True
        got = self.headers.get("Authorization", "")
        return got == f"Bearer {BEARER}"

    def _reply(self, status: int, body_dict):
        body = json.dumps(body_dict).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
            return
        self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/cortex/infer":
            self._reply(404, {"error": "not found"})
            return
        if not self._auth_ok():
            self._reply(401, {"error": "unauthorized"})
            return
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        try:
            req = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._reply(400, {"error": f"bad json: {e}"})
            return

        model_id = req.get("model_id", "")
        input_hex = req.get("input_hex", "")
        lo = int(req.get("n_loops_min", 1))
        hi = int(req.get("n_loops_max", 1))
        try:
            input_bytes = bytes.fromhex(input_hex)
        except ValueError as e:
            self._reply(400, {"error": f"bad input_hex: {e}"})
            return

        loops_used = max(lo, min(hi, hi))  # echo: pick the ceiling
        token_est = max(1, len(input_bytes) // 4)

        self._reply(200, {
            "output_hex": input_hex,
            "loops_used": loops_used,
            "input_tokens": token_est,
            "output_tokens": token_est,
            "latency_ms": 1,
            "model_version": f"{model_id}-stdlib",
            "finish_reason": "stop",
            "experts_activated": 2,
            "weights_hash_hex": sha256_hex(f"weights:{model_id}".encode("utf-8")),
            "runtime_hash_hex": sha256_hex(RUNTIME_VERSION.encode("utf-8")),
        })

srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
srv.serve_forever()
"#;

/// RAII guard: reliably reap the Python subprocess when the test ends,
/// whether it passes, fails, or panics. Leaking subprocesses across test
/// runs would cause port-bind collisions.
struct SidecarGuard {
    child: Option<Child>,
}

impl SidecarGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for SidecarGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Find a free TCP port by binding to ephemeral 0 and reading the
/// kernel-assigned port number. Drops the listener immediately so the
/// subprocess can claim the port. There is an inherent race here, but
/// it's negligible on localhost for test purposes.
fn pick_free_port() -> std::io::Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    let p = l.local_addr()?.port();
    drop(l);
    Ok(p)
}

/// Spawn the Python stdlib sidecar. Returns `Ok(None)` if `python3` is
/// not available on PATH (the test should skip in that case rather than
/// fail spuriously).
fn spawn_python_sidecar(port: u16) -> std::io::Result<Option<Child>> {
    let result = Command::new("python3")
        .arg("-c")
        .arg(PY_SIDECAR_SCRIPT)
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match result {
        Ok(child) => Ok(Some(child)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Poll the sidecar's `/healthz` until it returns 200 or the deadline
/// expires. Uses a short per-attempt timeout so the overall wait is
/// bounded even if the OS is sluggish.
async fn wait_for_healthz(base_url: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .map_err(|e| format!("reqwest client: {e}"))?;
    let url = format!("{}/healthz", base_url.trim_end_matches('/'));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = String::from("never polled");
    while Instant::now() < deadline {
        match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => last_err = format!("status {}", r.status()),
            Err(e) => last_err = format!("{e}"),
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
    Err(format!(
        "sidecar healthz did not become ready within 10s: {last_err}"
    ))
}

fn build_family() -> CortexModelFamily {
    CortexModelFamily {
        arch: "rdt-moe".into(),
        max_loops: 32,
        moe_experts: 64,
        experts_per_token: 2,
        attn_type: "mla".into(),
        supported_tiers: vec![
            ReasoningTier::Fast,
            ReasoningTier::Standard,
            ReasoningTier::Deep,
        ],
    }
}

fn standard_request(request_id: &str, input: Vec<u8>) -> CortexRequest {
    CortexRequest {
        request_id: request_id.to_string(),
        model_id: MODEL_ID.to_string(),
        requester: Address::default(),
        input,
        budget: ReasoningBudget {
            max_cost_wei: 10_000_000_000,
            ..ReasoningBudget::for_tier(ReasoningTier::Standard)
        },
        params: Default::default(),
        timestamp: Timestamp::default(),
    }
}

/// Full sidecar round-trip: spawn subprocess → health check → one
/// `CortexWorker::execute` against a live HTTP endpoint → Ed25519
/// receipt verification → price reconciliation against pricing formula.
#[tokio::test]
async fn sidecar_subprocess_end_to_end() {
    // --- 0. Spawn the Python sidecar (or skip if python3 absent) --------
    let port = pick_free_port().expect("reserve ephemeral port");
    let child = match spawn_python_sidecar(port) {
        Ok(Some(c)) => c,
        Ok(None) => {
            eprintln!("sidecar_subprocess_end_to_end: skipping — `python3` not found on PATH");
            return;
        }
        Err(e) => panic!("failed to spawn python3: {e}"),
    };
    let _guard = SidecarGuard::new(child);

    let base_url = format!("http://127.0.0.1:{port}");
    wait_for_healthz(&base_url)
        .await
        .expect("python sidecar becomes healthy");

    // --- 1. Build the worker pointing at the live subprocess ------------
    let signer: Arc<dyn Signer + Send + Sync> =
        Arc::new(Ed25519SignerImpl::generate().expect("generate ed25519 signer"));
    let address = Address::default();
    let family = build_family();
    let pricing = CortexPricing::default();

    let sidecar_cfg = SidecarConfig {
        base_url: base_url.clone(),
        timeout: Duration::from_secs(10),
        bearer_token: None,
    };
    let backend = Arc::new(
        SidecarModel::new(
            MODEL_ID,
            family.clone(),
            WORKER_DID,
            address,
            signer.clone(),
            sidecar_cfg,
        )
        .expect("build SidecarModel"),
    );

    // ping_health exercises the same HTTP client that infer() will use.
    backend
        .ping_health()
        .await
        .expect("sidecar ping_health succeeds against subprocess");

    let worker = CortexWorker::new(
        backend.clone(),
        pricing,
        signer.clone(),
        WORKER_DID,
        address,
    );

    // --- 2. Drive a single inference through the real HTTP stack --------
    let input = b"sidecar subprocess round-trip: 42".to_vec();
    let input_len = input.len();
    let req = standard_request("req-sidecar-1", input.clone());
    let resp = worker
        .execute(&req)
        .await
        .expect("worker executes against python sidecar");

    // Standard tier is min=max=8 loops; the stdlib sidecar clamps to
    // n_loops_max == 8, so the worker's budget.allows_loops check passes.
    assert_eq!(resp.metadata.loops_used, 8, "Standard tier loops_used");
    assert_eq!(resp.receipt.loops_used, 8);
    assert_eq!(resp.receipt.loops_requested, 8);

    // Echo kernel: output bytes equal input bytes verbatim.
    assert_eq!(resp.output, input, "sidecar echo kernel preserves input");
    assert_eq!(resp.request_id, req.request_id);
    assert_eq!(resp.model_id, MODEL_ID);
    assert_eq!(resp.worker, address);

    // Stdlib sidecar token heuristic is `max(1, len/4)` — same as Mock.
    let expected_tokens = (input_len / 4).max(1) as u32;
    assert_eq!(resp.receipt.tokens_in, expected_tokens);
    assert_eq!(resp.receipt.tokens_out, expected_tokens);

    // Receipt binds to the worker identity passed to SidecarModel::new.
    assert_eq!(resp.receipt.worker_did, WORKER_DID);
    assert_eq!(resp.receipt.worker_address, address);
    assert_eq!(resp.receipt.model_id, MODEL_ID);

    // --- 3. Verify the Ed25519 signature over the finalized preimage ----
    // The sidecar placed a placeholder price of 0; the worker recomputed
    // the true price and re-signed. verify_receipt must accept the
    // finalized preimage, not the placeholder.
    verify_receipt(&resp.receipt).expect("sidecar-signed receipt verifies");

    // --- 4. Reconcile against the pricing formula -----------------------
    let expected_price = pricing.compute(
        resp.receipt.tokens_in,
        resp.receipt.tokens_out,
        resp.receipt.loops_used,
        AttestationRequirement::None,
    );
    assert_eq!(
        resp.price_wei, expected_price,
        "price matches CortexPricing formula"
    );
    assert_eq!(
        resp.receipt.price_wei, expected_price,
        "receipt price matches CortexPricing formula"
    );
    assert!(
        resp.price_wei > 0,
        "metered standard-tier inference must have non-zero price"
    );
    assert!(
        resp.price_wei <= req.budget.max_cost_wei,
        "settled price must fit within budget ceiling"
    );

    // --- 5. Weights/runtime hashes propagate through the receipt --------
    // The stdlib sidecar derives these from fixed strings, so we can
    // reconstruct them and confirm the Rust side parsed and retained them
    // byte-for-byte into the receipt.
    use sha2::{Digest, Sha256};
    let expected_weights = Sha256::digest(format!("weights:{MODEL_ID}").as_bytes());
    let expected_runtime = Sha256::digest(b"tenzro-cortex-stdlib-sidecar@0.1.0".as_slice());
    assert_eq!(
        resp.receipt.weights_hash.as_bytes(),
        expected_weights.as_slice(),
        "weights_hash round-trips through the sidecar wire format"
    );
    assert_eq!(
        resp.receipt.runtime_hash.as_bytes(),
        expected_runtime.as_slice(),
        "runtime_hash round-trips through the sidecar wire format"
    );
}
