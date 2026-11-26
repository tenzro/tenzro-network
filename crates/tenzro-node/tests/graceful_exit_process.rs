//! `tenzro-node graceful-exit` stops a running node: the command signs in as
//! the machine, the node accepts the call, and the node process ends within
//! its drain time.
//!
//! The node needs its hardware key, so this runs with a TPM, which on a build
//! machine is a software one:
//!
//! ```text
//! scripts/tests/cargo-test-with-swtpm.sh -p tenzro-node --test graceful_exit_process -- --ignored
//! ```

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn node_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tenzro-node"))
}

/// The address the node's RPC server bound, once its JSON log says so.
fn rpc_addr_in(log: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(log)
        .ok()?
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["fields"]["message"] == "RPC server listening")
        .and_then(|v| v["fields"]["addr"].as_str().map(str::to_string))
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

#[tokio::test]
#[ignore = "starts a node: needs this machine's hardware key (TPM 2.0 or Secure Enclave); \
            run under scripts/tests/cargo-test-with-swtpm.sh with --ignored"]
async fn graceful_exit_stops_the_node_within_its_drain_time() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("node.log");
    // Every listener on a port the system picks as it binds; the RPC
    // server's is read back from the log.
    let mut node = Command::new(node_binary())
        .args(["--log-format", "json"])
        .arg("--dev")
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .args(["--rpc-addr", "127.0.0.1:0"])
        .args(["--web-addr", "127.0.0.1:0"])
        .args(["--mcp-addr", "127.0.0.1:0"])
        .args(["--a2a-addr", "127.0.0.1:0"])
        .env("TENZRO_HOME", dir.path())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();

    // The node is up once its RPC answers.
    let http = reqwest::Client::new();
    let started = Instant::now();
    let mut url = String::new();
    loop {
        if let Some(status) = node.try_wait().unwrap() {
            panic!(
                "the node exited before serving RPC ({status}):\n{}",
                log_tail(&log)
            );
        }
        if url.is_empty()
            && let Some(addr) = rpc_addr_in(&log)
        {
            url = format!("http://{addr}");
        }
        let up = !url.is_empty()
            && http
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

    let exit = Command::new(node_binary())
        .args([
            "graceful-exit",
            "--force",
            "--max-wait-secs",
            "1",
            "--rpc-url",
            &url,
        ])
        .env("TENZRO_HOME", dir.path())
        .output()
        .unwrap();
    if !exit.status.success() {
        let _ = node.kill();
        panic!(
            "graceful-exit failed ({}):\n{}\nnode log:\n{}",
            exit.status,
            String::from_utf8_lossy(&exit.stderr),
            log_tail(&log)
        );
    }

    // The node drains its servers for 5 s after its event loop stops.
    let Some(status) = wait_exit(&mut node, Duration::from_secs(30)) else {
        let _ = node.kill();
        panic!(
            "the node was still running 30 s after graceful-exit:\n{}",
            log_tail(&log)
        );
    };
    assert!(status.success(), "the node exited with {status}");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("Event loop stopped"), "{}", log_tail(&log));
}
