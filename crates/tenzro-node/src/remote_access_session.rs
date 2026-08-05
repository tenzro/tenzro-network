//! Running a confined session, and the audit record it leaves behind.
//!
//! [`remote_access`](crate::remote_access) decides *whether* a renter may open
//! a session and *what* they may touch. This module is what happens once the
//! answer is yes: launching the sandbox, relaying bytes between the renter's
//! iroh stream and the sandbox's PTY, enforcing the session deadline, and
//! writing the transcript out as a receipt.
//!
//! # The launcher seam
//!
//! [`KataConfinement`] does not itself know how to start a Kata VM with VFIO
//! passthrough. It runs an operator-supplied launcher and hands it the scope
//! as JSON on stdin, then treats the child's stdin/stdout as the PTY.
//!
//! That seam is deliberate. Getting a GPU through a VM boundary depends on the
//! host: IOMMU groups, which vfio-pci binding the operator uses, whether the
//! device supports MIG and at what granularity — a DGX Spark's partitioning
//! options are not an H100's. A launcher script the operator owns is the only
//! place that knowledge can correctly live. What this module owns is
//! everything that must be true regardless of the launcher: that a session
//! cannot start without one, that it cannot outlive its deadline, and that it
//! leaves a record.

use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};

use tenzro_iroh::shell::{SessionPeer, ShellHandler};
use tenzro_iroh::{RecvStream, SendStream};
use tenzro_storage::da::{ReceiptEnvelope, ReceiptKind, ReceiptSummary, compute_commitment};
use tenzro_types::primitives::Timestamp;

use crate::remote_access::{
    AccessLease, ConfinementBackend, ConfinementKind, LeaseRegistry, SandboxSession,
};

/// Chunk size for PTY reads.
const PTY_CHUNK: usize = 8 * 1024;

/// How much output to keep for the transcript.
///
/// A transcript is an audit record, not a recording: it needs to establish
/// that a session happened, for how long, under which lease, and roughly what
/// it did. Retaining a renter's entire terminal output would make the receipt
/// unbounded and make the operator the custodian of whatever the renter typed.
const TRANSCRIPT_CAP: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Kata-backed confinement
// ---------------------------------------------------------------------------

/// Confinement via an operator-supplied Kata Containers launcher.
#[derive(Debug, Clone)]
pub struct KataConfinement {
    /// Path to the operator's launcher. Receives the scope as JSON on stdin
    /// and must expose the sandbox PTY on its own stdin/stdout.
    launcher: std::path::PathBuf,
}

impl KataConfinement {
    /// Build a backend around `launcher`.
    pub fn new(launcher: impl Into<std::path::PathBuf>) -> Self {
        Self {
            launcher: launcher.into(),
        }
    }
}

#[async_trait]
impl ConfinementBackend for KataConfinement {
    fn kind(&self) -> ConfinementKind {
        ConfinementKind::KataVm
    }

    async fn open(&self, lease: &AccessLease) -> Result<Box<dyn SandboxSession>, String> {
        // The launcher is given the scope, not the lease: it has no business
        // knowing who the renter is, and a launcher that cannot learn the
        // renter's DID cannot make decisions based on it.
        let scope = serde_json::to_vec(&lease.scope).map_err(|e| e.to_string())?;

        let mut child = Command::new(&self.launcher)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                format!(
                    "could not start confinement launcher {:?}: {e}",
                    self.launcher
                )
            })?;

        // Hand over the scope and close stdin so the launcher can proceed;
        // the PTY is re-opened on the same descriptor by the launcher.
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| "launcher stdin unavailable".to_string())?;
            stdin.write_all(&scope).await.map_err(|e| e.to_string())?;
            stdin.write_all(b"\n").await.map_err(|e| e.to_string())?;
            stdin.flush().await.map_err(|e| e.to_string())?;
        }

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| "launcher stdout unavailable".to_string())?;

        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            let mut buf = vec![0u8; PTY_CHUNK];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Box::new(KataSession {
            child: Mutex::new(child),
            output: Mutex::new(rx),
        }))
    }
}

/// A live Kata-confined session.
#[derive(Debug)]
struct KataSession {
    child: Mutex<Child>,
    output: Mutex<mpsc::Receiver<Vec<u8>>>,
}

#[async_trait]
impl SandboxSession for KataSession {
    async fn write_stdin(&self, bytes: &[u8]) -> Result<(), String> {
        let mut child = self.child.lock().await;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "sandbox stdin is closed".to_string())?;
        stdin.write_all(bytes).await.map_err(|e| e.to_string())?;
        stdin.flush().await.map_err(|e| e.to_string())
    }

    async fn read_output(&self) -> Result<Vec<u8>, String> {
        Ok(self.output.lock().await.recv().await.unwrap_or_default())
    }

    async fn shutdown(&self) -> Result<(), String> {
        // Kill rather than signal-and-wait. The deadline has already passed or
        // the renter has gone; waiting politely for a sandbox that may be
        // running whatever the renter left behind is how a session outlives
        // its lease.
        let mut child = self.child.lock().await;
        let _ = child.start_kill();
        let _ = child.wait().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Session handler
// ---------------------------------------------------------------------------

/// Node-side [`ShellHandler`]: authorizes against the lease book, runs the
/// session inside the configured boundary, and files the transcript.
pub struct NodeShellHandler {
    leases: Arc<LeaseRegistry>,
}

impl NodeShellHandler {
    /// Build a handler over the node's lease book.
    pub fn new(leases: Arc<LeaseRegistry>) -> Self {
        Self { leases }
    }
}

impl std::fmt::Debug for NodeShellHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeShellHandler").finish()
    }
}

#[async_trait]
impl ShellHandler for NodeShellHandler {
    async fn serve_session(
        &self,
        peer: SessionPeer,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> tenzro_iroh::IrohResult<()> {
        let started_ms = now_ms();

        // First line is the grant the CLI got back from the passkey ceremony.
        // Read before anything else so an unauthorized peer never causes a
        // sandbox to be launched.
        let grant_id = match read_grant_line(&mut recv).await {
            Ok(id) => id,
            Err(e) => {
                let _ = send.write_all(format!("tenzro: {e}\n").as_bytes()).await;
                let _ = send.finish();
                return Err(tenzro_iroh::IrohError::Unauthorized(e));
            }
        };

        let (lease, grant) = match self.leases.redeem_grant(&grant_id, started_ms) {
            Ok(pair) => pair,
            Err(denied) => {
                // Told to the caller, because someone whose lease expired
                // needs to know that rather than see a closed socket. The
                // reason names no other tenant and no other lease.
                let _ = send
                    .write_all(format!("tenzro: {denied}\n").as_bytes())
                    .await;
                let _ = send.finish();
                return Err(tenzro_iroh::IrohError::Unauthorized(denied.to_string()));
            }
        };

        // The transport identity is recorded but is not the authorization —
        // the wallet that passkey-verified is. Logging both lets an operator
        // see a session opened from an unexpected machine even when the
        // wallet was the right one.
        let _ = peer;

        let backend = self.leases.confinement().ok_or_else(|| {
            tenzro_iroh::IrohError::Unauthorized(
                "confinement backend disappeared between authorization and launch".to_string(),
            )
        })?;

        let sandbox = backend
            .open(&lease)
            .await
            .map_err(tenzro_iroh::IrohError::Backend)?;

        info!(
            lease = %lease.lease_id,
            wallet = %grant.wallet,
            peer = %peer,
            confinement = ?backend.kind(),
            "opened confined remote-access session",
        );

        let deadline = tokio::time::Duration::from_secs(lease.scope.effective_session_secs());
        let mut transcript = Vec::new();

        let outcome = tokio::time::timeout(
            deadline,
            relay(&*sandbox, &mut send, &mut recv, &mut transcript),
        )
        .await;

        let _ = sandbox.shutdown().await;

        let ended = match outcome {
            Ok(Ok(())) => "closed",
            Ok(Err(e)) => {
                warn!(lease = %lease.lease_id, error = %e, "remote-access session failed");
                "error"
            }
            Err(_) => {
                // The ceiling firing is normal, not a fault: the renter can
                // reconnect while the lease is live.
                info!(lease = %lease.lease_id, "remote-access session hit its ceiling");
                "deadline"
            }
        };

        let receipt = session_receipt(
            &lease,
            &grant.wallet,
            started_ms,
            now_ms(),
            ended,
            &transcript,
        );
        if let Err(e) = self
            .leases
            .record_session_receipt(&lease.lease_id, started_ms, &receipt)
        {
            // Not fatal to the session, which is already over — but loud,
            // because an unfiled receipt is a session with no record.
            warn!(lease = %lease.lease_id, error = %e, "could not file session receipt");
        }
        info!(
            lease = %lease.lease_id,
            commitment = %receipt.commitment,
            "filed remote-access session receipt",
        );
        Ok(())
    }
}

/// Read the newline-terminated grant id the CLI sends as its first frame.
///
/// Bounded: a peer that never sends a newline must not be able to make the
/// provider buffer without limit before it has proved anything at all.
async fn read_grant_line(recv: &mut RecvStream) -> Result<String, String> {
    const MAX_GRANT_LINE: usize = 128;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match recv.read(&mut byte).await {
            Ok(Some(1)) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > MAX_GRANT_LINE {
                    return Err("session grant is malformed".to_string());
                }
            }
            _ => return Err("session grant was not presented".to_string()),
        }
    }
    String::from_utf8(line)
        .map(|s| s.trim().to_string())
        .map_err(|_| "session grant is malformed".to_string())
}

/// Pump bytes between the renter's stream and the sandbox PTY until either
/// side closes.
async fn relay(
    sandbox: &dyn SandboxSession,
    send: &mut SendStream,
    recv: &mut RecvStream,
    transcript: &mut Vec<u8>,
) -> Result<(), String> {
    let mut inbound = vec![0u8; PTY_CHUNK];
    loop {
        tokio::select! {
            read = recv.read(&mut inbound) => {
                match read {
                    Ok(Some(0)) | Ok(None) | Err(_) => return Ok(()),
                    Ok(Some(n)) => sandbox.write_stdin(&inbound[..n]).await?,
                }
            }
            out = sandbox.read_output() => {
                let bytes = out?;
                if bytes.is_empty() {
                    return Ok(());
                }
                if transcript.len() < TRANSCRIPT_CAP {
                    let room = TRANSCRIPT_CAP - transcript.len();
                    transcript.extend_from_slice(&bytes[..bytes.len().min(room)]);
                }
                send.write_all(&bytes).await.map_err(|e| e.to_string())?;
            }
        }
    }
}

/// Build the audit record for one session.
///
/// A [`ReceiptEnvelope`] rather than a bespoke record so a session transcript
/// has the same shape as every other receipt in the system and can be
/// offloaded to DA rather than retained inline — the same reason inference
/// results and agent messages are receipts.
///
/// The session detail lives in the payload rather than the summary, so the
/// envelope's commitment binds it: an audit record that can be edited
/// afterwards is not one.
fn session_receipt(
    lease: &AccessLease,
    wallet: &str,
    started_ms: u64,
    ended_ms: u64,
    ended: &str,
    transcript: &[u8],
) -> ReceiptEnvelope {
    let payload = serde_json::to_vec(&serde_json::json!({
        "lease_id": lease.lease_id,
        "rental_id": lease.rental_id,
        "renter_did": lease.renter_did,
        "wallet": wallet,
        "started_at_ms": started_ms,
        "ended_at_ms": ended_ms,
        "duration_secs": ended_ms.saturating_sub(started_ms) / 1000,
        "ended": ended,
        "confinement": lease.scope.confinement,
        "accelerators": lease.scope.accelerators(),
        "network": lease.scope.network,
        "transcript_bytes": transcript.len(),
        "transcript_truncated": transcript.len() >= TRANSCRIPT_CAP,
        "transcript": String::from_utf8_lossy(transcript),
    }))
    .unwrap_or_default();

    let summary = ReceiptSummary {
        receipt_id: compute_commitment(&payload),
        // The wallet that passkey-verified, not the lease's renter DID: a
        // lease may authorize several wallets, and the accountable party is
        // whichever one actually signed in. There is no payee — the money
        // moved through the rental agreement, and restating it here would
        // invite the two records to disagree.
        payer: Some(wallet.to_string()),
        payee: None,
        amount_wei: None,
        timestamp: Timestamp::new(ended_ms as i64),
        principal_chain_summary: None,
    };

    ReceiptEnvelope::inline(ReceiptKind::Lifecycle, summary, payload)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_access::{
        AccessChannel, AccessScope, ConfinementKind, DedicationMode, DeviceGrant, LeaseStatus,
        NetworkGrant, RentalTerm,
    };
    use std::path::PathBuf;

    const WALLET: &str = "0xabc0000000000000000000000000000000000001";

    fn lease() -> AccessLease {
        AccessLease {
            lease_id: "lease-1".to_string(),
            rental_id: Some("rental-1".to_string()),
            renter_did: "did:tenzro:human:abc".to_string(),
            service_key_hash: "ab".repeat(32),
            authorized_wallets: vec![WALLET.to_string()],
            scope: AccessScope {
                workspace: PathBuf::from("/workspace"),
                devices: vec![DeviceGrant::Accelerator { index: 1 }],
                network: NetworkGrant::None,
                max_session_secs: 60,
                confinement: ConfinementKind::KataVm,
                // Test fixtures share the public pool and pin nothing.
                reserved_slots: 0,
                models: Vec::new(),
                max_memory_bytes: None,
                sites: Vec::new(),
                databases: Vec::new(),
                storage_deals: Vec::new(),
                agents: Vec::new(),
                // A shell fixture, so the channel has to say so explicitly.
                channels: vec![AccessChannel::Shell],
                dedication: DedicationMode::Partial,
                term: RentalTerm::Hourly,
            },
            expires_at_ms: u64::MAX,
            status: LeaseStatus::Active,
            created_at_ms: 0,
        }
    }

    fn detail(receipt: &ReceiptEnvelope) -> serde_json::Value {
        serde_json::from_slice(receipt.inline_payload.as_ref().expect("inline payload")).unwrap()
    }

    #[test]
    fn a_receipt_records_the_session_without_becoming_a_recording() {
        let big = vec![b'x'; TRANSCRIPT_CAP * 2];
        let receipt = session_receipt(
            &lease(),
            WALLET,
            1_000,
            61_000,
            "closed",
            &big[..TRANSCRIPT_CAP],
        );
        let d = detail(&receipt);
        assert_eq!(d["lease_id"], "lease-1");
        assert_eq!(d["renter_did"], "did:tenzro:human:abc");
        assert_eq!(d["duration_secs"], 60);
        assert_eq!(d["ended"], "closed");
        assert_eq!(d["accelerators"], serde_json::json!([1]));
        assert_eq!(
            d["transcript_truncated"], true,
            "an operator must be able to tell a full transcript from a clipped one"
        );
        assert_eq!(
            d["wallet"], WALLET,
            "the receipt must name the wallet that actually signed in"
        );
        assert_eq!(
            receipt.inline_summary.payer.as_deref(),
            Some(WALLET),
            "a session is attributable to the wallet that passkey-verified, not to the lease"
        );
    }

    /// The receipt binds to what it carries, like every other receipt in the
    /// system — an audit record that can be edited afterwards is not one.
    #[test]
    fn the_receipt_commits_to_its_transcript() {
        let a = session_receipt(&lease(), WALLET, 0, 1, "closed", b"ls -la");
        let b = session_receipt(&lease(), WALLET, 0, 1, "closed", b"rm -rf /");
        assert_ne!(a.commitment, b.commitment);
        assert_eq!(
            a.commitment, a.inline_summary.receipt_id,
            "the id and the commitment must be the same hash of the same bytes"
        );
    }

    #[test]
    fn a_deadline_and_a_clean_close_are_distinguishable() {
        assert_eq!(
            detail(&session_receipt(&lease(), WALLET, 0, 1, "closed", b""))["ended"],
            "closed"
        );
        assert_eq!(
            detail(&session_receipt(&lease(), WALLET, 0, 1, "deadline", b""))["ended"],
            "deadline"
        );
    }

    #[tokio::test]
    async fn a_missing_launcher_fails_the_session_rather_than_falling_back() {
        let backend = KataConfinement::new("/nonexistent/kata-launcher");
        let err = backend.open(&lease()).await.unwrap_err();
        assert!(err.contains("launcher"), "{err}");
    }
}
