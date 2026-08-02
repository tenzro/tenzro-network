//! End-to-end tests for the `tenzro/shell` ALPN over a real iroh endpoint.
//!
//! The unit tests in `shell.rs` prove the trampoline and the peer type behave.
//! They do not prove that a peer can dial the ALPN, that the handler receives
//! the connecting peer's authenticated identity, or that a refusal reaches the
//! caller rather than hanging the stream — and those are the properties the
//! whole design rests on. Each test here binds two real endpoints and dials one
//! from the other.

use std::sync::Arc;

use async_trait::async_trait;
use iroh::{Endpoint, EndpointAddr, endpoint::presets, protocol::Router};

/// Every network step is bounded: a hanging test is worse than a missing one.
const STEP: std::time::Duration = std::time::Duration::from_secs(20);
use tenzro_iroh::shell::{
    ALPN_SHELL, DeferredShellHandler, RecvStream, SendStream, SessionPeer, ShellHandler,
    ShellProtocol,
};
use tokio::sync::mpsc;

/// A handler that records who connected and echoes a fixed reply, so a test
/// can assert on the identity the transport handed it.
#[derive(Debug)]
struct RecordingHandler {
    seen: mpsc::UnboundedSender<SessionPeer>,
    reply: Vec<u8>,
}

#[async_trait]
impl ShellHandler for RecordingHandler {
    async fn serve_session(
        &self,
        peer: SessionPeer,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> tenzro_iroh::IrohResult<()> {
        let _ = self.seen.send(peer);

        // Read the caller's first line, the way the node's handler reads a
        // session grant.
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while let Ok(Some(1)) = recv.read(&mut byte).await {
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            if line.len() > 128 {
                break;
            }
        }

        let mut out = self.reply.clone();
        out.extend_from_slice(&line);
        let _ = send.write_all(&out).await;
        let _ = send.finish();
        Ok(())
    }
}

/// A handler that always refuses, standing in for "no lease" / "no
/// confinement" without needing the node's whole lease book.
#[derive(Debug)]
struct RefusingHandler;

#[async_trait]
impl ShellHandler for RefusingHandler {
    async fn serve_session(
        &self,
        _peer: SessionPeer,
        mut send: SendStream,
        _recv: RecvStream,
    ) -> tenzro_iroh::IrohResult<()> {
        // Tell the caller, then close. A renter whose lease expired needs to
        // know that rather than see a socket close with no explanation.
        let _ = send
            .write_all(b"tenzro: no access lease for this service key\n")
            .await;
        let _ = send.finish();
        Err(tenzro_iroh::IrohError::Unauthorized("no lease".into()))
    }
}

/// Bind a provider endpoint serving `handler` on the shell ALPN.
///
/// Returns the full [`EndpointAddr`], not just the id: the `Minimal` preset
/// runs no address lookup and no relay, so a local peer dials by socket
/// address. That is the right shape for a test — it exercises the ALPN and the
/// handler without depending on DNS, Pkarr, or n0's relays being reachable.
async fn provider(handler: Arc<dyn ShellHandler>) -> (Router, EndpointAddr) {
    let endpoint = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN_SHELL.to_vec()])
        .bind()
        .await
        .expect("bind provider endpoint");
    // Not `online()`: with no relay configured that never resolves. Both
    // endpoints are local, so the bound sockets are the whole address.
    let addr = EndpointAddr::from_parts(
        endpoint.id(),
        endpoint
            .bound_sockets()
            .into_iter()
            .map(iroh::TransportAddr::Ip),
    );
    let router = Router::builder(endpoint)
        .accept(ALPN_SHELL, ShellProtocol::new(handler))
        .spawn();
    (router, addr)
}

/// Dial `target` on the shell ALPN, send `first_line`, and read the reply.
async fn dial(target: EndpointAddr, first_line: &str) -> (SessionPeer, Vec<u8>) {
    let caller = Endpoint::builder(presets::Minimal)
        .bind()
        .await
        .expect("bind caller");
    let caller_id = SessionPeer(*caller.id().as_bytes());

    let conn = tokio::time::timeout(STEP, caller.connect(target, ALPN_SHELL))
        .await
        .expect("dial did not time out")
        .expect("dial shell ALPN");
    let (mut send, mut recv) = tokio::time::timeout(STEP, conn.open_bi())
        .await
        .expect("open_bi did not time out")
        .expect("open bi stream");

    send.write_all(first_line.as_bytes()).await.expect("write");
    send.write_all(b"\n").await.expect("write newline");
    let _ = send.finish();

    let reply = tokio::time::timeout(STEP, recv.read_to_end(64 * 1024))
        .await
        .expect("read did not time out")
        .unwrap_or_default();
    (caller_id, reply)
}

/// The ALPN is reachable, and the handler is handed the caller's authenticated
/// identity by the transport — not by anything the caller claimed.
#[tokio::test]
async fn a_peer_can_dial_the_shell_alpn_and_the_handler_learns_who_it_is() {
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    let handler = Arc::new(RecordingHandler {
        seen: seen_tx,
        reply: b"ok:".to_vec(),
    });
    let (router, provider_addr) = provider(handler).await;

    let (caller_id, reply) = dial(provider_addr.clone(), "grant-abc123").await;

    let observed = tokio::time::timeout(std::time::Duration::from_secs(10), seen_rx.recv())
        .await
        .expect("handler ran")
        .expect("peer recorded");

    assert_eq!(
        observed, caller_id,
        "the handler must see the dialling endpoint's real identity"
    );
    assert_eq!(
        String::from_utf8_lossy(&reply),
        "ok:grant-abc123",
        "the first line must arrive intact — it is where the session grant rides"
    );

    router.shutdown().await.ok();
}

/// A refusal reaches the caller as a message and a closed stream, rather than
/// hanging. A renter cannot tell a hung stream from a node that is simply not
/// offering shell access.
#[tokio::test]
async fn a_refused_session_tells_the_caller_why() {
    let (router, provider_addr) = provider(Arc::new(RefusingHandler)).await;

    let (_caller, reply) = dial(provider_addr.clone(), "grant-that-does-not-exist").await;
    let text = String::from_utf8_lossy(&reply);

    assert!(
        text.contains("no access lease"),
        "the caller should be told why, got: {text:?}"
    );
    router.shutdown().await.ok();
}

/// A node that registered the ALPN but never installed a handler refuses,
/// rather than accepting and hanging. This is the state every node is in
/// between binding its endpoint and installing the real handler.
#[tokio::test]
async fn an_unbound_trampoline_refuses_rather_than_hanging() {
    let trampoline = Arc::new(DeferredShellHandler::new());
    assert!(!trampoline.is_ready());

    let (router, provider_addr) = provider(trampoline.clone()).await;
    let (_caller, reply) = dial(provider_addr.clone(), "anything").await;

    // The unbound handler returns Unauthorized and writes nothing, so the
    // caller sees a clean close rather than a stall.
    assert!(
        reply.is_empty(),
        "an unbound handler should close without a payload, got: {reply:?}"
    );
    router.shutdown().await.ok();
}

/// Installing the handler later works on the already-registered ALPN — the
/// whole reason the trampoline exists, since the node binds its endpoint
/// before the lease registry is built.
#[tokio::test]
async fn a_handler_installed_after_bind_serves_the_next_session() {
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    let trampoline = Arc::new(DeferredShellHandler::new());
    let (router, provider_addr) = provider(trampoline.clone()).await;

    // Install after the router is already spawned and serving.
    trampoline.set(Arc::new(RecordingHandler {
        seen: seen_tx,
        reply: b"late:".to_vec(),
    }));
    assert!(trampoline.is_ready());

    let (_caller, reply) = dial(provider_addr.clone(), "grant-xyz").await;
    assert_eq!(String::from_utf8_lossy(&reply), "late:grant-xyz");
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(10), seen_rx.recv())
            .await
            .expect("handler ran")
            .is_some()
    );

    router.shutdown().await.ok();
}

/// Two different callers are distinguished. A handler that could not tell them
/// apart could not attribute a session to a lease.
#[tokio::test]
async fn two_callers_are_seen_as_different_peers() {
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    let (router, provider_addr) = provider(Arc::new(RecordingHandler {
        seen: seen_tx,
        reply: Vec::new(),
    }))
    .await;

    let (first, _) = dial(provider_addr.clone(), "a").await;
    let (second, _) = dial(provider_addr.clone(), "b").await;
    assert_ne!(first, second, "two endpoints must have distinct identities");

    let mut observed = Vec::new();
    for _ in 0..2 {
        let peer = tokio::time::timeout(std::time::Duration::from_secs(10), seen_rx.recv())
            .await
            .expect("handler ran")
            .expect("peer recorded");
        observed.push(peer);
    }
    observed.sort_by_key(|p| p.to_hex());
    let mut expected = vec![first, second];
    expected.sort_by_key(|p| p.to_hex());
    assert_eq!(observed, expected);

    router.shutdown().await.ok();
}
