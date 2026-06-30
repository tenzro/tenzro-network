//! Node-side LAN layer-pipeline serving runtime.
//!
//! Turns the deterministic cluster plan from [`tenzro_model::cluster`] into a
//! running pipeline. A model too large for one machine is split into
//! contiguous transformer-layer ranges; each member runs llama.cpp's ggml
//! `rpc-server` over its range, and the head loads the single GGUF with those
//! members attached as RPC devices. Only the boundary activation crosses
//! member boundaries, so the pipeline tolerates commodity LAN RTTs.
//!
//! ## Two roles, one runtime
//!
//! A node can be a cluster **member**, the cluster **head**, or both. The
//! runtime owns the pieces each role needs and keeps them dormant until a plan
//! activates them — a node that neither heads nor joins a cluster pays nothing.
//!
//! ### Member
//!
//! The member never exposes its `rpc-server` socket on the network: the ggml
//! RPC protocol is unauthenticated and explicitly unsafe on an open network.
//! Instead it subscribes to the [`cluster_tunnel`] overlay and, for each
//! session a head opens, spawns a loopback `rpc-server` and splices the
//! tunnel's byte stream to that socket. Frames in, socket bytes out — the
//! `Ack` piggybacks the return bytes so one request-response pair is
//! full-duplex.
//!
//! ### Head
//!
//! The head consumes a [`LaunchPlan`]. For each stage it opens a tunnel
//! session to the member and binds a loopback TCP listener whose accepted
//! connection it bridges to that session; it then registers
//! `127.0.0.1:<local_port>` as a ggml RPC device via
//! [`tenzro_model::cluster::rpc_add_server`]-equivalent
//! ([`llama_cpp_2::rpc_add_server`]). With all members registered in pipeline
//! order it loads the GGUF, selecting those devices with the plan's
//! `--tensor-split` proportions so the runtime's proportional device-fill
//! reproduces the assigned layer ranges. The loaded model is exposed to the
//! inference path as one logical provider.
//!
//! ## Fault tolerance
//!
//! A dropped stage is a dropped RPC connection, which the ggml backend
//! surfaces as a load/decode failure. The serving path treats that as a stage
//! failure and fails over: the planner is asked for a fresh plan over the
//! members still reachable, and the model is reloaded. Re-planning is
//! deterministic, so two heads fed the same surviving-member set converge on
//! the same replacement plan with no coordination round.
//!
//! [`cluster_tunnel`]: tenzro_network::cluster_tunnel_proto
//! [`LaunchPlan`]: tenzro_model::cluster::LaunchPlan

use std::collections::HashMap;
use std::sync::Arc;

use libp2p::PeerId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, info, warn};

use tenzro_model::cluster::{LaunchPlan, LaunchStage};
use tenzro_network::cluster_tunnel_proto::{
    ClusterTunnelError, ClusterTunnelRequest, ClusterTunnelResponse, TunnelFrame, TunnelFrameKind,
    MAX_FRAME_PAYLOAD,
};
use tenzro_network::{InboundClusterTunnel, NetworkService, OutboundClusterTunnelResult};

/// Resolve the `rpc-server` binary path, preferring the `TENZRO_RPC_SERVER_BIN`
/// runtime override over the compile-time path baked in by `llama-cpp-2`.
///
/// The compile-time path points into the build's cargo `OUT_DIR`, which does
/// not survive into a multi-stage container image. The runtime image copies
/// rpc-server to a stable path and sets `TENZRO_RPC_SERVER_BIN` to point at it.
/// Returns `None` if neither source yields an existing file.
fn resolve_rpc_server_bin() -> Option<String> {
    if let Ok(p) = std::env::var("TENZRO_RPC_SERVER_BIN") {
        if !p.is_empty() && std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    let compiled = llama_cpp_2::rpc_server_bin()?;
    std::path::Path::new(compiled)
        .exists()
        .then(|| compiled.to_string())
}

/// Errors raised while bringing up or running a cluster pipeline.
#[derive(Debug, thiserror::Error)]
pub enum ClusterServingError {
    /// The `rpc-server` binary was not built into this binary — the
    /// `cluster-serving` feature (which enables `llama-cpp-2/rpc`) was off.
    #[error("rpc-server binary unavailable — build with the cluster-serving feature")]
    RpcServerUnavailable,
    /// The member's local `rpc-server` process could not be spawned.
    #[error("failed to spawn rpc-server: {0}")]
    RpcServerSpawn(String),
    /// A loopback socket bind / connect / accept failed.
    #[error("loopback socket error: {0}")]
    Socket(String),
    /// Registering a member as a ggml RPC device failed.
    #[error("failed to attach member as RPC device: {0}")]
    DeviceAttach(String),
    /// The plan named no data-plane-reachable members to serve.
    #[error("launch plan has no serviceable stages")]
    EmptyPlan,
    /// An attached RPC endpoint could not be matched to a ggml device index.
    #[error("could not resolve ggml device index for endpoint {0}")]
    DeviceResolve(String),
    /// Network-layer subscription / send failure.
    #[error("network error: {0}")]
    Network(String),
}

/// Owns a node's cluster-serving services for both roles.
///
/// Construction is cheap and side-effect-free; the member splice loop only
/// starts when [`Self::serve_as_member`] is called, and head sessions only
/// open when [`Self::head_attach_members`] is called with a plan.
pub struct ClusterServingRuntime {
    network: Arc<dyn NetworkService>,
    /// Active head-side sessions keyed by session id, retained so they can be
    /// torn down on failover. Each holds the loopback listener task handle.
    head_sessions: Mutex<HashMap<u64, HeadSession>>,
}

/// A head-side pipeline session: one member attached as an RPC device behind a
/// loopback bridge.
struct HeadSession {
    /// The member this session relays to. Read by the head-orchestration path
    /// (cluster formation → plan → attach) once it is wired.
    #[allow(dead_code)]
    peer: PeerId,
    /// The `host:port` the head registered as a ggml RPC device. Returned to
    /// the model loader for device selection by the head-orchestration path.
    #[allow(dead_code)]
    local_endpoint: String,
    /// Bridge task handle — aborts the loopback↔tunnel splice on drop.
    bridge: tokio::task::JoinHandle<()>,
}

impl Drop for HeadSession {
    fn drop(&mut self) {
        self.bridge.abort();
    }
}

impl std::fmt::Debug for ClusterServingRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterServingRuntime").finish_non_exhaustive()
    }
}

impl ClusterServingRuntime {
    /// Build a runtime over the node's network service. Inert until a role
    /// entry point is called.
    pub fn new(network: Arc<dyn NetworkService>) -> Self {
        Self {
            network,
            head_sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Start serving as a cluster **member**: subscribe to inbound tunnel
    /// frames and splice each session to a freshly-spawned loopback
    /// `rpc-server`. Spawns a background task and returns once subscribed.
    ///
    /// Requires the `cluster-serving` feature so the `rpc-server` binary is
    /// present; otherwise returns [`ClusterServingError::RpcServerUnavailable`]
    /// without subscribing (the head will see `NoMember` and fail over).
    pub async fn serve_as_member(&self) -> Result<(), ClusterServingError> {
        let rpc_bin = resolve_rpc_server_bin().ok_or(ClusterServingError::RpcServerUnavailable)?;

        let rx = self
            .network
            .subscribe_cluster_tunnel_requests()
            .await
            .map_err(|e| ClusterServingError::Network(e.to_string()))?;

        let network = Arc::clone(&self.network);
        tokio::spawn(async move {
            member_splice_loop(network, rx, rpc_bin).await;
        });
        info!("cluster-serving: member splice loop attached");
        Ok(())
    }

    /// Attach every stage of `plan` as a loopback-bridged ggml RPC device, in
    /// pipeline order. On success the caller can load the GGUF selecting the
    /// returned device endpoints with `plan.tensor_split` proportions.
    ///
    /// Returns the `host:port` endpoints in pipeline order — the same order the
    /// model loader must pass to `--rpc` / device selection so the proportional
    /// fill reproduces the planner's layer ranges.
    pub async fn head_attach_members(
        &self,
        plan: &LaunchPlan,
    ) -> Result<Vec<String>, ClusterServingError> {
        if plan.stages.is_empty() {
            return Err(ClusterServingError::EmptyPlan);
        }

        // Subscribe once to outbound results; the splice loops for every
        // session share this stream, demultiplexing by session id carried in
        // the returned frames.
        let results = self
            .network
            .subscribe_cluster_tunnel_results()
            .await
            .map_err(|e| ClusterServingError::Network(e.to_string()))?;
        let results = Arc::new(Mutex::new(results));

        let mut endpoints = Vec::with_capacity(plan.stages.len());
        let mut sessions = self.head_sessions.lock().await;

        for (idx, stage) in plan.stages.iter().enumerate() {
            let session_id = idx as u64;
            let peer = parse_member_peer(stage)?;

            // Bind a loopback listener on an OS-assigned port. ggml will dial
            // this; our bridge task accepts the single connection and splices
            // it to the tunnel session.
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| ClusterServingError::Socket(e.to_string()))?;
            let local_addr = listener
                .local_addr()
                .map_err(|e| ClusterServingError::Socket(e.to_string()))?;
            let local_endpoint = local_addr.to_string();

            let network = Arc::clone(&self.network);
            let results = Arc::clone(&results);
            let bridge = tokio::spawn(async move {
                head_bridge_loop(network, results, listener, peer, session_id).await;
            });

            // Register the loopback endpoint as a ggml RPC device. Order of
            // registration is pipeline order, which is what the device-fill
            // honours against tensor_split.
            attach_rpc_device(&local_endpoint)?;

            sessions.insert(
                session_id,
                HeadSession {
                    peer,
                    local_endpoint: local_endpoint.clone(),
                    bridge,
                },
            );
            endpoints.push(local_endpoint);
            debug!(%peer, session_id, "cluster-serving: attached member RPC device");
        }

        info!(
            stages = plan.stages.len(),
            "cluster-serving: head attached all members; ready to load model"
        );
        Ok(endpoints)
    }

    /// Resolve the ggml backend-registry device indices for `endpoints`, in the
    /// same order. Each endpoint was registered via [`llama_cpp_2::rpc_add_server`]
    /// in [`Self::head_attach_members`], so the RPC backend exposes one device per
    /// endpoint whose name embeds the `host:port`. The returned indices feed
    /// `LlamaModelParams::with_devices`, and pairing them with `plan.tensor_split`
    /// reproduces the planner's per-stage layer ranges.
    #[cfg(feature = "cluster-serving")]
    pub fn head_device_indices(
        &self,
        endpoints: &[String],
    ) -> Result<Vec<usize>, ClusterServingError> {
        let devices = llama_cpp_2::list_llama_ggml_backend_devices();
        let mut indices = Vec::with_capacity(endpoints.len());
        for ep in endpoints {
            // The RPC backend names each device with the endpoint it proxies
            // (e.g. "RPC[127.0.0.1:54321]"), so a substring match on the
            // `host:port` uniquely identifies the device we just registered.
            let dev = devices
                .iter()
                .find(|d| d.name.contains(ep.as_str()))
                .ok_or_else(|| ClusterServingError::DeviceResolve(ep.clone()))?;
            indices.push(dev.index);
        }
        Ok(indices)
    }

    /// Without the cluster-serving feature the RPC backend is not linked, so no
    /// device can be resolved.
    #[cfg(not(feature = "cluster-serving"))]
    pub fn head_device_indices(
        &self,
        _endpoints: &[String],
    ) -> Result<Vec<usize>, ClusterServingError> {
        Err(ClusterServingError::RpcServerUnavailable)
    }

    /// Tear down all head-side sessions (failover / shutdown). Aborts each
    /// bridge task and drops the loopback listeners.
    pub async fn head_teardown(&self) {
        let mut sessions = self.head_sessions.lock().await;
        let n = sessions.len();
        sessions.clear();
        if n > 0 {
            info!(sessions = n, "cluster-serving: head sessions torn down");
        }
    }
}

/// Register `endpoint` (a loopback `host:port`) as a ggml RPC device.
#[cfg(feature = "cluster-serving")]
fn attach_rpc_device(endpoint: &str) -> Result<(), ClusterServingError> {
    llama_cpp_2::rpc_add_server(endpoint)
        .map_err(|e| ClusterServingError::DeviceAttach(e.to_string()))
}

/// Without the cluster-serving feature the RPC backend is not linked, so
/// device attachment cannot succeed.
#[cfg(not(feature = "cluster-serving"))]
fn attach_rpc_device(_endpoint: &str) -> Result<(), ClusterServingError> {
    Err(ClusterServingError::RpcServerUnavailable)
}

/// Parse the member `PeerId` from a launch stage. The endpoint carries the
/// member's libp2p peer id appended after a `#` so the head knows which peer's
/// tunnel to dial (the LAN `host:port` is the member's own rpc-server bind,
/// reached through the tunnel, not dialed directly).
fn parse_member_peer(stage: &LaunchStage) -> Result<PeerId, ClusterServingError> {
    let peer_str = stage
        .local_endpoint
        .rsplit('#')
        .next()
        .filter(|s| !s.is_empty() && *s != stage.local_endpoint)
        .ok_or_else(|| {
            ClusterServingError::Network(format!(
                "launch stage endpoint missing member peer id: {}",
                stage.local_endpoint
            ))
        })?;
    peer_str
        .parse::<PeerId>()
        .map_err(|e| ClusterServingError::Network(format!("invalid member peer id: {e}")))
}

/// Member side: for each inbound tunnel frame, splice to a per-session loopback
/// `rpc-server`. Sessions are demultiplexed by `frame.session`; a new session
/// id with an `Open` frame spawns a fresh rpc-server + socket.
async fn member_splice_loop(
    network: Arc<dyn NetworkService>,
    mut rx: UnboundedReceiver<InboundClusterTunnel>,
    rpc_bin: String,
) {
    // One live socket + child process per session.
    let mut sessions: HashMap<u64, MemberSession> = HashMap::new();

    while let Some(inbound) = rx.recv().await {
        let InboundClusterTunnel {
            peer,
            request_id,
            request,
        } = inbound;
        let frame = request.frame;
        let session_id = frame.session;

        let response = match frame.kind {
            TunnelFrameKind::Open => {
                match MemberSession::open(&rpc_bin, session_id).await {
                    Ok(session) => {
                        sessions.insert(session_id, session);
                        debug!(%peer, session_id, "cluster-serving: member opened session");
                        ClusterTunnelResponse::Ack {
                            return_frames: Vec::new(),
                        }
                    }
                    Err(e) => {
                        warn!(%peer, session_id, error = %e, "cluster-serving: member open failed");
                        ClusterTunnelResponse::Error(ClusterTunnelError::SocketError(
                            e.to_string(),
                        ))
                    }
                }
            }
            TunnelFrameKind::Data => match sessions.get_mut(&session_id) {
                Some(session) => match session.exchange(&frame.payload).await {
                    Ok(return_frames) => ClusterTunnelResponse::Ack { return_frames },
                    Err(e) => {
                        warn!(%peer, session_id, error = %e, "cluster-serving: member splice failed");
                        sessions.remove(&session_id);
                        ClusterTunnelResponse::Error(ClusterTunnelError::SocketError(
                            e.to_string(),
                        ))
                    }
                },
                None => ClusterTunnelResponse::Error(ClusterTunnelError::SocketError(
                    "data frame for unknown session".to_string(),
                )),
            },
            TunnelFrameKind::Close => {
                sessions.remove(&session_id);
                debug!(%peer, session_id, "cluster-serving: member closed session");
                ClusterTunnelResponse::Ack {
                    return_frames: Vec::new(),
                }
            }
        };

        if let Err(e) = network
            .send_cluster_tunnel_response(request_id, response)
            .await
        {
            warn!(%peer, session_id, error = %e, "cluster-serving: member response send failed");
        }
    }

    debug!("cluster-serving: member splice loop ended (subscription closed)");
}

/// A live member session: the spawned `rpc-server` child and the loopback TCP
/// socket the splice loop reads/writes.
struct MemberSession {
    child: tokio::process::Child,
    socket: TcpStream,
    /// Next return-frame sequence number for this session's return path.
    return_seq: u64,
    session_id: u64,
}

impl MemberSession {
    /// Spawn a loopback `rpc-server` and connect a socket to it.
    async fn open(rpc_bin: &str, session_id: u64) -> Result<Self, ClusterServingError> {
        // Bind an ephemeral loopback port for the rpc-server.
        let probe = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| ClusterServingError::Socket(e.to_string()))?;
        let addr = probe
            .local_addr()
            .map_err(|e| ClusterServingError::Socket(e.to_string()))?;
        drop(probe); // free the port for rpc-server to bind

        let host = addr.ip().to_string();
        let port = addr.port().to_string();
        let child = tokio::process::Command::new(rpc_bin)
            .arg("-H")
            .arg(&host)
            .arg("-p")
            .arg(&port)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| ClusterServingError::RpcServerSpawn(e.to_string()))?;

        // Connect to it, retrying briefly while it binds its listener.
        let socket = connect_with_retry(&format!("{host}:{port}")).await?;

        Ok(Self {
            child,
            socket,
            return_seq: 0,
            session_id,
        })
    }

    /// Write inbound payload bytes to the rpc-server socket and read back any
    /// response bytes, chunked into return frames within the payload cap.
    async fn exchange(&mut self, payload: &[u8]) -> Result<Vec<TunnelFrame>, ClusterServingError> {
        if !payload.is_empty() {
            self.socket
                .write_all(payload)
                .await
                .map_err(|e| ClusterServingError::Socket(e.to_string()))?;
        }

        // Read whatever the rpc-server has produced. A single read up to the
        // frame cap; the head's pipelined frames keep the path saturated, so
        // we do not block waiting for a full logical message here.
        let mut buf = vec![0u8; MAX_FRAME_PAYLOAD];
        let n = self
            .socket
            .read(&mut buf)
            .await
            .map_err(|e| ClusterServingError::Socket(e.to_string()))?;
        if n == 0 {
            return Ok(Vec::new());
        }
        buf.truncate(n);
        let frame = TunnelFrame {
            session: self.session_id,
            seq: self.return_seq,
            kind: TunnelFrameKind::Data,
            payload: buf,
        };
        self.return_seq += 1;
        Ok(vec![frame])
    }
}

impl Drop for MemberSession {
    fn drop(&mut self) {
        // kill_on_drop is set on the child; nothing else to clean up.
        let _ = self.child.start_kill();
    }
}

/// Head side: accept the single ggml loopback connection and bridge it to the
/// tunnel session. Each chunk read from the socket becomes a `Data` frame sent
/// to the member; the member's `Ack.return_frames` are written back to the
/// socket in sequence order.
async fn head_bridge_loop(
    network: Arc<dyn NetworkService>,
    results: Arc<Mutex<UnboundedReceiver<OutboundClusterTunnelResult>>>,
    listener: TcpListener,
    peer: PeerId,
    session_id: u64,
) {
    let (mut socket, _addr) = match listener.accept().await {
        Ok(pair) => pair,
        Err(e) => {
            warn!(%peer, session_id, error = %e, "cluster-serving: head accept failed");
            return;
        }
    };

    // Open the session.
    let open = ClusterTunnelRequest {
        frame: TunnelFrame {
            session: session_id,
            seq: 0,
            kind: TunnelFrameKind::Open,
            payload: Vec::new(),
        },
    };
    if let Err(e) = send_and_await(&network, &results, peer, open, &mut socket).await {
        warn!(%peer, session_id, error = %e, "cluster-serving: head open failed");
        return;
    }

    let mut seq: u64 = 1;
    let mut buf = vec![0u8; MAX_FRAME_PAYLOAD];
    loop {
        let n = match socket.read(&mut buf).await {
            Ok(0) => break, // ggml closed the device connection
            Ok(n) => n,
            Err(e) => {
                warn!(%peer, session_id, error = %e, "cluster-serving: head socket read failed");
                break;
            }
        };
        let req = ClusterTunnelRequest {
            frame: TunnelFrame {
                session: session_id,
                seq,
                kind: TunnelFrameKind::Data,
                payload: buf[..n].to_vec(),
            },
        };
        seq += 1;
        if let Err(e) = send_and_await(&network, &results, peer, req, &mut socket).await {
            warn!(%peer, session_id, error = %e, "cluster-serving: head data exchange failed");
            break;
        }
    }

    // Best-effort close.
    let close = ClusterTunnelRequest {
        frame: TunnelFrame {
            session: session_id,
            seq,
            kind: TunnelFrameKind::Close,
            payload: Vec::new(),
        },
    };
    let _ = network.send_cluster_tunnel_frame(peer, close).await;
    debug!(%peer, session_id, "cluster-serving: head bridge ended");
}

/// Send one tunnel request and write the member's return frames back to the
/// loopback socket. Demultiplexes the shared result stream by request id.
async fn send_and_await(
    network: &Arc<dyn NetworkService>,
    results: &Arc<Mutex<UnboundedReceiver<OutboundClusterTunnelResult>>>,
    peer: PeerId,
    req: ClusterTunnelRequest,
    socket: &mut TcpStream,
) -> Result<(), ClusterServingError> {
    let want = network
        .send_cluster_tunnel_frame(peer, req)
        .await
        .map_err(|e| ClusterServingError::Network(e.to_string()))?;

    // Wait for the matching result. The result stream is shared across all
    // bridges, so holding the lock here serialises in-flight frames across
    // sessions: a result whose id is not ours is dropped by the `continue`,
    // which would starve a concurrent bridge. That is acceptable for the
    // single-host loopback path (the model loader drives one device connection
    // at a time during load), but multi-session concurrency requires a
    // per-session demux of this stream — the remaining step before multi-host
    // LAN validation.
    let mut rx = results.lock().await;
    loop {
        let Some(result) = rx.recv().await else {
            return Err(ClusterServingError::Network(
                "cluster-tunnel result stream closed".to_string(),
            ));
        };
        if result.request_id != want {
            continue;
        }
        return match result.result {
            Ok(ClusterTunnelResponse::Ack { return_frames }) => {
                let mut ordered = return_frames;
                ordered.sort_by_key(|f| f.seq);
                for frame in ordered {
                    if frame.payload.is_empty() {
                        continue;
                    }
                    socket
                        .write_all(&frame.payload)
                        .await
                        .map_err(|e| ClusterServingError::Socket(e.to_string()))?;
                }
                Ok(())
            }
            Ok(ClusterTunnelResponse::Error(e)) => {
                Err(ClusterServingError::Network(e.to_string()))
            }
            Err(transport) => Err(ClusterServingError::Network(transport.to_string())),
        };
    }
}

/// Connect to a loopback `host:port`, retrying briefly while the peer process
/// binds its listener.
async fn connect_with_retry(addr: &str) -> Result<TcpStream, ClusterServingError> {
    const ATTEMPTS: u32 = 50;
    for _ in 0..ATTEMPTS {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    Err(ClusterServingError::Socket(format!(
        "could not connect to {addr} after {ATTEMPTS} attempts"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::model::PipelineStage;
    use tenzro_types::primitives::Address;

    fn stage(endpoint: &str) -> LaunchStage {
        LaunchStage {
            address: Address::new([1u8; 32]),
            stage: PipelineStage {
                start_layer: 0,
                end_layer: 8,
            },
            local_endpoint: endpoint.to_string(),
        }
    }

    #[test]
    fn parse_member_peer_extracts_suffix() {
        let pid = PeerId::random();
        let s = stage(&format!("10.0.0.5:50052#{pid}"));
        assert_eq!(parse_member_peer(&s).unwrap(), pid);
    }

    #[test]
    fn parse_member_peer_rejects_missing_suffix() {
        let s = stage("10.0.0.5:50052");
        assert!(parse_member_peer(&s).is_err());
    }

    #[test]
    fn parse_member_peer_rejects_garbage_suffix() {
        let s = stage("10.0.0.5:50052#not-a-peer-id");
        assert!(parse_member_peer(&s).is_err());
    }
}
