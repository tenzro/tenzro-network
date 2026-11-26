//! One device's session with the app transport.

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tenzro_iroh::app_stream::{
    EXPORTER_BYTES, EXPORTER_LABEL, Frame, Usage, read_frame, sign_in_htu, sign_in_htu_bound,
    welcome_digest, write_frame,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tokio::task::JoinSet;
use tokio::time::timeout;
use wtransport::endpoint::IncomingSession;
use wtransport::stream::OpeningBiStream;
use wtransport::{Connection, RecvStream, SendStream, VarInt};

use super::devices::{Offer, Opening};
use super::flows::{FlowSide, Flows, Linked};
use super::{Admitted, Carried, Hold, Pending, Pipe, Refusal, Shared};

/// How long a device has to connect and sign in.
const SIGN_IN_WAIT: Duration = Duration::from_secs(10);

/// How long the first frame of a stream is waited for.
const HEAD_WAIT: Duration = Duration::from_secs(10);

/// How long a device has to accept or decline a stream offered to it.
const ANSWER_WAIT: Duration = Duration::from_secs(30);

/// How long a refusal is given to reach the device.
const LAST_WORD_WAIT: Duration = Duration::from_secs(2);

/// Serves one incoming connection until its session ends.
pub(super) async fn serve(
    shared: Arc<Shared>,
    incoming: IncomingSession,
    _connection: OwnedSemaphorePermit,
    pending: Pending,
) {
    let Ok(Ok(request)) = timeout(SIGN_IN_WAIT, incoming.into_future()).await else {
        return;
    };
    if request.path() != shared.path {
        request.not_found().await;
        return;
    }
    let Ok(connection) = request.accept().await else {
        return;
    };
    let ended = session(&shared, &connection, pending).await;
    connection.close(VarInt::from_u32(0), ended.as_bytes());
}

fn until(expires_at: u64) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Duration::from_secs(expires_at.saturating_sub(now))
}

/// The URI a sign-in proof on `connection` must name: the session's
/// `nonce`, and with a `binding` the keying material both ends export from
/// this TLS session, which the device's must match.
fn proof_htu(
    connection: &Connection,
    nonce: &str,
    binding: Option<&str>,
) -> Result<String, String> {
    let Some(claimed) = binding else {
        return Ok(sign_in_htu(nonce));
    };
    let mut ours = [0u8; EXPORTER_BYTES];
    connection
        .export_keying_material(&mut ours, EXPORTER_LABEL, nonce.as_bytes())
        .map_err(|_| "this session exports no keying material".to_string())?;
    let ours = hex::encode(ours);
    if claimed != ours {
        return Err("the binding is not this session's".to_string());
    }
    Ok(sign_in_htu_bound(nonce, &ours))
}

/// A signed-in control stream, and what a paying device's credential bought.
type SignedIn = (SendStream, RecvStream, Admitted, Option<Hold>);

/// Sends the challenge on a new control stream and reads the device's
/// answer to it: a hello, or when the access policy asks payment, a hello,
/// the node's payment challenge, and a hello carrying the payment.
async fn sign_in(
    shared: &Shared,
    connection: &Connection,
    nonce: &str,
) -> Result<SignedIn, String> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let challenge = Frame::Challenge {
        nonce: nonce.to_string(),
    };
    write_frame(&mut send, &challenge)
        .await
        .map_err(|e| e.to_string())?;
    let mut quoted = false;
    loop {
        let Ok(Frame::Hello {
            access_token,
            dpop,
            payment,
            binding,
        }) = read_frame(&mut recv).await
        else {
            return Err("sign in first".to_string());
        };
        let htu = match proof_htu(connection, nonce, binding.as_deref()) {
            Ok(htu) => htu,
            Err(reason) => {
                refuse(&mut send, reason.clone()).await;
                return Err(reason);
            }
        };
        let refusal = match shared.sign_in.admit(&htu, &access_token, &dpop) {
            Ok(admitted) => return Ok((send, recv, admitted, None)),
            Err(Refusal::No(reason)) => reason,
            Err(Refusal::Pay {
                admitted,
                price,
                asset,
            }) => match payment {
                Some(credential) => match shared.payments.hold(&credential, &price, &asset).await {
                    Ok(hold) => return Ok((send, recv, admitted, Some(hold))),
                    Err(reason) => reason,
                },
                None if !quoted => match shared.payments.quote(&price, &asset).await {
                    Ok(challenge) => {
                        quoted = true;
                        let required = Frame::PaymentRequired {
                            challenge,
                            price,
                            asset,
                        };
                        write_frame(&mut send, &required)
                            .await
                            .map_err(|e| e.to_string())?;
                        continue;
                    }
                    Err(reason) => reason,
                },
                None => "pay to sign in".to_string(),
            },
        };
        refuse(&mut send, refusal.clone()).await;
        return Err(refusal);
    }
}

/// A paid session: holds its identity to the bytes it paid for, and charges
/// what was carried when it ends, however it ends.
struct Paid {
    shared: Arc<Shared>,
    did: String,
    hold: Option<Hold>,
    /// What the identity had been carried when the session began.
    before: u64,
}

const MEBIBYTE: u64 = 1 << 20;

fn carried(usage: Usage) -> u64 {
    usage.bytes_sent + usage.bytes_received
}

impl Paid {
    /// Starts paying for `did`, unless it already pays in another session.
    fn begin(shared: &Arc<Shared>, did: &str, hold: Hold) -> Result<Self, String> {
        if !shared.paying.lock().insert(did.to_string()) {
            return Err(format!("{did} already pays for another session here"));
        }
        shared.meter.set_budget(did, hold.bytes);
        Ok(Self {
            shared: shared.clone(),
            did: did.to_string(),
            before: carried(shared.meter.usage(did)),
            hold: Some(hold),
        })
    }
}

impl Drop for Paid {
    fn drop(&mut self) {
        let meter = &self.shared.meter;
        let bytes = carried(meter.usage(&self.did)).saturating_sub(self.before);
        meter.lift_budget(&self.did);
        self.shared.paying.lock().remove(&self.did);
        if let Some(hold) = self.hold.take() {
            let payments = self.shared.payments.clone();
            tokio::spawn(async move {
                payments.settle(hold, bytes.div_ceil(MEBIBYTE)).await;
            });
        }
    }
}

/// The welcome for `did` on `device` until `expires_at`, signed by the node
/// over the session's `nonce`.
async fn welcome(
    shared: &Arc<Shared>,
    nonce: &str,
    did: &str,
    device: &str,
    expires_at: u64,
) -> Result<Frame, String> {
    let digest = welcome_digest(nonce, did, device, expires_at);
    let sign_in = shared.sign_in.clone();
    let vouch = tokio::task::spawn_blocking(move || sign_in.vouch(&digest))
        .await
        .map_err(|e| format!("signing the welcome stopped: {e}"))??;
    Ok(Frame::Welcome {
        did: did.to_string(),
        device: device.to_string(),
        expires_at,
        signature: vouch.signature,
        pq_signature: vouch.pq_signature,
    })
}

/// Runs a session and says why it ended.
async fn session(shared: &Arc<Shared>, connection: &Connection, pending: Pending) -> String {
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let (mut control, control_recv, admitted, hold) =
        match timeout(SIGN_IN_WAIT, sign_in(shared, connection, &nonce)).await {
            Ok(Ok(signed_in)) => signed_in,
            Ok(Err(reason)) => return reason,
            Err(_) => return "signing in took too long".to_string(),
        };
    // Signed in: no longer held against its address's unsigned connections.
    drop(pending);
    let Admitted {
        did,
        device,
        mut expires_at,
    } = admitted;
    let paid = match hold.map(|hold| Paid::begin(shared, &did, hold)).transpose() {
        Ok(paid) => paid,
        Err(reason) => {
            refuse(&mut control, reason.clone()).await;
            return reason;
        }
    };
    let (place, mut offers) = match shared.devices.sign_in(&did, &device) {
        Ok(signed_in) => signed_in,
        Err(reason) => {
            refuse(&mut control, reason.clone()).await;
            return reason;
        }
    };
    let first = match welcome(shared, &nonce, &did, &device, expires_at).await {
        Ok(first) => first,
        Err(reason) => {
            refuse(&mut control, reason.clone()).await;
            return reason;
        }
    };
    if write_frame(&mut control, &first).await.is_err() {
        return "the device went away".to_string();
    }

    // Tasks of this session; all end with it.
    let flows = Flows::new();
    let mut datagrams = true;
    let mut tasks = JoinSet::new();
    let (frames, mut control_frames) = mpsc::channel(4);
    tasks.spawn(read_control(control_recv, frames));
    loop {
        tokio::select! {
            frame = control_frames.recv() => match frame {
                Some(Frame::Listen { from, apps }) => {
                    place.listen(from, apps);
                    if write_frame(&mut control, &Frame::Listening).await.is_err() {
                        return "the device went away".to_string();
                    }
                }
                Some(Frame::Hello { access_token, dpop, binding, .. }) => {
                    let htu = match proof_htu(connection, &nonce, binding.as_deref()) {
                        Ok(htu) => htu,
                        Err(reason) => return reason,
                    };
                    let again = match shared.sign_in.admit(&htu, &access_token, &dpop) {
                        Ok(again) => Ok(again),
                        // A paid session goes on under the payment it holds.
                        Err(Refusal::Pay { admitted, .. }) if paid.is_some() => Ok(admitted),
                        Err(Refusal::Pay { .. }) => Err("pay to keep the session".to_string()),
                        Err(Refusal::No(reason)) => Err(reason),
                    };
                    match again {
                        Ok(again) if again.did == did && again.device == device => {
                            expires_at = again.expires_at;
                            let renewed =
                                match welcome(shared, &nonce, &did, &device, expires_at).await {
                                    Ok(renewed) => renewed,
                                    Err(reason) => return reason,
                                };
                            if write_frame(&mut control, &renewed).await.is_err() {
                                return "the device went away".to_string();
                            }
                        }
                        Ok(_) => {
                            return "a session keeps the identity and device it began with"
                                .to_string();
                        }
                        Err(reason) => return reason,
                    }
                }
                Some(_) => return "that frame does not belong on the control stream".to_string(),
                None => return "the control stream ended".to_string(),
            },
            _ = tokio::time::sleep(until(expires_at)) => {
                return "the access token ran out".to_string();
            }
            closed = connection.closed() => return closed.to_string(),
            opened = connection.accept_bi() => match opened {
                Ok((send, recv)) => {
                    let side = (connection.clone(), flows.clone());
                    tasks.spawn(open(shared.clone(), did.clone(), device.clone(), side, send, recv));
                }
                Err(e) => return e.to_string(),
            },
            offer = offers.recv() => match offer {
                Some(offer) => match connection.open_bi().await {
                    Ok(opening) => {
                        tasks.spawn(deliver(opening, offer, (connection.clone(), flows.clone())));
                    }
                    Err(e) => return e.to_string(),
                },
                None => return "the device signed in again".to_string(),
            },
            datagram = connection.receive_datagram(), if datagrams => match datagram {
                Ok(datagram) => flows.forward(&shared.meter, &datagram.payload()),
                // A device that cannot send datagrams still has its streams.
                Err(_) => datagrams = false,
            },
            Some(_) = tasks.join_next() => {}
        }
    }
}

/// Hands the frames of the control stream to the session, whole.
async fn read_control(mut recv: RecvStream, frames: mpsc::Sender<Frame>) {
    while let Ok(frame) = read_frame(&mut recv).await {
        if frames.send(frame).await.is_err() {
            return;
        }
    }
}

/// Ends a stream with a refusal.
async fn refuse(send: &mut SendStream, reason: impl Into<String>) {
    let refused = Frame::Refused {
        reason: reason.into(),
    };
    if write_frame(send, &refused).await.is_ok() && send.finish().await.is_ok() {
        // Let the refusal reach the device before whatever follows closes
        // the stream's connection.
        let _ = timeout(LAST_WORD_WAIT, send.stopped()).await;
    }
}

/// Serves a stream the device opened: offers it to the device it asks for
/// and, once that device accepts, carries it.
async fn open(
    shared: Arc<Shared>,
    did: String,
    device: String,
    side: (Connection, Arc<Flows>),
    mut send: SendStream,
    mut recv: RecvStream,
) {
    let Ok(Ok(Frame::Open {
        to,
        device: wanted,
        via,
        app,
    })) = timeout(HEAD_WAIT, read_frame(&mut recv)).await
    else {
        return refuse(&mut send, "a stream starts with an open frame").await;
    };
    let Some(_open) = shared.streams.admit(did.clone()) else {
        return refuse(
            &mut send,
            "you have as many streams open as one identity may",
        )
        .await;
    };
    if let Some(node) = via {
        let Some(between) = shared.between.as_ref() else {
            return refuse(
                &mut send,
                "this node carries streams to devices signed in to it only",
            )
            .await;
        };
        if let Err(unreached) = shared.devices.count_open(&did, Instant::now()) {
            return refuse(&mut send, unreached.to_string()).await;
        }
        let (mut from_node, mut to_node) = match timeout(HEAD_WAIT, between.peers.dial(&node)).await
        {
            Ok(Ok(pipe)) => pipe,
            Ok(Err(why)) => return refuse(&mut send, why).await,
            Err(_) => return refuse(&mut send, format!("{node} did not answer")).await,
        };
        let carry = Frame::Carry {
            from: did.clone(),
            from_device: device,
            to,
            device: wanted,
            app,
        };
        if write_frame(&mut to_node, &carry).await.is_err() {
            return refuse(&mut send, format!("{node} did not take the stream")).await;
        }
        let reached = match timeout(ANSWER_WAIT + HEAD_WAIT, read_frame(&mut from_node)).await {
            Ok(Ok(Frame::Opened { device, .. })) => device,
            Ok(Ok(Frame::Refused { reason })) => return refuse(&mut send, reason).await,
            _ => return refuse(&mut send, "the device did not take the stream").await,
        };
        if write_frame(
            &mut send,
            &Frame::Opened {
                device: reached,
                flow: None,
            },
        )
        .await
        .is_err()
        {
            return;
        }
        shared.meter.opened(&did);
        let _ = shared
            .meter
            .carry(&did, (recv, send), (from_node, to_node))
            .await;
        return;
    }
    let offered = shared.devices.offer(
        Opening {
            from: &did,
            from_device: &device,
            to: &to,
            device: wanted.as_deref(),
            via: None,
            app: &app,
        },
        Instant::now(),
    );
    let (reached, accepted) = match offered {
        Ok(offered) => offered,
        Err(unreached) => return refuse(&mut send, unreached.to_string()).await,
    };
    let Ok(Ok((target_recv, target_send, target_side))) =
        timeout(ANSWER_WAIT + HEAD_WAIT, accepted).await
    else {
        return refuse(&mut send, "the device did not take the stream").await;
    };
    // Datagrams flow between the two ends for as long as the stream does.
    let (connection, flows) = side;
    let linked = target_side.map(|target| {
        let id = flows.allocate();
        let opener = FlowSide {
            connection,
            flows,
            id,
        };
        (id, Linked::new(&did, opener, target))
    });
    let opened = Frame::Opened {
        device: reached,
        flow: linked.as_ref().map(|(id, _)| *id),
    };
    if write_frame(&mut send, &opened).await.is_err() {
        return;
    }
    shared.meter.opened(&did);
    let _ = shared
        .meter
        .carry(&did, (recv, send), (target_recv, target_send))
        .await;
    drop(linked);
}

/// Offers a stream to this session's device on a new stream to it, and hands
/// that stream to the opener when the device accepts.
async fn deliver(opening: OpeningBiStream, offer: Offer<Carried>, side: (Connection, Arc<Flows>)) {
    let Ok(Ok((mut send, mut recv))) = timeout(HEAD_WAIT, opening).await else {
        return;
    };
    // A stream from a device of this node gets a flow; one another node
    // carried here does not.
    let (connection, flows) = side;
    let flow = offer.via.is_none().then(|| flows.allocate());
    let incoming = Frame::Incoming {
        from: offer.from.clone(),
        device: offer.from_device.clone(),
        via: offer.via.clone(),
        app: offer.app.clone(),
        flow,
    };
    if write_frame(&mut send, &incoming).await.is_err() {
        return;
    }
    if let Ok(Ok(Frame::Accept)) = timeout(ANSWER_WAIT, read_frame(&mut recv)).await {
        let side = flow.map(|id| FlowSide {
            connection,
            flows,
            id,
        });
        let _ = offer.answer.send((recv, send, side));
    }
}

/// Serves a stream the node `peer` carries here: offers it to the device it
/// asks for and, once that device accepts, carries it, counting the bytes
/// against `peer`.
pub(super) async fn serve_peer(shared: Arc<Shared>, peer: String, pipe: Pipe) {
    let (mut recv, mut send) = pipe;
    let Some(between) = shared.between.as_ref() else {
        return refuse_pipe(&mut send, "this node takes no streams from other nodes").await;
    };
    let Some(_held) = between.by_peer.admit(peer.clone()) else {
        return refuse_pipe(
            &mut send,
            "your node already carries as many streams here as it may",
        )
        .await;
    };
    let Ok(Ok(Frame::Carry {
        from,
        from_device,
        to,
        device,
        app,
    })) = timeout(HEAD_WAIT, read_frame(&mut recv)).await
    else {
        return refuse_pipe(
            &mut send,
            "a stream between nodes starts with a carry frame",
        )
        .await;
    };
    let offered = shared.devices.offer(
        Opening {
            from: &from,
            from_device: &from_device,
            to: &to,
            device: device.as_deref(),
            via: Some(peer.clone()),
            app: &app,
        },
        Instant::now(),
    );
    let (reached, accepted) = match offered {
        Ok(offered) => offered,
        Err(unreached) => return refuse_pipe(&mut send, unreached.to_string()).await,
    };
    let Ok(Ok((target_recv, target_send, _))) = timeout(ANSWER_WAIT + HEAD_WAIT, accepted).await
    else {
        return refuse_pipe(&mut send, "the device did not take the stream").await;
    };
    if write_frame(
        &mut send,
        &Frame::Opened {
            device: reached,
            flow: None,
        },
    )
    .await
    .is_err()
    {
        return;
    }
    shared.meter.opened(&peer);
    let _ = shared
        .meter
        .carry(&peer, (recv, send), (target_recv, target_send))
        .await;
}

/// Ends a stream from another node with a refusal.
async fn refuse_pipe(send: &mut (dyn AsyncWrite + Send + Unpin), reason: impl Into<String>) {
    let refused = Frame::Refused {
        reason: reason.into(),
    };
    if write_frame(send, &refused).await.is_ok() {
        let _ = send.shutdown().await;
    }
}
