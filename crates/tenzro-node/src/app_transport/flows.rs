//! Datagrams between the two devices of a carried stream.
//!
//! Each session numbers the flows of its device. When a stream between two
//! devices of this node is accepted, each end's flow is routed to the other
//! end's session under the other end's number, for as long as the stream is
//! carried. A datagram the meter will not let through at once is dropped:
//! datagrams carry what is stale by the time it could wait.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::Mutex;
use tenzro_iroh::app_stream::{ByteMeter, decode_datagram, encode_datagram};
use wtransport::Connection;

/// Where datagrams on one flow go.
struct Route {
    peer: Connection,
    peer_flow: u32,
    /// The identity the stream is counted against: its opener.
    payer: String,
    /// Whether this end is the opener's (its datagrams count as sent).
    sent: bool,
}

/// The flows of one session.
#[derive(Default)]
pub(crate) struct Flows {
    next: AtomicU32,
    routes: Mutex<HashMap<u32, Route>>,
}

impl Flows {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A number for a new flow of this session.
    pub(crate) fn allocate(&self) -> u32 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Forwards a datagram the session's device sent, counting it against
    /// the stream's opener; drops it when its flow is unknown or the meter
    /// has no room for it now.
    pub(crate) fn forward(&self, meter: &ByteMeter, datagram: &[u8]) {
        let Some((flow, payload)) = decode_datagram(datagram) else {
            return;
        };
        let routes = self.routes.lock();
        let Some(route) = routes.get(&flow) else {
            return;
        };
        if meter.try_datagram(&route.payer, route.sent, payload.len() as u64) {
            let _ = route
                .peer
                .send_datagram(encode_datagram(route.peer_flow, payload));
        }
    }
}

/// One end of a flow: the session's connection, its flows and the number.
pub(crate) struct FlowSide {
    pub(crate) connection: Connection,
    pub(crate) flows: Arc<Flows>,
    pub(crate) id: u32,
}

/// Two ends routed to each other until dropped.
pub(crate) struct Linked {
    opener: (Arc<Flows>, u32),
    target: (Arc<Flows>, u32),
}

impl Linked {
    /// Routes `opener`'s flow to `target`'s and back, counting both ways
    /// against `payer`.
    pub(crate) fn new(payer: &str, opener: FlowSide, target: FlowSide) -> Self {
        opener.flows.routes.lock().insert(
            opener.id,
            Route {
                peer: target.connection.clone(),
                peer_flow: target.id,
                payer: payer.to_string(),
                sent: true,
            },
        );
        target.flows.routes.lock().insert(
            target.id,
            Route {
                peer: opener.connection,
                peer_flow: opener.id,
                payer: payer.to_string(),
                sent: false,
            },
        );
        Self {
            opener: (opener.flows, opener.id),
            target: (target.flows, target.id),
        }
    }
}

impl Drop for Linked {
    fn drop(&mut self) {
        self.opener.0.routes.lock().remove(&self.opener.1);
        self.target.0.routes.lock().remove(&self.target.1);
    }
}
