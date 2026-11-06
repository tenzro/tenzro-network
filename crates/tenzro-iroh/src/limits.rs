//! How the node's endpoint bounds what an unknown peer can make it hold.
//!
//! Every protocol here that answers a peer it has not vetted takes the same
//! three bounds from [`AdmissionLimits`]: how many streams it serves at once
//! (overall and per peer), how long a peer may take to send its request, and
//! how long one part of a reply may wait for the peer to take it. A request
//! body is read as it arrives, never allocated from the length a peer
//! declares.

use std::future::Future;

use iroh::endpoint::{RecvStream, SendStream};
pub use tenzro_types::admission::{Admission, AdmissionLimits};

use crate::error::{IrohError, IrohResult};

/// Stream error code for a stream refused because its surface or its peer is
/// at its bound.
pub(crate) const REFUSED_BUSY: u32 = 2;

/// Stream error code for a stream cut off because its peer was too slow.
pub(crate) const REFUSED_SLOW: u32 = 3;

/// Refuse a stream at once: nothing is read and nothing is sent.
pub(crate) fn refuse(mut send: SendStream, mut recv: RecvStream) {
    let _ = send.reset(REFUSED_BUSY.into());
    let _ = recv.stop(REFUSED_BUSY.into());
}

/// Cut a stream off once its peer has been too slow.
pub(crate) fn cut_off(send: &mut SendStream, recv: &mut RecvStream) {
    let _ = send.reset(REFUSED_SLOW.into());
    let _ = recv.stop(REFUSED_SLOW.into());
}

/// Run `fut`, failing with `what` once `limit` passes.
pub(crate) async fn within<T>(
    limit: std::time::Duration,
    what: &str,
    fut: impl Future<Output = IrohResult<T>>,
) -> IrohResult<T> {
    tokio::time::timeout(limit, fut)
        .await
        .map_err(|_| IrohError::Backend(format!("{what} took longer than {limit:?}")))?
}
