//! Network awaits that take the time they may wait.
//!
//! A dial that never completes, a stream a peer never accepts, or a permit
//! that is never returned holds its task, and whatever that task guards, for
//! good. The workspace's clippy configuration (`disallowed-methods` in
//! `clippy.toml`) refuses those calls everywhere but in this module, and
//! every function here takes its bound, so an await on a peer without one
//! does not pass the lint.
#![expect(
    clippy::disallowed_methods,
    reason = "this module holds the bounded wrappers around the calls the lint refuses elsewhere"
)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::{IrohError, IrohResult};

/// The bound on a dial or a stream open whose caller sets none of its own:
/// longer than every caller's own timeout (the consensus dial's is 20 s),
/// so it only ends a wait that nothing else would.
pub const BACKSTOP: Duration = Duration::from_secs(60);

/// `fut`, or an error naming `what` once `limit` has passed.
pub async fn bounded<T>(
    limit: Duration,
    what: &str,
    fut: impl Future<Output = T>,
) -> IrohResult<T> {
    tokio::time::timeout(limit, fut).await.map_err(|_| {
        IrohError::Backend(format!(
            "{what} did not finish within {} ms",
            limit.as_millis()
        ))
    })
}

/// Dials `peer` on `alpn` within `limit`.
pub async fn connect(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
    alpn: &[u8],
    limit: Duration,
) -> IrohResult<Connection> {
    bounded(limit, "the dial", endpoint.connect(peer, alpn))
        .await?
        .map_err(|e| IrohError::Backend(format!("connect: {e}")))
}

/// Opens a bidirectional stream on `conn` within `limit`.
pub async fn open_bi(conn: &Connection, limit: Duration) -> IrohResult<(SendStream, RecvStream)> {
    bounded(limit, "opening a stream", conn.open_bi())
        .await?
        .map_err(|e| IrohError::Backend(format!("open stream: {e}")))
}

/// Takes `n` permits of `semaphore` within `limit`.
pub async fn acquire_many(
    semaphore: &Arc<Semaphore>,
    n: u32,
    limit: Duration,
) -> IrohResult<OwnedSemaphorePermit> {
    bounded(
        limit,
        "waiting for a permit",
        semaphore.clone().acquire_many_owned(n),
    )
    .await?
    .map_err(|_| IrohError::Backend("the semaphore is closed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_future_that_finishes_in_time_gives_its_value() {
        let got = bounded(Duration::from_secs(5), "an answer", async { 7 }).await;
        assert_eq!(got.unwrap(), 7);
    }

    #[tokio::test]
    async fn a_future_that_never_finishes_ends_with_an_error_naming_the_wait() {
        let never = std::future::pending::<()>();
        let err = bounded(Duration::from_millis(20), "the dial", never)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("the dial did not finish within 20 ms"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn permits_are_taken_while_enough_are_free_and_the_wait_for_more_is_bounded() {
        let semaphore = Arc::new(Semaphore::new(3));
        let held = acquire_many(&semaphore, 2, Duration::from_secs(5))
            .await
            .unwrap();
        let err = acquire_many(&semaphore, 2, Duration::from_millis(20))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("waiting for a permit"), "{err}");
        drop(held);
        let again = acquire_many(&semaphore, 3, Duration::from_secs(5))
            .await
            .unwrap();
        drop(again);

        semaphore.close();
        let err = acquire_many(&semaphore, 1, Duration::from_secs(5))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("closed"), "{err}");
    }
}
