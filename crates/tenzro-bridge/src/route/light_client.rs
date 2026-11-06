//! The light-client verifier interface.
//!
//! A route may require, on top of its committees, a proof that the external
//! chain itself finalized the delivered message: a light client of that
//! chain (for example Ethereum's sync committee), verified on Tenzro. The
//! route names the kind of light client and its trusted starting point (its
//! [`LightClientAnchor`]); the framework calls the verifier installed for
//! that kind with the hash of the delivered body and the proof the delivery
//! carries. The light client's own state (the committee it currently
//! follows) lives in route state, keyed by the route and the anchor, and
//! moves forward only through [`LightClientVerifier::advance`], which anyone
//! may call with an update the external chain itself signed. With no
//! verifier installed, a route that requires one admits nothing.

use serde::Serialize;

use super::state::RouteState;
use super::{BridgeRoute, LightClientAnchor, LightClientKind};
use crate::error::Result;

/// Where a route's light client stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LightClientHead {
    /// The light client's kind, as a stable name.
    pub kind: &'static str,
    /// The latest finalized position of the external chain it has verified
    /// (a beacon slot for Ethereum).
    pub finalized: u64,
    /// The committee period it verifies signatures for.
    pub period: u64,
    /// Whether it already knows the next period's committee.
    pub next_known: bool,
}

/// Verifies that an external chain finalized a message.
pub trait LightClientVerifier: Send + Sync {
    /// The kind of light client this is.
    fn kind(&self) -> LightClientKind;

    /// Accept `proof` only if it shows that the chain `route` names finalized
    /// a message whose body hashes (Keccak-256) to `body_hash`, emitted by
    /// the route's ramp, as checked against the light-client state that
    /// `anchor` started.
    fn verify(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        body_hash: &[u8; 32],
        proof: &[u8],
    ) -> Result<()>;

    /// Accept `proof` only if it shows that the chain `route` names finalized
    /// an event emitted by the route's settlement lock `lock` (a leg's
    /// `Locked` event or the lock's reconciliation checkpoint), and return
    /// it.
    fn proven_lock_record(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        lock: &[u8; 32],
        proof: &[u8],
    ) -> Result<super::receipt_proof::LockRecord>;

    /// Move the light client forward with `update`: its bootstrap from the
    /// anchor, or a committee handover the current committee signed.
    fn advance(
        &self,
        state: &mut dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        update: &[u8],
    ) -> Result<LightClientHead>;

    /// Where the light client stands, if it has been bootstrapped.
    fn head(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
    ) -> Option<LightClientHead>;
}
