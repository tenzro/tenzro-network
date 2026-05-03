//! libp2p transport setup for Tenzro Network.
//!
//! TCP authentication uses **libp2p-tls** (rustls + aws-lc-rs) so the
//! handshake inherits the `X25519MLKEM768` hybrid post-quantum key exchange
//! group. libp2p-noise is *not* used — it has no upstream PQ path. Callers
//! must have installed `aws-lc-rs` as the rustls default `CryptoProvider`
//! before any transport is built (done at process start in
//! `tenzro-node::main`).
//!
//! QUIC keeps using `libp2p::quic` which is rustls-backed under the hood and
//! inherits the same `aws-lc-rs` provider.

use crate::error::{NetworkError, Result};
use libp2p::{
    core::upgrade,
    identity::Keypair,
    yamux, PeerId, Transport,
};
use std::time::Duration;

/// Builds the libp2p transport stack
///
/// This creates a transport that supports:
/// - TCP with **TLS** (rustls + aws-lc-rs, PQ-hybrid X25519MLKEM768) and Yamux multiplexing
/// - QUIC (rustls under the hood, inherits the same PQ-hybrid CryptoProvider)
pub fn build_transport(
    keypair: &Keypair,
) -> Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>> {
    // TCP transport
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true));

    // TLS authentication (rustls + aws-lc-rs → PQ-hybrid X25519MLKEM768).
    let tls_config = libp2p::tls::Config::new(keypair)
        .map_err(|e| NetworkError::Transport(format!("Failed to create TLS config: {}", e)))?;

    // Yamux multiplexing
    let yamux_config = yamux::Config::default();

    // Build authenticated + multiplexed TCP transport. We use `V1Lazy` so the
    // TLS handshake can begin immediately after multistream-select picks
    // `/tls/1.0.0`, mirroring rust-libp2p's recommended pattern.
    let tcp_transport = tcp
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(tls_config)
        .multiplex(yamux_config)
        .timeout(Duration::from_secs(20));

    // QUIC transport (has built-in encryption and multiplexing)
    let quic = libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(keypair));

    // Combine transports with DNS support
    let transport = libp2p::dns::tokio::Transport::system(
        tcp_transport.or_transport(quic)
    )
    .map_err(|e| NetworkError::Transport(format!("Failed to create DNS transport: {}", e)))?
    .map(|either, _| match either {
        futures::future::Either::Left((peer_id, muxer)) => (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer)),
        futures::future::Either::Right((peer_id, muxer)) => (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer)),
    });

    Ok(transport.boxed())
}

/// Builds a development transport (simpler, for local testing)
pub fn build_development_transport(
    keypair: &Keypair,
) -> Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>> {
    // TCP only for development
    let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true));

    // TLS authentication (rustls + aws-lc-rs).
    let tls_config = libp2p::tls::Config::new(keypair)
        .map_err(|e| NetworkError::Transport(format!("Failed to create TLS config: {}", e)))?;

    // Yamux multiplexing
    let yamux_config = yamux::Config::default();

    // Build transport
    let transport = tcp
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(tls_config)
        .multiplex(yamux_config)
        .timeout(Duration::from_secs(20))
        .boxed();

    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_creation() {
        let keypair = Keypair::generate_ed25519();
        let transport = build_transport(&keypair);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_development_transport_creation() {
        let keypair = Keypair::generate_ed25519();
        let transport = build_development_transport(&keypair);
        assert!(transport.is_ok());
    }
}
