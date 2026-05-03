//! Network error types for Tenzro Network

use thiserror::Error;

/// Network-specific errors
#[derive(Error, Debug)]
pub enum NetworkError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// libp2p transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Invalid message
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Gossipsub publish error
    #[error("Failed to publish to topic: {0}")]
    PublishError(String),

    /// Subscription error
    #[error("Subscription error: {0}")]
    SubscriptionError(String),

    /// DHT error
    #[error("DHT error: {0}")]
    DhtError(String),

    /// Peer banned
    #[error("Peer is banned: {0}")]
    PeerBanned(String),

    /// Maximum peers reached
    #[error("Maximum peers reached")]
    MaxPeersReached,

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Channel send error
    #[error("Channel send error")]
    ChannelSend,

    /// Channel receive error
    #[error("Channel receive error")]
    ChannelReceive,

    /// Service not started
    #[error("Service not started")]
    ServiceNotStarted,

    /// Service already running
    #[error("Service already running")]
    ServiceAlreadyRunning,

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Protocol not supported
    #[error("Protocol not supported: {0}")]
    ProtocolNotSupported(String),
}

/// Result type for network operations
pub type Result<T> = std::result::Result<T, NetworkError>;
