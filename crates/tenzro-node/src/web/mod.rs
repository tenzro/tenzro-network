//! Web Verification API — HTTP/REST endpoints for browser/external verification

#[cfg(feature = "edge-tls")]
pub mod edge_tls;
pub mod error;
pub mod handlers;
pub mod oauth;
pub mod passkey_auth;
pub mod server;
pub mod sites;
pub mod siwt;
pub mod types;
pub mod universal_resolver;
pub mod wallet_frost;
pub mod wallet_mldsa;
pub mod wallet_new;
pub mod passkey_registry;
pub mod wallet_share;

pub use server::WebServer;
