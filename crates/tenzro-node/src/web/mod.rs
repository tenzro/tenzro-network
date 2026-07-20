//! Web Verification API — HTTP/REST endpoints for browser/external verification

pub mod error;
pub mod server;
pub mod handlers;
pub mod oauth;
pub mod passkey_auth;
pub mod sites;
pub mod siwt;
pub mod types;
pub mod universal_resolver;
pub mod wallet_frost;
pub mod wallet_mldsa;
pub mod wallet_new;
pub mod wallet_share;

pub use server::WebServer;
