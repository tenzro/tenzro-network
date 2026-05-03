//! Web Verification API — HTTP/REST endpoints for browser/external verification

pub mod server;
pub mod handlers;
pub mod oauth;
pub mod types;
pub mod wallet_frost;
pub mod wallet_mldsa;
pub mod wallet_share;

pub use server::WebServer;
