//! Web Verification API — HTTP/REST endpoints for browser/external verification

pub mod error;
pub mod handlers;
pub mod oauth;
pub mod passkey_auth;
pub mod passkey_register;
pub mod passkey_registry;
pub mod server;
pub mod types;
pub mod universal_resolver;

pub use server::WebServer;
