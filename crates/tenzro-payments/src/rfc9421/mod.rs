//! RFC 9421 HTTP Message Signatures implementation
//!
//! Provides HTTP message signature verification and creation per RFC 9421.
//! This module is used as the foundation for both Visa TAP and Mastercard Agent Pay.
//!
//! # Components
//!
//! - **signature** — RFC 9421 signature parsing, creation, and verification
//! - **nonce** — Nonce cache for replay attack prevention
//! - **registry** — Agent public key registry abstraction for key lookup
//! - **jwks** — JWK / JWK Set publication per RFC 7517 / RFC 7518

pub mod jwks;
pub mod nonce;
pub mod registry;
pub mod signature;
pub mod web_bot_auth;

pub use jwks::{Jwk, JwkSet};
pub use nonce::NonceCache;
pub use registry::{AgentPublicKeyInfo, AgentRegistryClient, TenzroAgentRegistry};
pub use signature::{
    RequestParts, SignatureAlgorithm, SignatureInput, SignatureParams, SignedHeaders,
    build_signature_base, create_http_signature, parse_signature_input, verify_http_signature,
};
