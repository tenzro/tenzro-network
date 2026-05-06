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

pub mod signature;
pub mod nonce;
pub mod registry;
pub mod jwks;

pub use signature::{
    SignatureAlgorithm,
    SignatureParams,
    SignatureInput,
    RequestParts,
    SignedHeaders,
    parse_signature_input,
    build_signature_base,
    verify_http_signature,
    create_http_signature,
};
pub use nonce::NonceCache;
pub use registry::{AgentRegistryClient, AgentPublicKeyInfo, TenzroAgentRegistry};
pub use jwks::{Jwk, JwkSet};
