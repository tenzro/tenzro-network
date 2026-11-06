//! RFC 9421 HTTP Message Signatures implementation
//!
//! Provides HTTP message signature verification and creation per RFC 9421.
//! The node signs and checks the HTTP requests agents send with it.
//!
//! # Components
//!
//! - **signature** — RFC 9421 signature parsing, creation, and verification
//! - **nonce** — Nonce cache for replay attack prevention
//! - **registry** — Agent public key registry abstraction for key lookup
//! - **agent** — the Tenzro agent request profile: signing and verification

pub mod agent;
pub mod nonce;
pub mod registry;
pub mod signature;

pub use nonce::NonceCache;
pub use registry::{AgentPublicKeyInfo, AgentRegistryClient, TenzroAgentRegistry};
pub use signature::{
    HttpSigner, RequestParts, SignatureAlgorithm, SignatureInput, SignatureParams, SignedHeaders,
    build_signature_base, create_http_signature, parse_signature_input, verify_http_signature,
};
