//! Verifiable-inference commitments (TOPLOC).
//!
//! Moved into `praecise-runtime` as a general engine capability; this module
//! re-exports it so existing `crate::toploc::…` paths keep working while the
//! definitions live in one place (the runtime library, not the consumer).
pub use praecise_runtime::toploc::*;
