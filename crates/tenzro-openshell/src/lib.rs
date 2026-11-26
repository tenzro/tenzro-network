//! OpenShell extensions backed by Tenzro.
//!
//! OpenShell runs the agent in its sandbox; Tenzro decides what the agent may
//! do, records what it did and settles what it spent. Each module is one
//! OpenShell extension point, implemented against OpenShell's own generated
//! contract types:
//!
//! - [`credential_driver`]: provider credentials are short-lived tokens minted
//!   under the agent's Terms, refused once the agent or its root is revoked.
//! - [`interceptor`]: sandbox creation and policy changes are checked against
//!   the delegating account's Terms.
//! - [`middleware`]: every allow or deny decision and every network or tool
//!   call becomes a signed record, and a `402 Payment Required` from any
//!   service is answered with a payment inside the Terms.
//! - [`provider`]: the OpenAI-compatible Tenzro endpoint a sandbox reaches
//!   through `providers/tenzro.yaml`, settled per call against a signed
//!   receipt.
//! - [`attestation`]: the host the sandbox runs on is verified through
//!   `tenzro-tee`, and the result is bound into every record.
//!
//! What the extensions ask of Tenzro goes through [`authority::Authority`],
//! which reads each agent's delegation from a running Tenzro node
//! ([`node::NodeDelegations`]). Every call into an extension is
//! authenticated as the gateway's or a supervisor's ([`gateway_auth`]).

pub mod attestation;
pub mod authority;
pub mod credential_driver;
pub mod gateway_auth;
pub mod interceptor;
pub mod middleware;
pub mod node;
pub mod payments;
pub mod peer;
pub mod provider;
pub mod records;
pub mod token;

/// OpenShell's generated contract types, as this crate was built against
/// them.
pub use openshell_core::proto as openshell;

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    tenzro_crypto::session::now_ms()
}

/// SHA-256 of `parts`, each length-prefixed, under `domain`.
pub fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// Test support: a record signer over a hardware batch that signs at once.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Arc;
    use tenzro_crypto::batch::{BatchParams, BatchService, RecordSignature, RecordSigner};
    use tenzro_crypto::composite::CompositePublicKey;
    use tenzro_crypto::composite::testing::TestHybridSigner;

    pub struct Immediate(pub Arc<BatchService>);

    impl Immediate {
        pub fn new(seed: u8) -> Self {
            Self(Arc::new(
                BatchService::new(
                    Arc::new(TestHybridSigner::hybrid(seed)),
                    BatchParams {
                        max_batch: 8,
                        flush_interval_ms: 1_000,
                    },
                    0,
                )
                .unwrap(),
            ))
        }
    }

    impl RecordSigner for Immediate {
        fn identity(&self) -> &CompositePublicKey {
            self.0.identity()
        }
        fn sign_record(&self, m: &[u8]) -> tenzro_crypto::Result<RecordSignature> {
            self.0
                .sign_now(m.to_vec(), tenzro_crypto::session::now_ms())
                .map(RecordSignature::batched)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Each part is length-prefixed and the domain is bound, so no two
    /// different inputs share a digest by moving bytes between parts or
    /// between the domain and the parts.
    #[test]
    fn a_digest_binds_its_domain_and_where_each_part_ends() {
        let d = digest(b"tenzro/test", &[b"ab", b"c"]);
        assert_eq!(d, digest(b"tenzro/test", &[b"ab", b"c"]));
        assert_ne!(d, digest(b"tenzro/test", &[b"a", b"bc"]));
        assert_ne!(d, digest(b"tenzro/test", &[b"abc"]));
        assert_ne!(d, digest(b"tenzro/test", &[b"ab", b"c", b""]));
        assert_ne!(d, digest(b"tenzro/tes", &[b"tab", b"c"]));
        assert_ne!(d, digest(b"tenzro/other", &[b"ab", b"c"]));
    }

    /// The layout is SHA-256 over little-endian u64 lengths before the
    /// domain and each part: signatures over it outlive any one build.
    #[test]
    fn a_digest_is_sha256_over_length_prefixed_domain_and_parts() {
        let mut h = Sha256::new();
        for p in [&b"d"[..], b"xy", b""] {
            h.update((p.len() as u64).to_le_bytes());
            h.update(p);
        }
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(digest(b"d", &[b"xy", b""]), want);
    }
}
