//! Cryptographically secure random number generator (CSPRNG) for Tenzro Network
//!
//! This module provides the canonical entry point for all cryptographic random
//! number generation in Tenzro Network. All callers should use [`secure_rng`]
//! or [`fill_random_bytes`] rather than reaching for `rand::thread_rng()`,
//! `fastrand`, or platform-specific APIs.
//!
//! # Why
//!
//! `rand::thread_rng()` is *not guaranteed* to be a CSPRNG on all platforms,
//! and historical versions of `rand` have shipped with non-cryptographic
//! defaults. Using a non-CSPRNG for AES-GCM nonces, key generation, or
//! signature randomness can leak the underlying secret.
//!
//! [`OsRng`] is a thin shim over the OS-provided CSPRNG:
//!
//! - Linux: `getrandom(2)` syscall
//! - macOS: `getentropy(2)` syscall
//! - Windows: `BCryptGenRandom`
//! - WASM: `crypto.getRandomValues`
//!
//! These are guaranteed by the OS to be cryptographically secure.
//!
//! # Self-test
//!
//! [`verify_csprng`] performs a runtime sanity check that the underlying
//! generator is producing non-trivial output. It is invoked from the unit
//! tests in this module to catch misconfigured builds (for example, if
//! `getrandom` was compiled without OS support and silently fell back to a
//! deterministic stub).

use rand::RngCore;
use rand::rngs::OsRng;

/// Returns the canonical CSPRNG used throughout Tenzro Network.
///
/// This is a stateless wrapper over [`OsRng`]. It is safe to call from any
/// thread and any context.
pub fn secure_rng() -> OsRng {
    OsRng
}

/// Fills the given buffer with cryptographically random bytes.
///
/// This is the recommended entry point for one-shot random byte generation
/// (nonces, salts, key material). Internally it pulls from the OS CSPRNG.
pub fn fill_random_bytes(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// Generates a random `[u8; N]` array.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Performs a runtime sanity check on the CSPRNG.
///
/// Returns `true` if the generator produces non-trivial output (specifically:
/// 32 random bytes that are not all zero, not all 0xFF, and contain at least
/// 8 distinct byte values).
///
/// This is intended to detect misconfigured builds where `getrandom` was
/// compiled without OS support and silently fell back to a deterministic
/// stub. It is **not** a statistical test of randomness — production builds
/// should additionally rely on the OS CSPRNG vendor's certifications
/// (FIPS 140-3, BSI AIS 31, etc.) for any cryptographic guarantees.
pub fn verify_csprng() -> bool {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);

    // All-zeros or all-0xFF is a strong indicator of a stub/uninitialized RNG.
    if buf.iter().all(|&b| b == 0) || buf.iter().all(|&b| b == 0xFF) {
        return false;
    }

    // Require at least 8 distinct byte values out of 32 — a real CSPRNG
    // satisfies this with overwhelming probability (>99.99%), while most
    // stubs (constant, counter, sequence) fail.
    let mut seen = [false; 256];
    for &b in &buf {
        seen[b as usize] = true;
    }
    let distinct = seen.iter().filter(|&&s| s).count();
    distinct >= 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_rng_produces_distinct_outputs() {
        let a: [u8; 32] = random_array();
        let b: [u8; 32] = random_array();
        assert_ne!(a, b, "two CSPRNG draws should not collide");
    }

    #[test]
    fn test_fill_random_bytes_fills_buffer() {
        let mut buf = [0u8; 64];
        fill_random_bytes(&mut buf);
        // Probability of all-zeros from a real CSPRNG is 2^-512.
        assert!(
            buf.iter().any(|&b| b != 0),
            "buffer should not be all zeros"
        );
    }

    #[test]
    fn test_verify_csprng_passes() {
        assert!(verify_csprng(), "OS CSPRNG self-test should pass");
    }

    #[test]
    fn test_repeated_verify_passes() {
        // Run the self-test multiple times to ensure it's not flaky.
        for _ in 0..16 {
            assert!(verify_csprng());
        }
    }

    #[test]
    fn test_random_array_lengths() {
        let a: [u8; 16] = random_array();
        let b: [u8; 32] = random_array();
        let c: [u8; 64] = random_array();
        assert_eq!(a.len(), 16);
        assert_eq!(b.len(), 32);
        assert_eq!(c.len(), 64);
    }
}
