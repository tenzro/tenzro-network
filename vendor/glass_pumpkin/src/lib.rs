#![deny(
    warnings,
    missing_docs,
    unsafe_code,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Vendored: dropped `#![no_std]`. Upstream uses no_std + `core2::error` as
// the error-trait shim; with `core2` yanked we route error::Error through
// `std` instead. The cggmp24 → fast-paillier path that consumes this is
// std-only in our build, so this is functionally equivalent.

//! A crate for generating large prime numbers, suitable for cryptography.
//!
//! Primes are generated similarly to OpenSSL except it applies some recommendations
//! from the [Prime and Prejudice](https://eprint.iacr.org/2018/749.pdf).
//!
//! 1. Generate a random odd number of a given bit-length.
//! 2. Divide the candidate by the first 2048 prime numbers
//! 3. Test the candidate with Fermat's Theorem.
//! 4. Runs Baillie-PSW test with `log2(bits) + 5` Miller-Rabin tests

#[cfg(test)]
extern crate alloc;

mod common;
pub mod error;
pub mod prime;
mod rand;
pub mod safe_prime;
