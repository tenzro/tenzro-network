//! Error structs

use crate::common::MIN_BIT_LENGTH;
use core::{fmt, result};
// Vendored: replaced `use core2::error;` with `use std::error;`.
// `core2` is the no_std error-trait shim; the upstream `core2` crate is
// yanked from crates.io. We only build with `std`, so the `std` import is
// equivalent for our purposes. See vendor/glass_pumpkin/README.md.
use std::error;

/// Default result struct
pub type Result = result::Result<num_bigint::BigUint, Error>;

/// Error struct
#[derive(Debug)]
pub enum Error {
    /// Handles when the OS Rng fails to initialize
    OsRngInitialization(rand_core::Error),
    /// Handles when the bit sizes are too small
    BitLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::OsRngInitialization(ref err) => {
                write!(f, "Error initializing OS random number generator: {}", err)
            }
            Error::BitLength(length) => write!(
                f,
                "The given bit length is too small; must be at least {}: {}",
                MIN_BIT_LENGTH, length
            ),
        }
    }
}

impl error::Error for Error {}

impl From<rand_core::Error> for Error {
    fn from(err: rand_core::Error) -> Error {
        Error::OsRngInitialization(err)
    }
}
