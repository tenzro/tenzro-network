//! SVM (Solana Virtual Machine) executor module

pub mod executor;
/// Real SBF execution via Anza's `solana-svm`. Declared here rather than
/// inside `executor.rs` because `full.rs` sits beside `executor.rs`, not
/// under it — a `mod full;` in `executor.rs` resolves to
/// `svm/executor/full.rs`, which does not exist.
#[cfg(feature = "svm-full")]
mod full;
pub mod spl_adapter;

pub use executor::SvmExecutor;
