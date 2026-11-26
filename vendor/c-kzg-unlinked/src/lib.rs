//! Stands in for `c-kzg` 2 in dependency resolution and is never compiled.
//!
//! Two EVM engines are linked side by side while `feature.evm_osaka` is
//! dormant, and each names `c-kzg` as an optional dependency at a different
//! major version. Both versions declare `links = "ckzg"`, which Cargo allows
//! once per dependency graph even when neither is enabled. The engine of the
//! Osaka rule set verifies KZG proofs with its BLS12-381 backend and never
//! enables this dependency, so this crate takes its place without the
//! `links` key.

compile_error!(
    "the workspace replaces c-kzg 2 with a placeholder: the Osaka EVM engine is built without \
     its `c-kzg` feature"
);
