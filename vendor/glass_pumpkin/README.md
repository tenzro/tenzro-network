# Vendored `glass_pumpkin` 1.9.0

This is a vendored copy of [`glass_pumpkin`](https://github.com/mikelodder7/glass_pumpkin)
1.9.0, modified to compile in 2026 after a cascading upstream-yank.

(The upstream README is preserved at `UPSTREAM-README.md`.)

## Why vendor?

We need `cggmp24 0.7.0-alpha.3` for the bridge-signer's t-of-n threshold-ECDSA
(Phase D). Transitively:

```
cggmp24 → paillier-zk → fast-paillier 0.3.2 → glass_pumpkin
```

The blocker chain at the time of vendoring:

1. **`fast-paillier 0.3.2`** does not compile against **`glass_pumpkin 1.10.x`**
   because of an `impl rand_core::RngCore: rand_core::Rng` bound mismatch
   introduced in glass_pumpkin 1.10. See
   [`LFDT-Lockness/fast-paillier#23`](https://github.com/LFDT-Lockness/fast-paillier/issues/23).
   The issue description documents the workaround: constrain glass_pumpkin to
   `>=1.8,<1.10`.
2. **`glass_pumpkin 1.9.0`** (and 1.8.x) has a non-optional dep on
   **`core2 ^0.4`**, and the entire `core2` crate has been yanked from
   crates.io. `glass_pumpkin` only uses `core2` for the `core::error::Error`
   shim (one `use` statement in `src/error.rs`).
3. Therefore neither the latest glass_pumpkin nor the upstream-documented
   workaround compiles today.

## What we changed

Two surgical edits versus the published 1.9.0 source:

- `src/error.rs`: `use core2::error;` → `use std::error;`
- `src/lib.rs`: dropped `#![no_std]`

The `Cargo.toml` is hand-authored with the `core2` dep removed and the
relevant feature gates preserved.

## When to remove the vendor

Drop `vendor/glass_pumpkin/`, the workspace-root `[patch.crates-io]` entry,
and revert the workspace `cggmp24` comment block once upstream
`LFDT-Lockness/fast-paillier#24` (or a successor) lands and republishes a
`fast-paillier` release that compiles against `glass_pumpkin 1.10.x`.

## License

Apache-2.0, same as upstream. See `LICENSE`.
