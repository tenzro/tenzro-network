# Supply chain: policy and procedure

The machine-readable policy is `supply-chain/policy.toml`. The files that enforce it are
`deny.toml` (cargo-deny), `.cargo/audit.toml` (cargo-audit), `supply-chain/` (cargo-vet),
`scripts/supply-chain/` (pins, advisory gate, release gate, reproduction) and
`.github/workflows/supply-chain.yml`. The guard test
`crates/tenzro-types/tests/supply_chain_guard.rs` fails when any of them drifts from the policy.

## What runs, and when

| Gate | Where | Fails on |
|---|---|---|
| `scripts/supply-chain/check-pins.sh` | every push and pull request, release | a second Rust version, a build without `--locked`, an unpinned action or base image (release), npm install scripts enabled |
| `cargo deny --locked check` | every push and pull request, weekly | a RustSec advisory, a yanked crate, a licence outside the allow list, a registry or git source not listed |
| `scripts/supply-chain/advisory-gate.sh` | every push and pull request, release | a vulnerability or unsound advisory not accepted in `.cargo/audit.toml` with a recorded decision |
| `cargo vet --locked` | every push and pull request, weekly | a dependency that is neither audited (here or in an imported audit set) nor exempted on record |
| `scripts/supply-chain/check-keys.sh` (run by check-pins.sh) | every push and pull request, release | a new place in non-test code that creates or stores a private key in software; test-only key code must sit in an item gated by `cfg(any(test, feature = "test-keys"))` or `test-support`, and those features may be enabled only from dev-dependencies |
| `scripts/supply-chain/check-unsafe.sh` (run by check-pins.sh; tested by `test_check_unsafe.sh`) | every push and pull request, release | `unsafe` in tenzro-crypto, tenzro-identity, tenzro-iroh or tenzro-zk, a missing `#![forbid(unsafe_code)]` in them, or any `unsafe` in tenzro-consensus beyond the two libc calls in `compact_work.rs` |
| `scripts/supply-chain/release.sh` | each release | any of the above, plus reproducibility |

The tool versions are pinned in `scripts/testnet/security/tools.env` and nowhere else. The
scheduled security stage on the build hosts runs the same tools plus osv-scanner over every
lockfile in the tree.

## Adding or updating a dependency

1. Change `Cargo.toml`, then `cargo update -p <crate> --precise <version>` so that only the intended
   crate moves. Commit `Cargo.lock` with it.
2. `cargo deny --locked check` must pass. A new licence is a decision: add it to `deny.toml` only
   with the reason in the commit message.
3. `cargo vet --locked` must pass. For a crate that is neither audited nor in an imported audit set:
   review the diff, then `cargo vet certify <crate> <version>` (an audit), or, when the crate cannot
   be reviewed now, `cargo vet add-exemption`. An exemption is a debt and is listed in
   `supply-chain/config.toml`; an exemption is not renewed without a new review.
4. A git or registry source that is not crates.io needs an entry in `supply-chain/policy.toml`
   (`[sources]`) and in `deny.toml`, in the same commit. Both lists must match.
5. A new build script, proc-macro or `-sys` crate is read for what it downloads and executes at
   build time before it is accepted.

## Accepting an advisory

Only when no fixed release exists and the vulnerable path is not reachable, never to make a run
green. The entry in `deny.toml` and in `.cargo/audit.toml` states the reason and the condition that
reopens it (a fixed release, a changed use). `[advisories] exceptions_need_reason` in the policy is
enforced by the guard test. Review every exception when its condition may have changed, and at each
release.

## A published crate turns out malicious or is yanked

1. Pin the last good version in `Cargo.lock` (`cargo update -p <crate> --precise <good>`), or remove
   the dependency. Do not run a build on a host that holds signing material until the lockfile is
   clean.
2. Search every lockfile in the tree (`osv-scanner` stage) and every build host's cargo cache.
3. Rotate anything a build on an affected host could have read. Keys are hardware-held, so this is
   access tokens and registry credentials, not signing keys.
4. Record the decision in the exceptions or the vet exemptions, with the date.

## npm

Every npm project carries an `.npmrc` with `ignore-scripts=true`, and installs use the lockfile
(`npm ci`). `scripts/supply-chain/check-pins.sh` fails otherwise (the check and the `.npmrc` files come from the c-sec-ux lane and arrive with its merge).

## Releases

Release archives are built from a pinned commit with `--locked`, reproduced by
`scripts/supply-chain/reproduce.sh`, and gated by `scripts/supply-chain/release.sh`. Signing the
archives with a hardware-held key and recording the digest in the chain registry is tracked in the
threat model (section G); until that lands the digest in the release notes is the reference. Users verify a download with [VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md).
