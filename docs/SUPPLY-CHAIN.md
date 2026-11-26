# Supply chain: policy and procedure

The machine-readable policy is `supply-chain/policy.toml`. The files that enforce it are
`deny.toml` (cargo-deny), `.cargo/audit.toml` (cargo-audit), `supply-chain/` (cargo-vet),
`scripts/supply-chain/` (pins, advisory gate, release gate, reproduction) and
`.github/workflows/supply-chain.yml`. The guard test
`crates/tenzro-types/tests/supply_chain_guard.rs` fails when any of them drifts from the policy.

## What runs, and when

| Gate | Where | Fails on |
|---|---|---|
| `scripts/supply-chain/check-pins.sh` (needs python3 with PyYAML, which GitHub's Ubuntu image has; elsewhere install `python3-yaml`, or it fails rather than skip) | every push and pull request, release | a second Rust version, a build without `--locked`, an unpinned action or base image (release), a workflow file that does not parse, npm install scripts enabled |
| `cargo deny --locked check` | every push and pull request, weekly | a RustSec advisory, a yanked crate, a licence outside the allow list, a registry or git source not listed |
| `scripts/supply-chain/advisory-gate.sh` | every push and pull request, release | a vulnerability or unsound advisory not accepted in `.cargo/audit.toml` with a recorded decision |
| `cargo vet --locked` | every push and pull request, weekly | a dependency that is neither audited (here or in an imported audit set) nor exempted on record |
| `scripts/supply-chain/check-keys.sh` (run by check-pins.sh) | every push and pull request, release | a new place in non-test code that creates or stores a private key in software; test-only key code must sit in an item gated by `cfg(any(test, feature = "test-keys"))` or `test-support`, and those features may be enabled only from dev-dependencies |
| `scripts/supply-chain/check-unsafe.sh` (run by check-pins.sh; tested by `test_check_unsafe.sh`) | every push and pull request, release | `unsafe` in tenzro-crypto, tenzro-identity, tenzro-iroh or tenzro-zk, a missing `#![forbid(unsafe_code)]` in them, or any `unsafe` in tenzro-consensus beyond the two libc calls in `compact_work.rs` |
| `scripts/supply-chain/check-onboarding.sh` (run by check-pins.sh; tested by `test_check_onboarding.sh`) | every push and pull request, release | a `tenzro-node` start flag or subcommand, or a `TENZRO_*` environment variable read by non-test code, that is not listed with its reason in `onboarding-entry-points.txt`; an installer or package script that starts, enables, sets up, joins or stakes anything; a test-only key feature in a `default` set or turned on by a release, package or container build |
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
6. A version enters a lock file only once its registry has had it for `min_age_days`
   (`[new_versions]` in `supply-chain/policy.toml`, 7 days): a compromised release is usually
   found and withdrawn within days. `scripts/supply-chain/dependency_age.py --base <commit>`
   compares every committed `Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml` and `go.sum` with
   the base commit, asks crates.io, the npm registry or the Go module proxy when each new version
   was published, and fails on a younger one; the supply-chain workflow runs it on every pull
   request and push. The workflow runs the script as the base commit has it, and the minimum age
   is read from the base commit's policy, so a change cannot weaken the rule that judges it (only
   the change that introduces the rule is judged by its own). The exceptions and the git sources
   `[sources]` lists are read from the change itself, where a reviewer sees them, and cargo-deny
   checks the same sources against `deny.toml`. A security fix that cannot wait is
   listed under `[[new_versions.exception]]` with its ecosystem, name, version and reason, in the
   same reviewed change. Nothing whose age is unknown is admitted: a registry that does not answer
   after a few paced attempts, a lock file kind or format the check does not read, a malformed
   name or version, an npm or pnpm package not resolved from the npm registry, and a Cargo
   package from a source `[sources]` does not list all stop it. A Cargo package from a listed git
   source is pinned by its commit (`git-pin-drift.sh` and cargo-vet cover it); a path package is
   code in this tree, reviewed as code.

## Accepting an advisory

Only when no fixed release exists and the vulnerable path is not reachable, never to make a run
green. The entry in `deny.toml` and in `.cargo/audit.toml` states the reason and the condition that
reopens it (a fixed release, a changed use). `[advisories] exceptions_need_reason` in the policy is
enforced by the guard test. Review every exception when its condition may have changed, and at each
release.

## Future-incompatibility notices from dependencies

Two dependency paths carry a notice that a future compiler will reject their macro crates, and
neither has a release that avoids it: `core-models 0.0.7` (the newest, via `libcrux-ml-dsa`)
requires `hax-lib ^0.3.7`, which uses `proc-macro-error2`; and `genawaiter 0.99.1` (via
`bao-tree` and `iroh-blobs`) uses `proc-macro-error 0.4.12`. Both are waiting on upstream
releases (reported upstream at https://github.com/celabshq/libcrux/issues/1682 and
https://github.com/n0-computer/bao-tree/issues/119, 19 Nov 2026); the notice is not hidden by
configuration. Re-open when a `core-models` release
requires `hax-lib ^0.4`, or when `bao-tree` or `iroh-blobs` drops `genawaiter`.

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

## Registry packages

Packages go to npm, crates.io and PyPI with the registry's own provenance: a statement, signed
with a hosted runner's short-lived identity, of the repository, commit and workflow that built
and published the package. `.github/workflows/publish-provenance.yml` does it, started by hand
for one release tag and one registry, in the published repository (a registry issues provenance
only for a public source repository). It stores no registry token: each registry accepts the
workflow's identity as a trusted publisher, which the owner sets up once per package on the
registry, naming the workflow file and the `release` environment, so a token is issued only to
a job in that environment.

Nothing in the workflow enforces the environment's protection; the repository settings do, and
they are set up once with the trusted publishers: the `release` environment has required
reviewers (every publish waits for an approval) and admits deployments only from tags
(`refs/tags/*`), so a run on a branch cannot reach a publish job.

The workflow is started on the release tag itself, and its first job stops a run whose ref is not
`refs/tags/<tag>` for the tag it names: the provenance a registry records names the run's commit
and ref, and every job checks out exactly that commit. For each registry a build job tests and
packs with no identity token; a publish job in the `release` environment holds the token and
uploads what was packed (crates.io takes no packed file, so its publish job uploads from the same
commit without building it again; `cargo publish` waits until each crate is in the index before
the next, which depends on it, is sent). A version already on the registry is skipped, so a publish that stopped halfway
is resumed by starting it again; a registry that answers anything but "published" or "not found"
stops it. With `dry_run` (the default) only the build job runs.

- npm: the TypeScript SDK workspace packages (core first, the umbrella `tenzro-sdk` last), tested
  with `npm test`, packed with `npm pack`, uploaded with `npm publish --provenance`; check with
  `npm audit signatures`.
- crates.io: `tenzro-types`, `tenzro-crypto`, `tenzro-device-key`, then `tenzro-sdk` (its own
  workspace, published from `sdk/tenzro-sdk/Cargo.toml`), tested with `cargo test --locked`, with
  a token crates.io issues to the workflow for one run. The dry run builds `tenzro-types` and
  `tenzro-sdk` exactly as the registry will; `tenzro-crypto` and `tenzro-device-key` depend on a
  crate published in the same run, so the dry run packages them without that build.
- PyPI: the `tenzro` source archive and wheel from `sdk/tenzro-py`, tested with `pytest`, built
  with tools pinned by hash (`sdk/tenzro-py/tools/publish-requirements.txt`), uploaded with the
  attestations PyPI serves beside them.

The native device-key packages are built per platform outside this workflow and are published
from the release machine without registry provenance; so is any package until its trusted
publisher is set up.

## Releases

Release archives are built from a pinned commit with `--locked` and reproduced by
`scripts/supply-chain/reproduce.sh`. The manifest `SHA256SUMS` is signed with a non-exportable P-256 key held
in a TPM 2.0, by `scripts/supply-chain/sign-release-tpm.sh`. That script is the documented launch path: it
needs only tpm2-tools and openssl on the signing host, shows the signer every line of the manifest and its
SHA-256, takes the key passphrase from the terminal only, and writes a signature that
`cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true` accepts. The key and its
fingerprint are in [RELEASE-KEYS.md](RELEASE-KEYS.md); each signing is recorded in
[SIGNING-LOG.md](SIGNING-LOG.md).

Each archive ships with a debug archive beside it (`<archive>-debug.tar.gz`, or `-debug.zip` on Windows):
the symbol files split off the shipped binaries (Linux `.debug` files matched by build-id, macOS dSYM
bundles, Windows `.pdb` files), so a crash report from a released binary can be read. They hold symbols
and line tables only. `scripts/release/manifest.sh` refuses an archive without its debug archive, lists
both in `SHA256SUMS` and records the debug archive in `matrix.json`, so the signature covers them and
they are published with the release; the installers never offer one for installation.

`scripts/supply-chain/release.sh` is the other path: it runs the pins, cargo-deny, advisory-gate and
cargo-vet checks and then signs with cosign. It accepts only a `pkcs11:` key URI and refuses anything else, so
it does not sign with the TPM key above; for a release signed by `sign-release-tpm.sh` the gates it runs must
be run separately and their result recorded in the release notes. Recording the digest in the chain registry
is tracked in the threat model (section G); until that lands the digest in the release notes is a second
reference. Users verify a download with [VERIFY-DOWNLOAD.md](VERIFY-DOWNLOAD.md).
