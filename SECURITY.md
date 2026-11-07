# Security policy

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue, pull
request or discussion for an unpatched vulnerability.

- Email **eng@tenzro.com**, or
- use GitHub private vulnerability reporting ("Report a vulnerability" under
  the Security tab) on the affected repository in the `tenzro` organization.

Include what you found, how to reproduce it, the version or commit, and the
impact you expect. We acknowledge each report, keep you informed while we work
on the fix, and agree the disclosure with you. Please do not test against other
people's accounts or nodes, and do not disclose the issue publicly until a fix
is available.

## Scope

The node and CLI, the SDKs (`tenzro-sdk` for TypeScript and Rust, `tenzro` for
Python, `@tenzro/device-key`, `@tenzro/inject`), the MCP and A2A
surfaces the node serves, and tenzro.com.

## How the code is checked

Every commit to the main line goes through a standing program on the project's own build hosts:

- **Daily advisory gate.** The workspace lockfile is checked with `cargo-deny` against RustSec, and every lockfile the project builds from is checked against OSV for advisories published only on GitHub. Each accepted advisory is scoped to its lockfiles and recorded with its decision in `.cargo/audit.toml`. The release script stops on `scripts/supply-chain/advisory-gate.sh`: a lockfile that pulls in a vulnerable or unsound crate without a recorded decision is not released.
- **Nightly fuzzing.** Every decoder a peer can reach has a coverage-guided fuzz target (`fuzz/`): consensus frames, gossip, transactions, JSON-RPC, settlement plans and channels, bridge deliveries and proofs, iroh streams, identity documents, access tokens, HTTP signatures, x402 payloads, TEE and TPM evidence, proofs and finality journals, A2A and MCP client messages, and a differential check of two ML-DSA-65 verifiers. The targets run every night in a network namespace with only a loopback. A crash is fixed red then green, and its input is replayed on every later pass.
- **Per-merge review.** Each commit's diff is triaged for the existing tests and Kani proofs it puts at risk; exactly those run on that commit, and a finding is filed only when one of them fails. Every commit leaves one line in the review record.
- **Kani proofs.** Bounded model-checking harnesses in `crates/tenzro-vm/proofs` cover fee, supply, slashing, ledger, bridge-limit, governance and insurance arithmetic. A set of them is required: a required harness that fails, is renamed or goes missing fails the stage.
- **Static rules.** Semgrep rules refuse patterns the project has ruled out, such as a classical-only key exchange list.

## Supported versions

Security fixes go into the latest release. The testnet runs the current release
line; older releases are not patched.

The threat model, the security invariants and the wallet custody model are in
[docs/security](docs/security).
