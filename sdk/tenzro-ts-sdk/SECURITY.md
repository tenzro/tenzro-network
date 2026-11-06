# Security policy

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue, pull
request or discussion for an unpatched vulnerability.

- Email **eng@tenzro.com**, or
- use GitHub private vulnerability reporting ("Report a vulnerability" under
  the Security tab) on the affected repository in the `tenzro` organisation.

Include what you found, how to reproduce it, the version or commit, and the
impact you expect. We acknowledge each report, keep you informed while we work
on the fix, and agree the disclosure with you. Please do not test against other
people's accounts or nodes, and do not disclose the issue publicly until a fix
is available.

## Scope

The node and CLI, the SDKs (`tenzro-sdk` for TypeScript and Rust, `tenzro` for
Python, `@tenzro/device-key`, `@tenzro/inject`), the MCP and A2A
surfaces the node serves, and tenzro.com.

## Supported versions

Security fixes go into the latest release. The testnet runs the current release
line; older releases are not patched.

The threat model and invariants are in [docs/security](https://github.com/tenzro/tenzro-network/tree/main/docs/security).
