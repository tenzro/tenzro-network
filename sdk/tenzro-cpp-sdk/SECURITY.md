# Security policy

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue, pull request or discussion for an unpatched vulnerability.

- Email **eng@tenzro.com**, or
- use GitHub private vulnerability reporting ("Report a vulnerability" under the Security tab) on this repository.

Include what you found, how to reproduce it, the version or commit, and the impact you expect. We acknowledge each report, keep you informed while we work on the fix, and agree the disclosure with you. Please do not test against other people's accounts or nodes, and do not disclose the issue publicly until a fix is available.

## Scope

This repository: the C core (`src/tenzro.c`), the C header, and the C++ wrapper. Note that this client has no TLS: it speaks plain HTTP and should only be pointed at loopback or a trusted network.

## Supported versions

Security fixes go into the latest release only.
