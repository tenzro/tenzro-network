# Contributing

Thanks for helping. This is a small, early SDK.

## Setup

Requires a Swift 6.0+ toolchain. Apple-platform work needs Xcode 16+ on macOS.

```bash
swift build
swift test                                   # offline tests only
TENZRO_RPC_URL=http://127.0.0.1:28545 swift test   # plus live tests against a node
```

## Guidelines

- Keep the surface minimal and match the TypeScript SDK's method names where a counterpart exists (`getChainId`, `getBalance`, `getStatus`).
- Only call RPC methods in the node's open (no-auth) set.
- Do not import Apple-only frameworks (`CryptoKit`, `AuthenticationServices`) from the core target without `#if canImport(...)`; the package should keep building on Linux.
- Add an offline test for any new pure logic. Live tests must skip when `TENZRO_RPC_URL` is unset.
- Never commit keys, tokens or node data.
- Be honest in PRs about what you did and did not run, especially on Apple platforms.

Contributions are licensed under Apache 2.0. Report vulnerabilities per `SECURITY.md`, not in public issues.
