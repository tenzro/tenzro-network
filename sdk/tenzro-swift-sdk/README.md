# tenzro-swift-sdk

A minimal Swift client for the Tenzro network (chain id 13380, `0x3444`; production RPC `https://rpc.tenzro.com`). Pre-1.0, read-only.

## Verification status (read this first)

| Item | Status |
|---|---|
| Builds with Swift 6.1.3 on **Linux x86_64** | Verified (`swift build`) |
| 9 Swift Testing tests (5 offline, 4 live against a dev node) | Passed on **Linux**, live tests against a dev node |
| Builds/tests on **macOS, iOS, visionOS** | **Not verified.** No Mac or Xcode was available. First `macos-latest` CI run is the real check. |
| `URLSession` behavior on Apple platforms | **Not verified** (tested via swift-corelibs-foundation on Linux only) |
| `examples/BalanceView.swift` (SwiftUI) | **Uncompiled.** Needs Xcode. Not in any package target. |
| Signer | `Composite` (message representative, account address, P-256 leg check) and `SoftwareP256Signer`: tested against the shared hardware-signing vectors. `SecureEnclaveSigner` (P-256 leg in the Secure Enclave): **uncompiled**, Apple platforms only. No ML-DSA-65 leg and no passkey signer. |
| Platform minimums (iOS 17, macOS 14, visionOS 1) | A judgment call, not checked against a requirement |
| Production endpoint `rpc.tenzro.com` | Not exercised by tests |

## Surface

- `TenzroClient`: `getChainId()`, `getBlockNumber()`, `getBalance(_:)`, `getNonce(_:)`, `getStatus()`, `isConnected()`, `resolveDidDocument(_:)`, generic `call(_:_:)`. All `async throws`, `Codable` JSON-RPC envelopes, `URLSession` transport.
- `TenzroDID`: syntactic parsing of `did:tenzro:human:...` / `did:tenzro:machine:...`. No resolution or verification.
- `TenzroClient.get(_:)`: HTTP GET that throws `TenzroError.paymentRequired(PaymentChallenge)` on 402, exposing the `PAYMENT-REQUIRED` / `WWW-Authenticate` headers and body. Typed surfacing only; **no payment is built, signed or sent**.
- `TenzroSigner`: a key that signs in the composite format; `SoftwareP256Signer` and, on Apple platforms, `SecureEnclaveSigner` make its P-256 leg. Neither makes the ML-DSA-65 leg that transactions and payment authorizations need.
- Not included: streaming (SSE) inference, transaction building or signing, any write method.

`getStatus()` uses `tenzro_getNodeStatus` and models only fields seen on a dev node; all are optional. Balances are returned as the node's raw hex plus a decimal string (no big-integer type).

## Usage

```swift
import TenzroSDK

let client = TenzroClient()                       // https://rpc.tenzro.com
let chain = try await client.getChainId()         // 13380
let bal = try await client.getBalance("0x...")
```

## Tests

```bash
swift test
TENZRO_RPC_URL=http://127.0.0.1:28545 swift test   # live tests
```

## License

Apache 2.0. See `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`.
