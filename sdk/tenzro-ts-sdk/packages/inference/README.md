# @tenzro/inference

Tenzro inference and media: models, chat streams, multimodal and media generation, providers and training.

One capability of the Tenzro Network TypeScript SDK. Most applications install [`tenzro-sdk`](https://www.npmjs.com/package/tenzro-sdk), which re-exports this package with the others; install `@tenzro/inference` alone to ship only what you use.

```bash
npm install @tenzro/inference
```

Depends on `@tenzro/core`. Signing needs hardware: `@tenzro/device-key` (TPM 2.0, Secure Enclave) on a server or desktop, a passkey in a browser.

- Reference: [API.md](https://github.com/tenzro/tenzro-network/blob/main/sdk/tenzro-ts-sdk/API.md) and the [JSON-RPC reference](https://github.com/tenzro/tenzro-network/blob/main/docs/RPC.md)
- Docs: [tenzro.com/docs/sdk](https://tenzro.com/docs/sdk)
- Security: report vulnerabilities to eng@tenzro.com or through GitHub private vulnerability reporting

Apache-2.0. See [LICENSE](LICENSE).
