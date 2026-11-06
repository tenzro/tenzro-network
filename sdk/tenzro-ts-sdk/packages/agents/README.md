# @tenzro/agents

Tenzro delegated agents: Terms, wallets, payments, governance, lifecycle and the task market.

One capability of the Tenzro Network TypeScript SDK. Most applications install [`tenzro-sdk`](https://www.npmjs.com/package/tenzro-sdk), which re-exports this package with the others; install `@tenzro/agents` alone to ship only what you use.

```bash
npm install @tenzro/agents
```

Depends on `@tenzro/core`, `@tenzro/payments`. Signing needs hardware: `@tenzro/device-key` (TPM 2.0, Secure Enclave) on a server or desktop, a passkey in a browser.

## NVIDIA OpenShell

Helpers for running OpenShell sandboxes under Tenzro Terms ([docs/OPENSHELL.md](https://github.com/tenzro/tenzro-network/blob/main/docs/OPENSHELL.md)):

- `openShellPolicyTerms` maps an OpenShell sandbox policy to agent Terms.
- `mintOpenShellCredential` mints a credential under those Terms with the controller's passkey.
- `openShellSessionId`, `parseOpenShellRecords` and `verifyOpenShellRecords` name a sandbox session and verify the supervisor's signed, hash-chained records of it offline, up to the receipt over the final root.
- `openShellPayments` lists the payments a verified session made.

The same helpers are in the Python SDK (`tenzro.agents`, snake_case) and the Rust SDK (`tenzro_sdk::openshell`), all checked against `sdk/fixtures/openshell`.

- Reference: [API.md](https://github.com/tenzro/tenzro-network/blob/main/sdk/tenzro-ts-sdk/API.md) and the [JSON-RPC reference](https://github.com/tenzro/tenzro-network/blob/main/docs/RPC.md)
- Docs: [tenzro.com/docs/sdk](https://tenzro.com/docs/sdk)
- Security: report vulnerabilities to eng@tenzro.com or through GitHub private vulnerability reporting

Apache-2.0. See [LICENSE](LICENSE).
