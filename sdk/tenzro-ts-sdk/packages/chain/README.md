# @tenzro/chain

Tenzro chain operations: tokens, NFTs, staking, validators, governance, contracts, TEE, ZK, storage and events.

Offline helpers: `abiEncode` / `abiDecode` / `encodeFunctionCall` / `functionSelector` / `eventTopic` (Solidity ABI for any EVM contract or precompile), and for NFTs on the factory precompile at `0x…1006`: `nftCalldata.*` builders, `nftDecode.*` for return data, `decodeNftTransfer` for logs, `nftCollectionId`, and `nftTransaction(...)`, which runs factory calls as one all-or-nothing `ContractCall` transaction for `TypedTxClient`. `NftClient` reads collections, owners, balances and token URIs through `eth_call`.

One capability of the Tenzro Network TypeScript SDK. Most applications install [`tenzro-sdk`](https://www.npmjs.com/package/tenzro-sdk), which re-exports this package with the others; install `@tenzro/chain` alone to ship only what you use.

```bash
npm install @tenzro/chain
```

Depends on `@tenzro/core`. Signing needs hardware: `@tenzro/device-key` (TPM 2.0, Secure Enclave) on a server or desktop, a passkey in a browser.

- Reference: [API.md](https://github.com/tenzro/tenzro-network/blob/main/sdk/tenzro-ts-sdk/API.md) and the [JSON-RPC reference](https://github.com/tenzro/tenzro-network/blob/main/docs/RPC.md)
- Docs: [tenzro.com/docs/sdk](https://tenzro.com/docs/sdk)
- Security: report vulnerabilities to eng@tenzro.com or through GitHub private vulnerability reporting

Apache-2.0. See [LICENSE](LICENSE).
