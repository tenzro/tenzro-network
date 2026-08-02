---
namespace-identifier: tenzro-caip2
title: Tenzro Namespace - Chains
author: Tenzro Engineering (eng@tenzro.com)
discussions-to: https://github.com/ChainAgnostic/namespaces/pull/184
status: Draft
type: Standard
created: 2026-05-02
updated: 2026-05-02
requires: CAIP-2
---

# CAIP-2

*For context, see the [CAIP-2][] specification.*

## Rationale

In CAIP-2 a general blockchain identification scheme is defined. This is the
implementation of CAIP-2 for Tenzro. Blockchains in the "tenzro" namespace are
identified by their genesis state root; each chain runs an independent
HotStuff-2 BFT consensus instance with its own genesis state and validator
set. The genesis state root is a 32-byte SHA-256 digest that binds the
chain_id, the validator set, and the genesis account allocations; its first
32 hex characters are used as the CAIP-2 reference. The state root is
deterministic across every node that boots the same genesis configuration.

## Syntax

The namespace "tenzro" refers to the Tenzro Network protocol.

### Reference Definition

The CAIP-2 reference for a Tenzro chain is the lowercase hexadecimal
encoding of the first 16 bytes (32 hex characters) of the genesis state
root:

```
chain_id := "tenzro:" + lowercase(hex(genesis_state_root[0..16]))
```

This conforms to CAIP-2's reference grammar `[-a-zA-Z0-9]{1,32}`.

### Resolution Method

To resolve a Tenzro chain reference, make a JSON-RPC request to the chain's
RPC endpoint with method `tenzro_getBlock` and the genesis block height
(`block_number: 0`):

```jsonc
// Request
{
  "id": 1,
  "jsonrpc": "2.0",
  "method": "tenzro_getBlock",
  "params": [{ "block_number": 0 }]
}

// Response (truncated to relevant fields)
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "height": 0,
    "state_root": "bd7db8168a4fb61538147696bc8572700d644e6eb544d8c0469e816fd652036a"
  }
}
```

The `state_root` field is a 64-character lowercase hex string (32 bytes).
Truncate it to the first 32 characters to obtain the CAIP-2 reference.

EVM-compatible callers may also use `eth_chainId` to retrieve the
integer chain ID, but that integer is **not** the CAIP-2 reference —
the canonical reference always uses the truncated genesis state root.

### Backwards Compatibility

Not applicable. Tenzro Ledger is a fresh network with no prior CAIP-2 registration.

## Test Cases

```
# Tenzro Testnet
#   genesis state root: bd7db8168a4fb61538147696bc8572700d644e6eb544d8c0469e816fd652036a
#   integer chain_id (EVM-compat): 1337
tenzro:bd7db8168a4fb61538147696bc857270

# Tenzro Mainnet (TBD — populated at mainnet launch)
tenzro:<genesis_state_root[0..16] in lowercase hex>
```

Until mainnet is launched, only the testnet reference above is canonical.

## References

- [CAIP-2][]
- [Tenzro Network repository][repo]
- [HotStuff-2 BFT][hs2]

[CAIP-2]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
[repo]: https://github.com/tenzro/tenzro-network
[hs2]: https://eprint.iacr.org/2023/397.pdf

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
