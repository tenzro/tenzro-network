# Address alignment

A Tenzro `Address` is 32 bytes. An Ethereum-style address is 20. Widening one
into the other is a choice with exactly two answers, and this codebase uses one
of them everywhere:

> **A 20-byte address is widened left-aligned.** The 20 significant bytes lead;
> the trailing 12 are zero.

```
0x3d0291C0fC59EdA83f2D9f5f00A09e12f3f6a067

  correct   3d0291c0 fc59eda8 3f2d9f5f 00a09e12 f3f6a067 00000000 00000000 00000000
  wrong     00000000 00000000 00000000 3d0291c0 fc59eda8 3f2d9f5f 00a09e12 f3f6a067
```

The wrong one is not a corrupt value. It is a perfectly well-formed address
that simply belongs to nobody. That is the entire hazard, and it is why this
document exists.

---

## Why left, and who depends on it

The convention is set by the ledger, and everything else follows:

| Where                             | What fixes it                                                                    |
| --------------------------------- | -------------------------------------------------------------------------------- |
| `tenzro_token` RocksDB backend    | `balance_key()` is `b"balance:" ‖ addr[..32]`                                    |
| `tenzro_vm::state_adapter`        | `tnzo_balance_key()` right-zero-pads a raw 20-byte EVM address into the same key |
| `tenzro-node` `parse_address`     | copies hex-decoded bytes into `addr_bytes[..len]`                                |
| `tenzro-vm` native executor       | `pad_address_32()` copies into `out[..bytes.len()]`                              |
| wallet, consensus, agent, network | `addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes())`                       |

Note the second row: **even EVM accounts are left-aligned in Tenzro.** There is
no "EVM side" of the ledger that uses the other convention. An EVM address and
the native balance it points at are the same 32-byte key.

## Where right-alignment is still correct

Right-aligned `0x00 × 12 ‖ addr20` is the ABI encoding of an `address` inside a
32-byte EVM word. That is a **wire format**, not an account key, and it is
correct in exactly those places:

- ABI encode/decode — `tenzro-identity/erc8004.rs`, `erc7683.rs`,
  `tenzro-payments/x402/`, `tenzro-wallet/rpc_provider.rs`,
  `tenzro-cli/erc7579.rs`
- Address _derivation_ from a hash — `keccak256(pubkey)[12..]`, in
  `tenzro-identity/derivation.rs`, `tenzro-payments/tempo/participant.rs`,
  `tenzro-tee/sealed_secp256k1.rs`

The distinction that keeps these straight: **those sites build a word from a
raw 20-byte array at the encoding site. None of them parse an address.** If you
find yourself right-aligning the output of an address parser, that is the bug.

## The failure mode

It is silent, in every direction:

- A balance read against a wrong-aligned key returns `0`, not an error — the
  account genuinely has no balance, because nothing was ever written there.
- A credit to a wrong-aligned key succeeds. The value is now at an address
  whose owner cannot derive it.
- An authorization check comparing a wrong-aligned address never matches, so it
  fails closed — or, worse, matches the zero address, and fails open.

Nothing logs. Nothing panics. The symptom surfaces far from the cause, usually
as "insufficient balance" against a funded account.

## Known past breakages

All fixed 2026-08-04. Recorded because each one looked like a different bug:

| Site                                              | Presented as                                                                                                                                                                                          |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Address::from_hex_checksummed`                   | Media-generation settlement failed `-32023 insufficient balance` for every requester regardless of funding. Misdiagnosed for a day as an unfunded wallet.                                             |
| `evm/tnzo_bridge.rs::evm_addr_to_tenzro`          | wTNZO `balanceOf` read 0 against funded native accounts; `transfer`/`mint`/`burn` moved value to unreachable keys. The pointer model's core promise — one balance across VMs — silently did not hold. |
| `evm/tnzo_bridge.rs::is_authorized_bridge_caller` | Narrowed the treasury with `[12..32]`, i.e. its zero pad. The treasury never matched itself, and a caller at `0x00…00` matched in its place. This one gates `mint`/`burn`.                            |
| `cross_vm_bridge.rs`                              | Cross-VM TNZO transfers debited a key the payer's balance was never at.                                                                                                                               |
| Rust SDK `Address::from_hex`                      | Client-side. Produced a wrong-aligned address that serialized to a valid 64-hex string the node then faithfully used.                                                                                 |

## Rules

1. **Parse with `Address::from_hex`.** It validates the EIP-55 checksum for
   40-hex input and widens correctly. Do not hand-roll a widening.
2. **Never right-align the result of parsing an address.** Build right-aligned
   words from raw `[u8; 20]` at the ABI encoding site.
3. **A 64-hex address has no alignment to choose** and passes through
   byte-for-byte. Rendering is always `hex::encode(addr.as_bytes())` — full 32
   bytes — so anything this codebase emits round-trips unambiguously. The
   40-hex path is reachable only from user input and external announcements,
   which is exactly why it is the one that broke.
4. **Suspect alignment whenever a balance reads 0 against an account you
   believe is funded.** It is a cheaper hypothesis than it looks.

Regression tests live in `tenzro-types/src/primitives.rs`
(`address_widening_tests`) and `tenzro-vm/src/cross_vm_bridge.rs`.

## A note on migration

Correcting this was a flag-day change. Balances written under right-aligned
keys before the fix are unreachable afterwards. That is the intended posture
per the pre-launch hygiene rule in `CLAUDE.md` — replace, don't migrate — and
it is only tolerable because the network is pre-alpha with no live users. It
would not be tolerable after mainnet, which is the strongest argument for
having the tests above.
