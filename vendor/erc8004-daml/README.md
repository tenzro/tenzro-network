# Tenzro Canton ERC-8004 Templates

DAML 3.x templates implementing the ERC-8004 *Trustless Agents* registry
shape for Canton (Tenzro participant node). Authored in-tree because no
upstream Canton port of ERC-8004 exists at time of writing — the EVM
canonical contracts (`vendor/erc8004-evm/`) and Solana port
(`vendor/erc8004-solana/`, MIT-licensed QuantuLabs) are the reference
implementations the calldata builders in
`crates/tenzro-identity/src/erc8004_daml.rs` track.

## Layout

```
daml/
└── Tenzro/
    └── Erc8004/
        ├── Identity.daml      — IdentityRegistry (Register / Registered)
        ├── Reputation.daml    — ReputationRegistry (SubmitFeedback / RevokeFeedback / AppendResponse)
        └── Validation.daml    — ValidationRegistry (ValidationRequest / ValidationResponse)
```

## Template ID format

Canton template IDs are `{package_id}:{module_name}:{entity_name}`. The
`package_id` is the SHA-256 hash of the compiled `.dar` artifact and is
assigned at compile time, so it cannot be hard-coded here. The Rust
calldata builders in `crates/tenzro-identity/src/erc8004_daml.rs`
accept the `package_id` at construction time (`DamlPackageIds` struct)
and emit the full `{package_id}:Tenzro.Erc8004.Identity:IdentityRegistry`
identifier into the command JSON.

## Two-step authorization model

DAML templates require explicit signatory + observer parties; there is
no `msg.sender` equivalent. The templates use a **registry admin party**
(Tenzro Network) as a co-signatory for registration so the canonical
registry contract holds across all parties — matching the
"single canonical state" property of the EVM `IdentityRegistry`
contract.

Registration follows the Canton CIP-56-style two-step flow
(see `crates/tenzro-vm/src/daml/cip56.rs`): the caller submits a
`Register` choice that creates a `Registered` contract recording the
assigned `agentId`. The off-chain event reflector in `tenzro-node`
extracts the `agentId` from the `Created` event payload and writes it
into `CF_IDENTITIES` under the `erc8004_daml_did_index:` prefix.

## License

DAML templates: Apache-2.0 (Tenzro Network monorepo).
Compatible with the EVM reference (Apache-2.0) and SVM port (MIT).
