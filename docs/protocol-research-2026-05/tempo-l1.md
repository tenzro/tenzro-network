# Tempo L1 Research — Stripe + Paradigm payments chain

**Date:** 2026-05-05
**Sources:** https://tempo.xyz/, https://docs.tempo.xyz/, https://www.paradigm.xyz/2025/09/tempo-payments-first-blockchain, https://tempo.xyz/blog/tip20/, https://github.com/tempoxyz/tempo
**Companion docs:** [`mpp-ietf.md`](mpp-ietf.md) (wire), [`stripe-spt.md`](stripe-spt.md) (token primitive). This doc is the settlement venue.

## What Tempo is

Tempo is an EVM-compatible L1 incubated by Stripe and Paradigm (announced 2025-09-04, public testnet "Moderato" 2025-12-09, mainnet March 2026). Mission: stablecoin-native payments rail at Stripe scale, no native gas token, fees denominated in USD and payable in any supported stablecoin. Funding: $500M Series A at $5B (Sequoia, Ribbit, SV Angel) per Fortune 2026-04-21.

### Execution + consensus

- **Execution client:** Reth SDK (the Tempo team houses the Reth maintainers). Targets the **Osaka** EVM hard fork; Solidity / Foundry / Hardhat all work unmodified per `docs.tempo.xyz/quickstart/evm-compatibility`.
- **Consensus:** **Simplex Consensus** (BFT) via Commonware. Deterministic ~0.5–0.6s block finality, no reorgs, graceful degradation under adverse networks. Throughput target: 100k+ TPS sub-second.
- **Validator set:** invited / institutional at launch (Visa anchor validator per CoinDesk 2026-04-14; Stripe and Zodia Custody confirmed via MEXC 2026-04-14). Roadmapped to permissionless PoS — anyone can run the binary today, validation is gated.
- **Payment lanes:** block header carries separate gas budgets for general EVM execution and reserved **payment-lane** sub-blocks for TIP-20 transfers; payments cannot be starved by DeFi congestion (per `docs.tempo.xyz/learn/tempo/performance`). Fee target is ~$0.001 per payment transaction.

## TIP-20 stablecoin standard

Source: `tempo.xyz/blog/tip20/` and `docs.tempo.xyz/protocol/tip20/spec`.

TIP-20 is **fully ERC-20-backward-compatible** — every TIP-20 token is also a valid ERC-20, so existing wallets, indexers, and DEX routers work unchanged. TIP-20 *adds*:

- **Transfer memos.** 32-byte memo field attached to transfers (`transferWithMemo(address,uint256,bytes32)`) for invoice IDs, payment references, SWIFT-style reconciliation tags.
- **Role-based access control.** `ISSUER_ROLE` (mint/burn), `PAUSE_ROLE` / `UNPAUSE_ROLE` (halt all transfers), `BURN_BLOCKED_ROLE` (clawback from frozen addresses, complementary to TIP-403 authorization-policy hooks).
- **Compliance controls.** Address freeze/unfreeze, pause/unpause, and clawback via `BURN_BLOCKED_ROLE` are first-class — required for regulated stablecoin issuance.
- **Reward distribution.** On-chain yield/rebase plumbing per the TIP-20 spec (issuer can stream interest without off-chain reconciliation).
- **Gas-in-stablecoin.** An enshrined AMM converts any whitelisted stablecoin to whatever the protocol uses for fees — users transact in USDC/USDT/USDB and never need a separate gas token.

The issuer model is **permissioned-by-issuer, permissionless-by-deployment**: anyone can deploy a TIP-20, but the production stablecoins (Stripe-issued USDB, Circle USDC, etc.) are bank-grade and ride the role-gated controls. Off-the-shelf templates ship in the Tempo SDK.

## MPP settlement role

A Stripe MPP credential ([`mpp-ietf.md`](mpp-ietf.md)) settles on Tempo as a TIP-20 transfer:

1. Agent presents `Authorization: Payment <base64url-credential>` per IETF draft §4.
2. Stripe (or a Stripe-delegated facilitator) verifies the credential's `source` DID, AP2 mandate binding, and SPT ([`stripe-spt.md`](stripe-spt.md)) `usage_limits`.
3. The `SharedPaymentGrantedToken` redeems against a TIP-20 stablecoin contract on Tempo via `transfer(payee, amount)` (or `transferWithMemo` carrying the credential ID).
4. The receipt JWT records `principal_chain = "tempo"` plus the Tempo `tx_hash` so the audit trail points at a finalized Tempo block — Simplex BFT means receipt = finality.

Tempo is **one valid settlement venue** for MPP, not the only one — Stripe ships the same MPP credential against Ethereum, Solana, and (for Tenzro-aware merchants) the Tenzro VM. The chain selection is driven by the cart-mandate's `accepted_chains`.

## Bridge surface

Tempo has no canonical L1 bridge; it relies on third-party adapters and Stripe-operated lanes. Per `seangoedecke.com/tempo-faq` and `across.to/blog/stablechains`, value moves on/off Tempo via burn-and-mint coordinated by issuers (Circle CCTP for USDC, Stripe for USDB) or via liquidity pools on Wormhole / LayerZero / Across. There is no Tempo-native bridge token.

For Tenzro this means: **Tempo is a settlement venue for stablecoins, not a hop for TNZO**. TNZO native bridging stays on Wormhole NTT per `project_interop_architecture` — Tempo does not enter the TNZO bridge graph.

## Tenzro angles (the YES list)

### Already implemented

- **`TempoBridgeAdapter`** at `crates/tenzro-payments/src/tempo/adapter.rs` — implements `tenzro_bridge::traits::BridgeAdapter`. `submit_tempo_transfer()` (line 98) encodes TIP-20 `transfer(address,uint256)` calldata via `stablecoin::encode_transfer()`, estimates gas with `eth_estimateGas`, and either signs+submits via EIP-155 or returns unsigned calldata. `bridge_tokens()` (line 300) wraps the same path through the bridge trait surface; `get_transfer_status()` (line 340) reads `eth_getTransactionReceipt` and maps to `TransferStatus::{Pending, Delivered, Failed}`.
- **`TempoParticipant`** at `crates/tenzro-payments/src/tempo/participant.rs` — direct settlement client. `EvmTransaction::sign_eip155()` (line 118) does RLP-encode → Keccak-256 → Secp256k1 recoverable sign with `v = chain_id*2 + 35 + recovery_id`. `transfer_stablecoin()` (line 483) builds + signs + submits a TIP-20 transfer end-to-end. `settle_mpp_batch()` (line 577) iterates settlement entries and emits per-entry tx hashes. `get_finality_status()` (line 648) trusts Simplex BFT — a present receipt means `FinalityStatus::Finalized`.
- **`Tip20Token` / `Tip20Balance`** at `crates/tenzro-payments/src/tempo/stablecoin.rs` — token metadata struct + balance with `display_amount()` decimal formatting. ABI helpers: `encode_balance_of()` (line 80), `encode_transfer()` (line 91), `encode_approve()` (line 107), `encode_decimals()` (line 121), `decode_uint256()` (line 128). Selectors are byte-identical to ERC-20 since TIP-20 is backward-compatible.
- **`TempoConfig`** at `crates/tenzro-payments/src/tempo/config.rs` — `TEMPO_CHAIN_ID = 42431`, mainnet RPC `https://rpc.tempo.xyz`, testnet RPC `https://rpc.moderato.tempo.xyz`. `with_stablecoin(symbol, address)` registers per-asset contract addresses.
- **`MppReceipt.chain`** defaults to `"tempo"` at `crates/tenzro-payments/src/mpp/receipt.rs:56` and `principal_chain` at line 32 freezes the payer's chain at settlement time. Tempo is a first-class principal value.

### TODO (research published, code pending)

- **TIP-20 mirror in `TokenRegistry`.** Register Tempo USDC/USDT/USDB into the unified `tenzro_token::TokenRegistry` with a new `TokenVmType::TempoTip20` variant alongside `Native | Evm | Svm | Daml` (`crates/tenzro-token/src/cross_vm.rs:11`). `cross_vm_transfer()` then routes TNZO ↔ wTNZO ↔ Tempo-USDC through one catalog.
- **`SERVICE_TYPE_TEMPO_ACCOUNT = "TempoAccount"`** in `crates/tenzro-identity/src/kya.rs` next to `SERVICE_TYPE_MASTERCARD_KYA` / `SERVICE_TYPE_VISA_TAP` (line 51-55). Lets a `did:tenzro:machine:*` DID Document declare its Tempo address, mirroring the KYA / TAP federation pattern. Same persistence path through `IdentityRegistry::add_service_to_identity`.
- **Cart-mandate `accepted_chains` Tempo entry.** AP2 CheckoutMandate already carries the chain list; Tempo (`tempo:42431` or chain-selector `"tempo"`) goes in the accepted set so the MPP router can pick Tempo over Ethereum/Solana/Tenzro per the cart's `accepted_chains` policy.
- **ERC-8004 cross-chain reputation aggregation.** TIP-20 transfer events on Tempo where the agent DID is the sender get rolled into `submitFeedback` against the agent's `agentId = keccak256(utf8(did))` on the Tenzro `0x101b` precompile — same DID, multi-chain footprint.
- **`tenzro_tempoProtocolInfo` RPC.** Profile/discovery RPC alongside `tenzro_visaTapProtocolInfo` / `tenzro_x402ProtocolInfo` / `tenzro_mastercardKyaProtocolInfo`; advertises chain ID, RPC URLs, configured stablecoins, signing flow, finality model, and the federation surface.

### Out of scope

- Tenzro running a Tempo validator. Validator slots are invited; not a Tenzro-side engineering task.
- Native consensus participation (Simplex BFT inside Tenzro). Tenzro consensus is HotStuff-2; Tempo consensus is its own.
- Custom Tempo bridge for non-stablecoin assets (TNZO). TNZO bridging stays on Wormhole NTT — Tempo is a stablecoin settlement venue only.

## Implementation order

1. **Tempo settlement adapter** (DONE): `TempoBridgeAdapter` + `TempoParticipant` + `Tip20Token` / `Tip20Balance` + `TempoConfig` are all live at `crates/tenzro-payments/src/tempo/{adapter,participant,stablecoin,config}.rs`. EIP-155 signing via k256 (`participant.rs:118`), RLP via `rlp` crate, Keccak-256 via `sha3`, JSON-RPC via `reqwest`. EIP-55 checksummed address formatting at `participant.rs:164`. Round-trip signing test at `participant.rs:990`.
2. **TIP-20 catalog mirror** (TODO): add `TokenVmType::TempoTip20` to `crates/tenzro-token/src/cross_vm.rs:11` and teach `TokenRegistry` (`crates/tenzro-token/src/registry.rs`) to ingest TIP-20 contract addresses from `TempoConfig::stablecoin_addresses`. Cross-VM transfer paths in `crates/tenzro-vm/src/cross_vm_bridge.rs` then route through one catalog instead of bypassing the registry.
3. **DID-anchored Tempo identity** (TODO): `SERVICE_TYPE_TEMPO_ACCOUNT = "TempoAccount"` in `crates/tenzro-identity/src/kya.rs` next to the MastercardKYA / VisaTAP constants; service entries persisted via `IdentityRegistry::add_service_to_identity` (write-through to `CF_IDENTITIES`).
4. **MPP cart-mandate Tempo route** (TODO): add `tempo` to AP2 `accepted_chains` parsing; MPP router selects Tempo when the cart-mandate accepts it. The `principal_chain: "tempo"` audit trail and `MppReceipt.chain = "tempo"` defaults already hold.
5. **`tenzro_tempoProtocolInfo` RPC** (TODO): handler at `crates/tenzro-node/src/rpc_integrations.rs::handle_tempo_protocol_info` mirroring the shape of `handle_visa_tap_protocol_info` / `handle_x402_protocol_info`. Advertises Tempo chain ID, Moderato/mainnet RPCs, configured TIP-20 contracts, EIP-155 signing flow, Simplex BFT finality model, and the DID-federation `service[].type = "TempoAccount"` extension.
6. **Cross-chain reputation aggregation** (later wave): TIP-20 transfer events on Tempo by an agent DID feed `submitFeedback` against `agentId = keccak256(utf8(did))` on the Tenzro `0x101b` precompile — same DID, multi-chain footprint. Touches precompile dispatch; deferred behind the recognition surfaces above.
