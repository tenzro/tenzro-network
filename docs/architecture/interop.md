# Tenzro Interoperability Architecture

**Status:** Revised 2026-10-01 to match the code.
**Scope:** TNZO and arbitrary-asset interop across EVM, SVM, and external chains.

## Context

Tenzro Ledger is a multi-VM network (EVM + SVM + native runtime) where TNZO is one native balance with an EVM and an SVM view (the pointer model). Any bridge that mints TNZO on Tenzro has to answer three questions: who may cause a mint, how much can it cause, and what happens when the party vouching for a delivery is wrong or compromised. This document describes what the node enforces.

## What is implemented

### One bridge path: the route framework

TNZO moves between Tenzro and external chains only over governed routes
(`tenzro_bridge::route`). A route joins Tenzro to one external chain over one
transport: a CCIP-compatible envelope for the EVM family (Ethereum, Base,
Arbitrum) and Solana, IBC for Cosmos chains, a deposit route for Bitcoin, or
Tenzro's bridge contract on Sui, Aptos, Stellar and TON. Routes are written only by
enacted `SetBridgeRoute` proposals and read back with
`tenzro_listBridgeRoutes` / `tenzro_getBridgeRoute`.

The framework, not the adapters, enforces every rule:

- **Strict canonical decoding.** A delivery and the message inside it are read
  through `route::canonical::Reader`; truncation, non-canonical encodings and
  trailing bytes are refused. Outbound messages are decoded back and must
  match what was built.
- **Attestations bound to their use.** The route committee, and on CCIP routes
  an independent blessing committee, sign a digest that names this chain's
  id, the route, the nonce and an expiry (at most one hour ahead). A used nonce
  is refused for good; data messages use their own nonce space.
- **Light-client proofs** where a route requires one
  (`route::light_client::LightClientVerifier`).
- **Circuit breaker.** A paused route admits and sends nothing.
- **Caps.** Per transfer and per epoch, the tighter of the route's limits and
  the network-wide limits.
- **Supply invariant.** For every route, the representation outstanding on
  the external chain never exceeds the TNZO locked on Tenzro for it. Every
  outbound transfer locks before it authorises a remote mint; every inbound
  transfer is refused unless that much is outstanding.

### Transfers

- **Inbound** (a `Bridge` inbound transaction the relayer signs and pays
  for from its own account): a relayer submits a delivery;
  the framework admits it and the recipient it names is credited. The nonce,
  epoch usage and supply record are committed together with the credit.
- **Outbound** (a `Bridge` outbound transaction): the holder signs the
  transaction itself, so its account nonce runs once. Block execution locks
  the amount in the route's vault and stores the outbound message for
  relayers.

### Outbound signing

The EVM transaction signer (`EvmTransactionSigner`) holds no key. It wraps a
hardware device reached through `tenzro_wallet::pluggable_signer::PluggableSigner`.

### Payment network identifiers

x402 requirements name the network in CAIP-2 form. A Tenzro node offers `tenzro:<chain id>` (the numeric chain id the payer's authorization signs), and EVM schemes use `eip155:<chain id>`. The `tenzro:mainnet` / `tenzro:testnet` references proposed below are the registry names; the payment wire uses the chain id so that a signed authorization can never be replayed on another Tenzro chain.

An HTTP-402 payment settles on exactly one rail chosen by its asset: TNZO on the Tenzro Ledger (`PayerSettle`, payer-signed, 10% network share), stablecoins between Bridge custodial wallets when the operator configured the Bridge rail, or on the payer's own EVM chain through the `exact-eip3009` / `permit2` schemes and a facilitator. The gateway does not swap between assets; a payee whose settlement preference needs a swap venue is refused rather than silently paid in another asset.

### Cross-chain intents

Intent and solver markets are not part of the protocol. They run in a harness over the public surface: a solver posts a generic bond, payment settles through escrow, and a failed fill goes through the protocol's generic disputes and slashing.

### Settlement mirrors

A settlement mirrored onto another chain is queued as an outbound data
message on the governed route serving that chain and stays pending until a
relayer delivers it.

### Light clients

- **Ethereum:** the sync-committee light client
  (`route::ethereum_light_client`), installed on every node with
  `RouteFramework::with_light_client`. Its anchor is part of the governed
  route; its state (the committees it follows) lives in route state and moves
  only on a `Bridge` light-client transaction, signed by its relayer.

## PQ posture

Route committees sign with secp256k1, because the counterparty contracts verifying them have no ML-DSA verifier. Tenzro transactions themselves carry the Ed25519 + ML-DSA-65 hybrid signature.

## CAIP-2 namespace

See `docs/caip2-namespace/`. `tenzro:` is not yet registered with ChainAgnostic; the strings are used as pre-registration identifiers.
