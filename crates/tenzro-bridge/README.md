# Tenzro Bridge

Moves TNZO between Tenzro and external chains over governed routes. There is
one bridge path: the route framework in `route`.

## Routes

A route joins Tenzro to one external chain over one transport. Routes are
installed and removed only by governance, and every node reads them from
consensus state.

| Transport | Chain family | Module |
|-----------|--------------|--------|
| `ccip` | EVM: Ethereum, Base, Arbitrum (CCIP-compatible envelope) | `route::evm` |
| `ccip` | Solana (CCIP-compatible envelope) | `route::solana` |
| `ibc` | Cosmos SDK chains (ICS-20 over IBC) | `route::ibc` |
| `deposit` | Bitcoin (governed deposit script) | `route::bitcoin` |
| `contract` | Stellar, Sui, Aptos, TON (Tenzro bridge contract) | `route::stellar`, `route::sui`, `route::aptos`, `route::ton` |

## Rules every route obeys

The framework, not the adapters, enforces them:

- **Strict canonical decoding.** Deliveries and messages are read through
  `route::canonical::Reader`; a truncated, non-canonical or over-long payload
  is refused.
- **Attestations bound to their use.** The route committee (and the
  independent blessing committee on CCIP routes) signs a digest naming this
  chain, the route, the nonce and an expiry. A used nonce is refused for good.
- **Light-client proofs** where a route requires one
  (`route::light_client::LightClientVerifier`).
- **Circuit breaker.** A paused route admits and sends nothing.
- **Caps.** Per transfer and per epoch, the tighter of the route's and the
  network's limits.
- **Supply invariant.** For every route, what is outstanding on the external
  chain never exceeds the TNZO locked on Tenzro for it.

## API

- `RouteFramework::admit_inbound` — admit a transfer delivery.
- `RouteFramework::send_outbound` — lock TNZO and build the outbound message.
- `RouteFramework::admit_message` / `send_message` — attested data messages
  (fill proofs, settlement mirrors) that move no TNZO.
- `route::state::RouteState` — the consensus state view the node supplies.
- `route::attestation::Delivery` — the delivery envelope, `encode`/`decode`.

## Other modules

- `chainlink_feed`, `chainlink_por`, `data_streams` — Chainlink price,
  proof-of-reserve and Data Streams readers.
- `fee_oracle` — bridge fees quoted in TNZO.
- `evm_signer` — EIP-1559 signing with a hardware-held key.
- `secp256k1_multisig` — committee signature verification.

See `docs/BRIDGE.md` for the user-facing description.
