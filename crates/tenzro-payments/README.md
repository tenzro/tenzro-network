# tenzro-payments

Multi-protocol HTTP 402-based payment infrastructure for the Tenzro Network.

## Overview

**tenzro-payments** implements support for multiple payment protocols, enabling machine-to-machine and human-to-machine payments over HTTP. The crate provides a unified interface for MPP (Machine Payments Protocol) and x402, and the settlement rails behind them.

All payment protocols follow the HTTP 402 Payment Required pattern with challenge/credential/receipt flows, and integrate with Tenzro's identity system for delegation scope enforcement.

## Key Features

- **MPP (Machine Payments Protocol)** — Implements HTTP 402 challenge/credential/receipt flow with session management
- **Stripe Integration** — StripeClient for Payment Intents API (create/confirm/cancel/verify); HMAC-SHA256 webhook verification (RFC 2104)
- **ERC-8004 (Jan 2026 revision) Trustless Agents Registry** — full surface across IdentityRegistry, ReputationRegistry, and ValidationRegistry. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — server-allocated, never derivable client-side. The TDIP `IdentityData::Machine.erc8004_agent_id` field captures the allocation; reverse DID → id lookup via `OnChainAgentRegistry::lookup_agent_id_by_did`. Calldata is byte-identical against either the native Tenzro precompiles (`0x101a` / `0x101b` / `0x101c`) or an Ethereum mirror.
- **x402** — the HTTP 402 payment protocol, wire version 2 (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`). Tenzro schemes carry the payer-signed Tenzro credential; `PAYMENT-RESPONSE.transaction` is the ledger transaction the node saw executed before serving. EVM schemes (`exact-eip3009`, `permit2`) verify against the requirement rebuilt from the challenge
- **Settlement rails** — the gateway settles on the rail that carries a payment's asset and issues a receipt only after it settled: TNZO on the Tenzro Ledger with a payer-signed `PayerSettle` (10% network share), stablecoins on the optional Bridge rail, escrow vouchers through the session manager
- **Local x402 facilitation** — `LocalFacilitatorVerifier` runs the EIP-3009 admission checks against the operator's own EVM RPC. The node holds no EVM key, so it broadcasts through the settlement facilitator the operator names and then confirms on its own RPC that the transaction executed with exactly the verified calldata
- **Travel Rule** — exchanges and thresholds run in harnesses beside a facilitator, not in the node.
- **Metering** — `metering`: meter-signed usage records that bind an `upto` charge to what was served. The record rides back in `PAYMENT-RESPONSE` (`usageRecord`), and a meter key is backed by an on-chain bond: for 72 hours after a record is measured its payer can prove equivocation, a charge over the signed ceiling, or a settlement above what the meter signed (`DisputeMeteredCharge`), and is paid twice the ceiling from the bond. A bond withdraws only a full window after its owner asks
- **Delivery versus payment** — `dvp`: a sealed response whose key hash locks two buyer escrows, one to the seller for the price less the network share and one to the treasury for the share; the seller is paid by publishing the key on-chain, which opens both
- **Identity Binding** — Links payments to TDIP identities with automatic delegation scope enforcement
- **HTTP Middleware** — Axum middleware for automatic payment challenge and verification
- **Multi-Protocol Gateway** — Unified routing across all supported payment protocols
- **Session Management** — MPP `session` intent and x402 `batch-settlement`: sessions over an escrow the payer funded on the ledger, paid with cumulative vouchers the node claims on-chain

## Key Types

### Core Traits
- **PaymentProtocol** — Unified interface: `create_challenge`, `verify_credential`, `settle`, `create_credential`
- **PaymentGateway** — Multi-protocol routing and protocol selection

### AP2 (Agent Payments Protocol)
- **ap2** — AP2 v0.2 mandates (SD-JWT VCs, ES256), checked statelessly against the paying agent's consensus Terms: the merchant-signed `checkout_jwt`, the closed Payment Mandate (`mandate.payment.1`: `transaction_id`, `payee`, `payment_amount`, `payment_instrument`) signed by the agent's controller, or by the agent key an open Payment Mandate (`mandate.payment.open.1`) names in `cnf`, with the open mandate's constraints (`payment.reference`, `amount_range`, `allowed_payees`, `allowed_payment_instruments`, `allowed_pisps`, `execution_date`). A mandate only narrows the Terms; constraints that need a record of earlier payments (`payment.budget`, `payment.agent_recurrence`) are refused and belong in the Terms' period limits. Mandates ride on an x402 `tenzro-hybrid` or `upto` payment under `extensions.ap2`, checked by the node's facilitator.

### ACP (Agentic Commerce Protocol)
- **acp** — the seller side, API version 2026-04-17: `POST /checkout_sessions`, `POST|GET /checkout_sessions/{id}`, `.../complete`, `.../cancel`, with `API-Version` and `Idempotency-Key` enforced (replays answered with `Idempotent-Replayed: true`, a reused key with another body refused with 422). A node mounts it under `/acp` and sells its served models: `item.id` is `<model>/<unit>`, priced on its own rate card. The session offers one payment handler, `tenzro`, whose `config.requirement` is the x402 requirement for the session total; `complete` takes `payment_data.instrument = {type: "x402", credential: <x402 payload>}` and settles it through the node's facilitator (payer DID, Terms, AP2 mandates). Card instruments are refused: a card checkout needs a PSP and enters the ledger as an attested record.

### UCP (Universal Commerce Protocol)
- **ucp** — the business side of UCP 2026-08-25 (https://ucp.dev/2026-08-25/specification/overview/; schemas from github.com/Universal-Commerce-Protocol/ucp at tag `v2026-08-25`), REST transport, over the same sessions and seller as ACP. `GET /.well-known/ucp` is the business profile: the `dev.ucp.shopping` REST service, the `dev.ucp.shopping.checkout` capability, the `dev.ucp.common.payment.ap2_mandate` extension, the `dev.tenzro.x402` handler (id `tenzro`) and the business key under `keys`. `POST /checkout-sessions`, `GET|PUT /checkout-sessions/{id}`, `.../complete`, `.../cancel` take `UCP-Agent`, `Request-Id` and, when they change state, `Idempotency-Key` (a key reused with another body gets 409). Amounts are integers in nano-TNZO (handler `config.amount_scale` 9); the handler's `config.requirement` is the exact x402 requirement. Every checkout carries `ap2.merchant_authorization`, a detached ES256 JWS over the JCS checkout without `ap2`. `complete` takes `ap2.checkout_mandate` (SD-JWT, `vct` `mandate.checkout.1`, its `checkout` claim the approved checkout) and one `tenzro` instrument whose `credential.token` is base64url JSON `{payment, payment_mandate, open_payment_mandate?}`; the business checks its own authorization on the approved checkout, that it matches the session and that the checkout and payment mandates share their signer, then the facilitator checks the mandates against the payer's DID, Terms, payee and amount before funds move. Business refusals answer 200 with `messages` (`mandate_required`, `mandate_scope_mismatch`, `merchant_authorization_invalid`, `mandate_invalid_signature`, `payment_declined`). A node serves it at the root of its web surface, signing with its hardware key `ucp/merchant`.

### MPP (Machine Payments Protocol)
- **MppPaymentServer** — Server-side challenge/verification
- **MppClient** — Client-side credential creation and payment
- **MppChallenge** — Payment challenge with amount, resource, and nonce
- **MppCredential** — Signed payment credential with Ed25519 signature verification
- **MppReceipt** — Settlement receipt with proof
- **MppSessionManager** — sessions paid by payer-signed vouchers against an on-chain escrow
- **StripeClient** — Stripe Payment Intents API integration with HMAC-SHA256 webhook verification (RFC 2104)

### x402
- **X402PaymentServer** — Issues x402 challenges (network `tenzro:<chain id>`), verifies credentials through the scheme registry; optional offer signer and meter signer
- **X402Client** — Buyer: reads `PAYMENT-REQUIRED`, signs the canonical payment authorization with the payer's hybrid signer, retries with `PAYMENT-SIGNATURE`
- **X402PaymentRequired** / **X402PaymentRequirement** — the `PAYMENT-REQUIRED` body and one of its options (`scheme`, `network`, `amount`, `asset`, `payTo`, `maxTimeoutSeconds`, `extra.challengeId`)
- **X402PaymentPayload** — the `PAYMENT-SIGNATURE` body (`accepted`, `payload`)
- **X402SettlementResponse** — the `PAYMENT-RESPONSE` body (`success`, `transaction`, `network`, `payer`, `amount`)
- **wire** — maps challenges to requirements and payloads to credentials
- **X402Facilitator** — the facilitator a node serves to resource servers selling over x402 (`/verify`, `/settle`, `/supported`, x402 v2 shapes). Tenzro schemes (`tenzro-hybrid`, `upto`, `batch-settlement`, `dvp`, `proven`, `plan`) settle in consensus state; a payer naming a DID is bound to it and held to its Terms through `TermsGate`; EVM schemes go through the scheme registry. It holds no funds.
- **SchemeRegistry** — `tenzro-hybrid` (default, exact amount), `upto` (signed ceiling; charge bound to a meter-signed usage record when the challenge names a meter key), `batch-settlement` (escrow vouchers), `exact-eip3009`, `permit2`, `erc7710` (verification only; no settlement leg)
- **CdpFacilitatorClient** — client for a facilitator's HTTP API (`{x402Version, paymentPayload, paymentRequirements}`)

### Identity Integration
- **ap2::verify** — AP2 v0.2 mandates held to the agent's consensus Terms through `TermsGate`.
- **TermsGate** — The one payment-authority check; the node implements it over consensus state.

### Challenge Storage
- **ChallengeStore** — Shared store that both the MPP and x402 servers write a challenge into at creation time and read back at settlement, so a credential can be matched to the challenge that authorized it.

### RFC 9421 Foundation
- **Rfc9421SignatureBuilder** — HTTP Message Signature generation per RFC 9421
- **Rfc9421Verifier** — Signature verification with nonce replay protection
- **NonceRegistry** — Time-bounded nonce tracking (default: 5 min)

## Usage

```rust
use std::sync::Arc;
use tenzro_payments::gateway::{PaymentExpectation, TenzroPaymentGateway};
use tenzro_payments::traits::{PaymentGateway, PaymentProtocol};
use tenzro_payments::x402::X402PaymentServer;

// The chain id the network's genesis sets; 133801 is the preview network.
const CHAIN_ID: u64 = 133801;

// A gateway with the node's ledger rail attached.
let gateway = TenzroPaymentGateway::new(CHAIN_ID).with_rail(ledger_rail);
gateway.register_protocol(Arc::new(X402PaymentServer::new(CHAIN_ID, vec!["tenzro".into()])));

// Seller: mint a challenge for a resource (payee is a Tenzro address).
let challenge = gateway
    .create_challenge("x402", "/paid", 1_000, "TNZO", payee_hex)
    .await?;

// Buyer: sign the canonical payment authorization with its own signer.
let credential = x402_server.create_credential(&challenge, "", &payer_signer).await?;

// Seller: verify, settle on the rail, and get a receipt only once settled.
let receipt = gateway
    .verify_and_settle(&credential, PaymentExpectation::Challenge)
    .await?;
println!("settled in {:?}", receipt.settlement_tx);
```

## Stripe Integration Example

```rust
use tenzro_payments::mpp::StripeClient;

let stripe = StripeClient::new("sk_test_...".to_string())?;

// Create Payment Intent
let pi = stripe.create_payment_intent(1000, "usd", None).await?;

// Verify MPP credential against Stripe
let is_valid = stripe.verify_mpp_credential(&mpp_credential, &pi.id).await?;

// Verify webhook signature
let is_valid_webhook = stripe.verify_webhook_signature(
    payload,
    signature_header,
    webhook_secret,
)?;
```

## x402 Facilitator Client Example

```rust
use tenzro_payments::x402::{CdpFacilitatorClient, FacilitatorRequest};

let facilitator = CdpFacilitatorClient::new("https://facilitator.example");
let verified = facilitator.verify(&FacilitatorRequest::new(&payload, &requirement)).await?;
if verified.is_valid {
    let settled = facilitator.settle(&FacilitatorRequest::new(&payload, &requirement)).await?;
    println!("settled in {}", settled.transaction);
}
```

## Feature Flags

- **mpp** (default) — Enable Machine Payments Protocol support
- **x402** (default) — Enable Coinbase x402 protocol support

## Dependencies

- **tenzro-types** — Core types and primitives
- **tenzro-crypto** — Cryptographic operations (Ed25519, Secp256k1, SHA-256, Keccak-256)
- **tenzro-identity** — TDIP identity integration with delegation scopes
- **tenzro-settlement** — On-chain settlement engine
- **tenzro-bridge** — Cross-chain bridge adapters
- **tenzro-wallet** — Wallet integration
- **rlp** — Recursive Length Prefix encoding (Ethereum transactions)
- **axum** — HTTP middleware
- **tower** — Service middleware
- **reqwest** — HTTP client

## Testing

Unit tests cover MPP, x402, Stripe, Coinbase CDP, the local facilitator, AP2 mandates, RFC 9421 signatures, and identity binding.

```bash
cargo test -p tenzro-payments
```

## License

Apache-2.0.
