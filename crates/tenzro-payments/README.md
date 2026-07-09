# tenzro-payments

Multi-protocol HTTP 402-based payment infrastructure for the Tenzro Network.

## Overview

**tenzro-payments** implements support for multiple payment protocols, enabling machine-to-machine and human-to-machine payments over HTTP. The crate provides a unified interface for MPP (Machine Payments Protocol), x402 (Coinbase's HTTP 402 protocol), Tempo network integration, Visa TAP, and Mastercard Agent Pay.

All payment protocols follow the HTTP 402 Payment Required pattern with challenge/credential/receipt flows, and integrate with Tenzro's identity system for delegation scope enforcement.

## Key Features

- **AP2 v0.2 (Agent Payments Protocol)** — Google/FIDO-backed protocol for verifiable agent payments using Verifiable Digital Credentials (VDC) for intent, cart, and payment mandates. Three RPC surfaces: `tenzro_ap2SignMandate` (Ed25519 signing of the canonical preimage by the wallet bound to `signer_did`), `tenzro_ap2VerifyMandate`, `tenzro_ap2ValidateMandatePair` (enforces three nested ceilings: AP2 IntentMandate, TDIP `DelegationScope`, runtime `SpendingPolicy`). Session lifecycle (create → authorize → execute → cancel)
- **MPP (Machine Payments Protocol)** — Co-authored by Stripe and Tempo; implements HTTP 402 challenge/credential/receipt flow with session management
- **Stripe Integration** — StripeClient for Payment Intents API (create/confirm/cancel/verify); HMAC-SHA256 webhook verification (RFC 2104)
- **Stripe SPT (SharedPaymentToken)** — Token primitive that pairs with the MPP wire and Tempo settlement layers. `tenzro_sptIssue` signs an SPT bound to a principal/agent DID pair after `SptCeilingResolver` cross-checks the requested cap against the principal's `DelegationScope` and runtime `SpendingPolicy`. `tenzro_sptVerify` checks the SPT signature, principal/agent DID activity, and remaining cap. AP2 cart-mandate validation cross-checks `usage_limits ≥ cart_total`. ERC-8004 `ReputationRegistry` cross-write on every settled outcome. `granted_token.deactivated` webhook cascades into TDIP `apply_remote_revocation`.
- **ERC-8004 v0.6+ Trustless Agents Registry** — full surface across IdentityRegistry, ReputationRegistry, and ValidationRegistry. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — server-allocated, never derivable client-side. The TDIP `IdentityData::Machine.erc8004_agent_id` field captures the allocation; reverse DID → id lookup via `OnChainAgentRegistry::lookup_agent_id_by_did`. Calldata is byte-identical against either the native Tenzro precompiles (`0x101a` / `0x101b` / `0x101c`) or an Ethereum mirror.
- **x402 v1** — Coinbase's HTTP 402 payment protocol with facilitator-based settlement
- **Coinbase CDP Facilitator** — CdpFacilitatorClient for x402 verify/settle endpoints; EIP-3009 `transferWithAuthorization` calldata encoding; EIP-712 typed data; CAIP-2 chain identifiers; well-known USDC addresses
- **Tempo Integration** — Direct participation in the Tempo network for stablecoin payments (TIP-20 tokens) with EIP-155 transaction signing
- **Visa TAP** — RFC 9421 HTTP Message Signatures for agent verification in agentic commerce
- **Mastercard Agent Pay** — Know Your Agent (KYA) with agentic tokens and RFC 9421 signatures
- **Identity Binding** — Links payments to TDIP identities with automatic delegation scope enforcement
- **HTTP Middleware** — Axum middleware for automatic payment challenge and verification
- **Multi-Protocol Gateway** — Unified routing across all supported payment protocols
- **Session Management** — Stateful payment sessions with voucher-based prepayment (MPP)

## Key Types

### Core Traits
- **PaymentProtocol** — Unified interface: `create_challenge`, `verify_credential`, `settle`, `create_credential`
- **PaymentGateway** — Multi-protocol routing and protocol selection

### AP2 (Agent Payments Protocol)
- **Ap2Session** — Session lifecycle: Created → Authorized → Executed/Cancelled, tracks agent DID, provider DID, service, max_amount, asset
- **Ap2Mandate** — Verifiable Digital Credential (VDC) wrapper for intent, cart, and payment authorizations
- **Ap2Vdc** — Signed envelope containing mandate payload, issuer DID, subject DID, issuance timestamp, expiration, and Ed25519 signature
- **Ap2Verifier** — Verifies single VDC envelopes and validates intent→cart mandate pairs for consistency (resource match, amount bounds, expiration)
- **Ap2SessionManager** — Creates, authorizes, executes, cancels, and queries AP2 sessions with delegation scope enforcement

### MPP (Machine Payments Protocol)
- **MppPaymentServer** — Server-side challenge/verification
- **MppClient** — Client-side credential creation and payment
- **MppChallenge** — Payment challenge with amount, resource, and nonce
- **MppCredential** — Signed payment credential with Ed25519 signature verification
- **MppReceipt** — Settlement receipt with proof
- **MppSessionManager** — Prepaid session management with vouchers
- **StripeClient** — Stripe Payment Intents API integration with HMAC-SHA256 webhook verification (RFC 2104)

### x402 (Coinbase)
- **X402PaymentServer** — Server-side payment required responses
- **X402Client** — Client-side payment execution
- **X402PaymentRequired** — 402 response with payment details
- **X402PaymentPayload** — Payment transaction data
- **X402Facilitator** — Settlement facilitator interface (dispatches to a `SchemeRegistry` of pluggable scheme adapters)
- **SchemeRegistry** — Pluggable adapter table for x402 schemes; ships with `tenzro-hybrid` (the default), `exact-eip3009` (direct on-chain transfer of the exact challenge amount via EIP-3009 authorization), `permit2` (Permit2 authorization, facilitator pulls funds at settlement), and `erc7710` (ERC-7710 delegation-based authorization). Discoverable at runtime via `tenzro_listX402Schemes`; payers select via `--scheme <name>` on `tenzro x402 pay`.
- **CdpFacilitatorClient** — Coinbase CDP facilitator with EIP-3009 calldata encoding and EIP-712 typed data
- **ResourceCatalog (Bazaar)** — Discovery catalog for paid resources. A seller registers an `X402ResourceListing` (resource URL, scheme, network, asset, pay-to, max amount, tags); buyers browse via a `ResourceQuery` before ever hitting a `402`. The listing id is derived from `(seller_did, resource)`, so re-registering the same pair is idempotent. Optional `ResourceCatalogStore` gives write-through persistence. Surfaced over RPC as `tenzro_x402RegisterResource` / `tenzro_x402DiscoverResources` / `tenzro_x402DeregisterResource`, with `tenzro_x402VerifyOffer` for server-signed offers and `tenzro_x402PaymentId` for deterministic `pay_<hex>` idempotency ids.

### Tempo Network
- **TempoBridgeAdapter** — Direct Tempo network integration
- **Tip20Token** — TIP-20 token representation
- **Tip20Balance** — Token balance with 18-decimal precision
- **TempoParticipant** — Tempo network participant identity with EIP-155 Secp256k1 signing (k256), RLP encoding, Keccak-256 hashing, `eth_sendRawTransaction` submission
- **TempoConfig** — Network configuration (mainnet/testnet/devnet)

### Visa TAP
- **VisaTapServer** — Server-side agent verification
- **VisaTapClient** — Client-side signature generation
- **VisaTapRegistry** — Agent registration and revocation
- **VisaTapVerifier** — RFC 9421 HTTP Message Signature verification

### Mastercard Agent Pay
- **MastercardServer** — Know Your Agent (KYA) and agentic token issuance
- **MastercardClient** — Client-side token requests
- **KyaCredential** — Know Your Agent credential with agent attestation
- **MastercardTokenService** — Agentic token lifecycle management

### Identity Integration
- **IdentityBoundPayment** — Payment with TDIP identity binding
- **PaymentDelegationValidator** — Validates payments against delegation scopes
- **IdentityPaymentBinder** — Two-axis ceiling enforcer: (1) protocol-level `DelegationScope` via `IdentityRegistry::enforce_operation` (max_transaction_value, allowed_operations, time_bound, etc.) and (2) runtime `SpendingPolicy` via the `SpendingPolicyResolver` trait (max_per_transaction, max_daily_spend, current_daily_spend, enabled). Both ceilings must pass for a payment to settle. The resolver is wired in node startup via `IdentityPaymentBinder::with_spending_policy_resolver()`; absent a resolver or registry entry, the binder falls back to DelegationScope-only.
- **SpendingPolicyResolver** — Trait that resolves a payer DID to an optional `SpendingPolicySnapshot { max_per_transaction, max_daily_spend, current_daily_spend, enabled }`. Implemented in `tenzro-node` against the `AgentRuntime` runtime spending-policy registry.
- **Ap2Validator::validate_with_delegation_and_policy** — Three-layer ceiling for AP2 v0.2 PaymentMandates: AP2 CheckoutMandate constraints (item set, max_amount), TDIP DelegationScope (`enforce_operation`), and runtime SpendingPolicy (`SpendingPolicySnapshot::check`). Wired into `tenzro_validateMandatePair` RPC.

### RFC 9421 Foundation
- **Rfc9421SignatureBuilder** — HTTP Message Signature generation per RFC 9421
- **Rfc9421Verifier** — Signature verification with nonce replay protection
- **NonceRegistry** — Time-bounded nonce tracking (default: 5 min)

## Usage

```rust
use tenzro_payments::mpp::{MppPaymentServer, MppClient};
use tenzro_types::primitives::Address;

// Server: Create payment challenge
let server = MppPaymentServer::new()?;
let challenge = server.create_challenge(
    "inference_request_12345",
    1_000_000_000_000_000_000, // 1 TNZO (18 decimals)
    Address::from_public_key(&server_pubkey)
)?;

// Client: Create payment credential
let client = MppClient::new()?;
let credential = client.create_credential(
    &challenge,
    &client_keypair
)?;

// Server: Verify and settle
let is_valid = server.verify_credential(&credential).await?;
if is_valid {
    let receipt = server.settle(&credential).await?;
    println!("Settlement TX: {:?}", receipt.settlement_tx);
}

// Using the payment gateway for multi-protocol support
use tenzro_payments::gateway::PaymentGateway;

let mut gateway = PaymentGateway::new()?;
gateway.register_protocol("mpp", Box::new(server));

let challenge = gateway.create_challenge(
    "mpp",
    "resource_id",
    amount,
    recipient
)?;
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

## Coinbase CDP Facilitator Example

```rust
use tenzro_payments::x402::coinbase::CdpFacilitatorClient;

let cdp = CdpFacilitatorClient::new("https://facilitator.coinbase.com".to_string())?;

// Verify payment
let verification = cdp.verify_payment(&x402_payload).await?;

// Build EIP-3009 transferWithAuthorization calldata
let calldata = cdp.build_transfer_with_authorization_calldata(
    &x402_payload,
    &verification,
).await?;
```

## Tempo Participant Example

```rust
use tenzro_payments::tempo::participant::TempoParticipant;
use tenzro_crypto::KeyPair;

let keypair = KeyPair::generate();
let participant = TempoParticipant::new(
    keypair,
    "https://tempo-rpc.example.com".to_string(),
);

// Send a transaction
let tx_hash = participant.send_transaction(
    recipient_address,
    1_000_000_000_000_000_000, // 1 token (18 decimals)
).await?;

// Check balance
let balance = participant.get_balance().await?;
```

## Feature Flags

- **mpp** (default) — Enable Machine Payments Protocol support
- **x402** (default) — Enable Coinbase x402 protocol support
- **tempo-bridge** — Enable direct Tempo network integration
- **visa-tap** — Enable Visa TAP (RFC 9421 agent verification)
- **mastercard-agent-pay** — Enable Mastercard Agent Pay with Know Your Agent (KYA)

## Dependencies

- **tenzro-types** — Core types and primitives
- **tenzro-crypto** — Cryptographic operations (Ed25519, Secp256k1, SHA-256, Keccak-256)
- **tenzro-identity** — TDIP identity integration with delegation scopes
- **tenzro-settlement** — On-chain settlement engine
- **tenzro-bridge** — Cross-chain bridge adapters
- **tenzro-wallet** — Wallet integration
- **k256** — Secp256k1 elliptic curve (EIP-155 signing for Tempo)
- **rlp** — Recursive Length Prefix encoding (Ethereum transactions)
- **axum** — HTTP middleware
- **tower** — Service middleware
- **reqwest** — HTTP client

## Testing

The crate includes 75 unit tests covering MPP, x402, Tempo, Stripe, Coinbase CDP, Visa TAP, Mastercard Agent Pay, RFC 9421 signatures, and identity binding.

```bash
cargo test -p tenzro-payments
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
