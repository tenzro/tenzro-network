# Stripe SharedPaymentToken (SPT) — Research

**Date:** 2026-05-05
**Source:** https://docs.stripe.com/agentic-commerce/concepts/shared-payment-tokens, https://docs.stripe.com/api/shared-payment/issued-token, https://docs.stripe.com/api/shared-payment/granted-token/object, https://stripe.com/blog/supporting-additional-payment-methods-for-agentic-commerce

**Companion docs:**
- MPP wire (IETF `draft-ryan-httpauth-payment-01`) — see `mpp-ietf.md`
- Tempo L1 settlement chain — see `tempo-l1.md`

**Scope:** Stripe's SharedPaymentToken primitive specifically. MPP wire format and Tempo settlement details live in the companion notes; this note covers the token primitive Stripe Issuing exposes for agent-mediated card spend.

## What SPT is

Stripe's Shared Payment Token is a *limited-use reference to a PaymentMethod* — the Issuing-layer credential that lets an agent spend a customer's card under cryptographically-scoped caps without ever holding the underlying card data. Two resources, two halves of the same token:

- **`SharedPaymentIssuedToken`** — created by the *agent* (the AI platform / SA in AP2 terms). Stripe's docs: *"a limited-use reference to a PaymentMethod that can be created with a secret key. When shared with another Stripe account (Seller), it enables that account to either process a payment on Stripe against a PaymentMethod or to forward a usable credential to process the payment off-Stripe."*
- **`SharedPaymentGrantedToken`** — what the *seller* (merchant / CP) receives. Carries `usage_limits`, last-four, brand. Confirmed via PaymentIntent with `payment_method_data[shared_payment_granted_token]=spt_123`.

`usage_limits` is the load-bearing field: `{ currency, max_amount, expires_at }`. Stripe blog: *"scoped to a specific business, limited by time or amount, revoked at any time, and monitored via webhook events"* — agent grants caps at issuance, seller can only confirm within the cap.

## Lifecycle

`requires_action` → `active` → `used` / `deactivated`.
- Issued in `requires_action` if the customer needs to authenticate (3DS / SCA).
- Becomes `active` when authentication clears.
- `used` after the seller's PaymentIntent confirms; `deactivated` on revoke or expiry.
- Webhook event family: `shared_payment.issued_token.*` (created / activated / used) and `shared_payment.granted_token.deactivated`. (The exact event-name list isn't enumerated on the public docs page at audit time — hedge: the family prefix is documented; specific suffixes may shift before GA.)
- Revoke endpoint: `POST /v1/shared_payment/issued_tokens/{id}/revoke` — agent-side kill switch.

## Why SPT exists

Vanilla Stripe Issuing gives a card credential; SPT adds *delegation scoping*. The agent doesn't get the card — it gets a token bound to one merchant, one currency, one ceiling, one expiry. Three properties ordinary Issuing doesn't give:

1. **Per-session caps with cryptographic enforcement.** `usage_limits.max_amount` is enforced by Stripe at PaymentIntent confirm time, not by the merchant's good behaviour.
2. **Card-rail bridge for non-card wires.** SPT is the primitive Stripe + Tempo route MPP through: the MPP credential identifies the agent and the cart; the SPT is what actually settles on Visa/Mastercard rails.
3. **2026-Q1 expansion.** Stripe announced SPT support for Mastercard Agent Pay, Visa Intelligent Commerce, and BNPL (Affirm, Klarna) — *"the first and only provider that supports both agentic network tokens and BNPL tokens in agentic commerce through a single primitive."*

## Closed-network surface

SPT issuance is gated to Stripe Issuing accounts; KYC, dispute, FX, settlement all live on Stripe's rails. **Stripe-locked:** the underlying card vault, MDES/VTS network tokenisation, dispute/chargeback flow, fraud signals. **Portable:** the *delegation surface* (who is the agent, what are the caps, what cart is this for) — exactly the surface TDIP DelegationScope and AP2 Cart Mandates already model.

## Tenzro has all the missing pieces

Stripe owns the card-rail. Tenzro owns the identity + mandate + cryptographic-cap layer that SPT *describes in JSON* and Tenzro *enforces in protocol*:

- `did:tenzro:machine:*` (TDIP) — DID for the agent that holds the SPT
- `DelegationScope.max_transaction_value` / `time_bound` / `allowed_chains` — structural ceiling that maps 1:1 onto SPT `usage_limits {max_amount, expires_at, currency}`
- Runtime `SpendingPolicy` registry on `AgentRuntime` — execution ceiling with daily-spend windows
- ERC-8004 ReputationRegistry at precompile `0x101b` — peer-attestable record of SPT outcomes for cross-network agent vetting
- AP2 cart-mandate validator (`tenzro_validateMandatePair`) — already enforces all three nested ceilings on a cart

## Tenzro angle (YES)

**DID-anchored SPT issuance with three-ceiling enforcement and on-chain reputation cross-write.**

1. **DID-anchored issuance.** TDIP DID Document carries `service[].type = "StripeSPT"` (a sibling of `MastercardKYA` / `VisaTAP` per `crates/tenzro-identity/src/kya.rs`). Agent's `did:tenzro:machine:*` resolves to the Stripe Issuing account that minted the token; merchants can verify the token was issued to a known agent identity before confirming.

2. **DelegationScope ↔ `usage_limits` mapping.** `DelegationScope.max_transaction_value` projects to `usage_limits.max_amount`; `time_bound.expires_at` projects to `usage_limits.expires_at`; `allowed_chains` constrains which `principal_chain` the merchant may settle on. Both ceilings apply at SPT creation — Stripe enforces its copy, Tenzro enforces the TDIP copy, **whichever is stricter wins**.

3. **Three-ceiling enforcement.** `IdentityPaymentBinder` today enforces TDIP DelegationScope + runtime SpendingPolicy (`crates/tenzro-payments/src/identity_binding.rs:240` `with_spending_policy_resolver`). SPT adds a third ceiling: Stripe-side `usage_limits` returned from the granted-token retrieve. All three must pass — protocol scope (structural), runtime policy (daily window), Stripe SPT (per-token cap).

4. **AP2 cart-mandate ↔ SPT binding.** `tenzro_validateMandatePair` already validates a cart-mandate against delegation+policy (`crates/tenzro-payments/src/ap2/mod.rs`). Extend the validator to verify a presented SPT's `usage_limits` matches the cart's intent envelope and `max_amount ≥ cart_total`. SPT then becomes the on-rail half of the AP2 mandate pair.

5. **ERC-8004 reputation mirror.** SPT outcomes — `succeeded`, `disputed`, `chargeback_won`, `chargeback_lost` — fan out to `ReputationRegistry.submitFeedback` at precompile `0x101b` (cite: `crates/tenzro-identity/src/erc8004.rs`). Cross-network agent vetting: a Mastercard or Visa directory can read the same reputation record from Ethereum, the agent doesn't have to build trust separately on each rail.

6. **Tempo settlement alternative.** When the agent prefers crypto rails, the same SPT-bound mandate dispatches via `TempoParticipant` (EIP-155 Secp256k1 signing at `crates/tenzro-payments/src/tempo/participant.rs`) instead of Stripe PI confirm. The TDIP delegation + AP2 mandate stay identical; only the settlement leg changes. Cross-link `tempo-l1.md` for chain details.

**Out of scope:** Tenzro becoming a card issuer. We federate into Stripe Issuing's directory the same way we federate into Mastercard KYA / Visa TAP — DID `service` entry + reputation cross-write. No card-rail settlement code, no MDES tokenization, no fiat vault.

## Implementation order

1. **DONE — Stripe Payment Intents base path.** `crates/tenzro-payments/src/mpp/stripe.rs:131` `create_payment_intent` (POST `/v1/payment_intents` with `Idempotency-Key` header at `:158`); `:228` confirm path; `:450` `verify_webhook_signature` HMAC-SHA256 per RFC 2104. This is what every SPT path eventually settles through.
2. **TODO — `crates/tenzro-payments/src/mpp/stripe_spt.rs`.** New module:
   - `SharedPaymentIssuedToken` / `SharedPaymentGrantedToken` types
   - `UsageLimits { currency, max_amount, expires_at }` parser
   - `SptStatus` enum: `RequiresAction | Active | Used | Deactivated`
   - `create_issued_token()`, `retrieve_granted_token()`, `revoke_issued_token()` methods on `StripeClient`
   - `confirm_intent_with_spt(spt_id, amount, currency)` → POSTs `payment_method_data[shared_payment_granted_token]=spt_id`, `confirm=true`
3. **TODO — SPT-aware `PaymentProtocol::verify_credential` extension.** When an MPP credential carries a `granted_token` field, verify the SPT exists, is `active`, and `usage_limits.max_amount ≥ challenge.amount` *before* TDIP delegation enforcement.
4. **TODO — SPT webhook event dispatcher.** Extend the existing webhook verifier (`stripe.rs:450`) to route `shared_payment.issued_token.*` and `shared_payment.granted_token.deactivated` to typed handlers; revoke events trigger TDIP `apply_remote_revocation()` cascade.
5. **TODO — `SERVICE_TYPE_STRIPE_SPT = "StripeSPT"` in `crates/tenzro-identity/src/kya.rs`.** Sits alongside `SERVICE_TYPE_MASTERCARD_KYA` (`:51`) and `SERVICE_TYPE_VISA_TAP` (`:55`). Update `is_kya_service_type()` to include it. (KYA isn't a perfect umbrella term — SPT is a token primitive not a directory — but co-locating the federation-pointer constants keeps the DID-document service-type registry in one place.)
6. **TODO — `tenzro_stripeSptProtocolInfo` RPC.** Mirrors `tenzro_mastercardKyaProtocolInfo` / `tenzro_visaTapProtocolInfo` shape; advertises the federation surface, supported lifecycle states, three-ceiling enforcement claim, ERC-8004 cross-write entry point.
7. **TODO — Three-ceiling integration in `IdentityPaymentBinder`.** Add an `SptCeilingResolver` trait alongside `SpendingPolicyResolver` (`crates/tenzro-payments/src/identity_binding.rs:71`). When a credential carries a granted-token reference, resolver retrieves Stripe's `usage_limits` and the binder rejects if any of (DelegationScope | SpendingPolicy | SPT cap) fails.
8. **TODO — ERC-8004 feedback emission on SPT outcomes.** Wire SPT webhook → `ReputationRegistry.submitFeedback` calldata builder (cite: `crates/tenzro-identity/src/erc8004.rs`).
9. **OUT OF SCOPE:** card issuance, MDES/VTS network tokenisation, fiat dispute/chargeback flow, Stripe-side KYC. We federate; we do not become an issuer.
