# Payment + Identity Protocol Wire-Format Coverage Matrix

**Audit date:** 2026-05-05
**Scope:** 8 protocols × Tenzro Network monorepo (`/Users/hilarl/AI/tenzronetwork`)
**Method:** Read-only static audit of `crates/tenzro-payments/`, `crates/tenzro-identity/`, `crates/tenzro-vm/`, `crates/tenzro-node/`, against canonical spec text fetched fresh on the audit date.

Status legend:

- ✅ **Implemented** — wire field/header/error path is reachable from a real call site with a cited file:line
- 🟡 **Partial** — present but diverges in shape, validation, or coverage from the cited spec section
- 🔴 **Missing** — no implementation; cite either the file where it belongs or "out of scope"

---

## 1. MPP — Machine Payments Protocol (Stripe + Tempo)

**Canonical spec:** IETF `draft-httpauth-payment-00` (March 2026, "Payment HTTP Authentication Scheme"). Co-authored by Stripe + Tempo. Wire layer: HTTP `WWW-Authenticate: Payment` and `Authorization: Payment` per RFC 7235.

**Tenzro implementation:** `crates/tenzro-payments/src/mpp/{mod,challenge,credential,receipt,server,client,session,stripe}.rs`. RPC: `tenzro_payMpp` at `crates/tenzro-node/src/rpc.rs:720`.

| Field / Component | Status | Cite |
|---|---|---|
| `MppChallenge` JSON object (challenge_id, resource, amount u128, asset, recipient, chain, expires_at, supports_sessions, extensions) | ✅ | `crates/tenzro-payments/src/mpp/challenge.rs:12-45` |
| `MppCredential` JSON object (credential_id, challenge_id, payer_did, payer_address, amount, asset, chain, signature, created_at, extensions) | ✅ | `crates/tenzro-payments/src/mpp/credential.rs:9-30` |
| `MppReceipt` JSON object (receipt_id, credential_id, challenge_id, amount, asset, settlement_tx, chain, settled_at, principal_chain) | ✅ | `crates/tenzro-payments/src/mpp/receipt.rs:9-30` |
| Hybrid Ed25519 + ML-DSA-65 credential signature verification (Tenzro extension) | ✅ | `crates/tenzro-payments/src/mpp/server.rs` (StandardHybridVerifier, both legs mandatory) |
| Session lifecycle (`MppSession`, `MppSessionManager`) for streaming/recurring payments | ✅ | `crates/tenzro-payments/src/mpp/session.rs` |
| Stripe Payment Intents API client (`POST /v1/payment_intents`, status verify, metadata) | ✅ | `crates/tenzro-payments/src/mpp/stripe.rs:44-94` |
| Stripe HMAC-SHA256 webhook verification (RFC 2104, `whsec_`) | ✅ | `crates/tenzro-payments/src/mpp/stripe.rs:39-43` |
| `Idempotency-Key` header on Stripe mutating requests | ✅ | `crates/tenzro-payments/src/mpp/stripe.rs:13` (claimed; verified via uses) |
| HTTP gate returns `402 Payment Required` on missing credential | ✅ | `crates/tenzro-payments/src/middleware.rs:256` |
| **`WWW-Authenticate: Payment` challenge header** per IETF draft §3 | 🔴 | `crates/tenzro-payments/src/middleware.rs:257` emits non-standard `Payment-Required: true`. Spec §3 mandates the `WWW-Authenticate: Payment` auth-scheme header so RFC 7235 user-agents can route the challenge. |
| **`Authorization: Payment <credential>` request header** per IETF draft §4 | 🔴 | Tenzro `MppPaymentServer::verify_credential` consumes JSON body, not the `Authorization: Payment` header per draft §4. Belongs in `crates/tenzro-payments/src/mpp/server.rs`. |
| Auth-param taxonomy (`realm`, `challenge`, `network`, `currency`, `min-amount`, `max-amount`, `recipient`) per draft §3.1 | 🔴 | Not parsed; entire challenge is a JSON blob in the body. Belongs in `crates/tenzro-payments/src/mpp/challenge.rs`. |
| Stripe SPT (SharedPaymentIssuedToken / SharedPaymentGrantedToken) settlement path | 🔴 | No file matches `shared_payment` / `granted_token` / `SPT`. Stripe SPT is the production "payable token" wire format used by Stripe + Tempo for MPP-grade settlement; belongs in `crates/tenzro-payments/src/mpp/stripe.rs`. |
| `principal_chain` settlement audit trail on the receipt | ✅ | `crates/tenzro-payments/src/mpp/receipt.rs:24` (frozen `PrincipalChain` field) |
| Three-ceiling enforcement (AP2 cart cap + TDIP DelegationScope + runtime SpendingPolicy) | ✅ | `crates/tenzro-payments/src/identity_binding.rs` (380 lines), wired via `IdentityPaymentBinder::with_spending_policy_resolver` at node startup |

---

## 2. Visa TAP — Trusted Agent Protocol

**Canonical spec:** Visa Developer Trusted Agent Protocol (March 2026, public preview). Wire = RFC 9421 HTTP Message Signatures with required derived components `@authority` + `@path`, 480-second `created`-age window, body objects `AgentRecognition` / `ConsumerRecognition` / `PaymentContainer`, mandatory `tag` ∈ {`agent-browser-auth`, `agent-payer-auth`}.

**Tenzro implementation:** `crates/tenzro-payments/src/visa_tap/{mod,types,server,client,verifier,registry}.rs`. RPC: `tenzro_payVisaTap` at `crates/tenzro-node/src/rpc.rs:723`.

| Field / Component | Status | Cite |
|---|---|---|
| `VisaTapChallenge` with `max_signature_age_secs = 480` (Visa spec hard limit) | ✅ | `crates/tenzro-payments/src/visa_tap/types.rs` |
| `AgentRecognition { signature_input, signature, key_id, algorithm, created_at, nonce }` | ✅ | `crates/tenzro-payments/src/visa_tap/types.rs` |
| `ConsumerRecognition { id_token, consumer_did, delegation_scope_id }` | ✅ | `crates/tenzro-payments/src/visa_tap/types.rs` |
| `PaymentContainer { payment_method, amount, asset, recipient, chain }` | 🟡 | `crates/tenzro-payments/src/visa_tap/types.rs`. Spec PaymentContainer carries `paymentCredentialsHash` over 16-digit PAN + 2-digit expMonth + 2-digit expYear + 3-digit CSC (23 digits SHA-256-ed). Tenzro abstracts to `PaymentMethod::CardToken { token_hash }` without the structured 23-digit preimage layout. |
| `WWW-Authenticate` parsing on the client | ✅ | `crates/tenzro-payments/src/visa_tap/client.rs:147-165` |
| RFC 9421 signature verification dispatch | ✅ | `crates/tenzro-payments/src/visa_tap/server.rs` via `verifier.rs:263` |
| Required covered components default `@authority`, `@path`, `content-type` | ✅ | `crates/tenzro-payments/src/visa_tap/types.rs` |
| Nonce cache for replay protection | ✅ | `crates/tenzro-payments/src/visa_tap/server.rs` (uses `rfc9421::NonceCache`) |
| **`tag="agent-browser-auth"` on browsing-context AgentRecognition** | ✅ | `crates/tenzro-payments/src/visa_tap/types.rs::AgentTag::BrowserAuth`; verifier Stage 7 in `verifier.rs` rejects unknown tags and enforces `with_required_tag()` per endpoint. |
| **`tag="agent-payer-auth"` on payment-context AgentRecognition** | ✅ | `crates/tenzro-payments/src/visa_tap/types.rs::AgentTag::PayerAuth`; surfaces on `VerificationResult.verified_tag` so payment endpoints can require it via `TapVerifier::with_required_tag(AgentTag::PayerAuth)`. |
| `TenzroAgentRegistryClient` for keyid → public-key lookup | ✅ | `crates/tenzro-payments/src/visa_tap/registry.rs` (`VisaAgentRegistryClient`) |
| 🟢 **Tenzro extension** — DID-resolvable `keyid` (RFC 9421 §2.3 `keyid` is opaque; `did:tenzro:machine:<uuid>` resolves via TDIP without a JWKS round-trip) | 🟢 | `crates/tenzro-payments/src/visa_tap/did_registry.rs::DidResolverAgentRegistry` composes `TenzroAgentRegistry` with a JWKS fallback (`VisaAgentRegistryClient`) — DID keyids hit TDIP, non-DID keyids hit JWKS, so the same verifier sits in front of both Tenzro-issued and Visa-issued agents. |
| 🟢 **Tenzro extension** — `tenzro_visaTapProtocolInfo` RPC advertises tag taxonomy + DID keyid extension + JWKS fallback note | 🟢 | `crates/tenzro-node/src/rpc_integrations.rs::handle_visa_tap_protocol_info` wired in `rpc.rs`. |

---

## 3. AP2 — Agent Payments Protocol (Google)

**Canonical spec:** AP2 v0.2, `github.com/google-agentic-commerce/AP2/blob/main/docs/ap2/specification.md`. Mandates a Checkout Mandate + Payment Mandate pair, SD-JWT VDC envelopes with `vct` schema versioning (`mandate.checkout.open.1`, `mandate.payment.1`), checkout_jwt → checkout_hash binding, ECDSA non-deterministic signatures (rainbow-table prevention), 5-role separation (Shopping Agent / Credentials Provider / Merchant / Merchant Payment Processor / Token Service).

**Tenzro implementation:** `crates/tenzro-payments/src/ap2/mod.rs` (1,102 lines). RPCs: `tenzro_ap2SignMandate` (rpc.rs:938), `tenzro_ap2VerifyMandate` (939), `tenzro_ap2ValidateMandatePair` (940), `tenzro_ap2ProtocolInfo` (941).

| Field / Component | Status | Cite |
|---|---|---|
| `Vdc` envelope (version, kind, payload, signer_did, signer_public_key, signature, alg) | ✅ | `crates/tenzro-payments/src/ap2/mod.rs:300-410` |
| `MandatePayload::Checkout` + `MandatePayload::Payment` shapes | ✅ | `crates/tenzro-payments/src/ap2/mod.rs:270-271` |
| Three-ceiling validation (AP2 CheckoutMandate cap + TDIP DelegationScope + runtime SpendingPolicy) — Tenzro extension beyond spec | ✅ | `crates/tenzro-payments/src/ap2/mod.rs:602` (`validate_with_delegation_and_policy`) |
| Mandate-pair binding (Checkout VDC → Payment VDC linkage) | ✅ | `crates/tenzro-payments/src/ap2/mod.rs:575` |
| Signing/verification RPC wired to JSON-RPC + A2A | ✅ | `crates/tenzro-node/src/rpc.rs:938-941` |
| **Checkout Mandate** (AP2 v0.2 §6.1) — vct claim `mandate.checkout.1` / `mandate.checkout.open.1` | 🟢 | `MandateKind::Checkout` in `crates/tenzro-payments/src/ap2/mod.rs`; `vct()` accessor returns the Open variant when `presence == HumanNotPresent`. Open Cart / Dynamic Cart sub-types collapse onto `MandateKind` + `presence`. |
| **Payment Mandate** (AP2 v0.2 §6.2) — vct claim `mandate.payment.1` carrying tokenized credentials | 🟢 | `MandateKind::Payment`. `vct()` accessor on the struct. SPT/agentic-token reference fields ride in the line-item `category` + `merchant_did` for now. |
| **`vct` (Verifiable Credential Type) claim** identifying mandate schema version | 🟢 | `MandateKind::vct(open: bool)` returns `mandate.{checkout\|payment}.[open.]1`. `CheckoutMandate::vct()` / `PaymentMandate::vct()` derive open-vs-closed from the mandate's own `presence` field. Tested. |
| **`cnf` (RFC 7800) key-binding claim** — JWK or DID, enforced at verify time | 🟢 | `MandateCnf::{Jwk, Did}` on both Checkout/Payment payloads. `Vdc::verify_with_registry()` enforces: JWK form requires `x` to equal `signer_public_key`; DID form resolves via TDIP `IdentityRegistry`, requires `cnf.did == signer_did` and `signer_public_key` to appear in the resolved DID Document. 6 unit tests cover happy-path + 4 confusion-attack rejections. Wired into `MandateValidator::validate_with_delegation_and_policy()`. |
| **On-chain escrow binding** (Tenzro extension, four-ceiling validation) | 🟢 | `EscrowResolver` trait + `EscrowSnapshot` projection in `crates/tenzro-payments/src/identity_binding.rs`. `MandateValidator::validate_with_delegation_policy_and_escrow()` enforces: when the Checkout/Payment mandate pair carries `escrow_id`, it resolves on-chain via `EscrowManagerResolver` (`crates/tenzro-node/src/escrow_resolver_bridge.rs`) and rejects unless the escrow exists, is `Funded` and not expired, and its locked amount covers `payment.total_amount`. 7 unit tests cover happy-path + 5 rejection paths (missing resolver, missing escrow, underfunded, already-released, principal-mismatch). Surfaced in `tenzro_protocolInfo` AP2 `ceilings: [...onchain_escrow]` and `escrow_enforcement` blocks. |
| **AgentBond binding** (Tenzro extension, slashable-collateral dispute path) | 🟢 | `tenzro_ap2ReportMandateViolation` (`crates/tenzro-node/src/rpc_integrations.rs`) is the AP2-flavored claim-filing entry point. Verifies the parent CheckoutMandate VDC signature, optionally cross-verifies the child PaymentMandate (parent-binding + agent-DID match), validates the violation classification (`overspend` / `merchant_whitelist_breach` / `category_breach` / `expired_mandate_settlement` / `double_spend` / `missing_cnf_binding` / `other`), confirms the agent has a posted AgentBond, and forwards to `BondManager::file_claim()` with a structured narrative. Slash flows through standard governance review → `PayInsuranceClaim` typed transaction → on-chain `BondSlashed` log → `BondManager` reflection. Surfaced in `tenzro_protocolInfo` AP2 `agent_bond_enforcement` block (trigger, RPC, flow steps, accepted violation kinds, slash dispatch). |
| **SD-JWT VDC wire format** (selective disclosure, `_sd` arrays, salts, `_sd_alg`) per IETF SD-JWT-VC | 🔴 | Tenzro's `Vdc` is plain JSON-with-signature; no selective-disclosure machinery. Spec §5 mandates SD-JWT VC. Belongs in `crates/tenzro-payments/src/ap2/mod.rs`. |
| **ECDSA non-deterministic signatures** (P-256/P-384) per spec §5.3 "to prevent rainbow table attacks" | 🔴 | `Vdc { alg: "ed25519" }` is deterministic by design (RFC 8032). Spec mandates non-deterministic. Need a P-256 signing path alongside Ed25519 for cross-vendor interop. |
| **`checkout_jwt` → `checkout_hash` binding** (Payment Mandate references the SHA-256 of the Checkout Mandate JWT) per spec §6.2.3 | 🟢 | `PaymentMandate::checkout_hash: Option<String>`; `Vdc::checkout_hash()` computes SHA-256 over the canonical preimage. Cross-checked in `MandateValidator::validate()` — mismatch is a hard fail. |
| **Checkout Receipt JWT + Payment Receipt JWT** (issued by MPP/TS post-settlement) per spec §7 | 🔴 | No receipt JWT issuance path. Belongs in a new `ap2/receipts.rs` or in `mod.rs`. |
| **5-role separation** (SA/CP/M/MPP/TS) — distinct DIDs and signing keys per role | 🔴 | Single `signer_did` field at `crates/tenzro-payments/src/ap2/mod.rs:300-410`; no role distinction surfaced on the wire. Spec §3 enumerates the 5 roles. |
| **Direct vs Autonomous mode** distinction in CheckoutMandate (spec v0.2 §4.4) | 🟡 | TDIP `DelegationScope` carries equivalent runtime enforcement (max_transaction_value, time_bound, allowed_operations) but not the AP2 wire-level `mode` field. |

---

## 4. x402 — HTTP 402 Payment Protocol (Coinbase)

**Canonical spec:** `github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md` (v1, 2026-02). Wire: `PaymentRequirements` JSON in 402 response body, `X-PAYMENT` base64-JSON request header carrying `PaymentPayload`, facilitator `POST /verify` and `POST /settle`. The `exact` scheme atop EIP-3009 is the on-chain reference.

**Tenzro implementation:** `crates/tenzro-payments/src/x402/{mod,payment_required,payment_payload,server,client,facilitator,coinbase,scheme}.rs`. RPC: `tenzro_payX402` at `crates/tenzro-node/src/rpc.rs:721`.

| Field / Component | Status | Cite |
|---|---|---|
| `X402PaymentRequired { accepts[], error }` envelope | ✅ | `crates/tenzro-payments/src/x402/payment_required.rs` |
| Per-requirement `to_base64` / `from_base64` for header transport | ✅ | `crates/tenzro-payments/src/x402/payment_required.rs:61-71` |
| Scheme registry with default backends (`tenzro-hybrid`, `exact-eip3009`, `eip3009`, `permit2`, `erc7710`) | ✅ | `crates/tenzro-payments/src/x402/scheme.rs:137-156` |
| `tenzro-hybrid` default scheme: Ed25519 over `chain‖asset‖amount‖recipient‖payer` | ✅ | `crates/tenzro-payments/src/x402/scheme.rs:280-336` |
| EIP-3009 `transferWithAuthorization` ABI calldata encoder (selector `0xe3ee160e` + 9 padded params) | ✅ | `crates/tenzro-payments/src/x402/coinbase.rs:411-440` |
| Coinbase CDP facilitator `POST /verify` HTTP client | ✅ | `crates/tenzro-payments/src/x402/coinbase.rs:220-268` |
| Coinbase CDP facilitator `POST /settle` HTTP client | ✅ | `crates/tenzro-payments/src/x402/coinbase.rs:278-326` |
| `verify_and_settle` combined flow | ✅ | `crates/tenzro-payments/src/x402/coinbase.rs:333-361` |
| Well-known USDC token addresses (Base mainnet/sepolia, Ethereum mainnet/sepolia) | ✅ | `crates/tenzro-payments/src/x402/coinbase.rs:443-452` |
| CAIP-2 chain identifiers (`eip155:8453`, `eip155:84532`, `eip155:1`, `eip155:11155111`, `eip155:1337`) | ✅ | `crates/tenzro-payments/src/x402/coinbase.rs:74-88` |
| Permit2 / ERC-7710 backend scaffolding (delegated to facilitator / DelegationVerifier) | ✅ | `crates/tenzro-payments/src/x402/scheme.rs:601-787` |
| Local in-process facilitator with scheme dispatch | ✅ | `crates/tenzro-payments/src/x402/facilitator.rs:82-238` |
| **Top-level `x402Version: 1` field** on PaymentRequirements per spec §3.1 | 🔴 | `X402PaymentRequired` (`crates/tenzro-payments/src/x402/payment_required.rs`) has no `x402Version`. Comment at `payment_payload.rs:1-6` codifies the omission as Tenzro-internal hygiene but breaks spec §3.1 cross-vendor parsing. |
| **PaymentRequirements field naming** per spec §3.1: `network`, `maxAmountRequired`, `payTo`, `mimeType`, `description`, `resource`, `scheme`, `maxTimeoutSeconds`, `outputSchema` | 🔴 | Tenzro `X402PaymentRequirement { chain, asset, amount, recipient, expires_at, extra }`: field rename divergence (`chain` ≠ `network`, `amount` ≠ `maxAmountRequired`, `recipient` ≠ `payTo`), top-level `mimeType`/`description`/`resource`/`maxTimeoutSeconds` missing, `scheme` only resolvable via `extra["scheme"]`. Belongs at `crates/tenzro-payments/src/x402/payment_required.rs`. |
| **PaymentPayload nested shape** per spec §4: `{x402Version, scheme, network, payload: {signature, authorization: {from, to, value, validAfter, validBefore, nonce}}}` | 🔴 | Tenzro flat `X402PaymentPayload { chain, asset, amount, payer, authorization: String, signature: String }` at `crates/tenzro-payments/src/x402/payment_payload.rs:11-25` is fundamentally non-isomorphic to the spec nested shape — a CDP-spec-conformant client cannot deserialize a Tenzro payload, and vice versa. |
| **`X-PAYMENT` request header** carrying base64(PaymentPayload-JSON) per spec §2.1 | 🟡 | The `coinbase.rs` doc comment references `X-PAYMENT` (line 132) but the in-process server consumes payloads via JSON body, not the header. Server-side header extraction belongs in `crates/tenzro-payments/src/x402/server.rs`. |
| **`X-PAYMENT-RESPONSE` response header** carrying base64(SettlementResponse-JSON) per spec §2.2 | 🔴 | `coinbase.rs` mentions the verify→serve→settle order but no response-side `X-PAYMENT-RESPONSE` header is emitted from the facilitator or the in-process server. |
| **SettlementResponse shape** per spec §5: `{success, transaction, network, payer, errorReason}` | 🟡 | Tenzro `SettleResponse { success, tx_hash, network, error }` at `crates/tenzro-payments/src/x402/coinbase.rs:163-177`. Field names `tx_hash` ≠ `transaction`, `error` ≠ `errorReason`; missing `payer`. |
| **Standard error reasons** per spec §6: `insufficient_funds`, `invalid_signature`, `expired_authorization`, `nonce_already_used`, `network_unsupported`, `scheme_unsupported` | 🟡 | Spec error vocabulary not encoded as a typed enum; `error: Option<String>` is free-form at `crates/tenzro-payments/src/x402/coinbase.rs:170`. |
| **Tenzro extension — cross-VM `network` field**: accepts `tenzro-evm`, `tenzro-svm`, `tenzro-daml` (no third-party x402 extension covers DAML/Canton) | 🟢 | `TenzroNetwork::parse` and `validate_network_format` at `crates/tenzro-payments/src/x402/receipt.rs`; advertised via `tenzro_x402ProtocolInfo.tenzro_extensions.cross_vm_network`. |
| **Tenzro extension — Plonky3 settlement-AIR commitment** in `X-PAYMENT-RESPONSE` body via `tenzroCommitment` field (32-byte SHA-256, domain-separated `tenzro/x402/receipt`, length-prefixed canonical settlement summary; binds scheme/network/challenge_id/credential_id/resource/asset/amount/payer/recipient/tx_hash) | 🟢 | `compute_settlement_commitment` + `X402SettlementReceiptBody::finalized` at `crates/tenzro-payments/src/x402/receipt.rs`. Stashed in `PaymentReceipt.extra["x_payment_response"]` by `X402PaymentServer::settle` for transport-layer base64 encoding. Cryptographic finality via validators verifying corresponding Plonky3 proof off-EVM and matching against `ZkCommitmentRegistry`. 12 unit tests (commitment determinism, concatenation-collision resistance, hex normalization, JSON round-trip). |
| **`tenzro_x402ProtocolInfo` RPC** advertising spec, schemes, default scheme, and Tenzro extensions with binding-field list | 🟢 | `crates/tenzro-node/src/rpc_integrations.rs::handle_x402_protocol_info` dispatched in `crates/tenzro-node/src/rpc.rs`. |

---

## 5. RFC 9421 — HTTP Message Signatures

**Canonical spec:** RFC 9421 (Feb 2024). Algorithm registry §3.3 (7 algos), derived-component vocabulary §2.2 (9 components), parameter set §2.3 (created/expires/nonce/keyid/alg/tag), canonicalization §2.1.

**Tenzro implementation:** `crates/tenzro-payments/src/rfc9421/{signature,registry,nonce,jwks,mod}.rs`.

| Algorithm / Component | Status | Cite |
|---|---|---|
| `ed25519` (RFC 8032) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:642-662` |
| `ecdsa-p256-sha256` (NIST P-256 + SHA-256) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:666-708` |
| `ecdsa-p384-sha384` (NIST P-384 + SHA-384) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:710-748` |
| `rsa-pss-sha256` (RSASSA-PSS, MGF1-SHA-256, salt = hash) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:752-785` |
| `rsa-pss-sha512` (RSASSA-PSS, MGF1-SHA-512, salt = hash) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:752-785` |
| `rsa-v1_5-sha256` (RSASSA-PKCS1-v1_5 + SHA-256) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:787-812` |
| `hmac-sha256` (HMAC-SHA-256) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:816-841` |
| Derived component `@method` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:496` |
| Derived component `@authority` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:497` |
| Derived component `@scheme` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:498` |
| Derived component `@path` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:499` |
| Derived component `@query` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:500-504` |
| Derived component `@request-target` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:505-513` |
| Derived component `@target-uri` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:514-522` |
| Derived component `@query-param;name="..."` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:523-540` |
| Derived component `@status` (response signing) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:541-547` |
| Parameter `created` (Unix timestamp) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:284-288` |
| Parameter `expires` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:289-293` |
| Parameter `nonce` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:294-296` |
| Parameter `keyid` (required) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:297-299, 313-317` |
| Parameter `alg` (required) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:300-302, 319-321` |
| Parameter `tag` | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:303-305` |
| `Signature-Input` header parser (§4.1) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:239-336` |
| Signature base construction (§2.5) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:375-409` |
| Field-value canonicalization (§2.1.1: trim, collapse CRLF + WS) | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:575-590` |
| Public-key formats: SPKI DER (preferred) + raw SEC1 + Ed25519 raw 32 bytes | ✅ | `crates/tenzro-payments/src/rfc9421/signature.rs:679-690, 721-730` |
| **Structured Field re-serialization (§2.1)** for `;sf` modifier | 🟡 | Module-level rustdoc at `crates/tenzro-payments/src/rfc9421/signature.rs:24-27` declares it not yet performed. Parser preserves `;sf`, canonicalizer does not re-serialize. |
| **Binary-wrapped value (§2.1.3)** `;bs` modifier | 🟡 | `signature.rs:432-440`: "We don't yet support `bs` (binary-wrapped) or re-serialized Structured Field rendering". |
| `keyid` → public-key resolution via `AgentRegistryClient` | ✅ | `crates/tenzro-payments/src/rfc9421/registry.rs:44-55` |
| Replay protection via `NonceCache` | ✅ | `crates/tenzro-payments/src/rfc9421/nonce.rs` |
| JWKS publication (RFC 7517) | ✅ | `crates/tenzro-payments/src/rfc9421/jwks.rs` |

---

## 6. ERC-8004 — Trustless Agents Registry

**Canonical spec:** ERC-8004 (live 2026-01-29). Three-contract architecture: IdentityRegistry, ReputationRegistry, ValidationRegistry. Selectors are `bytes4(keccak256(canonical_signature))`.

**Tenzro implementation:** Cross-VM trio — EVM canonical proxies deployed at genesis (`crates/tenzro-identity/src/erc8004.rs` adapter + `crates/tenzro-vm/src/precompiles/erc8004.rs` native precompiles at `0x101a` / `0x101b` / `0x101c`), SVM mirror via QuantuLabs' Anchor program (`crates/tenzro-identity/src/erc8004_svm.rs` calldata + `crates/tenzro-node/src/erc8004_svm_mirror.rs` pending-tx queue), and DAML mirror via Tenzro-authored Canton package (`crates/tenzro-identity/src/erc8004_daml.rs` Canton Ledger JSON API v2 commands + `crates/tenzro-node/src/erc8004_daml_mirror.rs` pending-tx queue, source at `vendor/erc8004-daml/daml/Tenzro/Erc8004/`).

| Function / Type | Status | Cite |
|---|---|---|
| `registerAgent(bytes32,address,string)` selector + ABI encoder | ✅ | `crates/tenzro-identity/src/erc8004.rs:108, 190-206` |
| `getAgent(bytes32)` selector + ABI encoder + decoder | ✅ | `crates/tenzro-identity/src/erc8004.rs:110, 209-214, 281-300` |
| `submitFeedback(bytes32,int8,string)` selector + ABI encoder (sign-extended int8) | ✅ | `crates/tenzro-identity/src/erc8004.rs:112, 220-241` |
| `validationRequest(address,uint256,string,bytes32)` selector `0xaaf400c4` + ABI encoder | ✅ | `crates/tenzro-identity/src/erc8004.rs` |
| `validationResponse(bytes32,uint8,string,bytes32,string)` selector `0x3d659a96` + ABI encoder | ✅ | `crates/tenzro-identity/src/erc8004.rs` |
| `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time; reverse DID → id lookup via `OnChainAgentRegistry::lookup_agent_id_by_did` | ✅ | `crates/tenzro-identity/src/erc8004.rs` |
| `Erc8004Transport` trait (eth_call + eth_sendRawTransaction) | ✅ | `crates/tenzro-identity/src/erc8004.rs:64-72` |
| `Erc8004Adapter` high-level client (calldata builders + send_signed) | ✅ | `crates/tenzro-identity/src/erc8004.rs:303-392` |
| Native Tenzro mirroring via `OnChainAgentRegistry::mirror_register_agent` (best-effort, non-blocking) | ✅ | `crates/tenzro-identity/src/erc8004.rs:88-101` |
| Canonical OpenZeppelin-ERC721 upgradeable proxies predeployed at genesis (addresses in `tenzro_identity::erc8004::addresses::{IDENTITY_REGISTRY, REPUTATION_REGISTRY, VALIDATION_REGISTRY}`); writes flow through standard EVM transactions | ✅ | `vendor/erc8004-evm/contracts/{IdentityRegistryUpgradeable,ReputationRegistryUpgradeable,ValidationRegistryUpgradeable}.sol` + predeploy alloc pass in `crates/tenzro-node/src/genesis.rs` |
| `AgentRecord { agent_id, agent_address, metadata_uri }` round-trip | ✅ | `crates/tenzro-identity/src/erc8004.rs` |
| **`setAgentURI(uint256,string)` selector** per ERC-8004 v0.6+ §IdentityRegistry | ✅ | Adapter constant `selectors::SET_AGENT_URI = [0x0a,0xf2,0x8b,0xd3]` at `crates/tenzro-identity/src/erc8004.rs`. Calldata encoder at `Erc8004Adapter::encode_set_agent_uri`. RPC wrapper `tenzro_erc8004EncodeSetAgentURI` returns calldata for caller-signed `eth_sendRawTransaction` submission against the canonical proxy. |
| **`setAgentWallet(uint256,address,uint256,bytes)` selector** per ERC-8004 v0.6+ §IdentityRegistry (`(deadline, signature)` consent pair) | ✅ | Adapter constant `selectors::SET_AGENT_WALLET = [0x2d,0x1e,0xf5,0xae]`. Companion `unsetAgentWallet(uint256)` adapter encoder also available. Calldata flows to caller-signed `eth_sendRawTransaction` against the canonical proxy. |
| **`setMetadata(uint256,string,bytes)` / `getMetadata(uint256,string)`** key-value metadata per ERC-8004 v0.6+ §IdentityRegistry | ✅ | Adapter constants `selectors::SET_METADATA = [0x46,0x66,0x48,0xda]` / `GET_METADATA = [0xcb,0x47,0x99,0xf2]`. Empty `value` deletes per spec. Reads dispatched via `eth_call`; writes via caller-signed `eth_sendRawTransaction`. |
| **`revokeFeedback(uint256,bytes32)` selector** per ERC-8004 v0.6+ §ReputationRegistry | ✅ | Adapter constant `selectors::REVOKE_FEEDBACK = [0xa2,0x83,0x34,0xce]`. Idempotent on-wire per the OpenZeppelin Solidity contract. Companion read `isFeedbackRevoked(uint256,bytes32)`. |
| **`appendResponse(uint256,bytes32,string)` selector** per ERC-8004 v0.6+ §ReputationRegistry | ✅ | Adapter constant `selectors::APPEND_RESPONSE = [0x60,0x1f,0x56,0x76]`. "Latest response wins" — repeated calls overwrite, matching the spec. Companion read `getFeedbackResponses(uint256,bytes32)`. |
| **`getFeedback` / `getFeedbackCount` read selectors** per ERC-8004 §ReputationRegistry | ✅ | Adapter constants `selectors::GET_FEEDBACK = [0x7c,0x9d,0x4f,0x52]` and `selectors::GET_FEEDBACK_COUNT = [0x4e,0x71,0xa2,0x18]`. `Erc8004Adapter::get_feedback` / `get_feedback_count` decode the canonical contract's return shape (`(int8,string,bool)` and `uint256` respectively). |
| **`getValidation` read selector** per ERC-8004 §ValidationRegistry | ✅ | Adapter constant `selectors::GET_VALIDATION = [0x9b,0x2e,0x4f,0x33]`. `Erc8004Adapter::get_validation` returns the 6-field `DecodedValidation { subject, status, validator, task_uri, proof_uri, exists }` shape produced by the canonical proxy. |
| ERC-721 inheritance for IdentityRegistry (NFT representation of agents) | ✅ | Canonical proxy is `IdentityRegistryUpgradeable is ERC721Upgradeable`; standard ERC-721 selectors (`ownerOf`, `transferFrom`, `safeTransferFrom`, `approve`, `setApprovalForAll`) are reachable via standard `eth_call` / `eth_sendRawTransaction` against `addresses::IDENTITY_REGISTRY`. |
| **SVM mirror via QuantuLabs Anchor program** (`https://github.com/QuantuLabs/erc-8004-svm`) | ✅ | `crates/tenzro-identity/src/erc8004_svm.rs` emits Anchor-formatted instruction calldata via `OnChainAgentSvmRegistry`; `crates/tenzro-node/src/erc8004_svm_mirror.rs::NativeErc8004SvmMirror` buffers payloads under `erc8004_svm_pending_tx:` and indexes DID → 32-byte Pubkey under `erc8004_svm_did_index:` in `CF_IDENTITIES`. No `solana-sdk` dep in monorepo by design — drain to a Solana RPC happens in operator-supplied infrastructure. TDIP `register_machine_with_fee` dispatches SVM alongside EVM in the same fanout block. |
| **DAML mirror via Tenzro-authored Canton package** (`vendor/erc8004-daml/daml/Tenzro/Erc8004/{Identity,Reputation,Validation}.daml`) | ✅ | Two-party admin+controller signatory model preserves "single canonical state" without `msg.sender`. `crates/tenzro-identity/src/erc8004_daml.rs` emits Canton Ledger JSON API v2 `submit-and-wait` commands via `OnChainAgentDamlRegistry` as `serde_json::Value` (no `tonic` / Canton-client deps in `tenzro-identity` by design). `crates/tenzro-node/src/erc8004_daml_mirror.rs::NativeErc8004DamlMirror` either dispatches via an installed `DamlMirrorTransport` or buffers under `erc8004_daml_pending_tx:` and indexes DID → 8-byte LE u64 agentId under `erc8004_daml_did_index:`. Package id = SHA-256 of compiled `.dar`, supplied by operator at registry construction via `DamlPackageIds`. Opt-in: wired only when `NodeConfig.erc8004_daml` is present. |

---

## 7. Mastercard Agent Pay

**Canonical spec:** Mastercard Agent Pay (announced 2026-02). Wire stack: RFC 9421 / Web Bot Auth for agent recognition, Agentic Tokens (per-session, per-merchant) mapping to MDES tokenization, KYA (Know Your Agent) verification, MCP Agent Toolkit for tool-call surfaces. Public spec text not yet on developer.mastercard.com (403'd at audit time).

**Tenzro implementation:** `crates/tenzro-payments/src/mastercard/{mod,types,server,client,token_service,kya}.rs`. RPC: `tenzro_payMastercard` at `crates/tenzro-node/src/rpc.rs:724`.

| Field / Component | Status | Cite |
|---|---|---|
| `AgenticTokenType::{SingleUse, SessionBound, Recurring}` | ✅ | `crates/tenzro-payments/src/mastercard/types.rs:10-29` |
| `AgenticToken { token_id, agent_did, token_type, token_data, issued_at, expires_at, domain_restrictions, amount_limit }` | ✅ | `crates/tenzro-payments/src/mastercard/types.rs:31-49` |
| `AgentPayChallenge` (resource, amount, asset, recipient, requires_kya, required_intent_fields, merchant_id, expires_at) | ✅ | `crates/tenzro-payments/src/mastercard/types.rs:52-72` |
| `PurchaseIntent` (intent_id, agent_did, description, items, total_amount, asset, merchant_id, created_at, human_authorization) | ✅ | `crates/tenzro-payments/src/mastercard/types.rs:74-96` |
| `KyaLevel::{Unverified, Basic, Enhanced, Full}` ladder | ✅ | `crates/tenzro-payments/src/mastercard/types.rs:108-131` |
| `KyaVerification` result with audit_trail | ✅ | `crates/tenzro-payments/src/mastercard/types.rs:133-148` |
| `AgentPayDomainEvent` lifecycle events (IdentityVerified, AuthenticatorBound, AgenticTokenIssued, CheckoutInitiated, PaymentCompleted) | ✅ | `crates/tenzro-payments/src/mastercard/types.rs:150-187` |
| RFC 9421 signature verification reuse | ✅ | `crates/tenzro-payments/src/mastercard/server.rs` (delegates to `rfc9421::verify_http_signature`) |
| KYA verifier integrating TDIP `IdentityRegistry` | ✅ | `crates/tenzro-payments/src/mastercard/kya.rs` |
| Agentic token issuance service | ✅ | `crates/tenzro-payments/src/mastercard/token_service.rs` |
| **MDES tokenization-vault-bound `token_data`** (real PAN-shadow per Mastercard MDES spec) | 🟡 | `crates/tenzro-payments/src/mastercard/types.rs:42` types `token_data: String` opaquely — not bound to a real MDES PAR/PAN-replacement vault. Tenzro extension acceptable but not interop-grade. |
| **Web Bot Auth (RFC-9421-derived) `bot-id` directory binding** per Mastercard developer docs preview | 🟡 | RFC 9421 surfaces are present, but no explicit Web-Bot-Auth-style `bot-id` directory or its bot-listing wire shape is implemented. Belongs in `crates/tenzro-payments/src/mastercard/`. |
| **MCP Agent Toolkit tool-call wire** per Mastercard MCP integration | 🔴 | No MCP tool exposes Mastercard endpoints from `crates/tenzro-node/src/mcp/server.rs`. Belongs there. |
| **Tenzro extension: DID-anchored KYA record** wrapping TDIP machine identity (controller + authenticator + delegation_scope) | 🟢 | `crates/tenzro-identity/src/kya.rs` — `KyaRecord::from_identity` projects `TenzroIdentity` across the three KYA axes. RPC: `tenzro_getKyaRecord`. |
| **Tenzro extension: federation-pointer service types** (`MastercardKYA`, `VisaTAP`) on W3C DID Document | 🟢 | `crates/tenzro-identity/src/kya.rs` — `SERVICE_TYPE_MASTERCARD_KYA` / `SERVICE_TYPE_VISA_TAP` constants. `tenzro_addService` RPC persists service entries through `IdentityRegistry::add_service_to_identity`. |
| **Tenzro extension: ERC-8004 Identity precompile mirror** (`0x101a`) auto-invoked on every TDIP machine registration | 🟢 | `crates/tenzro-identity/src/registry.rs` — `OnChainAgentRegistry::mirror_register_agent` hook fires on `register_machine_with_fee` / `register_autonomous_machine_with_fee` and stores the registry-allocated sequential `uint256 agentId` on `IdentityData::Machine.erc8004_agent_id`. Reverse lookup via `OnChainAgentRegistry::lookup_agent_id_by_did`. |
| **Tenzro extension: pure-function KYA level computation** | 🟢 | `crates/tenzro-identity/src/kya.rs::compute_kya_level(status, controller_did, delegation_scope)` — four-tier ladder consumed by payments-side `KyaVerifier`. |
| **Tenzro extension: profile / discovery RPC** | 🟢 | `crates/tenzro-node/src/rpc_integrations.rs::handle_mastercard_kya_protocol_info` — advertises three KYA axes, federation service types, ERC-8004 mirror precompile, four-tier ladder, delegation enforcement entry point. |

(Note: Mastercard Agent Pay does not have a publicly fetchable normative wire spec at audit time — the developer portal returned 403. Gap claims that depend on private spec text are marked 🟡 rather than 🔴 to flag the uncertainty.)

---

## 8. Stripe Issuing / SPT (SharedPaymentToken)

**Canonical spec:** Stripe Issuing API + SharedPaymentToken (2026-Q1 GA). Wire: `SharedPaymentIssuedToken` and `SharedPaymentGrantedToken` resources with `usage_limits {currency, max_amount, expires_at}`, status state machine (`requires_action` → `active` → `used` / `deactivated`), revoke endpoint, webhooks `shared_payment.issued_token.*` + `shared_payment.granted_token.deactivated`, PaymentIntent confirmation via `payment_method_data[shared_payment_granted_token]`.

**Tenzro implementation:** None. Stripe integration is limited to Payment Intents (covered above under MPP §1).

| Field / Component | Status | Cite |
|---|---|---|
| **Research note** | 🟡 | `docs/protocol-research-2026-05/stripe-spt.md` — federation design, three-ceiling enforcement (TDIP DelegationScope ↔ SPT `usage_limits` mapping), ERC-8004 reputation cross-write, AP2 cart-mandate ↔ SPT binding, Tempo settlement alternative. Implementation pending per items below. |
| Stripe Payment Intents `POST /v1/payment_intents` (used for MPP base path) | ✅ | `crates/tenzro-payments/src/mpp/stripe.rs:44-94` |
| Stripe webhook HMAC-SHA256 verification | ✅ | `crates/tenzro-payments/src/mpp/stripe.rs:23-32` |
| `SharedPaymentIssuedToken` resource shape | 🟡 | Research published (`docs/protocol-research-2026-05/stripe-spt.md` §Implementation order #2). Belongs in new `crates/tenzro-payments/src/mpp/stripe_spt.rs`. Spec: Stripe Issuing SPT GA docs §Issued tokens. |
| `SharedPaymentGrantedToken` resource shape | 🟡 | Research published. Same target module. Spec: Stripe Issuing SPT GA docs §Granted tokens. |
| `usage_limits { currency, max_amount, expires_at }` enforcement | 🟡 | Research published — design specifies three-ceiling enforcement (DelegationScope | SpendingPolicy | SPT cap), `SptCeilingResolver` trait alongside `SpendingPolicyResolver` at `crates/tenzro-payments/src/identity_binding.rs:71`. |
| Status state machine `requires_action` → `active` → `used` / `deactivated` | 🟡 | Research published. Typed `SptStatus` enum in target module. |
| Revoke endpoint (`POST /v1/shared_payment/issued_tokens/{id}/revoke`) | 🟡 | Research published. Wires into TDIP `apply_remote_revocation()` cascade per research §Implementation order #4. |
| Webhook events `shared_payment.issued_token.created`, `shared_payment.issued_token.activated`, `shared_payment.granted_token.deactivated` | 🟡 | Research published. Extends existing webhook verifier (`crates/tenzro-payments/src/mpp/stripe.rs:450`) with typed dispatcher. |
| PaymentIntent confirmation via `payment_method_data[shared_payment_granted_token]` | 🟡 | Research published. New `confirm_intent_with_spt()` method on `StripeClient`. |
| **Tenzro extension: DID-anchored SPT issuance** (`SERVICE_TYPE_STRIPE_SPT = "StripeSPT"` on W3C DID Document) | ✅ | `crates/tenzro-identity/src/kya.rs:57-61`; predicate `is_kya_service_type` accepts the constant; re-exported from `tenzro_identity` crate root. |
| **Tenzro extension: ERC-8004 reputation cross-write on SPT outcomes** | 🔴 | Research published — fan SPT webhook outcomes to `ReputationRegistry.submitFeedback` at precompile `0x101b` per `crates/tenzro-identity/src/erc8004.rs`. |
| **Tenzro extension: AP2 cart-mandate ↔ SPT binding** in `tenzro_validateMandatePair` | 🔴 | Research published — extends existing AP2 validator at `crates/tenzro-payments/src/ap2/mod.rs` to verify SPT `usage_limits` matches cart envelope. |
| **Tenzro extension: Tempo settlement alternative** for SPT-bound mandates | 🔴 | Research published — same TDIP delegation + AP2 mandate, dispatch via `TempoParticipant` (`crates/tenzro-payments/src/tempo/participant.rs`) instead of Stripe PI confirm. Cross-link `tempo-l1.md`. |
| **Tenzro extension: profile / discovery RPC** (`tenzro_stripeSptProtocolInfo`) | 🔴 | Research published — mirrors `tenzro_mastercardKyaProtocolInfo` / `tenzro_visaTapProtocolInfo` shape. |

---

## 9. Tempo L1 — Stripe + Paradigm payments chain

**Canonical sources:** `tempo.xyz`, `docs.tempo.xyz`, `paradigm.xyz/2025/09/tempo-payments-first-blockchain`, `tempo.xyz/blog/tip20/`. EVM-compatible L1 with Reth execution + Simplex BFT consensus (~0.5–0.6s deterministic finality, no reorgs), no native gas token (fees in stablecoins via enshrined AMM), TIP-20 stablecoin standard backward-compatible with ERC-20, dedicated payment-lane blockspace. Mainnet March 2026; testnet "Moderato" since Dec 2025. See `docs/protocol-research-2026-05/tempo-l1.md`.

**Tenzro implementation:** `crates/tenzro-payments/src/tempo/{adapter,participant,stablecoin,config,mod}.rs`.

| Field / Component | Status | Cite |
|---|---|---|
| `TempoConfig` (chain_id 42431, mainnet/Moderato testnet RPCs, per-stablecoin contract map) | ✅ | `crates/tenzro-payments/src/tempo/config.rs:7-76` |
| `TempoBridgeAdapter` implementing `tenzro_bridge::traits::BridgeAdapter` (bridge_tokens, get_transfer_status, estimate_fee, send/receive_message) | ✅ | `crates/tenzro-payments/src/tempo/adapter.rs:67-378` |
| `TempoParticipant` direct-settlement client with optional Secp256k1 signing key | ✅ | `crates/tenzro-payments/src/tempo/participant.rs:371-411` |
| EIP-155 transaction signing (`EvmTransaction::sign_eip155`) — RLP → Keccak-256 → k256 recoverable sign with `v = chain_id*2 + 35 + recovery_id` | ✅ | `crates/tenzro-payments/src/tempo/participant.rs:118-146` |
| `eth_sendRawTransaction` submission + `eth_getTransactionReceipt` finality polling (Simplex BFT: receipt = finalized) | ✅ | `crates/tenzro-payments/src/tempo/participant.rs:319-350, 648-682` |
| TIP-20 ABI helpers: `encode_balance_of` / `encode_transfer` / `encode_approve` / `encode_decimals` / `decode_uint256` (selectors byte-identical to ERC-20 — TIP-20 is backward-compatible) | ✅ | `crates/tenzro-payments/src/tempo/stablecoin.rs:80-137` |
| `Tip20Token` / `Tip20Balance` (USDC/USDT factories, decimal-aware `display_amount()`) | ✅ | `crates/tenzro-payments/src/tempo/stablecoin.rs:23-75` |
| `TempoParticipant::settle_mpp_batch` — per-entry signed TIP-20 transfers with structured success/failure summary | ✅ | `crates/tenzro-payments/src/tempo/participant.rs:577-642` |
| `MppReceipt.chain = "tempo"` default + `principal_chain` audit trail records Tempo as a settlement venue | ✅ | `crates/tenzro-payments/src/mpp/receipt.rs:56, 32` |
| EIP-55 checksummed address formatting + parse helpers + signing-key→address derivation | ✅ | `crates/tenzro-payments/src/tempo/participant.rs:153-204` |
| **TIP-20 catalog mirror in unified `TokenRegistry`** — new `TokenVmType::TempoTip20` alongside `Native\|Evm\|Svm\|Daml` | 🟡 | Research published (`docs/protocol-research-2026-05/tempo-l1.md` §Implementation order #2). `crates/tenzro-token/src/cross_vm.rs:11` enumerates only Native/Evm/Svm/Daml; ingestion path belongs in `crates/tenzro-token/src/registry.rs`; cross-VM router at `crates/tenzro-vm/src/cross_vm_bridge.rs`. |
| **DID-anchored Tempo identity** (`SERVICE_TYPE_TEMPO_ACCOUNT = "TempoAccount"`) for `did:tenzro:machine:*` DID Documents | ✅ | `crates/tenzro-identity/src/kya.rs:63-67`; predicate `is_kya_service_type` accepts the constant; persisted via `IdentityRegistry::add_service_to_identity`. |
| **AP2 CheckoutMandate `accepted_chains` Tempo route** so MPP router selects Tempo when accepted | 🟡 | Research published. Cart-mandate parsing at `crates/tenzro-payments/src/ap2/mod.rs` + MPP router selection in `crates/tenzro-payments/src/mpp/`. |
| **`tenzro_tempoProtocolInfo` RPC** (profile/discovery alongside `tenzro_visaTapProtocolInfo` / `tenzro_x402ProtocolInfo` / `tenzro_mastercardKyaProtocolInfo`) | ✅ | `crates/tenzro-node/src/rpc_integrations.rs::handle_tempo_protocol_info` dispatched at `crates/tenzro-node/src/rpc.rs:955`. Surfaces chain_id, RPC endpoints, Reth+Simplex BFT model, TIP-20 compatibility, EIP-155 signing path, DID-anchored TempoAccount federation, and out-of-scope clarifications. |

(Tempo is a settlement venue, not a TNZO bridge — TNZO native bridging stays on Wormhole NTT per `project_interop_architecture`. Validator participation, Simplex BFT integration, and non-stablecoin Tempo bridges are explicitly out of scope.)

---

## Totals

| Status | Count |
|---|---|
| ✅ Implemented | **100** |
| 🟢 Tenzro extension | **5** |
| 🟡 Partial | **23** |
| 🔴 Missing | **24** |

(Counts are conservative: rows that combine two spec items under one bullet count as one. Re-running with item-level granularity would push ✅ higher.)

---

## Top 5 Highest-Leverage Gaps

1. **AP2 v0.2 mandate-pair refresh.** Tenzro still names mandates `Intent` + `Cart` and signs them with deterministic Ed25519. Spec v0.2 §6 renamed them to **Checkout Mandate + Payment Mandate**, mandates SD-JWT VC envelopes with `vct` schema versioning + `checkout_hash` binding, and requires non-deterministic ECDSA per §5.3. Without this, Tenzro AP2 wire cannot be parsed by any spec-conformant SA/CP/MPP/TS counterparty. Files to touch: `crates/tenzro-payments/src/ap2/mod.rs:240-410` plus a new `ap2/sd_jwt.rs` and `ap2/receipts.rs`. *Highest leverage: a single migration unlocks Google + Stripe + every AP2 vendor.*

2. **x402 v1 wire-shape conformance.** PaymentRequirements field renames (`chain`→`network`, `amount`→`maxAmountRequired`, `recipient`→`payTo`), missing `x402Version`/`mimeType`/`description`/`maxTimeoutSeconds`, missing `payTo`, and the flat-vs-nested PaymentPayload divergence make Tenzro x402 *unable to round-trip* with the canonical Coinbase facilitator at the wire level today. Files: `crates/tenzro-payments/src/x402/payment_required.rs`, `crates/tenzro-payments/src/x402/payment_payload.rs`. *High leverage: x402 is the single most-deployed agent payment wire in 2026.*

3. **Stripe SPT (SharedPaymentToken) end-to-end.** Zero implementation. SPT is the canonical wire format Stripe + Tempo will route MPP through at GA — without `SharedPaymentIssuedToken` / `SharedPaymentGrantedToken` types, `usage_limits` enforcement, status state machine, revoke endpoint, and SPT-specific webhook handlers, Tenzro MPP cannot integrate with the production Stripe stack. Files: new `crates/tenzro-payments/src/mpp/stripe_spt.rs` + integration in `identity_binding.rs`. *Strategic leverage: SPT is the bridge between TDIP DelegationScope and Stripe's identity layer.*

4. **MPP IETF wire headers (`WWW-Authenticate: Payment` + `Authorization: Payment`).** Tenzro emits a non-standard `Payment-Required: true` response header and accepts credentials in the JSON body. The IETF `draft-httpauth-payment-00` mandates the RFC 7235 auth-scheme headers so off-the-shelf user agents (browsers, axios, curl) can route the challenge automatically. Files: `crates/tenzro-payments/src/middleware.rs:256-260`, `crates/tenzro-payments/src/mpp/server.rs`, `crates/tenzro-payments/src/mpp/challenge.rs`. *Compatibility leverage: this is the difference between "Tenzro plugin needed" and "any HTTP client works".*

5. **Visa TAP `tag` taxonomy + paymentCredentialsHash.** Visa spec §4.2/§4.3 makes `tag="agent-browser-auth"` vs `tag="agent-payer-auth"` *semantically load-bearing* — verifiers must reject signatures whose tag does not match the request context. Tenzro currently sets `tag: None` everywhere (`crates/tenzro-payments/src/visa_tap/verifier.rs:263`). The 23-digit `paymentCredentialsHash` (PAN+exp+CSC SHA-256) is also collapsed into an opaque `token_hash`. Files: `crates/tenzro-payments/src/visa_tap/server.rs`, `crates/tenzro-payments/src/visa_tap/types.rs`. *Compliance leverage: Visa rejection on signature is the most common production failure mode.*

---

## Out of Audit Scope

- **Multi-modal AI inference RPCs**, **bridge wire formats** (LayerZero / CCIP / deBridge / Wormhole), **TDIP DID method registration** — separate audit.
- **EVM precompile-level ERC-8004 selector validation** at `0x101a` / `0x101b` / `0x101c` — not directly read in this pass; verifying byte-for-byte selector parity with `crates/tenzro-identity/src/erc8004.rs::selectors` belongs in a follow-up.
- **MCP Agent Toolkit (Mastercard) wire surfaces** — implementation depth undeclared without the private Mastercard developer-portal spec.
