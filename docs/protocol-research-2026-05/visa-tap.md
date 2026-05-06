# Visa TAP Agent-Recognition Layer — Research

**Date:** 2026-05-05
**Source:** https://github.com/visa/trusted-agent-protocol, https://developer.visa.com/capabilities/trusted-agent-protocol/

**Scope:** identity-only. Fiat-side `paymentCredentialsHash` (23-digit token) is OUT of scope.

## Tag taxonomy

> "the tag field indicates the type of agent interaction — if the agent is browsing, the tag should be `agent-browser-auth`, and if the agent is paying, the tag should be `agent-payer-auth`."

- `agent-browser-auth` — product details / browse
- `agent-payer-auth` — checkout / payment intent

Signature components (both tags): `@authority`, `@path`, `created`, `expires`, `nonce`, `keyid`, `tag`. Body `digest` covers payload integrity for POST. `@method` not listed.

## Created-age window

> "The timestamps (`created` and `expired`) should fall within the current GMT time and should not be more than 8 minutes apart."

8 min = 480 s. **Normative SHOULD**, not MUST.

## Algorithms

- **Ed25519** ("modern, recommended")
- **RSA-PSS-SHA256** ("traditional alternative")

ECDSA P-256 is **not** specified by TAP. (Cloudflare's web-bot-auth profile of RFC 9421 also uses Ed25519.)

## Identity assertion

> "Visa publishes public keys on the web in the following well-known location (`https://mcp.visa.com/.well-known/jwks`)… Each key must be easily identifiable so it can be selected by the relying party based on the `kid` or `keyid` specified in the header of the JWS or Signature-Input."

Centralized JWKS, gated by Visa Intelligent Commerce vetting. `keyid` = JWKS `kid`. **No DID, no blockchain, no decentralized resolver in the spec.**

## Tenzro angle (YES)

- **DID-resolvable `keyid`**: RFC 9421 `keyid` is an opaque string. `keyid="did:tenzro:machine:<uuid>"` resolves via `tenzro_resolveDidDocument` for the Ed25519 verification key — drop-in DID alternative to Visa's JWKS for the recognition layer.
- **Dual-purpose signature**: same Ed25519 signature over the RFC 9421 base string is (a) verifiable by TAP-aware merchant against resolved DID Document, (b) submittable to ERC-8004 `submitFeedback` (precompile `0x101b`) as on-chain peer-attestable reputation.
- **No public DID-based or blockchain-anchored TAP implementation exists** — `bug-ops/tap-mcp-bridge` uses Ed25519+JWKS, ERC-8004 isn't bridged to TAP anywhere.

## Implementation order

1. **`tag` taxonomy in signing/verification** (DONE): `AgentTag::{BrowserAuth, PayerAuth}` enum in `crates/tenzro-payments/src/visa_tap/types.rs` with `parse(&str) -> Option<Self>` / `as_str(&self) -> &'static str` and kebab-case serde. `TapVerifier::with_required_tag(AgentTag)` lets endpoints pin the expected tag. Stage 7 of the verify pipeline rejects unknown tag values and enforces the required tag when set; the parsed tag surfaces on `VerificationResult.verified_tag` so payment endpoints can require `PayerAuth` while browse endpoints require `BrowserAuth`.
2. **480s `created`-age window** (DONE — already default): `TapVerifier::new` initializes `max_signature_age = Duration::from_secs(480)`, matching `VisaTapChallenge::default().max_signature_age_secs = 480`. Stage 3 of the verify pipeline rejects signatures whose `created` parameter is older than 480s or in the future.
3. **DID-resolvable keyid** (DONE): `DidResolverAgentRegistry` in `crates/tenzro-payments/src/visa_tap/did_registry.rs` is a composite `AgentRegistryClient` that routes any `keyid` starting with `did:` through a DID resolver (TDIP via `TenzroAgentRegistry`) and any other `keyid` through a JWKS fallback (`VisaAgentRegistryClient`). Constructors: `DidResolverAgentRegistry::new(did, jwks)`, `did_only(did)`, `jwks_only(jwks)`. RFC 9421 §2.3 leaves `keyid` opaque — a DID-form `keyid` is fully spec-compliant and works against any conformant verifier; only Tenzro-aware verifiers can resolve it without network round-trips.
4. **ERC-8004 reputation write-through**: successful `agent-payer-auth` settlement → `submitFeedback` to precompile `0x101b`. Belongs in a later wave because it touches precompile dispatch; the recognition layer already exposes the verified `agent_did` + `verified_tag` fields needed to build the feedback call.

## RPC surfacing

`tenzro_visaTapProtocolInfo` advertises the spec, covered components, accepted signing algorithms, the 480s `created`-age window, the tag taxonomy, and the two Tenzro extensions (`tag_taxonomy`, `did_resolvable_keyid`) with their rationale and JWKS-fallback note. Wired in `crates/tenzro-node/src/rpc.rs`; handler at `crates/tenzro-node/src/rpc_integrations.rs::handle_visa_tap_protocol_info`.
