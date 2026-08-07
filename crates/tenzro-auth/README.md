# tenzro-auth

OAuth 2.1 + DPoP + RAR authentication and authorization for the Tenzro Network.

## Overview

Every token this crate issues is bound to three things: a TDIP DID, a
holder-of-key proof (RFC 9449), and an explicit narrowly-scoped authorization
request (RFC 9396). A caller that holds only the JWT holds nothing — the
request must also carry a fresh DPoP proof signed by the key the token names.

The crate is auth, not identity. It does not provision identities or wallets,
does not sign transactions, and does not serve the OAuth `/authorize` HTML
flow. It answers one question: is the bearer of this token, proving possession
of this key, authorized to take this action for this DID?

## Design principles

1. **Proof-of-possession, not bearer.** Every JWT carries a `cnf` claim with
   the RFC 7638 SHA-256 thumbprint of the holder's public key. Every protected
   request must carry a `DPoP` header signed by that key over
   `(htm, htu, iat, jti, ath)`. A bearer-only request is rejected even when the
   JWT signature validates.
2. **Narrow additive scopes.** Authorization is a list of RAR
   `authorization_details` entries — typed envelopes such as
   `{type: "transfer", asset: "TNZO", max_amount: 1000000000000000000}`. A
   request is permitted only when some grant strictly covers it. There is no
   implicit fallback, no string scope, no `"all"` shorthand.
3. **No private keys on the wire.** Onboarding returns a token bound to a key
   the caller already controls. The node never sees or stores user signing
   material.
4. **Cascading revocation by act-chain.** Revoking a token also revokes every
   token whose `controller_did` points back at the revoked DID, transitively.
5. **Append-only approvals.** A request that exceeds its delegation ceiling is
   recorded and returns `AuthError::ApprovalRequired { approval_id }`. The
   approval record is never mutated in place; status changes append a new
   history entry.

## Key Types

| Type / fn | Role |
|---|---|
| `AuthEngine` | Singleton owned by the node; issues, validates, and revokes JWTs |
| `AuthEngine::issue_jwt` | Mints a DPoP-bound JWT for an onboarded identity |
| `AuthEngine::validate_jwt` | Validates a JWT plus DPoP proof against scope and binding |
| `AuthEngine::revoke` | Revokes a token, cascading through the act-chain |
| `AuthEngine::resolve_authority` | Walks the DID → controller chain, returning the signing DID and its delegation envelope |
| `AuthEngineConfig` | Token lifetimes, DPoP nonce window, replay-cache bounds |
| `AuthClaims` / `Cnf` | JWT body: `cnf`, `authorization_details`, `controller_did`, `act` |
| `AuthorizationDetail` / `AuthorizationDetails` / `ResourceConstraint` | RAR scope envelopes per RFC 9396 |
| `DpopProof` / `DpopVerification` | RFC 9449 `DPoP-Proof` header parsing and verification |
| `TokenExchangeRequest` / `TokenExchangeOutcome` | RFC 8693 token exchange; `rar_is_subset` and `detail_covers` are the containment checks that keep an exchanged token no broader than its parent |
| `IntrospectionResponse` | RFC 7662 introspection body |
| `AuditEvent` / `AuditEventKind` | Append-only event log entries |
| `ApprovalRecord` / `ApprovalStatus` | Human-in-the-loop approval state |
| `RefreshTokenEntry` | Refresh-token record with its own binding |
| `AuthError` | Typed error surface |
| `parse_attestation` | Verifies a WebAuthn attestation object and returns what the device actually proved |
| `RegistrationFacts` | Output of `parse_attestation`: AAGUID, UP/UV/BE/BS/AT flags, sign counter, attestation format, key protection, whether the chain verified |
| `AttestationError` | Typed failure surface for attestation parsing and chain verification |

### AAP (Agent Access Protocol)

The `aap` module projects RAR grants into the agent-oriented claim set an
agent-to-agent caller expects: `AapAgentClaim`, `AapCapabilityClaim`,
`AapDelegationClaim`, `AapTaskClaim`, `AapContextClaim`, `AapOversightClaim`,
`AapAuditClaim`, `AapConstraints`, `AapTimeWindow`. `rar_to_aap_action` and
`authority_action_to_aap` translate between the two vocabularies, and
`aap_capabilities_is_subset` is the containment check on the AAP side — the
same discipline as `rar_is_subset`, so delegation cannot widen through a
change of vocabulary.

## Trust model

The issuer is the node. Each JWT is HS256-signed with a per-node-instance
secret derived from that node's identity keypair, so a token issued by one node
is presented to that node. Cross-node token validation needs validator-quorum
signing and is not attempted here.

## Storage

`AuthEngine` is `Send + Sync`, every method takes `&self`, hot caches (recent
JWTs, recent DPoP nonces for replay protection) sit in `dashmap`, and durable
state writes through to RocksDB via `KvStore::write_batch_sync`.

- **`CF_AUDIT`** — `audit:<ulid>` holds the JSON `AuditEvent`. ULIDs sort
  lexicographically by time, so a prefix scan returns events in order with no
  separate timestamp index. `audit_did:<did>:<ulid>` indexes every event for a
  DID; `audit_jti:<jti>` maps a token id back to its issuance event so
  revoke-by-jti can find the bound DID.
- **`CF_APPROVALS`** — `approval:<approval_id>` holds the JSON
  `ApprovalRecord`; `approval_pending:<approver_did>:<approval_id>` is the
  approver's queue index.


## WebAuthn attestation (`webauthn_attestation`)

Answers one question: **did vendor-placed hardware sign this, or is a piece of
software claiming it did?**

A passkey is hardware-bound only when its credential cannot be replicated off
the device *and* an attestation verified against a pinned vendor root says the
key lives in a TEE or secure element. The two are separate checks and neither
implies the other. `parse_attestation` reads the `authenticatorData` flags,
AAGUID and signature counter out of the CBOR attestation object, then verifies
the attestation certificate chain against the roots the operator pinned
(`webauthn_trusted_roots` in `NodeConfig`, base64 DER).

- **`BE` (backup-eligible) is disqualifying, not informational.** A credential
  that *may* sync proves control of a cloud account rather than possession of a
  device, so a backup-eligible credential is never hardware-bound however it is
  currently stored.
- **No platform account is an identity authority.** Apple, Google and Microsoft
  sign-ins are not trusted; what is trusted is a signature from vendor-placed
  hardware over a challenge Tenzro chose, matched to a root by AAGUID via the
  FIDO Metadata Service.
- Formats handled: `packed`, `tpm`, `apple`, `android-key`, and `none`. `none`
  parses but proves nothing and can never be graded hardware-bound. For
  `android-key` the key-description extension (OID `1.3.6.1.4.1.11129.2.1.17`)
  is parsed so StrongBox versus TEE residency is a fact rather than an
  assumption.
- An unverifiable chain **degrades the grade** rather than failing the parse —
  the caller sees `chain_verified: false` and decides, so an operator who has
  pinned no roots gets an honest answer instead of a silent pass.

Consumed by `tenzro-node`'s `device_rpc` (`tenzro_bindDevice`), which refuses a
binding whose evidence does not support the grade the identity needs.

## Used By

- **`tenzro-node`** — owns the `AuthEngine`, exposes `tenzro_oauthDiscovery` /
  `tenzro_exchangeToken` / `tenzro_introspectToken`, serves `/oauth/token`,
  `/oauth/introspect`, `/oauth/revoke`, and `/.well-known/jwks.json`, and gates
  the ambient-auth signing path on `resolve_authority`.
- **`tenzro-cli`** — `tenzro auth` and `tenzro approval` command groups, and
  `tenzro device` for the bindings this crate's attestation verifier grades.

## Tests

```bash
cargo test -p tenzro-auth
```

## License

Apache-2.0.
