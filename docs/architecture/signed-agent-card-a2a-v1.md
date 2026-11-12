# A2A 1.0 signed agent cards

The node serves its agent card at `GET /.well-known/agent-card.json` on the
A2A listener. The card carries a `signatures` array of detached JWS values
as defined by the A2A 1.0 specification (section 8.4, `AgentCardSignature`
in section 4.4.7). A node that cannot sign answers `503` and serves no card;
there is no unsigned card and no placeholder signature.

## Why sign the card

An unsigned card can be rewritten by a reverse proxy or a cache: the
interface URL (redirecting RPC traffic), the skills, or the declared
extensions (dropping the required DID envelope extension so a client
believes requests need no signature). A signature over the canonical card
makes any such rewrite detectable.

## Wire shape

```json
{
  "name": "Tenzro Network Agent",
  "supportedInterfaces": [
    {"url": "https://a2a.example/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
  ],
  "capabilities": {
    "streaming": true,
    "pushNotifications": false,
    "extensions": [{"uri": "https://tenzro.com/a2a/extensions/did-envelope", "required": true, "description": "..."}]
  },
  "...": "...",
  "signatures": [
    {"protected": "<base64url JWS protected header>", "signature": "<base64url Ed25519 signature>"}
  ]
}
```

Protected header (itself serialised in RFC 8785 form before base64url):

```json
{"alg": "ES256", "jwk": {"crv": "P-256", "kty": "EC", "x": "<base64url x>", "y": "<base64url y>"}, "kid": "<operator DID>", "typ": "JOSE"}
```

## Signing procedure

1. Take the card JSON and remove `signatures`.
2. Canonicalise it with RFC 8785 (JCS): members sorted by UTF-16 code
   units, numbers as ECMAScript doubles, minimal string escaping.
   Implementation: `crates/tenzro-trust/src/jcs.rs`, tested against the
   RFC 8785 number vectors (Appendix B), the section 3.2.2 sample object and
   the section 3.2.3 ordering example.
3. JWS signing input is `BASE64URL(protected) || "." || BASE64URL(canonical card)`.
   The payload is detached: it is not repeated in the signature object.
4. The signature is produced by `WalletService::sign_external` on the wallet of
   the node's operator DID (`TenzroNode::operator_did`). The wallet service
   holds no private key: it signs only through the hybrid signer bound to the
   wallet (device custody: Secure Enclave, TPM), and refuses otherwise. The
   operator's hardware P-256 key signs SHA-256 of the signing input, `r || s`
   (JWS `alg` `ES256`).
5. The node verifies its own signed card before serving it and caches it.
   Until signing succeeds, every card request retries.

Code: `sign_with_operator_wallet` and `verify_agent_card` in
`crates/tenzro-node/src/a2a/agent_card.rs`.

## Verification

`verify_agent_card(card_json)` succeeds only if the card carries at least
one signature and every signature verifies: `alg` must be `EdDSA`, the
protected header must carry `kid` and an Ed25519 `jwk`, and the Ed25519
signature (strict verification) must cover the canonical card. It returns
the `kid` and public key of each signature. A relying party must separately
check that `kid` resolves to that key (for a Tenzro DID, via
`tenzro_resolveDidDocument`).

Tests (`a2a::agent_card::tests`): a signed card verifies; pretty-printed
re-serialisation still verifies; a rewritten interface URL, a stripped
extension, and a signature by another key under the claimed `jwk` are all
rejected; an unsigned card and `alg: none` are rejected.

## Dependencies and limits

- The signing key is whatever hardware custody backs the operator wallet.
  A node with no operator identity, no bound signer, or a non-Ed25519
  operator key serves no card (503). A dedicated hardware-signer
  abstraction for node-level keys is owned by the identity stream; when it
  lands, `sign_with_operator_wallet` is the one function to repoint.
- `ES256` / `ES256K` card signatures are not verified; such a card is
  reported as malformed rather than accepted.
