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
4. The signature is made by the machine's identity key, the P-256 key in its
   TPM or Secure Enclave that its machine DID derives from. The protected
   header carries `kid` = `<machine DID>#hardware-key` (the method the node's
   DID Document lists for that key) and the key as a `jwk`. The key signs
   SHA-256 of the signing input, `r || s` (JWS `alg` `ES256`). No wallet or
   operator account on the node is involved.
5. The node verifies its own signed card before serving it and caches it.
   Until signing succeeds, every card request retries.

Code: `sign_with_machine_key` and `verify_agent_card` in
`crates/tenzro-node/src/a2a/agent_card.rs`.

## Verification

`verify_agent_card(card_json)` succeeds only if the card carries at least
one signature and every signature verifies: `alg` must be `ES256`, the
protected header must carry `kid` and a P-256 `jwk`, and the signature must
cover the canonical card. It returns the `kid` and public key of each
signature. A relying party then checks that the DID in `kid` derives from
that key (`did:tenzro:machine:` is derived from the key itself), so the
binding needs no trust in the serving node.

Tests (`a2a::agent_card::tests`): a signed card verifies; pretty-printed
re-serialisation still verifies; a rewritten interface URL, a stripped
extension, and a signature by another key under the claimed `jwk` are all
rejected; an unsigned card and `alg: none` are rejected.

## Dependencies and limits

- A node whose machine key cannot sign serves no card (503); every card
  request retries until signing succeeds.
- Card signatures other than `ES256` are reported as malformed rather than
  accepted.
