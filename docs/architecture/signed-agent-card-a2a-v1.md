# A2A v1.0 Signed Agent Cards

Tenzro implements the A2A v1.0 `SignedAgentCard` envelope, the
production-grade conformance bar in the A2A 2026 spec.

## Why sign the agent card?

A bare agent card at `/.well-known/agent.json` can be rewritten by a
hostile reverse proxy or an intermediate cache without detection — the
attacker swaps the `url` (redirects RPC traffic), `skills` (advertises
capabilities the agent does not have), or `securitySchemes` (advertises
weaker auth).

The `SignedAgentCard` envelope wraps the card alongside a JWS
signature over the canonical card hash, so relying parties verify the
domain owner's signature before consuming the card.

## Wire shape

```json
{
  "agentCard": { ... },
  "signature": "<JWS Flattened JSON Serialization>",
  "algorithm": "EdDSA",
  "issuer": "did:web:tenzro.network"
}
```

Detached payload semantics: the `signature` field carries a JWS
Compact Serialization over `SHA-256(canonical_agent_card_json)`.
Verifiers recompute the hash from `agentCard` and check the JWS. This
is byte-economical (no duplicated card body) and aligns with the
A2A 2026 spec.

The canonical card hash is computed via `SHA-256("tenzro/a2a/
signed-agent-card/v1" || canonical_card_json)` — sorted-keys, no
whitespace — so producer and verifier hash identically across
language implementations.

## RPC surface

| Method | Description |
|---|---|
| `tenzro_signedAgentCardCanonicalHash` | Compute the canonical hash for an A2A v1.0 SignedAgentCard payload. The caller passes the AgentCard JSON; the node returns the 32-byte hash the domain owner must sign via JWS to produce the envelope. |

## Status

Library types + canonical-hash RPC live. The Tenzro Network agent
card served at `https://a2a.tenzro.network/.well-known/agent.json`
will move to the SignedAgentCard envelope in a subsequent wave with
a `did:web:tenzro.network` JWS signing key.
