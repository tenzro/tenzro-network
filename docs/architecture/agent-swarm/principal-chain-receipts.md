# Principal-Chain Receipts

**Status:** Drafting (2026-05-04)
**Phase:** 1 (regulatory foundation, pairs with Kill-Switch)
**Touches:** `tenzro-settlement` (receipt schema), `tenzro-payments` (binder), `tenzro-identity` (chain resolver), `tenzro-agent` (lifecycle + spawn linkage), `tenzro-node` (RPC + indexes)

## Context

Today a settlement receipt names the paying agent: "agent_X paid 5 TNZO to provider_Y for inference." For a regulator, an insurer, or a counterparty trying to recover damages, that's the wrong unit of liability. The thing on the hook is the *human or organization* that delegated authority to agent_X — possibly through several layers of delegation. Today that chain is reconstructible only by recursive RPC walks against the identity registry, and only as long as the chain still resolves (a revoked intermediate breaks it).

EU AI Act Art. 14 (high-risk human oversight) and emerging US state laws on "AI accountability" both require that the *responsible legal entity* for an AI action be identifiable from the action's audit trail, not derived after the fact. Tenzro's identity model has the data — TDIP delegation chains — but receipts don't bake it in. Cart mandates (AP2) almost-but-don't-quite do this.

Pair this with the kill-switch (Spec 1): the receipt is the artifact a regulator uses to decide whom to subpoena, whose insurance to claim against, whose stake to slash. It needs to be self-contained.

## Decision

Every settlement and lifecycle receipt grows a typed `principal_chain` field that, at write time, captures the full delegation path from the acting identity up to the controller, plus the controller's KYC tier and bond status. The chain is **frozen at receipt write time** — later revocations of intermediates do not invalidate the receipt's chain.

Three layers of receipts gain the field:

1. **Settlement receipts** (`tenzro-settlement` Settlement, MicropaymentChannel update, EscrowRelease, EscrowRefund)
2. **Payment receipts** (`tenzro-payments` MppReceipt, x402 receipt, AP2 cart settlement)
3. **Lifecycle receipts** (kill-switch receipts from Spec 1, agent registration, agent spawn)

A future regulator query — "who is on the hook for this transaction?" — is a single index lookup against the receipt, not a chain walk.

## Architecture

### Schema

```
PrincipalChain {
    actor:                String,           // DID of identity that signed/acted
    chain:                Vec<PrincipalLink>,
    controller:           PrincipalLink,    // top of chain (== chain[0] if chain non-empty)
    controller_kyc_tier:  u8,               // snapshot at receipt write time
    controller_bond:      Option<u128>,     // snapshot in TNZO
    delegation_depth:     u8,               // 0 = controller acted directly
    frozen_at_block:      u64,
}

PrincipalLink {
    did:                  String,
    identity_type:        "Human" | "Machine",
    delegation_scope_id:  Option<Hash>,    // hash of the DelegationScope under which this link acted
    role:                 "controller" | "delegated_agent" | "autonomous_agent",
}
```

`chain` is ordered top-down: `chain[0]` is the controller, `chain[n-1]` is `actor`'s direct delegator. For `delegation_depth == 0`, `chain` is empty and `controller == {did: actor, ...}`.

### Resolution

At receipt write time, the receipt-writer calls `IdentityRegistry::resolve_principal_chain(actor_did)`:

1. Look up `actor_did` in registry.
2. If `IdentityType::Human`: chain is empty, controller is actor.
3. If `IdentityType::Machine` autonomous (no controller_did): chain is empty, controller is actor (typed as autonomous).
4. If `IdentityType::Machine` with `controller_did`: recurse on controller_did, append actor at end.
5. If a link in the chain is unresolvable (revoked, not found): chain is recorded with `did: <did>` and a `tombstone: true` flag; resolution does not fail. The receipt is still written; the regulator sees a partially-resolvable chain with an explicit gap.

Bounded at `MAX_DELEGATION_DEPTH = 16` (governance-tunable). Chains longer than this are rejected at delegation creation time, not at receipt write — receipts assume valid delegation chains and don't need to defend against deeply nested loops.

The resolution is **read-only** and performed inline with receipt writing — no async indexing, no risk that the chain on-record diverges from the chain the receipt should have had.

### Write-time freezing

The chain as resolved at receipt write time is stored verbatim in the receipt. Subsequent state changes — KYC downgrade, bond refund, controller revocation — do not update past receipts. This is deliberate:

- A regulator querying a 6-month-old receipt sees the *world as it was* when the action occurred, which is the legally relevant state.
- An insurer evaluating coverage as of a loss event sees the bond and tier that were in force.
- Reputation portability (ERC-8004 mirror) reads frozen receipts and tallies actor history without race conditions on identity changes.

Trade-off: we don't get "current state" from a receipt query. That's correct — current state lives in the registry; receipts are an audit log.

### Storage

Embedded in the existing receipt records (no new column family). Indexed via three new prefixes in CF_SETTLEMENTS:

```
principal_actor:<actor_did>:<timestamp>      → receipt_id
principal_controller:<controller_did>:<timestamp> → receipt_id
principal_kyc_tier:<tier>:<timestamp>          → receipt_id   // for tier-bucket regulator queries
```

A receipt that's part of a kill-switch lifecycle event also gets indexed under `principal_killswitch:<controller_did>:<timestamp>`.

### RPC surface

Read-only:

```
tenzro_getReceiptPrincipalChain { receipt_id }
    → PrincipalChain                    // typed, exact

tenzro_listReceiptsByActor { actor_did, since?, until?, limit }
    → [{ receipt_id, kind, principal_chain_summary }]

tenzro_listReceiptsByController { controller_did, since?, until?, limit }
    → [{ receipt_id, kind, principal_chain_summary }]

tenzro_summarizeController { controller_did, since?, until? }
    → {
        receipt_count,
        total_value_wei,
        agents_acted_under: [did_list],
        kill_switch_events: u32,
        kyc_tier_at_oldest: u8,
        kyc_tier_at_newest: u8,
        bond_min: u128,
        bond_max: u128,
      }
```

The `summarizeController` RPC is the one regulators and insurers actually use — a single call returns the controller's full activity over a window, formatted for compliance/audit.

CLI: `tenzro receipt principal <id>`, `tenzro identity activity <did>`.

MCP: `get_receipt_principal_chain`, `list_receipts_by_controller`, `summarize_controller` tools.

### Receipt examples

**Settlement receipt** (inference paid by autonomous agent under delegated agent under human):

```json
{
  "receipt_id": "0xabc...",
  "kind": "Settlement",
  "amount_wei": "5000000000000000000",
  "payer": "did:tenzro:machine:bot42:uuid",
  "payee": "did:tenzro:machine:provider:uuid",
  "principal_chain": {
    "actor": "did:tenzro:machine:bot42:uuid",
    "chain": [
      {"did": "did:tenzro:human:alice:uuid", "identity_type": "Human", "delegation_scope_id": null, "role": "controller"},
      {"did": "did:tenzro:machine:alicebot:uuid", "identity_type": "Machine", "delegation_scope_id": "0xdef...", "role": "delegated_agent"},
      {"did": "did:tenzro:machine:bot42:uuid", "identity_type": "Machine", "delegation_scope_id": "0x123...", "role": "autonomous_agent"}
    ],
    "controller": {"did": "did:tenzro:human:alice:uuid", ...},
    "controller_kyc_tier": 2,
    "controller_bond": "10000000000000000000000",
    "delegation_depth": 2,
    "frozen_at_block": 184523
  },
  "timestamp": 1741000000
}
```

**Kill-switch receipt** carries the chain of the *acting authorizer* (controller, committee, or governance) — different from the agent being acted on.

### Migration

This is pre-launch — no on-chain receipt history to migrate. Genesis ships with the field present on every receipt schema. Any existing testnet data from before this lands does not get backfilled (per project no-backcompat rule); old testnet state is reset.

## Interaction with existing systems

- **`tenzro-identity::IdentityRegistry`** gains `resolve_principal_chain(did)` accessor — read-only, no schema change. Uses existing controller_did + DelegationScope fields.
- **`tenzro-payments::IdentityPaymentBinder`** already resolves DelegationScope; the binder is the right place to compute and attach the chain to MppReceipt / x402 / AP2 receipts.
- **`tenzro-settlement::EscrowManager`** already produces receipts on Create/Release/Refund; the chain is computed at the privileged-VM dispatch site for the typed escrow txs.
- **AgentBond (Spec 9)**: `controller_bond` reads the bond posted by the controller (or by any link in the chain — governance-tunable whether intermediate bonds count).
- **Kill-switch (Spec 1)**: kill-switch receipts use the same PrincipalChain field with `actor` = the authorizer of the kill-switch action.
- **AP2 mandate validation**: AP2 v0.2 CheckoutMandate already names the controller; the PaymentMandate now writes a receipt with the full chain, not just the controller.
- **ERC-8004 reputation mirror**: cross-chain reputation systems can read PrincipalChain summaries from `summarizeController` to compute portable scores.

## PQ posture

Chain is data, not a signature. The receipt itself is signed by the validator quorum under hybrid Ed25519 + ML-DSA-65. No new signature surface.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `max_delegation_depth` | 16 | Enforced at delegation-create, asserted at receipt-write |
| `tombstone_unresolved` | true | Allow receipt write with tombstoned link vs reject (default: allow) |
| `chain_index_retention_days` | 2555 (7 years) | Regulatory retention |
| `summarize_window_default` | 90 days | Default `since` for summarizeController if not specified |

## Verification

1. **Direct controller action:** human signs and pays — receipt has `delegation_depth: 0`, empty chain, controller == actor.
2. **One-level delegation:** delegated agent of human pays — `delegation_depth: 1`, chain has [controller], controller_kyc_tier matches human's.
3. **Two-level delegation:** autonomous agent under delegated agent under human — `delegation_depth: 2`, full chain captured.
4. **Tombstone case:** intermediate revoked between scope-issuance and tx — receipt records `tombstone: true` for that link, regulator query surfaces gap.
5. **Frozen state:** controller's KYC downgraded after receipt — `getReceiptPrincipalChain` still returns original tier.
6. **Index parity:** every receipt with controller C is queryable via `listReceiptsByController(C)` within 1 block.
7. **Summarize correctness:** `summarizeController` totals match sum of individual `getReceiptPrincipalChain` queries over the window.
8. **Cycle defense:** delegation cycle (A→B→A) — caught at delegation-create time, never reaches receipt path.

## Out of scope

- **Backfilling foreign-chain receipts.** ERC-8004 mirror or Wormhole-published agent reputation events outside Tenzro are not part of this; reputation mirroring is a separate spec (touched in §"Out of scope" of agent-swarm/README.md).
- **Privacy-preserving controller queries.** Regulatory query is an open path; ZK-proof-based selective disclosure (regulator proves they're authorized to see chain X without revealing query) is a Phase 3 add-on. Until then, queries are public; index access is rate-limited per the existing RPC limits.
- **Cross-controller chains.** A delegation issued by the controller to a third-party org's agent is in scope (chain has [controller, third_party_agent]); a *split* delegation where actor is controlled jointly by two principals is not. Joint custody is modeled at the wallet layer (MPC), not the identity layer.
