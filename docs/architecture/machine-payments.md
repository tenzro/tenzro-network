# Machine payments

How a payment on Tenzro is authorized, settled and recorded, whoever makes
it: a human with a passkey, a machine with a TPM, or a delegated agent acting
under its terms. One mechanism per concern: settlement is
`crates/tenzro-vm/src/native/payment_settlement.rs`, authority is the agent's
consensus Terms (`native/agent_terms.rs`), fees are `native/economy.rs`.

## One record per payment

Every payment leaves one consensus record at `pay:<pay_ref>`:

```
pay_ref = SHA-256("tenzro/pay-ref", chain_id, payee, request_digest, quote_digest, nonce)
```

The record (`tenzro_types::settlement::PaymentRecord`) holds the class, payer,
payee, asset, amount, the TNZO settlement fee, the binding the payer signed
(request digest, quote digest, USD price), the paying agent when one paid,
and the payee's delivery receipts. Read it with `tenzro_getPayment
{ pay_ref | payment_id }` (CLI `tenzro payment record`). A payment id settles
at most once on the chain; a reference is recorded at most once.

Every record write emits a `PaymentRecorded` log (data `pay_ref || class`),
so payment history is the chain's event index, not a second store.
`tenzro_listPayments { payee?, payer?, agent_did?, class?, asset?,
from_cursor?, from_height?, to_cursor?, limit?, proofs? }` (CLI `tenzro
payment history`, MCP `list_payments`, SDK `listPayments`/`list_payments`)
pages those events in chain order, returning each record with its event
cursor and, with `proofs`, the event's proof against a certified
checkpoint. Pass the returned `cursor` back as `from_cursor` to continue.

The payee returns part or all of a native payment with a `Payment { op:
refund }` transaction it signs (CLI `tenzro payment refund`, MCP
`payment_refund`, TS `settlement.refundPayment`, Rust
`auth().refund_payment`). The asset goes
back to the payer in the asset it was paid in, the record's `refunded` total
never exceeds its amount, and the settlement fee is not returned.

A payee sets a standing split rule with a `Payment { op: set_split }`
transaction (CLI `tenzro payment set-split --rule <json>` or `--clear`, MCP
`payment_set_split`, TS `settlement.setPayeeSplit`, Rust
`auth().set_payee_split`). The
rule is the split engine's (`tenzro_types::split`): lines of a role, a fixed
account or a DID-derived one, and basis points, a fixed amount or the
remainder. Every settlement to the payee, direct or from an escrow, is
divided by that one engine after the fee, in the same asset and execution,
with the same conservation and largest-remainder rounding as a settlement
plan's split; a direct payment, an escrow release and a plan leg of the same
gross divide it identically. Read it with `tenzro_getPayeeSplit { payee }`
(CLI `tenzro payment split`).

An agent's evidence pack carries the payments it made in a `commerce`
section: `tenzro_exportEvidencePack { agent_did, payments: [pay_ref] }` (CLI
`tenzro evidence export --payment <pay_ref>`) proves each record under the
pack's certified state root, and the offline verifier refuses a record
proven at another reference or made by an agent the pack does not cover.

Three classes, never mixed:

| Class | Established by | Counts as proven |
|---|---|---|
| `native` | settlement on the Tenzro Ledger (`PayerSettle`, an agent's `pay`) | yes |
| `proven` | a delegated agent's account's `Paid` report from another chain, proven through that chain's report route (`PaymentOp::Proven { agent_did, chain, delivery }`, CLI `tenzro payment prove`) | yes |
| `attested` | the submitting account's statement of a payment on a rail outside any chain (card, bank, processor) | never |

Proven and attested nonces are scoped by their source and attestor, so no
statement about another rail can take a native payment's reference.
Attested payments are on by default, labelled and capped
(`payments.attested_enabled`, `payments.attested_cap_usd_e6`, 10,000 USD at
genesis). A rail that needs a business relationship (a card network, a
processor, an issuer's off-ramp) is an operator plug-in running under the
operator's own credentials; it records `attested` payments and is never
required.

## What a payment binds

The payer signs `payment_authorization_preimage`, which covers the chain, the
payment id, payer, payee, the ceiling, the asset, and the `PaymentBinding`:

- `request_digest`: SHA-256 of `"tenzro/request" || resource`. Never zero.
- `quote_digest`: `Quote::digest()` of the payee's quote, or zero for an
  unquoted payment. A quote carries the USD price, the accepted assets with
  their ceilings, the licence, the content-usage expression and the cart
  lines it covers, so a checkout can only pay for lines the payee quoted.
- `usd_e6`: the price in USD micro-units, or zero.
- `app_margin`: the developer margin an application takes, or none: the
  wallet it is paid to and its basis points, encoded as `0x00` for none or
  `0x01 || app_wallet || margin_bps (u32 LE)`. The settlement carves
  `amount * margin_bps / (10_000 + margin_bps)` out of the amount to exactly
  that wallet, within the governed `fees.max_developer_margin_bps`; whoever
  submits the settlement names no margin of its own.

After delivery the payee lists a `DeliveryReceipt` (body digest, optional
inference receipt digest) on the record with a `Payment { op: receipt }`
transaction. Request, quote, payment and receipts form one hash chain, in
state and in the evidence pack.

## Assets and fees

A payment settles in TNZO or in any token on the ledger the payee's quote
accepts (stablecoins included, bridged through the existing routes). The
asset is `TNZO` or a token id as `0x`-prefixed hex.

- TNZO: the settlement fee comes out of the amount. A USD-priced TNZO
  payment must not exceed what its price buys at the consensus rate.
- Any other token: the token moves in full and the payee pays the fee in
  TNZO on the payment's USD price at the consensus rate. TNZO stays the fee
  asset; a token payment without a USD price is refused.

Token transfers go through the token ledger, so the issuer's policy
(eligibility credentials, denied or allowed jurisdictions, holder kinds,
halts and freezes) applies to every payment the same way it applies to any
transfer. Escrows (channels, streams, hash locks, disputes) hold either kind
of asset and pay out in it.

### Stablecoins

Every stablecoin is opt-in at each layer, and no layer needs a central
allow-list or the client's network location:

- **Operator**: a node's gate and facilitator settle on the ledger only the
  tokens its operator lists in `payments.ledger_assets` (token ids) besides
  TNZO.
- **Payee**: a quote names the assets it accepts.
- **Agent**: an agent pays only in assets its Terms list in `asset_limits`,
  each with its own per-payment and daily limit, counted at its USD price.
- **Issuer**: eligibility is the token's policy on the ledger. A
  `jurisdiction` claim from an attestor the token names (a KYB or KYC
  provider) carries the holder's jurisdiction: `DenyJurisdiction` refuses
  some, `AllowJurisdiction` serves only those listed. Claims lapse and can
  be revoked by their attestor; consensus never reads an IP address.

A native issuer runs its token itself: mint, freeze, halt, forced transfer
and policy changes each sit under the issuer's own key or a k-of-n council
of its keys (or are renounced), a reserve-backed token mints only with k
attestations covering the supply after the mint, and policy changes wait
out a timelock no shorter than the governed floor. Governance holds no power
over an issuer's token or its holders' balances. Holders earn nothing for
holding a stablecoin: the token ledger has no yield, and payments in a token
pay the fee in TNZO. Rails that need a business relationship (an issuer's
or processor's off-ramp, card networks) are operator plug-ins under the
operator's own credentials; they record `attested` payments and are never
required.

Routes today carry TNZO and deposit assets. A route that carries a remote
stablecoin into a ledger token (minting a representation against the
remote lock, burning it on the way out, capped per route) is the bridge
framework's to add; payments already accept such a token once it exists.

### Paying in a stablecoin without holding TNZO

A buyer that holds only a stablecoin pays over x402 without TNZO: it signs a transfer authorisation (or a ceiling for a metered `upto` payment), and the node's facilitator verifies it and settles it on the stablecoin's own chain. Transactions on the Tenzro ledger itself always pay gas in TNZO, under one fee market across every runtime; a stablecoin never pays gas. Each payee chooses what it holds: the stablecoin as it arrived, or TNZO.

## Agents

An agent has no key of its own. Its authority is its Terms, granted by its
root (a human passkey or a machine TPM), and inside them it acts without
per-payment approval.

- **Pay**: `tenzro_agentAct { operation: "pay", counterparty, amount, asset?,
  usd_e6?, payment: { payment_id, request_digest, quote_digest } }`. The
  serving node checks the action against the Terms and signs it with its TPM
  key for the agent; the VM checks it again and settles from the agent's
  wallet, writing a record that names the agent.
- **Channels**: `create_escrow` locks from the agent's wallet; the lock counts
  against the Terms' limits when it opens. Vouchers on it are signed by a
  serving node the Terms assign, with its key for the agent
  (`tenzro_agentVoucher`, CLI `tenzro payment agent-voucher`). The ledger
  honors such a voucher only while the node is still assigned, and only if
  it was signed before the agent's revocation, quarantine or expiry and not
  dated more than `payments.voucher_freshness_ms` (60 s) ahead of block time.
- **Assets other than TNZO**: listed in the Terms' `asset_limits` with a
  per-payment and daily limit, and counted against the wei limits at their
  USD price.

A payee accepting vouchers off the ledger runs the same check the ledger
runs at the claim (`check_escrow_voucher`), so an agent's revoked channel
stops paying everywhere at once.

## Agent accounts on other chains

An agent's account on another chain pays only as an action under its live
grant, so the grant's signatures, budget, per-action limit, window and
targets apply to every payment. A paying action carries 104 bytes of pay
data (the Tenzro payee, the request and quote digests, the USD price) and
the account emits a report in the layout Tenzro decodes: kind 4, the grant's
chain, account, agent and sequence, the action's nonce, the pay data and the
amount. Tenzro records it as a `proven` payment of that agent only when the
chain's report route proves it and the report is of the account the agent's
DID derives there, under a grant Tenzro issued, within that grant's budget;
the payer is the account (CAIP-10) and the asset the grant's (CAIP-19).

| Chain | How the account pays |
|---|---|
| EVM | `pay(to, amount, payee, request, quote, usd_e6)` on the account itself, run by `act`; `approveHash` makes a hash its ERC-1271 signature for an EIP-3009 transfer, counted against the grant when approved and valid only under that grant; `openChannel` reserves a deposit that `claimChannel` pays on a serving node's P-256 voucher (`channel_voucher_digest`) and `closeChannel` releases after expiry |
| Solana | a system or token transfer whose action data is the pay data |
| Sui, Aptos, CosmWasm | an action with selector `pay` whose data is the pay data |
| Stellar | the account's own `pay` function, authorized by the account's custom auth as one action |

## Facilitator

A node serves an x402 facilitator (`/verify`, `/settle`, `/supported`) for
resource servers. Every scheme ends in consensus state; the facilitator
holds no funds and no keys.

| Scheme | Network | Settles by |
|---|---|---|
| `tenzro-hybrid`, `upto` | `tenzro:<chain id>` | a `PayerSettle` the payer signed |
| `batch-settlement` | `tenzro:<chain id>` | a cumulative voucher on an escrow, checked against chain state (an agent's against the node its Terms assign); the payee claims later |
| `dvp` | `tenzro:<chain id>` | escrows locked by the hash of a sealed delivery's key; the seller is paid when it reveals the key |
| `proven` | `tenzro:<chain id>` and each agent account chain with a report route | a delegated agent's payment record paying the payee at least the price in the required asset: on `tenzro:<chain id>` the `native` record its `tenzro_agentAct` `pay` wrote from its wallet within its Terms, on another chain the `proven` record of its account's payment; the payload names the record (`pay_ref`), one record buys one requirement and the receipt's transaction is `pay:<pay_ref>` |
| `plan` | `tenzro:<chain id>` | the payer's own signed transaction opening a settlement plan (payload `signed_tx`) for the requirement's `quote_digest`, whose Tenzro legs carry at least the price and whose split pays the payee; the facilitator checks the signature and admits the transaction as signed. The response's `plan` carries the plan id, its status, each leg's id and the receipts of decided legs (an all-Tenzro plan decides in the opening transaction; other legs are read later with `tenzro_getLegReceipt`) |
| EVM schemes | configured CAIP-2 networks | the scheme's verifier |

## Publishing and paying on the web

A publisher lists paid paths in a policy: a USD price per request, the
schemes and asset it accepts, and its licence terms. The publisher gate
(TS `web.PublisherGate`, Rust `web::PublisherGate` and its tower layer)
answers an agent's request for a paid path with 402 and the requirements,
priced in TNZO at the consensus rate (`tenzro_quotePayment`, CLI
`tenzro payment quote`, MCP `quote_resource`), and lets it through only
after a facilitator has settled the payment: a handler never runs for an
unpaid request. Requests that carry no agent signature pass free unless the
policy charges them. The same policy renders the RSL licence document, the
robots.txt `License:` line and the `Content-Usage` header served with each
paid path. Payouts go to the policy's Tenzro account, held by its owner's
passkey; there are no publisher accounts or keys to issue.

A site behind a reverse proxy uses the node instead: the proxy calls
`/payments/forward-auth` with the original method and URI
(`X-Forwarded-Method`, `X-Forwarded-Uri`) and headers, and serves the request
only on a 2xx. The node runs its own payment gate on the forwarded request,
so the payment settles before the answer is 2xx.

The payer side (TS `web.payingFetch`, Rust `web::PayingClient`) answers a
402 by paying one offered requirement within a ceiling and retrying, then
pays a path it paid before up front. A delegated agent pays from its
channel (`AgentChannelPayer`): each request asks a serving node for the next
cumulative voucher (`tenzro_agentVoucher`), so any number of requests over
one channel leave one voucher for the payee to claim. On another chain the
agent's account channel is paid the same way with
`tenzro_signRemoteChannelVoucher` (CLI `tenzro payment remote-voucher`, MCP
`sign_remote_channel_voucher`). A channel contract on a chain that verifies only classical signatures can take hash-based vouchers instead: when the channel opens it commits to the Merkle root of one-time WOTS+ keys (SHA-256, Winternitz 16) the serving node derives from its hardware root under a label naming the agent, the machine, the chain and the channel, and each voucher spends one key. Verifying one costs about 600 SHA-256 evaluations and no elliptic-curve arithmetic, so it holds when ECDSA is broken and stays cheap in a contract. The node stores only how many keys of each channel it spent, written and flushed before the signature leaves it, so a crash costs a key rather than reusing one. Contracts without hash-based vouchers keep taking the P-256 voucher. The shared vector
`sdk/fixtures/payments/x402_agent_voucher.json` pins the wire both SDKs write
and the node decodes.

## Web identity

A serving node signs each request an agent sends in the Web Bot Auth profile
of RFC 9421: `tag="web-bot-auth"`, `keyid` the key's JWK SHA-256 thumbprint,
and a covered `Signature-Agent` header naming the key directory
`<origin>/.well-known/http-message-signatures-directory?agent=<did>`
(`application/http-message-signatures-directory+json`). Every node serves the
same directory, rendered from the agent's Terms at the current height; a
revoked, quarantined or expired agent's directory is empty from the next
block. A node signs agent requests only
when its operator has published an origin (`external_rpc_addr`).

## Governed settings

| Key | Genesis value |
|---|---|
| `payments.attested_enabled` | 1 (on) |
| `payments.attested_cap_usd_e6` | 10,000,000,000 (10,000 USD) |
| `payments.voucher_freshness_ms` | 60,000 |
| `fees.settlement_fee_bps`, `fees.tnzo_usd_nano`, `fees.usd_rate_mode` | see fees |
