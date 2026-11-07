# TNZO on other chains

This page describes how TNZO can be represented on another blockchain, and the
rules that keep that representation honest.

## Canonical TNZO lives on Tenzro

TNZO is native to Tenzro. The Tenzro ledger is the only place where TNZO is
created, and its total supply is fixed there. Any TNZO you see on another chain
is a bridged representation: a token on that chain that stands for TNZO held on
Tenzro. It is never a second, independent supply.

## Minted only against locked TNZO

A bridged representation is minted on an external chain only when the same
amount of TNZO has been locked on Tenzro for that chain. When the
representation is returned, it is burned on the external chain and the same
amount of TNZO is released on Tenzro.

This gives one invariant for every external chain:

> The supply of the bridged representation on an external chain is never
> greater than the TNZO locked on Tenzro for that chain.

Because the lock happens on Tenzro and every node applies the same rules, anyone
can check the locked amount against the supply on the external chain.

## Routes are set by governance

Value moves between Tenzro and an external chain over a route. A route names
the transport, the external chain and its family, the token pool on that chain
allowed to send to Tenzro, the contract on that chain that emits deliveries,
the Tenzro endpoint deliveries are addressed to, the committee that attests
each delivery and how many of its members must sign, whether a light-client
proof is also required, and how much value may move through it. Each external
chain is served by one route.

Routes are not a fixed list in the software. They are recorded in Tenzro's
chain state and are added, changed or removed only by an enacted governance
proposal, so every node applies the same routes and anyone can read them back.
Which external chains are served at any time is therefore a governance
decision, and it can change. Nothing on this page commits the network to a
particular chain or provider.

The genesis file may list routes the network starts with
(`[[economy.bridge_routes]]`), each with the same fields a governance
proposal would carry and the same rules applied. A route listed as not open
starts disabled by governance: it is installed and anyone can read it, but it
carries nothing until an enacted policy update opens it. A route may also be
listed as a placeholder whose fields are still to be filled (below).

### Genesis routes: fields to fill before launch

`config/genesis-prod.toml` lists the routes the network starts with
(Ethereum, Base and Arbitrum over CCIP, Solana over CCIP) as
placeholders. Each entry's `placeholders` list names the fields still to be
filled; a placeholder route must be closed with zero caps, and it is installed
disabled with its placeholder fields recorded in chain state. The network runs
without it; a governance vote fills it (`set_bridge_route` with the complete
route) and another opens it, and opening is refused while any field is still a
placeholder (see "Route modes" below). The fields to fill:

| Field | What to fill in |
|---|---|
| `local_selector` | The CCIP chain selector assigned to Tenzro's lane |
| `peer` | The token pool on the external chain (left-padded to 32 bytes) |
| `ramp` | The on-ramp (EVM) or router program (Solana) that emits deliveries |
| `local_endpoint` | The Tenzro endpoint deliveries are addressed to |
| `remote_token` | The TNZO token on the external chain |
| `verifiers` | The attesting committee: its size and threshold, set by governance, and its members, drawn on chain (each member's signing address, the bonded attestor account behind it and its RPC provider) |
| `blessing` | The second, independent CCIP committee |
| `native_asset` | The external chain's native coin as a CAIP-19 asset id, on routes whose locked or hash-locked settlement legs may move it; an agent's `remote_limits` name it by this |
| `light_client` | The anchor: for Ethereum, the trusted finalized beacon block root (the genesis validators root and fork version are filled) |
| `mint_limit`, `lane_limits` | The route's caps, once the route is filled (zero while it is a placeholder). `lane_limits.version` is the on-ramp version of the CCIP lane (`2.0.0`, `1.6.0` or `1.5.0`); check it against the on-ramp's `typeAndVersion` when the lane is assigned. `lane_limits.off_ramp` and `lane_limits.ccv_and_executor_hash` are the lane's off-ramp and, for `2.0.0`, the verifier and executor hash it requires |

## One set of rules for every route

Every route, whatever chain it reaches, goes through the same route framework.
Each chain family has an adapter that only translates message formats: it
reads the messages its chains emit and writes the messages they accept. The
rules below are applied by the framework around every adapter, so no route can
skip one of them:

- **Strict decoding.** A delivery is read in one exact layout. A truncated
  payload, a field encoded in a non-standard way, or a single extra byte
  rejects the whole delivery. Nothing is parsed on a best-effort basis.
  Outbound messages are read back after they are built and must match.
- **Attestations bound to one use.** Committee members sign a digest that
  names this chain, the route, a nonce and an expiry. A signature collected
  for one route or one chain verifies for no other, an expired attestation is
  refused, and each nonce is accepted once.
- **Both signature legs, from every member.** A member counts toward a
  committee's threshold only with two signatures over the digest: a
  secp256k1 signature that recovers to its address, and an ML-DSA-65
  (FIPS 204) signature, under the context
  `tenzro/bridge/route-attestation/ml-dsa-65`, that verifies under the
  ML-DSA-65 key the member declared when it bonded. A signature on one leg
  alone counts for nothing, so a party that breaks secp256k1 (or ML-DSA)
  alone cannot forge an attestation. A delivery carries the two legs as
  separate lists, `committee` and `committee_pq` (and `blessing`,
  `blessing_pq`). A committee seat requires the key: a member with no
  ML-DSA-65 key fails the route's rules. Equivocation evidence needs both
  legs of the member on both deliveries, so a forger of one leg cannot frame
  an honest member.
- **Independent committees.** Where the transport has a second, independent
  committee, both must attest the same delivery.
- **Committees drawn from bonded attestors.** Governance sets a committee's
  size and threshold, never its members. Any account bonded as an attestor
  that declared a bridge signing key (`tenzro stake bond --role attestor
  --bridge-signer <address> --rpc-provider <name> --signer-proof <hex>
  --pq-public-key <hex> --pq-proof <hex>`, the proofs being the secp256k1
  key's and the ML-DSA-65 key's signatures binding them to the account) is
  eligible.
  `tenzro bridge draw-committee` (a `DrawCommittee` operation anyone may
  submit) seats members by a hash of the route, the set index, the first
  randomness-beacon value at or after the draw fell due and the account,
  divided by the account's attestor stake, under the committee rules: one
  seat per account and key, and no RPC provider behind the threshold. A draw
  falls due when the route is installed, when the committee's term
  (`bridge.committee_term_ms`) ends, and when an equivocation breaks it; until
  it is drawn the route carries no traffic. Each drawn committee keeps its set
  index and an expiry: the end of its term plus `bridge.handover_window_ms`.
  A member keeps its bond and its key until its committee expires, however
  early a new draw replaces it. A route governance installs again continues
  the set indexes of the one it replaces.
- **Handover to the bridge contracts.** The contracts on Stellar, Sui, Aptos
  and TON trust one committee at a time, by set index, and stop trusting it
  at its expiry. After a draw, members of the committee a contract trusts
  sign the handover digest of the new committee (`tenzro bridge attest
  --handover <set> --from-set <trusted set>`, which reads the committee as
  the chain drew it from `tenzro_getBridgeRoute`'s `committee_sets`); any
  relayer submits the signatures to the contract's `rotate_committee`, which
  accepts only a higher set index. The digest is Keccak-256 of
  `tenzro/bridge/route-committee`, Tenzro's chain id (8 bytes), the route
  key's length (8 bytes) and the key, the set index (4), the member count
  (4), each member's 20-byte address, the threshold (4) and the expiry in
  Unix seconds (8), all big-endian. A committee that is not handed over in
  time leaves the contract with no trusted committee: nothing executes there
  until the contract is deployed again. CCIP routes (EVM chains and Solana)
  are verified on the destination chain by the lane's own CCIP verifiers; no
  Tenzro committee is registered there, so they need no handover.
- **Equivocation and wrong handovers are slashed.** A member that signed two
  different deliveries with one nonce is reported with both (`tenzro bridge
  report-equivocation`); a member that signed a handover to anything but a
  committee the chain drew, with its exact set index (above the signer's
  own), members, threshold and expiry, is reported with that signature
  (`tenzro bridge report-wrong-handover`). The chain checks the signature,
  takes `bridge.equivocation_slash_bps` of the member's attestor stake into
  the insurance pool and, if the member sits on the route's committees,
  empties them for a new draw.
- **Light-client proofs.** A route can require, on top of its committees, a
  proof that the external chain itself finalized the message. The route
  names the light client and its trusted starting point, set by the same
  governance vote; such a route admits nothing until that light client has
  been started from the anchor. A delivery is then admitted only with the
  committee signatures, the light-client proof, the caps and no breaker:
  several independent checks, none trusted alone.
- **Caps, rate limits and the circuit breaker**, described below.
- **The supply invariant**, checked on every transfer in either direction.

The framework serves these chain families. The transport is what a route's
`adapter` names; the last column says what, besides the committee, proves a
delivery:

| Family | Transport | Chains | Proven by |
|---|---|---|---|
| EVM | `ccip` | Ethereum, Base, Arbitrum, Optimism, BNB Chain, Avalanche C-Chain, Polygon PoS | the blessing committee; on Ethereum also the sync-committee light client |
| Solana | `ccip` | Solana | the blessing committee |
| Cosmos | `ibc` (classic or v2) | Cosmos SDK chains on CometBFT | a Tendermint light client and ICS-23 proofs |
| Bitcoin | `deposit` | Bitcoin | an SPV header-chain client |
| Sui | `contract` | Sui | a light client of committee-certified checkpoints |
| Aptos | `contract` | Aptos | a light client of validator-signed ledger infos |
| Stellar | `contract` | Stellar | a light client of SCP-externalized ledgers |
| TON | `contract` | TON | a light client of masterchain blocks finalized by the validator set, through shard descriptors to the shard block |

EVM chains share one adapter with a per-chain entry for each chain's
identifiers (EIP-155 chain id, CCIP chain selector) and its finality depth:
the blocks a message's block is buried under before the chain's own rule
makes it final. EVM and Solana routes use the CCIP message envelope, a
published cross-chain message format, so the same messages can be carried by
any transport that speaks it.

A CCIP lane runs one on-ramp contract version on the external chain, and
different lanes of the same chain can run different versions at the same
time. Each CCIP route therefore declares its lane's version in
`lane_limits.version`, and the EVM adapter reads exactly that version's
message event, recomputing the message id the way that on-ramp does:

| Version | Event | Message id |
|---|---|---|
| `2.0.0` | `CCIPMessageSent(destChainSelector, sender, messageId, ...)` with the chain-agnostic encoded message | keccak-256 of the encoded message, which names the on-ramp |
| `1.6.0` | `CCIPMessageSent(destChainSelector, sequenceNumber, EVM2AnyRampMessage)` | the on-ramp's hash under the lane's selectors and on-ramp address |
| `1.5.0` | `CCIPSendRequested(EVM2EVMMessage)`, one on-ramp per destination | the on-ramp's hash under the lane's selectors and on-ramp address |

A message in another version's layout, or with another version's event, is
refused on that lane. On a `1.5.0` lane the receiver is a 20-byte address; it
names the Tenzro account with those 20 bytes followed by twelve zero bytes.
Solana's router emits the `1.6.0` layout, so Solana routes declare `1.6.0`.
Outbound messages (Tenzro to the external chain) follow the lane's version
too, in the layout the lane's off-ramp executes:

| Version | Outbound message | Message id |
|---|---|---|
| `2.0.0` | the chain-agnostic encoded message (version 1): Tenzro's endpoint as on-ramp, pool and source token (32 bytes), the sender's 32-byte Tenzro address, the off-ramp, receiver and destination token as 20-byte EVM addresses, the pool's gas only, no data or callback | keccak-256 of the encoded message |
| `1.6.0` | `Any2EVMRampMessage` | the hash under the lane's selectors and Tenzro's endpoint |
| `1.5.0` | refused: `EVM2EVMMessage` names a 20-byte sender, which a Tenzro account is not | |

A `2.0.0` message names the lane's off-ramp and the hash over the verifier
and executor set it requires, so a CCIP route's lane config carries both:
`lane_limits.off_ramp` (20-byte address) and
`lane_limits.ccv_and_executor_hash`, read from the lane on the external chain
when it is assigned (zero while the route is a placeholder).

Cosmos chains are reached over IBC: ICS-20 fungible-token packets, over IBC
classic or IBC v2 as the route declares (see "IBC" below). Sui, Aptos,
Stellar and TON are reached through Tenzro's bridge
contract on that chain, which emits each transfer as an event in the chain's
own encoding (BCS on Sui and Aptos, XDR on Stellar, the message body on TON)
and executes transfers from Tenzro.

Routes of the families whose chain publishes what a light client needs
(Cosmos, Bitcoin, Sui, Aptos, Stellar, TON) must carry that light client;
governance cannot install one without it. The TON light client starts from a
masterchain key block, takes the validator set from its configuration
(parameter 34), and accepts a masterchain block once validators holding more
than two thirds of the masterchain set's weight signed its finalize vote. A
transfer is proven by Merkle proofs (pruned bags of cells) from that block's
shard descriptors to the basechain shard block, and in it to the bridge
contract's external outbound message.

Further chains are added one route at a time, after their adapter passes its
tests and governance installs the route.

## TNZO as a CCIP cross-chain token

On a CCIP route TNZO follows the cross-chain token model: on Tenzro the route
framework is the lock/release side of the lane, holding TNZO locked against
the representation; on the external chain the representation is a burn/mint
ERC-20 behind a burn/mint token pool, the pool registered for that token in
the chain's token admin registry. Tenzro's endpoint on the lane is the
route's `local_endpoint`, which the external pool names as its remote pool and
remote token.

The framework's tests deploy the published CCIP contracts (router, on-ramp,
off-ramp, fee quoter, nonce manager, RMN remote, token admin registry, burn/
mint token pool and token) from their published bytecode on a Tenzro EVM and
run both legs: an outbound message the framework built is committed and
executed by the off-ramp, which mints the representation; a `ccipSend` on the
router burns it, and the on-ramp's message is admitted by the framework,
message id and all. After both legs the representation's total supply equals
the route's outstanding supply.

## The supply invariant on every route

For every route, Tenzro's chain state records two totals: the TNZO locked on
Tenzro for that route, and the bridged representation outstanding on the
external chain. The second is never greater than the first.

- Sending TNZO out locks it on Tenzro first, then authorises the same amount
  on the external chain.
- Bringing TNZO back is refused unless the route has at least that much
  outstanding. A message that tries to bring back more than ever left over the
  route is refused however many valid signatures it carries.

A deposit route (Bitcoin) moves the other way: the asset is native to the
external chain and held there under the route's deposit script, and Tenzro
credits a representation of it. Its two totals are the amount proven
deposited under the script and the representation credited on Tenzro, and
each deposit raises both by the same amount. The representation is a
registry token the node creates for the bridge at startup (`BTC`, 8
decimals, one unit per satoshi), which only the bridge can mint. Spending
from the deposit script is not supported: Bitcoin cannot check a Tenzro
proof, so a release would rest on whoever holds the script's keys.
Outbound transfers on a deposit route are refused.

## Rate limits

Every route is bounded in two ways:

- **A cap per mint.** No single mint through the route may carry more than
  this amount.
- **A limit per epoch.** The total minted through the route in one epoch may
  not exceed this amount. The allowance starts afresh each epoch.

Each route carries its own limits, and a network-wide limit bounds every route
as well; the tighter of the two applies. Both are governance parameters. The
network starts with conservative values and governance can raise or lower them.

The network-wide limits come in three sets. Routes with a light client (the
route from Ethereum) prove every delivery against the source chain's own
consensus and are bound by the proven-route limits. Routes without one
(Solana) admit on their committees' attestations alone and are bound by the
attested-route limits, which governance must keep strictly below the
proven-route limits, per mint and per epoch. A third set, the classical
ceiling (`bridge_classical_per_mint_tnzo`, `bridge_classical_per_epoch_tnzo`
in the genesis economy section; 500 and 2,000 TNZO unless the genesis names
others), binds every route whose external chain verifies only classical
signatures, on top of whichever set binds it: the tighter value applies.
Governance sets it with the same `BridgeMintLimitsSet` policy as the others,
and a raise is bounded to one step like any other network limit.

### What a route still depends on

Tenzro's own acceptance of a delivery is post-quantum on every route: both
committee legs are mandatory, and the light client, where a route has one,
is checked beside them. What a break of classical cryptography can still
reach is the external chain's side, which Tenzro cannot change:

| Route | Residual classical dependency |
|---|---|
| EVM chains (CCIP) | The chain's own transaction signatures (ECDSA) and, on Ethereum, the beacon chain's BLS12-381 sync committee signatures the light client follows. A party that forges them could make the source chain show a deposit that never happened, which the committee members would then read and attest; the contracts that verify Tenzro's outbound committee signatures check secp256k1 only. |
| Cosmos (IBC, `tendermint.rs`) | The Tendermint light client verifies Ed25519 validator signatures. The ML-DSA committee leg is still required for every delivery admitted, but a forged Ed25519 commit makes the source chain's state forgeable. |
| Bitcoin, Solana, Stellar, Sui, Aptos, TON | Each chain's own signatures (ECDSA or Schnorr on Bitcoin, Ed25519 elsewhere), which the light client or the committee's reading of the chain trusts. |

The classical ceiling is what limits the value exposed to these. The outbound
digests (`outbound`, committee handover) are verified by contracts on the
external chain and so carry the secp256k1 signature only; they are not an
admission path into Tenzro.

A CCIP route also carries its lane's rate limits: one token bucket for each
direction, with a capacity and a refill rate per second, the same values the
token pool on the external chain is configured with for Tenzro. A transfer
takes its amount out of the bucket for its direction and is refused when the
bucket holds less. The inbound bucket may hold no more than the route's limit
per epoch. Lane limits apply on top of the caps above: an inbound transfer
must pass the per-mint cap, the epoch limit and the inbound bucket, and an
outbound transfer the per-mint cap and the outbound bucket.

The limits exist so that even if a route's committee or signing keys were
compromised, the most that can be minted before anyone reacts is bounded by
what governance chose to risk on that route.

## Carried assets: stablecoins over a route

A route may also carry listed external tokens (`assets`, at most eight), such
as USDC and OUSD on Ethereum, Base and Solana. Each asset is lock-and-mint
in the other direction from TNZO: the token stays in the route's vault on
the external chain (the asset's `pool`) and Tenzro issues its 1:1
representation in the token ledger. The representation's id is fixed by the
symbol, so USDC carried over the Ethereum, Base and Solana routes is one
fungible token, and it appears in the EVM (ERC-20 facade) and SVM (Token-2022
view) views like any other ledger token.

| Field | Meaning |
|---|---|
| `symbol`, `name`, `decimals` | The token; the representation uses the same decimals |
| `pool` | The vault (token pool) on the external chain; for burn-and-mint, the issuer protocol's messenger |
| `remote_token` | The token on the external chain |
| `caip19` | The token on the external chain as a CAIP-19 asset id; an agent's `remote_limits` name it by this, and they hold every locked leg in it |
| `transfer` | `lock_and_mint`, or `{ burn_and_mint = { protocol, operator } }` |
| `mint_limit`, `lane` | Per-transfer and per-epoch limits and the CCIP pool buckets, in the asset's units (network TNZO limits do not apply) |
| `max_outstanding` | The most this route's vault may back at once |
| `enabled` | Assets ship disabled; an enacted `set_bridge_route` enables one |

An inbound delivery is matched to the asset by the pool that sent it and
must be addressed to the asset's representation. It raises the asset's
supply record (vault holdings against representation issued) and is refused
past `max_outstanding`: an issuer freezing one vault strands at most that
much, and the supply can be spread over vaults on several chains. Sending
out (`tenzro bridge send --asset USDC`; MCP `bridge_outbound` with `asset`;
`bridge().send(signer, chain, recipient, amount, "USDC")` in the TypeScript
SDK, `bridge().send(signer, chain, recipient, amount, Some("USDC"))` in Rust)
burns the representation and queues
the vault's release, never more than that route's vault holds. A disabled
route credits no new deposit of an asset but still lets holders redeem; a
paused route moves nothing.

**Burn-and-mint.** An issuer with its own transfer protocol plugs in as an
issuer transfer hook (`RouteFramework::with_issuer_hook`). The asset names
the hook's `protocol` and the `operator` account whose relationship with
the issuer the route runs under; that account must hold an attestor bond
when the route is installed. The committee still attests every delivery; the hook
also checks the issuer's burn evidence and builds the issuer's mint
instruction for the way out. Without the hook installed the asset carries
nothing.

## Route modes: open, disabled, paused

Every route is in one of three modes, which every node reads from chain state:

- **Open**: it carries traffic both ways.
- **Disabled**: it winds down. Nothing new leaves Tenzro over it, and a deposit
  route credits no new deposit. TNZO already sent out over a lock-and-mint route
  can still come back, and messages already sent to Tenzro (fill proofs, for
  example) are still admitted, so no transfer in flight when the route was
  disabled is stranded.
- **Paused**: it carries nothing at all.

How a route changes mode:

- **Governance sets any mode** with a policy update
  (`{"action":"policy_update","update":{"BridgeCircuitSet":{"adapter":"ccip","source_chain":"ethereum","mode":"disabled","reason":"..."}},"memo":"...","expedited":true}`).
  Disabling or pausing may take the expedited track (a shorter vote and
  timelock at a higher threshold), so a route can be stopped quickly. Opening
  always takes the standard track.
- **Validators pause a route on evidence.** A validator that observes an
  anomaly on a route, such as a delivery that does not match the locked
  amount, submits a finding carrying the hash of its evidence. The finding
  takes effect once validators holding at least two thirds of bonded stake
  have signed it. A validator finding never weakens a pause already recorded.
- **Opening is refused** while the route still holds a genesis placeholder,
  breaks the route rules, or its light client has not been bootstrapped from
  the route's anchor. The refusal names the route and what is missing, and
  `tenzro_getBridgeRoute` shows it in `open_refusal` before anyone votes.

### Procedure: bring a placeholder route into service

1. Fill the route: a `set_bridge_route` proposal carries the complete route
   (committee sizes and thresholds with no members, contract or ramp
   addresses, light-client anchor, caps). Its enactment clears the route's
   placeholders. The route stays disabled.
2. Draw its committees: once the beacon has taken a value since the
   enactment, anyone runs `tenzro bridge draw-committee --adapter ... --chain
   ...`.
3. Bootstrap its light client: anyone relays the bootstrap update from the
   anchor (`tenzro bridge light-client --adapter ... --chain ... --beacon <url>`
   for Ethereum, or `--update <hex>`); it is checked against the anchor.
4. Check `tenzro bridge route --adapter ... --chain ...`: `Cannot open` must be
   absent.
5. Open it: a policy update setting the mode to `open`, on the standard track.

### Procedure: stop a route

1. Disable it (wind down) or pause it (stop everything) with an expedited
   policy update; validators with two thirds of stake can pause it at once on
   evidence.
2. While disabled, relayers keep delivering returns of TNZO sent out earlier;
   holders on the other chain can still bring it home.
3. To resume, open it again through the standard track; the opening checks
   apply again.

## Sending TNZO out

A holder sends TNZO to another chain with a `Bridge` outbound transaction
it signs itself (`tenzro bridge send` in the CLI, `bridge().send` in the
SDKs, or MCP `bridge_outbound`, which returns the request and its signing
payload for the holder's device). The transaction names the destination chain, the recipient there and
the amount; its nonce and signature are the holder's own, so only the
holder's key can authorise it and each runs once.

The VM takes the TNZO out of the holder's balance, locks the same amount in
the route's vault, and builds the message that lets the other chain release
the same amount. The message is stored on Tenzro for the route's relayers to
carry. Nothing moves if any rule refuses the transfer.

## Receiving TNZO back

A relayer submits the route committee's signed delivery as a `Bridge`
inbound transaction it signs and pays the gas of from its own account
(`tenzro bridge deliver`, or `bridge().deliver` in the SDKs); the node never
relays from its own account. Block execution releases to the
recipient the delivery names only if every rule above passes: the committee
signatures, the nonce, the expiry, the caps, the breaker, and the amount the
route has outstanding on the other chain. A delivery is accepted once.

The same signed deliveries also carry statements that are not transfers, such
as an agent account's report or a settlement lock's event on another chain. Those are
checked the same way, use their own nonces, and never move TNZO. Tenzro sends
records the same way in the other direction, for example a settlement mirrored
onto another chain.

## Light clients

**Ethereum (sync committee).** For the route from Ethereum, governance sets
an anchor: the beacon chain's `genesis_validators_root`, the fork version
sync-committee signatures are made under, and the root of a finalized beacon
block anyone can check. The light client starts from that block's current sync
committee and follows each committee handover the committee itself signs. A
delivery's proof carries a beacon header signed by at least two thirds of a
committee the light client follows (an aggregate BLS signature), the
finalized header it commits to, optionally an older block proven through the
finalized state's `block_roots`, that block's `receipts_root`, and a
Merkle-Patricia proof of a successful receipt whose log is the on-ramp's
message event (of the lane's version) to this chain with exactly the
delivered message as its data. A header without a valid sync-committee signature, a receipt of a failed
transaction, a log from another contract or of another event, or any other
message is refused.

Anyone relays light-client updates as a `Bridge` light-client transaction
signed and paid for from its own account (`tenzro bridge light-client`): first the bootstrap from the anchor, then one
handover per sync-committee period (about 27 hours). An update is accepted only
on its own signatures and Merkle branches. `tenzro_getBridgeRoute` shows where
the light client stands (`light_client_head`).

The sync committee finalizes Ethereum itself. A rollup's messages are final
only once its own proof system settles them on Ethereum, which this light
client does not follow, so the Ethereum light client is accepted only on the
route from Ethereum.

The encodings of the bootstrap, the handover and the message proof are
fixed-layout and documented in `crates/tenzro-bridge/src/route/ethereum_light_client.rs`.
`tenzro bridge light-client --beacon <url>` relays from any beacon node: it
reads where the route's light client stands, fetches the update it needs next
through the standard Beacon API (the bootstrap from the anchor's block root,
or the light-client update of the period it is in), encodes it and submits it.

**Solana (attested execution).** Solana commits no per-slot receipt or
per-account state root a light client could check, and a transaction's
inclusion does not show that it succeeded. A Solana route therefore admits on
attestations alone, with a stronger rule than other routes: each verifier
reads the transaction that emitted the message from its own RPC provider at
finalized commitment, and signs, together with the message, an execution
record of the transaction's signature and slot stating that it succeeded. The
delivery carries that record as its proof, so every signature covers it. A
delivery is admitted only with the route's threshold of signatures from
verifiers that are pairwise independent: no two share an operator or an RPC
provider. Solana routes mint under the attested-route limits. When Solana
commits transaction results under a root its validators vote on, a Solana
light client takes the execution record's place: governance sets an anchor for
it on the route, as for Ethereum, and the route moves to the proven-route
limits.

## Proving Tenzro to other chains

A contract on an EVM chain follows Tenzro's finality with
`contracts/finality/TenzroFinalityClient.sol`. It is deployed with Tenzro's
chain id, genesis hash and genesis committee root, and holds the root of each
epoch's committee. It accepts a checkpoint when a Groth16 proof shows that the
finality program verified the checkpoint's certificate under the committee
whose root it holds for that epoch; a checkpoint that ends an epoch hands it
over to the next committee's root. The proof is checked by the RISC Zero
Groth16 verifier (`contracts/finality/vendor/risc0-ethereum`), for about a
quarter of a million gas.

The same client runs on Solana (`contracts/solana`, a program that checks the
proof with the `alt_bn128` syscalls and keeps the committee roots of recent
epochs and the latest final checkpoint in one account) and on Cosmos chains
(`contracts/cosmos`, an ibc-go 08-wasm light client: each accepted
checkpoint becomes a consensus state holding Tenzro's state root, under which
entries of Tenzro's IBC store are proven with Tenzro state proofs; see "IBC"
below). Both share the verifier in `contracts/finality-verifier` and are
tested on a real proof.

The finality program runs one light-client step inside the RISC Zero zkVM:
it checks the session certificates the certificate's signers name against
their hardware keys, each signer's ML-DSA-65 and P-256 signatures over the
checkpoint, and that the signers hold a quorum of seats. Its image id is
on-chain configuration on Tenzro (`finality_program` at genesis, then the
`FinalityProgramSet` policy) and a constructor argument of the contract. The
program is built in RISC Zero's guest-builder container with the repository
as its context and the built binary is committed
(`crates/tenzro-finality-prover/methods/finality-guest.bin`; an ignored test
rebuilds it and checks it is unchanged), so the prover builds on any host,
aarch64 GPU hosts included, and every build has the same image
id: `578bacf21a7a6a60d75ba661def3099b49231a66f52434b55cc987a18cf6ce39`, which
the production genesis names (`tenzro-finality-prover image-id` prints it; a
test of the prover fails if the two differ).

Proving is work anyone can pay for, for example through a harness task
market whose delivery evidence is the proof:

1. `tenzro finality step --chain-id .. --genesis-hash .. --out step.bin`
   writes the step of a checkpoint and prints its checkpoint digest,
   committee root and inputs digest.
2. Pay a prover for it (a task asking for a machine that wraps a finality
   proof into Groth16, paid from an escrow on delivery).
3. The prover proves in two stages, on two hosts or one:
   - the STARK stage, on an NVIDIA GPU host with `tenzro-finality-prover`
     built with `--features cuda`: `tenzro-finality-prover stark --step
     step.bin --out receipt.bin` writes the succinct receipt (the costly
     part: minutes on a GPU, most of an hour on a CPU for one
     signer);
   - the wrap stage, on any x86-64 host with `docker` (or podman as
     `docker`), with the prover built without `cuda`. The host pulls RISC
     Zero's Groth16 prover image (`v2025-04-03.1`) once, by digest, which
     checks its content:

     ```text
     docker pull risczero/risc0-groth16-prover@sha256:7f173963196570b7a71816ed70565a4579264c5d2e3e0ecb028102538ad0e331
     ```

     The wrap runs exactly that image (`--pull=never`, so a missing or
     different image is refused, never fetched) and without network
     (`--network=none`). `tenzro-finality-prover wrap --receipt receipt.bin
     --out proof.json` checks the receipt, wraps it on the CPU (one to two
     minutes, about 8 GB in the container) and checks the Groth16 receipt.
     Any other build refuses to wrap.

   Anyone checks the delivery with `tenzro_verifyEvidence` and a
   `finality_proof` item (journal and seal from `proof.json`): the chain
   verifies the seal against the governed finality program and returns the
   digest of the checkpoint and committee it proves, so the payer releases
   only for exactly the checkpoint it asked for.
4. Anyone submits the journal and the EVM seal from `proof.json` to the
   contract.

**Cosmos (Tendermint).** The anchor names the chain id, a trusted height and
the hash of the header at that height, and a trusting period shorter than
the chain's unbonding period. The client starts from that header and stores
a consensus state (time, app hash, next validator set hash) for each header
it accepts: a header newer than a trusted one, within the trusting period,
whose commit validators holding more than two thirds of its validator set's
power signed; for the next height its validator set must be the one the
trusted header named, further ahead more than a third of the trusted set's
power must have signed too. Two different headers at one height are refused.
A packet is proven by two ICS-23 existence proofs: its commitment under its
key in the IAVL store the route's `ramp` names, and that store's root in
the multistore, up to the app hash of a header the client holds. Any other
entry of that store (a connection or channel end, an acknowledgement) is
proven the same way, and the absence of one (a receipt the chain never
wrote) by its two neighbouring leaves, which must be adjacent. Packets
returning TNZO must time out by timestamp only, and a timed-out packet is
refused. `tenzro bridge light-client --adapter ibc --chain <c> --cosmos-rpc
<CometBFT RPC>` relays the bootstrap from the anchor, then each later header
(`--height`, default the latest) from the height the client trusts.

**Bitcoin (SPV).** The anchor names a header at a difficulty-adjustment
boundary, the confirmations a deposit needs (at least 6), and the deposit
descriptor: its signers' BIP-340 keys, how many must sign a withdrawal and
the withdrawal fee rate. The descriptor is
`tr(NUMS, multi_a(threshold, signers...))`, a Taproot output no key alone can
spend (`tenzro bridge descriptor` prints it, its output script and the route
`peer`, the SHA-256 of that script). The client follows the header chain with
the most cumulative work from that header, checking each header's proof of
work and its target under the mainnet retarget rule; a competing chain
replaces it only with more work. A deposit is proven by its block header
and a Merkle branch of its transaction, in a block of that chain buried
under the route's confirmations. The transaction must pay exactly one
output to the deposit script and name the Tenzro account in one
`OP_RETURN "TNZO" <account>` output.

Tenzro tracks every output the descriptor holds. A withdrawal (sending the
deposit asset to Bitcoin with `tenzro bridge send --target-chain bitcoin`,
whose route is the deposit route) burns the
representation and plans, from consensus state alone, the transaction that
spends the oldest outputs: the recipient's output script gets the amount less
the fee (the route's fee rate times the transaction's size), and the change
returns to the descriptor. Its transaction id, and with it the change output,
is fixed before anyone signs, so the change is tracked at once. The signers
read the withdrawal from a node (`tenzro bridge withdrawal --sequence N`),
sign each input's BIP-341 digest with their own keys, and the command
assembles the transaction once `threshold` of them signed. Bitcoin cannot
check a Tenzro proof, so what remains trusted is that `threshold` of the
signers sign no spend Tenzro did not order; the descriptor and a signed
withdrawal are checked against Bitcoin Core in its tests. Rotating the
signers is a new descriptor: governance installs the route with the new
signers after the old ones have signed a withdrawal moving the outputs to
it.

**Sui.** The anchor is the digest of an end-of-epoch checkpoint summary,
whose next-epoch committee the client starts from. Each later end-of-epoch
summary certified by the current committee (an aggregate BLS signature by
members holding more than two thirds of the stake) hands over to the next
committee. A message is proven by a certified checkpoint summary, its
contents, the transaction's effects (which must record success) and its
events; the delivered event must be one of them.

**Aptos.** The anchor is the hash of an epoch-ending ledger info, whose
next validator set the client starts from. Each later epoch-ending ledger
info signed by validators holding at least two thirds of the voting power
plus one hands over to the next set. A message is proven by a signed ledger
info, a transaction accumulator proof of the transaction's info (which must
record success) and an event accumulator proof of the delivered event.

**Stellar.** The anchor names the network id, a quorum of validator node
keys and how many of them must agree (more than two thirds). A ledger is
proven when that many of them signed SCP externalize statements for the next
slot with one value, whose transaction set names the ledger's header hash.
The proof then carries the ledger's transaction results, which the header
hashes, and the events of the bridge contract's invocation, whose hash its
success result is; every result and every event is parsed, so the proven
event is a real one. The quorum changes only when governance replaces the
route's anchor.

**TON.** The anchor is a masterchain key block (its seqno and root hash).
The client takes the validator set from that block's configuration
(parameter 34, through a Merkle proof of the block); the masterchain
validators are its first `main` members. A masterchain block is final once
validators holding more than two thirds of their weight signed the finalize
vote of the consensus candidate that names it. Each next key block finalized
by the current set hands over to its set. A message is proven by a finalized
masterchain block, Merkle proofs (pruned bags of cells) from its shard
descriptors to the basechain shard block that holds the bridge contract,
back through that shard's earlier blocks if needed, and in the last of them
the bridge contract's transaction and its external outbound message, whose
body must be exactly the delivered transfer record. The client is tested on
TON mainnet blocks.

Updates for the Tendermint, Bitcoin, Sui, Aptos and TON clients are relayed with
`Bridge` light-client transactions like Ethereum's. All encodings are
fixed-layout and documented in the light client's source file under
`crates/tenzro-bridge/src/route/`. A light client admits nothing until it has
been bootstrapped from its anchor (the Stellar client has no state and needs
no bootstrap).

**Relaying a message proof (Ethereum).** `tenzro bridge attest --adapter ccip
--chain ethereum --tx <hash> --source-rpc <execution RPC> --beacon <Beacon API>
--nonce N --expiry-ms T --request-out req.json` reads the on-ramp's message
(the event of the lane's version, picked by its sequence number with
`--sequence` when the transaction sent several) from the transaction's
receipt and builds the proof the light client checks:
the latest finality update, the headers from the message's block to the
finalized block, the block body's branch to its receipts root and the
receipt's trie proof, all from standard Beacon and execution APIs. It is
tested on Ethereum mainnet data.

**Attesting a Solana message.** A Solana route's verifiers each run `tenzro
bridge attest --adapter ccip --chain solana --tx <signature> --source-rpc
<their own RPC>`: it reads the transaction at finalized commitment, refuses a
failed one or truncated logs, and takes the router's `CCIPMessageSent` event
(logged by the route's router program itself). The delivery carries the
message and the execution record, and each verifier signs its digest with its
own hardware signer; `--request-in req.json --signature <hex>` adds a
signature (recovering the signer and checking it is a committee member) and
prints the delivery once the thresholds are met.

**Bridge contracts on other chains.** `contracts/` holds Tenzro's side on each
chain reached through a contract, each built and tested with its chain's own
toolchain: `sui` and `aptos` (Move), `stellar` (Soroban), `ton` (FunC, tested
in the TON sandbox). Each burns the TNZO representation and emits the
transfer record its Tenzro route decodes, and executes an outbound record
once the route's committee signed its digest (`tenzro bridge attest
--outbound-sequence N`), each sequence once. Each is initialized with the
committee the chain drew, its set index and its expiry, and afterwards only
takes a handover signed by the committee it trusts (above). The digest,
handover and record vectors in their tests are checked by Tenzro's route
tests too.

On TON, TNZO is a standard TEP-74 jetton: the bridge contract is its jetton
master and holders keep it in the reference jetton wallets. An outbound record
mints to the recipient's jetton wallet (owner `0:recipient`). A transfer to
Tenzro is an ordinary jetton transfer to the bridge contract's address whose
forward payload is `send_to_tenzro#54e0a5d1 recipient:uint256`: the bridge
burns the jettons through its own wallet and emits the transfer record (whose
sender is the jetton owner's account id); any other payload is returned. A
jetton amount is below 2^120, so the TON route refuses larger records in both
directions.

### Quantum safety of the proof forms

The Groth16 form of a finality proof (the BN254 wrap that an EVM chain, Solana and the other cheap
verifiers check) rests on elliptic-curve pairings. A large quantum computer breaks those, so a
Groth16-wrapped proof is not quantum-safe. The STARK form of the same proof is hash-based and is.
A holder of a large balance on an external chain should rely on the STARK form: verify it on a
chain or off chain verifier that accepts STARK receipts, or keep the balance on a route whose
limits (see above) cap what a forged Groth16 proof could release. Use the Groth16 wrap where gas
cost forces it, and size what you hold behind it accordingly.

## IBC

An IBC route speaks one of two protocol versions with its Cosmos chain,
named in its `ibc` settings:

- **IBC classic.** Packets travel the unordered `transfer` channel
  (`ics20-1`) on a connection between the two chains' light clients of each
  other. The connection and the channel are opened by handshakes whose state
  each chain keeps; a route's packets travel only once Tenzro's channel end
  is open.
- **IBC v2.** Packets travel between the two light clients directly: each
  chain registers the other's client as its counterparty, and there is no
  connection or channel. Use v2 for a chain that runs it (ibc-go v10 and
  later wire it in); a chain that runs only classic is reached over classic.

Both versions carry the same ICS-20 packets, and Tenzro commits, proves,
acknowledges and times them out with the same code. What differs is the
handshake layer and how a packet names its ends and its commitment:

| | Classic | v2 |
|---|---|---|
| A packet's ends | `transfer` and a channel on each chain | `transfer` and each chain's client of the other |
| Commitment key | `commitments/ports/transfer/channels/{channel}/sequences/{n}` | `{client} 0x01 {n}` |
| Commitment | SHA-256 of the timeout and the data's hash | SHA-256 over the destination client, the timeout and the payload's hash |
| Receipt, acknowledgement | `receipts/...`, `acks/...` | `{client} 0x02 {n}`, `{client} 0x03 {n}` |
| Timeout | Unix nanoseconds | Unix seconds, at most 24 hours ahead |
| Packet data (JSON) | keys sorted: `amount`, `denom`, `memo`, `receiver`, `sender` | `denom`, `amount`, `sender`, `receiver`, then `memo` when it is not empty |

**The route's settings.** `ibc` holds the version, the Cosmos chain's client
of Tenzro (`counterparty_client_id`), for classic the Cosmos chain's
connection and channel ends, and `packet_timeout_secs` (1 second to 24
hours). Tenzro's own identifiers are derived from the route's chain name, so
no two routes share one. With `n` the first eight bytes of the SHA-256 of
the chain name, read as a big-endian number in decimal (IBC identifiers are
`{prefix}-{number}`), its client of the chain is `07-tendermint-{n}`, and for
classic its connection is `connection-{n}` and its channel `channel-{n}`.
`tenzro_getBridgeRoute` shows them (`ibc.client_id`, `ibc.packet_id`). The route's `peer` and `local_endpoint` are the SHA-256 of
the Cosmos chain's end and of Tenzro's end (`transfer/{channel or client}`),
`remote_token` the SHA-256 of TNZO's trace on the Cosmos chain
(`transfer/{its channel or client}/atnzo`), and `ramp` the name of the Cosmos
chain's IBC store (`ibc`). A route whose fields do not match its settings
carries nothing.

**Tenzro's IBC store.** Tenzro keeps what a Cosmos chain verifies about it in
chain state: its connection and channel ends, the commitments of the packets
it sent, and the receipts and acknowledgements of the packets it received.
Its commitment prefix is `ibc`. The Cosmos chain's client of Tenzro
(`contracts/cosmos`) proves the path `[ibc, key]` as the committed state
entry `storage:{ff x 20}:{hex("ibc/" + hex(key))}` (namespace `state`) under
a Tenzro checkpoint's state root, with the proof `tenzro_getStateProof`
serves for that entry.

**Classic handshakes.** The Cosmos chain starts each handshake: its
`ConnOpenInit` names Tenzro's client and the prefix `ibc`, and its
`ChanOpenInit` the transfer port, the unordered order and `ics20-1`. Tenzro
then answers each step on a proof of the Cosmos chain's end, relayed by
anyone as a `Bridge` transaction (`tenzro bridge ibc --chain <c> --message
<m> --cosmos-rpc <CometBFT RPC>`, the `bridge_ibc` MCP tool, or `ibc` in the
SDKs):

1. `connection-open-try`: the Cosmos connection end is `INIT` towards
   Tenzro's client; Tenzro writes its end `TRYOPEN`. The Cosmos chain's
   `ConnOpenAck` then proves Tenzro's end through its client of Tenzro.
2. `connection-open-confirm`: the Cosmos end is `OPEN`; so is Tenzro's.
3. `channel-open-try` and `channel-open-confirm`: the same for the channel.

Each step checks every identifier against the route's settings and refuses
a second attempt. A v2 route takes no handshake message.

**Packets out.** `tenzro bridge send` over an IBC route locks the TNZO,
commits the packet in Tenzro's IBC store and records it as the route's
outbound record (`tenzro_getBridgeOutbound` shows its commitment, the state
key that holds it and whether it is `pending` or `settled`). The Cosmos
chain receives it on a proof of the commitment through its client of Tenzro.
A packet settles once:

- `acknowledge --sequence n --acknowledgement <hex>`: the Cosmos chain
  committed this acknowledgement. `{"result":"AQ=="}` leaves the TNZO on the
  Cosmos chain; an error acknowledgement (`{"error":...}` in classic, the
  universal error acknowledgement in v2) refunds the sender from the route's
  vault.
- `timeout --sequence n`: at a height whose block time is past the packet's
  timeout, the Cosmos chain holds no receipt of it. The sender is refunded.

Settling replaces the commitment, so the packet cannot settle twice and the
Cosmos chain can no longer prove it was sent.

**Packets in.** A packet returning TNZO is admitted as on every route
(committee, light-client proof of its commitment, caps, supply), on classic
only through an open channel, and Tenzro writes its receipt and its success
acknowledgement, which the Cosmos chain's relayer proves to it.

**Running both versions against a local chain.** `scripts/ibc-round-trip.sh`
starts a Cosmos chain built from ibc-go v10 with 08-wasm (`chain`), prints
the header a Tenzro route's light client trusts (`anchor`), stores and
creates Tenzro's client there, opens the Cosmos side of the classic
handshakes, registers the v2 counterparty and records the chain's headers and
proofs (`cosmos`, `record`). The routes reach Tenzro either at genesis, with
the anchor written into the genesis routes, or by governance on the standard
track (`routes`, which waits out the voting period and timelock). Its
`round-trip` stage then runs the whole exchange for both versions. Every
update of the Cosmos chain's client of Tenzro carries a Groth16 finality
proof, so that stage needs a prover built with `--features cuda` on an
NVIDIA GPU.

## Proof of Reserve

A route can have a reserve feed: an oracle network's independent report of
the TNZO held on Tenzro behind the route's representation. The feed is
consensus configuration: a `SetReserveFeed` governance proposal installs it
under the asset id `tnzo:<route key>` (for example
`tnzo:bridge_route:ccip:ethereum`) with its aggregator address, `eip155`
chain, decimals and staleness bound, and `RemoveReserveFeed` removes it.
Validators read only the aggregator consensus names; no operator setting
chooses it. `tenzro_getReserveFeed` returns the installed feed.

The reserve and the route's supply record are two views of the same number.
They may differ only by what the route can have moved since the feed's
round: one epoch's limit inbound, plus the lane's outbound bucket and what it
refilled since the round. Each epoch, every validator reads the feed of every
live route; a reserve outside that allowance is a finding against the route,
and once validators holding two thirds of bonded stake have flagged the same
round, the route's circuit breaker trips. `tenzro_readPorReserve` on the
route's asset id returns the reading with the same check (`route_check`).

Signed rate streams follow the same rule: their oracle signer sets are
installed by `SetRateStream` and removed by `RemoveRateStream` votes.

## Checking a route

Any node answers these read calls:

- `tenzro_listBridgeRoutes` lists every governed route with its limits, what
  it has minted this epoch, what remains, its lane buckets as they stand now,
  how much TNZO is locked for it, how much is outstanding on the other chain,
  its finality depth, where its light client stands, and whether it is
  paused.
- `tenzro_getBridgeRoute` returns one route by `adapter` (`ccip`, `ibc`,
  `deposit` or `contract`) and `source_chain`.
- `tenzro_getBridgeCircuit` returns the records that disable or pause the
  routes to and from a `source_chain`, for one `adapter` or all of them.

There is one bridge path. Earlier per-protocol bridges, their RPCs, CLI
commands, SDK clients and agent tools have been removed.
