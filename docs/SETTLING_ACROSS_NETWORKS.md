# Settling across networks

A settlement plan is one payment with several value legs and exactly one
decision: every leg settles, or none does. Tenzro is the coordinator and the
books; it never holds another network's keys or signs for it.

## The plan

A plan (`plan:<plan_id>` in consensus state) carries:

- the payer (`opened_by`) and the quote it settles (`quote_digest`);
- the agent that opened it from its wallet, if one did (`agent_did`);
- the split rule that divides its Tenzro value, whose hash the quote signed;
- 1 to 16 legs (at most 8 on other networks), each with the weakest evidence
  class it accepts: `native` (executed in Tenzro consensus), `proven` (proven
  from the other network's own consensus through a governed route) or
  `attested`;
- a decision deadline, at most `settlement.escape_horizon_ms` (14 days at
  genesis) after it opens;
- its tier, the weakest any leg needs: `native`, `decision_locked`,
  `ibc_transfer`, `hash_locked` or `compensated`.

`plan_id = SHA-256("tenzro/plan/v1" || chain_id || payer || quote_digest || nonce)`
and leg `i` is `SHA-256("tenzro/plan/leg/v1" || plan_id || i)`.

## Legs

| Leg | What it is | Reaches its class when |
|---|---|---|
| `native_transfer` | TNZO paid into the plan vault when the plan opens, from the payer's balance or from an escrow the payer funded (`escrow_id`) | at once (`native`) |
| `rail_instruction` | a bank, card or ISO 20022 payment sent after the commit, backed by a TNZO reserve (see Rail legs) | its payee or attestor confirms it inside the compensation window (`attested`) |

Every leg carries `usd_e6`, its USD value in micro-units as the quote priced
it. A leg off Tenzro must state it (a `native_transfer` leg is valued at its
amount).

### Plans an agent pays

A delegated agent opens a plan with `agent` set on the `open` operation: an
action its serving node signed, with operation `settlement_plan`. The plan is
paid from the agent's wallet, and the chain holds it to the agent's terms
before anything moves. A plan that is not netted moves only TNZO on Tenzro,
so its action names no asset, and its `amount` must be the plan's whole value
in wei: the `native_transfer` amounts, the USD value of every other leg
(rail legs and legs on other networks alike) at the rate in force, and the
TNZO the plan escrows beside them (a hash-locked leg's premium, rail
reserves); its `usd_e6` is the USD value of the legs off Tenzro. That value
counts against the per-transaction, hourly and daily limits and is spent
from the agent's budget when the plan opens. Every chain a leg settles on and
every party the plan pays must be within the terms' scope. What a leg locks on
another chain (a `remote_lock` leg's asset, a `hash_locked` leg's bitcoin) is
also named by its CAIP-19 id, which the leg's route gives it (`native_asset`
for the chain's coin, a carried asset's `caip19` for its token): the terms must
list that id in `remote_limits`, and the amount counts against its daily limit
there, the same daily count the agent's grants on other chains use. A leg in a
token its route names no id for is refused to an agent. A plan over the
limits needs the controller's step-up, like any other agent action.

The plan records the agent that opened it (`agent_did`). Revoking, pausing,
quarantining or terminating that agent aborts every plan it opened that is
still undecided, in the same transaction: the vault returns to the agent's
wallet, except a griefing premium a counterparty's funded hash lock has
earned. An agent holds at most 32 undecided plans at a time.

## The decision

- A plan whose legs are all on Tenzro commits in the transaction that opens
  it.
- Otherwise `prove_leg` (anyone may send it) records a leg's evidence; the
  transaction that brings the last leg to its class commits the plan, and a
  leg that can no longer reach its class aborts it.
- A plan still open after its deadline aborts in block execution before the
  next minute's transactions, and its vault returns to the payer in full.

On commit, in the same transaction, the protocol fee is charged once on the
plan's Tenzro value, the rest is divided by the split rule, every line is
paid from the vault, the decision is kept in the plan, and each leg's
receipt is written at `plr:<leg_id>`. Every decision, commit or abort, also
writes a fixed-size commitment at `decision:<plan_id>`:
`version (1) || outcome (1 = commit, 2 = abort) || decided_at_ms (8, big endian) || plan_id (32)`,
the record a lock on another network proves before it releases or refunds. Every one of these records can be
proven against a checkpoint with `tenzro_getStateProof`; each read below
returns the record's `namespace` and `key` for it.

### Network fees

Each leg off Tenzro may name a `max_network_fee` (TNZO wei): the most the
plan repays whoever carries that leg's proof for the fee it paid on the
leg's network. The relayer states the fee it paid in `ProveLeg`
(`network_fee`; CLI `tenzro settle prove --network-fee`). On commit the
plan repays each relayer `min(stated, max_network_fee)` from its vault,
after the protocol fee and before the split lines (the payee side bears it);
a relayer that paid more bears the rest, and nothing is repaid when the plan
aborts. A plan whose Tenzro value cannot cover every leg's cap after the
protocol fee is refused at open. A Tenzro leg and a rail leg repay no
network fee.

### Leg receipts on other networks

The receipt at `plr:<leg_id>` is fixed-size, so any chain reads it without
a JSON parser:
`version (1) || outcome (1 = commit, 2 = abort) || index (1) || class (1: 0 none, 1 native, 2 proven, 3 attested) || flags (1: bit 0 proof digest, bit 1 compensation, bit 2 relayer) || decided_at_ms (8) || plan_id (32) || leg_id (32) || amount (16) || network_fee (16) || compensation (16) || proof_digest (32) || relayer (32)`,
integers big endian, absent fields zero. `tenzro_getLegReceipt` returns it
decoded (`receipt`), as stored (`commitment`), and its proof key. A contract
relies on it once it is proven under a final checkpoint's state root:
`TenzroSettlementLock.provenLegReceipt(checkpoint, legId, receipt, proof)` on
EVM chains, and instruction 6 (`receipt leg_id checkpoint`, the receipt and
its proof staged in a buffer) of the Solana lock program, which returns the
receipt as return data for the program that called it. The shared vectors
are `sdk/fixtures/settlement_lock/leg_receipts.json`.

## Locks on other networks

A leg's value on another network waits in that network's settlement lock
until Tenzro decides the plan. On EVM chains this is
`contracts/settlement/evm/src/TenzroSettlementLock.sol`:

- `lock(plan_id, index, token, amount, recipient)` holds the value (the zero
  token address is the native coin) under the leg id
  `SHA-256("tenzro/plan/leg/v1" || plan_id || index)`.
- `settle(plan_id, index, checkpoint, decision, proof)` (anyone) checks the
  state proof of the decision commitment at `decision:<plan_id>` under the
  state root of a final checkpoint of Tenzro's finality client on that chain:
  a commit pays the recipient, an abort refunds the payer, once.
- `escape(plan_id, index)` refunds the payer only after the escape horizon
  (`settlement.escape_horizon_ms`, 14 days at genesis), so no refund can race
  a commit while Tenzro is live.

On CosmWasm chains `contracts/settlement/cosmwasm` has the same three
messages (`lock` takes the one bank coin sent with it) and reads checkpoint
roots from Tenzro's finality registry on that chain (`state_root { index }`).
On Stellar `contracts/settlement/stellar` has `lock(payer, plan_id, index,
token, amount, recipient)` for any Stellar asset contract, `settle` and
`escape`, reading roots from Tenzro's finality client on Stellar.
On Solana the program in `contracts/settlement/solana` holds lamports in, or
SPL tokens (Token or Token-2022) in a vault owned by, the leg's PDA
`["leg", config, leg_id]`; `lock` takes the payer and, separately, the
account that funds the leg's rent (a wallet passes itself twice). A decision and its proof outgrow a transaction,
so the settler stages `decision || proof` in a buffer account (`write`,
reclaimed with `close`) and `settle` checks it against the state root of
the finality client's latest final checkpoint (about 260k compute units).
On Sui `tenzro_bridge::settlement_lock` keeps each leg's `Coin<T>` balance in
a shared lock object (`lock<T>`, `settle<T>`, `escape<T>`); on Aptos the
module of the same name holds fungible assets at the lock object's address
(`lock(payer, plan_id, index, asset, amount, recipient)`, `settle`,
`escape`). Both read roots from Tenzro's finality client in their package
and check the proof with the package's state-proof verifier.
On TON `contracts/ton/contracts/settlement-lock.fc` holds legs of one asset:
TON (`lock`), or one jetton whose master is fixed in the lock's data; the
lock learns its jetton wallet from that master (`learn_wallet`) and a leg
is a standard jetton transfer to the lock whose forward payload is
`plan_id (256) || index (8) || recipient (256)`. To settle, a relayer asks
Tenzro's finality client on TON to report a final root to the lock with
`plan_id, index, ^decision, ^proof` as payload; the lock accepts reports
only from that client. Each leg brings 0.1 TON for its payout.
Chains written in Rust share one leg state machine,
`tenzro_finality_verifier::settlement` (`settle_leg`, `escape_leg`), so a leg
moves once and only on a proven outcome or after the horizon.

The lock holds no key and trusts no relayer; `sdk/fixtures/settlement_lock`
carries real decision commitments and their proofs for every chain's tests.

### Lock evidence

A remote leg counts once `prove_leg` records evidence for it at
`ple:<leg_id>`. For a lock leg the evidence is the lock's `Locked` event
proof: under the route's light client it reaches `Proven`, under a route
committee `Attested`; the event must name the plan, the leg, the asset, the
amount and the recipient, and the lock must hold the leg until the plan's
deadline plus the release margin. `tenzro_getLegReceipt` returns the
recorded evidence (class, evidence digest) beside the leg's receipt, each
with its state-proof key.

Every lock also keeps a running reconciliation hash over what it records
(each lock, release and refund, in order, from zero: `sha256("tenzro/settlement/recon/v1"
|| acc || plan_id || leg_id || kind || amount)`) and its entry count, and
`checkpoint()` emits them. The route proves that checkpoint the way it proves
a `Locked` event: under its light client from the family's event proof (on
EVM the `Accumulator(uint64 count, bytes32 acc)` log), under a route
committee as the attested 40-byte body `count (8, big endian) || acc` (a lock
event's body is 185 bytes). A checkpoint is never a leg's evidence:
`prove_leg` refuses it.

Per family, the checkpoint is:

- EVM: `checkpoint()` emits `Accumulator(uint64 count, bytes32 acc)`.
- Stellar: `checkpoint()` publishes topics `[accumulator]`, data `[count: u64, acc: bytes]`.
- Solana: instruction `7 checkpoint` (accounts: config) logs `[accumulator,
  body]` and returns the 40-byte body as return data. The config account
  holds the running hash, so `lock`, `settle` and `escape` take it writable.
- Sui: `settlement_lock::checkpoint(&lock)` emits `Accumulator { count: u64, acc: vector<u8> }`;
  `reconciliation(&lock)` reads the pair.
- Aptos: the entry function `settlement_lock::checkpoint()` emits the same `Accumulator`
  event; the view `reconciliation()` reads the pair.
- TON: op `0x5c1a3e29` (checkpoint) sends the external log tag `0x64`, count (64), acc
  (256); the getter `get_reconciliation` reads the pair. The lock's data keeps them in a
  reference cell after the legs dictionary.
- CosmWasm: the lock stores `{"count", "acc": hex}` at `recon` (query `reconciliation {}`
  reads it); the stored entry is the checkpoint, proven under the chain's app hash. A
  lock proof is `0 || plan_id || index || entry proof` for a leg or `1 || entry proof`
  for the checkpoint.

### Reconciliation

Anyone may reconcile a route's lock against Tenzro's books with
`SettlementPlan { op: reconcile { adapter, chain, entries, checkpoint } }`:
the entries the lock recorded since the last reconciliation, in order (1 to
512 of `{plan_id, leg_id, kind: locked | released | refunded, amount}`), and
the route's proof of the lock's checkpoint. Folded from the stored running
hash, the entries must give the proven hash, and the stored count plus their
number must give the proven count; otherwise the transaction is refused, so
an invalid submission costs only its fee and changes nothing. Gas grows with
the entries and the evidence bytes.

Each admitted entry is then checked against the plan and decision it names: a
lock or payout must belong to a lock leg of a plan on this route, of the
leg's amount; a release needs the plan's commit, and a refund must not follow
one. An entry that disagrees is stored as a mismatch at
`recon_mismatch:<route>:<position>` (with the running hash before it, so it is
provable against the checkpoint), logs `ReconciliationMismatch`, and the
route is disabled by the reconciliation authority (a pause in force is kept).
The route's progress is stored at `recon:<route>`.

A mismatch records the account on Tenzro it cost the leg's value, if any (the
plan's payer for a release without a commit; the account the plan's first
payee line pays for a refund after one), and that value in TNZO at the rate
in force (`loss`). On an attested route (one without a light client, whose
checkpoint stands on its committee's attestation alone), a reconciliation
that finds mismatches slashes `settlement.attestor_slash_bps` (genesis 10%)
of the attestor stake of every member of the route's committees, the account
each member's signing key names, into the insurance pool, and the harmed
account may claim its loss from the pool with
`PayInsuranceClaim { recon_mismatch: { adapter, chain, position } }`, once
per mismatch and within the pool's claim cap. A route with a light client
answers for its own proofs, so its mismatches stop the route but neither
slash nor pay.

Reconciliation is a paid job, so it happens every epoch rather than only
when someone volunteers. In the first block of each epoch the chain opens a
network duty for every route with a settlement lock (`reconciliation { route,
epoch }`, funded by the treasury), moving the governed reward
`settlement.reconciliation_reward` (genesis 1 TNZO; 0 opens none) from the
treasury, which the settlement fee's treasury share funds, into the duty's
keyless vault. The first verified reconciliation of the route in the epoch is
paid the reward at once and the duty becomes `paid`; later reconciliations in
the same epoch are recorded but not paid. A duty still open when its epoch
ends is closed (`expired`) and its reward returns to the treasury. A route
whose duty the treasury cannot fund is listed as `unfunded` in the epoch's
`recon_jobs` record. Open duties are read with `tenzro_listDuties`. Routes enter and leave
the set (`recon_routes`) when governance installs or removes them with or
without a settlement lock, and at genesis.

`tenzro_submitReconciliation {adapter, chain, entries, checkpoint}` checks
the entries continue the stored reconciliation and returns the transaction to
sign (`tx_type`) with the count and hash the checkpoint must prove.
`tenzro_getReconciliation {adapter, chain}` returns the progress, this
epoch's reconciliation task (`task`) and
`tenzro_listMismatches {adapter, chain}` every stored mismatch, each with its
state-proof key.

### Bitcoin legs

A Bitcoin leg is hash-locked: the payer funds a P2WSH output paying the
recipient's key with the preimage of the leg's hash, or the payer's key after
`refund_after`. The first `prove_leg` carries the SPV proof of the funding
transaction (one output of exactly the leg's amount to the leg's script; a
funding output backs one leg); the second carries the preimage, which
Tenzro accepts only inside the transaction that commits the plan. The secret
is derived from the payer's hardware key over the plan and leg ids, never
stored. Once committed, `tenzro_getLegReceipt` returns the preimage and the
recipient claims with it. The script's refund must open no earlier than the
plan's deadline plus the release margin.

The Bitcoin leg's payer also escrows a TNZO `premium` in the plan vault when
the plan opens, at least `settlement.griefing_premium_bps` (1% at genesis) of
the plan's Tenzro value. Holding back the preimage after funding would keep
every other leg's value locked until the deadline at no cost, so if the plan
aborts with the HTLC funded, every other leg in and the preimage never
revealed, the premium is divided by the plan's split rule (no protocol fee;
a line paid to the submitter goes to the aborting transaction's sender, or in
block execution to the first line naming an account) and the decision
records it as `premium_paid`. Every other outcome, a commit included, returns
it to the payer.

Residual risk: a claim must confirm on Bitcoin before `refund_after`. If
Bitcoin fees spike for longer than the release margin after a commit, a
recipient that bid too low can be outrun by the payer's refund, which then
recovers the coins although the plan committed. Recipients claim as soon as
the preimage is public and raise the fee (RBF or CPFP) while the refund is
still closed; routes set the release margin with the chain's fee history in
mind.

### Agent accounts paying into a lock

A Tenzro agent account on another chain pays into a lock with one action
that moves exactly its stated amount and leaves nothing approved:

| Chain | How |
|---|---|
| EVM | `_execute` approves exactly the amount to the lock, calls it, resets the allowance to 0 |
| Stellar | the lock call carries one nested `transfer(account, lock, amount)` of the grant asset; any other nested call is refused |
| CosmWasm | selector `execute`: `WasmMsg::Execute` to the lock with the signed `lock` message and exactly the amount as funds |
| Sui | `settlement_lock::lock_from_agent` / `lock_exact_from_agent`: the account hands over a coin of exactly the amount and is the leg's payer; `agent_account::receive` takes a refund back |
| Aptos | `settlement_lock::lock_exact_from_agent`: exactly the amount of the fungible asset, the account as payer |
| TON | selector `call`: the action's data is the hash of the message body, sent with exactly the amount, bounceable |
| Solana | selector `4`: the lock's `lock` instruction with the account signing as payer and the relayer funding the leg's rent; the source token account must end exactly the amount lower and otherwise unchanged |

Refunds go back to the account itself.

## Rail legs

A bank credit transfer (ISO 20022 pacs.008 or pacs.009) or a card capture
cannot be locked, so a `rail_instruction` leg does not hold up the decision:
the plan commits once its other legs are in, and the rail payment is sent
after the commit. The leg names the rail, the SHA-256 of the instruction, the
currency and amount, the payee's Tenzro account, an optional
attestor, and a TNZO `reserve` the payer escrows in the plan vault when the
plan opens. A rail leg is `attested` and its USD value (the leg's `usd_e6`) is held to
`payments.attested_cap_usd_e6`; the plan's tier is `compensated`.

The commit opens the leg's compensation window,
`settlement.compensation_window_ms` (72 hours at genesis). Inside it:

- With no attestor named, the payee confirms with `prove_leg`, carrying the
  rail's settlement confirmation (for ISO 20022, its camt.054). Its own
  signature completes the leg and the reserve returns to the payer at once.
- With an attestor named (the operator that connected the rail under its own
  relationship), only the attestor confirms. It must hold an `attestor` role
  bond when the plan opens and when it confirms. The reserve stays in the
  vault until the window closes, and the payee may send `dispute_rail` with
  its evidence that the payment did not arrive.

When the window closes, block execution ends every open rail leg: a confirmed
leg returns its reserve to the payer; an unconfirmed leg pays the reserve to
the payee. A dispute does the same at once. Either way a compensated leg
slashes `settlement.attestor_slash_bps` (10% at genesis) of its attestor's
bond into the insurance pool, and its receipt records `compensation`. A plan
that aborts returns every reserve to the payer, and no rail leg is ever in
when a Bitcoin leg's premium is weighed.

A payer that does not trust the payee's word names an attestor: without one,
the payee's signature is the only evidence either way.

## The split

One pure function divides a gross amount, the same in the VM, the RPC
preview and every SDK (checked against `sdk/fixtures/split/vectors.json`):

1. `fee = max(floor(gross * fees.settlement_fee_bps / 10000), min_fee)`,
   never above the gross; `min_fee` is `fees.min_settlement_fee_micro_usd`
   (1 micro-USD at genesis) at the live rate. The fee divides into burn
   (`fees.settlement_fee_burn_bps`), insurance (`fees.insurance_pool_bps` of
   the unburned part) and treasury.
2. Network fees the payee side bears come off next.
3. `fixed` lines are paid in order, each capped by what remains.
4. `bps` lines share what is left by largest remainder: each takes the floor
   of its share, and the units lost to flooring go one each to the largest
   fractions, ties to the lower line.
5. The single `remainder` line takes the rest, so the parts sum to the gross
   exactly. A line's `cap` sends its excess to the remainder line.

A rule is `{version: 1, lines: [{role, recipient, basis, cap}]}`; a recipient
is a 32-byte hex `address`, a registered `did_derived` identity (paid to the
account its root key derived; refused if revoked) or `leg_submitter` (the
account whose transaction decided the plan). The fee is charged once per
plan, however many legs or lines it has.

## Netted plans

A `netted` leg (`{ "netted": { "asset", "amount" } }`, class `native`) is value
the opener owes the plan's split recipients in one asset, TNZO or a carried
asset a governed route lists. A plan holding one holds only netted legs of
that asset, and commits in the
transaction that opens it: the protocol fee is charged on the gross at once,
and the split's credits become the opener's obligations in the asset's open
batch.

Netted value is backed by collateral posted on Tenzro:
`SettlementPlan { op: post_collateral { asset, amount } }` moves it into the
participant's own collateral vault, and `withdraw_collateral` takes it back
down to what its net debit in the open batch needs. A plan is refused when
the opener's net debit in the batch would exceed its collateral after the fee.

A delegated agent nets from its own wallet under its terms. It posts with
`agent` set on `post_collateral`: the collateral leaves the agent's wallet for
the agent's vault. The action names the asset (`asset`, the `0x` token id;
absent for TNZO), states the amount in it (`amount`) and, off TNZO, its USD
value (`usd_e6`), so the most its net debit can reach counts against the
asset's own per-payment and daily limits in the terms (`asset_limits`; an
asset not listed is refused) and against the wei limits at its USD value.
Each netted plan it opens names the plan's asset and states its gross the
same way and counts against the same limits, and every party the plan pays is
within its scope.
`withdraw_collateral` with `agent` returns collateral to the agent's wallet
and states no value.

When the batch's epoch (`settlement.netting_epoch_ms`, default one hour)
ends, block execution nets it and pays each net instruction from the debtor's
collateral vault. A debtor whose collateral was frozen or taken in the
meantime defaults: what it has is divided over its instructions in
proportion, the default is recorded, and it opens no netted plans again.
`tenzro_getNettingBatch` returns the batch (obligations, their Merkle root,
instructions, what each paid, defaults) and, for a participant, a statement
proving its gross position equals its net.

## Surfaces

| | |
|---|---|
| Transactions | `SettlementPlan { op: open | prove_leg | dispute_rail | post_collateral | withdraw_collateral | reconcile }`; `PayInsuranceClaim { recon_mismatch }` |
| RPC | `tenzro_previewSplit`, `tenzro_getPlan`, `tenzro_getPlanDecision`, `tenzro_getLegReceipt`, `tenzro_listPlans`, `tenzro_getNettingBatch`, `tenzro_submitReconciliation`, `tenzro_getReconciliation`, `tenzro_listMismatches` |
| CLI | `tenzro settle preview | open | prove | dispute | get | decision | receipt | list | post-collateral | withdraw-collateral | netting | reconcile | reconciliation | mismatches`; `tenzro insurance claim --recon-adapter --recon-chain --recon-position` |
| MCP | `settle_preview_split`, `settle_open_plan`, `settle_prove_leg`, `settle_dispute_rail` (complete an unsigned request and return its signing payload; the wallet signs client-side), `settle_get_plan`, `settle_get_decision`, `settle_get_leg_receipt`, `settle_list_plans`, `settle_get_netting_batch`, `settle_submit_reconciliation` (returns the transaction to sign), `settle_get_reconciliation`, `settle_list_mismatches` |
| SDKs | Rust `client.settle()`, `PlanBuilder`, `SettleClient::open_plan_tx`/`prove_leg_tx`/`dispute_rail_tx`/`collateral_tx`, `get_netting_batch`, `preview_split`, `submit_reconciliation`/`get_reconciliation`/`list_mismatches`; TypeScript `client.settle`, `PlanBuilder`, `SettleClient.openPlanTx`/`proveLegTx`/`disputeRailTx`/`collateralTx`, `getNettingBatch`, `previewSplit`, `submitReconciliation`/`getReconciliation`/`listMismatches`. The Python SDK has no settlement-plan helpers yet; until it does, send the `SettlementPlan` operation as a raw signed transaction |

Opening a plan and proving a leg are transactions the caller signs with its
own key (the CLI signs locally); the node never signs for anyone.

A completed generative-media job returns the plan its requester signs to pay
its workers: one leg drawing the price from the job's escrow and a split rule
giving each worker its share.
