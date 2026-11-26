# Network parameters

Every network policy and economic value of Tenzro Network is a governed
parameter: fees and the fee market, slashing rates and correlation penalties,
unbonding and cooldown periods, SLA penalties, bridge-adjacent caps,
reward claim terms and the voting rules themselves. Each one:

- starts at its genesis value, written into chain state at block 0;
- is read from chain state by every node, so all nodes apply the same value;
- changes only through an enacted `parameter_change` governance proposal.
  There is no admin RPC, CLI flag or node configuration that sets one.

## Reading them

```bash
tenzro governance params                        # all of them
tenzro governance params --key dispute.max_rounds
```

Over JSON-RPC, `tenzro_getNetworkParams` returns every parameter (or one, with
`{"key": "..."}`) with its current value, bounds, genesis value, the direction
that tightens it and any enacted change still waiting for its epoch. Values
are decimal strings, since several exceed what a JSON number holds exactly.
The MCP tool is `get_network_params`; the SDKs expose
`GovernanceClient.getNetworkParams()` (TypeScript),
`GovernanceClient::get_network_params` (Rust) and
`get_network_params` (Python).

## Changing one

```bash
tenzro governance propose-param --key dispute.max_rounds --value 4 --memo "why"
```

The SDKs build the same proposal with `parameterChangeProposal` (TypeScript),
`parameter_change_proposal` (Rust) and `tenzro.governance.parameter_change_proposal`
(Python); sign and send it like any other transaction.

1. **Submission.** A value outside the parameter's bounds, or a key that is
   not a governed parameter, is refused when the proposal is submitted.
2. **Vote.** The proposal is decided on the standard track by the voting
   rules in force when it opened (`governance.*`). A rule change enacted
   while a proposal is open never moves that proposal's window, timelock or
   threshold.
3. **Enactment.** After the timelock the proposal is executed. The bounds are
   checked again, and the change is scheduled rather than applied.
4. **Activation.** The change applies at the start of the next epoch: the
   first block of that epoch, before its transactions, writes the new value
   and every block of the epoch runs on it.
5. **Grace window.** A change that asks more of the people a rule binds (a
   higher bond, slash or fee, or a shorter window to respond in) waits a
   further `governance.tightening_grace_epochs` epochs, so those it binds can
   adjust first. Loosening changes apply at the next epoch.

Bounds are hard safety limits that keep the network working at both ends: an
epoch-based value of zero, a quorum anyone could clear alone, a slash above
100%. They change only with a protocol upgrade. Cryptography, encodings,
state-transition rules and gas costs are protocol rules, not parameters.

Epoch and round lengths (the `[time]` rules: checkpoint interval, checkpoints
per epoch, idle round interval, leader slots) and the consensus weight cap are
fixed at genesis in the current release and become governable from a later
upgrade.

## Proposal actions

A parameter change is one of the actions a proposal can carry. The node
accepts 32, each with a stable `kind` label that `tenzro_getProposal` and the
event stream report. Every action belongs to one of three domains: `network`
(operational and reversible by another vote), `treasury` (moves value, so a
later vote cannot take it back) and `sanction` (takes something from a named
party). Agents originate nothing by default (agent phase `none`). At phase
`network` they may originate `network` actions only; `treasury` and `sanction`
actions need phase `all`, which a vote must set explicitly.

| Kind | Domain | What it does |
|---|---|---|
| `parameter_change` | network | Sets a governed parameter, switch or status lever. A change that only pauses a feature runs on the expedited track. |
| `policy_update` | network | Changes structured policy: the economic policy, the burn dial and supply targets, TPM endorsement roots, a bridge route's limits or circuit, the finality program, or a protocol upgrade. |
| `set_delegate_code` | network | Lists or delists the code hash of an EIP-7702 delegate. |
| `set_rate_stream`, `remove_rate_stream` | network | Installs, replaces or removes the signer set of a signed rate stream validators quote from. |
| `set_reserve_feed`, `remove_reserve_feed` | network | Installs, replaces or removes the Proof-of-Reserve feed validators read for an asset. |
| `set_settlement_asset` | network | Installs or replaces the entry that lets payments settle in a token other than TNZO. |
| `remove_bridge_route` | network | Removes an inbound bridge route. |
| `lift_module_freeze` | network | Lifts a freeze the value-invariant monitor put on a module; the monitor refreezes it while the vault is short. |
| `approve_validators` | network | Approves accounts to register as validators while admission needs approval. |
| `recall_sponsored_bond` | network | Recalls a validator's sponsored bond to the treasury after the governed unbonding period. |
| `revoke_operator`, `revoke_grantee` | network | Withdraws an approval; later payments stop at once. |
| `treasury_grant`, `release_grant_tranche` | treasury | Pays a grant to an approved grantee, then each tranche. |
| `running_cost_payment` | treasury | Pays the network's running costs from the running-cost reserve. |
| `recover_unowned_funds` | treasury | Reassigns funds at a system address that the accounting shows belong to nobody. |
| `set_network_payout` | treasury | Sets where the network's share of an off-ledger rail's payments is paid. |
| `set_bridge_route` | treasury | Installs or replaces the inbound route for one bridge protocol and source chain. |
| `set_agent_account_chain` | treasury | Installs or replaces the record of a chain agents hold accounts on. |
| `treasury_remote_action` | treasury | Moves treasury funds on another chain through the treasury's keyless account there. |
| `sponsor_validator_bond` | treasury | Bonds existing treasury TNZO on a validator's behalf; slashable, never votes, earns nothing. |
| `approve_operator`, `approve_grantee` | treasury | Opens the gate that sponsorship and grants pay through. |
| `sponsor_operator_running_cost`, `sponsor_operator_stable` | treasury | Pays an approved operator part of its running cost for verified hours, in TNZO or in an approved USD stable asset. |
| `revoke_identity` | sanction | Revokes a registered identity and everything it controls. |
| `set_guardian`, `remove_guardian` | sanction | Seats a human guardian for a fixed term, or unseats one early. |
| `retire_registry_entry` | sanction | Retires an abusive registry entry; its bond goes to the insurance pool. |
| `reinstate_validator` | sanction | Returns a jailed validator to candidacy at the next epoch boundary (see "Jail" below). |

Sponsorship and grants are described in `docs/SPONSORSHIP-AND-GRANTS.md`.

## Levers

Every integration and extension point ships with levers governance can
operate at an epoch boundary through the same `parameter_change` proposal,
with no code change:

- **Status levers** (keys ending in `.status`): `0` enabled, `1` paused, `2`
  retired. Paused means nothing new starts on the feature and what already
  started finishes or winds down under its own rules; another vote resumes
  it. Pausing and resuming apply at the next epoch. Retiring waits out the
  tightening grace window as well, and it is final: a proposal to change a
  retired lever is refused at submission. Status levers exist for each
  inference verification level (`inference.verification.*.status`), each
  proof system the chain verifies (`zk.*.status`), each kind of recovery
  signer and recovery by code (`keystore.recovery.*.status`), new bonds for
  each bonded operator role other than validator (`roles.*.status`; the
  committee stays open to anyone who bonds), and each bridge transport over
  all its routes (`bridge.*.status`; retired winds a transport down as a
  disabled route does, so nothing in flight is stranded).
- **Pausing in a hurry.** A `parameter_change` that sets a status lever to
  paused (`1`) runs on the expedited track (short vote and timelock, higher
  threshold, open to a veto by the guardians and stewards); it applies at the
  next epoch. Resuming (`0`) and retiring (`2`) run on the standard track.
  Protocol guardians can also stop one running feature without a vote:
  `governance.guardian_threshold` of them signal the same lever and the same
  number of epochs (at most `governance.feature_pause_max_epochs`) with a
  `GovernanceFeaturePause` call (selector `0x0200000c`, payload: the epochs
  as 4 bytes big endian, then the lever key). The lever then reads paused
  until those epochs pass, and guardians cannot pause the same feature again
  until `governance.feature_pause_cooloff_epochs` after it lifts. Guardians
  can only stop an enabled feature: they cannot enable, resume or retire
  one, or change a value, and the chain keeps running. `tenzro_listLevers`
  shows a running guardian pause as `guardian_pause_until_epoch`.
- **Switches** (keys ending in `_enabled`): `1` on, `0` off.
- **Values**: amounts, caps, rates and windows, each within the bounds in
  the table below. Bounds on a validator's own round timing
  (`consensus.leader_timeout_*`, `consensus.round_interval_*`) are read when
  an epoch begins and hold whatever the validator's configuration says.

Registration stays permissionless where the rules require it: a lever only
opens, bounds or closes a class; it never admits or refuses a named party.

`tenzro_listLevers` (optional `{"area": "bridge"}`) returns every lever with
its kind, value, status, bounds and any enacted change waiting with the epoch
it activates in, plus every installed bridge route with the mode its own
record and its transport's lever leave it in. The MCP tool is `list_levers`;
the SDKs expose `GovernanceClient.listLevers()` (TypeScript),
`GovernanceClient::list_levers` (Rust) and `list_levers` (Python).

Structured policy records (the economic policy split, the adaptive burn
configuration, supply targets, bridge
routes and mint limits, guardians, TPM endorsement roots, the finality
program) are changed by the matching `policy_update` or governance action and
read with `tenzro_getPolicy` and their own read methods.

## Feature gates

A new state-transition rule ships in the binary dormant and is switched on
for every node at one epoch by a vote. The gate is the parameter
`feature.<name>.activation_epoch`: the first epoch whose blocks run the
rule. Execution code asks `feature_gate::is_live(state, key, epoch)` with the
epoch of the block it executes. The convention, and the helper, live in
`crates/tenzro-vm/src/feature_gate.rs`:

- Its registry entry is bounded `0` to `1 << 62` (the highest value means
  never), tightens neither way, and starts at `1 << 62` for a rule added to a
  chain that has run without it, or at `0` for a rule a new chain has always
  had. Other tunables of the rule are `feature.<name>.<parameter>`.
- The epoch moves by an ordinary `parameter_change`. While the rule is
  dormant a vote may set it at least 2 epochs ahead of the epoch the change
  is checked in, or back to never; a proposal that falls short is refused at
  submission and again at enactment. Once the network's release floor is
  0.2.2 or above, an epoch already set moves or goes back to never only
  while it is itself at least 2 epochs ahead, so the change applies before
  that epoch starts and a consensus core rebuilt in it after a restart
  counts as the cores built at its start. Once the rule is live its epoch is
  final. A rule that needs an off switch after it is live carries a status
  lever beside its gate.
- Keys in the `feature.` namespace are not in the genesis state root and not
  in the genesis state unless the genesis file's `[network_params]` names
  them; a key that is absent reads as its registry genesis value. A release
  that adds one starts on an existing data directory
  (docs/GENESIS-ROOT-UPGRADES.md).
- A binary that does not know a key refuses a `parameter_change` naming it,
  while one that knows it enacts the change. So no proposal naming a key a
  release adds is submitted until every validator runs that release;
  otherwise validators on the two binaries execute the proposal differently.

### The idle beacon

`feature.idle_beacon.activation_epoch` switches on a rule for what
validators send, not for what a block accepts: from that epoch a validator
holds its beacon contribution while the only transactions since the beacon's
latest value are the validators' own upkeep, and sends it once a block holds
other traffic or the latest value is `feature.idle_beacon.idle_interval_ms`
old (30 minutes at genesis), whichever comes first. The round's turns are
counted from that moment, read from the chain alone, so the validators send
one after another as before however long the hold lasted. The same rollout
rule applies: neither key is named in a proposal before every validator runs
the release that adds them.

### The reliable-broadcast fault bound

`feature.rbc_whole_member_fault_bound.activation_epoch` is the first epoch
whose reliable broadcast takes its thresholds from the most seats that whole
committee members within `f = (n - 1) / 3` can hold, in place of `f`. A
validator is faulty with all its seats or none, so that figure bounds the
faulty seats as `f` does and is lower whenever no set of members adds up to
`f`: four validators of 200 seats have `f = 266` and a bound of 200, and
deliver in two steps with one of them silent, which `f` does not allow.
The bound is 0 when no single member fits within `f` (two validators of 400
seats): such a committee tolerates no faulty member under either bound.
Before that epoch the thresholds are the ones `f` gives. Every validator of
an epoch uses the same thresholds, so the bound changes only at an epoch
start, for the whole committee at once.

### Indexed availability cap

From `feature.availability_index_cap.activation_epoch` a unit the
availability reward pays per proven GPU earns at most
`feature.availability_index_cap.bps` (750, 7.5%, at most 10%) of the
datacenter-GPU compute price index in force (`IDXDCGPU`, nano-USD per
compute-hour, converted at the TNZO rate in force), when that is below the
absolute per-unit-hour cap. A unit with no proven GPU keeps the absolute cap:
the chain knows no other hardware class for a bond, and the provider's own
announcement would let it pick the dearest index. While validators have
frozen no index, the absolute cap holds. The rule is dormant: switching it on,
and the share it uses, are decided by a governance vote after the simulation
of both caps across the three markets in `tenzro-econsim`.

### Whole-USD demand target

The availability reward's demand offset phases the reward out as verified
paid demand reaches a target. `reward.availability_demand_target_atto_usd_per_day`
holds the target in atto-USD in a 64-bit value, so it can say at most about
18 USD a day. From `feature.availability_demand_target_usd.activation_epoch`
the target is read from `feature.availability_demand_target_usd.usd_per_day`, in
whole USD up to 10,000,000 a day, and the atto-USD key is no longer read. Both
are zero at genesis, which leaves the offset off.

### The identity rule

A transaction from an account with no registered identity
is refused at execution (`feature.identity_required.activation_epoch`).
Registration (`RegisterIdentity`, key enrolment) and protocol records stay
open to an unregistered account, and an account holding a validator bond is
exempt, so the genesis validators keep producing blocks from block 1 and any
other account can register itself. The registry value is never, so a running
chain is untouched; the launch genesis names `0`, so the rule is live from
the first block of a new network.

Because a live rule's epoch is final, the rule carries a governed mode beside
its gate, `feature.identity_required.mode`:

| Value | Mode | What happens to an account or peer with no registered identity |
|---|---|---|
| `0` | enforce (genesis value) | refused at execution, and by every node's peer gate, mempool and edge |
| `1` | audit | admitted everywhere; each admission enforce would have refused is logged |
| `2` | off | admitted everywhere without a check |

The mode moves by an ordinary `parameter_change`, with no new genesis and no
release. Relaxing (to `1` or `2`) applies at the next epoch; a change to
audit runs on the expedited track like pausing a status lever, a change to
off on the standard track. Returning to enforce asks more of everyone the
rule binds, so it waits out the tightening grace window
(`governance.tightening_grace_epochs`). Every node reads the mode from chain
state at admission time: while it is enforce, a node's peer gate, mempool
and edge run in the node's own `[onboarding]` mode; once governance relaxes
it, every node admits what the governed mode admits, with no restart and no
config change. The execution rule is the same on every validator whatever a
node's own `[onboarding]` table says.

## One derivation of the root behind an identity

Rules that count parties (funding limits per root, fee-weighted shares,
distinct payers, a validator's operator, an aged human root) ask who stands
behind an identity. From `feature.one_operator.activation_epoch` (dormant
until a vote sets it) they all take one answer: the identity followed through
the controllers its agent terms name, then the root its DID is derived under,
with a machine root named as a machine. Before that epoch two of them read the
root from the DID's text.

The answer changes for two kinds of identity only: one delegated under an
autonomous machine (its root was read as a human of the same id), and one
whose DID is neither a human's nor a machine's (an institution's, for one).
The records those rules keep are keyed by root, and the gate's epoch need not
start a reward epoch, so in the one reward epoch the gate goes live in:

- such a payer that already paid in that reward epoch is counted once more
  among its distinct payers, only in that reward epoch (the one the activation
  epoch falls in) and never again; before the activation epoch nothing changes;
- the fees such a root paid earlier in that reward epoch stay under its old
  key and do not weigh in that epoch's fee-weighted shares.

Every other identity reads the same on both sides, and no balance moves at
the switch.

## Jail

A validator that signs two checkpoints with one index is slashed (see the
`slashing.*` parameters) and jailed: it leaves the active set. Jail is never
permanent. It ends in either of two ways, and the validator then returns as a
candidate, admitted again like any candidate by the activation churn cap and
the self-stake floor:

- **The term runs out.** `slashing.jail_term_epochs` (genesis 720, 24 to
  8766) counts from the epoch of the jailing. A longer term asks more of a
  validator, so raising it waits out the tightening grace window; shortening
  it applies at the next epoch and also shortens the jail of a validator
  already jailed.
- **Governance reinstates it.** A `reinstate_validator` proposal (a
  `Sanction` action, standard track, with a stated reason) names the
  validator. Once enacted, the validator is released at the next epoch
  boundary if it was jailed at or before the epoch of the enactment. The
  proposal needs a validator that holds a bond. It does not undo the slash,
  and for a validator that is not jailed it does nothing. Open one with
  `tenzro governance propose-reinstate-validator --account <validator> --memo
  <reason>`, or build it with `reinstate_validator_proposal` (Rust and Python
  SDKs) or `reinstateValidatorProposal` (TypeScript SDK); the MCP tools and
  `tenzro_getProposal` return it as `reinstate_validator`.

`tenzro_listValidators` shows the epoch a jailed validator is released from
(`jailed_until_epoch`).

## Settlement asset entries

Each settlement asset carries its own limits in the entry a
`SetSettlementAsset` vote installs; an entry outside these bounds is refused.

| Field | Default | Min | Max | What it does |
|---|---|---|---|---|
| `par_band_bps` | 100 | 25 | 300 | Most the asset's frozen rate may sit from its currency's rate, bps. Outside it, nothing settles in the asset. |
| `epoch_inflow_cap_units` | 1000000 | 0 | 100000000 | Most value that may settle in the asset in one epoch, whole units of account. |
| `max_treasury_share_bps` | 5000 | 1000 | 7000 | The share of the treasury's stable holdings payout swaps rebalance the asset toward. A target, not a refusal. |
| `max_exposure_bps` | 7500 | 1000 | 9000 | Most of the treasury's whole value (TNZO and stable holdings) the asset may make up. A payout swap that would take the treasury past it does not run. Must sit above `max_treasury_share_bps`. |

The peg breaker that suspends and re-enables an asset runs on the network
parameters `settlement_asset.breaker_suspend_epochs`,
`settlement_asset.breaker_resume_epochs` and
`settlement_asset.breaker_resume_band_bps` below.

## Hardware levels

A provider's hardware level adds a small bonus to its provider reward share;
it never admits or excludes anyone, and no role is closed to level 0. The
chain derives the level at every reward epoch close from attestation evidence
already in state, never from what a participant declares: level 1 is a
machine identity whose TPM endorsement certificate chains to a manufacturer
root governance recognizes, that is not revoked, whose TPM backs no other
live identity, and that proved this epoch it still holds the TPM; everything
else is level 0. Level 2 is level 1 where the same TPM holds the identity's
enrolled ML-DSA key: the machine's admitted attestation key certifies it
(`TPM2_Certify`) as a TPM 2.0 library v1.85 ML-DSA object, generated in the
TPM and unable to leave it, over a statement naming the identity and the key,
and the certification is sent as a `HardwareProof`. Level 3 is level 2 where
that key is a restricted ML-DSA attestation key, or level 1 with a second,
independent hardware scheme proven in the same epoch: an NVIDIA GPU whose
per-device certificate chain ends at a GPU device root governance recognizes
signs the epoch's GPU challenge in an SPDM measurement report, sent as a
`HardwareProof`. One GPU counts for one live identity. Enrolling a different
ML-DSA key leaves the earlier certification matching nothing, so the level
falls back until the new key is certified.

`tenzro_getHardwareLevel` answers with the level derived now and, under
`unproven`, why an address is at level 0: no registered identity behind the
account, a revoked identity, no TPM attestation on the machine root (a node
whose root was registered without one attaches it by itself once the
registration is on chain; `tenzro validator attach-attestation` does the same
by hand),
an endorsement certificate no recognized root covers, no possession quote for
the current or previous epoch, or a TPM another live identity holds. Level 0
says no hardware is proven yet; it does not say the key is held in software.

The GPU device roots are a governed record (`gpu_device_roots`), replaced by a
`GpuDeviceRootsSet` policy update and empty until one passes, so no GPU counts
until governance names a root. NVIDIA publishes its device identity root for
offline verification (`NVIDIA Device Identity CA`, SHA-256 fingerprint
`10:2B:F6:59:D5:41:96:14:C9:D8:E6:AE:CE:BC:80:45:4E:B2:6B:1D:F6:A7:69:AC:72:0B:9A:69:0B:16:7B:48`,
in NVIDIA's open-source verifier `nvtrust`). The report's measurements must
also match NVIDIA's reference values, a governed record
(`gpu_reference_values`) replaced by a `GpuReferenceValuesSet` policy update:
for each measurement index it lists, the values NVIDIA's reference integrity
manifests accept there (indices NVIDIA marks inactive are left out and not
compared). It is empty until one passes, so no GPU counts until governance
names the values for the firmware and drivers in service. Revocation, which
NVIDIA publishes only by OCSP, is an online question and so no part of the
chain's check; a node may ask it of each GPU proof it receives
(`[gpu_revocation]`, off by default) and keep refused proofs out of its pool.

A key in an Apple Secure Enclave stays at level 0, and Tenzro has no verifier
for it. The enclave offers no attestation of its own: it has no endorsement
key or certificate that anyone can check without Apple, and every statement
that a key lives in it (App Attest, DeviceCheck, managed device attestation,
the `apple` WebAuthn attestation format) is signed by Apple and verifies only
against an Apple root used under Apple's licence terms. A verifier would put
that root, and that licence, in the network's trust root, which the network
does not allow. Level 0 earns the full base reward; the level is only a
capped bonus.

Possession is proven every reward epoch. Once the randomness beacon takes its
first value in the epoch, the machine's admitted TPM attestation key quotes a
challenge bound to its identity, the epoch and that beacon value, and the node
sends the quote as a `HardwareProof` transaction. Nobody knows the challenge
before the epoch begins, so no quote can be made ahead and replayed once the
TPM is gone. An epoch's close counts only a quote for that epoch: a machine
that sends none, or whose quote is refused, is level 0 at that close and
returns to its level at the first epoch it proves again.

The bonus is `hardware.level<N>_bonus_bps` of the base share, at most
`hardware.level_bonus_cap_bps` (0 turns it off). It is paid on top of every
base share, first from the provider share's unmatched rights and then from the
pool, so nobody's base reward changes. The levels may not decrease from 1 to
3, and the cap is bound with the settlement reward shares so that a buyer,
provider and app acting together still never earn back what a settlement cost
them. `tenzro_getHardwareLevel` returns an address's recorded and current
level with its hardware type; quotes and delivery receipts that name a level
must name that one.

## Genesis

The genesis file may set any parameter's starting value in a
`[network_params]` table:

```toml
[network_params]
"fees.settlement_fee_bps" = 10
"governance.steward_sunset_ms" = 1917043200000
```

A key that is not a governed parameter, or a value outside its bounds,
refuses the genesis. A parameter the file leaves out starts at the genesis
value below.

### Ordering rules

Two consensus values decide what every validator must compute alike: the DAG
rounds kept below the last committed leader (`gc_depth`, the floor of the
ordering state) and the seats a committee apportions by stake
(`seat_budget`, part of the committee root). They are the network's, not a
node's, and are fixed in the genesis `[consensus]` table:

```toml
[consensus]
gc_depth = 50
seat_budget = 1000
```

A value the table leaves out is this release's default (50 rounds, 1,000
seats) on every node. A value it names is committed by the genesis state
root and `genesis_inputs_digest`; a genesis without the table keeps the
digests it had. Each must be positive. A node's own `[consensus]` table keeps
its local settings (round timing, batching, mempool limits), but a `gc_depth`
or `seat_budget` in it is ignored with a warning naming the value the
network applies, so two validators with different files derive the same
committee and ordering state. They are not governed parameters: changing
them is a protocol upgrade.

### Validator registry rules

The validator registry's configuration is committed chain state. Two of its
rules have no governed parameter, so they are fixed in the genesis
`[validator_registry]` table rather than compiled into a release:

```toml
[validator_registry]
activation_churn_bps = 400     # validators activated per epoch, of the active set
reentry_cooldown_epochs = 4    # epochs before an exited validator may register again
```

The table names both or neither; a partial table refuses the genesis. When
named, genesis writes the registry configuration (these two, with the
governed rules at their genesis values) where every node's registry reads
it, and both genesis digests commit to the table. The governed rules are the
validator self-stake floor (`stake.validator_tnzo`), the minimum self-stake
of a validator that also serves RPC (`stake.rpc_tnzo`, the RPC operator
bond), `staking.exit_churn_bps` and `slashing.jail_term_epochs`; each node
reads them from chain state at the epoch's last block, so a vote that
changes one moves the registry at the next boundary on every node alike. A
genesis without the table writes nothing and keeps its digests.

## Every parameter

`Tightens` is the direction that makes the rule stricter for those it binds:
a change that way waits out the grace window.

<!-- BEGIN GENERATED PARAMETERS -->
| Key | Genesis | Min | Max | Tightens | What it does |
|---|---|---|---|---|---|
| `accounts.ml_dsa_leg_on_enrolment.status` | 1 | 0 | 2 | neither | Whether an account that enrolls an ML-DSA-65 key requires from then on the ML-DSA-65 leg of every key acting for it (its own key, linked passkeys, recovery signers), as if it sent the require-leg operation: 0 enabled, 1 paused, 2 retired. Paused until the network runs a build that reads it. |
| `accounts.outflow_max_open_releases` | 16 | 1 | 1024 | down | Most queued releases one account may have open at once. |
| `accounts.outflow_min_hold_ms` | 3600000 | 60000 | 2592000000 | up | Shortest hold, ms, an account may set on its own outflow policy: the time its owner or guardian has to cancel a queued release or a queued loosening. |
| `accounts.outflow_min_window_ms` | 3600000 | 60000 | 2592000000 | up | Shortest window, ms, an account may count its outflow cap over. |
| `admission.delegated_burst` | 100 | 1 | 1000000 | down | Transactions a delegated-lane sender may submit at once after being idle. |
| `admission.delegated_fee_mult_bps` | 15000 | 10000 | 1000000 | up | Least gas price a delegated-lane sender's transaction is admitted at, in bps of the base fee the next block charges. |
| `admission.delegated_rate_milli` | 10000 | 1 | 100000000 | down | Transactions per second, in thousandths, a sender in the delegated lane (machine identity under a verified controller, or holding an agent bond) may submit. |
| `admission.open_burst` | 10 | 1 | 1000000 | down | Transactions any other sender may submit at once after being idle. |
| `admission.open_fee_mult_bps` | 40000 | 10000 | 1000000 | up | Least gas price any other sender's transaction is admitted at, in bps of the base fee the next block charges: what each transaction of a flood from funded fresh keys costs its owner over a verified sender's. |
| `admission.open_rate_milli` | 250 | 1 | 100000000 | down | Transactions per second, in thousandths, any other sender may submit. |
| `admission.verified_burst` | 500 | 1 | 1000000 | down | Transactions a verified-lane sender may submit at once after being idle. |
| `admission.verified_fee_mult_bps` | 10000 | 10000 | 1000000 | up | Least gas price a verified-lane sender's transaction is admitted at, in bps of the base fee the next block charges. |
| `admission.verified_rate_milli` | 50000 | 1 | 100000000 | down | Transactions per second, in thousandths, a sender in the verified lane (attested identity with bonded stake) may submit. |
| `agent.max_unrenewed_ms` | 7776000000 | 86400000 | 34560000000 | down | How long (ms) a delegated agent may act after its root last approved its terms in full. A scope change within pre-approved bounds does not renew; a lapsed agent acts again once its root re-approves its terms. |
| `agent.relay_deposit_utnzo.aptos` | 1000000 | 0 | 1000000000 | up | Relay deposit a grant on Aptos holds, micro-TNZO. |
| `agent.relay_deposit_utnzo.cosmos` | 1000000 | 0 | 1000000000 | up | Relay deposit a grant on a Cosmos chain holds, micro-TNZO. |
| `agent.relay_deposit_utnzo.eip155` | 1000000 | 0 | 1000000000 | up | Relay deposit a grant on an EVM chain holds, micro-TNZO. |
| `agent.relay_deposit_utnzo.solana` | 1000000 | 0 | 1000000000 | up | Relay deposit a grant on Solana holds, micro-TNZO. |
| `agent.relay_deposit_utnzo.stellar` | 1000000 | 0 | 1000000000 | up | Relay deposit a grant on Stellar holds, micro-TNZO. |
| `agent.relay_deposit_utnzo.sui` | 1000000 | 0 | 1000000000 | up | Relay deposit a grant on Sui holds, micro-TNZO. |
| `agent.relay_deposit_utnzo.tvm` | 1000000 | 0 | 1000000000 | up | Relay deposit a grant on TON holds, micro-TNZO. |
| `agent.remote_grant_budget_divisor` | 24 | 1 | 1440 | neither | A grant on another chain holds at most the asset's daily limit over this. |
| `agent.remote_grant_ttl_ms` | 600000 | 10000 | 86400000 | neither | Lifetime of an agent's grant on another chain when its terms set none. It bounds how long a revoked agent can still act there. |
| `agent.topup_max_days` | 90 | 1 | 366 | down | Days ahead the expiry of an agent top-up allowance may be set; an allowance runs out within this and the controller renews it to keep refills going. |
| `agent_bond.spend_bps` | 1000 | 0 | 10000 | up | A delegated agent's bond, in basis points of its spend ceiling. |
| `agent_bond.withdraw_cooldown_ms` | 1209600000 | 3600000 | 7776000000 | up | Milliseconds between starting an agent-bond withdrawal and finalizing it; the bond stays slashable meanwhile. |
| `beacon.commit_reveal.status` | 1 | 0 | 2 | neither | Whether beacon contributions commit to a secret and reveal the last one, which the mix takes beside the VRF output: 0 enabled, 1 paused, 2 retired. Paused until the network runs a build that reads them. |
| `bridge.ccip.status` | 0 | 0 | 2 | retire | Every CCIP route at once: 0 enabled (each route's own mode applies), 1 paused (carries nothing), 2 retired (winds down: nothing new leaves, TNZO already out may come back). |
| `bridge.committee_term_ms` | 2592000000 | 86400000 | 31536000000 | neither | How long a drawn bridge committee serves before a new draw falls due, ms. |
| `bridge.contract.status` | 0 | 0 | 2 | retire | Every contract route at once: 0 enabled (each route's own mode applies), 1 paused (carries nothing), 2 retired (winds down: nothing new leaves, TNZO already out may come back). |
| `bridge.deposit.status` | 0 | 0 | 2 | retire | Every deposit route at once: 0 enabled (each route's own mode applies), 1 paused (carries nothing), 2 retired (winds down: nothing new is credited). |
| `bridge.equivocation_slash_bps` | 5000 | 1 | 10000 | up | Share of a bridge committee member's attestor bond taken when it signed two deliveries with one nonce or a handover to a committee the chain did not draw, bps. |
| `bridge.exit_delay_ms` | 86400000 | 3600000 | 604800000 | neither | How long a large bridge exit waits before anyone may release it, ms: the window in which a seated guardian, or anyone after a proven fault of its route's committee, may cancel it. |
| `bridge.exit_delay_threshold_bps` | 2500 | 1 | 10000 | neither | A bridge exit larger than this share of its outflow bucket's capacity waits out the exit delay before it leaves, bps. |
| `bridge.handover_window_ms` | 604800000 | 3600000 | 7776000000 | neither | How long after its term a bridge committee may still hand bridge contracts over to the next one, ms. Its members stay bonded until then, and the contracts stop trusting it after. |
| `bridge.ibc.status` | 0 | 0 | 2 | retire | Every IBC route at once: 0 enabled (each route's own mode applies), 1 paused (carries nothing), 2 retired (winds down: nothing new leaves, TNZO already out may come back). |
| `bridge.queue_max_epochs` | 24 | 1 | 168 | neither | Epochs of a unit's bridge outflow cap the exit queue may hold. An exit over the cap this epoch queues instead of failing while the queue is shorter, and anyone may release it once an epoch has room. |
| `bridge.security_gamma_bps` | 10000 | 2000 | 40000 | up | Margin of the stake-backed bridge caps, bps: each epoch the caps of units other than TNZO shrink so that, with TNZO's cap, one epoch lets out at most two thirds of bonded stake over one plus this, valued at the safety rate. |
| `bridge.watcher_cooloff_ms` | 86400000 | 3600000 | 2592000000 | up | How long, ms, after a watcher pause ended before a watcher may pause the same route again. |
| `bridge.watcher_min_bond_age_ms` | 86400000 | 3600000 | 2592000000 | up | How long, ms, a bond must have been held to count for a watcher. |
| `bridge.watcher_min_stake_tnzo` | 1000 | 1 | 10000000000 | up | Least bonded stake, whole TNZO, an account holds to pause a bridge route as a watcher. |
| `bridge.watcher_pause_ms` | 21600000 | 600000 | 259200000 | up | How long, ms, the pause a bonded watcher puts on a bridge route holds before it lifts by itself. |
| `bridge.watcher_review_ms` | 259200000 | 3600000 | 1209600000 | up | How long, ms, after a watcher pause ended validators and governance have to confirm it before it is judged. |
| `bridge.watcher_slash_bps` | 100 | 1 | 10000 | up | Share, basis points, of everything a watcher has at stake that an unconfirmed pause costs it. |
| `catalog.fault_slash_bps` | 1000 | 1 | 10000 | up | Share of a catalog publisher's bond an upheld catalog fault takes into the insurance pool, bps. |
| `compute_bond.min_escrow_gwei` | 100000000 | 0 | 1000000000000 | up | Least TNZO, in gwei, one escrow toward a bonded provider may lock, so the open escrows a provider's bond carries stay few enough to check on every new one. |
| `compute_bond.min_tnzo` | 100 | 1 | 10000000 | up | Least compute bond a provider posts to be probed and routed to, whole TNZO. |
| `compute_bond.var_ratio_bps` | 11000 | 0 | 1000000 | up | Least ratio, in basis points, of a bonded provider's compute bond to the TNZO it holds in open escrows; an escrow that would breach it is refused. 0 turns the check off. |
| `compute_bond.withdraw_cooldown_ms` | 604800000 | 3600000 | 7776000000 | up | Milliseconds between starting a compute-bond withdrawal and finalizing it; the bond stays slashable meanwhile. |
| `consensus.leader_lookahead_rounds` | 4 | 1 | 64 | neither | Rounds between the anchor that closes a checkpoint and the first round its seed draws leaders for. Read when an epoch begins and fixed for that epoch; a validator behind on its decisions waits rather than judge leaders it may yet see redrawn, so a shorter value costs speed, never safety. |
| `consensus.leader_timeout_max_ms` | 30000 | 100 | 600000 | neither | Longest leader timeout a validator runs with, whatever its own configuration says, ms. Read when an epoch begins. |
| `consensus.leader_timeout_min_ms` | 100 | 10 | 10000 | neither | Shortest leader timeout a validator runs with, whatever its own configuration says, ms. Read when an epoch begins. |
| `consensus.max_committee_members` | 100 | 4 | 110 | down | Most validators the committee of an epoch holds, once the committee cap is in force. Validators past it by stake rank hold no seat that epoch. A certificate costs about 8.9 KB per signer and must fit one gossip message of 1,048,576 bytes, so no value above 110 can be certified. |
| `consensus.operator_weight_max_bps` | 3300 | 1000 | 3333 | down | Most of the committee's seats the validators behind one root identity may hold once the operator cap is in force, bps; below a third, so no one operator can stop or split the committee alone. |
| `consensus.region_weight_max_bps` | 3300 | 1000 | 3333 | down | Most of the committee's seats the validators declared in one region may hold once the region cap is in force, bps; below a third, so the loss of one region leaves a quorum. |
| `consensus.round_interval_max_ms` | 2000 | 10 | 60000 | neither | Least time between a validator's rounds it may configure, at the longest, ms. Read when an epoch begins. |
| `consensus.round_interval_min_ms` | 0 | 0 | 1000 | neither | Least time between a validator's rounds it may configure, at the shortest, ms. Read when an epoch begins. |
| `consensus.sender_failover_ms` | 10000 | 1000 | 600000 | neither | The most a sender's ready transactions wait on the validator they are assigned to before the next validator in turn may batch them, and each further validator as long again, ms. Read when an epoch begins. Shorter takes a sender off a slow or absent validator sooner; longer orders fewer transactions twice. |
| `escrow.close_grace_hours` | 168 | 0 | 8784 | neither | Hours past its expiry after which anyone may close an escrow; what accrued goes to the payee and the rest to the payer, as when they close it. |
| `escrow.retention_hours` | 720 | 24 | 87840 | neither | Hours an escrow's record stays in state once it can no longer move, counted from its expiry; it is then deleted and its whole record emitted in an EscrowArchived log for indexers. |
| `evm.block_gas_limit` | 30000000 | 1000000 | 1000000000 | down | Gas the EVM and SVM transactions of one block may use, once feature.evm_conformance is live. They run in order while the gas used so far is below it; the one that crosses it completes and the rest run in a later block. |
| `evm.delegate_allowlist_enforced` | 0 | 0 | 1 | up | Whether an EIP-7702 authorization may only name a delegate whose code hash governance listed (SetDelegateCode). The zero address, which clears a delegation, is always admitted. |
| `evm.delegation_changes_per_window` | 4 | 1 | 10000 | down | Most delegation changes (EIP-7702) one account may make in the rolling window, across transactions. Slows a thief who lands one authorization per transaction. |
| `evm.delegation_window_ms` | 86400000 | 60000 | 2592000000 | up | Rolling window, ms, over which delegation changes per account are counted against the ceiling. |
| `evm.foreign_chain_authorization_allowed` | 0 | 0 | 1 | down | Whether an EIP-7702 authorization signed for another chain id is admitted in a transaction here (the EVM then skips it). |
| `evm.max_authorizations_per_tx` | 2 | 1 | 256 | down | Most EIP-7702 authorizations one set-code transaction may carry. A run of them over consecutive nonces is how a stolen key sweeps accounts. |
| `evm.multiple_authorizations_per_signer_allowed` | 0 | 0 | 1 | down | Whether one signer may appear more than once in an EIP-7702 authorization list. Entries over consecutive nonces for one account are how a stolen key sweeps it. |
| `evm.universal_authorization_allowed` | 0 | 0 | 1 | down | Whether an EIP-7702 authorization signed for every chain (chain id zero) is admitted. One signature then holds on each chain that admits it. |
| `feature.active_set_cap.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which feature.active_set_cap.max_active bounds the active validator set; before it candidates are activated within the churn budget alone. |
| `feature.active_set_cap.max_active` | 10000 | 4 | 10000 | down | Most validators the active set holds once its feature gate is live: bonded candidates beyond it wait in stake order for a free seat, and a seated validator is never removed for it. |
| `feature.affiliated_share.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept a proposal marking an account as affiliated with the founders, publish the year's sponsorship and grants paid to marked accounts, and refuse a payout to one that would lift that share above feature.affiliated_share.max_bps. Until then the proposal is refused. Dormant until a vote sets it. |
| `feature.affiliated_share.max_bps` | 2500 | 0 | 10000 | down | Most of a calendar year's sponsorship and grants, bps of the year's total in each unit, that accounts marked as affiliated with the founders may receive once the affiliated share is in force; a payout that would exceed it is refused. |
| `feature.agent_cap.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks refuse a root (a human or an autonomous machine) a further agent once it has feature.agent_cap.max_agents_per_root agents it has not revoked. Dormant until a vote sets it. |
| `feature.agent_cap.max_agents_per_root` | 64 | 1 | 65536 | down | Most agents one root may have delegated and not revoked, once the agent cap is live. Agents a root already has are never removed by a lower value; it is refused new ones until it is under the limit. |
| `feature.agent_spend_expiry.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks refuse a PayerSettle from a delegated agent's registered wallet once the agent's terms have expired, as AgentAct, protocol payments and channel vouchers already are. |
| `feature.agent_succession.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept RevokeIdentityTo: a root revokes itself in favour of a successor, its delegated agents are quarantined for good instead of revoked, and only the successor reclaims what their wallets hold. Until then the transaction is refused. Dormant until a vote sets it. |
| `feature.agent_succession.successor_human_only` | 1 | 0 | 1 | up | Whether the successor a root names when it is revoked in its favour must be a human identity: 1 a human root only, 0 any root (a human or an autonomous machine). |
| `feature.agent_terms_bounds.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks record an agent's terms only when they state a daily spending ceiling (max_daily_spend) and an expiry (expires_at_ms). Terms recorded before it stay in force; their next change states both. Dormant until a vote sets it. |
| `feature.availability_demand_target_usd.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose availability reward reads its demand target from feature.availability_demand_target_usd.usd_per_day (whole USD) instead of reward.availability_demand_target_atto_usd_per_day, which cannot hold more than about 18 USD a day. Dormant until a vote sets it. |
| `feature.availability_demand_target_usd.usd_per_day` | 0 | 0 | 10000000 | neither | Verified-paid demand, whole USD per day, at which the availability reward's demand offset has phased the reward to zero. Read from feature.availability_demand_target_usd.activation_epoch. Zero (genesis) disables the offset. |
| `feature.availability_index_cap.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose availability rewards cap a unit paid per proven GPU at feature.availability_index_cap.bps of the datacenter-GPU compute price index in force, when that is below the absolute per-unit-hour cap. Units with no proven GPU keep the absolute cap. Dormant until a vote sets it. |
| `feature.availability_index_cap.bps` | 750 | 0 | 1000 | down | Basis points of the datacenter-GPU compute price index one proven GPU's unit-hour of availability reward may reach once the indexed cap is live. Read only from feature.availability_index_cap.activation_epoch. |
| `feature.availability_paid_activity.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which the availability reward pays only a subject whose owner earned the governed minimum of provider work within the governed window (feature.availability_paid_activity.window_epochs, .min_work_wei, .bootstrap_until_epoch); before it recent paid work is not asked for. |
| `feature.availability_paid_activity.bootstrap_until_epoch` | 0 | 0 | 4294967295 | neither | Reward epoch before which the availability reward's paid-activity requirement is waived, so a network with no paid demand yet can pay its first hardware-bound operators. Zero waives nothing. |
| `feature.availability_paid_activity.min_work_wei` | 40000000000000000 | 0 | 4000000000000000000 | neither | Least provider work, wei of reward weight, the owner of an availability-reward subject must have earned over the paid-activity window. Weight is the governed share of the protocol fee a settlement paid, so this is a floor on fees other parties paid; genesis is what 100 TNZO of settled payments earn at the genesis fee and provider share. |
| `feature.availability_paid_activity.window_epochs` | 30 | 0 | 365 | neither | Reward epochs back, counting the current one, within which the owner of an availability-reward subject must have earned the governed minimum of provider work (recorded only for settled payments from a registered party of another root identity) for the reward to pay it. Zero asks for no paid activity. |
| `feature.bond_onramp.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept a validator bond bought with a stable settlement asset: the treasury takes the asset and pays TNZO, at the higher of the rate in force and the safety rate less fees.onramp_spread_bps, straight into the buyer's validator bond, within treasury.onramp_max_tnzo_epoch. The treasury exchanging TNZO for stable assets distributes TNZO, so setting this is the owner's decision. Dormant until a vote sets it. |
| `feature.boot_nodes.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which governance may replace the machine identities a node dials to find the network (`BootNodesSet`), and from which a node that has chain state reads them from it. A node without chain state dials the list its genesis file names. Until then a proposal that names the set is refused. |
| `feature.builder_attestations.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept BuildAttestation transactions from accounts bonded in the attestor role, and enact a protocol upgrade only once every binary it names has feature.builder_attestations.min_builders such attestations from builders whose bonds stand. Dormant until a vote sets it. |
| `feature.builder_attestations.min_builders` | 2 | 1 | 64 | up | Distinct bonded builders that must have rebuilt and attested each binary of a protocol upgrade before it enacts, once builder attestations are in force. |
| `feature.burn_bound_release.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose closes hold what the rewards pool releases to a ratio of the TNZO the epoch burned. Before it, release follows the schedule and the paid-work peg alone. |
| `feature.burn_bound_release.boot_budget_bps` | 0 | 0 | 500 | down | Most the matched start of the burn-bound rule releases in all, bps of the genesis rewards pool. |
| `feature.burn_bound_release.boot_epochs` | 0 | 0 | 1000000 | down | Epochs after the burn-bound rule goes live over which the matched ratio falls to the ratio. |
| `feature.burn_bound_release.boot_ratio_bps` | 10000 | 10000 | 30000 | down | Matched ratio at the burn-bound rule's first epoch, bps of the epoch's own burn, falling in a straight line to the ratio over the matched epochs. It only lifts the epoch ceiling: a settlement still earns at most its own reward ceiling. 10000 or anything at or under the ratio is no matched start. |
| `feature.burn_bound_release.floor_pool_bps` | 200 | 0 | 10000 | up | Share of the genesis rewards pool, bps, under which the burn-bound rule releases nothing; validators' running cost is still paid from the fees kept. |
| `feature.burn_bound_release.operator_share_cap_bps` | 3333 | 1 | 10000 | down | Most one address takes of an epoch's release under the burn-bound rule, bps of the release its ceiling allows; the rest lapses and stays in the pool. |
| `feature.burn_bound_release.ratio_bps` | 10000 | 0 | 10000 | down | Most an epoch releases from the rewards pool under the burn-bound rule, bps of its burn budget (its burn and burn-equivalent). At most one times the burn, so a payer buying its own service burns more than the pool returns. |
| `feature.burn_bound_release.smoothing_keep_bps` | 0 | 0 | 9900 | neither | Share of the prior burn budget kept each epoch under the burn-bound rule, bps; the rest is the epoch's own burn. 0 makes the budget each epoch's own burn; 8571 keeps six sevenths. |
| `feature.burn_bound_release.step_pool_bps` | 1000 | 0 | 10000 | up | Share of the genesis rewards pool, bps, under which the burn-bound rule applies its step ratio instead of its ratio. |
| `feature.burn_bound_release.step_ratio_bps` | 5000 | 0 | 10000 | down | The burn-bound ratio once the pool is under the step, bps of the burn budget; a value above the ratio counts as the ratio. |
| `feature.burn_bound_release.yearly_pool_limit_bps` | 1000 | 1 | 10000 | down | Most one schedule year releases under the burn-bound rule, bps of the rewards pool left when the year began. |
| `feature.ccip_finality_policy.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks read the finality a CCIP 2.0 transfer asked for: one that waited for its sending chain's finality draws on its lane as before; any other is refused unless its route (or carried asset) has a finality policy that allows it, and then draws on that policy's own bucket. From this epoch on governance may set such a policy (SetBridgeFinalityPolicy); no route has one until it does. Until then the finality a message carries is not read and the proposal is refused. Dormant until a vote sets it. |
| `feature.challenge_windows_fit.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a change of the inference challenge commit window, its reveal window or the fault window is refused when the two committee windows together would exceed the fault window. |
| `feature.claim_placement.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept a placement rule on a bought claim: the buyer names countries, operators or both, the purchase is refused for a claim whose declared country or writer is outside it, and the held claim records the rule. |
| `feature.claim_placement.max_entries` | 16 | 1 | 64 | down | Most countries, and most operators, one placement rule on a bought claim may name. |
| `feature.committee_cap.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose committee holds at most consensus.max_committee_members validators, the highest stakes, a tie to the lower address: a certificate costs about 8.9 KB per signer and must fit one gossip message of a megabyte. Dormant until a vote sets it. |
| `feature.correlation_window_day.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose equivocation slashes correlate offences up to feature.correlation_window_day.checkpoints checkpoints apart (at least one day) in place of slashing.correlation_window_checkpoints. |
| `feature.correlation_window_day.checkpoints` | 172800 | 172800 | 10000000 | up | Once feature.correlation_window_day is live, the checkpoints the correlation window spans: at least one day of checkpoints at the 500 ms interval. |
| `feature.cover_funded_seats.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose closes fund only the validator seats paid usage carries: the cover reserve's fill target and epoch payout follow the stable fees booked since the last close over one validator's epoch cost, at least feature.cover_funded_seats.seat_floor, split equally over the active set. Dormant until a vote sets it. |
| `feature.cover_funded_seats.seat_floor` | 7 | 0 | 1000 | down | Fewest validator seats the cover reserve funds in an epoch once funded seats are in force, whatever paid usage carried. Lowering it is the tightening direction: a lower floor draws less from the reserve in thin epochs, so the reserve lasts. |
| `feature.custom_escrow_refused.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which CreateEscrow refuses a custom release condition (free text no validator can check) and no proof releases an escrow already under one, which its payer refunds; before it any non-empty proof releases one. |
| `feature.deferred_slash_removal.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a validator slashed for signing two checkpoints, its penalty already applied, keeps its seat while the active set without it would have fewer than four validators or, counting only the validators that signed in the last certified epoch as live, could not certify or would have no spare. It is jailed at the first epoch boundary where the set without it holds, and staking.inactivity_limit_epochs epochs after the slash regardless. Before this epoch a slashed validator is jailed at once. |
| `feature.erc7786_gateway.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks run the ERC-7786 gateway at 0x1012: an EVM contract sends a message over a governed bridge route with sendMessage, and a route that refuses it fails the transaction. Until then the address is an account with no code. Dormant until a vote sets it. |
| `feature.erc7786_gateway.delivery_gas` | 500000 | 50000 | 10000000 | down | Gas the ERC-7786 gateway gives a recipient contract's receiveMessage when a DeliverMessage operation delivers a message from a bridge route. The operation's sender pays for all of it, whatever the recipient uses. |
| `feature.erc7943_final.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks run the final ERC-7943 rules: a token's frozen amount may exceed the balance, the token factory and facades serve canSend and canReceive in place of canTransact under interface id 0x3edbb4c4, and a facade logs the standard Frozen, Transfer and ForcedTransfer events. Dormant until a vote sets it. |
| `feature.evm_conformance.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks run the EVM with the whole Prague precompile set and account removal: the BLS12-381 precompiles at 0x0b to 0x11 and KZG point evaluation at 0x0a are served, an account that destroys itself in the transaction that created it leaves no nonce, code or storage, and an error of the engine after a transaction ran fails it at its whole gas limit, and the EVM and SVM transactions of a block run only while they have used less than evm.block_gas_limit. Until then the BLS12-381 addresses are accounts with no code, a call to 0x0a fails its whole transaction, such an account keeps what it wrote, an engine error is charged as a transaction that never ran, and a block's gas is not limited. Dormant until a vote sets it. |
| `feature.evm_osaka.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks run the EVM under the Osaka rule set, on the engine of that rule set: the CLZ opcode, the P256VERIFY precompile at 0x100 at its Ethereum price, the MODEXP input bound and price, a transaction gas limit of at most 16,777,216, the BLS12-381 precompiles at 0x0b to 0x11 and KZG point evaluation at 0x0a, and an account destroyed in the transaction that created it leaves nothing behind. From this epoch on a node's pool admits no EVM transaction above that gas limit. Dormant until a vote sets it. |
| `feature.evm_prague_only.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks run the EVM under the Prague rule set alone. Until then a creation whose init code opens with the EOF magic is validated and deployed as an EOF container. A container deployed before this epoch is legacy code from it on: a call into it halts on its first byte and the code opcodes read its bytes whole, so it can no longer be used. Dormant until a vote sets it. |
| `feature.exit_hold.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose boundary holds a voluntary validator exit that would leave the seated set below the launch arithmetic, the exiting validator staying counted until the set can spare it. Raise it only after every validator runs a release that knows the rule. |
| `feature.external_payment_activity.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a payment made off the ledger and recorded on it (proven on its own chain or attested) counts in its epoch's settled value at its signed USD price, so paid demand read from activity includes it; before it such a payment records no activity. |
| `feature.fee_payer.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a native transaction whose memo carries another account's consent (prefix tenzro-fee-payer-1:, the payer's signature over the transaction body under its own context) has its fee paid by that account: the gas limit at the gas price is advanced from the payer before the transaction runs and what the gas did not use goes back. Before it such a memo is a plain memo and the sender pays. |
| `feature.firmware_tpm_tier.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a machine whose TPM its manufacturer certifies as firmware on the host processor (Intel PTT, AMD fTPM, Qualcomm) earns feature.firmware_tpm_tier.reward_bps of the availability reward, a tier below a discrete chip. |
| `feature.firmware_tpm_tier.reward_bps` | 5000 | 0 | 10000 | down | Share of the availability reward, bps, a machine on a firmware TPM earns once feature.firmware_tpm_tier is live; a discrete chip earns all of it. Genesis half. |
| `feature.first_registration_free.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks waive the fee of a registration (RegisterIdentity or a key enrolment) from an account that cannot pay it: at most two per account, and no more per epoch than feature.first_registration_free.waivers_per_epoch, counting every waived registration that executes, kept or reverted. Dormant until a vote sets it. |
| `feature.first_registration_free.waivers_per_epoch` | 16 | 0 | 1024 | down | How many registrations an epoch waives the fee of once feature.first_registration_free is live. A registration is kept only with the identity's own hardware or passkey proof; reverted attempts count too, so this bounds the free blockspace. 0 waives none. |
| `feature.heartbeat_session.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a serving node signs its provider heartbeats with a session key its machine identity certified once for at most an hour (and again each hour) instead of a hardware batch signature every few seconds, and every node accepts that form beside the batch form. Set it after every node runs a release that knows the form: a node that does not drops the heartbeat as unverifiable. |
| `feature.identity_caps.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks hold a root to feature.identity_caps.per_root delegated identities (the agents it delegated and the machines registered under its DID, revoked ones included): one more is refused. Dormant until a vote sets it. |
| `feature.identity_caps.per_root` | 64 | 1 | 1000000 | down | Most delegated identities (agents and machines under its DID, revoked ones included) one root may stand behind once identity caps are in force. |
| `feature.identity_keys.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept identity key changes (an identity's root recording its next Ed25519 and ML-DSA-65 key, declaring a key compromised or revoking a delegation) and keep one head per identity over the logs about it. Until then the transaction is refused and no head is written. Dormant until a vote sets it. |
| `feature.identity_required.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks refuse a transaction from an account with no registered identity (RegisterIdentity, key enrolment and protocol records stay open; a bonded validator is exempt). Dormant until a vote sets it. |
| `feature.identity_required.mode` | 0 | 0 | 2 | down | What the identity rule does once live, at execution and at every node's peer, mempool and edge admission: 0 enforce (refuse an account or peer with no registered identity), 1 audit (refuse nothing, log what enforce would refuse), 2 off. Relaxing applies at the next epoch, and a change to audit runs on the expedited track; returning to enforce waits out the tightening grace window. |
| `feature.idle_beacon.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch in which validators hold their beacon contributions while nobody uses the chain, sending one per idle interval. It binds what validators send; a block accepts the same contributions before and after. |
| `feature.idle_beacon.idle_interval_ms` | 1800000 | 60000 | 86400000 | neither | How old the beacon's latest value may grow, ms, while nobody uses the chain, before a validator contributes all the same. Read once the idle beacon rule is live. |
| `feature.native_call.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept NativeCall transactions: one kind that reaches, by selector, the native operations listed for it (an identity's key change, a root's revocation in favour of a successor, a builder's attestation), each also waiting for its own gate. Until then the kind is refused at submission and in blocks. Dormant until a vote sets it. |
| `feature.nras_jwks.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which governance may replace the JSON Web Key Set NVIDIA attestation tokens are verified under (`NrasJwksSet`), and from which a validator reads that set from chain state instead of a file of its own. Until then a proposal that names the set is refused. |
| `feature.one_operator.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks derive the root behind an identity one way everywhere a rule counts parties (funding limits, fee-weighted shares, distinct payers, a validator's operator, an aged human root): through the controllers its agent terms name, then the root its DID is derived under, a machine root named as a machine. Dormant until a vote sets it. |
| `feature.operator_weight_cap.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose committee every node stages so that the validators behind one root identity (a machine's controller, or the identity itself) hold at most consensus.operator_weight_max_bps of its seats, their stakes scaled down until they do. The cap binds roots, not people: validators under separate root identities count as separate operators. Dormant until a vote sets it. |
| `feature.paid_readiness.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose settlements record the hour a provider served a request paid by another root, which validators count as its readiness proof for that hour instead of probing it. Dormant until a vote sets it. |
| `feature.plan_treasury_line.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose settlement plans fix their treasury line at open: a plan whose remainder goes to a bonded provider records the treasury-leg rate of its work class then, and its commit takes that share of the provider's credit for the treasury. A later change of the rate does not reach a plan already open. Before it, a plan pays no treasury leg. |
| `feature.possession_probe.samples` | 8 | 1 | 24 | up | Chunks of each due object an SLA possession probe asks the provider to prove; a provider missing a share f of an object passes a probe with probability about (1-f)^samples. |
| `feature.probe_beacon.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which validators draw each SLA probe under the randomness beacon value in force, so a probe's challenge cannot be computed before that value exists, and a probed node answers no probe drawn without one; before it probes are drawn from epoch, round, issuer and subject alone. |
| `feature.provider_presence.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks let the owner of a compute bond say it stops or resumes serving, from the next hour, and give an hour it said it was offline, and owes to no held claim, no availability verdict: no penalty and no availability reward. Validators and storage stakes are always judged. Dormant until a vote sets it. |
| `feature.provider_revenue.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose settlements keep, for each payee paid for provider work, the value and count it was settled in its last two reward epochs, so every node reports the same provider revenue. Dormant until a vote sets it. |
| `feature.rate_symbol_isolation.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks judge each symbol of an opened rate report on its own: a symbol that fails its source count or quote checks is left out and the report's other symbols count. Before it, one failing symbol refuses the whole opening. Dormant until a vote sets it. |
| `feature.rbc_whole_member_fault_bound.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose reliable broadcast computes its thresholds from the most seats whole committee members within f = (n - 1) / 3 can hold, in place of f itself, so a committee of a few equal validators still delivers in two steps when one is silent. Dormant until a vote sets it. |
| `feature.recovery_cancel.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks let a recovery the recovery signers started be cancelled only by passkeys of the account holding two independent roots or by the signers at their threshold, and refuse a change of the recovery signers while such a recovery is pending. Until then any one passkey cancels a recovery. Dormant until a vote sets it. |
| `feature.recovery_rotation.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks complete a passkey account's recovery by replacing every passkey it held with the recovered one (policy back to one passkey), and whose keystore logs name the owner and the passkeys each change linked and retired. Until then a recovery adds its passkey beside the others. Dormant until a vote sets it. |
| `feature.region_weight_cap.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose committee every node stages so that the validators of approved operators that declared one region hold at most consensus.region_weight_max_bps of its seats, their stakes scaled down until they do, so losing any one region leaves a quorum. A region is what the operator declared at approval; a validator without one is held to no region. Dormant until a vote sets it. |
| `feature.registration_attestation.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks register a root only with hardware evidence the chain checks: an autonomous machine with a TPM quote by the attestation key its DID derives from, a human with a device-bound WebAuthn passkey attested to a governance-set root over a challenge naming the DID and key. Dormant until a vote sets it. |
| `feature.report_agreement.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a validator's rate report carries no rate for a symbol whose two middle quotes (an even number of sources) spread wider than fees.usd_rate_breaker_spread_bps; before it the lower middle quote is the report's rate. |
| `feature.reserve_no_volume_sale.max_tnzo_epoch` | 0 | 0 | 10000000 | down | The running-cost reserve's sale cap, whole TNZO an epoch, while no validator volume report is recent enough to size it; never above treasury.max_sale_tnzo_epoch. 0 pays nothing until a market reports volume. |
| `feature.reward_clawback.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a slash also returns the same share of the offender's reward still in vesting escrow to the rewards pool; before it vesting rewards are untouched by a slash. |
| `feature.reward_root.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose reward coupons go only to work whose root is a passkey-held human or an autonomous machine with a manufacturer-endorsed TPM; other work is left unmatched and its share stays in the pool. Dormant until a vote sets it; the vote waits until tenzro_getRewardEpoch shows reward_root.all_matched for every active validator. |
| `feature.role_availability_reward.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which an available verdict on an RPC, edge relay or storage role stake pays the availability reward against the owner's machine identity, as a validator's does; before it only validators and compute bonds can earn it. |
| `feature.role_stake_guard.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks check that the role-stake vault holds at least every role's bonded stake, and freeze role bonding, unbonding and withdrawal when it does not, until governance lifts the freeze. |
| `feature.root_pause.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks let a root (a human or an autonomous machine) pause every agent it delegated with one pause that names the root itself, sent from the wallet the root is registered with. The agents neither act nor pay on Tenzro until it ends; grants already issued on other chains run to their expiry. Dormant until a vote sets it. |
| `feature.root_revocation_reach.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks treat an identity derived under a revoked root (a machine the root registered) as revoked wherever a revoked identity is refused or its hardware is released. Dormant until a vote sets it. |
| `feature.root_signatures.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a node signs its jurisdiction receipts with its identity key at the version the chain records for it (one member of a batch whose root that key signed), when the chain records its key, and verifiers check such a receipt against the identity's key history. Until then receipts carry the hardware record signature only. Node behaviour: no block reads it. Dormant until a vote sets it. |
| `feature.root_signatures.max_gap_ms` | 60000 | 1000 | 3600000 | down | Milliseconds a verifier's chain view may lag its clock when it checks a record signed with an identity key, and the most a record's signing time may run ahead of that clock. A view older than this is refused rather than trusted to know of a key declared compromised. |
| `feature.root_vote_cap.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which feature.root_vote_cap.max_share_bps bounds what the ballots of one root's validators count together on a proposal; before it each validator's ballot counts its whole weight. |
| `feature.root_vote_cap.max_share_bps` | 10000 | 100 | 10000 | down | Most of a proposal's eligible stake, in basis points, the ballots of one root's validators count together once its feature gate is live; a ballot past it counts only what is left. |
| `feature.rpc_provider_approval.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a bridge committee seats only verifiers whose bond names an RPC provider governance has approved and not revoked; before it any provider label is accepted. |
| `feature.rpc_provider_leg.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept a payee naming the bonded validator it relies on, and pay that validator fees.rpc_provider_leg_bps of each TNZO settlement to a payee that holds no validator bond. Dormant until a vote sets it. |
| `feature.sealed_endpoint_pull.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a validator's endpoint announcement may name the committee members whose sealed endpoints it asks for, and a member named publishes them again. Dormant until a vote sets it. |
| `feature.settled_work_registered.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which ReportSettledWork counts a plan only when its payer and the payee reporting it are both registered identities of different roots; before it an account with no identity counts as a party of its own. |
| `feature.settlement_asset_payer_share.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks count what each payer settles in an asset and refuse a payment that would take it past its share of the asset's epoch inflow cap, so a higher fee, which orders a payment earlier, cannot take the whole of what is left. Dormant until a vote sets it. |
| `feature.settlement_asset_payer_share.share_bps` | 2500 | 1 | 10000 | down | Once the per-payer share rule is live, the most one payer may settle in an asset in an epoch, in basis points of the asset's epoch inflow cap. A lower share tightens the rule. |
| `feature.sla_burst.rounds_between` | 36 | 1 | 1000 | neither | Probe rounds between two burst challenges against each operator claiming more than one compute unit: every one of its units must answer a matrix proof in the same window. Sparse enough that the work stays a small share of challenge energy. Read only by a validator's own prober to pace its challenges; no consensus rule reads it. |
| `feature.sla_failure_window.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose unavailable SLA verdicts count toward a failure window: the verdict that brings a subject's count within feature.sla_failure_window.window_epochs to feature.sla_failure_window.max_failures takes feature.sla_failure_window.multiple times the flat penalty, and the count starts again. Dormant until a vote sets it. |
| `feature.sla_failure_window.max_failures` | 3 | 1 | 100 | down | Unavailable SLA verdicts within the window whose last takes the failure-window multiple. Read from feature.sla_failure_window.activation_epoch. |
| `feature.sla_failure_window.multiple` | 5 | 1 | 100 | up | Times the flat sla.unavailable.penalty_gwei the failure-window's triggering verdict takes. Read from feature.sla_failure_window.activation_epoch. |
| `feature.sla_failure_window.window_epochs` | 720 | 1 | 8784 | up | One-hour epochs an unavailable SLA verdict counts toward the failure-window multiple. Read from feature.sla_failure_window.activation_epoch. |
| `feature.sla_tiers.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which validators judge each readiness tier's SLA verdict against its own governed share (sla.<tier>_available_bps); before it every subject is available above half its probes. |
| `feature.sla_tiers.cold_available_bps` | 5000 | 0 | 9999 | up | Share of a validator's probes, bps, a Cold subject must answer more than for an available verdict, once feature.sla_tiers is live. Genesis more than half. |
| `feature.sla_tiers.cool_available_bps` | 5000 | 0 | 9999 | up | Share of a validator's probes, bps, a Cool subject must answer more than for an available verdict, once feature.sla_tiers is live. Genesis more than half. |
| `feature.sla_tiers.warm_available_bps` | 5000 | 0 | 9999 | up | Share of a validator's probes, bps, a Warm subject must answer more than for an available verdict, once feature.sla_tiers is live. Genesis more than half. |
| `feature.sla_wake_energy.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose SLA energy budget check and energy report charge a scheduled probe a liveness reply and a burst challenge the wake cost of the unit's declared readiness tier at that tier's burst cadence, against the tier's own idle energy. Before it every scheduled probe is charged a cool-tier wake against the cool-tier idle baseline. Dormant until a vote sets it. |
| `feature.sponsorship_usage_end.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which running-cost sponsorship (TNZO or stable) is refused while trailing paid usage carries the validator set: value settled between distinct registered roots over the last feature.sponsorship_usage_end.window_epochs closed reward epochs, at the fee rate in force, at or above feature.sponsorship_usage_end.paid_usage_usd_day_per_validator a day per validator. Dormant until a vote sets it. |
| `feature.sponsorship_usage_end.paid_usage_usd_day_per_validator` | 4300 | 0 | 1000000 | down | Paid usage a day, whole USD, per validator at which running-cost sponsorship ends once the usage trigger is in force; lowering it ends sponsorship sooner, which protects the treasury. |
| `feature.sponsorship_usage_end.window_epochs` | 90 | 7 | 365 | down | Closed reward epochs the trailing paid usage that ends running-cost sponsorship is counted over; a shorter window ends it sooner after usage rises. |
| `feature.stable_intake_exposure.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose settlements in a stable asset are refused when what the treasury keeps of the settlement fee and the treasury leg in that asset would lift it past the max_exposure_bps of the treasury its registry entry sets; the payer settles in another asset or in TNZO. Until then only payout swaps are held to the ceiling. Dormant until a vote sets it. |
| `feature.storage_classes.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks hold a storage claim to its class: an offer in stored_bytes names hot, warm or cold and prices inside that class's range, and validators count an object proven only when its possession proof arrives within the class deadline. Dormant until a vote sets it. |
| `feature.storage_classes.cold_deadline_ms` | 30000 | 5000 | 600000 | down | How long after a possession probe goes out the proof for a cold storage claim must reach the validator to count, ms. The probe window still binds when it is shorter. |
| `feature.storage_classes.cold_price_ceiling` | 10000000000000000000 | 1 | 10000000000000000000 | neither | Highest price of a cold storage claim, wei per gibibyte kept for an hour. |
| `feature.storage_classes.cold_price_floor` | 0 | 0 | 10000000000000000000 | neither | Lowest price of a cold storage claim, wei per gibibyte kept for an hour. |
| `feature.storage_classes.cold_read_price_ceiling` | 10000000000000000000 | 0 | 10000000000000000000 | down | Highest price a provider may charge to read a cold object, wei per gibibyte read. |
| `feature.storage_classes.hot_deadline_ms` | 10000 | 5000 | 600000 | down | How long after a possession probe goes out the proof for a hot storage claim must reach the validator to count, ms. The probe window still binds when it is shorter. |
| `feature.storage_classes.hot_price_ceiling` | 10000000000000000000 | 1 | 10000000000000000000 | neither | Highest price of a hot storage claim, wei per gibibyte kept for an hour. |
| `feature.storage_classes.hot_price_floor` | 0 | 0 | 10000000000000000000 | neither | Lowest price of a hot storage claim, wei per gibibyte kept for an hour. |
| `feature.storage_classes.hot_read_price_ceiling` | 10000000000000000000 | 0 | 10000000000000000000 | down | Highest price a provider may charge to read a hot object, wei per gibibyte read. |
| `feature.storage_classes.warm_deadline_ms` | 20000 | 5000 | 600000 | down | How long after a possession probe goes out the proof for a warm storage claim must reach the validator to count, ms. The probe window still binds when it is shorter. |
| `feature.storage_classes.warm_price_ceiling` | 10000000000000000000 | 1 | 10000000000000000000 | neither | Highest price of a warm storage claim, wei per gibibyte kept for an hour. |
| `feature.storage_classes.warm_price_floor` | 0 | 0 | 10000000000000000000 | neither | Lowest price of a warm storage claim, wei per gibibyte kept for an hour. |
| `feature.storage_classes.warm_read_price_ceiling` | 10000000000000000000 | 0 | 10000000000000000000 | down | Highest price a provider may charge to read a warm object, wei per gibibyte read. |
| `feature.unit_basket.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which ledger payments are valued in the fiat basket (feature.unit_basket.weight_*), scaled so the unit is worth one dollar at the switch; before it they are valued in the dollar. |
| `feature.unit_basket.weight_cny_bps` | 1228 | 0 | 10000 | neither | Weight of the renminbi (CNY) in the fiat basket payments are valued in once feature.unit_basket is live, bps of the weights' sum. A reweight takes effect at the next epoch start, scaled so nothing jumps. Genesis: the IMF SDR 2022 weight. |
| `feature.unit_basket.weight_eur_bps` | 2931 | 0 | 10000 | neither | Weight of the euro (EUR) in the fiat basket payments are valued in once feature.unit_basket is live, bps of the weights' sum. A reweight takes effect at the next epoch start, scaled so nothing jumps. Genesis: the IMF SDR 2022 weight. |
| `feature.unit_basket.weight_gbp_bps` | 744 | 0 | 10000 | neither | Weight of the pound (GBP) in the fiat basket payments are valued in once feature.unit_basket is live, bps of the weights' sum. A reweight takes effect at the next epoch start, scaled so nothing jumps. Genesis: the IMF SDR 2022 weight. |
| `feature.unit_basket.weight_jpy_bps` | 759 | 0 | 10000 | neither | Weight of the yen (JPY) in the fiat basket payments are valued in once feature.unit_basket is live, bps of the weights' sum. A reweight takes effect at the next epoch start, scaled so nothing jumps. Genesis: the IMF SDR 2022 weight. |
| `feature.unit_basket.weight_usd_bps` | 4338 | 0 | 10000 | neither | Weight of the dollar (USD) in the fiat basket payments are valued in once feature.unit_basket is live, bps of the weights' sum. A reweight takes effect at the next epoch start, scaled so nothing jumps. Genesis: the IMF SDR 2022 weight. |
| `feature.unit_budget.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose availability reward per verified unit is a share of a budget pinned to verified paid demand, split equally over the units the last closed hour verified and never above the decayed cap. Dormant until a vote sets it. |
| `feature.unit_budget.demand_bps` | 0 | 0 | 10000 | down | Share of verified paid demand per hour that budgets the availability reward once the unit budget is live, bps. Zero at genesis: the vote that activates the budget sets it. |
| `feature.update_notice_keys.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which governance may replace the release signing keys a signed update notice must verify under (`UpdateNoticeKeysSet`), and from which a node reads them from chain state. Until then a proposal that names the keys is refused. |
| `feature.upgrade_platforms.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept a protocol upgrade proposal that names a binary per platform (protocol_upgrade_platforms): readiness counts validators that quoted any named binary, and a node runs through the activation on any of them. Until then such a proposal is refused and an upgrade names one binary. Dormant until a vote sets it. |
| `feature.usd_compute_bond.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose new compute bonds must meet the minimum kept at its USD value at stake.bond_floor_rate_nano_usd, as role stakes do; bonds already posted keep serving at the TNZO minimum. Dormant until a vote sets it. |
| `feature.usd_sla_penalty.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose unavailable SLA verdicts take a penalty set in USD and never less than the hour's refund to the provider's claim holders. Dormant until a vote sets it. |
| `feature.usd_sla_penalty.micro_usd` | 0 | 0 | 10000000000000 | up | Micro-USD an unavailable SLA verdict takes once the USD penalty is live, converted at the fee rate; never less than the hour's refund. Zero at genesis: the vote that activates it sets it. |
| `feature.validator_exit_floor.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks refuse a validator's exit that would leave the seated validators below the launch arithmetic (at least the launch minimum of members, and more than two thirds of the stake left without the largest). Applies only to a chain whose genesis kept the index of seated validators. Dormant until a vote sets it. |
| `feature.validator_outside_stake_cap.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks refuse a validator bond that would take the stake of validators outside the genesis set past the governed share of the seated stake. Applies only to a chain whose genesis kept the index of seated validators. Dormant until a vote sets it. |
| `feature.validator_outside_stake_cap.cap_bps` | 2000 | 0 | 10000 | down | Once the outside-stake cap is live, the most stake validators outside the genesis set may hold, in basis points of the seated stake. Governance raises it in published steps; a lower value tightens the rule. |
| `feature.validator_stake_weight.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch from which a validator's consensus work is weighted by its bonded stake when an epoch closes; before it each vote and block counts the same whoever bonded what. |
| `feature.zk_verdict.activation_epoch` | 4611686018427387904 | 0 | 4611686018427387904 | neither | First epoch whose blocks accept ZK verdicts: a bonded validator states that a proof it received directly and verified outside the block verifies, and the proof is recorded where the ZK_VERIFY precompile reads it once validators holding two thirds of the bonded stake stated the same verdict. Once in force, nodes refuse AttestZkProof at submission. Dormant until a vote sets it. |
| `fees.activity_reward_fee_bps` | 5000 | 0 | 9000 | neither | Most one settlement earns in ecosystem activity rewards, in basis points of the settlement fee it paid, shared by the apps, agents and tools its payer attributed it to. With mint.provider_reward_cost_bps and fees.creator_royalty_fee_bps it may add up to at most 9000, below the whole fee, so trading with oneself never pays. |
| `fees.bandwidth_target_per_block` | 2500000 | 1 | 18446744073709551615 | neither | Gas worth of transaction bytes a block targets; the bandwidth base fee follows its own use against it. |
| `fees.base_fee_change_denominator` | 8 | 2 | 1024 | neither | The base fee moves at most 1/this per block (8: 12.5%). |
| `fees.burn_debt_cap_epochs` | 24 | 0 | 168 | neither | Most burn debt carried from epoch to epoch, in epochs of scheduled pool release. Fees collected in other assets burn by withholding pool release; what the release cannot cover is carried up to this cap, and past it the treasury burns TNZO. |
| `fees.compute_target_gas_per_block` | 15000000 | 1000000 | 1000000000 | neither | Compute gas a block targets. The base fee rises when blocks use more and falls when they use less. |
| `fees.creator_royalty_fee_bps` | 0 | 0 | 9000 | neither | Royalty one settlement pays the apps, agents and tools its payer attributed it to, in basis points of its settlement fee, out of the fee's treasury part, so the payer pays no more. With mint.provider_reward_cost_bps and fees.activity_reward_fee_bps it may add up to at most 9000. |
| `fees.http402_network_share_bps` | 1000 | 0 | 5000 | up | Share of an HTTP-402 payment settled off chain (delivery-versus-payment and fiat rails) offered to the network treasury, bps of the amount after the developer margin. |
| `fees.identity_register_micro_usd` | 10000 | 0 | 100000000 | neither | USD price of registering an identity, in micro-USD, paid in TNZO at the rate in force and burned. |
| `fees.inference_settle_micro_usd` | 100 | 0 | 100000000 | neither | USD price of one inference or compute stream settlement, in micro-USD, paid by the claiming provider in TNZO at the rate in force and burned. |
| `fees.insurance_pool_bps` | 1000 | 0 | 10000 | up | Share of the fee revenue bound for the treasury (block fees and settlement fees) credited to the insurance pool instead. |
| `fees.max_base_fee` | 1000000000000 | 1000000000 | 18446744073709551615 | neither | Highest base fee, atto-USD per unit of gas or resource. Read as the floor if set below it. |
| `fees.max_developer_margin_bps` | 2000 | 0 | 10000 | neither | Most a developer may add on top of a network cost as its own margin on an HTTP-402 payment, bps. |
| `fees.min_base_fee` | 100000000 | 1 | 1000000000000 | up | Lowest base fee, atto-USD per unit of gas or resource. |
| `fees.min_settlement_fee_micro_usd` | 1 | 0 | 1000000 | up | The least fee one settlement pays, in micro-USD at the live rate, charged once per settlement and never above the value settled. |
| `fees.onramp_spread_bps` | 100 | 0 | 2000 | up | Share of a bond purchase's value the treasury keeps, bps: the TNZO paid into the bond is the stable's value at the higher of the rate in force and the safety rate, less this. |
| `fees.payout_swap_carry_epochs` | 24 | 1 | 720 | neither | Epochs the unfilled part of a payout swap request is carried into later epochs' pro-rata fills before it is paid to the payee in the asset it arrived in. |
| `fees.payout_swap_max_units_epoch` | 100000 | 0 | 100000000 | down | Most value swapped from the treasury's stable holdings for payouts in one epoch, whole units of account. Requests are collected through the epoch and the cap is shared pro-rata by value when it closes, so a request's place in the epoch changes nothing. |
| `fees.payout_swap_spread_bps` | 15 | 0 | 100 | up | Spread the treasury keeps on a payout swap, bps, taken from the lower of the par amount and the amount at the two validator rates. |
| `fees.proof_target_per_block` | 2500000 | 1 | 18446744073709551615 | neither | Gas of proof verification a block targets; the proof base fee follows its own use against it. |
| `fees.relay_reimburse_max_bps` | 10000 | 0 | 10000 | neither | Most of the treasury's share of a fee collected in kind a relayer is reimbursed for the gas it fronted, bps; never more than the gas at the rates in force. |
| `fees.rpc_provider_leg_bps` | 1000 | 0 | 2000 | down | Share of what a TNZO settlement leaves a non-validating payee after the settlement fee and the treasury leg that is paid to the validator it named, bps, once the RPC-provider leg is in force. |
| `fees.safety_rate_window_epochs` | 24 | 1 | 168 | neither | Epochs of frozen medians the safety rate looks back over. Safety checks (the security ratio, the stake-backed bridge caps, the USD floor on bonds) value TNZO at the lower of the rate in force and the lowest median in this window; payments keep the rate in force. |
| `fees.settlement_fee_bps` | 10 | 0 | 1000 | up | Settlement fee, in basis points of the value each on-chain settlement pays out, divided between burn and treasury by fees.settlement_fee_burn_bps. |
| `fees.settlement_fee_burn_bps` | 5000 | 0 | 10000 | neither | Share of the settlement fee burned, in basis points; the rest goes to the treasury. |
| `fees.state_growth_target_per_block` | 2500000 | 1 | 18446744073709551615 | neither | Gas worth of new state entries a block targets. Above it the state-growth base fee rises, below it falls, independently of compute. |
| `fees.tnzo_usd_nano` | 100000000 | 1 | 1000000000000000 | neither | The TNZO/USD rate in governance mode, in nano-USD per TNZO. Validator mode starts from it. |
| `fees.treasury_burn_max_tnzo_epoch` | 10000 | 0 | 10000000 | neither | Most TNZO the treasury burns in one epoch for burn debt past its cap, whole TNZO; never more than treasury.max_sale_tnzo_epoch. Debt past both caps is written off and recorded on the epoch's netting record. |
| `fees.treasury_leg_compute_bps` | 0 | 0 | 5000 | up | Treasury leg of a compute lease payment settled on chain to a provider whose bond or stake makes it that class of work, in basis points of what the provider is credited after the settlement fee. It is paid outside the trade, so it counts with the fee toward what the settlement may earn. |
| `fees.treasury_leg_inference_bps` | 0 | 0 | 5000 | up | Treasury leg of an inference payment settled on chain to a provider whose bond or stake makes it that class of work, in basis points of what the provider is credited after the settlement fee. It is paid outside the trade, so it counts with the fee toward what the settlement may earn. |
| `fees.treasury_leg_rpc_bps` | 0 | 0 | 5000 | up | Treasury leg of an RPC traffic payment settled on chain to a provider whose bond or stake makes it that class of work, in basis points of what the provider is credited after the settlement fee. It is paid outside the trade, so it counts with the fee toward what the settlement may earn. |
| `fees.treasury_leg_storage_bps` | 0 | 0 | 5000 | up | Treasury leg of a storage payment settled on chain to a provider whose bond or stake makes it that class of work, in basis points of what the provider is credited after the settlement fee. It is paid outside the trade, so it counts with the fee toward what the settlement may earn. |
| `fees.treasury_leg_tee_bps` | 0 | 0 | 5000 | up | Treasury leg of a TEE session payment settled on chain to a provider whose bond or stake makes it that class of work, in basis points of what the provider is credited after the settlement fee. It is paid outside the trade, so it counts with the fee toward what the settlement may earn. |
| `fees.usd_rate_breaker_epochs` | 3 | 1 | 24 | down | Tallied epochs in a row whose reports breach the dispersion spread or the governance-rate gap before the TNZO rate falls back to the governance rate. It stays there until governance sets fees.usd_rate_mode to 1 again. |
| `fees.usd_rate_breaker_gap_bps` | 5000 | 500 | 50000 | down | Widest gap between an epoch's TNZO median and the governance rate, in basis points of the governance rate, before that epoch holds the rate and counts toward the dispersion breaker. |
| `fees.usd_rate_breaker_spread_bps` | 500 | 50 | 5000 | down | Widest spread between the low and high stake-weighted quantiles of an epoch's rate reports, in basis points of the low quantile, before that epoch holds the rate instead of moving it and counts toward the dispersion breaker. Once feature.report_agreement.activation_epoch is live, also the widest spread between the two middle quotes of a report with an even number of sources, in basis points of the lower, before that report carries no rate for the symbol. |
| `fees.usd_rate_frozen` | 0 | 0 | 1 | neither | 1 holds the validator-reported rate where it is while a challenge or a lost quorum is decided; medians are still recorded. Fees go on at the held rate. |
| `fees.usd_rate_max_age_epochs` | 24 | 1 | 8760 | neither | Epochs the validator-reported rate may go without a newer frozen median before it is reported as held. Fees go on at the last good rate while it is held; it never moves on its own. |
| `fees.usd_rate_max_change_bps` | 100 | 1 | 10000 | neither | Most the validator-reported rate may rise in one hourly epoch, in basis points of the rate in force. |
| `fees.usd_rate_max_fall_bps` | 500 | 100 | 2000 | neither | Most the validator-reported rate may fall in one hourly epoch, in basis points of the rate in force. Above the rise cap, so a crash is followed within days, not weeks. |
| `fees.usd_rate_min_sources` | 2 | 2 | 16 | up | Fewest independent sources a validator's rate report must quote for each symbol. A report quoting fewer is refused when opened, and an opened report below the value in force at the tally is not counted, so no single venue sets a report. |
| `fees.usd_rate_mode` | 0 | 0 | 1 | neither | Where the TNZO/USD rate that prices fees comes from: 0 the governance-set rate, 1 the stake-weighted median of the rates bonded validators report each epoch. |
| `fees.usd_rate_quantile_high_bps` | 6666 | 5000 | 10000 | neither | High stake-weighted quantile of an epoch's opened rate reports, in basis points; the top of the band the rate may move into. |
| `fees.usd_rate_quantile_low_bps` | 3334 | 0 | 5000 | neither | Low stake-weighted quantile of an epoch's opened rate reports, in basis points: the rate moves only into the band between it and the high quantile, so reporters below this share of stake can hold the rate but not move it. |
| `fees.usd_rate_quorum_bps` | 6666 | 5001 | 10000 | neither | Share of bonded stake, in basis points, that must open its sealed rates for an epoch before that epoch's median moves the rate. |
| `fees.usd_rate_stale_epochs` | 6 | 1 | 720 | neither | Epochs in a row short of the quorum, with at least the staleness quorum still reporting, that the rate in force may sit further than the staleness gap from their median before it moves toward that median at the per-epoch bound. |
| `fees.usd_rate_stale_gap_bps` | 300 | 1 | 10000 | neither | Gap between the rate in force and an epoch's median, in basis points of the median, that counts the epoch as stale. |
| `fees.usd_rate_stale_quorum_bps` | 5001 | 5001 | 10000 | neither | Share of bonded stake, in basis points, that must open its rates for an epoch short of the quorum to count toward staleness and to move a stale rate toward its median; never less than a majority. |
| `fees.usd_rate_unopened_slash_bps` | 10 | 1 | 500 | up | Share of its validator bond, in basis points, a validator forfeits to the insurance pool for each epoch it sealed rates for and never opened, so sealing a report and withholding it when it turns out unwelcome costs stake. |
| `fees.validator_burn_share_bps` | 2500 | 0 | 10000 | neither | Share of each epoch's burned fees, in basis points, that funds validators' base rewards, drawn from the rewards pool on top of the validator share. |
| `fees.verify_micro_usd` | 1000 | 0 | 100000000 | neither | USD price of one verification (a proof attestation), in micro-USD, paid in TNZO at the rate in force and burned. |
| `funding.request_window_ms` | 86400000 | 60000 | 2592000000 | neither | Length of the funding-request cap window, in milliseconds. |
| `funding.requests_per_window` | 64 | 1 | 100000 | down | Most funding requests the network accepts per request window, network-wide. Requests are filed without a balance, so this bounds what they cost the treasury. |
| `gossip.ban_seconds` | 300 | 10 | 86400 | up | Seconds a gossip neighbour is refused after its invalid messages brought its score to the ban threshold. |
| `gossip.consensus_messages_per_window` | 20000 | 1000 | 10000000 | down | Messages one gossip neighbour may deliver per window on the topics consensus and sync depend on: certificates, blocks, validator endpoints and peer status. Kept apart from transactions so user load never delays them. Messages over it are dropped without penalty. |
| `gossip.general_messages_per_window` | 50000 | 100 | 10000000 | down | Messages one gossip neighbour may deliver per window on every other topic, transactions included. Messages over it are dropped without penalty; only invalid messages cost a neighbour its standing. |
| `gossip.rate_window_ms` | 10000 | 1000 | 600000 | neither | Window, in milliseconds, over which each gossip neighbour's message budgets are counted. |
| `governance.agent_phase` | 0 | 0 | 2 | neither | How far agents are trusted to originate proposals: 0 none, 1 network only, 2 all. Advancing this is itself a governed decision. |
| `governance.agent_weight_max_bps` | 500 | 0 | 10000 | neither | Most of the eligible stake one agent-cast ballot may weigh; the rest of the validator's weight abstains. |
| `governance.concern_quorum` | 100 | 1 | 1000000 | neither | Distinct aged human roots whose concerns, once exceeded, double a queued proposal's timelock (once only). |
| `governance.expedited_threshold_bps` | 8000 | 6667 | 9500 | neither | Share of participating stake that must vote yes on the expedited and security-fix tracks, bps; never below the standard threshold. |
| `governance.expedited_timelock_ms` | 14400000 | 3600000 | 259200000 | neither | Timelock on the expedited and security-fix tracks, ms. |
| `governance.expedited_voting_period_ms` | 21600000 | 3600000 | 259200000 | neither | Voting window on the expedited and security-fix tracks, ms. |
| `governance.feature_pause_cooloff_epochs` | 168 | 0 | 4380 | neither | Epochs after a guardian pause of one feature lifts before guardians may pause the same feature again. |
| `governance.feature_pause_max_epochs` | 72 | 1 | 720 | neither | Longest a guardian pause of one feature (a status lever) holds before it lifts by itself. Guardians stop a running feature and nothing else. |
| `governance.guard_loosening_grace_epochs` | 2160 | 24 | 8760 | neither | Epochs a change that loosens a capture guard waits after the next epoch boundary before it applies: a treasury guard (an outflow cap or period, the large-spend size, approval or timelock, a running-cost reserve limit, an insurance claim cap, the bond age, the raise bound or this grace), the vote's quorum and thresholds, pool release and validator pay, slashing and unbonding, and the fee rate's move cap and quorum. |
| `governance.guardian_max_term_ms` | 31536000000 | 86400000 | 63072000000 | neither | Longest term a guardian seat may be granted for. |
| `governance.guardian_signal_window_ms` | 3600000 | 60000 | 604800000 | neither | How long a guardian's pause or resume signal counts toward the threshold. |
| `governance.guardian_threshold` | 2 | 1 | 15 | neither | Distinct seated guardians of a role whose signals it takes to veto a proposal or to pause or resume enactment. |
| `governance.large_spend_approval_bps` | 7500 | 5001 | 10000 | up | Yes votes any payment out of the treasury or its running-cost reserve, and any change that loosens a capture guard (an economic safety bound), needs, bps of all stake eligible when it opened rather than of the stake that voted. |
| `governance.large_spend_timelock_ms` | 1209600000 | 86400000 | 7776000000 | up | Least timelock of a large spend, ms. |
| `governance.large_spend_tnzo` | 100000 | 1 | 18446744073709551615 | down | Whole TNZO from which a payment out of the treasury or its running-cost reserve is a large spend and waits the large-spend timelock. |
| `governance.max_cap_raise_bps` | 20000 | 10000 | 100000 | neither | The most one enacted proposal may raise a bridge cap or loosen an exit limit to, in bps of its value before (10 000 keeps it). Applies to this parameter too. |
| `governance.max_pause_ms` | 259200000 | 60000 | 2592000000 | neither | Longest a guardian pause holds enactment before it lifts by itself. |
| `governance.min_bond_age_ms` | 604800000 | 0 | 7776000000 | up | Milliseconds stake must have been bonded before a proposal opened to weigh in its vote; stake bonded later counts for nothing on that proposal. |
| `governance.pause_cooloff_ms` | 604800000 | 0 | 2592000000 | neither | Time after a pause ends before guardians may pause again. |
| `governance.proposal_threshold_bps` | 100 | 0 | 1000 | up | Share of all bonded stake a proposer must hold to open a proposal, bps. |
| `governance.quorum_bps` | 3334 | 2000 | 6667 | neither | Share of all bonded stake that must take part in a vote, bps. |
| `governance.ratify_threshold_bps` | 7500 | 6667 | 9500 | neither | Share of participating stake that must vote yes on the Ratify track, bps; never below the standard threshold. |
| `governance.ratify_timelock_ms` | 2592000000 | 604800000 | 15552000000 | neither | Timelock of a proposal re-passed on the Ratify track, ms, so holders who contested it can leave before it applies. |
| `governance.release_floor` | 2002 | 2002 | 999999999 | neither | Newest release whose governed keys and bounds a parameter change may use, as major * 1,000,000 + minor * 1,000 + patch. Raise it only once every validator runs that release: a node that does not know a key refuses the change and parts from the chain. |
| `governance.root_min_age_ms` | 2592000000 | 0 | 31536000000 | neither | How long before a proposal opened a human root must have been registered for its concern to count. |
| `governance.security_reveal_slash_bps` | 1000 | 1 | 10000 | up | Share of a proposer's stake, in basis points, slashed when a security fix's vulnerability is not revealed in time. |
| `governance.security_reveal_window_ms` | 2592000000 | 86400000 | 15552000000 | neither | How long after a security fix enacts its proposer has to reveal the vulnerability it committed to. |
| `governance.steward_max_seats` | 5 | 0 | 15 | neither | Most live Foundation steward seats; governance may only lower it. |
| `governance.steward_sunset_ms` | 0 | 0 | 4102444800000 | neither | Block time after which Foundation steward seats hold no power; governance may only move it earlier. |
| `governance.threshold_bps` | 6667 | 5001 | 9000 | neither | Share of participating stake that must vote yes on the standard track, bps. |
| `governance.tightening_grace_epochs` | 168 | 0 | 2160 | down | Epochs a tightening parameter change (a higher bond, slash or fee, or a shorter window) waits after the next epoch boundary before it applies. At most 90 days. |
| `governance.timelock_ms` | 172800000 | 14400000 | 2592000000 | neither | How long a passed standard proposal waits before it may execute, ms: the window in which guardians and holders can still respond. |
| `governance.voting_period_ms` | 259200000 | 86400000 | 2592000000 | neither | Voting window on the standard and Ratify tracks, ms. A proposal keeps the rules it opened under. |
| `grants.per_grantee_yearly_max_tnzo` | 0 | 0 | 1000000000 | down | Most treasury TNZO one approved grantee may be paid in a 365-day period, whole TNZO, whoever the grantee is. 0 disables grants. |
| `grants.per_grantee_yearly_max_usd` | 0 | 0 | 1000000000 | down | Most one approved grantee may be paid in a stable asset in a 365-day period, whole US dollars. 0 disables stable grants. |
| `hardware.level1_bonus_bps` | 100 | 0 | 1000 | neither | Bonus on a provider's base reward share for hardware level 1 (a manufacturer-certified TPM the chain verified), in basis points, at most hardware.level_bonus_cap_bps. Paid on top of base shares, never out of them; at most hardware.level2_bonus_bps. |
| `hardware.level2_bonus_bps` | 200 | 0 | 1000 | neither | Bonus for hardware level 2 (level 1 plus a hardware-held ML-DSA key proven on chain), in basis points, at most hardware.level_bonus_cap_bps; between hardware.level1_bonus_bps and hardware.level3_bonus_bps. |
| `hardware.level3_bonus_bps` | 300 | 0 | 1000 | neither | Bonus for hardware level 3 (a hardware post-quantum attestation key, or a second hardware scheme, proven on chain), in basis points, at most hardware.level_bonus_cap_bps; at least hardware.level2_bonus_bps. |
| `hardware.level_bonus_cap_bps` | 300 | 0 | 1000 | neither | Most hardware-level bonus any provider earns, in basis points of its base reward share; 0 turns the bonus off. A level never admits or excludes anyone. With mint.provider_reward_cost_bps raised by it, fees.activity_reward_fee_bps and fees.creator_royalty_fee_bps may add up to at most 9500, so the bonus never makes trading with oneself pay. |
| `heartbeat.max_skew_ms` | 60000 | 1000 | 300000 | down | How far a provider heartbeat's timestamp may be from the receiving node's clock, in milliseconds, before the node drops it. Lowering it tightens the rule. |
| `heartbeat.session_issue_skew_ms` | 60000 | 1000 | 300000 | down | How far past a node's own clock a heartbeat session certificate's issue time may be, in milliseconds. Lowering it tightens the rule. |
| `heartbeat.session_max_lifetime_ms` | 3600000 | 60000 | 86400000 | down | The longest a heartbeat session certificate may be valid, in milliseconds, from the moment it was issued. A node refuses a session-signed heartbeat whose certificate is valid for longer. Lowering it tightens the rule. |
| `inference.challenge_commit_window_secs` | 3600 | 60 | 604800 | down | Seconds an inference challenge's committee has to commit its votes after the challenge is filed. |
| `inference.challenge_reveal_window_secs` | 3600 | 60 | 604800 | down | Seconds an inference challenge's committee has to reveal its votes after the commit window. |
| `inference.optimistic.max_refund_gwei` | 100000000000 | 0 | 18446744073709551615 | neither | Largest refund (gwei of TNZO) one inference fault may claim. |
| `inference.optimistic.penalty_floor_micro_usd` | 100000 | 0 | 1000000000000 | up | Least penalty (micro-USD, paid in TNZO at the rate in force) a provider's bond pays to the insurance pool for an upheld inference fault, on top of the refund. |
| `inference.optimistic.penalty_payment_bps` | 200000 | 10000 | 100000000 | up | Penalty a provider's bond pays to the insurance pool for an upheld inference fault, in basis points of what the requester paid, when above the floor. Held at or above 10^8 / inference.optimistic.sample_bps, so the expected penalty of a substituted answer is at least what it was paid. |
| `inference.optimistic.sample_bps` | 500 | 1 | 10000 | up | Least share (bps) of optimistic-level answers a requester's node re-executes on another provider serving the same model; never zero. |
| `inference.optimistic.sample_escrow_step_gwei` | 1000000000 | 1 | 18446744073709551615 | down | Payment, gwei, for each multiple of which an optimistic answer's re-execution share rises by the sample step. |
| `inference.optimistic.sample_step_bps` | 1000 | 0 | 10000 | up | Bps added to an optimistic answer's re-execution share for each sample escrow step its payment holds. |
| `inference.optimistic.window_ms` | 86400000 | 60000 | 2592000000 | neither | Challenge window (ms): a fault must be filed this soon after the receipt was signed, and decided this soon after it was filed. |
| `inference.verification.commitment_logit_delta_milli` | 600 | 0 | 10000 | neither | Largest mean absolute top-k logit difference (thousandths) a re-executed step of an inference commitment may show and still pass. |
| `inference.verification.commitment_passing_bps` | 9000 | 5000 | 10000 | neither | Least share (bps) of an inference commitment's steps that must pass on re-execution for it to verify, counting the tolerated misses as passing. |
| `inference.verification.commitment_tolerated_misses` | 2 | 0 | 64 | neither | Failing steps an inference commitment may carry beyond the passing share while more of its steps pass than fail, so a short honest answer survives a rounding miss. |
| `inference.verification.optimistic.status` | 0 | 0 | 2 | retire | Whether inference at the optimistic verification level is routed and served: 0 enabled, 1 paused, 2 retired. Faults on answers already served stay fileable. |
| `inference.verification.optimistic_bps` | 1000 | 0 | 10000 | up | Surcharge (bps of the base price) for an answer at the optimistic verification level, which pays for sampled re-execution. |
| `inference.verification.receipt.status` | 0 | 0 | 2 | retire | Whether inference at the receipt verification level is routed and served: 0 enabled, 1 paused (requests at the level are refused), 2 retired for good. |
| `inference.verification.receipt_bps` | 0 | 0 | 10000 | up | Surcharge (bps of the base price) for an answer at the receipt verification level. |
| `inference.verification.tee.status` | 0 | 0 | 2 | retire | Whether inference at the TEE verification level is routed and served: 0 enabled, 1 paused, 2 retired. |
| `inference.verification.tee_bps` | 2000 | 0 | 10000 | up | Surcharge (bps of the base price) for an answer at the TEE verification level. |
| `insurance.cover_target_units` | 1000000 | 0 | 1000000000000 | neither | Value the insurance pool is meant to cover, whole units of account. Each epoch boundary publishes the pool's value, its TNZO at the safety rate, against it as the coverage ratio; 0 publishes no ratio. |
| `insurance.max_claim_bps` | 1000 | 1 | 10000 | neither | Most of the insurance pool one claim may take. |
| `insurance.max_claim_tnzo` | 10000 | 1 | 1000000000 | neither | Most one insurance claim may take, in whole TNZO. |
| `insurance.max_paid_tnzo_epoch` | 30000 | 0 | 1000000000 | down | Most all insurance claims pay in one epoch, whole TNZO, whatever the rate their USD losses were priced at. |
| `keystore.add_device_wait_ms` | 172800000 | 3600000 | 2592000000 | up | How long a passkey added to an account with fewer than two independent roots waits before it counts as one, ms; any other passkey can remove it meanwhile. |
| `keystore.recovery.code.status` | 0 | 0 | 2 | retire | Whether accounts may set, claim and use a one-time recovery code: 0 enabled, 1 paused (a recovery started with a code cannot finish), 2 retired. |
| `keystore.recovery.device.status` | 0 | 0 | 2 | retire | Whether another device may be set as a recovery signer and its approval counts: 0 enabled, 1 paused (a recovery it approved cannot finish), 2 retired. |
| `keystore.recovery.email_verifier.status` | 0 | 0 | 2 | retire | Whether an email verifier may be set as a recovery signer and its approval counts: 0 enabled, 1 paused (a recovery it approved cannot finish), 2 retired. |
| `keystore.recovery.recovery_key.status` | 0 | 0 | 2 | retire | Whether a recovery key may be set as a recovery signer and its approval counts: 0 enabled, 1 paused (a recovery it approved cannot finish), 2 retired. |
| `keystore.recovery_code_claim_ttl_ms` | 86400000 | 600000 | 604800000 | neither | Age at which a recovery code claim expires unrevealed, ms. |
| `keystore.recovery_code_reveal_delay_ms` | 60000 | 5000 | 3600000 | neither | Least age of a recovery code claim before the code may be revealed, ms: long enough that a claim made after seeing a revealed code is too late. |
| `keystore.recovery_code_wait_ms` | 604800000 | 86400000 | 7776000000 | up | How long a recovery started with an account's one-time recovery code waits before it completes, ms; any linked passkey can cancel it meanwhile. |
| `keystore.recovery_wait_key_and_email_ms` | 3600000 | 600000 | 604800000 | up | How long a recovery approved by a recovery key and an email verifier waits before it completes, ms; any linked passkey can cancel it meanwhile. |
| `keystore.recovery_wait_key_ms` | 172800000 | 3600000 | 2592000000 | up | How long a recovery approved by a recovery key, without an email verifier, waits before it completes, ms. |
| `keystore.recovery_wait_other_ms` | 604800000 | 86400000 | 7776000000 | up | How long any other recovery waits before it completes, ms: the longest wait. |
| `metering.dispute_penalty_multiple` | 2 | 1 | 100 | up | Multiple of a disputed record's ceiling a proven dispute takes from the meter bond, capped by what the bond holds. |
| `metering.dispute_window_ms` | 259200000 | 3600000 | 2592000000 | down | Milliseconds after a metered record is measured that its payer may dispute it; a meter bond stays slashable this long after its owner asks to withdraw. |
| `mint.adj_bps_per_year` | 2500 | 0 | 10000 | neither | Most the pool release controller moves its multiplier in a year, in basis points of 1x. |
| `mint.base_tnzo_per_year` | 60000000 | 0 | 400000000 | neither | TNZO released from the genesis-funded network-rewards pool in schedule year 0, in whole TNZO. Never priced in fiat. The `mint.` keys name pool releases: no TNZO is minted, and releases stop when the pool is empty. |
| `mint.decay_bps_per_year` | 1500 | 0 | 10000 | neither | Share of a year's pool release dropped the following year, in basis points. |
| `mint.ecosystem_share_bps` | 1500 | 0 | 10000 | neither | Apps' share of each epoch's pool release, paid by the fees their users paid, in basis points of the three shares' sum. |
| `mint.floor_tnzo_per_year` | 10000000 | 0 | 400000000 | neither | Least yearly pool release, in whole TNZO, while the pool lasts. |
| `mint.max_mult_bps` | 10000 | 0 | 100000 | neither | Greatest pool release controller multiplier, in basis points of 1x. |
| `mint.min_mult_bps` | 5000 | 0 | 100000 | neither | Least pool release controller multiplier, in basis points of 1x. |
| `mint.provider_reward_cost_bps` | 4000 | 0 | 9000 | neither | Most provider reward weight one settlement earns, in basis points of the protocol fee it paid outside the trade. With fees.activity_reward_fee_bps and fees.creator_royalty_fee_bps it may add up to at most 9000, so a buyer, provider and app acting together never earn back what a settlement cost them. |
| `mint.provider_share_bps` | 4000 | 0 | 10000 | neither | Providers' share of each epoch's pool release, paid by verified served revenue, in basis points of the three shares' sum. |
| `mint.revenue_peg_bps` | 10000 | 0 | 10000 | neither | Cap on what the provider and app shares pay in an epoch, in basis points of the work weight their settlements recorded (each settlement's own reward ceiling); the rest stays in the pool. |
| `mint.validator_share_bps` | 4500 | 0 | 10000 | neither | Validators' share of each epoch's pool release, in basis points of the three shares' sum. |
| `payments.attested_cap_usd_e6` | 10000000000 | 1000000 | 1000000000000 | neither | Most one attested payment may be worth, USD micro-units. |
| `payments.attested_enabled` | 1 | 0 | 1 | neither | Whether payments attested on rails outside any chain are recorded. They are labelled attested and never count as proven. |
| `payments.max_reseller_legs` | 4 | 0 | 16 | down | Most reseller legs one payment carries, each a commission the payer signed on top of the operator's price; zero refuses resold payments. |
| `payments.voucher_freshness_ms` | 60000 | 1000 | 600000 | down | How far ahead of block time a serving node may date an agent's voucher. Zero would refuse every voucher signed on a clock slightly ahead of the chain. |
| `records.max_record_age_ms` | 3600000 | 60000 | 2592000000 | neither | Milliseconds before a block within which the date of a signed record and the date of the batch root that signs it must fall. The signing node supplies those dates, so consensus bounds them against block time; together with the ML-DSA requirement being judged at block time, a classical-only signer cannot backdate a record to before the moment the requirement starts. |
| `records.pq_leg_required_from_ms` | 18446744073709551615 | 0 | 18446744073709551615 | neither | Milliseconds since the Unix epoch from which a machine identity key must carry a native ML-DSA-65 leg: a node without one then refuses to start and a batch root signed from then on needs both legs. Before it, classical-only roots are accepted. The highest value means never; a network whose validators hold ML-DSA-capable hardware sets it to zero in its genesis. |
| `registry.bond_tnzo` | 10 | 0 | 1000000 | up | Bond the first put of a registry id locks while the entry stands, whole TNZO; returned when its owner retires it, forfeited to the insurance pool when governance does. |
| `registry.conformance_max_digests` | 64 | 1 | 512 | down | Most standard bundle digests one registry conformance entry lists. |
| `registry.max_data_bytes` | 16384 | 256 | 1048576 | down | Most bytes of data one registry entry carries. |
| `registry.name_bond_tnzo` | 25 | 0 | 1000000 | up | Bond the first put of a registry name locks, whole TNZO; names are first come and only governance retires one, forfeiting the bond to the insurance pool. |
| `registry.name_max_data_bytes` | 256 | 32 | 4096 | down | Most bytes of data a registry name carries (what the name points to). |
| `registry.name_max_len` | 63 | 32 | 160 | down | Most characters in a registry name. |
| `registry.name_min_len` | 3 | 1 | 32 | up | Fewest characters in a registry name. |
| `registry.standard_max_data_bytes` | 1024 | 64 | 16384 | down | Most bytes of data a registry standard carries beside its bundle digest. |
| `reward.availability_decay_half_life_days` | 0 | 0 | 3650 | down | Half-life, in whole days, of the availability reward's decay once its start epoch is reached. Decay is a deterministic integer half-life, not floating- point exponential (this VM has no floating-point arithmetic, for cross-validator determinism): exact at every whole half-life (a bit shift) and linearly interpolated in between, so it keeps halving rather than clamping to zero at some fixed multiple of the half-life. Zero disables decay. |
| `reward.availability_decay_start_epoch` | 0 | 0 | 4294967295 | down | The one-hour epoch the availability reward's decay clock starts counting from. Zero means decay has not been scheduled: the reward pays its full per-unit-hour cap undecayed for as long as the cap stays nonzero. Lowering it starts decay sooner, which is why it tightens downward. |
| `reward.availability_demand_target_atto_usd_per_day` | 0 | 0 | 18446744073709551615 | up | Verified-paid-demand target, atto-USD per day (at most about 18 USD; read until feature.availability_demand_target_usd.activation_epoch), at which the availability reward's demand offset has phased the reward all the way to zero. Converted to wei at the validator-signed rate in force. Zero (genesis) disables the offset: the reward ignores settled demand until governance sets a real target. |
| `reward.availability_demand_window_epochs` | 24 | 1 | 2160 | neither | One-hour epochs the availability reward's demand offset trails behind the attested epoch when summing verified-paid demand. Genesis one day. |
| `reward.availability_per_unit_hour_wei` | 0 | 0 | 1000000000000000000 | neither | TNZO per hour the availability reward pays, before decay, for one verified-available SLA verdict (every serving role an SLA probe owes: TEE, model, compute, storage and RPC providers, plus wallet and edge stakes). Zero disables the reward entirely, which is genesis. Paid out of the treasury; an epoch the treasury cannot cover forfeits that epoch's reward. |
| `reward.availability_readiness_cold_bps` | 10000 | 0 | 10000 | down | Availability reward multiplier, bps, for a subject that declared ReadinessTier::Cold (a DeclareReadinessTier transaction signed by the account that owns its bond or stake). Genesis 100%: the tier changes no payout until governance sets it apart from Warm. |
| `reward.availability_readiness_cool_bps` | 10000 | 0 | 10000 | down | Availability reward multiplier, bps, for a subject that declared ReadinessTier::Cool. Genesis 100%. |
| `reward.availability_readiness_warm_bps` | 10000 | 0 | 10000 | down | Availability reward multiplier, bps, for ReadinessTier::Warm -- the default tier for any subject that has never declared one. Genesis 100%. |
| `reward.availability_require_hardware_binding` | 0 | 0 | 1 | up | Whether the availability reward is paid at all: while zero (genesis) it pays nothing, whatever its cap, decay, demand offset or readiness tiers, because nothing ties a verdict to a real machine. Set, a verified-available verdict pays only when the subject's provider_did is a machine identity with a TPM endorsement chaining to a recognised root (the check validator admission uses). |
| `reward.sla_challenge_energy_budget_bps` | 0 | 0 | 1000 | neither | Most of the bonded compute fleet's own daily energy the SLA probe cadence may spend on challenges, bps. Zero disables the check. |
| `rewards.base_liquid_bps` | 10000 | 0 | 10000 | neither | Share of a validator's running-cost base paid liquid when it claims, bps; the base is the operator's and is split before the rest of the claim. |
| `rewards.claim_liquid_bps` | 2500 | 0 | 10000 | neither | Share of a reward claim paid liquid, bps; the rest vests. |
| `rewards.claim_vesting_ms` | 31536000000 | 0 | 126144000000 | neither | Milliseconds the vesting part of a reward claim vests over, linearly. |
| `rewards.claim_window_epochs` | 30 | 1 | 3650 | down | Epochs an issued reward coupon stays claimable before it expires unclaimed, its amount staying in the pool. |
| `roles.ai.status` | 0 | 0 | 2 | retire | Whether new model provider bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `roles.attestor.status` | 0 | 0 | 2 | retire | Whether new attestor bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `roles.catalog.status` | 0 | 0 | 2 | retire | Whether new catalog publisher bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `roles.compute.status` | 0 | 0 | 2 | retire | Whether new compute provider bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `roles.edge.status` | 0 | 0 | 2 | retire | Whether new edge operator bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `roles.rpc.status` | 0 | 0 | 2 | retire | Whether new RPC operator bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `roles.storage.status` | 0 | 0 | 2 | retire | Whether new storage provider bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `roles.tee.status` | 0 | 0 | 2 | retire | Whether new TEE provider bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `roles.wallet.status` | 0 | 0 | 2 | retire | Whether new wallet provider bonds are taken: 0 enabled (open to anyone who bonds), 1 paused, 2 retired. Existing bonds keep serving and unbond as usual. |
| `routing.standing_availability` | 7000 | 0 | 10000 | neither | Most routing standing the SLA verdicts add, scaled by the share of judged hours found available, out of 10000. |
| `routing.standing_bonded` | 3000 | 0 | 10000 | neither | Routing standing a provider holds for a live serving bond alone, out of 10000. |
| `routing.standing_unjudged_bps` | 5000 | 0 | 10000 | neither | Share of the availability standing a bonded provider holds while no verdict in the window has judged it, bps. |
| `routing.standing_window_hours` | 24 | 1 | 720 | neither | Closed SLA hours whose verdicts count toward routing standing. |
| `rpc.address_burst` | 200 | 1 | 1000000 | down | JSON-RPC requests one network address may make at once after being idle. |
| `rpc.address_rate_per_second` | 50 | 1 | 1000000 | down | JSON-RPC requests per second one network address may make before anything else is known about it: the floor every caller gets. |
| `rpc.identity_checks_per_second` | 500 | 0 | 1000000 | down | Transaction submissions per second one network address may make beyond its floor; each is admitted only if its sender is in the verified or delegated lane, and then counts against that sender's quota. |
| `security.attack_stake_bps` | 3334 | 100 | 3334 | down | Share of bonded stake, bps, a safety fault must put at risk: the slashable side of the security ratio. |
| `security.attack_window_epochs` | 24 | 1 | 8760 | up | Epochs an attack drains the bridge outflow caps before it is stopped: the extractable side of the security ratio is this many epochs of every cap. |
| `security.min_ratio_bps` | 15000 | 10000 | 100000 | up | Least security ratio, bps: slashable stake over what one attack can take out over the bridges. A raise of any bridge outflow cap, and the switch of the fee rate to validator mode, are refused below it; the pool release rises below it and falls above it. |
| `session.hybrid_records_from_ms` | 18446744073709551615 | 0 | 18446744073709551615 | neither | Milliseconds since the Unix epoch from which stored records (receipts, billing, SLA answers, availability attestations) must carry hybrid Ed25519 / ML-DSA-65 session signatures. The highest value means never. |
| `settlement.attestor_slash_bps` | 1000 | 0 | 10000 | up | Share of a rail attestor's bond, in basis points, slashed into the insurance pool when a leg it attests is compensated. 10% at genesis. |
| `settlement.compensation_window_ms` | 259200000 | 3600000 | 518400000 | down | How long after a settlement plan commits its bank, card or ISO 20022 legs may be confirmed or disputed before an unconfirmed leg's payee is compensated from the plan's reserve. 72 hours at genesis. |
| `settlement.escape_horizon_ms` | 1209600000 | 3600000 | 7776000000 | neither | Longest a settlement plan may stay undecided, and the least time a remote lock holds before its holder may reclaim it without a proven decision. |
| `settlement.griefing_premium_bps` | 100 | 0 | 10000 | up | Least TNZO premium a settlement plan's Bitcoin leg escrows, in basis points of the plan's Tenzro value; paid by the split rule when the plan aborts with that leg funded and every other leg in but its preimage withheld. |
| `settlement.netting_epoch_ms` | 3600000 | 60000 | 604800000 | neither | Milliseconds between payment netting rounds. |
| `settlement.reconciliation_reward` | 1000000000000000000 | 0 | 10000000000000000000 | neither | Reward, in wei, of the reconciliation task the chain opens each epoch for every route with a settlement lock, paid from the treasury to the first verified reconciliation of the route in the epoch. 0 opens no tasks. 1 TNZO at genesis. |
| `settlement.release_margin_ms` | 86400000 | 3600000 | 2592000000 | neither | How long past a settlement plan's deadline a remote lock or Bitcoin script must still hold its leg, so a proven decision can be relayed before the payer may reclaim. 24 hours at genesis. |
| `settlement_asset.breaker_resume_band_bps` | 50 | 10 | 300 | down | Band around par, bps, a suspended settlement asset's rate must hold inside to count toward settling again; never wider than the asset's own par band. |
| `settlement_asset.breaker_resume_epochs` | 24 | 1 | 720 | up | Consecutive epochs a suspended settlement asset's frozen rate must hold inside the resume band before it settles again, so a rate at the band edge cannot switch it on and off. |
| `settlement_asset.breaker_suspend_epochs` | 3 | 1 | 168 | down | Consecutive epochs a settlement asset's frozen rate may sit outside its par band before its peg breaker suspends it. A suspended asset settles nothing and pays nothing out; what the treasury holds of it is kept, never sold. |
| `sla.down_retention_epochs` | 0 | 0 | 878400 | neither | Market epochs the mark of an hour judged unavailable is kept after its verdict is gone; 0 keeps it. A stream or claim settled after the mark is gone pays that hour. |
| `sla.probe_interval_ms` | 600000 | 60000 | 1200000 | neither | How often validators probe each bonded provider, ms. Probe rounds align to it; at most a third of a market epoch. |
| `sla.probe_window_ms` | 30000 | 15000 | 600000 | down | How long a provider has to answer a scheduled probe, ms; never longer than the probe interval. |
| `sla.unavailable.penalty_gwei` | 10000000000 | 0 | 18446744073709551615 | up | Gwei slashed from a serving role's stake for one frozen unavailable SLA verdict. |
| `sla.verdict_retention_epochs` | 168 | 48 | 87840 | neither | Market epochs a frozen SLA verdict is kept. After it an hour judged unavailable still reads as unavailable from a small mark, and one judged available reads as paid. |
| `slashing.bond_min_residual_tnzo` | 10 | 0 | 1000000 | up | Whole TNZO below which a slashed bond is drained entirely and marked slashed. |
| `slashing.correlation_multiplier` | 3 | 1 | 100 | up | How steeply an equivocation's penalty grows with the share of stake that equivocated together, and the multiple of the floor a repeat offender pays. |
| `slashing.correlation_window_checkpoints` | 16 | 1 | 100000 | up | Equivocations within this many checkpoints of each other are correlated: each offender's penalty scales with the stake of all offenders in the window. |
| `slashing.equivocation_min_bps` | 500 | 1 | 10000 | up | Least an equivocation costs, bps of the offender's stake. |
| `slashing.jail_term_epochs` | 720 | 24 | 8766 | up | Epochs a validator slashed for misbehaviour stays jailed before it returns as a candidate. Jail is never permanent: it ends at the term, or sooner when a reinstatement proposal passes. A longer term waits out the tightening grace window. |
| `sponsorship.running_cost_per_verified_epoch_usd_e6` | 0 | 0 | 1000000000 | down | Most one verified-available hour of an approved operator backs in a stable-asset running-cost payment, micro-dollars. 0 disables stable running-cost payments. |
| `sponsorship.running_cost_per_verified_epoch_wei` | 0 | 0 | 1000000000000000000 | down | Most TNZO, in wei, one verified-available hour of an approved operator backs in a running-cost sponsorship. 0 disables running-cost sponsorship. |
| `sponsorship.yearly_max_tnzo` | 0 | 0 | 1000000000 | down | Most treasury TNZO sponsorship may commit in a 365-day period, whole TNZO: sponsored bonds and running-cost payments to approved operators. One operator receives at most one third of it. 0 disables sponsorship. |
| `sponsorship.yearly_max_usd` | 0 | 0 | 1000000000 | down | Most treasury sponsorship paid in an approved USD stable asset may commit in a 365-day period, whole US dollars. One operator receives at most one third of it. 0 disables stable sponsorship. |
| `stake.ai_tnzo` | 1000 | 1 | 10000000 | up | Model provider bond, whole TNZO. |
| `stake.attestor_tnzo` | 100000 | 1 | 10000000 | up | Attestor bond, whole TNZO. It also admits an attestor to bridge committee draws and reserve attestation. |
| `stake.bond_floor_rate_nano_usd` | 100000000 | 0 | 1000000000000 | up | TNZO/USD rate, nano-USD per TNZO, at which the bond amounts keep their USD value for a new or raised bond and a validator joining the set: below it, at the safety rate, each amount rises in proportion. Bonds already in place keep serving at the TNZO amounts. 0 turns the floor off. |
| `stake.catalog_tnzo` | 1000 | 1 | 10000000 | up | Catalog publisher bond, whole TNZO. |
| `stake.compute_floor_tnzo` | 500 | 1 | 10000000 | up | Smallest compute provider bond, whole TNZO. |
| `stake.compute_per_accelerator_tnzo` | 1000 | 1 | 10000000 | up | Compute bond per pledged accelerator at consumer class, before its class multiplier, whole TNZO. |
| `stake.edge_tnzo` | 10000 | 1 | 10000000 | up | Edge operator bond, whole TNZO. An edge operator serves the relay nodes find on chain at the URL its bond publishes. |
| `stake.rpc_tnzo` | 100000 | 1 | 10000000 | up | RPC operator bond, whole TNZO. |
| `stake.storage_floor_tnzo` | 100 | 1 | 10000000 | up | Smallest storage provider bond, whole TNZO. |
| `stake.storage_per_tb_tnzo` | 100 | 1 | 10000000 | up | Storage bond per pledged terabyte, whole TNZO. |
| `stake.tee_tnzo` | 10000 | 1 | 10000000 | up | TEE provider bond, whole TNZO. |
| `stake.unbonding_ms` | 604800000 | 3600000 | 7776000000 | up | Milliseconds a role stake stays slashable after its operator asks to withdraw it. |
| `stake.validator_tnzo` | 10000 | 1 | 10000000 | up | Validator self-stake admitted to the active set, whole TNZO. Seated validators are not ejected by a raise. |
| `stake.wallet_tnzo` | 1000 | 1 | 10000000 | up | Wallet provider bond, whole TNZO. |
| `staking.active_set_floor` | 4 | 4 | 10000 | neither | Fewest validators the active set keeps: an ejection for inactivity never takes it below this. |
| `staking.exit_churn_bps` | 400 | 100 | 2000 | neither | Share of the active validator set's self-stake that may finish exiting in one epoch, bps. Exits complete in address order while their stake fits; at least one completes every epoch. |
| `staking.inactivity_activation_epoch` | 0 | 0 | 4611686018427387904 | neither | First epoch whose validators' participation counts toward inactivity ejection. A running chain sets it to an epoch every node has reached the build that keeps the count; a new chain starts at 0. |
| `staking.inactivity_limit_epochs` | 5000 | 0 | 10000000 | neither | Consecutive epochs in which a validator signs nothing the chain certifies before it is moved to exit, so a validator that is gone cannot hold the quorum above what the live set reaches. 0 turns ejection off. |
| `staking.validator_machine_identity.status` | 1 | 0 | 2 | neither | Whether a validator may name its machine identity on chain, so peers hold its endpoint records to the machine's ML-DSA key: 0 enabled, 1 paused, 2 retired. Paused until the network runs a build that reads the registration. |
| `staking.validator_signature_schemes` | 1 | 1 | 3 | neither | Signature schemes a validator may register its consensus key under, one bit per scheme id: 1 is ML-DSA-65 with P-256, 2 is ML-DSA-87 with P-256. Keys already registered are unaffected. |
| `staking.validator_unbonding_ms` | 604800000 | 3600000 | 7776000000 | up | Milliseconds an exiting validator's bond stays slashable in the staking vault before it can be withdrawn. |
| `storage.audit_retention_seconds` | 15811200 | 15811200 | 18446744073709551615 | neither | Seconds an agent's recorder keeps its audit entries, with their proofs, after the session closed. Independent of block-history retention; the floor is six months. |
| `storage.da_history_retention_seconds` | 63072000 | 15811200 | 18446744073709551615 | neither | Seconds a history segment stays in the data-availability layer after it was recorded. Block execution expires it after that and committee members drop its slivers. Audit objects follow storage.audit_retention_seconds. |
| `storage.history_retention_blocks` | 1209600 | 10000 | 18446744073709551615 | neither | Recent blocks validators and RPC nodes keep locally. Older blocks are held by the committee's data-availability layer and fetched from it, verified against checkpoint certificates. The floor keeps every node able to serve the blocks peers catching up still import. |
| `storage.placement_new_provider_bps` | 2000 | 0 | 5000 | neither | Share of each shard's replicas placed on storage providers no verdict in the standing window has judged yet, so a new provider can earn a record, bps, rounded up to whole replicas. |
| `token.policy_timelock_floor_ms` | 604800000 | 3600000 | 7776000000 | neither | Shortest timelock a token's issuer may set on its eligibility policy and attestor-set changes; holders move under the policy in force until a queued change executes. |
| `token.reserve_attestation_max_age_secs` | 86400 | 60 | 2592000 | down | Oldest a reserve attestation behind a reserve-backed mint may be, seconds. |
| `training.challenge_bond_gwei` | 10000000000 | 1 | 18446744073709551615 | up | Bond (gwei of TNZO) a challenger posts against a training round. |
| `training.challenge_fee_bps` | 500 | 0 | 10000 | up | Share (bps) of a training challenge bond kept as the fee, paid to the insurance pool whatever the outcome. |
| `training.challenge_window_ms` | 86400000 | 60000 | 2592000000 | neither | Challenge window (ms) of a committed training round: anyone may challenge it this long after its receipt was committed. |
| `training.challenger_reward_gwei` | 5000000000 | 0 | 18446744073709551615 | neither | Reward (gwei of TNZO) an upheld training challenge pays its challenger out of the trainer's compute bond. |
| `training.decide_window_ms` | 86400000 | 60000 | 2592000000 | neither | How long (ms) validators have to decide a training challenge after it was filed; undecided, it expires. |
| `training.max_challenges` | 4 | 1 | 64 | neither | Most challenges one training round may carry. |
| `training.penalty_gwei` | 10000000000 | 0 | 18446744073709551615 | up | Penalty (gwei of TNZO) a trainer's compute bond pays to the insurance pool for an upheld training challenge. |
| `training.sample_steps` | 32 | 2 | 4096 | neither | Steps a verifier replays for one training challenge; the first and the last step are always among them. |
| `training.tee_challenge_window_ms` | 3600000 | 60000 | 2592000000 | neither | Challenge window (ms) of a training round whose receipt carries an accepted TEE attestation. |
| `training.tolerance_ppm` | 100 | 0 | 1000000 | neither | Largest distance (ppm) between a replayed and a claimed training state that still counts as reproduced; 0 for bit-exact kernels. |
| `treasury.grant_reserve_floor_bps` | 5000 | 0 | 10000 | up | Reserve balance, bps of the running-cost reserve's target, under which treasury grants and grant tranche releases are refused; running costs are still paid. A reserve with no target yet has no floor. |
| `treasury.max_period_outflow_bps` | 300 | 1 | 10000 | down | Most the treasury pays out within one outflow period, bps of its balance when the period began. |
| `treasury.max_proposal_outflow_bps` | 200 | 1 | 10000 | down | Most one proposal pays out of the treasury, bps of the treasury balance when it enacts. |
| `treasury.max_sale_tnzo_epoch` | 10000 | 1 | 10000000 | neither | Most the running-cost reserve pays out in one epoch, whole TNZO, however much volume the reports show. A ceiling wash trading cannot raise. |
| `treasury.month_epochs` | 720 | 1 | 8760 | neither | Epochs one treasury accounting month spans: the window realised revenue, paid running costs and the reserve target are measured over. |
| `treasury.onramp_max_tnzo_epoch` | 0 | 0 | 10000000 | down | Most TNZO, whole, the bond on-ramp pays from the treasury into validator bonds in one epoch; zero pays nothing. Raising it above zero distributes TNZO for stable assets, which is the owner's decision. |
| `treasury.outflow_period_ms` | 2592000000 | 3600000 | 31536000000 | up | Length of a treasury outflow period, ms. |
| `treasury.payment_ttl_epochs` | 720 | 1 | 8760 | neither | Epochs an enacted running-cost payment stays payable; what the reserve's caps have not paid by then lapses, so a payment sized at one price is never paid out at a much later one. |
| `treasury.proposal_outflow_exception_bps` | 0 | 0 | 500 | down | Basis points of the period's opening stable holdings one stable sponsorship payment may use above the period outflow limit when its proposal asks for the exception. The yearly USD caps and the per-proposal limit still bind. 0 disables the exception. |
| `treasury.reserve_drawdown_bps` | 300 | 0 | 10000 | neither | Share of the running-cost reserve's balance running-cost payments may draw in a trailing month beyond the revenue share, bps. |
| `treasury.reserve_fill_share_bps` | 5000 | 0 | 10000 | neither | Share of the fee revenue the treasury realised since the last epoch boundary that moves into the running-cost reserve at the boundary, while the reserve is under its target and only as far as the target, bps. |
| `treasury.reserve_target_months` | 12 | 0 | 120 | neither | The running-cost reserve's target, in months of observed running cost: the larger of what the reserve paid over the trailing month and what that month's revenue share allowed. |
| `treasury.running_cost_revenue_share_bps` | 3000 | 0 | 10000 | neither | Share of the trailing month's realised fee revenue running-cost payments may use in that month, bps. |
| `treasury.sale_volume_share_bps` | 500 | 0 | 10000 | neither | Most the running-cost reserve pays out in one epoch, bps of the TNZO the market traded in an epoch as the validators' volume reports observe it; no recent report, no payout. |
| `treasury.sponsorship_grants_yearly_max_tnzo` | 0 | 0 | 1000000000 | down | Most treasury TNZO sponsorship and grants may pay out together in a 365-day period, whole TNZO. 0 disables both. |
| `treasury.sponsorship_grants_yearly_max_usd` | 0 | 0 | 1000000000 | down | Most sponsorship and grants may pay together in stable assets in a 365-day period, whole US dollars. 0 disables both. |
| `treasury.volume_max_age_epochs` | 6 | 1 | 720 | neither | Market epochs a traded-volume report stays usable for the running-cost sale cap; an older one counts as no volume. |
| `treasury.volume_window_epochs` | 168 | 1 | 720 | neither | Market epochs of traded-volume reports the running-cost sale cap takes the lowest of, so a sale sized from them does not outrun a market whose volume has since fallen. |
| `tx.max_validity_ms` | 3600000 | 1000 | 604800000 | down | Longest window a signed transaction's valid_until may reach past the block time it executes at. |
| `tx.privileged_max_validity_ms` | 600000 | 1000 | 86400000 | down | Longest validity window for a privileged transaction (governance, guardian, issuer, agent Terms and kill-switch actions). |
| `upgrade.activation_delay_blocks` | 1000 | 1 | 1000000 | neither | Blocks between an upgrade's enactment and the height from which every node runs the new binary. |
| `upgrade.readiness_bps` | 6700 | 5001 | 10000 | neither | Share of bonded validator stake, in basis points, whose machines must have quoted the new binary before a protocol upgrade enacts. |
| `validator.admission_approval` | 0 | 0 | 1 | up | 1: closed: a validator registers and sits on a committee only if it is on the admitted set (the genesis validators and the accounts an enacted ApproveValidators proposal approved); 0: open: any account that meets the bond rules may. |
| `validator.base_cap_tnzo_month` | 20000 | 0 | 10000000 | neither | Most base reward one validator earns, in whole TNZO a month, so a falling rate cannot raise it without bound. |
| `validator.base_cost_usd_month` | 1500 | 0 | 100000 | neither | Running cost one active validator's base reward covers, in USD a month at the rate in force; one base per validator with recorded consensus work. |
| `validator.sponsored_bond_max_tnzo` | 0 | 0 | 1000000000 | down | Most sponsored stake one validator may hold, bonded and unbonding, whole TNZO: existing treasury TNZO an enacted SponsorValidatorBond bonded on its behalf. It counts toward the bond and is slashable, never votes, earns nothing and returns to the treasury on recall or exit. 0 disables sponsorship. |
| `validator.sponsored_bond_total_max_tnzo` | 0 | 0 | 1000000000 | down | Most sponsored stake out of the treasury network-wide, bonded and unbonding, whole TNZO. 0 disables sponsorship. |
| `validator.stable_cover_fee_share_bps` | 10000 | 0 | 10000 | neither | Share of the stable settlement fees the treasury keeps that fills the validator cover reserve, bps; the reserve pays each active validator's running cost in stable assets before any base reward. |
| `validator.stable_cover_target_months` | 12 | 0 | 60 | neither | Months of the active validators' running cost the validator cover reserve fills up to from stable settlement fees; fees beyond it stay with the treasury. |
| `veto.block_bps` | 1000 | 1 | 10000 | neither | Share of TNZO supply, in basis points, locked in a proposal's veto escrow that contests it: it is voted again on the Ratify track. |
| `veto.max_extension_ms` | 2592000000 | 0 | 7776000000 | neither | Most the holders' veto escrow may stretch a timelock, reached at the blocking share. |
| `veto.signal_bps` | 100 | 1 | 10000 | neither | Share of TNZO supply, in basis points, locked in a proposal's veto escrow before its timelock starts to stretch. |
| `wallet.human_ceiling_window_ms` | 86400000 | 3600000 | 2592000000 | up | The rolling window the ordinary-account sending ceiling covers, ms. |
| `wallet.human_daily_ceiling_tnzo` | 10000 | 1 | 1000000000 | down | Most one ordinary account sends in the ceiling window, whole TNZO; a wallet refuses to sign a transfer that would pass it. |
| `wallet.recipient_lookalike_prefix_bytes` | 3 | 1 | 8 | down | Leading address bytes that must match a trusted address for a recipient to be flagged as a look-alike (address poisoning) before signing; fewer bytes flag more addresses. |
| `wallet.recipient_lookalike_suffix_bytes` | 3 | 1 | 8 | down | Trailing address bytes that must match a trusted address for a recipient to be flagged as a look-alike (address poisoning) before signing; fewer bytes flag more addresses. |
| `wallet.step_up_threshold_tnzo` | 1000 | 1 | 1000000000 | down | A transfer of at least this much, whole TNZO, needs the amount typed back before a wallet signs it. |
| `zk.goldilocks_blake3_fri.status` | 0 | 0 | 2 | retire | Whether proofs from the Goldilocks BLAKE3 FRI system are accepted on chain: 0 enabled, 1 paused, 2 retired. Proofs already recorded stay. |
| `zk.halo2_ipa_pasta.status` | 0 | 0 | 2 | retire | Whether proofs from the Halo2 IPA Pasta system are accepted on chain: 0 enabled, 1 paused, 2 retired. Proofs already recorded stay. |
| `zk.koala_bear_sha256_fri.status` | 0 | 0 | 2 | retire | Whether proofs from the KoalaBear SHA-256 FRI system are accepted on chain: 0 enabled, 1 paused, 2 retired. Proofs already recorded stay. |
<!-- END GENERATED PARAMETERS -->
