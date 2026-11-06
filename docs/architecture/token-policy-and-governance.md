# Transaction expiry, guardians, votes and token policy

Consensus rules for how long a signed transaction stays valid, who may
pause or veto governance, who casts a validator's ballot, and what a token
issuer may do. Every limit below is a governed parameter: it is changed by a
`ParameterChange` proposal, never by node configuration.

## Transaction expiry

Every signed transaction carries `valid_until` (ms) inside its signing
digest. The VM checks it against the block timestamp before execution:

- a transaction with no `valid_until` is refused;
- a transaction whose `valid_until` is before the block time is refused;
- `valid_until` may sit at most `tx.max_validity_ms` (default 1 hour) past
  the block time, and at most `tx.privileged_max_validity_ms` (default
  10 minutes) for privileged classes: governance actions, issuer powers,
  agent Terms changes and kill-switch actions.

`tenzro_sendRawTransaction` requires `valid_until` as well. The mempool TTL is
hygiene only; expiry is decided at execution, from block time, by every
validator alike.

## Guardians

Guardians hold negative powers only.

- `ProposalAction::SetGuardian { did, role, term_ends_ms, key_root }` and
  `RemoveGuardian` seat and unseat them; both are Sanction-domain proposals
  and are never expedited.
- A guardian DID is a human DID; agent and machine DIDs are refused.
- Roles: a governance guardian vetoes a passed proposal during its
  timelock; a protocol guardian pauses enactment. Voting and proposing
  continue during a pause.
- Each act needs `governance.guardian_threshold` distinct seated guardians,
  each sending its own transaction within
  `governance.guardian_signal_window_ms`.
- A pause lapses by itself after `governance.max_pause_ms` and cannot be
  renewed until `governance.pause_cooloff_ms` has passed.
- A term is at most `governance.guardian_max_term_ms`; an expired seat
  counts for nothing.
- A guardian can never move funds or set a parameter.
- Every seat names its `key_root`: the passkey sync provider (AAGUID) or the
  device-bound credential its key lives in. Two live seats of one role never
  share a root, so a threshold counts independent keys.

Genesis may seat an initial set under `[[economy.guardians]]`, each with a
hard expiry. Read every seat, both pauses and the steward sunset with
`tenzro_getGuardianState` (CLI `tenzro governance guardians`, MCP
`get_guardian_state`, SDK `get_guardian_state` / `getGuardianState`).

## Foundation stewardship

The treasury is `network_treasury_address`: it has no key, and only an
enacted proposal moves its funds. At genesis Tenzro Foundation holds steward
seats (`role = "steward"`).

- A steward may veto a queued proposal during its timelock only when the
  proposal moves treasury value or runs on the expedited track. A change to
  the seats, the sunset or any other network setting is outside its reach.
- A steward may hold treasury and expedited enactment (`GovernancePause`
  from a steward seat). The hold takes the guardian threshold, lifts by
  itself after `governance.max_pause_ms`, and shares the cool-off rule.
- A steward never spends, proposes on the treasury's behalf or sets a
  parameter; it signs only veto and hold signals, each counted m-of-n.
- Seats are human passkey identities with independent key roots and terms of
  at most `governance.guardian_max_term_ms`, ending by the sunset.
- `governance.steward_sunset_ms` ends all steward power;
  `governance.steward_max_seats` caps live seats. A parameter change may only
  lower either, so governance can shrink or end stewardship and nothing can
  extend it. Seating a steward takes an enacted `SetGuardian` proposal.
- All of it is consensus state under the system address
  (`governance_guardian:<addr>`, `governance_guardian_index`,
  `governance_treasury_hold`, `governance_param:governance.steward_*`), so a
  light client checks it with ordinary state proofs.

## Validator ballots

Governance spans humans, machines and agents, and a validator is a machine.
A `GovernanceVote` is cast by the validator's root, the identity its
account's identity is rooted in:

- A validator whose identity is delegated from a person is voted by its
  operator: that person's passkey identity signs the transaction, and
  `root_approval` is empty. A ballot signed by the validator's machine key
  is refused.
- A validator whose identity is an autonomous machine
  (`did:tenzro:machine:{id}`) is voted by its machine root: the hardware key
  (TPM or Secure Enclave) its machine DID derives from, as the on-chain
  identity registry binds it, approves exactly this ballot in
  `root_approval`. The approval is a composite signature over the custody
  challenge digest for operation `governance_ballot` and target
  `proposal_id || vote || len || validator`, naming the validator account,
  under the account-owner context. It is checked by the same root
  verification as every other root approval (`verify_root_approval`): the
  ML-DSA-65 key comes from chain state and is mandatory once enrolled, so
  the P-256 leg alone does not pass. Any account may submit it and pay its
  gas. `tenzro governance vote --machine-root` signs it with the node's
  identity key and submits it from the node account; the SDKs build it
  with `machine_root_ballot` (Rust) and `machineRootBallot` (TypeScript).

A validator has one root, so it has one ballot: a passkey ballot for a
machine-rooted validator, or a machine approval for a person-rooted one, is
refused. A machine approval counts once, so replaying an earlier approval
cannot restore a vote the root has since changed; changing the vote moves
the bond, never counts it twice. The weight counted is the smaller of the
validator's bond when the proposal opened and its bond now, so bonding
during a vote adds nothing.

## Holder veto escrow, concerns and the Ratify track

Stake decides; holders can delay and contest, and human roots can delay.

- `GovernanceVetoSignal { proposal_id, amount }` locks TNZO from any account
  against a treasury, sanction or protocol upgrade proposal, in an escrow
  vault keyed by the proposal. It is accepted while the proposal is voting,
  contested, or in its timelock.
- Past `veto.signal_bps` of native supply (default 1%) the timelock stretches
  in proportion to the locked share, reaching `veto.max_extension_ms`
  (default 30 days) at `veto.block_bps`. The stretch never shrinks.
- At `veto.block_bps` (default 10%) the proposal becomes `contested` and is
  voted again on the `ratify` track: a fresh tally over the same electorate,
  three quarters in favour, and a thirty-day timelock that replaces any
  earlier stretch. A Ratify vote is neither contested nor stretched again.
- `GovernanceVetoWithdraw { proposal_id, holder }` returns a lock in full to
  its holder once the proposal is decided: executed, vetoed, rejected, or
  past its timelock. Anyone may submit it. There is no reward and no slash.
- A delegated agent signals from its wallet with the `governance.veto_signal`
  operation (`veto_signal` names the proposal, `amount` the TNZO) when its
  Terms' governance scope has `may_veto_signal` in the proposal's domain. A
  treasury or sanction signal carries the principal's step-up, and one signal
  locks at most `governance.agent_weight_max_bps` of supply (or the scope's
  lower `max_weight_bps`).
- `GovernanceConcern { proposal_id }` is one concern per live human root on
  a proposal in its timelock. The root must have been registered at least
  `governance.root_min_age_ms` (default 30 days) before the proposal opened.
  Once concerns exceed `governance.concern_quorum` (default 100), the
  timelock doubles, once only. Concerns are a count, never weight.
- Surfaces: CLI `tenzro governance veto-signal|veto-withdraw|concern`;
  `tenzro_getProposal` and `tenzro_listProposals` return `veto_locked`, and
  the proposal's `veto_extension_ms`, `concerns` and `concern_doubled`.

## Clear signing of privileged actions

A transaction that exercises a privileged power is signed over a typed
preimage, not an opaque hash. The classes are `governance` (propose, vote,
execute, veto escrow, concern, readiness, disclosure), `guardian` (veto,
pause), `issuer` (a token issuer power), `terms` (delegating, re-scoping or
revoking an agent) and `step_up` (an agent action carrying its controller's
step-up approval).

- `typed_action_digest(tx)` in `tenzro-types` is SHA-256 of the canonical
  JSON `ActionPreimage`: domain, class, chain id, signer, nonce, gas,
  timestamps, the action as its transaction type encodes it, the custody
  digest of every passkey approval it carries, and the hash of the
  post-quantum key. `Transaction::hash` returns it for these transactions,
  so it is the digest the VM verifies.
- A privileged transaction carries no memo: no text supplied by the
  application asking for the signature enters what is signed.
- Surfaces: RPC `tenzro_decodeAction { transaction } | { preimage }`
  returns the class, digest, preimage and a description generated from the
  preimage; SDK `decode_action` / `decodeAction` recompute the digest from
  the returned bytes and check the action is the one given; CLI
  `tenzro tx explain <json | hex preimage>` decodes locally; the CLI signing
  path prints the decoded action before the hardware key signs.
- Every transaction type can be signed client-side. RPC
  `tenzro_getSigningPayload` takes the unsigned request
  `tenzro_sendRawTransaction` takes and returns what it is signed over: the
  canonical `tx_type` encoding for a plain transaction, the typed preimage for
  a privileged one, and `Transaction::hash`. The SDK `transactions` client
  (`TxKind` / `TX_KINDS`, one per `TransactionType` variant, held to it by
  `tenzro-types/tests/sdk_transaction_coverage.rs`) checks that the payload
  decodes to the transaction it built, recomputes the digest, and only then
  signs with the caller's hybrid key. CLI `tenzro tx signing-payload`, MCP
  `transaction_signing_payload`.

## Governance receipts and decisions on other chains

Enacting a proposal records `governance_decision:<id>` in consensus state:
the SHA-256 of the executed proposal record followed by the enacting height
(u64 big-endian), 40 bytes.

- `tenzro_getGovernanceReceipt { proposal_id }` returns the proposal's
  records (proposal, tally, veto escrow total, decision, and for a protocol
  upgrade its readiness signals and scheduled activation), each with a state
  proof under the latest certified checkpoint, and that checkpoint's proof
  from genesis. `tenzro governance receipt <id> --verify --chain-id ...
  --genesis-hash ... --genesis-committee-root ...` checks it offline with the
  evidence pack's verifier: every record proves under the certified root,
  and the decision is of exactly the proven proposal record. MCP
  `governance_get` kind `receipt`; SDK `get_governance_receipt` /
  `getGovernanceReceipt`.
- On an EVM chain, `TenzroGovernanceReceiptVerifier` (contracts/finality)
  checks a decision record with a state proof under a checkpoint its
  `TenzroFinalityClient` holds (`verifyDecision`, `verifyUndecided`). On
  Solana, the finality program's instruction 2, `verify_decision`, checks it
  under the latest final checkpoint. Both share the vectors in
  `sdk/fixtures/governance_receipt`.
- Evidence packs carry two more sections, each proven under the pack's
  state root: `governance` (the proposal and decision records of the
  proposals named with `--proposal`) and `token_actions` (the issuer actions,
  with reason code and evidence hash, the VM now records per token at
  `token_action:<token>:<seq>`, for the tokens named with `--token`).

## Upgrade readiness and the security-fix track

A `ProtocolUpgrade { version, code_hash }` names the SHA-256 of the binary
every node runs once it activates.

- `UpgradeReady { code_hash, quote }` is sent from a validator account whose
  identity is a TPM-attested machine. The quote is by the attestation key
  recorded when that machine was admitted, over
  `upgrade_ready_digest(code_hash, validator)`. One signal per validator per
  binary; the VM records the machine DID and the quoted PCR digest.
- A queued protocol upgrade enacts only once validators whose machines have
  signalled hold `upgrade.readiness_bps` (default 6700) of bonded stake,
  weighed as it stands at enactment.
- Enactment records `UpgradeActivation { readiness_met_height,
  activation_height }`, with `activation_height = readiness_met_height +
  upgrade.activation_delay_blocks` (default 1000). Every replica derives it
  from the enacting block. A node whose own binary hashes to anything else
  stops executing blocks from that height.
- An operator stages the new binary at `<data_dir>/upgrade/staged`;
  `tenzro governance upgrade-ready <code_hash>` (admin RPC
  `tenzro_signalUpgradeReady`) hashes it, refuses a mismatch, quotes the
  digest with the machine's TPM and sends `UpgradeReady`.
  `tenzro governance readiness <code_hash>` (`tenzro_getUpgradeReadiness`,
  MCP `governance_get` kind `readiness`, SDK `get_upgrade_readiness` /
  `getUpgradeReadiness`) shows the signals, the ready and required shares,
  and the scheduled activation.

A policy change carries `track`: `standard`, `expedited`, or
`security_fix { basis }`. The security-fix track is for a protocol upgrade
only, runs on the expedited window, timelock and four-fifths threshold, and
the readiness gate still applies. A governance guardian may not originate
one. Its basis is either:

- `fault { fault_id }`, an inference fault the validators upheld; or
- `vulnerability { commitment }`, the hex SHA-256 of a disclosure. Enactment
  opens a reveal window of `governance.security_reveal_window_ms` (default
  30 days). `GovernanceSecurityDisclosure { proposal_id, disclosure }` with
  the disclosure settles it as revealed; with an empty disclosure after the
  deadline anyone settles it as lapsed, which slashes
  `governance.security_reveal_slash_bps` (default 1000) of the proposer's
  stake into the insurance pool through the protocol slash path. CLI:
  `tenzro governance disclose <proposal_id> [--file <disclosure>]`.

## Token policy

A token is created with a power manifest, an eligibility policy, an
optional issuer council and optional reserve backing.

- **Powers** (`mint`, `freeze`, `halt`, `force`, `policy_change`) are each
  held by the issuer, by `k` members of the issuer council (each approving
  with its own signed transaction), or by nobody. `RenouncePower` only
  narrows a power; it never widens one.
- **Freeze, halt and forced transfer** apply at once and carry a non-zero
  reason code and an evidence hash, both recorded on-chain.
- **Policy and reserve-backing changes** are queued with an ETA at least
  `token.policy_timelock_floor_ms` (default 7 days) ahead and applied by
  `ExecutePolicy`. Until then the current policy binds, so holders can exit
  under the rules they bought in under.
- **Eligibility rules**: a live claim of a kind from an issuer the token
  names (`AddClaim` / `RevokeClaim`), denied jurisdictions, holder kind
  (human, agent under Terms, machine, any), maximum holders, maximum share
  of supply, lockup, a minimum agent Terms verification level, and a minimum
  KYC tier (the best live `kyc` claim grade, `basic`, `enhanced` or `full`,
  from an issuer the token names).
- **Reserve-backed mints** carry reserve attestations, each covering the
  supply after the mint and at most `token.reserve_attestation_max_age_secs`
  old, signed by accounts bonded as attestors (the `attestor` role stake);
  the attestor stake of the distinct accounts behind them must together
  reach the token's `min_attestor_stake_tnzo`. Any bonded attestor may
  attest: the issuer chooses how much bonded stake a mint needs, never who
  provides it. An attestor's signature is checked against the hardware key
  its identity registered on chain.

`tenzro_canTransfer { token_id, from, to, amount }` answers whether a
transfer would pass, with the refusal when it would not. Every VM view of a
token (native, EVM, SVM) applies the same check.

## EVM: ERC-7943 and the ERC-20 facade

The token factory precompile (`0x1002`) carries the ERC-7943 (uRWA)
interface keyed by token id: `canTransact(bytes32,address)`,
`canTransfer(bytes32,address,address,uint256)`,
`getFrozenTokens(bytes32,address)`, `setFrozenTokens(bytes32,address,uint256)`,
`forcedTransfer(bytes32,address,address,uint256)`, plus
`supportsInterface(bytes4)` and `facadeOf(bytes32)`.

Every token also answers at its own facade address, returned by
`facadeOf` and as `erc20_facade` by `tenzro_getToken`. The facade speaks
standard ERC-20 (`name`, `symbol`, `decimals`, `totalSupply`, `balanceOf`,
`transfer`, `approve`, `allowance`, `transferFrom`, with standard
`Transfer` / `Approval` logs) and the standard ERC-7943 functions without a
token-id argument. It holds no state: every call is the factory call with
the id filled in, against the same ledger and the same rule engine, so an
`eth_call` of `canTransfer` returns what `tenzro_canTransfer` returns.

`setFrozenTokens` and `forcedTransfer` act only when the manifest gives the
power to the issuer alone and the caller is the issuer. They record an
issuer action with reason code `0x7943` and the hash of the call as its
evidence. A council-held power, or an action that should carry its own
reason code and evidence, goes through the native `Token` transaction.

## SVM: the Token-2022 view

The Token-2022 program id (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`) is
a second SVM view of the same ledger, beside the classic SPL Token view.

- `TransferChecked` moves any mint through the ledger's rule engine.
- Instruction 201 (`GetMintExtensions`, accounts `[mint]`) returns the mint's
  extensions as Token-2022 TLV, derived from the token record: Pausable is
  the halt, DefaultAccountState is frozen when holding needs a claim
  (`RequireClaim`), PermanentDelegate is the issuer when it alone holds the
  force power, and ScaledUiAmount is 1.0 and display only.
- Refused by name: `TransferHookUnsupported` (rules are policy data, not
  hook programs), `ConfidentialTransferUnsupported`, `SupplyOutsideTokenOp`
  (MintTo, Burn and their checked forms), `UncheckedTransfer` (plain
  `Transfer`), and `UnsupportedExtension` for any other extension
  instruction.

## Treasury on other chains

The treasury holds an account on every chain agents hold accounts on, made
by the same account code: the address is
`omni_address("did:tenzro:treasury:network", caip2, deployment)` for the
chain's governed `AgentAccountChain` deployment (EVM chains, Solana, Sui,
Aptos, Stellar, Cosmos, TON). It is computed, never stored, and no
key exists for it.

- Funds move only through `ProposalAction::TreasuryRemoteAction { caip2,
  caip19, action, ttl_ms, memo }`, a Treasury-domain proposal. Enactment,
  after the vote, the timelock and any Foundation steward veto or hold,
  writes one exact remote grant at `agent_grant:did:tenzro:treasury:network:{caip2}`:
  budget = the action's amount, the action's payload hash pinned, no
  serving-node keys.
- On the other chain anyone relays: the account proves the grant under a
  final checkpoint's state root (`sync`) and runs the pinned action
  (`actExact` on EVM, and the equivalent on each family). Nothing else can
  move its funds.
- Bitcoin has no account code; treasury BTC moves through the deposit route
  only, and a `bip122` action is refused.
- `tenzro_getTreasuryAccounts` lists every account and its last grant (CLI
  `tenzro governance treasury`, MCP `get_treasury_accounts`, SDK
  `get_treasury_accounts` / `getTreasuryAccounts`). The addresses follow
  from the deployments in `[[economy.agent_account_chains]]` of the genesis
  file.

