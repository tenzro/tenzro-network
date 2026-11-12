# Consensus

Tenzro orders transactions with a signature-free DAG protocol and makes the
result transferable with checkpoint certificates signed by hardware-held
post-quantum keys. The protocol core is `crates/tenzro-consensus`; the node
drives it from `crates/tenzro-node/src/consensus_driver.rs`.

## Keys and committee

- A validator's consensus key is a composite ML-DSA-65 + ECDSA-P256 key. The
  P-256 half is a key in the Secure Enclave or TPM; the ML-DSA-65 half is
  derived from the machine's hardware root for each signature and wiped
  after it (`HardwareValidatorSigner` in the node). There is no software or
  sealed fallback: a machine without such hardware follows the chain as a
  full node.
- Registration (`RegisterValidator`) and genesis entries carry the two key
  halves, the node's Ed25519 node key (derived from the same hardware; it
  signs peer bindings and availability attestations), a composite proof of
  possession over the address, both halves and the node key, and the node
  key's own Ed25519 signature over the same. The VM refuses a registration
  without both proofs. No network address is registered.
- Each boot, the validator's hardware key signs one endpoint announcement
  (`announce`): a salted commitment to its iroh endpoint for this boot, this
  boot's session key (`session`, a composite key held only in memory) and
  this boot's disclosure key (X25519 + ML-KEM-768, also memory only), with a
  lifetime of six hours, re-signed at half-life. Announcements are gossiped
  on `tenzro/validators` and sent first on every consensus stream.
- The endpoint itself is never published. To the committee the validator
  seals the endpoint and the commitment salt to each member's disclosure key
  (both key exchanges, AES-256-GCM) and gossips the sealed copies with the
  announcement. A member opens its copy and admits the endpoint only if it
  matches the signed commitment. The sealed copy also names the machine
  identity whose signed endpoint record resolves the endpoint; a member dials
  only through that record, and only when it names the committed endpoint.
  A validator shares its record with the committee's machines and with the
  machines on its own boot list, the entry points its operator chose; a boot
  machine outside the committee keeps the record and passes it to no one. The
  record names relays, never an address. Publicly a validator shows its key,
  stake, announcements and certificates, never a network location. A
  validator needs no inbound port: it reaches the others over the Tenzro
  relays and the point-to-point paths the transport opens from them.
- Stake is apportioned into integer seats (largest remainder over a budget
  of 1,000 seats by default). No validator holds more than 10% of the
  committee's weight once the set has at least ten validators; the excess is
  spread over the others. There is no one-seat floor: a validator whose stake
  earns no seat is not a committee member, so splitting stake across many
  validators buys no weight. Every quorum is counted in seats: `n` seats,
  `f = (n-1)/3`, quorum `n - f`.

## Channels

Validators exchange consensus frames over one QUIC stream per pair on the
node's iroh endpoint, ALPN `tenzro/consensus`. The dialer sends its
announcement and commitment salt first; the stream must come from the
endpoint the peer's newest announcement commits to, and a four-message handshake
(X25519 + ML-KEM-768, both sides sign with the session keys their
announcements certify, the responder only after authenticating the
initiator) derives per-direction keys, so a handshake costs no hardware
signature; every frame then
carries a keyed-BLAKE3 MAC and a strict sequence number. Nothing inside a frame
is signed.

Channels come up in any order and at any time. A validator proposes an epoch's
first vertex only once it has channels to a quorum of the committee, itself
included. Whenever a channel comes up, each side sends its frontier (its
round, each author's highest delivered vertex, its next uncertified
checkpoint), and the other answers with what that frontier lacks of the rounds
still in play: its own undelivered vertices, the reliable-broadcast signals it
sent, its pending checkpoint votes and its latest certificate, the same
messages again and never different ones. A round that stands still for twice
the leader timeout asks every peer for the same repair. Missing vertices of the
current rounds are fetched on every retry; older history a validator catching
up needs, at most 256 per retry.

## Ordering

- Each validator proposes one vertex per round through a reliable broadcast
  (ECHO, VOTE, ACK, READY; two-step delivery on a large ECHO quorum). A vertex
  strongly references a quorum of the previous round, introduces this
  validator's batches and acknowledges others'.
- Batches are pushed to every validator ahead of the vertices that introduce
  them; a batch is executed once its introduction and a quorum of
  acknowledgements are ordered.
- Every round has `leader_slots` leader slots, each held by a distinct
  validator. Slots are decided in order (round, then slot), each one
  committed or skipped:
  - directly committed once next-round vertices from a quorum of seats
    reference the slot's vertex, counting each author's delivered vertex or,
    before it is delivered, its first proposal;
  - directly skipped once every seat's delivered next-round vertex does not
    reference it;
  - otherwise decided by the first slot at least two rounds later that is not
    skipped: if that slot is committed, the slot commits exactly when that
    slot's vertex reaches it through strong references; if it is undecided,
    so is this one.
  A quorum of first proposals holds at least `f + 1` honest supporters, and
  every vertex two or more rounds later reaches a quorum of the next round,
  so a slot committed directly by one validator is reached from every later
  vertex, and one skipped directly is reached from none: every validator
  decides every slot alike. Each committed slot orders its not yet ordered
  causal history, by round then author, into one block when that history
  holds transactions; a slot that orders none makes no block, so heights
  advance, and storage and sync grow, only with transactions.
- A validator proposes the next round as soon as it holds a quorum of the
  current round and every leader vertex of it; while a leader vertex is
  missing, it waits at most `leader_timeout_ms` from entering the round.
- While nothing waits to be ordered (no unreleased batch, and a leader
  committed after the last round that introduced one), rounds are at least
  `idle_round_interval_ms` apart instead: the committee keeps a heartbeat in
  which leaders are still committed or skipped by a quorum. A batch reaching
  any validator is pushed to all of them and returns each to full pace at
  once, so it is ordered within a round or two. Batches hold only
  transactions admitted to a mempool, so only a valid, fee-paying
  transaction, or a bonded validator's record of checkpoint signers (below),
  wakes the committee.
- Each leader also carries the other validators' batches it holds that no
  vertex it references introduced yet. When its slot is committed, those
  batches are ordered with it, a round earlier than
  their authors' own vertices would order them; the later introduction of the
  same batch is ignored. A validator echoes a leader vertex only once it holds
  every carried batch under the author and sequence it is carried as, and
  fetches a missing one from the leader.
- The leader schedule weights validators by seats and recent behavior and is
  a function of the committed prefix: it changes only at checkpoints and draws
  its seed from the checkpoint two back.

## Checkpoints and finality

- At the first committed leader at least `checkpoint_interval_ms` (500 ms)
  after the previous checkpoint, a checkpoint over the blocks since is
  decided, when there are any. The first one after that, if blocks stopped,
  covers no block and commits the state root of the last block, so the state
  after the last transaction is certified without a later block. The epoch's
  last checkpoint is decided at the first committed leader once
  `epoch_checkpoints` × `checkpoint_interval_ms` has passed since the epoch
  started, blocks or none: an idle epoch is one checkpoint. Once executed,
  its body (chain, genesis, epoch, index, previous
  checkpoint, height range, the state height and its state root (two blocks
  behind the range's last when it covers blocks, its last when it covers none),
  statement root, next committee root at an epoch's end, anchor round,
  timestamp) is signed by each validator after persisting that it is about
  to, and a quorum of votes forms a certificate.
- A vote is signed by the validator's in-memory session key, never by the
  hardware key directly. At each epoch (and on each boot) the hardware key
  signs a `SessionCertificate` binding the session key to (chain, genesis,
  epoch, validator). Every vote, every certificate signature and every piece
  of equivocation evidence carries that certificate; a signature counts only
  when its certificate verifies under the signer's registered hardware key
  for the checkpoint's own epoch. Light clients verify certificates the same
  way, so certified finality and slashing both trace to the hardware key.
  The session key is never persisted and is zeroised when dropped.
- The RPC reports two heights: `ordered` (final for every honest validator)
  and `certified` (covered by a certificate: transferable, accountable).
  Bridges act on `certified`.
- The signers of each certificate are recorded on chain so they earn the
  epoch's vote reward: one committee member per checkpoint (index modulo
  committee size) sends a `RecordCheckpointSigners` transaction from its
  account. The record pays no fee and needs no balance: the mempool admits
  it from a bonded validator at no gas price and orders it ahead of
  fee-paying transactions, and the VM charges it nothing, kept or refused.
  Nothing waits on it: blocks and checkpoints go on whether or not a record
  lands, and no validator's spendable balance bears on consensus.
- Two votes for different bodies with one index are complete evidence. A
  `ReportCheckpointEquivocation` transaction carrying it (both votes with their
  session certificates) is verified by the VM, which slashes the bond of
  the account that registered the hardware key into the insurance pool, and
  is recorded once; every node jails the signer when it replays the log. The
  penalty scales with the bonded share of every validator that equivocated
  within the governed correlation window: three times that share, at least 5%
  and at most all of the bond (TOKENOMICS, section 7).

## Followers

Blocks carry no signatures. A follower holds gossiped or synced blocks until a
certificate covering them arrives (gossip topic `tenzro/certificates`, or with
the checkpoint bodies a `/tenzro/block-sync` range carries), checks that they
rebuild the certified blocks root, executes them and checks the certified
state root. Sync evidence never crosses an epoch boundary: an epoch's last
certificate is always kept and a follower derives the next committee from its
own state before it verifies the next epoch's certificates.

## Execution and commit

Ordered segments execute in order. Each block's state, trie version, block,
transaction index and events go to the store as one batch, so a crash cannot
leave a height's state without its block. Segments that queue while a run
executes (up to 64) execute together with unsynced writes and one log sync at
the end of the run; consensus learns of each block only after that sync, so
no checkpoint is signed over data that is not on disk, and a run stops at the
epoch-closing height.

Ordering waits for execution. A validator with more than 32 ordered heights
not yet executed holds its frontier and proposes only in rounds in which its
peers already hold a quorum, so ordering cannot outrun a quorum's execution.
This changes only when a validator proposes, never what is ordered. A
validator stopped mid-epoch rejoins its epoch.

## Time rules

Every period the protocol keys on is a genesis parameter (`[time]` in the
genesis file), validated at startup and committed in the genesis state root:
`checkpoint_interval_ms` (500), `epoch_checkpoints` (7,200, one hour),
`handover_confirmations` (2), `announcement_lifetime_ms` (six hours),
`compact_interval_ms` (60 s), `compact_handoff_ms` (90 s), `leader_slots`
(2), `calendar_scale` (1) and `idle_round_interval_ms` (5 s; 1 s in the local
genesis). A test network
compresses them to run many epochs in little time. `calendar_scale` runs the
calendar faster than block time from the genesis timestamp without changing the
pace of rounds: every calendar rule executed on chain (the reward year,
vesting, unbonding, campaign windows) reads the calendar
clock, and so do the rules a node checks against its own clock before anything
reaches the chain: guardian recovery start, expiry and wait, and payment-channel
escrow expiry. A margin that exists for real-world latency (the time a voucher
claim takes to land) stays that much wall-clock time, measured in calendar
milliseconds. Timestamps an external chain checks (EIP-3009 and ERC-7710
`validBefore`) stay wall-clock time. The local genesis sets 8,640, so a
ten-second epoch is one calendar day.

## Epochs

The checkpoint ending an epoch commits the next committee's root, derived by
every node from the state executed through that checkpoint. The old committee
keeps ordering for `handover_confirmations` more checkpoints, then stops, and
the next committee starts from the last of them. A follower whose key is
seated in the next committee starts validating at that handover.

## Recovery

Before a validator sends a frame it persists what the frame commits it to:
its own vertices, every reliable-broadcast signal it sent, every vertex it
delivered and every batch it authored. After a restart it rebuilds its core
from that journal, re-derives the committed sequence (the same one, since
every honest view commits the same sequence), takes the hashes and roots of
blocks it already executed from storage, and carries on in the same epoch. A
validator that finds the network already past its epoch stands down and
follows until it is seated again.
