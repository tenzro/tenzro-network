## Joining a network that has already run

On this release a new node joins by block replay from genesis. Start it with the genesis file and
leave out `--state-sync-from`, `--checkpoint-height` and `--checkpoint-hash`:

```
tenzro-node --genesis genesis.toml
```

The node replays the chain from block 0, says so in its log, and is in step when it reports the
network's finalized height. `--no-state-sync` forces the replay even where a checkpoint is
configured. Joining from a snapshot arrives in an update; the rest of this section describes it
for that update.

### Joining by snapshot (arrives in an update)

A node that is not a validator, joining a network that has already run, will restore the committed
state from a peer's snapshot instead of replaying every block. It needs three things, all
published by the operators at launch and repeated on the release page and the operators'
channels (docs/operations/GENESIS-PUBLICATION.md):

| What | Value |
|---|---|
| Checkpoint height (`--checkpoint-height`) | `checkpoint_height` of a snapshot a serving node lists (below) |
| Checkpoint block hash (`--checkpoint-hash`) | `checkpoint_hash` of the same entry, checked against a second source |
| Peers to fetch the snapshot from (`--state-sync-from ENDPOINT_ID[@IP:PORT]`, repeatable) | published at launch |

Without a checkpoint the node joins from the certified anchor of a peer's newest snapshot: the
peer sends the certification of the checkpoint covering the block that commits the snapshot, and
the node verifies every certificate from its genesis committee and checks that the block's hash is
among those the certified checkpoint commits before it uses any of the snapshot. Peers the
operator names must serve such an anchor or the node does not start; boot peers that serve none
leave the node replaying the chain. A checkpoint, when given, is still the block the node joins
from and the one every import path holds to.

The checkpoint is a finalized block the operator has verified out of band. Compare the hash with
at least two independent sources before using it: the node refuses any other block at that height,
which is what protects a new node from a forged history.

The checkpoint must be one a serving node holds a snapshot for. A checkpoint block at height `A`
commits the state root of height `A - 2`, and the joining node asks its peers for the snapshot at
that height. Validators snapshot only the first block of an epoch, at most once per
`[snapshot] interval_blocks`, and keep the newest `retain_count` (the newest is never removed), so
an arbitrary finalized block almost never has one. Take the checkpoint from the peer's own list
(the listing works on this release too):

```
tenzro node snapshots --rpc <peer rpc url>
```

Each entry gives `checkpoint_height` and `checkpoint_hash` (the block that commits that snapshot)
and the `endpoint_id` to sync from; use the newest, and compare its hash with another node's
`eth_getBlockByNumber` at that height. Once the update is installed, start with:

```
tenzro-node --genesis genesis.toml \
  --checkpoint-height <checkpoint_height> --checkpoint-hash <checkpoint_hash> \
  --state-sync-from <endpoint-id>@<ip:port>
```

The node asks every state-sync peer in turn and logs `State sync complete` with the restored root.
If no peer holds the snapshot for the checkpoint, the node does not start: it exits naming each
peer's answer, rather than replaying the chain from genesis while the operator believes it joined
at the checkpoint. Pick a listed checkpoint, or replay instead: drop `--state-sync-from` and
pass `--no-state-sync`.

Check the genesis file first (`launch-manifest.sh verify`, same page). A validator always replays
the chain and does not join by snapshot; `--no-state-sync` forces a replay on any role.

A node whose store already holds chain state continues from its tip and ignores
`--state-sync-from`; it logs a warning saying so. To replace a stalled or far-behind store with a
snapshot, stop the node and start it once with `--replace-store` and the same snapshot options. The
old store is moved to `db.replaced-<unix seconds>` in the data directory, not deleted: move it
back to undo. `--replace-store` without `--state-sync-from` is refused, because nothing would
restore the store.

## Granting a key holder its key label with the operator passkey

A machine whose keys are in another machine's TPM (a Raspberry Pi, a server with no TPM of its own)
runs `tenzro-node tpm key-holder`; the machine that holds the TPM runs `tenzro-node tpm serve`. The
key holder may use its key label only with a grant the operator passkey signs. The passkey is on the
operator's own device (a laptop or phone), so the signature is made in a browser page, `tools/passkey-grant/`
in the repository: one static page and a small local server, no dependencies, nothing leaves the page. Three commands on the
operator's side:

1. On the key holder's machine, ask for a grant, naming the passkey enrolled for the label (its
   credential id, base64url) and how long it lasts:

   ```
   tenzro-node tpm grant-request --socket /run/tenzro/holder.sock --label <label> \
     --valid-hours 720 --json --credential-id <enrolled credential id>
   ```

   It prints one JSON object: the key holder's endpoint, the label, the end of the grant, the
   challenge, the credential id with its fingerprint, and the relying party (`--rp-id`, default `localhost`).

2. On the operator's device, serve the page from `localhost` and open it:

   ```
   python3 tools/passkey-grant/serve.py
   ```

   Open `http://localhost:8743`, paste the JSON into step 2 and press the button. (Step 1 of the page enrols the passkey once and prints the `[[clients]]` block for the provider file and the credential id.) The browser is asked
   for the enrolled passkey only, with user verification; a synced passkey the page did not name
   is not offered. The page shows the label, the key holder, the end of the grant and the passkey's
   fingerprint, and refuses a request with no credential id, a credential id that does not match its
   fingerprint, a host other than the relying party, or an end that has passed.

3. Copy the `tenzro-node tpm grant-install ...` line the page prints and run it on the key
   holder's machine. `tenzro-node tpm remote-check --key-holder <socket> --label <label>` then opens
   the identity key at the provider and signs a test message.

A key holder that restarts with its machine needs a new grant; a restart of the node alone does not.
`scripts/tests/grant_roundtrip_test.sh` runs these steps on a software TPM with a software passkey in
the operator's place.

## Adding a device to a running TPM provider

A machine with no TPM of its own signs through a provider's TPM, and each such machine is
enrolled with the operator passkey that approves its key grants. Add one with
`tenzro-node tpm enrol-client --config <provider file> --passkey-public-key <hex x||y> --rp-id <id> --label <label>`
on the provider's machine. The command checks the whole file before it replaces it, so a refused
client leaves the file as it was, and then tells the provider running from that file to re-read
its client list. The provider needs no restart and keeps every client it is serving; the command
says which process it told, or that none is running and the client is used when one starts.

## Testnet use and reporting a vulnerability

The testnet is for testing. Test tokens reach an operator through the
sponsorship request at the project's join page, and they carry no value. Report a security issue privately to the contact in
[SECURITY.md](../SECURITY.md), as described there, and do not test against other people's
accounts or nodes.
