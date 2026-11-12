## Joining a new network by snapshot

A node that is not a validator, joining a network that has already run, can restore the committed
state from a peer's snapshot instead of replaying every block. It needs three things, all
published by the operators at launch and repeated on the release page and the operators'
channels (docs/operations/GENESIS-PUBLICATION.md):

| What | Value |
|---|---|
| Checkpoint height (`--checkpoint-height`) | published at launch |
| Checkpoint block hash (`--checkpoint-hash`) | published at launch |
| Peers to fetch the snapshot from (`--state-sync-from ENDPOINT_ID[@IP:PORT]`, repeatable) | published at launch |

The checkpoint is a finalized block the operator has verified out of band. Compare the hash with
at least two independent sources before using it: the node refuses any other block at that height,
which is what protects a new node from a forged history. Start with:

```
tenzro-node --genesis genesis.toml \
  --checkpoint-height <height> --checkpoint-hash <hash> \
  --state-sync-from <endpoint-id>@<ip:port>
```

Check the genesis file first (`launch-manifest.sh verify`, same page). A validator always replays
the chain and does not join by snapshot; `--no-state-sync` forces a replay on any role.

## Testnet use and reporting a vulnerability

The testnet is for testing. Test tokens reach an operator through the
sponsorship request at the project's join page, and they carry no value. Report a security issue privately to the contact in
[SECURITY.md](../SECURITY.md), as described there, and do not test against other people's
accounts or nodes.
