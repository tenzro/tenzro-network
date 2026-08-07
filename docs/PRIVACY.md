# Node Privacy

An operator decides, per capability, what their node tells the network it has.

## Discovery, not access

A private capability serves the same callers at the same speed. What changes is
that the node stops publishing "here is what I have" to peers: no gossip
announcement, no entry in another node's discovery, nothing to browse.

**This is not access control, and must not be mistaken for it.** Suppressing an
advertisement stops a stranger *finding* the node. It does not stop them *using*
it if they learn the address anyway. Access control is the API-key scopes, the
service-key admission gate, and the per-resource access policies — all of which
apply identically whether a capability is advertised or not.

Stated this plainly because the failure mode is an operator marking something
private and believing it is therefore protected. Every response from
`tenzro_nodeVisibility` repeats it, and the CLI prints it as a warning whenever
anything is private.

## Per capability

| Capability | Can be private |
|---|---|
| `validator` | **no** |
| `ai` | yes |
| `storage` | yes |
| `database` | yes |
| `hosting` | yes |
| `rpc` | yes |
| `tee` | yes |
| `compute` | yes |

The configurations that matter are mixed — a public web app on a machine whose
GPUs are reserved for the operator's own team, or a validator earning consensus
rewards while renting storage to three named customers. A single node-wide
switch would force those operators to run two nodes to express one intent.

**Consensus is the exception.** A validator must be reachable by its peers to
vote, so a hidden validator is a node that has taken on an obligation it has
arranged to be unable to meet. Setting it is *refused*, not silently ignored:
an operator who asked and got silence would believe their validator was hidden
and still earning.

## Using it

```
tenzro visibility show
tenzro visibility hide ai
tenzro visibility hide --all         # everything that can be hidden
tenzro visibility publish storage
tenzro visibility publish --all
```

Reading is open — a caller may reasonably ask what a node offers. Writing is
admin-gated: it is the operator's own machine policy, not a tenant's.

Over RPC: `tenzro_nodeVisibility` (open) and `tenzro_setNodeVisibility` (admin),
which take either `{capability, visibility}` or `{preset: "public"|"private"}`.
Both are reachable from every surface via the gateway — see
[`SURFACES.md`](SURFACES.md).

## What actually stops being published

Per heartbeat tick, read live so a change takes effect on the next announcement
rather than the next restart:

- **`ai` private** — the `tenzro/models` re-announcement is skipped entirely,
  and the provider heartbeat carries no `served_models` and no advertised
  concurrency.
- **`hosting` private** — no hosting runtimes and no hosting price.
- **`rpc` private** — no advertised RPC endpoint.
- **any capability private** — its label is removed from the announcement's
  capability list.

Capabilities are *stripped from* the announcement rather than suppressing the
whole thing, so a node public for hosting and private for AI still appears as a
hosting provider. When everything is hidden there is nothing left to say, and
the heartbeat is skipped rather than publishing an empty record that still tells
peers the node exists.

A label the mapping does not recognise is left alone: dropping it would silently
unadvertise a capability nobody asked to hide.

## Persistence

The policy is stored in `CF_METADATA` and reloaded at boot. A node that came
back advertising capabilities its operator had made private would be worse than
never offering the switch. An unreadable row falls back to public *and warns*
rather than failing startup — a node that will not boot because it cannot parse
a discovery preference has turned a cosmetic problem into an outage.

## Default

Public. An operator who has expressed no preference is running an ordinary
network participant, and defaulting to private would mean a node that joins and
is never found — a confusing silence rather than a safe default, because what
privacy protects here is discoverability, not secrets.
