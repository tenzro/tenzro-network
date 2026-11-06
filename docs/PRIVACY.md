# Node Visibility

An operator sets one visibility for their node. It applies to every resource the
node offers — models of every type, compute, storage, databases, hosting and
tools — unless a resource carries its own override.

## The three values

| Visibility | Announced? | Who may use a resource |
|---|---|---|
| `public` | Yes | Anyone, by paying the operator's per-use price (`payments.default_amount`; `0` is free). A caller the operator's access policy names also admits. |
| `gated` | Yes, flagged as access-required | Only callers the operator's access policy names. There is no pay-per-use path. |
| `private` | No — never announced, never heartbeated | Only this node's own callers. |

A resource's effective visibility is its override when it has one, otherwise the
node's visibility.

## Private is not non-participation

A private node still validates if it runs the validator role. Private describes
what the node publishes about its resources, not whether it takes part in
consensus.

## Using it

```
tenzro visibility show
tenzro visibility set public
tenzro visibility set gated
tenzro visibility set private
```

Reading is open — a caller may reasonably ask what a node offers. Writing is
admin-gated: it is the operator's own machine policy.

Over RPC: `tenzro_nodeVisibility` (open) returns the node's visibility, whether
it is announced, whether a key is required, the per-use price, and every
resource that overrides it. `tenzro_setNodeVisibility` (admin) takes
`{visibility: "public" | "gated" | "private"}`. Both are reachable from every
surface via the gateway — see [`SURFACES.md`](SURFACES.md).

In config, `visibility = "public" | "gated" | "private"` sets the value at
start. A value set over RPC is persisted and takes precedence on the next start.

## Per-resource overrides

- **Models** — `tenzro_serveModel` and every `tenzro_load*Model` call accept a
  `visibility` parameter. Without it the model follows the node. The CLI's
  `tenzro model serve --public | --gated | --private` sets it; with none of the
  three flags the model follows the node.

## What is announced

Per heartbeat tick, read live so a change to the node's visibility re-announces
or stops announcing every resource without an override on the next
announcement, not the next restart:

- **Models** — each model whose effective visibility is `public` or `gated` is
  re-announced on `tenzro/models` with its visibility (`"public"` or `"gated"`)
  and listed in the provider heartbeat's `served_models`; gated ones are also
  listed in `key_required_models`. Private models are never announced, and a
  model that stops being served is withdrawn.
- **Storage** — the `storage` capability label is announced when storage's
  effective visibility is `public` or `gated`.
- **Everything else** (hosting runtimes and price, the RPC endpoint, other
  capability labels) follows the node's visibility.

When nothing is left to announce the heartbeat is skipped rather than publishing
an empty record that still tells peers the node exists.

## Default

Public. An operator who has expressed no preference is running an ordinary
network participant.
