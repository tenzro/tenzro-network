# Tenzro Hosting

Publish a static website, single-page app, a server-side function, or an unmodified long-lived server to Tenzro nodes. Static content is content-addressed over iroh and served from a signed route manifest; a function is a `wasi:http` component that runs in a sandbox and answers requests directly; a machine is a resident process in a Firecracker microVM. This document defines the RPC and CLI surfaces for all three.

Static hosting is covered first; [Functions](#functions) covers the request-handling sandbox and [Machines](#machines) covers the resident-process runtime.

## Status

Pre-alpha. Not version-locked. Names, fields, and event types may change without deprecation cycles until the network has live external users.

## Model

A **site** is a manifest:

| Field | Meaning |
|-------|---------|
| `site_id` | Derived from `owner_did` + `name`. Stable across re-deploys. |
| `owner_did` | The identity that controls the site. Mutations require a signed envelope. |
| `routes` | Map of request path → `{ blob_hash, content_type, size }`. |
| `index_path` | Route served for the site root. Defaults to `/index.html`. |
| `not_found_path` | Optional route served at HTTP 404 for asset misses. |
| `spa` | Single-page-app flag. When set, route misses serve the index at 200. |
| `price_per_request` | Optional per-request TNZO price. When set, serving is x402-gated. |

`blob_hash` is the content-addressed hash of a file in the node's iroh blob store — the last segment of the `tenzro://blob/<hash>` URI returned when the file is uploaded. Content never touches the filesystem; a request path only ever indexes the route map.

## Resolution order

A request to `GET /sites/<site_id><path>` resolves in order:

1. **Exact route match** → serve at 200.
2. **SPA fallback** — if the manifest is a single-page app and the path is not an asset (its last segment has no file extension), serve the index at 200 so the client-side router takes over.
3. **Not-found route** — if the manifest declares one, serve it at 404.
4. **Plain 404.**

Asset misses (a path whose last segment has a file extension, e.g. `/assets/app.abc123.js`) skip the SPA fallback and 404 directly — a missing bundle chunk is never masked as the index page.

Responses carry an ETag (the blob hash) and a short cache-control window. A matching `If-None-Match` returns 304.

## Naming

A hostname can point at a site. When the Web-API edge receives a request whose Host header matches an alias, it serves that site's route map directly, so the site is served by hostname without the caller naming the `site_id`. Control-plane paths are never shadowed by an alias.

Setting an alias requires control of the owner DID and ownership of the target site. Re-pointing an existing hostname additionally requires ownership of the existing alias.

## Placement

A site's content is content-addressed and node-agnostic, so any node holding the blobs can serve it. A **placement** records which nodes a site is served from. Each entry is a serving node's iroh `EndpointId`.

When the edge resolves a request to a site that is placed on remote nodes, it forwards the request over the `tenzro/http` transport (one QUIC bi-stream per HTTP request) to a placed node and streams the response back. The edge rewrites the forwarded path to the serving node's `/sites/<site_id>` path, so the serving node identifies the site by path without needing the edge's alias or domain tables.

An empty placement (or none) means the site serves locally on whichever node receives the request — no remote forwarding. A placement that includes the receiving node's own `EndpointId` also serves locally for that node; the edge only forwards when no local entry matches.

Setting or clearing a placement requires control of the site owner's DID — it is an owner-level routing decision authorized the same way as publish and remove.

## Operators serve under their own domain

Each operator configures the domain its edge serves sites under. There is no network-wide canonical host — a site is served by whichever operator hosts it, under that operator's app domain. An operator sets this in node config:

```toml
[hosting]
app_domain = "apps.example-operator.tld"   # subdomain CNAME target for auto-assigned + attached names
edge_ipv4  = "203.0.113.10"                 # apex A record target
edge_ipv6  = "2001:db8::10"                 # apex AAAA record target
```

When an operator declares no `[hosting]` block, onboarding output reports the fields it does have and prints placeholders for the rest, which the operator fills in from its own edge address. The node returns the records to publish in the RPC response, so the CLI never bakes in a host.

## Custom domains

A site can attach a domain the owner controls. TLS and DNS at the edge are automatic — there is no certificate to obtain and no web server to configure on the owner's side.

Attaching a domain is two steps:

1. **Claim.** `tenzro site domain add` records the claim and returns the DNS records to publish, reported by the hosting operator's node: a record pointing the hostname at that operator's app edge (a `CNAME` to the operator's `app_domain` for a subdomain, or `A`/`AAAA` to its edge address for an apex), plus a `_tenzro-ownership.<hostname>` `TXT` carrying a deterministic ownership token bound to the hostname and owner DID.
2. **Verify.** After the records resolve, `tenzro site domain verify` reads the `TXT` and, on a match, admits the domain. The token is derived, not stored as a secret, so verification can be re-run without re-issuing a challenge.

Once verified, the domain serves the site over HTTPS. The edge obtains the certificate lazily on the first request, gated by an ask endpoint that admits only verified claims, so an unverified or hostile hostname cannot trigger certificate issuance. An operator's auto-assigned names under its own `app_domain` are served from a single wildcard certificate and never reach that path.

Claiming a domain requires control of the owner DID and ownership of the target site. Verifying and removing a claim require ownership of the claim.

## RPC

All mutating methods require a hex `did_envelope` proving control of `owner_did`.

| Method | Description |
|--------|-------------|
| `tenzro_sitePublish` | Publish a manifest. Params: `name`, `owner_did`, `routes`, `index_path?`, `not_found_path?`, `spa?`, `price_per_request?`, `did_envelope`. |
| `tenzro_siteGet` | Read a manifest by `site_id`. |
| `tenzro_listSites` | List sites, optionally filtered by `owner_did`. |
| `tenzro_siteRemove` | Remove a site. Params: `site_id`, `owner_did`, `did_envelope`. |
| `tenzro_siteSetAlias` | Point a hostname at a site. Params: `hostname`, `site_id`, `owner_did`, `did_envelope`. |
| `tenzro_siteGetAlias` | Read a hostname alias. |
| `tenzro_listSiteAliases` | List aliases, optionally filtered by `owner_did`. |
| `tenzro_siteRemoveAlias` | Remove an alias. Params: `hostname`, `owner_did`, `did_envelope`. |
| `tenzro_siteSetPlacement` | Set the serving nodes a site is placed on. Params: `site_id`, `serving_nodes` (array of iroh `EndpointId`; empty serves locally), `owner_did`, `did_envelope`. |
| `tenzro_siteGetPlacement` | Read a site's placement. Params: `site_id`. |
| `tenzro_listSitePlacements` | List all site placements. |
| `tenzro_siteRemovePlacement` | Clear a site's placement, reverting to local serving. Params: `site_id`, `owner_did`, `did_envelope`. |
| `tenzro_siteClaimDomain` | Claim a custom domain for a site; returns the DNS records to publish. Params: `hostname`, `site_id`, `owner_did`, `did_envelope`. |
| `tenzro_siteVerifyDomain` | Verify the DNS `TXT` ownership proof and admit the domain. Params: `hostname`, `owner_did`, `did_envelope`. |
| `tenzro_siteGetDomain` | Read a custom-domain claim. |
| `tenzro_listSiteDomains` | List custom domains, optionally filtered by `owner_did`. |
| `tenzro_siteRemoveDomain` | Remove a custom-domain claim. Params: `hostname`, `owner_did`, `did_envelope`. |

Each route in the `routes` array is an object `{ path, blob_hash, content_type, size }`. Files are uploaded to the node's iroh store via `tenzro_iroh_publishBlob` (`bytes_b64` param → `tenzro_uri` in the response); the last URI segment is the `blob_hash`.

## CLI

```bash
# Deploy a build-output directory: walk files, upload each as an iroh blob,
# build the route map, detect single-page-app layout, publish the manifest.
tenzro site deploy \
  --name my-app \
  --owner-did did:tenzro:human:... \
  --dir ./dist \
  --did-envelope <hex> \
  --rpc https://rpc.tenzro.xyz

# Override single-page-app auto-detection
tenzro site deploy ... --spa       # force fallback on
tenzro site deploy ... --no-spa    # force fallback off

# Manage sites
tenzro site get --site-id <site_id>
tenzro site list [--owner-did did:tenzro:...]
tenzro site remove --site-id <site_id> --owner-did ... --did-envelope <hex>

# Manage hostnames (a subdomain of the hosting operator's app domain)
tenzro site set-alias --hostname my-app.<operator-app-domain> --site-id <site_id> \
  --owner-did did:tenzro:human:... --did-envelope <hex>
tenzro site get-alias --hostname my-app.<operator-app-domain>
tenzro site list-aliases [--owner-did did:tenzro:...]
tenzro site remove-alias --hostname my-app.<operator-app-domain> \
  --owner-did ... --did-envelope <hex>

# Place a site on serving nodes (each --serving-node is an iroh EndpointId).
# The edge forwards requests to a placed node over the tenzro/http transport.
tenzro site set-placement --site-id <site_id> \
  --serving-node <endpoint_id> [--serving-node <endpoint_id> ...] \
  --owner-did did:tenzro:human:... --did-envelope <hex>
tenzro site get-placement --site-id <site_id>
tenzro site list-placements
# Clear placement to revert to local serving
tenzro site remove-placement --site-id <site_id> \
  --owner-did ... --did-envelope <hex>

# Attach a custom domain you control. `domain add` prints the DNS records to
# publish (reported by the hosting operator's node), then `verify` admits it.
tenzro site domain add --hostname app.example.com --site-id <site_id> \
  --owner-did did:tenzro:human:... --did-envelope <hex>
tenzro site domain verify --hostname app.example.com \
  --owner-did did:tenzro:human:... --did-envelope <hex>
tenzro site domain get --hostname app.example.com
tenzro site domain list [--owner-did did:tenzro:...]
tenzro site domain remove --hostname app.example.com \
  --owner-did ... --did-envelope <hex>
```

The `deploy` command sets a content type per file by extension and produces route paths relative to `--dir` with a leading slash. Single-page-app detection looks for an `/index.html` with a JavaScript bundle and no additional HTML pages; `--spa` / `--no-spa` override it.

## Payment

When a manifest carries `price_per_request`, the node gates serving behind an x402 challenge. A caller without a payment credential receives a 402 with a challenge; a caller presenting a valid credential has it verified and settled before the content is served. See [Chat API](chat-api.md) for the credential header conventions shared across payment-gated surfaces.

## Functions

A **function** is a single `wasi:http` component — a `.wasm` file that exports the `wasi:http/incoming-handler` proxy world (the same shape used by Fastly Compute, Fermyon Spin, and wasmCloud). It compiles from Rust, TypeScript/JavaScript, Go, Python, or any language with a WASI 0.2 target. The node compiles the component once, then invokes it per request inside a capability sandbox with deterministic fuel metering and a wall-clock deadline.

A function shares the naming and ingress layer with a static site: a function id is derived from `owner_did` + `name` the same way a `site_id` is, and a hostname alias can point at either. A given id is a function or a site, never both.

### Model

| Field | Meaning |
|-------|---------|
| `id` | Derived from `owner_did` + `name`. Stable across re-deploys. |
| `owner_did` | The identity that controls the function. Mutations require a signed envelope. |
| `version` | Bumped on each re-deploy by the same owner. |
| `wasm_blob_hash` | Content-addressed hash of the component in the node's iroh blob store. |
| `capabilities` | The ambient authority the component runs with. Empty by default. |
| `fuel_limit` | Per-request fuel budget (deterministic metering). Uses the node default when unset. |
| `deadline_ms` | Per-request wall-clock deadline. Uses the node default when unset. |
| `price_per_request` | Optional per-request TNZO price. When set, serving is x402-gated. |

The component starts with **no** filesystem, network, or environment access. A capability grant is a JSON object that opens named authority explicitly:

```json
{
  "storage": [{ "mount": "/data", "read_only": false }],
  "network": [{ "host": "api.example.com", "port": 443 }],
  "env": { "LOG_LEVEL": "info" },
  "host_methods": ["chat"]
}
```

### Request scope

A function invocation is request-scoped and stateless: each request runs the handler fresh with no in-memory state carried to the next request. State that must survive across requests belongs in a granted storage mount, an external service reached through a network capability, or a companion long-lived component. A workload that needs a resident process — a persistent connection, an in-memory cache, a background loop — is a `machine` app, not a function.

### Resolution

A hostname alias, custom domain, or `/functions/<id>` path resolves to a function. The ingress checks the function registry first and the static-site registry second, so a name bound to a function is served by invoking it; a name bound to a site serves its route map. The request — method, path, headers, and body — is handed to the component as a `wasi:http` incoming request, and the component's response is streamed back. A response body is capped at 128 MiB.

### RPC

All mutating methods require a hex `did_envelope` proving control of `owner_did`.

| Method | Description |
|--------|-------------|
| `tenzro_functionDeploy` | Publish a component. Params: `name`, `owner_did`, `wasm_blob_hash`, `capabilities?`, `fuel_limit?`, `deadline_ms?`, `price_per_request?`, `did_envelope`. |
| `tenzro_functionGet` | Read a deployment by `id`. |
| `tenzro_listFunctions` | List deployments, optionally filtered by `owner_did`. |
| `tenzro_functionRemove` | Remove a deployment. Params: `id`, `owner_did`, `did_envelope`. |

The component is uploaded to the node's iroh store via `tenzro_iroh_publishBlob` (`bytes_b64` param → `tenzro_uri` in the response); the last URI segment is the `wasm_blob_hash`.

### CLI

```bash
# Upload a wasi:http component and publish a deployment.
tenzro function deploy \
  --name my-fn \
  --owner-did did:tenzro:human:... \
  --wasm ./target/wasm32-wasip2/release/my_fn.wasm \
  --capabilities ./caps.json \
  --fuel-limit 200000000 \
  --deadline-ms 10000 \
  --did-envelope <hex> \
  --rpc https://rpc.tenzro.xyz

# Manage functions
tenzro function get --id <id>
tenzro function list [--owner-did did:tenzro:...]
tenzro function remove --id <id> --owner-did ... --did-envelope <hex>

# Point a hostname at a function (same alias mechanism as a site)
tenzro site set-alias --hostname my-fn.<operator-app-domain> --site-id <id> \
  --owner-did did:tenzro:human:... --did-envelope <hex>
```

`--capabilities` is optional; when omitted the component runs with no ambient authority. Point a hostname at the function with `tenzro site set-alias`, whose id argument accepts a function id.

When a deployment carries `price_per_request`, serving is x402-gated on the same challenge/credential path as a static site.

## Machines

A **machine** is an unmodified long-lived server — a Node, Python, Rust, or Go process that binds a loopback port — run inside a hardware-virtualized Firecracker microVM. Where a function is a per-request sandbox that runs the handler fresh each time, a machine keeps a resident process: persistent connections, an in-memory cache, and background loops all survive between requests. A workload that needs any of those is a machine, not a function.

A machine shares the naming and ingress layer with static sites and functions: a machine id is derived from `owner_did` + `name` the same way a `site_id` is, and a hostname alias can point at any of the three. A given id is exactly one class.

Serving a machine requires an operator node that runs the microVM supervisor — a Linux host with `/dev/kvm`, nested virtualization, and the `firecracker` and `jailer` binaries. A node without that capability holds machine deployment metadata (deploy / get / list / remove work) but answers a machine request with HTTP 501. Placement filters machine deployments to nodes that advertise the `machine` hosting class.

### Model

| Field | Meaning |
|-------|---------|
| `id` | Derived from `owner_did` + `name`. Stable across re-deploys. |
| `owner_did` | The identity that controls the machine. Mutations require a signed envelope. |
| `version` | Bumped on each re-deploy by the same owner. |
| `artifact_caid` | Content-addressed id of the microVM image in the node's iroh blob store. |
| `internal_port` | The loopback port the guest server listens on. Ingress bridges to it. |
| `resources` | `vcpus`, `mem_mib`, `disk_mib` for the guest. Node defaults apply when unset. |
| `sealed_env` | Environment secrets, each sealed to the assigned node's sealing key. |
| `tee_required` | When set, the assigned node must run the microVM inside a TEE. |
| `price_per_request` | Optional per-request TNZO price. When set, serving is x402-gated. |

### Ingress bridge

The guest server listens on a loopback port inside the microVM and does not speak the network's forwarding transport itself. The deployment declares that port as `internal_port`; the supervisor gives the microVM a tap NIC and returns a host-routable address. The ingress bridge dials that address over plain TCP, replays the request as raw HTTP/1.1, and reads the raw response back — so an unmodified server that only knows how to bind a port and answer HTTP is reachable through the network's edge with no code changes.

The supervisor boots the microVM on the first request that resolves to it and keeps it running for subsequent requests. A response body is capped the same way as other ingress paths.

### Sealed secrets

Environment secrets never travel in plaintext. The deploy client fetches the assigned node's X25519 sealing public key, envelope-wraps each value to it (X25519 key agreement + AES-256-GCM), and sends only the ciphertext in `sealed_env`. Only the node holding the matching sealing key can unseal the values, and it does so in memory when it launches the microVM. The plaintext never leaves the deploying host and is never persisted in the clear.

### Isolation

The supervisor launches every microVM under `jailer`, which sets up a chroot as root and then drops privileges before executing firecracker. The defaults harden this drop:

- **Unprivileged uid/gid.** Each microVM runs as a non-root host account (uid/gid `30000` by default), so a guest-to-host escape reaches an account with no privileges rather than root. Operators reserve a dedicated system account and can override the pair.
- **cgroup accounting.** The jailer places each microVM in a cgroup v2 hierarchy for per-machine resource accounting. Hosts without cgroup v2 can select cgroup v1.
- **Seccomp filtering.** Firecracker installs its advanced per-thread syscall allow-list (`--seccomp-level 2`).

These are node-level operator settings, not per-deployment fields.

The node's sealing key is derived deterministically from its validator key, so it is stable across restarts and can be fetched ahead of a deploy.

### RPC

All mutating methods require a hex `did_envelope` proving control of `owner_did`.

| Method | Description |
|--------|-------------|
| `tenzro_machineDeploy` | Publish a machine. Params: `name`, `owner_did`, `artifact_caid`, `internal_port`, `resources?`, `sealed_env?`, `tee_required?`, `price_per_request?`, `did_envelope`. |
| `tenzro_machineGet` | Read a deployment by `id`. |
| `tenzro_listMachines` | List deployments, optionally filtered by `owner_did`. |
| `tenzro_machineRemove` | Remove a deployment (stops the running microVM first). Params: `id`, `owner_did`, `did_envelope`. |
| `tenzro_machineStatus` | Report the runtime status of a deployment. Params: `id`. |
| `tenzro_machineSealingKey` | Read the node's X25519 sealing public key for sealing env secrets. Returns `sealing_public_key` (hex) and `alg`. |

Each `sealed_env` entry is an object `{ name, sealed_value }`, where `sealed_value` is the JSON-serialized encrypted envelope. The microVM image is uploaded to the node's iroh store via `tenzro_iroh_publishBlob` (`bytes_b64` param → `tenzro_uri` in the response); the last URI segment is the `artifact_caid`.

### CLI

```bash
# Upload a microVM image and publish a deployment. --env is a JSON file of
# secrets; the CLI seals each value to the node's sealing key before sending.
tenzro machine deploy \
  --name my-server \
  --owner-did did:tenzro:human:... \
  --image ./rootfs.ext4 \
  --internal-port 8080 \
  --vcpus 2 --mem-mib 1024 --disk-mib 4096 \
  --env ./secrets.json \
  --did-envelope <hex> \
  --rpc https://rpc.tenzro.xyz

# Manage machines
tenzro machine get --id <id>
tenzro machine list [--owner-did did:tenzro:...]
tenzro machine status --id <id>
tenzro machine remove --id <id> --owner-did ... --did-envelope <hex>

# Point a hostname at a machine (same alias mechanism as a site)
tenzro site set-alias --hostname my-server.<operator-app-domain> --site-id <id> \
  --owner-did did:tenzro:human:... --did-envelope <hex>
```

`--env` is optional; when omitted the machine runs with no injected secrets. `--tee-required` asks the network to place the machine only on a node that runs the microVM inside a TEE. Point a hostname at the machine with `tenzro site set-alias`, whose id argument accepts a machine id.

When a deployment carries `price_per_request`, serving is x402-gated on the same challenge/credential path as a static site.

## Placement and economics

Deploying a site, function, or machine to a node does not pin the workload to that node. The receiving node runs an automatic placement pass that spreads the app across capable nodes elsewhere on the network and records the result as a set of leases. The manual [placement](#placement) controls (`tenzro_siteSetPlacement` and friends) remain the owner-level override; automatic placement is what runs when the owner does not pin nodes by hand.

### How placement runs

Each node announces its hosting capability — the runtime classes it serves (`static`, `function`, `machine`), its free CPU / RAM / disk, whether it can run a workload inside a TEE, and the per-hour TNZO price it charges — with a time-to-live. Announcements that have not been refreshed within their TTL are treated as stale and ignored.

On deploy, the receiving node:

1. Reads the fresh announcements into a candidate set.
2. Hard-filters to nodes that satisfy the app's requirements: the right runtime class, enough CPU / RAM / disk, TEE support when required, and a price at or below the deploy's `max_price_per_hour` when one is given.
3. Ranks the survivors — a node in the requested region first, then cheapest per hour.
4. Leases the top N distinct nodes, where N is the requested replica count.

The advertised price in an announcement is the bid: placement is a pure function of the announcement snapshot, so the same candidate set always yields the same choice. When no capable remote node exists, the app serves locally on the deploying node and no lease is recorded — a deploy never fails for lack of a placement target.

The chosen nodes are written into the app's ingress placement, so the edge forwards requests to them exactly as it does for a hand-set placement.

### Deploy parameters

The three deploy methods accept optional placement parameters:

| Param | Meaning |
|-------|---------|
| `replicas` | Number of distinct nodes to lease. Defaults to 1. |
| `region_hint` | Preferred region; ranked ahead of other regions, not required. |
| `max_price_per_hour` | Upper bound on a candidate's per-hour TNZO price. Unset accepts any price. |

The deploy response carries a `placement` array of the leased nodes' iroh `EndpointId`s (empty for local serving).

### Leases

A lease is the on-ledger record binding one app replica to one node:

| Field | Meaning |
|-------|---------|
| `app_id` | The site, function, or machine id. |
| `node_id` | The serving node's iroh `EndpointId`. |
| `runtime_class` | `static`, `function`, or `machine`. |
| `cpu_cores`, `ram_gb`, `disk_gb` | Resources reserved for the replica. |
| `tee` | Whether the replica runs inside a TEE. |
| `price_per_hour` | The per-hour TNZO price bid at placement time. |
| `region` | The serving node's region, when known. |
| `capability_set` | The capabilities the node advertised. |
| `leased_at`, `expires_at` | Lease window in milliseconds since the epoch. |
| `metered_tnzo` | TNZO metered against the lease so far. |

Removing an app releases every lease it holds.

### Failover

A serving node that stops announcing falls out of the candidate set when its announcement TTL lapses. A reconcile pass runs on a fixed interval: it sweeps expired leases, then for any lease whose node is no longer announcing, it re-runs placement for that replica against the fresh candidate set — excluding the dead node — and moves the replica to a surviving node. The replica count stays stable across a node loss without the owner intervening.

### RPC

| Method | Description |
|--------|-------------|
| `tenzro_listLeases` | List every active hosting lease held by this node. Returns `leases` and `count`. |
| `tenzro_getLeasesForApp` | List the leases placed for one app. Params: `app_id`. Returns `app_id`, `leases`, `count`. |

### CLI

```bash
# List all active hosting leases on the node
tenzro lease list --rpc https://rpc.tenzro.xyz

# Show the leases placed for one app (site, function, or machine id)
tenzro lease get --app-id <app_id> --rpc https://rpc.tenzro.xyz
```
