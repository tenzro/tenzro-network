# Plan: fail-closed, provider-gated access for every node resource

Status: LARGELY LANDED — plan originally drafted 2026-08-12 from the external
attack-surface audit; the acute gaps have since shipped. Landed: the credential
gate on the `tenzro/infer` overlay; fail-closed access hardening (iroh MCP
allowlist, `moe/execute` gate, loopback RPC/web/sidecar binds — gaps 1, 2, 3 and
Part A); a unified `ResourceAccess` (open/gated/private) for database and storage
(Part C); and a native in-node ACME HTTPS edge (`web/edge_tls.rs`, edge role) so
a node fronts its own public TLS without an external Caddy. Remaining: the
node-level firewall (Part D — ops, see `NODE-FIREWALL.md`) and full extension of
`ResourceAccess` (overlay reachability + Open/x402 mode) to database, storage,
and web-hosting. Section numbers below describe the plan as designed; treat the
gap list as the pre-hardening baseline.

## Principle (the founder's requirement)
Every network-reachable resource on a node — model inference, each MCP server,
A2A, remote shell, ingress, MoE compute — is governed by ONE access policy, and
the provider explicitly opts each resource in. **Default = not exposed
(fail-closed).** A resource is reachable off-box only when the provider has said
"serve this, on these terms" (private / on-demand-paid / subscription-key /
rental), and the matching credential is required. Anything that binds `0.0.0.0`
or answers the overlay without that opt-in is a provider exposed without consent.

This generalizes what inference now has (`ModelVisibility` Network/Gated/Private
+ `NodeInferenceAdmission` credential gate) to all resources.

## Current gaps (from the audit — what violates the principle)
1. **CRITICAL — `tenzro/mcp` over iroh is unauthenticated.** `mcp/iroh_transport.rs:74-83`
   builds the MCP server over the raw stream with no credential/peer-identity;
   the HTTP MCP auth (`bearer_auth_check`, `ServiceSurface::Mcp` gate) is
   axum-only and bypassed. Reachable unauthenticated: `chat_completion`
   (`mcp/server.rs:8171+`, direct `model_runtime.generate`, ungated even for
   Gated models) and `serve_model`(local)/`stop_model`/`delete_model_mcp`
   (`mcp/server.rs:11844-11959`, direct `served_models` + disk mutation —
   remote model DELETE).
2. **HIGH — HTTP RPC binds `0.0.0.0:8545` by default.** CLI default
   (`main.rs:117-118`) overrides the loopback profile default at `main.rs:1884`;
   `service_key_refusal` no-ops unless the admission gate is enabled, so an
   ungated node exposes every non-allowlisted method off-box. The tsbridge is
   redundant with this — fixing the bind closes both.
3. **HIGH — `tenzro/moe` `moe/execute` unauthenticated** (`moe.rs:167-192`, ALPN
   always advertised `node.rs:4323`): free distributed compute to any dialer.
4. **MEDIUM — Web API `0.0.0.0:8080`**: `/chat` is gated, but `/wallet/mldsa/sign`
   (`web/server.rs:494`) and `/faucet` rely on the optional admission gate.
5. **MEDIUM — MCP sidecars `0.0.0.0:3001-3008`** (Ethereum/LayerZero/Chainlink/
   LI.FI/A2A ungated; Canton gated by `scope=canton`). Bound all-interfaces.

Correctly gated (no change): `infer`, `shell`, `a2a` mutations, `http` ingress.

## The design

### A. Fail-closed binds (the biggest exposure reducer, smallest change)
- Change CLI defaults `main.rs:117/121` `--rpc-addr`/`--web-addr` to
  `127.0.0.1:8545` / `127.0.0.1:8080`. Off-box HTTP access becomes opt-in
  (`--rpc-addr 0.0.0.0` or config), and even then must pass the gates below.
- Bind the MCP sidecars (`main.rs:145-173`, ports 3001-3008) to `127.0.0.1`
  by default; a provider opts a given integration onto the network via config
  with its access tier. Closes gap 5 and most of 2/4 at the network layer.
- The intended off-box path stays the iroh overlay (`9001`), which is
  ALPN-gated per B.

### B. One admission check on every overlay ALPN (fail-closed)
Introduce a single `ResourceAdmission` seam (generalize `NodeInferenceAdmission`)
that every iroh dispatcher calls before doing work, keyed on (resource-kind,
resource-id, presented credential):
- **mcp (gap 1):** in `IrohMcpHandler::serve_stream`, require a credential frame
  / session credential; route `chat_completion` through the SAME
  `decide_creds(api_key, service_key, model)` as `infer.rs`; make
  `serve_model`/`stop_model`/`delete_model_mcp` (and other mutations) require the
  operator admin token (route via the admin-gated `rpc_dispatch`) or REFUSE over
  iroh. Non-inference tenant tools keep their `ServiceSurface::Mcp` scope check,
  now enforced on the iroh path too (populate the header/task-local from the
  session credential instead of defaulting).
- **moe (gap 3):** gate `moe/execute` behind a lease/credential or a settled
  x402 receipt before `runtime.execute`, mirroring infer.
- infer/shell/a2a/http already conform.

### C. Provider access policy (make it declarative + default-private)
Generalize `ModelVisibility` → a per-resource `ResourceAccess { Private |
Network(on-demand x402) | Gated(key/rental) }`, default `Private`, declared by
the provider:
- models: already `serve --gated|--private|(network)`.
- MCP integrations, moe, ingress: a `[access]` config block naming which
  resources are network-exposed and at which tier; unnamed = Private (loopback
  / refuse overlay). The dispatchers in B consult this.

### D. Firewall (defense-in-depth, ops — needs founder sudo)
On each node: allow inbound only `9000/tcp+udp` (p2p) and `9001/udp` (iroh);
drop everything else from off-box (3001-3008, 8080, 8545). Then retire the
tsbridge (`tsbridge.py`) — with loopback binds + overlay access it is obsolete.
(nftables/ufw rules provided at implementation.)

## Sequencing
1. **Gap 1 first (CRITICAL):** gate the iroh MCP path — stop unauthenticated
   inference + remote model deletion. Ship + deploy.
2. Fail-closed binds (A) — one-line-ish defaults; huge exposure cut. Ship.
3. moe gate (B/gap 3).
4. Firewall + drop tsbridge (D) — ops, founder sudo.
5. Declarative access policy (C) — the durable model; larger, do after the
   acute gaps are closed.

## Part C elevated — the decentralized-cloud access model (founder, 2026-08-12)
Compute (models), Database, Storage, and Web-hosting are PEER resource types of
one decentralized cloud. Each is **Open (public, pay-per-use x402) | Gated
(subscription api-key / rental service-key) | Private** — the OPERATOR decides
per resource. Default Private (fail-closed). This is the same `ResourceAccess`
policy for all four, enforced identically, reachable over the overlay by machine
identity + the matching credential.

Current state vs target:
- Compute: has all three modes (serve --gated/--private/network) + overlay
  (tenzro/infer, gated) ✓.
- Database (`/v1/databases/*`, database_routes.rs) + Storage (`/v1/files/*`,
  files_routes.rs): WIRED + GATED-only (ApiKeyScope::Database/Storage), HTTP-only
  (no overlay ALPN). MISSING: the Open (x402) + Private modes, an operator
  access-policy per db/store, and overlay reachability.
- Web-hosting (tenzro/http ingress): public-free / priced (x402); MISSING the
  Gated (key) mode + operator policy unification.

Build: a single `ResourceAccess` the operator sets per resource; extend
db/storage/hosting to all three modes; give db/storage an overlay path (an ALPN
or route them through the credential-gated overlay like infer); test each mode
(open + gated + private) for each resource type.

## Risks / notes
- Changing RPC/web bind defaults to loopback will break any current off-box
  HTTP caller (incl. the tsbridge-based tenzro-code path). That path is already
  migrating to the iroh overlay; confirm nothing else depends on off-box HTTP
  before flipping the default, or provide an explicit opt-in.
- Spark is NATed today (no public IP), so these are LAN/tailnet exposures now,
  but the fix must hold when a node has a public IP or a working relay.
- MoE/x402-over-overlay share the "no frame-level payment yet" gap noted in the
  transport plan; gate moe by credential/lease first, add x402 later.
