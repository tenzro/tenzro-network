# Incident Drills

Practitioner-grade runbooks for operators. Each drill is structured as **signal → confirmation → response → recovery**. Reference: `docs/operators/OPERATOR_GUIDE.md` for the happy-path topology and config.

These drills assume the Tenzro testnet topology (10-VM GCE fleet, `tenzro-validator-0` as RPC-public + bootstrap + Caddy edge + pkarr-relay; validators 1–9 standard). Adjust hostnames for your deployment.

---

## D1. Canary rollback (bad image rolled to validator-0)

**Scenario:** A freshly-built image was rolled to the canary (`tenzro-validator-0`) per the CLAUDE.md canary-first procedure. The canary container is up but consensus is unhealthy — block height stalls, peer_count is low, or the RPC starts 500ing.

### Signal

From the operator workstation, no SSH needed:

```bash
curl -s https://rpc.tenzro.network -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
curl -s https://rpc.tenzro.network -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"net_peerCount","params":[]}'
```

Stale block height after 60s, or peer_count not advancing toward `0x9`, is the trigger. A neighbor's height advancing past the canary's height is the more direct signal — query any healthy validator from inside the fleet.

### Confirmation

SSH the canary, inspect what's actually running:

```bash
gcloud compute ssh tenzro-validator-0 --zone=us-central1-a --project=tenzro-operator-project \
  --tunnel-through-iap --command='
sudo docker ps --format "{{.Names}} {{.Status}} {{.Image}}" | grep tenzro-node
sudo docker logs --tail 100 tenzro-node 2>&1 | tail -50
'
```

Look for: panic backtrace, `Storage error`, `consensus stalled`, `Insufficient votes for quorum`, repeated view-change timeouts. If the container is `Up` and `healthy` but logs show a consensus-layer error, it is still a bad image — the docker healthcheck only probes liveness, not consensus.

### Response

Roll the canary back to the previous-known-good digest. The previous digest lives in the wrapper's git history *and* in the artifact registry. Fastest path is to inspect the registry:

```bash
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/tenzro-operator-project/tenzro/tenzro-node \
  --project=tenzro-operator-project \
  --include-tags \
  --sort-by="~CREATE_TIME" \
  --limit=5 --format='table(IMAGE,DIGEST,CREATE_TIME)'
```

Pick the second-most-recent entry (the most recent is the broken one). On the canary:

```bash
gcloud compute ssh tenzro-validator-0 --zone=us-central1-a --project=tenzro-operator-project \
  --tunnel-through-iap --command="
PREV_DIGEST=sha256:<previous-good-digest>
BAD=\$(sudo grep -oE 'sha256:[a-f0-9]+' /var/lib/tenzro-bin/tenzro-run | head -1)
sudo sed -i \"s|\$BAD|\$PREV_DIGEST|\" /var/lib/tenzro-bin/tenzro-run
sudo docker stop tenzro-node
"
```

Per the systemd note in CLAUDE.md: `docker stop` is the trigger, not `systemctl restart` — the Main PID is the docker CLI, not the container; `systemctl restart` is a no-op for `docker run --rm` units.

### Recovery

Wait 30–60s, then re-run the signal checks. Acceptance:

```bash
gcloud compute ssh tenzro-validator-0 --zone=us-central1-a --project=tenzro-operator-project \
  --tunnel-through-iap --command='
sudo docker ps --format "{{.Names}} {{.Status}}" | grep tenzro-node
curl -s -X POST http://127.0.0.1:8545 -H "content-type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}"
curl -s -X POST http://127.0.0.1:8545 -H "content-type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"net_peerCount\",\"params\":[]}"
'
```

Container `Up` + `healthy`, peer_count `0x9`, block height advancing. **Do not** proceed to roll validators 1–9 onto the new image until a root-cause analysis on the broken image is complete. Tag the broken image as `BROKEN-YYYYMMDD` so it cannot be re-rolled by mistake.

---

## D2. Equivocation slashing (validator double-voted)

**Scenario:** A validator emits two conflicting votes in the same view. The consensus engine's `EquivocationDetector` fires; the `StakingSlashingCallback` is invoked; 10% of the validator's stake is slashed, they are dropped from the next epoch's pending queue, and they are jailed in the permissionless `ValidatorRegistry`.

This is **automatic**. The drill is verifying it landed correctly, and recovering from a false positive.

### Signal

On any validator, the slash emits a `WARN`-level log:

```
WARN consensus::voter: Equivocation detected for validator <addr>: vote1=<hash1> vote2=<hash2> view=<n>
WARN tenzro_node::node: Slashed validator <addr> for equivocation (view=<n>, slash_amount=<u128>)
INFO tenzro_node::node: Removed slashed validator <addr> from next-epoch pending queue
INFO tenzro_node::node: Jailed slashed validator <addr> in permissionless registry (epoch=<n>)
```

These are also emitted as `tenzro/attestations` gossipsub messages (evidence packets) so any node in the fleet can observe the event by tailing logs, not just the one that detected it.

### Confirmation

Query the validator's current state and registry entry from any node's RPC:

```bash
curl -s https://rpc.tenzro.network -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_getValidatorState","params":["<validator-address>"]}'
curl -s https://rpc.tenzro.network -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listActiveValidators","params":[]}'
```

Acceptance: the slashed address appears in `getValidatorState` with `status: "Jailed"`, jail_until epoch is set, and the address is absent from `listActiveValidators`. The validator's stake amount in `tenzro_providerStats` should be 90% of what it was pre-slash.

Cross-check the staking layer:

```bash
curl -s https://rpc.tenzro.network -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_providerStats","params":["<validator-address>"]}'
```

### Response

If the slash was **correct** (the validator really did double-vote — e.g. operator ran two binaries against the same key by accident), the operator of that validator must:

1. Identify the root cause (most common: two `tenzro-node` processes started against the same `--data-dir`, or two physical machines provisioned with the same Ed25519 + ML-DSA-65 + BLS key bundle).
2. Stop **all** processes against that key.
3. Wait for the jail_until epoch to elapse (default 100 epochs from the slash epoch).
4. Restart a single node against the key, re-stake the residual balance, wait for the next epoch boundary to be re-promoted.

If the slash was a **false positive** (network partition replay, software bug), follow the governance path documented in OPERATOR_GUIDE.md §7 Slashing: submit a governance proposal with the conflicting vote evidence and a remediation plan; if passed, the slashed amount is restored from the treasury.

### Recovery — confirming the validator is back

After the jail period elapses and the operator re-stakes, the next epoch transition re-promotes the validator. Confirm:

```bash
curl -s https://rpc.tenzro.network -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listActiveValidators","params":[]}' \
  | jq '.result[] | select(.address == "<validator-address>")'
```

The entry should re-appear with `status: "Active"`. The validator will start receiving PREPARE messages within the first view of the new epoch.

---

## D3. Training run NEC carry-forward (witness committee couldn't reach quorum)

**Scenario:** A Tenzro Train sync round's witness committee fails to assemble a k-of-N quorum within the configured `grace_window_ms`. The `SyncerState::build_nec_sync_round` path constructs a no-endorsement-cert sync round that carries forward the prior `state_root` to `round+1`. The run advances; no gradients are applied; the next round retries.

This is a **healthy** behavior — it's the protocol-correct response to network partition or a slow witness set. The drill is recognizing it, distinguishing it from a stuck run, and intervening if NECs are accumulating across many consecutive rounds.

### Signal

On any node participating in the run, the NEC emission emits:

```
WARN tenzro_training::runtime: build_nec_sync_round(run=<run-id>, round=<n>) — witness committee did not reach quorum within <grace_window_ms>ms, carrying forward state_root=<hash>
```

The published `SyncRound` envelope on the `tenzro/training/syncer` gossipsub topic has `no_quorum_witnesses: Some(Vec<Signature>)` populated and `state_root` equal to the prior round's `state_root`.

### Confirmation

Fetch the run's recent rounds via RPC:

```bash
curl -s https://rpc.tenzro.network -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_training_getRun","params":["<run-id>"]}'
```

Look at the most-recent rounds: each round entry includes a `no_quorum_witnesses` field. If exactly one or two rounds in the recent history have it set, this is normal protocol behavior — a transient witness flap.

### Response — when to act

- **0–2 consecutive NEC rounds:** no action. The run is correctly recovering from a witness-set hiccup.
- **3–5 consecutive NEC rounds:** investigate. Check the committee membership for the run (`tenzro_training_getRun` response includes the committee witness DIDs) and probe the witnesses' health:
  ```bash
  # For each witness DID, resolve to a node and check connectivity
  curl -s https://rpc.tenzro.network -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_resolveDidDocument","params":["<witness-did>"]}'
  # Then ping the resolved node-id over libp2p (from another node in the fleet)
  ```
- **6+ consecutive NEC rounds:** the witness set is broken. Pause the run via governance and re-elect the committee. The `select_witness_committee` function in `tenzro-training` is pure and chain-entropy-driven; a fresh finalized block hash (which advances independently of the training run) will produce a new committee on the next round.

### Recovery — confirming the run is healthy again

Watch a few successive rounds via `tenzro_training_getRun` and confirm `no_quorum_witnesses == None` on the new rounds. The `state_root` should start advancing (it stays pinned during NEC carry-forward). The next `tenzro_training_getReceipt` for the run should reflect a non-zero round-count delta.

---

## D4. RPC public is down but the node is up (Caddy / TLS layer)

**Scenario:** `https://rpc.tenzro.network` returns 502/504 or TLS handshake fails. The underlying node on `tenzro-validator-0` is fine — consensus is healthy, peer_count is 9, blocks are advancing.

### Signal

```bash
curl -sI https://rpc.tenzro.network/   # not -X POST; HEAD on the root is enough
curl -sI https://api.tenzro.network/health
```

5xx, TLS error, or `connection refused` — but `tenzro-validator-0:8545` answers locally.

### Confirmation

SSH the validator-0 host, check Caddy:

```bash
gcloud compute ssh tenzro-validator-0 --zone=us-central1-a --project=tenzro-operator-project \
  --tunnel-through-iap --command='
sudo docker ps --format "{{.Names}} {{.Status}}" | grep tenzro-caddy
sudo docker logs --tail 100 tenzro-caddy 2>&1 | tail -50
sudo docker exec tenzro-caddy caddy validate --config /etc/caddy/Caddyfile
'
```

Common failures: Caddy container crashed (OOM, config invalid), upstream (`127.0.0.1:8545`) unreachable from within the Caddy container's network, ACME cert renewal failed.

### Response

If Caddy is down:
```bash
gcloud compute ssh tenzro-validator-0 --zone=us-central1-a --project=tenzro-operator-project \
  --tunnel-through-iap --command='sudo systemctl restart tenzro-caddy'
```

If Caddy is up but the upstream is unreachable, the issue is COS host iptables (see CLAUDE.md note on COS default-DROP and the `feedback_gce_cos_default_drop_iptables` memory). Re-apply the cloud-init iptables ACCEPT rules:
```bash
gcloud compute ssh tenzro-validator-0 --zone=us-central1-a --project=tenzro-operator-project \
  --tunnel-through-iap --command='sudo iptables -L INPUT -n | head -20'
```

If the ACME cert is expired, `docker logs tenzro-caddy` will show explicit ACME errors. Caddy will retry automatically; if it's failing because LE rate-limited the domain, switch to ZeroSSL as the issuer in the Caddyfile (Caddy supports both natively).

### Recovery

Re-run the signal checks from outside the fleet. `https://rpc.tenzro.network` should return JSON-RPC responses, `https://api.tenzro.network/health` should return 200.

---

## D5. Disk filling on a validator (RocksDB compaction lag)

**Scenario:** A validator's data disk crosses 80% utilization. Without intervention, write stalls and eventually OOM-like behavior (RocksDB returns `IOError: No space left on device`).

### Signal

```bash
gcloud compute ssh tenzro-validator-<n> --zone=<zone> --project=tenzro-operator-project \
  --tunnel-through-iap --command='df -h /var/lib/tenzro'
```

`Use%` ≥ 80% is the trigger; ≥ 90% is critical.

### Confirmation

Identify the largest RocksDB column families:

```bash
gcloud compute ssh tenzro-validator-<n> --zone=<zone> --project=tenzro-operator-project \
  --tunnel-through-iap --command='
sudo du -sh /var/lib/tenzro/rocksdb/* 2>/dev/null | sort -hr | head -10
'
```

`CF_BLOCKS` and `CF_TRANSACTIONS` are usually the largest. If `CF_SNAPSHOTS` is the largest, snapshot retention (default 100) is set too high for the disk.

### Response

**Option A — increase disk (preferred, no downtime):**
```bash
gcloud compute disks resize tenzro-validator-<n>-data \
  --zone=<zone> --project=tenzro-operator-project --size=<new-size-GB>
gcloud compute ssh tenzro-validator-<n> --zone=<zone> --project=tenzro-operator-project \
  --tunnel-through-iap --command='sudo resize2fs /dev/disk/by-id/google-tenzro-data'
```

**Option B — trigger snapshot pruning (no downtime):**
```bash
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_pruneSnapshots","params":[<keep-n>]}'
```

**Option C — manual RocksDB compaction (5–15 min of degraded write throughput):**
Stop accepting new writes via `tenzro node drain` (per OPERATOR_GUIDE.md §7), then trigger compaction. Restart afterward.

### Recovery

Verify disk has dropped below 70% and RocksDB log shows no compaction warnings.

---

## D6. Bridge adapter offline (LayerZero / CCIP / deBridge fee quote failures)

**Scenario:** Outbound bridge sends start failing because a remote adapter's fee-quote eth_call is timing out or reverting.

### Signal

Node logs:
```
WARN tenzro_bridge::layerzero: EndpointV2.quote() failed: <error>; falling back to static fee
```

Fallback static fees are intentionally conservative (over-charge slightly); the user transaction still goes through. But if the static fee is meaningfully wrong, settlement reconciliation breaks.

### Confirmation

Test the underlying RPC the adapter is dialing:
```bash
# LayerZero — uses the configured EVM RPC endpoint
echo $LZ_RPC_URL  # or whatever env var the deployment uses
curl -s $LZ_RPC_URL -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
```

If this returns quickly with the expected chain ID, the issue is contract-side (LayerZero endpoint upgrade, paused). If it's slow/timing out, the RPC provider is the problem.

### Response

- **RPC provider down:** rotate to a backup endpoint via `tenzro-node` config reload (or restart with the alternate `--config`).
- **Endpoint contract paused:** wait for LayerZero / Chainlink / deBridge to resolve upstream. Disable that adapter via governance proposal if outage exceeds the configured SLA window.

### Recovery

Watch the WARN logs disappear. `tenzro_quoteBridge` over RPC should start returning non-fallback fees.

---

## Reference

- **Happy-path operations:** `docs/operators/OPERATOR_GUIDE.md`
- **Build & deploy procedure:** `CLAUDE.md` § Deployment
- **Consensus internals:** `crates/tenzro-consensus/README.md`
- **Training internals:** `docs/TRAIN.md`, `crates/tenzro-training/src/runtime.rs`
- **Bridge adapter source:** `crates/tenzro-bridge/src/`
